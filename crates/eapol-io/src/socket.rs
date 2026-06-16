//! A safe async wrapper over an `AF_PACKET`/`SOCK_RAW` socket bound to the EAPOL
//! EtherType, for one front-panel interface.
//!
//! Binding the socket's protocol to `htons(ETH_P_PAE)` makes the kernel deliver
//! **only** `0x888E` frames, so an explicit BPF filter is unnecessary (DESIGN
//! §4). All `unsafe` is confined to this file and each block is justified.
//!
//! Portability: `AF_PACKET` and `sockaddr_ll` are Linux concepts. We define them
//! locally and use only portable libc calls so the crate *compiles* everywhere
//! (catching mistakes off-target), but `socket(AF_PACKET, …)` only succeeds on
//! Linux — elsewhere `open` returns an I/O error.

use crate::error::EapolError;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

/// EAPOL EtherType (IEEE 802.1X), `0x888E`.
pub const ETH_P_PAE: u16 = 0x888E;
/// `AF_PACKET` address family (Linux), as the C `int` and `u16` forms.
const AF_PACKET_I32: i32 = 17;
const AF_PACKET_U16: u16 = 17;
/// Max interface-name length including the trailing NUL (`IFNAMSIZ`).
const IFNAMSIZ: usize = 16;
/// Receive buffer: a full Ethernet frame with a VLAN tag and slack.
const FRAME_CAP: usize = 1600;
/// Smallest valid Ethernet frame (dst+src+ethertype) we will transmit.
const ETHERNET_HEADER_LEN: usize = 14;
/// Linux `SOCK_CLOEXEC` / `SOCK_NONBLOCK` socket-type flags, defined locally so
/// the crate compiles off-Linux. ORed into the `socket(2)` type so the fd is
/// close-on-exec and non-blocking atomically (no fork/exec leak window).
const SOCK_CLOEXEC: i32 = 0o2_000_000;
const SOCK_NONBLOCK: i32 = 0o4_000;

/// Convert a `u16` to network byte order.
#[must_use]
pub const fn htons(value: u16) -> u16 {
    value.to_be()
}

/// Linux `struct sockaddr_ll` (packet address). Defined locally so the crate
/// compiles on non-Linux hosts; the layout matches the kernel's.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
// Field names mirror the kernel's `struct sockaddr_ll` for layout fidelity.
#[allow(clippy::struct_field_names)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

/// Validate an interface name and return it as a C string.
///
/// # Errors
/// [`EapolError::InvalidInterfaceName`] if empty, ≥ `IFNAMSIZ`, or containing a
/// NUL.
fn ifname_cstring(ifname: &str) -> Result<CString, EapolError> {
    if ifname.is_empty() || ifname.len() >= IFNAMSIZ {
        return Err(EapolError::InvalidInterfaceName(ifname.to_string()));
    }
    CString::new(ifname).map_err(|_| EapolError::InvalidInterfaceName(ifname.to_string()))
}

/// Resolve an interface name to its index.
fn interface_index(ifname: &str) -> Result<i32, EapolError> {
    let cstr = ifname_cstring(ifname)?;
    // SAFETY: `cstr` is a valid NUL-terminated C string; `if_nametoindex` reads
    // it and returns 0 on failure (no ownership transfer, no aliasing).
    let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if index == 0 {
        return Err(EapolError::InterfaceNotFound(ifname.to_string()));
    }
    i32::try_from(index).map_err(|_| EapolError::InterfaceNotFound(ifname.to_string()))
}

/// An EAPOL raw socket bound to one interface.
#[derive(Debug)]
pub struct EapolSocket {
    fd: AsyncFd<OwnedFd>,
    ifindex: i32,
}

impl EapolSocket {
    /// Open an `AF_PACKET` socket on `ifname`, delivering only EAPOL frames.
    /// Must be called within a Tokio runtime (it registers with the reactor).
    ///
    /// # Errors
    /// - [`EapolError::InvalidInterfaceName`] / [`EapolError::InterfaceNotFound`].
    /// - [`EapolError::Io`] if any syscall fails (incl. a non-Linux host).
    pub fn open(ifname: &str) -> Result<Self, EapolError> {
        let ifindex = interface_index(ifname)?;

        // SAFETY: a straightforward `socket(2)` call with constant arguments.
        // SOCK_CLOEXEC | SOCK_NONBLOCK make the fd close-on-exec and non-blocking
        // atomically (no fork/exec leak window, and ready for the async reactor).
        // Returns a new fd (≥0) or -1 with errno set. No memory is touched.
        let raw = unsafe {
            libc::socket(
                AF_PACKET_I32,
                libc::SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                i32::from(htons(ETH_P_PAE)),
            )
        };
        if raw < 0 {
            return Err(EapolError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `raw` is a fresh, exclusively-owned fd from `socket`; wrapping
        // it in `OwnedFd` gives it RAII close and sole ownership.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        bind_to_interface(&owned, ifindex)?;

        let fd = AsyncFd::new(owned).map_err(EapolError::Io)?;
        Ok(Self { fd, ifindex })
    }

    /// Await and receive one EAPOL frame (the full Ethernet frame bytes).
    ///
    /// # Errors
    /// [`EapolError::Io`] on a socket error or closed interface.
    pub async fn recv(&self) -> Result<Vec<u8>, EapolError> {
        loop {
            let mut guard = self.fd.readable().await.map_err(EapolError::Io)?;
            let outcome = guard.try_io(|inner| {
                let mut buf = vec![0u8; FRAME_CAP];
                // SAFETY: `buf` is valid for `buf.len()` writes; `recv` writes at
                // most that many bytes and returns the count (or -1).
                let n = unsafe {
                    libc::recv(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                buf.truncate(usize::try_from(n).unwrap_or(0));
                Ok(buf)
            });
            match outcome {
                Ok(result) => return result.map_err(EapolError::Io),
                Err(_would_block) => {}
            }
        }
    }

    /// Send a complete EAPOL Ethernet frame out the bound interface. The frame
    /// includes its own L2 header (built by `pacp`); for `SOCK_RAW` the kernel
    /// transmits that header verbatim and selects egress solely by the bound
    /// interface (`sll_ifindex`), so the destination is not supplied here.
    ///
    /// # Errors
    /// - [`EapolError::FrameTooShort`] if `frame` is shorter than an Ethernet header.
    /// - [`EapolError::Io`] on a socket error.
    pub async fn send(&self, frame: &[u8]) -> Result<(), EapolError> {
        if frame.len() < ETHERNET_HEADER_LEN {
            return Err(EapolError::FrameTooShort(frame.len()));
        }
        let dest = SockaddrLl {
            sll_family: AF_PACKET_U16,
            sll_protocol: htons(ETH_P_PAE),
            sll_ifindex: self.ifindex,
            ..SockaddrLl::default()
        };
        let addrlen = u32::try_from(core::mem::size_of::<SockaddrLl>()).unwrap_or(0);

        loop {
            let mut guard = self.fd.writable().await.map_err(EapolError::Io)?;
            let outcome = guard.try_io(|inner| {
                // SAFETY: `frame` is valid for `frame.len()` reads; `dest` is a
                // valid initialized `sockaddr_ll` of `addrlen` bytes. `sendto`
                // only reads from both and returns the count (or -1).
                let n = unsafe {
                    libc::sendto(
                        inner.get_ref().as_raw_fd(),
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                        0,
                        (&raw const dest).cast::<libc::sockaddr>(),
                        addrlen,
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match outcome {
                Ok(result) => return result.map_err(EapolError::Io),
                Err(_would_block) => {}
            }
        }
    }
}

/// Bind the socket to `ifindex` with the EAPOL protocol.
fn bind_to_interface(fd: &OwnedFd, ifindex: i32) -> Result<(), EapolError> {
    let addr = SockaddrLl {
        sll_family: AF_PACKET_U16,
        sll_protocol: htons(ETH_P_PAE),
        sll_ifindex: ifindex,
        ..SockaddrLl::default()
    };
    let addrlen = u32::try_from(core::mem::size_of::<SockaddrLl>()).unwrap_or(0);
    // SAFETY: `addr` is a valid initialized `sockaddr_ll` of `addrlen` bytes;
    // `bind` only reads it and the fd is valid and owned by `fd`.
    let ret = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            addrlen,
        )
    };
    if ret < 0 {
        return Err(EapolError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
