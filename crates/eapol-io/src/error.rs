//! Errors from the EAPOL raw-socket layer.

/// An `eapol-io` error.
#[derive(Debug)]
pub enum EapolError {
    /// The interface name is empty or exceeds the OS limit (`IFNAMSIZ-1`), or
    /// contains an interior NUL.
    InvalidInterfaceName(String),
    /// The interface could not be resolved to an index (`if_nametoindex`).
    InterfaceNotFound(String),
    /// A socket syscall (`socket`/`bind`/`recv`/`send`) failed. On a non-Linux
    /// host, `socket(AF_PACKET, …)` fails here — the layer only functions on
    /// Linux (SONiC).
    Io(std::io::Error),
    /// A frame too short to be a valid Ethernet frame was passed to `send`.
    FrameTooShort(usize),
}

impl core::fmt::Display for EapolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInterfaceName(n) => write!(f, "invalid interface name {n:?}"),
            Self::InterfaceNotFound(n) => write!(f, "interface {n:?} not found"),
            Self::Io(e) => write!(f, "socket I/O error: {e}"),
            Self::FrameTooShort(n) => write!(f, "frame too short to send: {n} octets"),
        }
    }
}

impl std::error::Error for EapolError {}

impl From<std::io::Error> for EapolError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
