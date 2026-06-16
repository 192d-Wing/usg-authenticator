//! The Ethernet II framing that carries EAPOL on the wire.
//!
//! Frames arrive from an `AF_PACKET`/`SOCK_RAW` socket (the `eapol-io` crate in
//! a later milestone) as a full Ethernet II frame: `dst | src | EtherType | payload`.
//! This module decodes/encodes that header and hands the EAPOL PDU off to
//! [`crate::pdu`]. The 4-octet FCS is not present on a captured frame, and short
//! frames are zero-padded to 60 octets — so the payload may be **longer** than
//! the EAPOL PDU; the EAPOL layer's own length field is authoritative.

use super::error::PacpError;

/// Octets in an Ethernet II header: `dst(6) | src(6) | EtherType(2)`.
pub const HEADER_LEN: usize = 14;

/// A 48-bit MAC address.
pub type MacAddr = [u8; 6];

/// `EtherType` for EAPOL (IEEE Std 802.1X), `0x888E`.
pub const ETHERTYPE_EAPOL: u16 = 0x888E;

/// PAE group address — "Nearest non-TPMR Bridge" (`01:80:C2:00:00:03`), the
/// canonical destination a supplicant uses for EAPOL on a wired LAN (IEEE
/// 802.1X-2020 Table 11-1).
pub const PAE_GROUP_ADDR: MacAddr = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// "Nearest Customer Bridge" group address (`01:80:C2:00:00:00`).
pub const NEAREST_CUSTOMER_BRIDGE_ADDR: MacAddr = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];

/// "Nearest Bridge" group address (`01:80:C2:00:00:0E`).
pub const NEAREST_BRIDGE_ADDR: MacAddr = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

/// A decoded Ethernet II header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination MAC (a PAE group address for supplicant-originated EAPOL).
    pub dst: MacAddr,
    /// Source MAC — the supplicant's address; becomes `Calling-Station-Id`.
    pub src: MacAddr,
    /// `EtherType`. For EAPOL frames this is [`ETHERTYPE_EAPOL`].
    pub ethertype: u16,
}

/// The result of decoding an Ethernet frame: the header plus the borrowed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// The decoded header.
    pub header: EthernetHeader,
    /// The payload following the header (the EAPOL PDU, possibly with trailing
    /// Ethernet padding — the EAPOL length field is authoritative).
    pub payload: &'a [u8],
}

impl EthernetHeader {
    /// Format `src` as the IETF-canonical `AA-BB-CC-DD-EE-FF` string used for
    /// `Calling-Station-Id` (SERVER-CONTRACT.md §2).
    #[must_use]
    pub fn src_station_id(&self) -> String {
        format_mac(&self.src)
    }

    /// Serialize the header onto `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.ethertype.to_be_bytes());
    }
}

/// Format a MAC as upper-case hyphen-separated `AA-BB-CC-DD-EE-FF`.
#[must_use]
pub fn format_mac(mac: &MacAddr) -> String {
    let mut out = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        use core::fmt::Write as _;
        if i != 0 {
            out.push('-');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Decode an Ethernet II frame, returning the header and the borrowed payload.
///
/// This does **not** require the `EtherType` to be EAPOL — callers that only want
/// EAPOL should check [`EthernetHeader::ethertype`] or use
/// [`decode_eapol_frame`].
///
/// # Errors
/// - [`PacpError::TruncatedEthernet`] if fewer than [`HEADER_LEN`] octets exist.
pub fn decode_frame(buf: &[u8]) -> Result<EthernetFrame<'_>, PacpError> {
    // Destructure the fixed 14-octet header in one fallible step (the same idiom
    // as `pdu`/`eap`): the array conversion is the bounds check, so there are no
    // unreachable per-field defaults that could fail open to a zero MAC.
    let [d0, d1, d2, d3, d4, d5, s0, s1, s2, s3, s4, s5, e0, e1] = buf
        .get(..HEADER_LEN)
        .and_then(|s| <[u8; HEADER_LEN]>::try_from(s).ok())
        .ok_or(PacpError::TruncatedEthernet {
            available: buf.len(),
        })?;

    // `HEADER_LEN <= buf.len()` was just proven, so this slice is in-bounds.
    let payload = buf.get(HEADER_LEN..).unwrap_or(&[]);
    Ok(EthernetFrame {
        header: EthernetHeader {
            dst: [d0, d1, d2, d3, d4, d5],
            src: [s0, s1, s2, s3, s4, s5],
            ethertype: u16::from_be_bytes([e0, e1]),
        },
        payload,
    })
}

/// Decode an Ethernet frame and require it to carry EAPOL.
///
/// # Errors
/// - [`PacpError::TruncatedEthernet`] on a short header.
/// - [`PacpError::NotEapol`] if the `EtherType` is not [`ETHERTYPE_EAPOL`].
pub fn decode_eapol_frame(buf: &[u8]) -> Result<EthernetFrame<'_>, PacpError> {
    let frame = decode_frame(buf)?;
    if frame.header.ethertype != ETHERTYPE_EAPOL {
        return Err(PacpError::NotEapol {
            ethertype: frame.header.ethertype,
        });
    }
    Ok(frame)
}
