//! IEEE 802.1X-2020 EAPOL/PACP frame codec for the authenticator (NAS).
//!
//! Milestone 1 provides the **EAPOL/PACP codec**: a bounds-checked, panic-free
//! decoder/encoder for the Ethernet+EAPOL framing a supplicant sends, plus a
//! read-only view of the encapsulated EAP packet header. Later milestones add
//! the authenticator PAE state machine (`pae`), the RADIUS client
//! (`radius-client`), and the `SONiC` enforcement backend (`enforce-sonic`).
//!
//! Design rules for this crate:
//! - **Pure**: no I/O, no OS calls, no `unsafe`.
//! - **Panic-free on input**: every decode path returns [`error::PacpError`];
//!   no `unwrap`/`expect`/slice-index can abort on malformed bytes.
//! - **Structure, not policy**: the codec validates framing and length fields.
//!   Deciding what an EAPOL-Start or an unknown packet type *means* is the
//!   `pae` state machine's job in a later milestone.
//! - **Pass-through**: EAP method content is never interpreted; the EAP body is
//!   relayed verbatim into a RADIUS `EAP-Message`. [`eap`] reads only the header.
#![forbid(unsafe_code)]

pub mod eap;
pub mod error;
pub mod ethernet;
pub mod pdu;

pub use error::PacpError;

/// A fully-decoded inbound EAPOL frame: the Ethernet header and the EAPOL PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolFrame {
    /// The Ethernet header (source MAC → `Calling-Station-Id`).
    pub ethernet: ethernet::EthernetHeader,
    /// The decoded EAPOL PDU.
    pub pdu: pdu::EapolPdu,
}

/// Decode a raw Ethernet frame (as delivered by `AF_PACKET`) into an
/// [`EapolFrame`], requiring the `EtherType` to be EAPOL.
///
/// This is the one-shot entry point the `eapol-io` reactor will call per
/// received frame.
///
/// # Errors
/// - [`PacpError::TruncatedEthernet`] / [`PacpError::NotEapol`] from the L2 layer.
/// - [`PacpError::TruncatedEapolHeader`] / [`PacpError::TruncatedEapolBody`] from EAPOL.
pub fn decode_frame(buf: &[u8]) -> Result<EapolFrame, PacpError> {
    let frame = ethernet::decode_eapol_frame(buf)?;
    let pdu = pdu::EapolPdu::decode(frame.payload)?;
    Ok(EapolFrame {
        ethernet: frame.header,
        pdu,
    })
}
