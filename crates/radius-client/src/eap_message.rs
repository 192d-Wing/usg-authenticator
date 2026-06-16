//! `EAP-Message` (RFC 3579 §3.1) fragmentation and reassembly.
//!
//! We fragment and reassemble the **raw** EAP bytes rather than round-tripping
//! through `radius_proto::EapPacket`, so the inner method content (the TEAP/TLS
//! tunnel) is relayed byte-for-byte and never normalized by a re-encode. The
//! authenticator is a pass-through: it must not alter what it forwards.

use crate::consts::{EAP_MESSAGE, MAX_ATTR_VALUE};
use crate::error::RadiusClientError;
use radius_proto::{Attribute, Packet};

/// Split `eap` into ≤253-octet `EAP-Message` attributes appended to `packet`,
/// preserving order. An empty `eap` adds nothing.
///
/// # Errors
/// Propagates [`RadiusClientError::Proto`] if an attribute cannot be built.
pub fn fragment_into(packet: &mut Packet, eap: &[u8]) -> Result<(), RadiusClientError> {
    for chunk in eap.chunks(MAX_ATTR_VALUE) {
        packet.add_attribute(Attribute::new(EAP_MESSAGE, chunk.to_vec())?);
    }
    Ok(())
}

/// Concatenate every `EAP-Message` attribute, in order, into the original EAP
/// packet. Returns an empty vector if the packet carries none.
#[must_use]
pub fn reassemble(packet: &Packet) -> Vec<u8> {
    let mut out = Vec::new();
    for attr in packet.find_all_attributes(EAP_MESSAGE) {
        out.extend_from_slice(&attr.value);
    }
    out
}
