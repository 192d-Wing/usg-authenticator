//! Parsing RADIUS replies into PAE events, and verifying the Response
//! Authenticator that binds a reply to our request.

use crate::consts::{MAX_TAG_OCTET, TUNNEL_PRIVATE_GROUP_ID};
use crate::eap_message;
use crate::error::RadiusClientError;
use pae::{Authorization, Event};
use radius_proto::{Attribute, AttributeType, Code, Packet, verify_response_authenticator};

/// Verify a reply's Response Authenticator against the request we sent
/// (RFC 2865). The daemon MUST call this before [`parse_reply`]; a reply that
/// fails is discarded (fail closed).
///
/// Byte-level `Message-Authenticator` verification is performed by the transport
/// layer, which holds the raw bytes and the attribute offset.
#[must_use]
pub fn verify_reply(reply: &Packet, request_authenticator: &[u8; 16], secret: &[u8]) -> bool {
    verify_response_authenticator(reply, request_authenticator, secret)
}

/// Map a RADIUS reply to the PAE event it drives.
///
/// # Errors
/// - [`RadiusClientError::MissingEapMessage`] if an `Access-Challenge` has no EAP.
/// - [`RadiusClientError::UnexpectedReplyCode`] for any non-auth reply code.
pub fn parse_reply(reply: &Packet) -> Result<Event, RadiusClientError> {
    match reply.code {
        Code::AccessChallenge => {
            let eap = eap_message::reassemble(reply);
            if eap.is_empty() {
                return Err(RadiusClientError::MissingEapMessage);
            }
            Ok(Event::AccessChallenge { eap })
        }
        Code::AccessAccept => Ok(Event::AccessAccept {
            authorization: parse_authorization(reply),
            eap: non_empty(eap_message::reassemble(reply)),
        }),
        Code::AccessReject => Ok(Event::AccessReject {
            eap: non_empty(eap_message::reassemble(reply)),
        }),
        other => Err(RadiusClientError::UnexpectedReplyCode(other.as_u8())),
    }
}

/// Extract the authorization parameters usg-radius can emit (SERVER-CONTRACT §3).
#[must_use]
pub fn parse_authorization(reply: &Packet) -> Authorization {
    Authorization {
        vlan: reply
            .find_attribute(TUNNEL_PRIVATE_GROUP_ID)
            .map(|a| parse_tunnel_group(&a.value)),
        filter_id: reply
            .find_attribute(AttributeType::FilterId as u8)
            .map(|a| String::from_utf8_lossy(&a.value).into_owned()),
        session_timeout: reply
            .find_attribute(AttributeType::SessionTimeout as u8)
            .and_then(read_u32),
        class: reply
            .find_attribute(AttributeType::Class as u8)
            .map(|a| a.value.clone()),
    }
}

/// Decode an RFC 2868 `Tunnel-Private-Group-ID`: a leading tag octet (≤ 0x1F)
/// is stripped; the remainder is the ASCII VLAN id/name.
fn parse_tunnel_group(value: &[u8]) -> String {
    let body = match value.first() {
        Some(&tag) if tag <= MAX_TAG_OCTET => value.get(1..).unwrap_or(&[]),
        _ => value,
    };
    String::from_utf8_lossy(body).into_owned()
}

/// Read a 4-octet integer attribute as a big-endian `u32`.
fn read_u32(attr: &Attribute) -> Option<u32> {
    <[u8; 4]>::try_from(attr.value.as_slice())
        .ok()
        .map(u32::from_be_bytes)
}

fn non_empty(v: Vec<u8>) -> Option<Vec<u8>> {
    if v.is_empty() { None } else { Some(v) }
}
