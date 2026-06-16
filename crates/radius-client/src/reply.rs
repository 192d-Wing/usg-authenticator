//! Parsing RADIUS replies into PAE events, verifying the integrity fields that
//! bind a reply to our request, and extracting the `State` to echo next round.

use crate::consts::{
    EAP_MESSAGE, MAX_TAG_OCTET, MESSAGE_AUTHENTICATOR, STATE, TUNNEL_MEDIUM_802,
    TUNNEL_MEDIUM_TYPE, TUNNEL_PRIVATE_GROUP_ID, TUNNEL_TYPE, TUNNEL_TYPE_VLAN,
};
use crate::eap_message;
use crate::error::RadiusClientError;
use pae::{Authorization, Event};
use radius_proto::{
    Attribute, AttributeType, Code, Packet, calculate_message_authenticator,
    verify_response_authenticator,
};

/// Verify a reply's integrity against the request we sent (fail closed). The
/// daemon MUST call this before [`parse_reply`]; a reply that fails is discarded.
///
/// Checks both:
/// - the Response Authenticator (RFC 2865), and
/// - the `Message-Authenticator` (RFC 3579 §3.2): required when the reply
///   carries `EAP-Message`, and verified whenever present. The reply's HMAC is
///   computed with our Request Authenticator in the authenticator field, so we
///   substitute it before recomputing.
#[must_use]
pub fn verify_reply(reply: &Packet, request_authenticator: &[u8; 16], secret: &[u8]) -> bool {
    if !verify_response_authenticator(reply, request_authenticator, secret) {
        return false;
    }
    verify_message_authenticator(reply, request_authenticator, secret)
}

fn verify_message_authenticator(
    reply: &Packet,
    request_authenticator: &[u8; 16],
    secret: &[u8],
) -> bool {
    let has_eap = reply.find_attribute(EAP_MESSAGE).is_some();
    let Some(attr) = reply.find_attribute(MESSAGE_AUTHENTICATOR) else {
        // RFC 3579 §3.2: a reply carrying EAP-Message MUST include a
        // Message-Authenticator. Absent it, fail closed for EAP replies.
        return !has_eap;
    };
    if attr.value.len() != 16 {
        return false;
    }
    let received = attr.value.clone();

    // Recompute over the reply with our Request Authenticator substituted and the
    // Message-Authenticator zeroed.
    let mut copy = reply.clone();
    copy.authenticator = *request_authenticator;
    for a in &mut copy.attributes {
        if a.attr_type == MESSAGE_AUTHENTICATOR {
            a.value = vec![0u8; 16];
        }
    }
    let Ok(bytes) = copy.encode() else {
        return false;
    };
    calculate_message_authenticator(&bytes, secret).as_slice() == received.as_slice()
}

/// The `State` attribute (RFC 2865 §5.24) to echo in the next `Access-Request`.
#[must_use]
pub fn extract_state(reply: &Packet) -> Option<Vec<u8>> {
    reply.find_attribute(STATE).map(|a| a.value.clone())
}

/// Map a RADIUS reply to the PAE event it drives.
///
/// # Errors
/// - [`RadiusClientError::MissingEapMessage`] if an `Access-Challenge` has no EAP.
/// - [`RadiusClientError::MalformedVlanAssignment`] if an `Access-Accept` VLAN is
///   not a well-formed RFC 3580 group.
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
            authorization: parse_authorization(reply)?,
            eap: non_empty(eap_message::reassemble(reply)),
        }),
        Code::AccessReject => Ok(Event::AccessReject {
            eap: non_empty(eap_message::reassemble(reply)),
        }),
        other => Err(RadiusClientError::UnexpectedReplyCode(other.as_u8())),
    }
}

/// Extract the authorization parameters usg-radius can emit (SERVER-CONTRACT §3).
///
/// # Errors
/// [`RadiusClientError::MalformedVlanAssignment`] if a `Tunnel-Private-Group-ID`
/// is present without `Tunnel-Type = VLAN(13)` and `Tunnel-Medium-Type = 802(6)`,
/// or its group id is empty — we refuse to apply a malformed VLAN (fail closed).
pub fn parse_authorization(reply: &Packet) -> Result<Authorization, RadiusClientError> {
    let vlan = match reply.find_attribute(TUNNEL_PRIVATE_GROUP_ID) {
        Some(attr) => Some(parse_vlan(reply, &attr.value)?),
        None => None,
    };
    Ok(Authorization {
        vlan,
        filter_id: reply
            .find_attribute(AttributeType::FilterId as u8)
            .map(|a| String::from_utf8_lossy(&a.value).into_owned()),
        session_timeout: reply
            .find_attribute(AttributeType::SessionTimeout as u8)
            .and_then(read_u32),
        class: reply
            .find_attribute(AttributeType::Class as u8)
            .map(|a| a.value.clone()),
    })
}

/// Validate the RFC 3580 VLAN group and decode the `Tunnel-Private-Group-ID`.
fn parse_vlan(reply: &Packet, group_value: &[u8]) -> Result<String, RadiusClientError> {
    // RFC 3580 §3.1: a VLAN assignment requires Tunnel-Type=13 and
    // Tunnel-Medium-Type=6. Require both to be present and correct.
    let tunnel_type = reply.find_attribute(TUNNEL_TYPE).and_then(read_tagged_u32);
    let medium = reply
        .find_attribute(TUNNEL_MEDIUM_TYPE)
        .and_then(read_tagged_u32);
    if tunnel_type != Some(TUNNEL_TYPE_VLAN) || medium != Some(TUNNEL_MEDIUM_802) {
        return Err(RadiusClientError::MalformedVlanAssignment);
    }
    // RFC 2868 §3.6: a leading tag octet (0x01..=0x1F) precedes the group id.
    let body = match group_value.first() {
        Some(&tag) if (0x01..=MAX_TAG_OCTET).contains(&tag) => group_value.get(1..).unwrap_or(&[]),
        _ => group_value,
    };
    if body.is_empty() {
        return Err(RadiusClientError::MalformedVlanAssignment);
    }
    Ok(String::from_utf8_lossy(body).into_owned())
}

/// Read a 4-octet integer attribute as a big-endian `u32`.
fn read_u32(attr: &Attribute) -> Option<u32> {
    <[u8; 4]>::try_from(attr.value.as_slice())
        .ok()
        .map(u32::from_be_bytes)
}

/// Read an RFC 2868 tagged integer `[tag, hi, mid, lo]` as its `u32` value,
/// ignoring the tag octet.
fn read_tagged_u32(attr: &Attribute) -> Option<u32> {
    match *attr.value.as_slice() {
        [_tag, hi, mid, lo] => Some(u32::from_be_bytes([0, hi, mid, lo])),
        _ => None,
    }
}

fn non_empty(v: Vec<u8>) -> Option<Vec<u8>> {
    if v.is_empty() { None } else { Some(v) }
}
