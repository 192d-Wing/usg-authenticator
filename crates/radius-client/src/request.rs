//! Building `Access-Request` packets — both EAP pass-through and MAC
//! Authentication Bypass — with a mandatory `Message-Authenticator` (RFC 3579).

use crate::consts::{MESSAGE_AUTHENTICATOR, SERVICE_TYPE_CALL_CHECK, SERVICE_TYPE_FRAMED};
use crate::context::RequestContext;
use crate::error::RadiusClientError;
use crate::{eap_message, sanitize};
use pacp::ethernet::format_mac;
use radius_proto::{Attribute, AttributeType, Code, Packet, calculate_message_authenticator};

/// Build an EAP pass-through `Access-Request`.
///
/// `request_authenticator` is the random Request Authenticator (the daemon
/// supplies `radius_proto::generate_request_authenticator()`; tests pass a fixed
/// value). `identity` is the supplicant's EAP identity for the `User-Name`, when
/// known (the first relay); `None` omits it. `eap` is the EAP response relayed
/// verbatim. `secret` is the RADIUS shared secret (the literal `"radsec"` over
/// `RadSec`, RFC 6614 §2.3).
///
/// # Errors
/// - [`RadiusClientError::InvalidUserName`] if `identity` is non-conforming.
/// - [`RadiusClientError::Proto`] if any attribute is malformed.
pub fn access_request_eap(
    ctx: &RequestContext,
    identifier: u8,
    request_authenticator: [u8; 16],
    identity: Option<&[u8]>,
    eap: &[u8],
    secret: &[u8],
) -> Result<Packet, RadiusClientError> {
    let mut packet = Packet::new(Code::AccessRequest, identifier, request_authenticator);
    if let Some(id) = identity {
        packet.add_attribute(Attribute::string(
            AttributeType::UserName as u8,
            sanitize::user_name(id)?,
        )?);
    }
    packet.add_attribute(Attribute::integer(
        AttributeType::ServiceType as u8,
        SERVICE_TYPE_FRAMED,
    )?);
    ctx.append_nas_attributes(&mut packet)?;
    eap_message::fragment_into(&mut packet, eap)?;
    seal_message_authenticator(&mut packet, secret)?;
    Ok(packet)
}

/// Build a MAC Authentication Bypass `Access-Request`: `User-Name` and
/// `Calling-Station-Id` are the endpoint MAC, `Service-Type = Call-Check`, no EAP.
///
/// # Errors
/// Propagates [`RadiusClientError::Proto`] on a malformed attribute.
pub fn access_request_mab(
    ctx: &RequestContext,
    identifier: u8,
    request_authenticator: [u8; 16],
    secret: &[u8],
) -> Result<Packet, RadiusClientError> {
    let mut packet = Packet::new(Code::AccessRequest, identifier, request_authenticator);
    packet.add_attribute(Attribute::string(
        AttributeType::UserName as u8,
        format_mac(&ctx.calling_station),
    )?);
    packet.add_attribute(Attribute::integer(
        AttributeType::ServiceType as u8,
        SERVICE_TYPE_CALL_CHECK,
    )?);
    ctx.append_nas_attributes(&mut packet)?;
    seal_message_authenticator(&mut packet, secret)?;
    Ok(packet)
}

/// Append a `Message-Authenticator` (RFC 3579 §3.2): insert a 16-zero
/// placeholder, encode, HMAC over those bytes, then write the MAC back into the
/// attribute. The caller encodes the returned packet for transport.
///
/// # Errors
/// Propagates [`RadiusClientError::Proto`] if the placeholder cannot be added or
/// the packet cannot be encoded.
fn seal_message_authenticator(packet: &mut Packet, secret: &[u8]) -> Result<(), RadiusClientError> {
    packet.add_attribute(Attribute::new(MESSAGE_AUTHENTICATOR, vec![0u8; 16])?);
    let encoded = packet.encode()?;
    let mac = calculate_message_authenticator(&encoded, secret);
    for attr in &mut packet.attributes {
        if attr.attr_type == MESSAGE_AUTHENTICATOR {
            attr.value = mac.to_vec();
            break;
        }
    }
    Ok(())
}
