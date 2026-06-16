//! Building `Accounting-Request` packets (RFC 2866) for session start/stop. The
//! `Acct-Session-Id` + `Calling-Station-Id` + `NAS-Port-Id` triple is the key a
//! future `CoA` targets (SERVER-CONTRACT.md §4).

use crate::context::RequestContext;
use crate::error::RadiusClientError;
use pae::{AcctTrigger, TerminateCause};
use radius_proto::{
    AcctStatusType, AcctTerminateCause, Attribute, AttributeType, Code, Packet,
    calculate_accounting_request_authenticator,
};

/// Build an `Accounting-Request` for the given lifecycle `trigger`.
///
/// `class` is the opaque RADIUS `Class` from the `Access-Accept`, echoed for
/// server-side correlation. The accounting Request Authenticator (RFC 2866) is
/// computed and set. `secret` is the shared secret (`"radsec"` over `RadSec`).
///
/// # Errors
/// Propagates [`RadiusClientError::Proto`] on a malformed attribute.
pub fn accounting_request(
    ctx: &RequestContext,
    identifier: u8,
    trigger: AcctTrigger,
    session_id: &str,
    class: Option<&[u8]>,
    secret: &[u8],
) -> Result<Packet, RadiusClientError> {
    let status = match trigger {
        AcctTrigger::Start => AcctStatusType::Start,
        AcctTrigger::Stop(_) => AcctStatusType::Stop,
    };

    // Built with a zero authenticator; the accounting authenticator is computed
    // over exactly that form and written back below.
    let mut packet = Packet::new(Code::AccountingRequest, identifier, [0u8; 16]);
    packet.add_attribute(Attribute::integer(
        AttributeType::AcctStatusType as u8,
        status.as_u32(),
    )?);
    packet.add_attribute(Attribute::string(
        AttributeType::AcctSessionId as u8,
        session_id,
    )?);
    ctx.append_nas_attributes(&mut packet)?;
    if let Some(class) = class {
        packet.add_attribute(Attribute::new(AttributeType::Class as u8, class.to_vec())?);
    }
    if let AcctTrigger::Stop(cause) = trigger {
        packet.add_attribute(Attribute::integer(
            AttributeType::AcctTerminateCause as u8,
            terminate_cause(cause).as_u32(),
        )?);
    }

    packet.authenticator = calculate_accounting_request_authenticator(&packet, secret);
    Ok(packet)
}

/// Map a PAE [`TerminateCause`] to the RADIUS `Acct-Terminate-Cause` (RFC 2866).
fn terminate_cause(cause: TerminateCause) -> AcctTerminateCause {
    match cause {
        TerminateCause::SupplicantLogoff => AcctTerminateCause::UserRequest,
        TerminateCause::PortLinkDown => AcctTerminateCause::LostCarrier,
        TerminateCause::SessionTimeout => AcctTerminateCause::SessionTimeout,
        TerminateCause::AdminReset => AcctTerminateCause::AdminReset,
        TerminateCause::ReauthFailure => AcctTerminateCause::NasRequest,
    }
}
