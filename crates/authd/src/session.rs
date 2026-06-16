//! Per-`{port, MAC}` RADIUS correlation: allocates RADIUS Identifiers, echoes
//! the server's `State` across challenge rounds, builds requests (via
//! `radius-client`), and verifies+parses replies into PAE events.
//!
//! This is the orchestration the daemon's worker drives for every
//! `ToAuthServer` / `StartMab` effect; it is pure (no transport) and fully
//! tested.

use crate::error::AuthdError;
use pae::Event;
use radius_client::{
    RequestContext, access_request_eap, access_request_mab, accounting_request, extract_state,
    parse_reply, verify_reply,
};
use radius_proto::Packet;

/// The in-flight request awaiting a reply, kept so the reply can be bound to it.
#[derive(Debug, Clone, Copy)]
struct Pending {
    request_authenticator: [u8; 16],
}

/// RADIUS correlation state for one supplicant session.
#[derive(Debug, Default)]
pub struct RadiusSession {
    /// Next RADIUS Identifier to use (wraps).
    next_id: u8,
    /// The server's last `State`, echoed in the next Access-Request.
    last_state: Option<Vec<u8>>,
    /// The outstanding request, if any.
    pending: Option<Pending>,
    /// `Class` from the last Access-Accept, echoed in accounting.
    class: Option<Vec<u8>>,
}

impl RadiusSession {
    /// A fresh session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The `Class` to echo in accounting for this session, if one was granted.
    #[must_use]
    pub fn class(&self) -> Option<&[u8]> {
        self.class.as_deref()
    }

    /// Allocate the next RADIUS Identifier (wraps at 256).
    pub fn next_identifier(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Build an EAP pass-through `Access-Request`, echoing the current `State`.
    /// `request_authenticator` is a fresh random nonce
    /// (`radius_proto::generate_request_authenticator()` in production).
    ///
    /// # Errors
    /// [`AuthdError::Radius`] if the request cannot be built (e.g. bad identity).
    pub fn build_eap_request(
        &mut self,
        ctx: &RequestContext,
        identity: Option<&[u8]>,
        eap: &[u8],
        request_authenticator: [u8; 16],
        secret: &[u8],
    ) -> Result<Packet, AuthdError> {
        let id = self.next_identifier();
        self.pending = Some(Pending {
            request_authenticator,
        });
        access_request_eap(
            ctx,
            id,
            request_authenticator,
            identity,
            self.last_state.as_deref(),
            eap,
            secret,
        )
        .map_err(AuthdError::Radius)
    }

    /// Build a MAC Authentication Bypass `Access-Request`.
    ///
    /// # Errors
    /// [`AuthdError::Radius`] if the request cannot be built.
    pub fn build_mab_request(
        &mut self,
        ctx: &RequestContext,
        request_authenticator: [u8; 16],
        secret: &[u8],
    ) -> Result<Packet, AuthdError> {
        let id = self.next_identifier();
        self.pending = Some(Pending {
            request_authenticator,
        });
        access_request_mab(ctx, id, request_authenticator, secret).map_err(AuthdError::Radius)
    }

    /// Verify a reply against the outstanding request, parse it into the PAE
    /// event it drives, and remember the new `State`/`Class`.
    ///
    /// # Errors
    /// - [`AuthdError::NoPendingRequest`] if no request was outstanding.
    /// - [`AuthdError::ReplyVerificationFailed`] if integrity verification fails.
    /// - [`AuthdError::Radius`] if the reply cannot be parsed.
    pub fn handle_reply(&mut self, reply: &Packet, secret: &[u8]) -> Result<Event, AuthdError> {
        let pending = self.pending.take().ok_or(AuthdError::NoPendingRequest)?;
        if !verify_reply(reply, &pending.request_authenticator, secret) {
            return Err(AuthdError::ReplyVerificationFailed);
        }
        self.last_state = extract_state(reply);
        let event = parse_reply(reply).map_err(AuthdError::Radius)?;
        if let Event::AccessAccept { authorization, .. } = &event {
            self.class.clone_from(&authorization.class);
        }
        Ok(event)
    }

    /// Build an `Accounting-Request` of the given status, echoing `Class`.
    ///
    /// # Errors
    /// [`AuthdError::Radius`] if the request cannot be built.
    pub fn build_accounting(
        &self,
        ctx: &RequestContext,
        identifier: u8,
        trigger: pae::AcctTrigger,
        session_id: &str,
        secret: &[u8],
    ) -> Result<Packet, AuthdError> {
        accounting_request(ctx, identifier, trigger, session_id, self.class(), secret)
            .map_err(AuthdError::Radius)
    }
}
