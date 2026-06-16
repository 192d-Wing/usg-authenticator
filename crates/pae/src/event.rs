//! The typed inputs that drive the state machine. The daemon decodes EAPOL
//! frames (via `pacp`), RADIUS replies (via `radius-client`), timer expiries,
//! and `CoA` requests into these and feeds them to `step`.

use crate::config::TimerKind;
use crate::effect::Authorization;
use pacp::eap::{EapCode, EapType};

/// An EAP packet received from the supplicant, already decoded by `pacp`. The
/// raw `packet` is carried so it can be relayed verbatim to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEap {
    /// EAP code (Request/Response/Success/Failure).
    pub code: EapCode,
    /// EAP identifier.
    pub identifier: u8,
    /// Method type, if the code carries one.
    pub eap_type: Option<EapType>,
    /// The full EAP packet bytes, for verbatim relay to RADIUS.
    pub packet: Vec<u8>,
}

/// An input event for a single `{port, MAC}` session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The port has been brought into 802.1X service for this MAC.
    Enable,
    /// Physical link came up.
    LinkUp,
    /// Physical link went down — tear the session down.
    LinkDown,
    /// EAPOL-Start from the supplicant.
    EapolStart,
    /// EAPOL-Logoff from the supplicant.
    EapolLogoff,
    /// An EAP packet from the supplicant.
    EapFromSupplicant(InboundEap),

    /// RADIUS `Access-Challenge` — relay the inner EAP back to the supplicant.
    AccessChallenge {
        /// The EAP request the server wants delivered to the supplicant.
        eap: Vec<u8>,
    },
    /// RADIUS `Access-Accept` — authorize the session.
    AccessAccept {
        /// Parsed authorization parameters.
        authorization: Authorization,
        /// The EAP-Success to relay to the supplicant, if the Accept carried one.
        eap: Option<Vec<u8>>,
    },
    /// RADIUS `Access-Reject` — deny.
    AccessReject {
        /// The EAP-Failure to relay to the supplicant, if the Reject carried one.
        eap: Option<Vec<u8>>,
    },
    /// Every configured authentication server is unreachable.
    ServerUnreachable,

    /// A previously-armed timer expired.
    Timer(TimerKind),

    /// `CoA` `Disconnect-Request` — terminate the session (RFC 5176).
    CoaDisconnect,
    /// `CoA` `Request` asking for re-authentication.
    CoaReauthenticate,
    /// `CoA` `Request` changing authorization in place (no re-auth).
    CoaAuthorize {
        /// The new authorization to apply.
        authorization: Authorization,
    },
}
