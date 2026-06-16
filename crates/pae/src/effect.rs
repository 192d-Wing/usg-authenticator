//! The typed side effects the state machine asks the daemon to perform. The
//! machine itself does no I/O: `step` returns an ordered list of these, and the
//! daemon (a later milestone) executes them against EAPOL, RADIUS, and the
//! `SONiC` dataplane.

use crate::config::TimerKind;
use pacp::ethernet::MacAddr;

/// Authorization parameters granted by the authentication server, parsed from a
/// RADIUS `Access-Accept` by `radius-client` (a later milestone). Held here so
/// the machine can re-apply it on CoA-authorize and re-authentication.
///
/// Per `SERVER-CONTRACT.md` §3 these are exactly what usg-radius can emit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authorization {
    /// `Tunnel-Private-Group-ID` — VLAN id or name (ASCII, opaque here).
    pub vlan: Option<String>,
    /// `Filter-Id` — the name of a pre-provisioned ACL to bind.
    pub filter_id: Option<String>,
    /// `Session-Timeout` in seconds, if present.
    pub session_timeout: Option<u32>,
    /// `Class` — opaque server correlation handle, echoed in accounting/CoA.
    pub class: Option<Vec<u8>>,
}

/// Why a fallback VLAN is being applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// No supplicant appeared and MAB did not succeed.
    Guest,
    /// The server returned `Access-Reject`.
    AuthFail,
    /// The authentication server was unreachable (deliberate fail-open).
    Critical,
}

/// The authorization state to program for this `{port, MAC}` on the dataplane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortAuthorization {
    /// Authorized with the server-granted parameters.
    Authorized(Authorization),
    /// Restrictive: only EAPOL is permitted; all other traffic dropped.
    Unauthorized,
    /// A fallback VLAN with a stated reason (guest/auth-fail/critical).
    Fallback {
        /// Why the fallback is applied.
        reason: FallbackReason,
        /// The VLAN to place the port in, if one is configured for the reason.
        vlan: Option<String>,
    },
}

/// Reason a session ended — becomes a RADIUS `Acct-Terminate-Cause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateCause {
    /// Supplicant sent EAPOL-Logoff.
    SupplicantLogoff,
    /// Port link went down.
    PortLinkDown,
    /// RADIUS `Session-Timeout` expired.
    SessionTimeout,
    /// Server-initiated CoA-Disconnect / administrative reset.
    AdminReset,
    /// Re-authentication failed.
    ReauthFailure,
}

/// RADIUS accounting lifecycle trigger; `radius-client` builds the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcctTrigger {
    /// Session authorized — send Accounting-Start.
    Start,
    /// Session ended — send Accounting-Stop with the cause.
    Stop(TerminateCause),
}

/// A single side effect for the daemon to perform, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Send this EAP packet to the supplicant (the daemon wraps it in
    /// EAPOL-EAP and an Ethernet frame). Used for the originated
    /// Request/Identity and for relayed server challenges / Success / Failure.
    TxEapToSupplicant(Vec<u8>),
    /// Relay this EAP response to the authentication server; `radius-client`
    /// wraps it in an `Access-Request`.
    ToAuthServer {
        /// The EAP packet to encapsulate.
        eap: Vec<u8>,
    },
    /// Begin MAC Authentication Bypass for this MAC (a `Call-Check`
    /// Access-Request with no EAP).
    StartMab {
        /// The endpoint MAC to authenticate by address.
        mac: MacAddr,
    },
    /// Program the dataplane with the new authorization for this `{port, MAC}`.
    SetAuthorization(PortAuthorization),
    /// Arm a timer; the daemon resolves the duration from [`crate::config::Timers`].
    ArmTimer(TimerKind),
    /// Cancel a specific armed timer.
    CancelTimer(TimerKind),
    /// Cancel every armed timer for this session (used on teardown).
    CancelAllTimers,
    /// Fire a RADIUS accounting trigger.
    Accounting(AcctTrigger),
}
