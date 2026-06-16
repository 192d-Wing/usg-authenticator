//! The per-`{port, MAC}` authenticator state machine (IEEE 802.1X-2020 §8/§12,
//! the merged authenticator-PAE + backend-authentication behavior of
//! DESIGN.md §5.1).
//!
//! Pure and deterministic: [`PortSession::step`] takes one [`Event`] plus the
//! port [`PaeConfig`] and returns an ordered list of [`Effect`]s. There is no
//! clock and no I/O — the daemon owns both. Every unhandled `(state, event)`
//! pair is a safe no-op (empty effect list); the only way to authorize a port
//! is the explicit `Access-Accept` path, so the machine fails closed.

use crate::config::{HostMode, PaeConfig, TimerKind};
use crate::effect::{
    AcctTrigger, Authorization, Effect, FallbackReason, PortAuthorization, TerminateCause,
};
use crate::event::Event;
use pacp::eap::{self, EapCode};
use pacp::ethernet::MacAddr;

/// Which credential path is in flight for the current attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    /// 802.1X / EAP.
    Dot1x,
    /// MAC Authentication Bypass.
    Mab,
}

/// The session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not yet brought into service.
    New,
    /// Soliciting an identity (EAP-Request/Identity outstanding) or falling
    /// through to MAB/guest on `tx-period` expiry.
    Connecting,
    /// An Access-Request is outstanding; awaiting the server.
    AuthServer,
    /// A server challenge was relayed; awaiting the supplicant.
    Authenticating,
    /// Authorized.
    Authenticated,
    /// Held after a failure; retries after the quiet period.
    Held,
    /// A fallback VLAN is active (guest / auth-fail / critical).
    Fallback(FallbackReason),
}

/// One authenticator session for a single supplicant MAC on a port.
#[derive(Debug, Clone)]
pub struct PortSession {
    mac: MacAddr,
    state: State,
    auth_kind: AuthKind,
    /// EAP Identifier for the next originated Request/Identity.
    eap_id: u8,
    /// EAP-Request/Identity transmissions in the current connecting attempt.
    tx_count: u32,
    /// Last granted authorization, retained for re-auth and CoA-authorize.
    authz: Option<Authorization>,
    /// Whether an accounting session is currently open (gates Start/Stop and
    /// distinguishes a re-auth failure from a first-attempt reject).
    accounting_open: bool,
}

impl PortSession {
    /// Create an idle session for `mac`. No effects until [`Event::Enable`].
    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            state: State::New,
            auth_kind: AuthKind::Dot1x,
            eap_id: 0,
            tx_count: 0,
            authz: None,
            accounting_open: false,
        }
    }

    /// The MAC this session authenticates.
    #[must_use]
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// The current state (primarily for tests and diagnostics).
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the session currently holds an open (authorized) session.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.state == State::Authenticated
    }

    /// Whether the in-flight (or last) attempt used MAC Authentication Bypass
    /// rather than 802.1X — affects the RADIUS `Acct-Authentic` the daemon sets.
    #[must_use]
    pub fn is_mab(&self) -> bool {
        self.auth_kind == AuthKind::Mab
    }

    /// Advance the machine by one event, returning the effects to perform.
    pub fn step(&mut self, event: Event, cfg: &PaeConfig) -> Vec<Effect> {
        // Events that apply in (almost) any state come first.
        match event {
            Event::LinkDown => return self.teardown(TerminateCause::PortLinkDown),
            Event::CoaDisconnect => return self.teardown(TerminateCause::AdminReset),
            Event::CoaAuthorize { authorization } => return self.coa_authorize(authorization),
            Event::CoaReauthenticate => {
                if self.state == State::Authenticated {
                    return self.begin_reauth();
                }
                return Vec::new();
            }
            Event::Enable => return self.enable(),
            _ => {}
        }

        match self.state {
            State::Connecting => self.in_connecting(event, cfg),
            State::AuthServer => self.in_auth_server(event, cfg),
            State::Authenticating => self.in_authenticating(event, cfg),
            State::Authenticated => self.in_authenticated(event),
            State::Held => self.in_held(event),
            State::Fallback(_) => self.in_fallback(event),
            State::New => Vec::new(),
        }
    }

    // ---- state handlers ----

    fn enable(&mut self) -> Vec<Effect> {
        self.authz = None;
        self.accounting_open = false;
        self.auth_kind = AuthKind::Dot1x;
        self.tx_count = 1;
        self.state = State::Connecting;
        let mut fx = vec![Effect::SetAuthorization(PortAuthorization::Unauthorized)];
        fx.extend(self.send_identity());
        fx
    }

    fn in_connecting(&mut self, event: Event, cfg: &PaeConfig) -> Vec<Effect> {
        match event {
            Event::EapolStart | Event::LinkUp => self.send_identity(),
            Event::Timer(TimerKind::TxPeriod) => {
                if self.tx_count < cfg.max_reauth_req {
                    self.tx_count = self.tx_count.saturating_add(1);
                    self.send_identity()
                } else {
                    self.no_supplicant(cfg)
                }
            }
            Event::EapFromSupplicant(eap) if eap.code == EapCode::Response => {
                self.auth_kind = AuthKind::Dot1x;
                self.state = State::AuthServer;
                vec![
                    Effect::CancelTimer(TimerKind::TxPeriod),
                    Effect::ToAuthServer { eap: eap.packet },
                    Effect::ArmTimer(TimerKind::ServerTimeout),
                ]
            }
            Event::EapolLogoff => self.teardown(TerminateCause::SupplicantLogoff),
            _ => Vec::new(),
        }
    }

    fn in_auth_server(&mut self, event: Event, cfg: &PaeConfig) -> Vec<Effect> {
        match event {
            Event::AccessChallenge { eap } => {
                self.state = State::Authenticating;
                vec![
                    Effect::CancelTimer(TimerKind::ServerTimeout),
                    Effect::TxEapToSupplicant(eap),
                    Effect::ArmTimer(TimerKind::SuppTimeout),
                ]
            }
            Event::AccessAccept { authorization, eap } => self.authorize(authorization, eap, cfg),
            Event::AccessReject { eap } => self.reject(eap, cfg),
            Event::ServerUnreachable | Event::Timer(TimerKind::ServerTimeout) => {
                self.server_unreachable(cfg)
            }
            Event::EapolLogoff => self.teardown(TerminateCause::SupplicantLogoff),
            _ => Vec::new(),
        }
    }

    fn in_authenticating(&mut self, event: Event, _cfg: &PaeConfig) -> Vec<Effect> {
        match event {
            Event::EapFromSupplicant(eap) if eap.code == EapCode::Response => {
                self.state = State::AuthServer;
                vec![
                    Effect::CancelTimer(TimerKind::SuppTimeout),
                    Effect::ToAuthServer { eap: eap.packet },
                    Effect::ArmTimer(TimerKind::ServerTimeout),
                ]
            }
            Event::Timer(TimerKind::SuppTimeout) => {
                if self.accounting_open {
                    self.teardown(TerminateCause::ReauthFailure)
                } else {
                    self.hold()
                }
            }
            Event::EapolStart => {
                self.state = State::Connecting;
                let mut fx = vec![Effect::CancelTimer(TimerKind::SuppTimeout)];
                fx.extend(self.send_identity());
                fx
            }
            Event::EapolLogoff => self.teardown(TerminateCause::SupplicantLogoff),
            _ => Vec::new(),
        }
    }

    // `event` is taken by value for signature uniformity with the other
    // state handlers (some of which move owned EAP bytes out of the event).
    #[allow(clippy::needless_pass_by_value)]
    fn in_authenticated(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::Timer(TimerKind::Reauth) | Event::EapolStart => self.begin_reauth(),
            Event::EapolLogoff => self.teardown(TerminateCause::SupplicantLogoff),
            Event::Timer(TimerKind::SessionTimeout) => {
                // SERVER-CONTRACT G-3: usg-radius emits no Termination-Action, so
                // Session-Timeout means full de-auth (RFC 3580 §3.18). Tear down,
                // then immediately re-solicit so a still-present supplicant can
                // re-authenticate.
                let mut fx = self.teardown(TerminateCause::SessionTimeout);
                self.tx_count = 1;
                self.state = State::Connecting;
                fx.extend(self.send_identity());
                fx
            }
            _ => Vec::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn in_held(&mut self, event: Event) -> Vec<Effect> {
        match event {
            Event::Timer(TimerKind::Held) | Event::EapolStart => {
                self.tx_count = 1;
                self.state = State::Connecting;
                let mut fx = vec![Effect::CancelTimer(TimerKind::Held)];
                fx.extend(self.send_identity());
                fx
            }
            _ => Vec::new(),
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn in_fallback(&mut self, event: Event) -> Vec<Effect> {
        match event {
            // A supplicant appearing preempts a guest/critical fallback.
            Event::EapolStart => {
                self.tx_count = 1;
                self.state = State::Connecting;
                self.send_identity()
            }
            // Periodic retry of the authentication server while in critical VLAN.
            Event::Timer(TimerKind::ServerTimeout)
                if self.state == State::Fallback(FallbackReason::Critical) =>
            {
                self.tx_count = 1;
                self.state = State::Connecting;
                self.send_identity()
            }
            _ => Vec::new(),
        }
    }

    // ---- shared transitions ----

    /// Emit an EAP-Request/Identity with a fresh Identifier and arm `tx-period`.
    fn send_identity(&mut self) -> Vec<Effect> {
        self.eap_id = self.eap_id.wrapping_add(1);
        vec![
            Effect::TxEapToSupplicant(eap::request_identity(self.eap_id).to_vec()),
            Effect::ArmTimer(TimerKind::TxPeriod),
        ]
    }

    /// No supplicant within `max_reauth_req` prompts: try MAB, else guest VLAN,
    /// else hold the (closed) port.
    fn no_supplicant(&mut self, cfg: &PaeConfig) -> Vec<Effect> {
        // If this happened during a re-authentication (a session is already
        // open), the supplicant has gone silent: fail the established session
        // closed rather than silently keeping it authorized or shifting it to a
        // fallback VLAN without closing accounting.
        if self.accounting_open {
            return self.teardown(TerminateCause::ReauthFailure);
        }
        if cfg.mab_enabled {
            self.auth_kind = AuthKind::Mab;
            self.state = State::AuthServer;
            return vec![
                Effect::CancelTimer(TimerKind::TxPeriod),
                Effect::StartMab { mac: self.mac },
                Effect::ArmTimer(TimerKind::ServerTimeout),
            ];
        }
        if let Some(vlan) = cfg.guest_vlan.clone() {
            return self.enter_fallback(FallbackReason::Guest, vlan);
        }
        self.hold()
    }

    fn authorize(
        &mut self,
        authz: Authorization,
        eap: Option<Vec<u8>>,
        cfg: &PaeConfig,
    ) -> Vec<Effect> {
        let mut fx = Vec::new();
        if let Some(success) = eap {
            fx.push(Effect::TxEapToSupplicant(success));
        }
        fx.push(Effect::CancelAllTimers);
        fx.push(Effect::SetAuthorization(PortAuthorization::Authorized(
            authz.clone(),
        )));
        if !self.accounting_open {
            fx.push(Effect::Accounting(AcctTrigger::Start));
            self.accounting_open = true;
        }
        if cfg.reauth_enabled {
            fx.push(Effect::ArmTimer(TimerKind::Reauth));
        }
        if authz.session_timeout.is_some() {
            fx.push(Effect::ArmTimer(TimerKind::SessionTimeout));
        }
        self.authz = Some(authz);
        self.state = State::Authenticated;
        fx
    }

    fn reject(&mut self, eap: Option<Vec<u8>>, cfg: &PaeConfig) -> Vec<Effect> {
        let mut fx = Vec::new();
        if let Some(failure) = eap {
            fx.push(Effect::TxEapToSupplicant(failure));
        }
        // A reject while a session is open is a re-authentication failure: tear
        // the established session down fully.
        if self.accounting_open {
            fx.extend(self.teardown(TerminateCause::ReauthFailure));
            return fx;
        }
        if let Some(vlan) = cfg.auth_fail_vlan.clone() {
            fx.extend(self.enter_fallback(FallbackReason::AuthFail, vlan));
        } else {
            fx.extend(self.hold());
        }
        fx
    }

    fn server_unreachable(&mut self, cfg: &PaeConfig) -> Vec<Effect> {
        // If a session is already open, "critical authentication" keeps the
        // authorized supplicant connected through the outage; just schedule a
        // later retry rather than dropping a working session.
        if self.accounting_open {
            self.state = State::Authenticated;
            let mut fx = vec![Effect::CancelTimer(TimerKind::ServerTimeout)];
            // Re-validate later only if periodic re-auth is configured; without
            // it the session simply rides out the outage until a link/CoA event.
            if cfg.reauth_enabled {
                fx.push(Effect::ArmTimer(TimerKind::Reauth));
            }
            return fx;
        }
        if let Some(vlan) = cfg.critical_vlan.clone() {
            let mut fx = self.enter_fallback(FallbackReason::Critical, vlan);
            // Periodically retry the server to leave the critical VLAN.
            fx.push(Effect::ArmTimer(TimerKind::ServerTimeout));
            return fx;
        }
        // No critical VLAN configured: fail closed.
        self.hold()
    }

    /// Begin re-authentication while keeping the port authorized meanwhile.
    fn begin_reauth(&mut self) -> Vec<Effect> {
        self.state = State::Connecting;
        self.tx_count = 1;
        let mut fx = vec![Effect::CancelTimer(TimerKind::Reauth)];
        fx.extend(self.send_identity());
        fx
    }

    fn coa_authorize(&mut self, authz: Authorization) -> Vec<Effect> {
        if self.state != State::Authenticated {
            return Vec::new();
        }
        self.authz = Some(authz.clone());
        vec![Effect::SetAuthorization(PortAuthorization::Authorized(
            authz,
        ))]
    }

    /// Enter a fallback VLAN with the given reason. Centralized so the state's
    /// `reason` and the emitted `SetAuthorization` reason can never disagree.
    fn enter_fallback(&mut self, reason: FallbackReason, vlan: String) -> Vec<Effect> {
        self.state = State::Fallback(reason);
        vec![
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Fallback {
                reason,
                vlan: Some(vlan),
            }),
        ]
    }

    /// Close the port and hold it for the quiet period before retrying.
    fn hold(&mut self) -> Vec<Effect> {
        self.state = State::Held;
        vec![
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Unauthorized),
            Effect::ArmTimer(TimerKind::Held),
        ]
    }

    /// Fully tear the session down: stop accounting if open, close the port,
    /// cancel timers, and return to `New`.
    fn teardown(&mut self, cause: TerminateCause) -> Vec<Effect> {
        if self.state == State::New {
            return Vec::new();
        }
        let mut fx = Vec::new();
        if self.accounting_open {
            fx.push(Effect::Accounting(AcctTrigger::Stop(cause)));
            self.accounting_open = false;
        }
        fx.push(Effect::CancelAllTimers);
        fx.push(Effect::SetAuthorization(PortAuthorization::Unauthorized));
        self.state = State::New;
        self.authz = None;
        self.auth_kind = AuthKind::Dot1x;
        self.tx_count = 0;
        fx
    }
}

/// The host mode governs how many sessions a port admits; exposed so the
/// per-port wrapper ([`crate::port::PortPae`]) and tests can query it.
#[must_use]
pub fn max_sessions(mode: HostMode) -> Option<usize> {
    match mode {
        HostMode::SingleHost | HostMode::MultiHost => Some(1),
        HostMode::MultiDomain => Some(2),
        HostMode::MultiAuth => None,
    }
}
