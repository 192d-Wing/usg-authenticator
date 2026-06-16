//! The effect orchestrator: turns the PAE's [`Effect`]s into I/O against four
//! boundary traits (supplicant link, auth server, dataplane enforcer, timer
//! scheduler). RADIUS-bearing effects (`ToAuthServer`, `StartMab`) perform a
//! round-trip and yield a follow-up [`Event`] that is fed back into the PAE.
//!
//! The boundaries are traits so the orchestration is testable with mocks; the
//! real implementations (radsec, eapol-io, enforce-sonic, a tokio scheduler)
//! live in the daemon's worker.

use crate::error::AuthdError;
use crate::timers;
use core::future::Future;
use core::time::Duration;
use enforce::{Enforcer, Target};
use pacp::ethernet::MacAddr;
use pae::{
    AcctTrigger, DirectedEffect, Effect, Event, PortAuthorization, PortPae, TimerKind, Timers,
};
use radius_client::RequestContext;
use radius_proto::{Packet, generate_request_authenticator};
use std::collections::HashMap;

use crate::session::RadiusSession;

/// Sends an EAP packet to a supplicant (the daemon wraps it in an EAPOL frame).
pub trait SupplicantLink {
    /// Send `eap` to `mac`.
    fn send_eap(&self, mac: MacAddr, eap: Vec<u8>) -> impl Future<Output = Result<(), AuthdError>>;
}

/// The RADIUS authentication server over a transport (RadSec).
pub trait AuthServer {
    /// Send an Access-Request and return the reply.
    fn access_request(&self, request: &Packet) -> impl Future<Output = Result<Packet, AuthdError>>;
    /// Send an Accounting-Request (the response is not needed by the caller).
    fn accounting(&self, request: &Packet) -> impl Future<Output = Result<(), AuthdError>>;
}

/// Arms/cancels the timers that deliver [`Event::Timer`] back to the PAE.
pub trait Scheduler {
    /// Arm `kind` for `mac` to fire after `dur`.
    fn arm(&self, mac: MacAddr, kind: TimerKind, dur: Duration);
    /// Cancel `kind` for `mac`.
    fn cancel(&self, mac: MacAddr, kind: TimerKind);
    /// Cancel every timer for `mac`.
    fn cancel_all(&self, mac: MacAddr);
}

/// The boundary implementations the orchestrator drives.
#[derive(Debug)]
pub struct Deps<'a, S, A, E, C> {
    /// EAPOL link to supplicants.
    pub supplicant: &'a S,
    /// RADIUS server transport.
    pub server: &'a A,
    /// Dataplane enforcer.
    pub enforcer: &'a E,
    /// Timer scheduler.
    pub scheduler: &'a C,
    /// Configured timer durations.
    pub timers: &'a Timers,
    /// RADIUS shared secret (`"radsec"` over RadSec).
    pub secret: &'a [u8],
}

/// Per-supplicant orchestration state.
#[derive(Debug, Default)]
struct SessionState {
    radius: RadiusSession,
    /// Session-Timeout (seconds) from the last Accept, for arming SessionTimeout.
    session_timeout: Option<u32>,
    /// Stable accounting session id.
    acct_id: Option<String>,
}

/// Orchestrates one port's sessions: applies PAE effects and feeds RADIUS
/// replies back through the PAE.
#[derive(Debug)]
pub struct Orchestrator {
    port: String,
    ctx_template: RequestContext,
    sessions: HashMap<MacAddr, SessionState>,
    acct_counter: u64,
}

impl Orchestrator {
    /// Create an orchestrator for `port`. `ctx_template` carries the NAS
    /// attributes shared by every session (the per-MAC `calling_station` is
    /// filled in per request).
    #[must_use]
    pub fn new(port: String, ctx_template: RequestContext) -> Self {
        Self {
            port,
            ctx_template,
            sessions: HashMap::new(),
            acct_counter: 0,
        }
    }

    fn ctx_for(&self, mac: MacAddr) -> RequestContext {
        let mut ctx = self.ctx_template.clone();
        ctx.calling_station = mac;
        ctx
    }

    fn session(&mut self, mac: MacAddr) -> &mut SessionState {
        self.sessions.entry(mac).or_default()
    }

    fn acct_id_for(&mut self, mac: MacAddr) -> String {
        if let Some(existing) = self.sessions.get(&mac).and_then(|s| s.acct_id.clone()) {
            return existing;
        }
        self.acct_counter = self.acct_counter.wrapping_add(1);
        let id = format!(
            "{}-{}-{}",
            self.port,
            pacp::ethernet::format_mac(&mac),
            self.acct_counter
        );
        self.session(mac).acct_id = Some(id.clone());
        id
    }

    /// Feed an event to the PAE and perform the resulting effects, looping over
    /// any RADIUS-reply follow-up events (bounded).
    ///
    /// # Errors
    /// Propagates the first boundary error ([`AuthdError`]).
    pub async fn handle_event<S, A, E, C>(
        &mut self,
        pae: &mut PortPae,
        mac: MacAddr,
        event: Event,
        deps: &Deps<'_, S, A, E, C>,
    ) -> Result<(), AuthdError>
    where
        S: SupplicantLink,
        A: AuthServer,
        E: Enforcer,
        E::Error: core::fmt::Display,
        C: Scheduler,
    {
        // FIFO so follow-up events are processed in the order they were produced.
        let mut queue = std::collections::VecDeque::from([(mac, event)]);
        let mut steps = 0u32;
        while let Some((m, ev)) = queue.pop_front() {
            // Safety bound: a healthy exchange resolves in a few steps; this
            // stops any pathological feedback loop.
            steps = steps.saturating_add(1);
            if steps > 64 {
                break;
            }
            for de in pae.handle(m, ev) {
                let de_mac = de.mac;
                if let Some(follow) = self.dispatch(de, deps).await? {
                    // A RADIUS reply follow-up belongs to the session that
                    // triggered the request.
                    queue.push_back((de_mac.unwrap_or(m), follow));
                }
            }
        }
        Ok(())
    }

    /// Apply a batch of port-level effects (e.g. from `enable`/`link_down`).
    ///
    /// # Errors
    /// Propagates the first boundary error.
    pub async fn apply_effects<S, A, E, C>(
        &mut self,
        effects: Vec<DirectedEffect>,
        deps: &Deps<'_, S, A, E, C>,
    ) -> Result<(), AuthdError>
    where
        S: SupplicantLink,
        A: AuthServer,
        E: Enforcer,
        E::Error: core::fmt::Display,
        C: Scheduler,
    {
        for de in effects {
            // Port-level effects (enable/link_down) never trigger a RADIUS
            // round-trip, so any follow-up is ignored here.
            let _ = self.dispatch(de, deps).await?;
        }
        Ok(())
    }

    /// Perform one effect, returning a follow-up event when a RADIUS round-trip
    /// produced one.
    async fn dispatch<S, A, E, C>(
        &mut self,
        de: DirectedEffect,
        deps: &Deps<'_, S, A, E, C>,
    ) -> Result<Option<Event>, AuthdError>
    where
        S: SupplicantLink,
        A: AuthServer,
        E: Enforcer,
        E::Error: core::fmt::Display,
        C: Scheduler,
    {
        match de.effect {
            Effect::TxEapToSupplicant(eap) => {
                if let Some(mac) = de.mac {
                    deps.supplicant.send_eap(mac, eap).await?;
                }
                Ok(None)
            }
            Effect::ToAuthServer { eap } => {
                let Some(mac) = de.mac else { return Ok(None) };
                let ctx = self.ctx_for(mac);
                let identity = eap_identity(&eap);
                let request = self.session(mac).radius.build_eap_request(
                    &ctx,
                    identity.as_deref(),
                    &eap,
                    generate_request_authenticator(),
                    deps.secret,
                )?;
                let reply = deps.server.access_request(&request).await?;
                let event = self.session(mac).radius.handle_reply(&reply, deps.secret)?;
                Ok(Some(event))
            }
            Effect::StartMab { mac } => {
                let ctx = self.ctx_for(mac);
                let request = self.session(mac).radius.build_mab_request(
                    &ctx,
                    generate_request_authenticator(),
                    deps.secret,
                )?;
                let reply = deps.server.access_request(&request).await?;
                let event = self.session(mac).radius.handle_reply(&reply, deps.secret)?;
                Ok(Some(event))
            }
            Effect::SetAuthorization(auth) => {
                if let PortAuthorization::Authorized(a) = &auth
                    && let Some(mac) = de.mac
                {
                    self.session(mac).session_timeout = a.session_timeout;
                }
                let target = de.mac.map_or(Target::Port, Target::Mac);
                deps.enforcer
                    .apply(&self.port, target, &auth)
                    .await
                    .map_err(|e| AuthdError::Enforce(e.to_string()))?;
                Ok(None)
            }
            Effect::ArmTimer(kind) => {
                if let Some(mac) = de.mac
                    && let Some(dur) = self.timer_duration(mac, kind, deps.timers)
                {
                    deps.scheduler.arm(mac, kind, dur);
                }
                Ok(None)
            }
            Effect::CancelTimer(kind) => {
                if let Some(mac) = de.mac {
                    deps.scheduler.cancel(mac, kind);
                }
                Ok(None)
            }
            Effect::CancelAllTimers => {
                if let Some(mac) = de.mac {
                    deps.scheduler.cancel_all(mac);
                }
                Ok(None)
            }
            Effect::Accounting(trigger) => {
                if let Some(mac) = de.mac {
                    self.send_accounting(mac, trigger, deps).await?;
                }
                Ok(None)
            }
        }
    }

    /// Resolve a timer duration: config-backed kinds from [`Timers`], and
    /// `SessionTimeout` from the session's RADIUS `Session-Timeout`. Returns
    /// `None` for a `SessionTimeout` with no per-session value so the caller
    /// does **not** arm a 0-second (immediate-fire) timer.
    fn timer_duration(&self, mac: MacAddr, kind: TimerKind, timers: &Timers) -> Option<Duration> {
        if let Some(dur) = timers::duration(timers, kind) {
            return Some(dur);
        }
        // SessionTimeout: only arm if the session actually carries a value.
        self.sessions
            .get(&mac)
            .and_then(|s| s.session_timeout)
            .map(|secs| Duration::from_secs(u64::from(secs)))
    }

    async fn send_accounting<S, A, E, C>(
        &mut self,
        mac: MacAddr,
        trigger: AcctTrigger,
        deps: &Deps<'_, S, A, E, C>,
    ) -> Result<(), AuthdError>
    where
        A: AuthServer,
    {
        let ctx = self.ctx_for(mac);
        let acct_id = self.acct_id_for(mac);
        let session = self.session(mac);
        let id = session.radius.next_accounting_identifier();
        let request = session
            .radius
            .build_accounting(&ctx, id, trigger, &acct_id, deps.secret)?;
        deps.server.accounting(&request).await
    }
}

/// Extract a `User-Name` from an EAP-Response/Identity packet, if that is what
/// this EAP packet is.
fn eap_identity(eap: &[u8]) -> Option<Vec<u8>> {
    pacp::eap::EapPacket::decode(eap)
        .ok()
        .and_then(|p| p.identity().map(<[u8]>::to_vec))
}
