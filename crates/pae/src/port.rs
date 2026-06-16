//! Per-port host-mode logic: routes events to the right `{port, MAC}` session
//! and enforces how many supplicants a port admits (IEEE 802.1X-2020 §12.4).
//!
//! Scope note: the pre-supplicant, group-addressed EAPOL solicitation (sending
//! EAP-Request/Identity to the PAE group address before any supplicant MAC is
//! known) is a **daemon** responsibility. This layer models one [`PortSession`]
//! per supplicant MAC, created on first contact, so each session cleanly owns
//! its own timers.

use crate::config::{HostMode, PaeConfig};
use crate::effect::{Effect, PortAuthorization};
use crate::event::Event;
use crate::session::{PortSession, State};
use pacp::ethernet::MacAddr;

/// An effect with its target: `None` means the whole port (e.g. the initial
/// unauthorized state, or a multi-host port-open), `Some(mac)` a single session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectedEffect {
    /// Target MAC, or `None` for a port-wide effect.
    pub mac: Option<MacAddr>,
    /// The effect to perform.
    pub effect: Effect,
}

/// The authenticator for one physical port.
#[derive(Debug, Clone)]
pub struct PortPae {
    cfg: PaeConfig,
    sessions: Vec<PortSession>,
}

impl PortPae {
    /// Create the port authenticator with the given configuration.
    #[must_use]
    pub fn new(cfg: PaeConfig) -> Self {
        Self {
            cfg,
            sessions: Vec::new(),
        }
    }

    /// Bring the port into 802.1X service: it starts unauthorized port-wide.
    #[must_use]
    pub fn enable(&self) -> Vec<DirectedEffect> {
        vec![DirectedEffect {
            mac: None,
            effect: Effect::SetAuthorization(PortAuthorization::Unauthorized),
        }]
    }

    /// The current session for `mac`, if any (for diagnostics and tests).
    #[must_use]
    pub fn session(&self, mac: MacAddr) -> Option<&PortSession> {
        self.sessions.iter().find(|s| s.mac() == mac)
    }

    /// Number of live (non-`New`) sessions on the port.
    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.state() != State::New)
            .count()
    }

    /// Handle an event for a specific supplicant `mac`.
    pub fn handle(&mut self, mac: MacAddr, event: Event) -> Vec<DirectedEffect> {
        let host_mode = self.cfg.host_mode;
        let directed = if let Some(session) = self.sessions.iter_mut().find(|s| s.mac() == mac) {
            let fx = session.step(event, &self.cfg);
            decorate(host_mode, mac, fx)
        } else if self.can_admit() {
            self.admit(mac, event)
        } else {
            // Host mode won't admit another supplicant. In multi-host a later
            // MAC rides on the already-open port, so dropping the event here is
            // correct; in single-host it is a denied second supplicant.
            Vec::new()
        };
        self.prune();
        directed
    }

    /// Tear every session down (link lost): port returns to unauthorized.
    pub fn link_down(&mut self) -> Vec<DirectedEffect> {
        let mut out = Vec::new();
        for session in &mut self.sessions {
            let mac = session.mac();
            for effect in session.step(Event::LinkDown, &self.cfg) {
                out.push(DirectedEffect {
                    mac: Some(mac),
                    effect,
                });
            }
        }
        out.push(DirectedEffect {
            mac: None,
            effect: Effect::SetAuthorization(PortAuthorization::Unauthorized),
        });
        self.prune();
        out
    }

    // ---- internals ----

    /// Create a session for a new MAC, bootstrap it (Enable → solicit identity),
    /// then apply the triggering event.
    fn admit(&mut self, mac: MacAddr, event: Event) -> Vec<DirectedEffect> {
        let mut session = PortSession::new(mac);
        let mut fx = session.step(Event::Enable, &self.cfg);
        // Enable already solicited an identity, so an Enable/EapolStart trigger
        // needs no further step; anything else is applied on top.
        if !matches!(event, Event::Enable | Event::EapolStart) {
            fx.extend(session.step(event, &self.cfg));
        }
        self.sessions.push(session);
        decorate(self.cfg.host_mode, mac, fx)
    }

    /// Whether the port can admit another supplicant MAC right now.
    fn can_admit(&self) -> bool {
        let active = self.active_sessions();
        match self.cfg.host_mode {
            HostMode::MultiAuth => true,
            HostMode::SingleHost | HostMode::MultiHost => active == 0,
            HostMode::MultiDomain => active < 2,
        }
    }

    /// Drop sessions that have torn down to `New`, freeing host-mode capacity.
    fn prune(&mut self) {
        self.sessions.retain(|s| s.state() != State::New);
    }
}

/// Tag a session's effects with its MAC, and in multi-host mirror a session
/// authorization as a port-wide open so the dataplane admits all MACs.
fn decorate(host_mode: HostMode, mac: MacAddr, fx: Vec<Effect>) -> Vec<DirectedEffect> {
    let mut out = Vec::with_capacity(fx.len());
    for effect in fx {
        if host_mode == HostMode::MultiHost
            && let Effect::SetAuthorization(PortAuthorization::Authorized(_)) = &effect
        {
            out.push(DirectedEffect {
                mac: None,
                effect: effect.clone(),
            });
        }
        out.push(DirectedEffect {
            mac: Some(mac),
            effect,
        });
    }
    out
}
