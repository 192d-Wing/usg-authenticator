//! IEEE 802.1X-2020 authenticator PAE — the pure decision core of the NAS.
//!
//! Milestone 2 provides the **authenticator state machine**: a deterministic,
//! event-driven model of one supplicant session ([`PortSession`]) and the
//! per-port host-mode logic that multiplexes sessions ([`PortPae`]). It is the
//! brain that the daemon's EAPOL, RADIUS, and SONiC-enforcement plumbing drive
//! in later milestones.
//!
//! Design rules:
//! - **Pure**: no I/O, no OS calls, no clock, no `unsafe`. [`PortSession::step`]
//!   maps `(state, Event)` to an ordered list of [`Effect`]s; the daemon
//!   performs them and owns the timers.
//! - **Fail closed**: the only path that authorizes a port is an explicit
//!   `Access-Accept`. Every unhandled `(state, event)` is a no-op, and every
//!   error/timeout path leaves the port unauthorized — except the one
//!   deliberately opt-in critical-VLAN behavior.
//! - **Pass-through**: the machine never inspects EAP method content; it relays
//!   EAP between the supplicant and the server and reacts to the RADIUS result.
#![forbid(unsafe_code)]

pub mod config;
pub mod effect;
pub mod event;
pub mod port;
pub mod session;

pub use config::{HostMode, PaeConfig, TimerKind, Timers};
pub use effect::{
    AcctTrigger, Authorization, Effect, FallbackReason, PortAuthorization, TerminateCause,
};
pub use event::{Event, InboundEap};
pub use port::{DirectedEffect, PortPae};
pub use session::{PortSession, State};
