//! The 802.1X authenticator daemon library.
//!
//! Milestone 7: the integration capstone. `authd` wires the pure component
//! stack into a running NAS:
//! - [`config`] — daemon configuration + validation.
//! - [`session`] — per-`{port, MAC}` RADIUS correlation (Identifier allocation,
//!   `State` echo, reply verification/parse) over `radius-client`.
//! - [`timers`] — PAE `TimerKind` → real duration mapping.
//! - [`dispatch`] — the [`dispatch::Orchestrator`]: turns PAE effects into I/O
//!   over four boundary traits, looping RADIUS replies back through the PAE.
//! - [`worker`] — the per-port async event loop binding the real boundaries
//!   (`eapol-io`, `radsec`, `enforce-sonic`, a tokio scheduler).
//!
//! Design: the pure orchestration ([`session`], [`dispatch`], [`config`],
//! [`timers`]) is unit-tested with mocked boundaries; the live I/O wiring in
//! [`worker`] is exercised in trio integration. Fail-closed throughout — the
//! daemon refuses to service a port whose EAPOL trap or FIPS posture is
//! unconfirmed.
#![forbid(unsafe_code)]
// Docs reference RadSec/EAPOL/SONiC/PAE identifiers throughout; relax doc_markdown.
#![allow(clippy::doc_markdown)]

pub mod config;
pub mod dispatch;
pub mod error;
pub mod session;
pub mod timers;
pub mod worker;

pub use config::{AuthdConfig, ConfigError, PortConfig, RadiusConfig};
pub use dispatch::{AuthServer, Deps, Orchestrator, Scheduler, SupplicantLink};
pub use error::AuthdError;
pub use session::RadiusSession;
