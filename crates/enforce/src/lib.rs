//! Backend-neutral dataplane enforcement for the 802.1X authenticator.
//!
//! The PAE decides *what* authorization a `{port, MAC}` should have
//! ([`pae::PortAuthorization`]); this trait is *how* that desired state reaches
//! the switch. The daemon translates each `SetAuthorization` /
//! `ensure-trap` effect into one [`Enforcer`] call. The SONiC (SAI/swss) backend
//! is `enforce-sonic`; mirroring usg-nos's backend-neutral split, a Linux/dev
//! backend can be added without touching the PAE or the daemon.
//!
//! Design rules:
//! - **No I/O here**: this crate is just the trait, the [`Target`] model, and a
//!   recording test double. Backends own the I/O.
//! - **Fail closed**: a backend that cannot confirm it programmed the dataplane
//!   MUST return an error so the daemon never reports a port authorized on an
//!   unconfirmed change (DESIGN §3).
#![forbid(unsafe_code)]
// Docs reference SONiC/SAI/usg-nos identifiers; relax doc_markdown crate-wide.
#![allow(clippy::doc_markdown)]

use core::future::Future;
use pacp::ethernet::MacAddr;
use pae::PortAuthorization;

/// What an authorization applies to on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// The whole port (the initial unauthorized state, or a multi-host open).
    Port,
    /// A single supplicant identified by MAC (multi-auth / multi-domain).
    Mac(MacAddr),
}

/// Programs port authorization onto a concrete dataplane.
///
/// Methods are `async`; the daemon awaits them. Implementors confirm the change
/// took effect (e.g. an ASIC read-back) and return an error otherwise — never a
/// silent success on an unconfirmed program.
pub trait Enforcer {
    /// Backend-specific error type.
    type Error;

    /// Ensure the EAPOL (`0x888E`) trap-to-CPU is installed for `port`, so the
    /// daemon receives supplicant frames. Without a confirmed trap the daemon
    /// must refuse to bring the port into 802.1X service (DESIGN §4).
    fn ensure_eapol_trap(&self, port: &str) -> impl Future<Output = Result<(), Self::Error>>;

    /// Apply `auth` to `target` on `port`: open the controlled port with the
    /// granted VLAN/ACL, close it (unauthorized), or move it to a fallback VLAN.
    fn apply(
        &self,
        port: &str,
        target: Target,
        auth: &PortAuthorization,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

pub mod recording;
pub use recording::RecordingEnforcer;
