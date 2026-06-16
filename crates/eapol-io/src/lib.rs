//! AF_PACKET raw-socket rx/tx of EAPOL (`0x888E`) frames for the 802.1X
//! authenticator.
//!
//! Milestone 6: the L2 transport. With the EAPOL trap-to-CPU installed by
//! `enforce-sonic`, EAPOL frames arrive on each front-panel host netdev
//! (`EthernetN`); this crate opens an `AF_PACKET`/`SOCK_RAW` socket per port,
//! bound to the EAPOL EtherType so only `0x888E` is delivered, and exposes a
//! safe async [`EapolSocket`] (`recv`/`send`) that the daemon's reactor drives.
//! Received frames are decoded by `pacp`; this crate moves raw bytes only.
//!
//! **This is the one crate permitted `unsafe`** — the AF_PACKET FFI. It does not
//! inherit the workspace `forbid(unsafe_code)`; every `unsafe` block is confined
//! to [`socket`] and carries a `SAFETY:` justification (CONTRIBUTING.md). All
//! other security-baseline deny lints still apply.
//!
//! Fail-closed coupling (DESIGN §4): the daemon must confirm the EAPOL trap is
//! installed (`enforce`) before servicing a port — an untrapped port would
//! receive no frames and silently authenticate no one.
// Docs are dense with FFI/protocol identifiers (AF_PACKET, sockaddr_ll,
// EtherType, EAPOL); backticking each adds noise, so relax doc_markdown.
#![allow(clippy::doc_markdown)]

pub mod error;
pub mod socket;

pub use error::EapolError;
pub use socket::{ETH_P_PAE, EapolSocket};
