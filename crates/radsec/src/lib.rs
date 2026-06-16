//! `RadSec` (RADIUS over TLS 1.3, RFC 6614) transport for the 802.1X authenticator.
//!
//! Milestone 4: the FIPS, ML-KEM-1024-only channel to usg-radius (SERVER-CONTRACT
//! gap G-1). It carries the RADIUS packets built by `radius-client` over a
//! mutually-authenticated TLS 1.3 connection.
//!
//! Layers:
//! - [`fips`] — the locked crypto policy (ML-KEM-1024 + `TLS_AES_256_GCM_SHA384`)
//!   and the fail-closed self-checks.
//! - [`tls`] — the mutual-TLS [`rustls::ClientConfig`] (NAS client cert + pinned
//!   server trust anchor).
//! - [`framing`] — RADIUS-over-stream framing (pure, fully testable).
//! - [`client`] — the live [`client::RadSecConnection`] (TCP + TLS + request).
//!
//! Design rules:
//! - **TLS 1.3 only**: `rustls` is built without the `tls12` feature, so 1.2
//!   cannot be negotiated even by mistake.
//! - **Fail closed**: the crypto policy is asserted when the config is built;
//!   a malformed RADIUS frame or a failed handshake is an error, never a
//!   silent fallback. The `fips` build feature makes the module FIPS 140-3
//!   validated; [`fips::assert_fips`] gates production startup.
//!
//! This crate is the only one that performs network I/O; everything below it
//! (`radius-client`, `pae`, `pacp`) stays pure.
#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod fips;
pub mod framing;
pub mod tls;

pub use client::{RADSEC_PORT, RadSecConnection};
pub use error::RadSecError;
pub use tls::client_config;
