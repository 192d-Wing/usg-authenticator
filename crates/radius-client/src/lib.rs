//! EAP-over-RADIUS client for the 802.1X authenticator (NAS).
//!
//! Milestone 3 turns the PAE's `ToAuthServer` / `StartMab` / `Accounting`
//! effects into RADIUS packets, and RADIUS replies back into PAE [`pae::Event`]s.
//! It reuses usg-radius's `radius-proto` codec verbatim (SERVER-CONTRACT.md §9)
//! so both ends share one wire format.
//!
//! Design rules:
//! - **Pure / no transport**: builds and parses [`radius_proto::Packet`]s. The
//!   `RadSec` (TLS 1.3 / ML-KEM-1024) transport is the separate `radsec` crate.
//! - **Verbatim EAP relay**: EAP is fragmented/reassembled at the byte level so
//!   the inner TEAP/TLS tunnel is never re-encoded ([`eap_message`]).
//! - **Fail closed**: a non-conforming `User-Name` is rejected rather than
//!   forwarded ([`sanitize`]); a reply must pass [`reply::verify_reply`] before
//!   it is parsed.
#![forbid(unsafe_code)]

pub mod accounting;
pub mod consts;
pub mod context;
pub mod eap_message;
pub mod error;
pub mod reply;
pub mod request;
pub mod sanitize;

pub use accounting::accounting_request;
pub use context::RequestContext;
pub use error::RadiusClientError;
pub use reply::{parse_authorization, parse_reply, verify_reply};
pub use request::{access_request_eap, access_request_mab};
