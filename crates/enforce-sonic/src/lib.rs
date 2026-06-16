//! SONiC (SAI/swss) dataplane backend for the 802.1X authenticator.
//!
//! Milestone 5: implements [`enforce::Enforcer`] against SONiC. The authenticator
//! does **not** call SAI directly — it follows SONiC's contract: write desired
//! state to CONFIG_DB and let `orchagent` program the ASIC, then read back to
//! confirm (DESIGN §3).
//!
//! Layers:
//! - [`db`] — the declarative op model ([`db::DbOp`]) and the [`db::DbConn`]
//!   abstraction (mock for tests; a redis-backed connection for production).
//! - [`schema`] — the pure CONFIG_DB mapping and the reconciling transition.
//!   This is the reviewable core; it is fully unit-tested.
//! - [`enforcer`] — [`SonicEnforcer`], which tracks applied posture, plans the
//!   minimal delta, applies it, and **confirms** it before reporting success.
//!
//! Design rules:
//! - **Fail closed**: an unconfirmed change is [`error::SonicError::Unconfirmed`],
//!   never a silent success — the daemon must not report a port authorized on a
//!   change the ASIC did not program.
//! - **No SAI linkage**: pure CONFIG_DB ops keep us ABI-stable across SONiC
//!   releases. The exact schema is pinned against the target release (Q-E).
//!
//! Integration boundary: the production [`db::DbConn`] is a thin redis-backed
//! connection to the SONiC databases (plus an ASIC_DB read-back for `confirm`).
//! It is exercised against a SONiC virtual switch in trio integration; the
//! planner and [`SonicEnforcer`] here are validated with a mock connection.
#![forbid(unsafe_code)]
// This crate's docs are dense with SONiC schema identifiers (CONFIG_DB,
// VLAN_MEMBER, ACL_TABLE, COPP_TRAP, …); backticking each adds noise without
// clarity, so doc_markdown is relaxed crate-wide.
#![allow(clippy::doc_markdown)]

pub mod db;
pub mod enforcer;
pub mod error;
pub mod schema;

pub use db::{Db, DbConn, DbOp, Op};
pub use enforcer::SonicEnforcer;
pub use error::SonicError;
pub use schema::Desired;
