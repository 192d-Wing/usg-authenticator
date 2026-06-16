//! The SONiC database operation model and the `DbConn` abstraction.
//!
//! SONiC stores configuration and state in a set of Redis databases. The
//! authenticator writes desired config to CONFIG_DB and confirms the ASIC
//! actually programmed it by reading ASIC_DB (DESIGN §3). This module models the
//! operations declaratively so the planner ([`crate::schema`]) is pure and the
//! transport ([`DbConn`]) is swappable (a mock for tests, redis for production).

use core::future::Future;

/// A SONiC Redis database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Db {
    /// CONFIG_DB (index 4): desired configuration consumed by orchagent.
    Config,
    /// APPL_DB (index 0): application state.
    Appl,
    /// ASIC_DB (index 1): what was actually programmed — read for confirmation.
    Asic,
    /// STATE_DB (index 6): operational state.
    State,
}

impl Db {
    /// The SONiC Redis logical database index.
    #[must_use]
    pub fn index(self) -> i64 {
        match self {
            Self::Appl => 0,
            Self::Asic => 1,
            Self::Config => 4,
            Self::State => 6,
        }
    }
}

/// A single declarative database operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbOp {
    /// Which database the op targets.
    pub db: Db,
    /// The operation.
    pub op: Op,
}

/// The kinds of mutation the planner emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Create/replace a hash entry (`HSET key field value …`).
    HSet {
        /// The `TABLE|key…` Redis key (CONFIG_DB uses `|` separators).
        key: String,
        /// Field/value pairs.
        fields: Vec<(String, String)>,
    },
    /// Delete a key (`DEL key`).
    Del {
        /// The key to delete.
        key: String,
    },
    /// Add `value` to the comma-separated list in `key`'s `field` (read-modify-
    /// write), e.g. binding a port into an ACL table's `ports` list.
    ListAdd {
        /// The Redis key.
        key: String,
        /// The list-valued field.
        field: String,
        /// The value to add (idempotent).
        value: String,
    },
    /// Remove `value` from the comma-separated list in `key`'s `field`.
    ListRemove {
        /// The Redis key.
        key: String,
        /// The list-valued field.
        field: String,
        /// The value to remove.
        value: String,
    },
}

/// A connection to the SONiC databases. Backends implement apply + confirm; the
/// mutating ops and the read-back confirmation are all the [`crate::SonicEnforcer`]
/// needs.
pub trait DbConn {
    /// Backend error type.
    type Error;

    /// Apply the ops in order (atomically where the backend can).
    fn apply(&self, ops: &[DbOp]) -> impl Future<Output = Result<(), Self::Error>>;

    /// Whether `key` exists in `db` — used to confirm a write landed (in
    /// production, that the ASIC programmed it).
    fn confirm(&self, db: Db, key: &str) -> impl Future<Output = Result<bool, Self::Error>>;
}
