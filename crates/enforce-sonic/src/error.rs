//! Errors from the SONiC enforcement backend.

use crate::db::Db;

/// A SONiC backend error, generic over the [`crate::db::DbConn`] error.
#[derive(Debug)]
pub enum SonicError<E> {
    /// The underlying database connection failed.
    Backend(E),
    /// A write was applied but could not be confirmed in the dataplane (the
    /// ASIC did not program it). We fail closed: the port is not reported
    /// authorized on an unconfirmed change (DESIGN §3).
    Unconfirmed {
        /// The database the confirmation read targeted.
        db: Db,
        /// The key that was expected to exist.
        key: String,
    },
    /// The server assigned a VLAN that is not a programmable SONiC VLAN id
    /// (non-numeric name, or out of 1..=4094). Fail closed — we do not guess.
    InvalidVlan(String),
}

impl<E: core::fmt::Display> core::fmt::Display for SonicError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "SONiC DB error: {e}"),
            Self::Unconfirmed { db, key } => {
                write!(f, "dataplane change not confirmed in {db:?}: {key}")
            }
            Self::InvalidVlan(v) => {
                write!(f, "assigned VLAN {v:?} is not a SONiC VLAN id (1..=4094)")
            }
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for SonicError<E> {}
