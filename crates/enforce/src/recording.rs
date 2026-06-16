//! An in-memory [`Enforcer`] that records the calls made to it, for testing the
//! daemon's effect→enforcement wiring without a real dataplane.

use crate::{Enforcer, Target};
use core::convert::Infallible;
use pae::PortAuthorization;
use std::sync::Mutex;

/// A recorded enforcement call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `ensure_eapol_trap(port)`.
    EnsureEapolTrap {
        /// The port a trap was requested for.
        port: String,
    },
    /// `apply(port, target, auth)`.
    Apply {
        /// The port.
        port: String,
        /// The target (whole port or a MAC).
        target: Target,
        /// The authorization applied.
        auth: PortAuthorization,
    },
}

/// Records every [`Enforcer`] call; never fails.
#[derive(Debug, Default)]
pub struct RecordingEnforcer {
    calls: Mutex<Vec<Call>>,
}

impl RecordingEnforcer {
    /// A fresh recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the calls recorded so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn push(&self, call: Call) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }
}

impl Enforcer for RecordingEnforcer {
    type Error = Infallible;

    async fn ensure_eapol_trap(&self, port: &str) -> Result<(), Infallible> {
        self.push(Call::EnsureEapolTrap {
            port: port.to_string(),
        });
        Ok(())
    }

    async fn apply(
        &self,
        port: &str,
        target: Target,
        auth: &PortAuthorization,
    ) -> Result<(), Infallible> {
        self.push(Call::Apply {
            port: port.to_string(),
            target,
            auth: auth.clone(),
        });
        Ok(())
    }
}
