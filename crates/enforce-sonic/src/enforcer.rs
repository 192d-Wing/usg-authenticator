//! [`SonicEnforcer`]: the [`enforce::Enforcer`] over a SONiC [`DbConn`]. It keeps
//! the last-applied posture per `{port, target}`, plans the minimal transition,
//! applies it, and confirms the change landed before reporting success.

use crate::db::{Db, DbConn};
use crate::error::SonicError;
use crate::schema::{self, Desired};
use enforce::{Enforcer, Target};
use pae::PortAuthorization;
use std::collections::HashMap;
use std::sync::Mutex;

/// Programs port authorization on SONiC via a [`DbConn`].
#[derive(Debug)]
pub struct SonicEnforcer<C> {
    conn: C,
    /// Last posture applied per `{port, target}`, so transitions emit only deltas.
    applied: Mutex<HashMap<(String, Target), Desired>>,
}

impl<C: DbConn> SonicEnforcer<C> {
    /// Wrap a database connection.
    #[must_use]
    pub fn new(conn: C) -> Self {
        Self {
            conn,
            applied: Mutex::new(HashMap::new()),
        }
    }

    fn previous(&self, port: &str, target: Target) -> Desired {
        self.applied
            .lock()
            .ok()
            .and_then(|m| m.get(&(port.to_string(), target)).cloned())
            .unwrap_or_default()
    }

    fn remember(&self, port: &str, target: Target, desired: Desired) {
        if let Ok(mut m) = self.applied.lock() {
            m.insert((port.to_string(), target), desired);
        }
    }

    /// Confirm a key exists in `db`, mapping a negative result to a fail-closed
    /// [`SonicError::Unconfirmed`].
    async fn require(&self, db: Db, key: String) -> Result<(), SonicError<C::Error>> {
        if self
            .conn
            .confirm(db, &key)
            .await
            .map_err(SonicError::Backend)?
        {
            Ok(())
        } else {
            Err(SonicError::Unconfirmed { db, key })
        }
    }
}

impl<C: DbConn> Enforcer for SonicEnforcer<C> {
    type Error = SonicError<C::Error>;

    async fn ensure_eapol_trap(&self, _port: &str) -> Result<(), Self::Error> {
        let ops = schema::plan_eapol_trap();
        self.conn.apply(&ops).await.map_err(SonicError::Backend)?;
        self.require(Db::Config, schema::EAPOL_TRAP_KEY.to_string())
            .await
    }

    async fn apply(
        &self,
        port: &str,
        target: Target,
        auth: &PortAuthorization,
    ) -> Result<(), Self::Error> {
        let new = Desired::from_authorization(auth);
        let old = self.previous(port, target);
        let ops = schema::transition(port, target, &old, &new);
        self.conn.apply(&ops).await.map_err(SonicError::Backend)?;

        // Confirm the load-bearing change landed before recording success.
        if new.authorized {
            if let Some(vlan) = &new.vlan {
                self.require(Db::Config, schema::vlan_member_key(vlan, port))
                    .await?;
            }
        } else {
            self.require(Db::Config, schema::deny_rule_key(port, target))
                .await?;
        }

        self.remember(port, target, new);
        Ok(())
    }
}
