//! [`SonicEnforcer`]: the [`enforce::Enforcer`] over a SONiC [`DbConn`].
//!
//! It keeps the last-applied posture per **port** (SONiC v1 authorization is
//! port-level — see [`crate::schema`]), plans the minimal transition, applies
//! it, and confirms the change landed before reporting success. The [`Target`]
//! is accepted for trait conformance; per-MAC dataplane isolation is a
//! documented limitation, so all targets on a port share one posture.

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
    /// Last posture applied per port, so transitions emit only deltas.
    applied: Mutex<HashMap<String, Desired>>,
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

    fn previous(&self, port: &str) -> Desired {
        self.applied
            .lock()
            .ok()
            .and_then(|m| m.get(port).cloned())
            .unwrap_or_default()
    }

    fn remember(&self, port: &str, desired: Desired) {
        if let Ok(mut m) = self.applied.lock() {
            m.insert(port.to_string(), desired);
        }
    }

    /// Require `key` to exist in `db`, else fail closed.
    async fn require_present(&self, db: Db, key: String) -> Result<(), SonicError<C::Error>> {
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

    /// Require `key` to be absent in `db` (e.g. the deny rule is gone, i.e. the
    /// port is genuinely open), else fail closed.
    async fn require_absent(&self, db: Db, key: String) -> Result<(), SonicError<C::Error>> {
        if self
            .conn
            .confirm(db, &key)
            .await
            .map_err(SonicError::Backend)?
        {
            Err(SonicError::Unconfirmed { db, key })
        } else {
            Ok(())
        }
    }
}

impl<C: DbConn> Enforcer for SonicEnforcer<C> {
    type Error = SonicError<C::Error>;

    /// Bring a port into 802.1X service: install the EAPOL trap **and** close the
    /// controlled port, so it is never open before it authenticates (fail
    /// closed). Confirms both landed.
    async fn ensure_eapol_trap(&self, port: &str) -> Result<(), Self::Error> {
        let mut ops = schema::plan_eapol_trap();
        ops.extend(schema::plan_close(port));
        self.conn.apply(&ops).await.map_err(SonicError::Backend)?;
        self.require_present(Db::Config, schema::EAPOL_TRAP_KEY.to_string())
            .await?;
        self.require_present(Db::Config, schema::deny_rule_key(port))
            .await?;
        self.remember(port, Desired::default());
        Ok(())
    }

    async fn apply(
        &self,
        port: &str,
        _target: Target,
        auth: &PortAuthorization,
    ) -> Result<(), Self::Error> {
        let new = Desired::from_authorization(auth);

        // Fail closed on a VLAN we cannot program as a SONiC VLAN id.
        if let Some(vlan) = &new.vlan
            && !schema::is_valid_vlan(vlan)
        {
            return Err(SonicError::InvalidVlan(vlan.clone()));
        }
        // Fail closed if the requested Filter-Id ACL is not provisioned on the
        // switch (SERVER-CONTRACT §3.2): confirm the named table exists first.
        if let Some(filter) = &new.filter_id {
            self.require_present(Db::Config, format!("ACL_TABLE|{filter}"))
                .await?;
        }

        let old = self.previous(port);
        let ops = schema::transition(port, &old, &new);
        self.conn.apply(&ops).await.map_err(SonicError::Backend)?;

        // Confirm the load-bearing change landed before recording success.
        if new.authorized {
            match &new.vlan {
                Some(vlan) => {
                    self.require_present(Db::Config, schema::vlan_member_key(vlan, port))
                        .await?;
                }
                // No VLAN to confirm — instead confirm the port is genuinely open
                // (the default-deny rule is gone), never just assume.
                None => {
                    self.require_absent(Db::Config, schema::deny_rule_key(port))
                        .await?;
                }
            }
        } else {
            self.require_present(Db::Config, schema::deny_rule_key(port))
                .await?;
        }

        self.remember(port, new);
        Ok(())
    }
}
