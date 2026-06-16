//! The production [`DbConn`]: a redis-backed connection to the SONiC databases.
//!
//! SONiC exposes its databases over Redis (CONFIG_DB index 4, APPL_DB 0,
//! ASIC_DB 1, STATE_DB 6). The authenticator writes desired config to CONFIG_DB
//! (orchagent programs the ASIC) and reads back to confirm. This type holds one
//! multiplexed connection per database and maps each [`DbOp`] to a Redis command.
//!
//! Gated behind the `redis-backend` feature so the default build, tests, and CI
//! need no Redis server; it is validated against a SONiC virtual switch in trio
//! integration. List fields (e.g. an `ACL_TABLE` `ports` binding) are stored
//! comma-separated here — the exact SONiC list encoding is part of the Q-E
//! schema validation against the target release.

use crate::db::{Db, DbConn, DbOp, Op};
use redis::{AsyncCommands, RedisError};
use std::collections::HashMap;

/// The SONiC databases the authenticator touches.
const CONNECTED_DBS: [Db; 4] = [Db::Config, Db::Appl, Db::Asic, Db::State];

/// A redis-backed [`DbConn`] for SONiC.
#[derive(Debug, Clone)]
pub struct RedisDbConn {
    conns: HashMap<i64, redis::aio::MultiplexedConnection>,
}

impl RedisDbConn {
    /// Connect to the SONiC Redis at `base_url` (e.g. `redis://127.0.0.1:6379`),
    /// opening one multiplexed connection per database.
    ///
    /// # Errors
    /// [`RedisError`] if any per-database connection cannot be established.
    pub async fn connect(base_url: &str) -> Result<Self, RedisError> {
        let mut conns = HashMap::new();
        for db in CONNECTED_DBS {
            let client = redis::Client::open(format!("{base_url}/{}", db.index()))?;
            let conn = client.get_multiplexed_async_connection().await?;
            conns.insert(db.index(), conn);
        }
        Ok(Self { conns })
    }

    fn conn(&self, db: Db) -> Result<redis::aio::MultiplexedConnection, RedisError> {
        self.conns.get(&db.index()).cloned().ok_or_else(|| {
            RedisError::from((
                redis::ErrorKind::InvalidClientConfig,
                "SONiC DB not connected",
            ))
        })
    }
}

impl DbConn for RedisDbConn {
    type Error = RedisError;

    async fn apply(&self, ops: &[DbOp]) -> Result<(), RedisError> {
        for op in ops {
            let mut conn = self.conn(op.db)?;
            match &op.op {
                Op::HSet { key, fields } => {
                    let _: () = conn.hset_multiple(key, fields.as_slice()).await?;
                }
                Op::Del { key } => {
                    let _: () = conn.del(key).await?;
                }
                Op::ListAdd { key, field, value } => {
                    let current: Option<String> = conn.hget(key, field).await?;
                    let mut items: Vec<&str> = current
                        .as_deref()
                        .map(|s| s.split(',').filter(|x| !x.is_empty()).collect())
                        .unwrap_or_default();
                    if !items.contains(&value.as_str()) {
                        items.push(value);
                    }
                    let _: () = conn.hset(key, field, items.join(",")).await?;
                }
                Op::ListRemove { key, field, value } => {
                    let current: Option<String> = conn.hget(key, field).await?;
                    if let Some(current) = current {
                        let items: Vec<&str> = current
                            .split(',')
                            .filter(|x| !x.is_empty() && *x != value.as_str())
                            .collect();
                        let _: () = conn.hset(key, field, items.join(",")).await?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn confirm(&self, db: Db, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.conn(db)?;
        let exists: bool = conn.exists(key).await?;
        Ok(exists)
    }
}
