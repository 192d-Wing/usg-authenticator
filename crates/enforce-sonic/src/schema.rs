//! The pure SONiC CONFIG_DB mapping: desired authorization → declarative
//! [`DbOp`]s. This is the reviewable core of the SONiC backend.
//!
//! v1 schema (to be pinned against the target SONiC release — DESIGN §11 Q-E):
//! - **Authorization is port-level.** `VLAN_MEMBER|Vlan<id>|<port>` untagged sets
//!   the port's VLAN; a closed port carries a per-port default-deny ACL. Multi-
//!   auth per-MAC dataplane isolation (different VLAN/ACL per MAC on one port) is
//!   a documented limitation — a port has one untagged VLAN — so the backend
//!   reconciles one posture per port; the last authorization wins.
//! - **dACL**: `Filter-Id` names a pre-provisioned `ACL_TABLE`; binding adds the
//!   port to that table's `ports` list. The enforcer first confirms the named
//!   table exists (fail closed otherwise, SERVER-CONTRACT §3.2).
//! - **Unauthorized (controlled port closed)**: a per-port default-deny
//!   `ACL_TABLE`/`ACL_RULE` that drops ingress, plus a higher-priority rule that
//!   permits EAPOL (`0x888E`) so the supplicant can still authenticate.
//! - **EAPOL trap**: a global `COPP_TRAP` entry punts `0x888E` to the CPU.

use crate::db::{Db, DbOp, Op};
use pae::PortAuthorization;

/// CoPP trap key for EAPOL.
pub const EAPOL_TRAP_KEY: &str = "COPP_TRAP|eapol";
/// EAPOL EtherType (`0x888E`) for the permit rule.
const EAPOL_ETHERTYPE: &str = "0x888E";

/// The desired dataplane posture for a port, distilled from a
/// [`PortAuthorization`]. `Default` is the closed (unauthorized) state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
    /// Whether the controlled port is open (forwarding).
    pub authorized: bool,
    /// Assigned VLAN id, if any (validated numeric by the enforcer).
    pub vlan: Option<String>,
    /// Bound `Filter-Id` ACL table name, if any.
    pub filter_id: Option<String>,
}

impl Desired {
    /// Distill a [`PortAuthorization`] into the desired posture.
    #[must_use]
    pub fn from_authorization(auth: &PortAuthorization) -> Self {
        match auth {
            PortAuthorization::Authorized(a) => Self {
                authorized: true,
                vlan: a.vlan.clone(),
                filter_id: a.filter_id.clone(),
            },
            PortAuthorization::Fallback { vlan, .. } => Self {
                authorized: true,
                vlan: vlan.clone(),
                filter_id: None,
            },
            PortAuthorization::Unauthorized => Self::default(),
        }
    }
}

/// `VLAN_MEMBER|Vlan<id>|<port>` key.
#[must_use]
pub fn vlan_member_key(vlan: &str, port: &str) -> String {
    format!("VLAN_MEMBER|Vlan{vlan}|{port}")
}

/// The per-port default-deny ACL table name (`DOT1X_<port>`).
#[must_use]
pub fn deny_table(port: &str) -> String {
    format!("DOT1X_{port}")
}

/// The default-deny (catch-all DROP) rule key for a port.
#[must_use]
pub fn deny_rule_key(port: &str) -> String {
    format!("ACL_RULE|DOT1X_{port}|DENY_ALL")
}

/// The EAPOL-permit rule key for a port (so a closed port can authenticate).
#[must_use]
pub fn eapol_permit_key(port: &str) -> String {
    format!("ACL_RULE|DOT1X_{port}|ALLOW_EAPOL")
}

/// Plan the global EAPOL trap-to-CPU (idempotent).
#[must_use]
pub fn plan_eapol_trap() -> Vec<DbOp> {
    vec![DbOp {
        db: Db::Config,
        op: Op::HSet {
            key: EAPOL_TRAP_KEY.to_string(),
            fields: vec![
                ("trap_ids".to_string(), "eapol".to_string()),
                ("trap_group".to_string(), "queue4_group1".to_string()),
            ],
        },
    }]
}

/// Plan the ops to move `port` from posture `old` to `new`. Only deltas are
/// emitted, so re-applying the same posture is a no-op.
#[must_use]
pub fn transition(port: &str, old: &Desired, new: &Desired) -> Vec<DbOp> {
    let mut ops = Vec::new();

    // VLAN delta.
    if old.vlan != new.vlan {
        if let Some(prev) = &old.vlan {
            ops.push(del(Db::Config, vlan_member_key(prev, port)));
        }
        if let Some(next) = &new.vlan {
            ops.push(DbOp {
                db: Db::Config,
                op: Op::HSet {
                    key: vlan_member_key(next, port),
                    fields: vec![("tagging_mode".to_string(), "untagged".to_string())],
                },
            });
        }
    }

    // Filter-Id (named ACL) binding delta.
    if old.filter_id != new.filter_id {
        if let Some(prev) = &old.filter_id {
            ops.push(DbOp {
                db: Db::Config,
                op: Op::ListRemove {
                    key: format!("ACL_TABLE|{prev}"),
                    field: "ports".to_string(),
                    value: port.to_string(),
                },
            });
        }
        if let Some(next) = &new.filter_id {
            ops.push(DbOp {
                db: Db::Config,
                op: Op::ListAdd {
                    key: format!("ACL_TABLE|{next}"),
                    field: "ports".to_string(),
                    value: port.to_string(),
                },
            });
        }
    }

    // Controlled-port open/close delta.
    if old.authorized != new.authorized {
        if new.authorized {
            ops.extend(open_controlled_port(port));
        } else {
            ops.extend(close_controlled_port(port));
        }
    }

    ops
}

/// The ops to close a port at bring-up (before any authentication), so a port
/// is never open before it authorizes. Equivalent to a transition into the
/// unauthorized state from nothing.
#[must_use]
pub fn plan_close(port: &str) -> Vec<DbOp> {
    close_controlled_port(port)
}

fn del(db: Db, key: String) -> DbOp {
    DbOp {
        db,
        op: Op::Del { key },
    }
}

/// Open the controlled port: remove the default-deny and EAPOL-permit rules so
/// normal traffic forwards.
fn open_controlled_port(port: &str) -> Vec<DbOp> {
    vec![
        del(Db::Config, deny_rule_key(port)),
        del(Db::Config, eapol_permit_key(port)),
    ]
}

/// Close the controlled port: a per-port ACL that permits EAPOL to the CPU
/// (higher priority) and drops everything else (catch-all). EAPOL must be
/// permitted so a closed port can still (re)authenticate.
fn close_controlled_port(port: &str) -> Vec<DbOp> {
    vec![
        DbOp {
            db: Db::Config,
            op: Op::HSet {
                key: format!("ACL_TABLE|{}", deny_table(port)),
                fields: vec![
                    ("type".to_string(), "L3".to_string()),
                    ("stage".to_string(), "ingress".to_string()),
                    ("ports".to_string(), port.to_string()),
                ],
            },
        },
        DbOp {
            db: Db::Config,
            op: Op::HSet {
                key: eapol_permit_key(port),
                fields: vec![
                    ("PRIORITY".to_string(), "9999".to_string()),
                    ("ETHER_TYPE".to_string(), EAPOL_ETHERTYPE.to_string()),
                    ("PACKET_ACTION".to_string(), "FORWARD".to_string()),
                ],
            },
        },
        DbOp {
            db: Db::Config,
            op: Op::HSet {
                key: deny_rule_key(port),
                fields: vec![
                    ("PRIORITY".to_string(), "1".to_string()),
                    ("PACKET_ACTION".to_string(), "DROP".to_string()),
                ],
            },
        },
    ]
}

/// Whether a `Tunnel-Private-Group-ID` value is a usable SONiC VLAN id (numeric,
/// 1..=4094). SONiC `VLAN_MEMBER` keys are `Vlan<number>`; a VLAN *name* cannot
/// be programmed without a name→id resolution the switch does not expose here.
#[must_use]
pub fn is_valid_vlan(vlan: &str) -> bool {
    matches!(vlan.parse::<u16>(), Ok(id) if (1..=4094).contains(&id))
}
