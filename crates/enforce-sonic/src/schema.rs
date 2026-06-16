//! The pure SONiC CONFIG_DB mapping: desired authorization → declarative
//! [`DbOp`]s. This is the reviewable core of the SONiC backend.
//!
//! v1 schema (to be pinned against the target SONiC release — DESIGN §11 Q-E):
//! - **VLAN assignment**: `VLAN_MEMBER|Vlan<id>|<port>` untagged (untagged
//!   membership sets the port's effective PVID). VLAN is **port-level**;
//!   per-MAC VLAN differentiation in multi-auth is a documented limitation
//!   (a port has one untagged VLAN) — per-MAC isolation is via ACL (follow-up).
//! - **dACL**: `Filter-Id` names a pre-provisioned `ACL_TABLE`; binding adds the
//!   port to that table's `ports` list.
//! - **Unauthorized (controlled port closed)**: a per-port default-deny
//!   `ACL_TABLE`/`ACL_RULE` dropping ingress; EAPOL still reaches the CPU via the
//!   trap, so the supplicant can authenticate.
//! - **EAPOL trap**: a global `COPP_TRAP` entry punts `0x888E` to the CPU.

use crate::db::{Db, DbOp, Op};
use enforce::Target;
use pacp::ethernet::format_mac;
use pae::PortAuthorization;

/// CoPP trap key for EAPOL.
pub const EAPOL_TRAP_KEY: &str = "COPP_TRAP|eapol";

/// The desired dataplane posture for a `{port, target}`, distilled from a
/// [`PortAuthorization`]. `Default` is the closed (unauthorized) state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Desired {
    /// Whether the controlled port is open (forwarding) for this target.
    pub authorized: bool,
    /// Assigned VLAN id/name, if any.
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
            // A fallback VLAN forwards on a restricted VLAN: open, that VLAN, no
            // server-supplied ACL.
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

/// The default-deny rule key, scoped per target so multi-auth sessions don't
/// collide on one port.
#[must_use]
pub fn deny_rule_key(port: &str, target: Target) -> String {
    match target {
        Target::Port => format!("ACL_RULE|DOT1X_{port}|DENY_ALL"),
        Target::Mac(mac) => format!("ACL_RULE|DOT1X_{port}|DENY_{}", format_mac(&mac)),
    }
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

/// Plan the ops to move `{port, target}` from `old` to `new`. Only the deltas
/// are emitted, so re-applying the same posture is a no-op.
#[must_use]
pub fn transition(port: &str, target: Target, old: &Desired, new: &Desired) -> Vec<DbOp> {
    let mut ops = Vec::new();

    // VLAN delta.
    if old.vlan != new.vlan {
        if let Some(prev) = &old.vlan {
            ops.push(DbOp {
                db: Db::Config,
                op: Op::Del {
                    key: vlan_member_key(prev, port),
                },
            });
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
            ops.extend(open_controlled_port(port, target));
        } else {
            ops.extend(close_controlled_port(port, target));
        }
    }

    ops
}

/// Remove the default-deny rule so traffic forwards (the controlled port opens).
fn open_controlled_port(port: &str, target: Target) -> Vec<DbOp> {
    vec![DbOp {
        db: Db::Config,
        op: Op::Del {
            key: deny_rule_key(port, target),
        },
    }]
}

/// Install the default-deny rule (the controlled port closes). EAPOL still
/// reaches the CPU via the trap, so a supplicant can (re)authenticate.
fn close_controlled_port(port: &str, target: Target) -> Vec<DbOp> {
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
                key: deny_rule_key(port, target),
                fields: vec![
                    ("PRIORITY".to_string(), "1".to_string()),
                    ("PACKET_ACTION".to_string(), "DROP".to_string()),
                ],
            },
        },
    ]
}
