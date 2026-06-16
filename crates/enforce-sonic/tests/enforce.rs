//! Tests for the SONiC op planner and the SonicEnforcer, using an in-memory
//! mock DbConn (no Redis / SONiC needed).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use enforce::{Enforcer, Target};
use enforce_sonic::db::{Db, DbConn, DbOp, Op};
use enforce_sonic::schema::{self, Desired};
use enforce_sonic::{SonicEnforcer, SonicError};
use pae::{Authorization, FallbackReason, PortAuthorization};
use std::collections::HashSet;
use std::sync::Mutex;

const PORT: &str = "Ethernet12";
const MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

// ---- A mock DbConn that records ops and tracks which keys "exist". ----

#[derive(Default)]
struct MockDb {
    keys: Mutex<HashSet<String>>,
    confirm_everything: Mutex<bool>,
}

impl MockDb {
    fn new() -> Self {
        let m = Self::default();
        *m.confirm_everything.lock().unwrap() = true;
        m
    }
    fn fail_confirmation(&self) {
        *self.confirm_everything.lock().unwrap() = false;
    }
}

impl DbConn for MockDb {
    type Error = std::convert::Infallible;

    async fn apply(&self, ops: &[DbOp]) -> Result<(), Self::Error> {
        let mut keys = self.keys.lock().unwrap();
        for op in ops {
            match &op.op {
                Op::HSet { key, .. } => {
                    keys.insert(key.clone());
                }
                Op::Del { key } => {
                    keys.remove(key);
                }
                Op::ListAdd { .. } | Op::ListRemove { .. } => {}
            }
        }
        Ok(())
    }

    async fn confirm(&self, _db: Db, key: &str) -> Result<bool, Self::Error> {
        if *self.confirm_everything.lock().unwrap() {
            Ok(self.keys.lock().unwrap().contains(key))
        } else {
            Ok(false)
        }
    }
}

fn authz(vlan: Option<&str>, filter: Option<&str>) -> PortAuthorization {
    PortAuthorization::Authorized(Authorization {
        vlan: vlan.map(str::to_string),
        filter_id: filter.map(str::to_string),
        ..Authorization::default()
    })
}

// ---- Planner ----

#[test]
fn eapol_trap_plan_targets_copp() {
    let ops = schema::plan_eapol_trap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].db, Db::Config);
    assert!(matches!(&ops[0].op, Op::HSet { key, .. } if key == "COPP_TRAP|eapol"));
}

#[test]
fn transition_unauthorized_to_authorized_with_vlan_and_acl() {
    let old = Desired::default();
    let new = Desired::from_authorization(&authz(Some("100"), Some("acl-staff")));
    let ops = schema::transition(PORT, Target::Mac(MAC), &old, &new);

    // VLAN membership added, ACL bound, controlled port opened (deny removed).
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key == "VLAN_MEMBER|Vlan100|Ethernet12"
            && fields.iter().any(|(f, v)| f == "tagging_mode" && v == "untagged"))));
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::ListAdd { key, value, .. } if key == "ACL_TABLE|acl-staff" && value == "Ethernet12")));
    assert!(
        ops.iter()
            .any(|o| matches!(&o.op, Op::Del { key } if key.contains("DENY")))
    );
}

#[test]
fn transition_authorized_to_unauthorized_installs_default_deny_and_drops_vlan() {
    let old = Desired::from_authorization(&authz(Some("100"), None));
    let new = Desired::default();
    let ops = schema::transition(PORT, Target::Port, &old, &new);

    // Prior VLAN removed; default-deny rule installed.
    assert!(
        ops.iter()
            .any(|o| matches!(&o.op, Op::Del { key } if key == "VLAN_MEMBER|Vlan100|Ethernet12"))
    );
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key.contains("DENY")
            && fields.iter().any(|(f, v)| f == "PACKET_ACTION" && v == "DROP"))));
}

#[test]
fn reapplying_same_posture_is_a_noop() {
    let d = Desired::from_authorization(&authz(Some("100"), Some("f")));
    assert!(schema::transition(PORT, Target::Port, &d, &d).is_empty());
}

#[test]
fn fallback_authorization_forwards_on_restricted_vlan() {
    let d = Desired::from_authorization(&PortAuthorization::Fallback {
        reason: FallbackReason::Guest,
        vlan: Some("guest".to_string()),
    });
    assert!(d.authorized);
    assert_eq!(d.vlan.as_deref(), Some("guest"));
    assert_eq!(d.filter_id, None);
}

// ---- SonicEnforcer ----

#[tokio::test]
async fn ensure_eapol_trap_applies_and_confirms() {
    let enf = SonicEnforcer::new(MockDb::new());
    enf.ensure_eapol_trap(PORT).await.unwrap();
}

#[tokio::test]
async fn ensure_eapol_trap_fails_closed_when_unconfirmed() {
    let db = MockDb::new();
    db.fail_confirmation();
    let enf = SonicEnforcer::new(db);
    assert!(matches!(
        enf.ensure_eapol_trap(PORT).await,
        Err(SonicError::Unconfirmed { .. })
    ));
}

#[tokio::test]
async fn apply_authorize_then_unauthorize_tracks_state() {
    let enf = SonicEnforcer::new(MockDb::new());
    // Authorize on VLAN 100.
    enf.apply(PORT, Target::Mac(MAC), &authz(Some("100"), None))
        .await
        .unwrap();
    // Re-applying the same authorization is a no-op (state tracked) — confirm
    // still succeeds because the vlan key persists.
    enf.apply(PORT, Target::Mac(MAC), &authz(Some("100"), None))
        .await
        .unwrap();
    // Unauthorize: removes VLAN, installs deny; confirm sees the deny rule.
    enf.apply(PORT, Target::Mac(MAC), &PortAuthorization::Unauthorized)
        .await
        .unwrap();
}

#[tokio::test]
async fn apply_fails_closed_when_change_is_not_confirmed() {
    let db = MockDb::new();
    db.fail_confirmation();
    let enf = SonicEnforcer::new(db);
    assert!(matches!(
        enf.apply(PORT, Target::Mac(MAC), &authz(Some("100"), None))
            .await,
        Err(SonicError::Unconfirmed { .. })
    ));
}
