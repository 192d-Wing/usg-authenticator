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

// ---- A mock DbConn that tracks which keys "exist". ----

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
    /// Pre-create a key (e.g. a provisioned ACL_TABLE).
    fn seed(&self, key: &str) {
        self.keys.lock().unwrap().insert(key.to_string());
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
fn close_permits_eapol_and_drops_the_rest() {
    let ops = schema::plan_close(PORT);
    // EAPOL permit at high priority...
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key.contains("ALLOW_EAPOL")
            && fields.iter().any(|(f, v)| f == "ETHER_TYPE" && v == "0x888E"))));
    // ...and a catch-all DROP.
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key.contains("DENY_ALL")
            && fields.iter().any(|(f, v)| f == "PACKET_ACTION" && v == "DROP"))));
}

#[test]
fn transition_unauthorized_to_authorized_with_vlan_and_acl() {
    let old = Desired::default();
    let new = Desired::from_authorization(&authz(Some("100"), Some("acl-staff")));
    let ops = schema::transition(PORT, &old, &new);

    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key == "VLAN_MEMBER|Vlan100|Ethernet12"
            && fields.iter().any(|(f, v)| f == "tagging_mode" && v == "untagged"))));
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::ListAdd { key, value, .. } if key == "ACL_TABLE|acl-staff" && value == "Ethernet12")));
    // Opening removes both the deny and the EAPOL-permit rules.
    assert!(
        ops.iter()
            .any(|o| matches!(&o.op, Op::Del { key } if key.contains("DENY_ALL")))
    );
    assert!(
        ops.iter()
            .any(|o| matches!(&o.op, Op::Del { key } if key.contains("ALLOW_EAPOL")))
    );
}

#[test]
fn transition_authorized_to_unauthorized_installs_default_deny_and_drops_vlan() {
    let old = Desired::from_authorization(&authz(Some("100"), None));
    let new = Desired::default();
    let ops = schema::transition(PORT, &old, &new);

    assert!(
        ops.iter()
            .any(|o| matches!(&o.op, Op::Del { key } if key == "VLAN_MEMBER|Vlan100|Ethernet12"))
    );
    assert!(ops.iter().any(|o| matches!(&o.op,
        Op::HSet { key, fields } if key.contains("DENY_ALL")
            && fields.iter().any(|(f, v)| f == "PACKET_ACTION" && v == "DROP"))));
}

#[test]
fn reapplying_same_posture_is_a_noop() {
    let d = Desired::from_authorization(&authz(Some("100"), Some("f")));
    assert!(schema::transition(PORT, &d, &d).is_empty());
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

#[test]
fn vlan_validity() {
    assert!(schema::is_valid_vlan("100"));
    assert!(schema::is_valid_vlan("4094"));
    assert!(!schema::is_valid_vlan("0"));
    assert!(!schema::is_valid_vlan("4095"));
    assert!(!schema::is_valid_vlan("ENGINEERING"));
}

// ---- SonicEnforcer ----

#[tokio::test]
async fn ensure_eapol_trap_closes_the_port_fail_closed_start() {
    let enf = SonicEnforcer::new(MockDb::new());
    // Bring-up installs the trap AND closes the port (deny present), so the
    // port is never open before it authenticates.
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
async fn full_lifecycle_close_authorize_unauthorize() {
    let enf = SonicEnforcer::new(MockDb::new());
    enf.ensure_eapol_trap(PORT).await.unwrap(); // closed
    enf.apply(PORT, Target::Mac(MAC), &authz(Some("100"), None))
        .await
        .unwrap(); // open on VLAN 100
    enf.apply(PORT, Target::Mac(MAC), &PortAuthorization::Unauthorized)
        .await
        .unwrap(); // closed again
}

#[tokio::test]
async fn authorized_without_vlan_confirms_port_is_open() {
    let enf = SonicEnforcer::new(MockDb::new());
    enf.ensure_eapol_trap(PORT).await.unwrap(); // deny present
    // Bare accept (no VLAN): opening must remove the deny; confirmed via absence.
    enf.apply(PORT, Target::Port, &authz(None, None))
        .await
        .unwrap();
}

#[tokio::test]
async fn non_numeric_vlan_is_rejected_fail_closed() {
    let enf = SonicEnforcer::new(MockDb::new());
    assert!(matches!(
        enf.apply(PORT, Target::Port, &authz(Some("ENGINEERING"), None))
            .await,
        Err(SonicError::InvalidVlan(_))
    ));
}

#[tokio::test]
async fn filter_id_to_missing_acl_table_fails_closed() {
    let enf = SonicEnforcer::new(MockDb::new());
    // ACL_TABLE|acl-x is NOT provisioned → authorize must fail closed.
    assert!(matches!(
        enf.apply(PORT, Target::Port, &authz(Some("100"), Some("acl-x")))
            .await,
        Err(SonicError::Unconfirmed { .. })
    ));
}

#[tokio::test]
async fn filter_id_to_provisioned_acl_table_succeeds() {
    let db = MockDb::new();
    db.seed("ACL_TABLE|acl-staff"); // pre-provisioned named ACL
    let enf = SonicEnforcer::new(db);
    enf.apply(PORT, Target::Port, &authz(Some("100"), Some("acl-staff")))
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
