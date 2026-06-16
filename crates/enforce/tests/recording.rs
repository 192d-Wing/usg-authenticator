//! The RecordingEnforcer faithfully records calls (used to test the daemon's
//! effect→enforcement wiring).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use enforce::recording::Call;
use enforce::{Enforcer, RecordingEnforcer, Target};
use pae::{Authorization, PortAuthorization};

const MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[tokio::test]
async fn records_trap_and_apply_in_order() {
    let enf = RecordingEnforcer::new();
    enf.ensure_eapol_trap("Ethernet1").await.unwrap();
    let auth = PortAuthorization::Authorized(Authorization {
        vlan: Some("100".to_string()),
        ..Authorization::default()
    });
    enf.apply("Ethernet1", Target::Mac(MAC), &auth)
        .await
        .unwrap();
    enf.apply("Ethernet1", Target::Port, &PortAuthorization::Unauthorized)
        .await
        .unwrap();

    let calls = enf.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0],
        Call::EnsureEapolTrap {
            port: "Ethernet1".to_string()
        }
    );
    assert!(matches!(
        &calls[1],
        Call::Apply { target: Target::Mac(m), auth: PortAuthorization::Authorized(_), .. } if *m == MAC
    ));
    assert!(matches!(
        &calls[2],
        Call::Apply {
            target: Target::Port,
            auth: PortAuthorization::Unauthorized,
            ..
        }
    ));
}
