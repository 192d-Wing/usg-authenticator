//! Scripted event→effect tests for the per-session authenticator state machine.
//! Tests drive `PortSession::step` and assert the exact effects and resulting
//! state for each transition in DESIGN.md §5.1.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use pacp::eap::{EapCode, EapType, request_identity};
use pae::PaeConfig;
use pae::config::TimerKind;
use pae::effect::{
    AcctTrigger, Authorization, Effect, FallbackReason, PortAuthorization, TerminateCause,
};
use pae::event::{Event, InboundEap};
use pae::session::{PortSession, State};

const MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

fn resp_identity(id: u8, name: &[u8]) -> InboundEap {
    let len = (5 + name.len()) as u16;
    let mut packet = vec![2, id, (len >> 8) as u8, len as u8, 1];
    packet.extend_from_slice(name);
    InboundEap {
        code: EapCode::Response,
        identifier: id,
        eap_type: Some(EapType::Identity),
        packet,
    }
}

fn resp(id: u8) -> InboundEap {
    // A generic EAP-Response (e.g. carrying a method payload) we just relay.
    InboundEap {
        code: EapCode::Response,
        identifier: id,
        eap_type: Some(EapType::Tls),
        packet: vec![2, id, 0, 6, 13, 0xAB],
    }
}

fn accept(vlan: &str) -> Event {
    Event::AccessAccept {
        authorization: Authorization {
            vlan: Some(vlan.to_string()),
            ..Authorization::default()
        },
        eap: Some(vec![3, 7, 0, 4]), // EAP-Success
    }
}

fn tx_id(id: u8) -> Effect {
    Effect::TxEapToSupplicant(request_identity(id).to_vec())
}

/// Drive a fresh session to Authenticated and return it. Asserts the spine of
/// the happy path along the way.
fn authenticate(cfg: &PaeConfig) -> PortSession {
    let mut s = PortSession::new(MAC);

    // Enable: port closed, first identity solicited, tx-period armed.
    let fx = s.step(Event::Enable, cfg);
    assert_eq!(
        fx,
        vec![
            Effect::SetAuthorization(PortAuthorization::Unauthorized),
            tx_id(1),
            Effect::ArmTimer(TimerKind::TxPeriod),
        ]
    );
    assert_eq!(s.state(), State::Connecting);

    // Identity response → relay to server.
    let fx = s.step(Event::EapFromSupplicant(resp_identity(1, b"alice")), cfg);
    assert!(matches!(fx[1], Effect::ToAuthServer { .. }));
    assert_eq!(fx[0], Effect::CancelTimer(TimerKind::TxPeriod));
    assert_eq!(fx[2], Effect::ArmTimer(TimerKind::ServerTimeout));
    assert_eq!(s.state(), State::AuthServer);

    // Server challenge → relay to supplicant.
    let fx = s.step(
        Event::AccessChallenge {
            eap: vec![1, 8, 0, 6, 13, 0x00],
        },
        cfg,
    );
    assert_eq!(fx[0], Effect::CancelTimer(TimerKind::ServerTimeout));
    assert!(matches!(fx[1], Effect::TxEapToSupplicant(_)));
    assert_eq!(fx[2], Effect::ArmTimer(TimerKind::SuppTimeout));
    assert_eq!(s.state(), State::Authenticating);

    // Supplicant response → relay to server.
    let fx = s.step(Event::EapFromSupplicant(resp(8)), cfg);
    assert_eq!(fx[0], Effect::CancelTimer(TimerKind::SuppTimeout));
    assert!(matches!(fx[1], Effect::ToAuthServer { .. }));
    assert_eq!(s.state(), State::AuthServer);

    s
}

#[test]
fn happy_path_authorizes_and_starts_accounting() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);

    let fx = s.step(accept("100"), &cfg);
    assert_eq!(
        fx,
        vec![
            Effect::TxEapToSupplicant(vec![3, 7, 0, 4]), // relayed EAP-Success
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Authorized(Authorization {
                vlan: Some("100".to_string()),
                ..Authorization::default()
            })),
            Effect::Accounting(AcctTrigger::Start),
            Effect::ArmTimer(TimerKind::Reauth),
        ]
    );
    assert!(s.is_authorized());
}

#[test]
fn session_timeout_arms_when_present_and_tears_down_on_expiry() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    let fx = s.step(
        Event::AccessAccept {
            authorization: Authorization {
                session_timeout: Some(120),
                ..Authorization::default()
            },
            eap: None,
        },
        &cfg,
    );
    assert!(fx.contains(&Effect::ArmTimer(TimerKind::SessionTimeout)));
    assert!(s.is_authorized());

    // G-3: no Termination-Action → full de-auth, then re-solicit.
    let fx = s.step(Event::Timer(TimerKind::SessionTimeout), &cfg);
    assert!(fx.contains(&Effect::Accounting(AcctTrigger::Stop(
        TerminateCause::SessionTimeout
    ))));
    assert!(fx.contains(&Effect::SetAuthorization(PortAuthorization::Unauthorized)));
    assert!(fx.contains(&tx_id(2)));
    assert_eq!(s.state(), State::Connecting);
}

#[test]
fn reject_without_fallback_holds_then_retries() {
    let cfg = PaeConfig::default();
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg);
    s.step(Event::EapFromSupplicant(resp_identity(1, b"bob")), &cfg);

    let fx = s.step(
        Event::AccessReject {
            eap: Some(vec![4, 9, 0, 4]),
        },
        &cfg,
    );
    assert_eq!(
        fx,
        vec![
            Effect::TxEapToSupplicant(vec![4, 9, 0, 4]), // relayed EAP-Failure
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Unauthorized),
            Effect::ArmTimer(TimerKind::Held),
        ]
    );
    assert_eq!(s.state(), State::Held);

    let fx = s.step(Event::Timer(TimerKind::Held), &cfg);
    assert!(fx.contains(&tx_id(2)));
    assert_eq!(s.state(), State::Connecting);
}

#[test]
fn reject_with_auth_fail_vlan_applies_fallback() {
    let cfg = PaeConfig {
        auth_fail_vlan: Some("999".to_string()),
        ..PaeConfig::default()
    };
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg);
    s.step(Event::EapFromSupplicant(resp_identity(1, b"bob")), &cfg);

    let fx = s.step(Event::AccessReject { eap: None }, &cfg);
    assert_eq!(
        fx,
        vec![
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Fallback {
                reason: FallbackReason::AuthFail,
                vlan: Some("999".to_string()),
            }),
        ]
    );
    assert_eq!(s.state(), State::Fallback(FallbackReason::AuthFail));
}

#[test]
fn server_unreachable_uses_critical_vlan_when_configured() {
    let cfg = PaeConfig {
        critical_vlan: Some("666".to_string()),
        ..PaeConfig::default()
    };
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg);
    s.step(Event::EapFromSupplicant(resp_identity(1, b"bob")), &cfg);

    let fx = s.step(Event::ServerUnreachable, &cfg);
    assert!(
        fx.contains(&Effect::SetAuthorization(PortAuthorization::Fallback {
            reason: FallbackReason::Critical,
            vlan: Some("666".to_string()),
        }))
    );
    assert!(fx.contains(&Effect::ArmTimer(TimerKind::ServerTimeout)));
    assert_eq!(s.state(), State::Fallback(FallbackReason::Critical));
}

#[test]
fn server_unreachable_without_critical_vlan_fails_closed() {
    let cfg = PaeConfig::default();
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg);
    s.step(Event::EapFromSupplicant(resp_identity(1, b"bob")), &cfg);

    let fx = s.step(Event::Timer(TimerKind::ServerTimeout), &cfg);
    assert!(fx.contains(&Effect::SetAuthorization(PortAuthorization::Unauthorized)));
    assert_eq!(s.state(), State::Held);
}

#[test]
fn mab_after_no_supplicant_then_authorizes() {
    let cfg = PaeConfig {
        mab_enabled: true,
        max_reauth_req: 2,
        ..PaeConfig::default()
    };
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg); // tx_count = 1
    // First tx-period: still under the cap → resend identity.
    let fx = s.step(Event::Timer(TimerKind::TxPeriod), &cfg);
    assert!(fx.contains(&tx_id(2)));
    // Second tx-period: cap reached → MAB.
    let fx = s.step(Event::Timer(TimerKind::TxPeriod), &cfg);
    assert!(fx.contains(&Effect::StartMab { mac: MAC }));
    assert_eq!(s.state(), State::AuthServer);
    assert!(s.is_mab());

    let fx = s.step(accept("50"), &cfg);
    assert!(fx.contains(&Effect::Accounting(AcctTrigger::Start)));
    assert!(s.is_authorized());
}

#[test]
fn no_supplicant_falls_back_to_guest_vlan() {
    let cfg = PaeConfig {
        max_reauth_req: 1,
        guest_vlan: Some("guest".to_string()),
        ..PaeConfig::default()
    };
    let mut s = PortSession::new(MAC);
    s.step(Event::Enable, &cfg); // tx_count = 1, cap = 1
    let fx = s.step(Event::Timer(TimerKind::TxPeriod), &cfg);
    assert!(
        fx.contains(&Effect::SetAuthorization(PortAuthorization::Fallback {
            reason: FallbackReason::Guest,
            vlan: Some("guest".to_string()),
        }))
    );
    assert_eq!(s.state(), State::Fallback(FallbackReason::Guest));

    // A supplicant appearing preempts the guest VLAN.
    let fx = s.step(Event::EapolStart, &cfg);
    assert!(fx.contains(&tx_id(2)));
    assert_eq!(s.state(), State::Connecting);
}

#[test]
fn logoff_tears_down_authorized_session() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    s.step(accept("100"), &cfg);

    let fx = s.step(Event::EapolLogoff, &cfg);
    assert_eq!(
        fx,
        vec![
            Effect::Accounting(AcctTrigger::Stop(TerminateCause::SupplicantLogoff)),
            Effect::CancelAllTimers,
            Effect::SetAuthorization(PortAuthorization::Unauthorized),
        ]
    );
    assert_eq!(s.state(), State::New);
}

#[test]
fn reauth_failure_tears_down_established_session() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    s.step(accept("100"), &cfg);

    // Periodic re-auth begins; port stays authorized meanwhile.
    let fx = s.step(Event::Timer(TimerKind::Reauth), &cfg);
    assert_eq!(fx[0], Effect::CancelTimer(TimerKind::Reauth));
    assert!(fx.contains(&tx_id(2)));
    assert_eq!(s.state(), State::Connecting);

    // Drive to the server, then reject: a reject with an open session is a
    // re-auth failure → full teardown (NOT held).
    s.step(Event::EapFromSupplicant(resp_identity(2, b"alice")), &cfg);
    let fx = s.step(Event::AccessReject { eap: None }, &cfg);
    assert!(fx.contains(&Effect::Accounting(AcctTrigger::Stop(
        TerminateCause::ReauthFailure
    ))));
    assert_eq!(s.state(), State::New);
}

#[test]
fn critical_auth_keeps_open_session_through_outage() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    s.step(accept("100"), &cfg);

    // Re-auth begins, reaches the server, server goes unreachable: the working
    // session is preserved (no de-auth), retry rescheduled.
    s.step(Event::Timer(TimerKind::Reauth), &cfg);
    s.step(Event::EapFromSupplicant(resp_identity(2, b"alice")), &cfg);
    let fx = s.step(Event::ServerUnreachable, &cfg);
    assert!(
        !fx.iter()
            .any(|e| matches!(e, Effect::SetAuthorization(PortAuthorization::Unauthorized)))
    );
    assert!(fx.contains(&Effect::ArmTimer(TimerKind::Reauth)));
    assert!(s.is_authorized());
}

#[test]
fn coa_disconnect_and_authorize() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    s.step(accept("100"), &cfg);

    // CoA-authorize changes the VLAN in place without re-auth.
    let fx = s.step(
        Event::CoaAuthorize {
            authorization: Authorization {
                vlan: Some("200".to_string()),
                ..Authorization::default()
            },
        },
        &cfg,
    );
    assert_eq!(
        fx,
        vec![Effect::SetAuthorization(PortAuthorization::Authorized(
            Authorization {
                vlan: Some("200".to_string()),
                ..Authorization::default()
            }
        ))]
    );
    assert!(s.is_authorized());

    // CoA-disconnect tears the session down.
    let fx = s.step(Event::CoaDisconnect, &cfg);
    assert!(fx.contains(&Effect::Accounting(AcctTrigger::Stop(
        TerminateCause::AdminReset
    ))));
    assert_eq!(s.state(), State::New);
}

#[test]
fn link_down_tears_down_from_any_state() {
    let cfg = PaeConfig::default();
    let mut s = authenticate(&cfg);
    s.step(accept("100"), &cfg);
    let fx = s.step(Event::LinkDown, &cfg);
    assert!(fx.contains(&Effect::Accounting(AcctTrigger::Stop(
        TerminateCause::PortLinkDown
    ))));
    assert_eq!(s.state(), State::New);
}

#[test]
fn unhandled_events_are_safe_no_ops() {
    let cfg = PaeConfig::default();
    let mut s = PortSession::new(MAC);
    // No Enable yet: nothing should happen, and the port must not authorize.
    assert!(s.step(Event::EapolStart, &cfg).is_empty());
    assert!(s.step(Event::Timer(TimerKind::Reauth), &cfg).is_empty());
    assert!(s.step(accept("1"), &cfg).is_empty());
    assert_eq!(s.state(), State::New);
    assert!(!s.is_authorized());
}
