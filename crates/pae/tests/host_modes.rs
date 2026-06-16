//! Tests for the per-port host-mode multiplexing in `PortPae`.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use pacp::eap::{EapCode, EapType};
use pae::config::HostMode;
use pae::effect::{Authorization, Effect, PortAuthorization};
use pae::event::{Event, InboundEap};
use pae::{DirectedEffect, PaeConfig, PortPae};

const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_B: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

fn cfg(mode: HostMode) -> PaeConfig {
    PaeConfig {
        host_mode: mode,
        ..PaeConfig::default()
    }
}

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

fn accept(vlan: &str) -> Event {
    Event::AccessAccept {
        authorization: Authorization {
            vlan: Some(vlan.to_string()),
            ..Authorization::default()
        },
        eap: None,
    }
}

/// Drive a given MAC's session to authorized within a port.
fn authorize(port: &mut PortPae, mac: [u8; 6], vlan: &str) -> Vec<DirectedEffect> {
    port.handle(mac, Event::EapolStart);
    port.handle(mac, Event::EapFromSupplicant(resp_identity(1, b"x")));
    port.handle(mac, accept(vlan))
}

#[test]
fn first_contact_creates_session_and_solicits_identity() {
    let mut port = PortPae::new(cfg(HostMode::MultiAuth));
    let fx = port.handle(MAC_A, Event::EapolStart);
    // The new session is bootstrapped (Enable): port-unauthorized + identity.
    assert!(
        fx.iter()
            .any(|d| d.mac == Some(MAC_A) && matches!(d.effect, Effect::TxEapToSupplicant(_)))
    );
    assert!(port.session(MAC_A).is_some());
    assert_eq!(port.active_sessions(), 1);
}

#[test]
fn multi_auth_admits_independent_sessions_per_mac() {
    let mut port = PortPae::new(cfg(HostMode::MultiAuth));
    authorize(&mut port, MAC_A, "10");
    authorize(&mut port, MAC_B, "20");

    assert!(port.session(MAC_A).unwrap().is_authorized());
    assert!(port.session(MAC_B).unwrap().is_authorized());
    assert_eq!(port.active_sessions(), 2);
}

#[test]
fn single_host_denies_a_second_mac() {
    let mut port = PortPae::new(cfg(HostMode::SingleHost));
    authorize(&mut port, MAC_A, "10");

    // A different MAC gets no session and no effects while the first holds.
    let fx = port.handle(MAC_B, Event::EapolStart);
    assert!(fx.is_empty());
    assert!(port.session(MAC_B).is_none());
    assert_eq!(port.active_sessions(), 1);
}

#[test]
fn multi_host_opens_whole_port_on_first_auth() {
    let mut port = PortPae::new(cfg(HostMode::MultiHost));
    let fx = authorize(&mut port, MAC_A, "10");

    // The session authorization is mirrored as a port-wide open (mac == None)
    // so the dataplane admits every MAC behind the port.
    assert!(fx.iter().any(|d| d.mac.is_none()
        && matches!(
            d.effect,
            Effect::SetAuthorization(PortAuthorization::Authorized(_))
        )));

    // A second MAC rides the open port: no new session, no effects.
    let fx = port.handle(MAC_B, Event::EapolStart);
    assert!(fx.is_empty());
    assert_eq!(port.active_sessions(), 1);
}

#[test]
fn multi_host_logoff_revokes_the_port_wide_open() {
    // Regression: in multi-host the opener logging off must revoke the port-wide
    // open, not leave the whole port admitting every MAC.
    let mut port = PortPae::new(cfg(HostMode::MultiHost));
    authorize(&mut port, MAC_A, "10");

    let fx = port.handle(MAC_A, Event::EapolLogoff);
    assert!(fx.iter().any(|d| d.mac.is_none()
        && matches!(
            d.effect,
            Effect::SetAuthorization(PortAuthorization::Unauthorized)
        )));
    assert_eq!(port.active_sessions(), 0);
}

#[test]
fn multi_domain_admits_two_then_caps() {
    let mut port = PortPae::new(cfg(HostMode::MultiDomain));
    port.handle(MAC_A, Event::EapolStart);
    port.handle(MAC_B, Event::EapolStart);
    assert_eq!(port.active_sessions(), 2);

    // A third MAC is refused.
    let third = [0x00, 0x99, 0x99, 0x99, 0x99, 0x99];
    let fx = port.handle(third, Event::EapolStart);
    assert!(fx.is_empty());
    assert_eq!(port.active_sessions(), 2);
}

#[test]
fn teardown_frees_capacity_in_single_host() {
    let mut port = PortPae::new(cfg(HostMode::SingleHost));
    authorize(&mut port, MAC_A, "10");

    // MAC_A logs off → its session is torn down and pruned.
    let fx = port.handle(MAC_A, Event::EapolLogoff);
    assert!(fx.iter().any(|d| matches!(
        d.effect,
        Effect::SetAuthorization(PortAuthorization::Unauthorized)
    )));
    assert_eq!(port.active_sessions(), 0);
    assert!(port.session(MAC_A).is_none());

    // Now a different MAC can take the port.
    authorize(&mut port, MAC_B, "20");
    assert!(port.session(MAC_B).unwrap().is_authorized());
}

#[test]
fn link_down_tears_down_all_sessions() {
    let mut port = PortPae::new(cfg(HostMode::MultiAuth));
    authorize(&mut port, MAC_A, "10");
    authorize(&mut port, MAC_B, "20");

    let fx = port.link_down();
    // Every session is torn down and the port goes unauthorized port-wide.
    assert!(fx.iter().any(|d| d.mac.is_none()
        && matches!(
            d.effect,
            Effect::SetAuthorization(PortAuthorization::Unauthorized)
        )));
    assert_eq!(port.active_sessions(), 0);
}
