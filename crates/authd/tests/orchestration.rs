//! Tests for the daemon orchestration: config validation, RADIUS session
//! correlation (Identifier/State/verify), timer mapping, and the effect
//! dispatcher driven with mock boundaries (no real sockets/RadSec/SONiC).
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::doc_markdown,
    clippy::missing_panics_doc
)]

use authd::dispatch::{AuthServer, Deps, Orchestrator, Scheduler, SupplicantLink};
use authd::{AuthdConfig, AuthdError, ConfigError, PortConfig, RadiusConfig, RadiusSession};
use enforce::recording::Call;
use enforce::{RecordingEnforcer, Target};
use pacp::ethernet::MacAddr;
use pae::{
    AcctTrigger, Authorization, Effect, Event, FallbackReason, PaeConfig, PortAuthorization,
    PortPae, TimerKind, Timers,
};
use radius_client::RequestContext;
use radius_proto::{
    Attribute, AttributeType, Code, Packet, calculate_message_authenticator,
    calculate_response_authenticator,
};
use std::sync::Mutex;

const SECRET: &[u8] = b"radsec";
const MAC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const CALLED: MacAddr = [0x02, 0, 0, 0, 0, 1];
const REQ_AUTH: [u8; 16] = [0x5A; 16];

fn ctx() -> RequestContext {
    RequestContext {
        nas_ip: Some([10, 0, 0, 1]),
        nas_identifier: "sw1".to_string(),
        nas_port_id: "Ethernet1".to_string(),
        nas_port: None,
        calling_station: MAC,
        called_station: CALLED,
    }
}

fn radius_cfg() -> RadiusConfig {
    RadiusConfig {
        server_addr: "radius.example:2083".to_string(),
        server_name: "radius.example".to_string(),
        ca_pem: b"ca".to_vec(),
        client_cert_pem: b"cert".to_vec(),
        client_key_pem: b"key".to_vec(),
    }
}

// ---- Config validation ----

#[test]
fn valid_config_passes() {
    let cfg = AuthdConfig {
        radius: radius_cfg(),
        ports: vec![PortConfig {
            name: "Ethernet1".to_string(),
            pae: PaeConfig::default(),
        }],
        io_timeout_secs: 30,
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn config_rejects_no_ports_dupes_and_empties() {
    let base = AuthdConfig {
        radius: radius_cfg(),
        ports: vec![],
        io_timeout_secs: 30,
    };
    assert_eq!(base.validate(), Err(ConfigError::NoPorts));

    let dupe = AuthdConfig {
        ports: vec![
            PortConfig {
                name: "E1".into(),
                pae: PaeConfig::default(),
            },
            PortConfig {
                name: "E1".into(),
                pae: PaeConfig::default(),
            },
        ],
        ..base.clone()
    };
    assert_eq!(
        dupe.validate(),
        Err(ConfigError::DuplicatePort("E1".into()))
    );

    let zero = AuthdConfig {
        io_timeout_secs: 0,
        ..base.clone()
    };
    assert_eq!(zero.validate(), Err(ConfigError::ZeroTimeout));

    let mut empty_field = base.clone();
    empty_field.radius.server_name = String::new();
    empty_field.ports = vec![PortConfig {
        name: "E1".into(),
        pae: PaeConfig::default(),
    }];
    assert_eq!(
        empty_field.validate(),
        Err(ConfigError::EmptyField("radius.server_name"))
    );
}

// ---- Timer mapping ----

#[test]
fn timer_durations_map_from_config_except_session_timeout() {
    let timers = Timers::default();
    assert_eq!(
        authd::timers::duration(&timers, TimerKind::TxPeriod),
        Some(core::time::Duration::from_secs(u64::from(timers.tx_period)))
    );
    assert_eq!(
        authd::timers::duration(&timers, TimerKind::Held),
        Some(core::time::Duration::from_secs(u64::from(
            timers.held_period
        )))
    );
    // SessionTimeout is session-supplied, not config-backed.
    assert_eq!(
        authd::timers::duration(&timers, TimerKind::SessionTimeout),
        None
    );
}

// ---- RADIUS session correlation ----

/// Seal a reply like the server: M-A (with the request authenticator) then the
/// Response Authenticator.
fn seal_reply(code: Code, attrs: Vec<Attribute>, req_auth: &[u8; 16]) -> Packet {
    let mut p = Packet::new(code, 0, [0u8; 16]);
    for a in attrs {
        p.add_attribute(a);
    }
    p.add_attribute(Attribute::new(80, vec![0u8; 16]).unwrap());
    p.authenticator = *req_auth;
    let mac = calculate_message_authenticator(&p.encode().unwrap(), SECRET);
    for a in &mut p.attributes {
        if a.attr_type == 80 {
            a.value = mac.to_vec();
        }
    }
    p.authenticator = calculate_response_authenticator(&p, req_auth, SECRET);
    p
}

#[test]
fn session_builds_request_echoes_state_and_verifies_reply() {
    let mut s = RadiusSession::new();
    let eap = [2u8, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e'];

    // First request: no State yet, identity "alice".
    let req = s
        .build_eap_request(&ctx(), Some(b"alice"), &eap, REQ_AUTH, SECRET)
        .unwrap();
    assert_eq!(req.code, Code::AccessRequest);
    assert_eq!(req.identifier, 0);
    assert!(req.find_attribute(24).is_none()); // no State on the first request

    // Server challenges with a State.
    let challenge = seal_reply(
        Code::AccessChallenge,
        vec![
            Attribute::new(79, vec![1, 2, 0, 6, 13, 0]).unwrap(),
            Attribute::new(24, b"sess-state".to_vec()).unwrap(),
        ],
        &REQ_AUTH,
    );
    let ev = s.handle_reply(&challenge, SECRET).unwrap();
    assert!(matches!(ev, Event::AccessChallenge { .. }));

    // Next request echoes the State and uses the next Identifier.
    let req2 = s
        .build_eap_request(&ctx(), None, &[2, 2, 0, 6, 13, 0], [0x11; 16], SECRET)
        .unwrap();
    assert_eq!(req2.identifier, 1);
    assert_eq!(req2.find_attribute(24).unwrap().value, b"sess-state");
}

#[test]
fn session_rejects_forged_reply_and_missing_pending() {
    let mut s = RadiusSession::new();
    // No request outstanding.
    let accept = seal_reply(Code::AccessAccept, vec![], &REQ_AUTH);
    assert!(matches!(
        s.handle_reply(&accept, SECRET),
        Err(AuthdError::NoPendingRequest)
    ));

    // Build a request, then reply sealed with the WRONG authenticator.
    s.build_eap_request(&ctx(), Some(b"x"), &[2, 1, 0, 5, 1], REQ_AUTH, SECRET)
        .unwrap();
    let forged = seal_reply(Code::AccessAccept, vec![], &[0u8; 16]);
    assert!(matches!(
        s.handle_reply(&forged, SECRET),
        Err(AuthdError::ReplyVerificationFailed)
    ));
}

// ---- Effect dispatcher with mock boundaries ----

#[derive(Default)]
struct MockSupplicant {
    sent: Mutex<Vec<(MacAddr, Vec<u8>)>>,
}
impl SupplicantLink for MockSupplicant {
    async fn send_eap(&self, mac: MacAddr, eap: Vec<u8>) -> Result<(), AuthdError> {
        self.sent.lock().unwrap().push((mac, eap));
        Ok(())
    }
}

/// A mock server that seals a valid Access-Accept (VLAN 100) for any request.
#[derive(Default)]
struct MockServer {
    requests: Mutex<u32>,
    accounting: Mutex<u32>,
}
impl AuthServer for MockServer {
    async fn access_request(&self, request: &Packet) -> Result<Packet, AuthdError> {
        *self.requests.lock().unwrap() += 1;
        let group = {
            let mut v = vec![1u8];
            v.extend_from_slice(b"100");
            v
        };
        let attrs = vec![
            Attribute::new(64, vec![1, 0, 0, 13]).unwrap(),
            Attribute::new(65, vec![1, 0, 0, 6]).unwrap(),
            Attribute::new(81, group).unwrap(),
            Attribute::new(79, vec![3, request.identifier, 0, 4]).unwrap(),
        ];
        Ok(seal_reply(
            Code::AccessAccept,
            attrs,
            &request.authenticator,
        ))
    }
    async fn accounting(&self, _request: &Packet) -> Result<(), AuthdError> {
        *self.accounting.lock().unwrap() += 1;
        Ok(())
    }
}

#[derive(Default)]
struct MockScheduler {
    armed: Mutex<Vec<(MacAddr, TimerKind)>>,
    cancelled_all: Mutex<Vec<MacAddr>>,
}
impl Scheduler for MockScheduler {
    fn arm(&self, mac: MacAddr, kind: TimerKind, _dur: core::time::Duration) {
        self.armed.lock().unwrap().push((mac, kind));
    }
    fn cancel(&self, _mac: MacAddr, _kind: TimerKind) {}
    fn cancel_all(&self, mac: MacAddr) {
        self.cancelled_all.lock().unwrap().push(mac);
    }
}

fn deps<'a>(
    sup: &'a MockSupplicant,
    srv: &'a MockServer,
    enf: &'a RecordingEnforcer,
    sch: &'a MockScheduler,
    timers: &'a Timers,
) -> Deps<'a, MockSupplicant, MockServer, RecordingEnforcer, MockScheduler> {
    Deps {
        supplicant: sup,
        server: srv,
        enforcer: enf,
        scheduler: sch,
        timers,
        secret: SECRET,
    }
}

#[tokio::test]
async fn dispatch_set_authorization_calls_enforcer() {
    let (sup, srv, enf, sch, timers) = (
        MockSupplicant::default(),
        MockServer::default(),
        RecordingEnforcer::new(),
        MockScheduler::default(),
        Timers::default(),
    );
    let d = deps(&sup, &srv, &enf, &sch, &timers);
    let mut orch = Orchestrator::new("Ethernet1".to_string(), ctx());
    let pae = PortPae::new(PaeConfig::default());

    // Feed an authorize directly through the PAE→dispatch path is complex; assert
    // the enforcer wiring via a port-wide unauthorized from enable().
    orch.apply_effects(pae.enable(), &d).await.unwrap();
    assert!(enf.calls().iter().any(|c| matches!(
        c,
        Call::Apply {
            target: Target::Port,
            auth: PortAuthorization::Unauthorized,
            ..
        }
    )));
}

#[tokio::test]
async fn full_eap_exchange_authorizes_via_mock_server() {
    let (sup, srv, enf, sch, timers) = (
        MockSupplicant::default(),
        MockServer::default(),
        RecordingEnforcer::new(),
        MockScheduler::default(),
        Timers::default(),
    );
    let d = deps(&sup, &srv, &enf, &sch, &timers);
    let mut orch = Orchestrator::new("Ethernet1".to_string(), ctx());
    let mut pae = PortPae::new(PaeConfig::default());

    // Supplicant appears and sends its identity; the mock server returns Accept.
    orch.handle_event(&mut pae, MAC, Event::EapolStart, &d)
        .await
        .unwrap();
    let identity = vec![2u8, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e'];
    orch.handle_event(
        &mut pae,
        MAC,
        Event::EapFromSupplicant(pae::InboundEap {
            code: pacp::eap::EapCode::Response,
            identifier: 1,
            eap_type: Some(pacp::eap::EapType::Identity),
            packet: identity,
        }),
        &d,
    )
    .await
    .unwrap();

    // A RADIUS round-trip happened and the port was authorized on VLAN 100.
    assert_eq!(*srv.requests.lock().unwrap(), 1);
    assert!(enf.calls().iter().any(|c| matches!(
        c,
        Call::Apply { auth: PortAuthorization::Authorized(a), .. } if a.vlan.as_deref() == Some("100")
    )));
    // Accounting-Start was sent, and a reauth timer armed.
    assert_eq!(*srv.accounting.lock().unwrap(), 1);
    assert!(
        sch.armed
            .lock()
            .unwrap()
            .iter()
            .any(|(_, k)| *k == TimerKind::Reauth)
    );
    // The supplicant got the relayed EAP-Success.
    assert!(!sup.sent.lock().unwrap().is_empty());
    assert!(pae.session(MAC).unwrap().is_authorized());
}

#[tokio::test]
async fn unused_helpers_are_referenced() {
    // Touch the otherwise-unused effect/fallback imports so the test module
    // documents the full surface without dead-code warnings.
    let _ = Effect::CancelAllTimers;
    let _ = FallbackReason::Guest;
    let _ = Authorization::default();
    let _ = AcctTrigger::Start;
    let _ = AttributeType::UserName;
}
