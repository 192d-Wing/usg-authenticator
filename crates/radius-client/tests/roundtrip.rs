//! Tests for RADIUS request building, reply parsing/verification, accounting,
//! State echoing, and the User-Name sanitization carried from the M1 review.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use pae::{AcctTrigger, Event, TerminateCause};
use radius_client::{
    RadiusClientError, RequestContext, access_request_eap, access_request_mab, accounting_request,
    extract_state, parse_reply, verify_reply,
};
use radius_proto::{
    Attribute, AttributeType, Code, Packet, calculate_message_authenticator,
    calculate_response_authenticator,
};

const SECRET: &[u8] = b"radsec";
const REQ_AUTH: [u8; 16] = [0xA5; 16];
const CALLING: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const CALLED: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

fn ctx() -> RequestContext {
    RequestContext {
        nas_ip: Some([10, 0, 0, 1]),
        nas_identifier: "tor-sw-1".to_string(),
        nas_port_id: "Ethernet12".to_string(),
        nas_port: Some(12),
        calling_station: CALLING,
        called_station: CALLED,
    }
}

fn find_string(p: &Packet, ty: AttributeType) -> String {
    String::from_utf8(p.find_attribute(ty as u8).unwrap().value.clone()).unwrap()
}

// ---- Access-Request (EAP) ----

#[test]
fn access_request_carries_nas_attrs_username_and_eap() {
    let eap = [2u8, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e'];
    let pkt = access_request_eap(&ctx(), 7, REQ_AUTH, Some(b"alice"), None, &eap, SECRET).unwrap();

    assert_eq!(pkt.code, Code::AccessRequest);
    assert_eq!(find_string(&pkt, AttributeType::UserName), "alice");
    assert_eq!(
        find_string(&pkt, AttributeType::CallingStationId),
        "00-11-22-33-44-55"
    );
    assert_eq!(find_string(&pkt, AttributeType::NasIdentifier), "tor-sw-1");
    let npt = pkt
        .find_attribute(AttributeType::NasPortType as u8)
        .unwrap();
    assert_eq!(npt.value, 15u32.to_be_bytes());
    assert_eq!(pkt.find_attribute(79).unwrap().value, eap);
    // No challenge yet → no State echoed.
    assert!(pkt.find_attribute(24).is_none());
}

#[test]
fn access_request_echoes_state_from_challenge() {
    let eap = [2u8, 5, 0, 6, 13, 0x00];
    let state = b"opaque-server-state";
    let pkt = access_request_eap(&ctx(), 5, REQ_AUTH, None, Some(state), &eap, SECRET).unwrap();
    // The State attribute (24) is echoed verbatim so the server finds the
    // in-flight EAP session.
    assert_eq!(pkt.find_attribute(24).unwrap().value, state);
}

#[test]
fn empty_eap_relay_is_rejected() {
    assert!(matches!(
        access_request_eap(&ctx(), 1, REQ_AUTH, None, None, &[], SECRET),
        Err(RadiusClientError::EmptyEapRelay)
    ));
}

#[test]
fn access_request_message_authenticator_is_valid() {
    let eap = [2u8, 1, 0, 5, 1];
    let pkt = access_request_eap(&ctx(), 1, REQ_AUTH, Some(b"x"), None, &eap, SECRET).unwrap();

    let mut zeroed = pkt.clone();
    let stored = zeroed
        .attributes
        .iter()
        .find(|a| a.attr_type == 80)
        .unwrap()
        .value
        .clone();
    // Exactly one Message-Authenticator (seal is idempotent).
    assert_eq!(
        zeroed
            .attributes
            .iter()
            .filter(|a| a.attr_type == 80)
            .count(),
        1
    );
    for a in &mut zeroed.attributes {
        if a.attr_type == 80 {
            a.value = vec![0u8; 16];
        }
    }
    let expected = calculate_message_authenticator(&zeroed.encode().unwrap(), SECRET);
    assert_eq!(stored, expected.to_vec());
}

#[test]
fn long_eap_is_fragmented_then_reassembles_verbatim() {
    let eap: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    let pkt = access_request_eap(&ctx(), 3, REQ_AUTH, None, None, &eap, SECRET).unwrap();

    let frags = pkt.find_all_attributes(79);
    assert!(frags.len() >= 3);
    assert!(frags.iter().all(|a| a.value.len() <= 253));
    let reassembled: Vec<u8> = frags.iter().flat_map(|a| a.value.clone()).collect();
    assert_eq!(reassembled, eap);
}

// ---- MAB ----

#[test]
fn mab_request_uses_mac_username_and_call_check() {
    let pkt = access_request_mab(&ctx(), 9, REQ_AUTH, SECRET).unwrap();
    assert_eq!(
        find_string(&pkt, AttributeType::UserName),
        "00-11-22-33-44-55"
    );
    let st = pkt
        .find_attribute(AttributeType::ServiceType as u8)
        .unwrap();
    assert_eq!(st.value, 10u32.to_be_bytes());
    assert!(pkt.find_attribute(79).is_none());
}

// ---- User-Name sanitization (fail closed) ----

#[test]
fn identity_with_control_or_separator_chars_is_rejected() {
    let eap = [2u8, 1, 0, 5, 1];
    let line_sep = "a\u{2028}b";
    for bad in [
        &b"alice\n"[..],
        &b"a\0b"[..],
        &b"x\r\nFilter-Id"[..],
        line_sep.as_bytes(),
    ] {
        let err = access_request_eap(&ctx(), 1, REQ_AUTH, Some(bad), None, &eap, SECRET);
        assert!(matches!(err, Err(RadiusClientError::InvalidUserName)));
    }
}

#[test]
fn empty_or_oversize_identity_is_rejected() {
    let eap = [2u8, 1, 0, 5, 1];
    assert!(matches!(
        access_request_eap(&ctx(), 1, REQ_AUTH, Some(b""), None, &eap, SECRET),
        Err(RadiusClientError::InvalidUserName)
    ));
    let huge = vec![b'a'; 254];
    assert!(matches!(
        access_request_eap(&ctx(), 1, REQ_AUTH, Some(&huge), None, &eap, SECRET),
        Err(RadiusClientError::InvalidUserName)
    ));
}

// ---- Reply fixtures: seal like the server (M-A then Response Authenticator) ----

fn seal_reply(code: Code, attrs: Vec<Attribute>) -> Packet {
    let mut p = Packet::new(code, 7, [0u8; 16]);
    for a in attrs {
        p.add_attribute(a);
    }
    // Message-Authenticator is computed with the Request Authenticator in the
    // authenticator field (RFC 3579 §3.2).
    p.add_attribute(Attribute::new(80, vec![0u8; 16]).unwrap());
    p.authenticator = REQ_AUTH;
    let mac = calculate_message_authenticator(&p.encode().unwrap(), SECRET);
    for a in &mut p.attributes {
        if a.attr_type == 80 {
            a.value = mac.to_vec();
        }
    }
    p.authenticator = calculate_response_authenticator(&p, &REQ_AUTH, SECRET);
    p
}

/// A valid RFC 3580 VLAN group: Tunnel-Type=13, Tunnel-Medium-Type=6, and the
/// Tunnel-Private-Group-ID (tagged or untagged).
fn vlan_group(vlan: &str, tagged: bool) -> Vec<Attribute> {
    let group = if tagged {
        let mut v = vec![1u8];
        v.extend_from_slice(vlan.as_bytes());
        v
    } else {
        vlan.as_bytes().to_vec()
    };
    vec![
        Attribute::new(64, vec![1, 0, 0, 13]).unwrap(),
        Attribute::new(65, vec![1, 0, 0, 6]).unwrap(),
        Attribute::new(81, group).unwrap(),
    ]
}

#[test]
fn parse_access_accept_extracts_authorization() {
    let mut attrs = vlan_group("100", true);
    attrs.push(Attribute::string(AttributeType::FilterId as u8, "acl-staff").unwrap());
    attrs.push(Attribute::integer(AttributeType::SessionTimeout as u8, 3600).unwrap());
    attrs.push(Attribute::new(AttributeType::Class as u8, vec![0xDE, 0xAD]).unwrap());
    attrs.push(Attribute::new(79, vec![3, 7, 0, 4]).unwrap()); // EAP-Success
    let reply = seal_reply(Code::AccessAccept, attrs);

    assert!(verify_reply(&reply, &REQ_AUTH, SECRET));
    match parse_reply(&reply).unwrap() {
        Event::AccessAccept { authorization, eap } => {
            assert_eq!(authorization.vlan.as_deref(), Some("100"));
            assert_eq!(authorization.filter_id.as_deref(), Some("acl-staff"));
            assert_eq!(authorization.session_timeout, Some(3600));
            assert_eq!(authorization.class.as_deref(), Some(&[0xDE, 0xAD][..]));
            assert_eq!(eap.as_deref(), Some(&[3, 7, 0, 4][..]));
        }
        other => panic!("expected AccessAccept, got {other:?}"),
    }
}

#[test]
fn challenge_verifies_and_state_is_extracted() {
    let reply = seal_reply(
        Code::AccessChallenge,
        vec![
            Attribute::new(79, vec![1, 8, 0, 6, 13, 0]).unwrap(),
            Attribute::new(24, b"sess-7".to_vec()).unwrap(),
        ],
    );
    assert!(verify_reply(&reply, &REQ_AUTH, SECRET));
    assert_eq!(extract_state(&reply), Some(b"sess-7".to_vec()));
    assert!(matches!(
        parse_reply(&reply).unwrap(),
        Event::AccessChallenge { eap } if eap == vec![1, 8, 0, 6, 13, 0]
    ));
}

#[test]
fn reject_parses_with_no_eap() {
    let rej = seal_reply(Code::AccessReject, vec![]);
    assert!(verify_reply(&rej, &REQ_AUTH, SECRET));
    assert!(matches!(
        parse_reply(&rej).unwrap(),
        Event::AccessReject { eap: None }
    ));
}

#[test]
fn challenge_without_eap_is_rejected() {
    let chal = seal_reply(Code::AccessChallenge, vec![]);
    assert!(matches!(
        parse_reply(&chal),
        Err(RadiusClientError::MissingEapMessage)
    ));
}

#[test]
fn reply_with_eap_but_no_message_authenticator_fails_verification() {
    // Access-Accept carrying EAP but WITHOUT a Message-Authenticator, with only a
    // valid Response Authenticator — must fail (RFC 3579 §3.2).
    let mut p = Packet::new(Code::AccessAccept, 7, [0u8; 16]);
    p.add_attribute(Attribute::new(79, vec![3, 7, 0, 4]).unwrap());
    p.authenticator = calculate_response_authenticator(&p, &REQ_AUTH, SECRET);
    assert!(!verify_reply(&p, &REQ_AUTH, SECRET));
}

#[test]
fn forged_reply_fails_verification() {
    let reply = seal_reply(Code::AccessAccept, vlan_group("100", true));
    let wrong = [0u8; 16];
    assert!(!verify_reply(&reply, &wrong, SECRET));
}

#[test]
fn vlan_without_tunnel_type_is_rejected_fail_closed() {
    // A Tunnel-Private-Group-ID present without Tunnel-Type/Medium-Type.
    let group = {
        let mut v = vec![1u8];
        v.extend_from_slice(b"100");
        v
    };
    let reply = seal_reply(Code::AccessAccept, vec![Attribute::new(81, group).unwrap()]);
    assert!(matches!(
        parse_reply(&reply),
        Err(RadiusClientError::MalformedVlanAssignment)
    ));
}

#[test]
fn untagged_tunnel_group_is_parsed() {
    // First octet >= 0x20 → no tag; whole value is the VLAN id.
    let reply = seal_reply(Code::AccessAccept, vlan_group("200", false));
    match parse_reply(&reply).unwrap() {
        Event::AccessAccept { authorization, .. } => {
            assert_eq!(authorization.vlan.as_deref(), Some("200"));
        }
        other => panic!("expected AccessAccept, got {other:?}"),
    }
}

// ---- Accounting ----

#[test]
fn accounting_start_and_stop_round_trip() {
    let start = accounting_request(&ctx(), 1, AcctTrigger::Start, "sess-42", None, SECRET).unwrap();
    assert_eq!(start.code, Code::AccountingRequest);
    let st = start
        .find_attribute(AttributeType::AcctStatusType as u8)
        .unwrap();
    assert_eq!(st.value, 1u32.to_be_bytes());
    assert_eq!(find_string(&start, AttributeType::AcctSessionId), "sess-42");

    let stop = accounting_request(
        &ctx(),
        2,
        AcctTrigger::Stop(TerminateCause::SupplicantLogoff),
        "sess-42",
        Some(&[0xDE, 0xAD]),
        SECRET,
    )
    .unwrap();
    let st = stop
        .find_attribute(AttributeType::AcctStatusType as u8)
        .unwrap();
    assert_eq!(st.value, 2u32.to_be_bytes());
    let tc = stop
        .find_attribute(AttributeType::AcctTerminateCause as u8)
        .unwrap();
    assert_eq!(tc.value, 1u32.to_be_bytes()); // User-Request
    assert_eq!(
        stop.find_attribute(AttributeType::Class as u8)
            .unwrap()
            .value,
        vec![0xDE, 0xAD]
    );
    assert_ne!(stop.authenticator, [0u8; 16]);
}
