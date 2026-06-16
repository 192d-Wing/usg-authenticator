//! Tests for RADIUS request building, reply parsing, accounting, and the
//! User-Name sanitization carried forward from the Milestone 1 review.
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
    parse_reply, verify_reply,
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
    // EAP-Response/Identity "alice".
    let eap = [2u8, 1, 0, 10, 1, b'a', b'l', b'i', b'c', b'e'];
    let pkt = access_request_eap(&ctx(), 7, REQ_AUTH, Some(b"alice"), &eap, SECRET).unwrap();

    assert_eq!(pkt.code, Code::AccessRequest);
    assert_eq!(pkt.identifier, 7);
    assert_eq!(find_string(&pkt, AttributeType::UserName), "alice");
    assert_eq!(
        find_string(&pkt, AttributeType::CallingStationId),
        "00-11-22-33-44-55"
    );
    assert_eq!(find_string(&pkt, AttributeType::NasIdentifier), "tor-sw-1");
    // NAS-Port-Type = Ethernet (15).
    let npt = pkt
        .find_attribute(AttributeType::NasPortType as u8)
        .unwrap();
    assert_eq!(npt.value, 15u32.to_be_bytes());
    // The EAP we passed is present as an EAP-Message attribute, verbatim.
    let eap_attr = pkt.find_attribute(79).unwrap();
    assert_eq!(eap_attr.value, eap);
}

#[test]
fn access_request_message_authenticator_is_valid() {
    let eap = [2u8, 1, 0, 5, 1];
    let pkt = access_request_eap(&ctx(), 1, REQ_AUTH, Some(b"x"), &eap, SECRET).unwrap();

    // Recompute: zero the Message-Authenticator, re-encode, HMAC, compare.
    let mut zeroed = pkt.clone();
    let stored = zeroed
        .attributes
        .iter()
        .find(|a| a.attr_type == 80)
        .unwrap()
        .value
        .clone();
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
    // 600-octet EAP packet (a TEAP/TLS handshake fragment) → multiple
    // EAP-Message attributes that reassemble to the original.
    let eap: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    let pkt = access_request_eap(&ctx(), 3, REQ_AUTH, None, &eap, SECRET).unwrap();

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
    assert_eq!(st.value, 10u32.to_be_bytes()); // Call-Check
    assert!(pkt.find_attribute(79).is_none()); // no EAP
}

// ---- User-Name sanitization (fail closed) ----

#[test]
fn identity_with_control_chars_is_rejected() {
    let eap = [2u8, 1, 0, 5, 1];
    for bad in [&b"alice\n"[..], &b"a\0b"[..], &b"x\r\nFilter-Id"[..]] {
        let err = access_request_eap(&ctx(), 1, REQ_AUTH, Some(bad), &eap, SECRET);
        assert!(matches!(err, Err(RadiusClientError::InvalidUserName)));
    }
}

#[test]
fn empty_or_oversize_identity_is_rejected() {
    let eap = [2u8, 1, 0, 5, 1];
    assert!(matches!(
        access_request_eap(&ctx(), 1, REQ_AUTH, Some(b""), &eap, SECRET),
        Err(RadiusClientError::InvalidUserName)
    ));
    let huge = vec![b'a'; 254];
    assert!(matches!(
        access_request_eap(&ctx(), 1, REQ_AUTH, Some(&huge), &eap, SECRET),
        Err(RadiusClientError::InvalidUserName)
    ));
}

// ---- Reply parsing ----

/// Build a reply with a valid Response Authenticator over the request.
fn signed_reply(code: Code, attrs: Vec<Attribute>) -> Packet {
    let mut p = Packet::new(code, 7, [0u8; 16]);
    for a in attrs {
        p.add_attribute(a);
    }
    p.authenticator = calculate_response_authenticator(&p, &REQ_AUTH, SECRET);
    p
}

fn tunnel_group(vlan: &str) -> Attribute {
    // RFC 2868 tagged string: tag octet (1) then the ASCII VLAN id.
    let mut v = vec![1u8];
    v.extend_from_slice(vlan.as_bytes());
    Attribute::new(81, v).unwrap()
}

#[test]
fn parse_access_accept_extracts_authorization() {
    let reply = signed_reply(
        Code::AccessAccept,
        vec![
            tunnel_group("100"),
            Attribute::string(AttributeType::FilterId as u8, "acl-staff").unwrap(),
            Attribute::integer(AttributeType::SessionTimeout as u8, 3600).unwrap(),
            Attribute::new(AttributeType::Class as u8, vec![0xDE, 0xAD]).unwrap(),
            Attribute::new(79, vec![3, 7, 0, 4]).unwrap(), // EAP-Success
        ],
    );
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
fn parse_access_challenge_and_reject() {
    let chal = signed_reply(
        Code::AccessChallenge,
        vec![Attribute::new(79, vec![1, 8, 0, 6, 13, 0]).unwrap()],
    );
    assert!(matches!(
        parse_reply(&chal).unwrap(),
        Event::AccessChallenge { eap } if eap == vec![1, 8, 0, 6, 13, 0]
    ));

    let rej = signed_reply(Code::AccessReject, vec![]);
    assert!(matches!(
        parse_reply(&rej).unwrap(),
        Event::AccessReject { eap: None }
    ));
}

#[test]
fn challenge_without_eap_is_rejected() {
    let chal = signed_reply(Code::AccessChallenge, vec![]);
    assert!(matches!(
        parse_reply(&chal),
        Err(RadiusClientError::MissingEapMessage)
    ));
}

#[test]
fn forged_reply_fails_verification() {
    let reply = signed_reply(Code::AccessAccept, vec![tunnel_group("100")]);
    // Wrong request authenticator → verification fails.
    let wrong = [0u8; 16];
    assert!(!verify_reply(&reply, &wrong, SECRET));
}

#[test]
fn tunnel_group_without_tag_octet_is_parsed() {
    // A value whose first octet is >= 0x20 is all string (no tag).
    let reply = signed_reply(
        Code::AccessAccept,
        vec![Attribute::new(81, b"200".to_vec()).unwrap()],
    );
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
    assert_eq!(st.value, 1u32.to_be_bytes()); // Start
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
    assert_eq!(st.value, 2u32.to_be_bytes()); // Stop
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
    // The accounting Request Authenticator is non-zero (computed).
    assert_ne!(stop.authenticator, [0u8; 16]);
}
