//! Codec tests for the EAPOL/PACP layer: known-answer vectors, round-trips, and
//! adversarial/malformed inputs. Tests may index and unwrap freely.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use kat::from_hex;
use pacp::eap::{EapCode, EapPacket, EapType};
use pacp::ethernet::{
    self, ETHERTYPE_EAPOL, EthernetHeader, MacAddr, PAE_GROUP_ADDR, decode_eapol_frame,
    decode_frame, format_mac,
};
use pacp::pdu::{EapolPdu, PROTOCOL_VERSION_2010, PacketType};
use pacp::{PacpError, decode_frame as decode_eapol};

const SUPPLICANT_MAC: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

// ---- Known-answer vectors ----

/// A complete EAPOL-Start frame: PAE group dst, supplicant src, `EtherType` 888e,
/// version 3, type 1 (Start), body length 0.
const EAPOL_START_HEX: &str = concat!(
    "0180c2000003", // dst = PAE group address
    "001122334455", // src = supplicant
    "888e",         // EtherType = EAPOL
    "03",           // version 3
    "01",           // type 1 = EAPOL-Start
    "0000",         // body length 0
);

/// A complete EAPOL-EAP frame carrying EAP-Response/Identity "alice".
const EAPOL_EAP_IDENTITY_HEX: &str = concat!(
    "0180c2000003", // dst
    "001122334455", // src
    "888e",         // EtherType
    "03",           // version 3
    "00",           // type 0 = EAPOL-EAP
    "000a",         // body length 10 (EAP packet)
    // EAP packet: code 2 (Response), id 7, length 10, type 1 (Identity), "alice"
    "02",
    "07",
    "000a",
    "01",
    "616c696365", // "alice"
);

#[test]
fn kat_eapol_start_decodes() {
    let bytes = from_hex(EAPOL_START_HEX).unwrap();
    let frame = decode_eapol(&bytes).unwrap();
    assert_eq!(frame.ethernet.dst, PAE_GROUP_ADDR);
    assert_eq!(frame.ethernet.src, SUPPLICANT_MAC);
    assert_eq!(frame.ethernet.ethertype, ETHERTYPE_EAPOL);
    assert_eq!(frame.pdu.version, PROTOCOL_VERSION_2010);
    assert_eq!(frame.pdu.packet_type, PacketType::Start);
    assert!(frame.pdu.body.is_empty());
}

#[test]
fn kat_eapol_start_round_trips_bit_exact() {
    let bytes = from_hex(EAPOL_START_HEX).unwrap();
    let frame = decode_eapol(&bytes).unwrap();
    let reencoded = frame
        .pdu
        .encode_frame(frame.ethernet.dst, frame.ethernet.src)
        .unwrap();
    assert_eq!(reencoded, bytes);
}

#[test]
fn kat_eapol_eap_identity_decodes_and_extracts_username() {
    let bytes = from_hex(EAPOL_EAP_IDENTITY_HEX).unwrap();
    let frame = decode_eapol(&bytes).unwrap();
    assert_eq!(frame.pdu.packet_type, PacketType::Eap);

    let eap = EapPacket::decode(&frame.pdu.body).unwrap();
    assert_eq!(eap.code, EapCode::Response);
    assert_eq!(eap.identifier, 7);
    assert_eq!(eap.eap_type, Some(EapType::Identity));
    assert_eq!(eap.identity().unwrap(), b"alice");
    assert_eq!(frame.ethernet.src_station_id(), "00-11-22-33-44-55");
}

#[test]
fn kat_eapol_eap_round_trips_bit_exact() {
    let bytes = from_hex(EAPOL_EAP_IDENTITY_HEX).unwrap();
    let frame = decode_eapol(&bytes).unwrap();
    let reencoded = frame
        .pdu
        .encode_frame(frame.ethernet.dst, frame.ethernet.src)
        .unwrap();
    assert_eq!(reencoded, bytes);
}

// ---- Ethernet padding tolerance ----

#[test]
fn trailing_ethernet_padding_is_ignored() {
    let mut bytes = from_hex(EAPOL_EAP_IDENTITY_HEX).unwrap();
    // Pad the frame to 60 octets as a switch would for a short frame.
    bytes.resize(60, 0);
    let frame = decode_eapol(&bytes).unwrap();
    // Body is exactly the 10 declared octets — padding is not absorbed.
    assert_eq!(frame.pdu.body.len(), 10);
    let eap = EapPacket::decode(&frame.pdu.body).unwrap();
    assert_eq!(eap.identity().unwrap(), b"alice");
}

// ---- PDU encode/decode units ----

#[test]
fn pdu_round_trip_with_body() {
    let pdu = EapolPdu::new(PacketType::Key, vec![0xde, 0xad, 0xbe, 0xef]);
    let encoded = pdu.encode().unwrap();
    assert_eq!(
        encoded,
        vec![0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(EapolPdu::decode(&encoded).unwrap(), pdu);
}

#[test]
fn packet_type_round_trips_all_known() {
    for raw in [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 200] {
        assert_eq!(PacketType::from_u8(raw).to_u8(), raw);
    }
    assert_eq!(PacketType::from_u8(9), PacketType::Unknown(9));
}

// ---- Malformed / adversarial inputs (must error, never panic) ----

#[test]
fn truncated_ethernet_header_errors() {
    let bytes = from_hex("0180c20000").unwrap(); // 5 octets, < 14
    assert!(matches!(
        decode_eapol(&bytes),
        Err(PacpError::TruncatedEthernet { available: 5 })
    ));
}

#[test]
fn non_eapol_ethertype_errors() {
    // Same framing but EtherType 0x0800 (IPv4).
    let bytes = from_hex("010203040506000102030405080045").unwrap();
    assert!(matches!(
        decode_eapol(&bytes),
        Err(PacpError::NotEapol { ethertype: 0x0800 })
    ));
}

#[test]
fn eapol_body_longer_than_buffer_errors() {
    // version 3, type 0, declared body length 0x00ff but no body present.
    let bytes = from_hex(concat!(
        "0180c2000003",
        "001122334455",
        "888e",
        "03",
        "00",
        "00ff",
    ))
    .unwrap();
    assert!(matches!(
        decode_eapol(&bytes),
        Err(PacpError::TruncatedEapolBody {
            declared: 255,
            available: 0
        })
    ));
}

#[test]
fn truncated_eapol_header_errors() {
    let payload = from_hex("0300").unwrap(); // only 2 of 4 header octets
    assert!(matches!(
        EapolPdu::decode(&payload),
        Err(PacpError::TruncatedEapolHeader { available: 2 })
    ));
}

#[test]
fn eap_length_exceeding_buffer_errors() {
    // code 1 (Request), id 1, length 0x00ff, type 13 — but only 5 octets present.
    let body = from_hex("010100ff0d").unwrap();
    assert!(matches!(
        EapPacket::decode(&body),
        Err(PacpError::EapLengthMismatch {
            declared: 255,
            available: 5
        })
    ));
}

#[test]
fn eap_request_below_minimum_length_errors() {
    // code 1 (Request) with declared length 4 (no Type octet).
    let body = from_hex("01010004").unwrap();
    assert!(matches!(
        EapPacket::decode(&body),
        Err(PacpError::EapTooShort {
            code: 1,
            declared: 4
        })
    ));
}

#[test]
fn truncated_eap_header_errors() {
    let body = from_hex("0101").unwrap();
    assert!(matches!(
        EapPacket::decode(&body),
        Err(PacpError::TruncatedEapHeader { available: 2 })
    ));
}

// ---- EAP view semantics ----

#[test]
fn eap_success_has_no_type_and_no_identity() {
    // code 3 (Success), id 9, length 4.
    let body = from_hex("03090004").unwrap();
    let eap = EapPacket::decode(&body).unwrap();
    assert_eq!(eap.code, EapCode::Success);
    assert_eq!(eap.eap_type, None);
    assert!(eap.identity().is_none());
}

#[test]
fn eap_request_identity_is_not_an_identity_response() {
    // A Request/Identity (server→peer) must NOT yield a User-Name.
    let body = from_hex("0101000501").unwrap(); // code 1, id 1, len 5, type 1
    let eap = EapPacket::decode(&body).unwrap();
    assert_eq!(eap.code, EapCode::Request);
    assert_eq!(eap.eap_type, Some(EapType::Identity));
    assert!(eap.identity().is_none());
}

#[test]
fn eap_response_identity_may_be_empty() {
    // code 2, id 1, len 5, type 1, no identity octets.
    let body = from_hex("0201000501").unwrap();
    let eap = EapPacket::decode(&body).unwrap();
    assert_eq!(eap.identity(), Some(&[][..]));
}

#[test]
fn eap_teap_type_recognized() {
    // code 2 (Response), id 3, len 6, type 55 (TEAP), one data octet.
    let body = from_hex("020300063700").unwrap();
    let eap = EapPacket::decode(&body).unwrap();
    assert_eq!(eap.eap_type, Some(EapType::Teap));
    assert_eq!(eap.type_data, &[0x00]);
}

#[test]
fn eap_length_shorter_than_body_is_rejected() {
    // The EAPOL layer hands EAP an exact, padding-free body, so a declared
    // Length (5) shorter than the buffer (7) is a malformed frame, not padding —
    // honoring it would silently truncate (and could corrupt) the User-Name.
    let body = from_hex("02010005 01 ffff").unwrap();
    assert!(matches!(
        EapPacket::decode(&body),
        Err(PacpError::EapLengthMismatch {
            declared: 5,
            available: 7
        })
    ));
}

#[test]
fn eap_success_with_wrong_length_is_rejected() {
    // RFC 3748 §4.2: Success/Failure Length MUST be 4. A 6-octet Success body
    // declaring Length 6 matches the buffer but violates the code's fixed length.
    let body = from_hex("0309 0006 aabb").unwrap();
    assert!(matches!(
        EapPacket::decode(&body),
        Err(PacpError::EapTooShort {
            code: 3,
            declared: 6
        })
    ));
}

// ---- MAC formatting ----

#[test]
fn format_mac_is_canonical_uppercase_hyphen() {
    assert_eq!(format_mac(&PAE_GROUP_ADDR), "01-80-C2-00-00-03");
    assert_eq!(format_mac(&SUPPLICANT_MAC), "00-11-22-33-44-55");
}

#[test]
fn decode_frame_accepts_non_eapol_but_decode_eapol_frame_rejects() {
    let bytes = from_hex("010203040506000102030405080045").unwrap();
    // Generic decode is happy and reports the EtherType...
    let generic = decode_frame(&bytes).unwrap();
    assert_eq!(generic.header.ethertype, 0x0800);
    // ...the EAPOL-requiring variant rejects it.
    assert!(matches!(
        decode_eapol_frame(&bytes),
        Err(PacpError::NotEapol { ethertype: 0x0800 })
    ));
}

#[test]
fn encode_frame_sets_pae_group_dst_and_ethertype() {
    let pdu = EapolPdu::new(PacketType::Start, vec![]);
    let frame = pdu.encode_frame(PAE_GROUP_ADDR, SUPPLICANT_MAC).unwrap();
    let decoded = decode_eapol(&frame).unwrap();
    assert_eq!(decoded.ethernet.dst, PAE_GROUP_ADDR);
    assert_eq!(decoded.ethernet.ethertype, ETHERTYPE_EAPOL);
    assert_eq!(decoded.pdu.packet_type, PacketType::Start);
    let _ = EthernetHeader {
        dst: PAE_GROUP_ADDR,
        src: SUPPLICANT_MAC,
        ethertype: ethernet::ETHERTYPE_EAPOL,
    };
}
