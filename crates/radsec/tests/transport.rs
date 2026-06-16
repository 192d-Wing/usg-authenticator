//! Tests for the locked crypto policy and the RADIUS-over-stream framing. The
//! live TLS handshake against usg-radius is exercised in trio integration (it
//! needs a server) — here we pin the policy and the byte framing.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use radius_proto::{Attribute, Code, Packet};
use radsec::framing::{self, MAX_RADIUS_LEN, MIN_RADIUS_LEN};

// ---- Crypto policy ----

#[test]
fn provider_offers_only_mlkem1024_and_aes256() {
    use rustls::{CipherSuite, NamedGroup};
    let p = radsec::fips::provider();
    assert_eq!(p.kx_groups.len(), 1, "exactly one key-exchange group");
    assert_eq!(p.kx_groups[0].name(), NamedGroup::MLKEM1024);
    assert_eq!(p.cipher_suites.len(), 1, "exactly one cipher suite");
    assert_eq!(
        p.cipher_suites[0].suite(),
        CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    // The policy assertion accepts exactly this provider.
    assert!(radsec::fips::assert_policy(&p).is_ok());
}

#[test]
fn assert_policy_rejects_a_widened_provider() {
    use rustls::crypto::aws_lc_rs;
    // A provider that also offers X25519 (classical) must be rejected.
    let mut p = radsec::fips::provider();
    p.kx_groups.push(aws_lc_rs::kx_group::X25519);
    assert!(radsec::fips::assert_policy(&p).is_err());

    // Adding AES-128 must also be rejected.
    let mut p = radsec::fips::provider();
    p.cipher_suites
        .push(aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256);
    assert!(radsec::fips::assert_policy(&p).is_err());
}

#[test]
fn assert_fips_requires_the_fips_module() {
    // In a non-`fips` build the provider is not FIPS-validated, so the
    // fail-closed FIPS gate must reject it (the policy is still correct).
    let p = radsec::fips::provider();
    if cfg!(feature = "fips") {
        assert!(radsec::fips::assert_fips(&p).is_ok());
    } else {
        assert!(matches!(
            radsec::fips::assert_fips(&p),
            Err(radsec::RadSecError::NotFips)
        ));
    }
}

#[test]
fn client_config_fails_closed_without_fips_module() {
    // The whole transport refuses to build a config off the FIPS boundary. In a
    // non-`fips` build that means client_config cannot succeed at all (the gate
    // runs before any PEM is parsed), so RadSec never runs on a non-FIPS module.
    let result = radsec::client_config(b"", b"", b"");
    if cfg!(feature = "fips") {
        // With FIPS, the gate passes and we fail later on the empty trust anchor.
        assert!(matches!(result, Err(radsec::RadSecError::NoCredential)));
    } else {
        assert!(matches!(result, Err(radsec::RadSecError::NotFips)));
    }
}

// ---- Framing ----

fn sample_packet() -> Packet {
    let mut p = Packet::new(Code::AccessRequest, 7, [0x11; 16]);
    p.add_attribute(Attribute::string(1, "alice").unwrap());
    p
}

#[test]
fn declared_length_reads_the_header_length_field() {
    // code=1, id=7, length=0x0102 (258).
    assert_eq!(framing::declared_length(&[1, 7, 0x01, 0x02]), 258);
}

#[tokio::test]
async fn write_then_read_round_trips_a_packet() {
    let packet = sample_packet();
    let encoded = packet.encode().unwrap();

    // Write to an in-memory buffer, then read it back through the framer.
    let mut sink: Vec<u8> = Vec::new();
    framing::write_packet(&mut sink, &packet).await.unwrap();
    assert_eq!(sink, encoded);

    let mut src = sink.as_slice();
    let decoded = framing::read_packet(&mut src).await.unwrap();
    assert_eq!(decoded.code, Code::AccessRequest);
    assert_eq!(decoded.identifier, 7);
    assert_eq!(decoded.encode().unwrap(), encoded);
}

#[tokio::test]
async fn back_to_back_packets_are_each_delimited_by_length() {
    // Two packets concatenated on one stream must read as two distinct packets.
    let mut stream: Vec<u8> = Vec::new();
    framing::write_packet(&mut stream, &sample_packet())
        .await
        .unwrap();
    let mut second = sample_packet();
    second.identifier = 8;
    framing::write_packet(&mut stream, &second).await.unwrap();

    let mut src = stream.as_slice();
    let a = framing::read_packet(&mut src).await.unwrap();
    let b = framing::read_packet(&mut src).await.unwrap();
    assert_eq!(a.identifier, 7);
    assert_eq!(b.identifier, 8);
}

#[tokio::test]
async fn frame_length_below_minimum_is_rejected() {
    // Header declaring length 4 (< 20) — fail closed before reading a body.
    let bytes = vec![1u8, 7, 0x00, 0x04];
    let mut src = bytes.as_slice();
    assert!(matches!(
        framing::read_packet(&mut src).await,
        Err(radsec::RadSecError::BadFrameLength(4))
    ));
}

#[tokio::test]
async fn frame_length_above_maximum_is_rejected() {
    let too_big = u16::try_from(MAX_RADIUS_LEN).unwrap() + 1;
    let hi = (too_big >> 8) as u8;
    let lo = (too_big & 0xff) as u8;
    let bytes = vec![1u8, 7, hi, lo];
    let mut src = bytes.as_slice();
    assert!(matches!(
        framing::read_packet(&mut src).await,
        Err(radsec::RadSecError::BadFrameLength(n)) if n == MAX_RADIUS_LEN + 1
    ));
}

#[tokio::test]
async fn truncated_body_is_an_io_error_not_a_panic() {
    // Declares a 20-octet packet but supplies only the 4-octet header.
    let bytes = vec![1u8, 7, 0x00, MIN_RADIUS_LEN as u8];
    let mut src = bytes.as_slice();
    assert!(matches!(
        framing::read_packet(&mut src).await,
        Err(radsec::RadSecError::Io(_))
    ));
}
