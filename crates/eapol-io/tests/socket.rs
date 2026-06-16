//! Tests for the portable, deterministic paths of the EAPOL socket layer. The
//! live AF_PACKET rx/tx requires root + a real Linux interface and is exercised
//! in integration on the SONiC target; here we cover validation, name
//! resolution failure, and the constants.
#![allow(clippy::unwrap_used, clippy::doc_markdown, clippy::missing_panics_doc)]

use eapol_io::socket::htons;
use eapol_io::{ETH_P_PAE, EapolError, EapolSocket};

#[test]
fn eapol_ethertype_and_byteorder() {
    assert_eq!(ETH_P_PAE, 0x888E);
    // htons puts the value in network (big-endian) byte order.
    assert_eq!(htons(ETH_P_PAE).to_ne_bytes(), [0x88, 0x8E]);
}

#[test]
fn empty_interface_name_is_rejected() {
    assert!(matches!(
        EapolSocket::open(""),
        Err(EapolError::InvalidInterfaceName(_))
    ));
}

#[test]
fn overlong_interface_name_is_rejected() {
    // >= IFNAMSIZ (16) characters.
    let name = "abcdefghijklmnop"; // 16 chars
    assert!(matches!(
        EapolSocket::open(name),
        Err(EapolError::InvalidInterfaceName(_))
    ));
}

#[test]
fn unknown_interface_is_not_found() {
    // A short, syntactically valid name that does not exist on any host.
    assert!(matches!(
        EapolSocket::open("zzz9"),
        Err(EapolError::InterfaceNotFound(_))
    ));
}
