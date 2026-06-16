//! RADIUS attribute-type numbers and coded values not in `radius_proto`'s
//! `AttributeType` enum, plus the small set of coded constants we emit.

/// `EAP-Message` (RFC 3579) — repeated, each ≤ 253 octets.
pub const EAP_MESSAGE: u8 = 79;
/// `Message-Authenticator` (RFC 3579).
pub const MESSAGE_AUTHENTICATOR: u8 = 80;
/// `NAS-Port-Id` (RFC 2869).
pub const NAS_PORT_ID: u8 = 87;
/// `Tunnel-Private-Group-ID` (RFC 2868) — carries the assigned VLAN.
pub const TUNNEL_PRIVATE_GROUP_ID: u8 = 81;

/// Largest value an `EAP-Message` (or any) attribute can carry: 255-octet TLV
/// minus the 2-octet type/length header.
pub const MAX_ATTR_VALUE: usize = 253;

/// `Service-Type = Framed` (2) — used for 802.1X.
pub const SERVICE_TYPE_FRAMED: u32 = 2;
/// `Service-Type = Call-Check` (10) — used for MAC Authentication Bypass.
pub const SERVICE_TYPE_CALL_CHECK: u32 = 10;
/// `NAS-Port-Type = Ethernet` (15).
pub const NAS_PORT_TYPE_ETHERNET: u32 = 15;
/// RFC 2868 tagged-attribute octet below which a leading byte is a tag, not
/// part of the value.
pub const MAX_TAG_OCTET: u8 = 0x1F;
