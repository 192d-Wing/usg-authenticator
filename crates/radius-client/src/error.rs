//! Errors produced while building or parsing RADIUS packets.

use radius_proto::PacketError;

/// A `radius-client` error.
#[derive(Debug)]
pub enum RadiusClientError {
    /// The underlying `radius-proto` codec rejected an attribute or packet.
    Proto(PacketError),
    /// An EAP identity could not be used as a `User-Name`: empty, too long,
    /// not valid UTF-8, or containing control characters (NUL/CR/LF/…). We fail
    /// closed rather than forward an injectable `User-Name` to the policy engine
    /// (SERVER-CONTRACT.md §2/§5 V-3).
    InvalidUserName,
    /// A reply had a code the authenticator does not expect on the auth path.
    UnexpectedReplyCode(u8),
    /// An `Access-Challenge` carried no `EAP-Message` to relay.
    MissingEapMessage,
    /// Asked to relay an empty EAP packet — there is nothing to send, and a
    /// request with no `EAP-Message` and no `User-Name` is degenerate.
    EmptyEapRelay,
    /// An `Access-Accept` carried a VLAN (`Tunnel-Private-Group-ID`) without the
    /// RFC 3580 `Tunnel-Type = VLAN(13)` / `Tunnel-Medium-Type = 802(6)` pair, or
    /// with an empty group id. We refuse the assignment (fail closed).
    MalformedVlanAssignment,
}

impl From<PacketError> for RadiusClientError {
    fn from(e: PacketError) -> Self {
        Self::Proto(e)
    }
}

impl core::fmt::Display for RadiusClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Proto(e) => write!(f, "RADIUS codec error: {e}"),
            Self::InvalidUserName => {
                write!(
                    f,
                    "EAP identity is not a valid User-Name (empty/long/control chars)"
                )
            }
            Self::UnexpectedReplyCode(c) => write!(f, "unexpected RADIUS reply code {c}"),
            Self::MissingEapMessage => write!(f, "Access-Challenge carried no EAP-Message"),
            Self::EmptyEapRelay => write!(f, "asked to relay an empty EAP packet"),
            Self::MalformedVlanAssignment => {
                write!(
                    f,
                    "VLAN assignment lacks Tunnel-Type=13/Tunnel-Medium-Type=6 or is empty"
                )
            }
        }
    }
}

impl std::error::Error for RadiusClientError {}
