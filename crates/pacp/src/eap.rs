//! A minimal, read-only view of an EAP packet (RFC 3748 §4) — enough for the
//! pass-through authenticator to drive its state machine and build the RADIUS
//! `User-Name`, without interpreting any EAP method.
//!
//! The authenticator never originates inner EAP method content: it relays the
//! whole EAP packet verbatim into a RADIUS `EAP-Message` and copies challenges
//! back. So this module decodes only the common header (Code/Identifier/Length),
//! the method Type for Request/Response, and — for EAP-Response/Identity — the
//! identity octets that become `User-Name`.

use super::error::PacpError;

/// Octets in the common EAP header: `Code(1) | Identifier(1) | Length(2)`.
pub const HEADER_LEN: usize = 4;

/// Minimum length of a Request/Response EAP packet (header + 1 Type octet).
const MIN_REQUEST_RESPONSE_LEN: usize = 5;

/// EAP Code (RFC 3748 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// Request (1) — server→peer.
    Request,
    /// Response (2) — peer→server.
    Response,
    /// Success (3).
    Success,
    /// Failure (4).
    Failure,
    /// An unassigned code, preserved verbatim.
    Unknown(u8),
}

impl EapCode {
    /// Decode a code octet.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Success,
            4 => Self::Failure,
            other => Self::Unknown(other),
        }
    }

    /// Whether this code carries a Type octet (Request/Response only).
    #[must_use]
    pub fn has_type(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

/// EAP method Type number (IANA). Only the ones the authenticator's logic
/// branches on are named; everything else is [`EapType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapType {
    /// Identity (1).
    Identity,
    /// Notification (2).
    Notification,
    /// Legacy Nak (3).
    Nak,
    /// EAP-TLS (13).
    Tls,
    /// EAP-TEAP (55) — the trio's outer method (terminated by usg-radius).
    Teap,
    /// Any other method type.
    Other(u8),
}

impl EapType {
    /// Decode a Type octet.
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            13 => Self::Tls,
            55 => Self::Teap,
            other => Self::Other(other),
        }
    }
}

/// A decoded EAP packet header with borrowed type-data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket<'a> {
    /// The EAP code.
    pub code: EapCode,
    /// The Identifier, used to match Requests with Responses.
    pub identifier: u8,
    /// The method Type — `Some` for Request/Response, `None` for Success/Failure.
    pub eap_type: Option<EapType>,
    /// Type-Data (the method payload), borrowed. Empty for Success/Failure and
    /// for a Request/Response with no data beyond the Type octet.
    pub type_data: &'a [u8],
}

impl<'a> EapPacket<'a> {
    /// Decode an EAP packet from `buf` (an EAPOL-EAP body).
    ///
    /// The EAP Length field is authoritative (RFC 3748 §4): octets beyond it are
    /// ignored as padding, but a Length larger than the buffer, or smaller than
    /// the minimum for the code, is an error.
    ///
    /// # Errors
    /// - [`PacpError::TruncatedEapHeader`] if fewer than [`HEADER_LEN`] octets exist.
    /// - [`PacpError::EapLengthMismatch`] if the Length field exceeds the buffer.
    /// - [`PacpError::EapTooShort`] if the Length is below the minimum for the code.
    pub fn decode(buf: &'a [u8]) -> Result<Self, PacpError> {
        let [code_octet, identifier, len_hi, len_lo] = buf
            .get(..HEADER_LEN)
            .and_then(|s| <[u8; HEADER_LEN]>::try_from(s).ok())
            .ok_or(PacpError::TruncatedEapHeader {
                available: buf.len(),
            })?;

        let declared = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if declared > buf.len() {
            return Err(PacpError::EapLengthMismatch {
                declared,
                available: buf.len(),
            });
        }

        let code = EapCode::from_u8(code_octet);
        if code.has_type() {
            if declared < MIN_REQUEST_RESPONSE_LEN {
                return Err(PacpError::EapTooShort {
                    code: code_octet,
                    declared,
                });
            }
            // Type octet sits at offset HEADER_LEN; type-data runs to `declared`.
            let eap_type = buf.get(HEADER_LEN).copied().map(EapType::from_u8);
            let type_data = buf
                .get(HEADER_LEN.saturating_add(1)..declared)
                .unwrap_or(&[]);
            Ok(Self {
                code,
                identifier,
                eap_type,
                type_data,
            })
        } else {
            // Success/Failure carry no type and, per RFC 3748, Length == 4.
            if declared < HEADER_LEN {
                return Err(PacpError::EapTooShort {
                    code: code_octet,
                    declared,
                });
            }
            Ok(Self {
                code,
                identifier,
                eap_type: None,
                type_data: &[],
            })
        }
    }

    /// If this is an EAP-Response/Identity, the identity octets (the value that
    /// becomes RADIUS `User-Name`). Returns `None` for any other packet.
    ///
    /// Per RFC 3748 §5.1 the identity is not null-terminated and may legitimately
    /// be empty; callers decide how to treat an empty identity.
    #[must_use]
    pub fn identity(&self) -> Option<&'a [u8]> {
        (self.code == EapCode::Response && self.eap_type == Some(EapType::Identity))
            .then_some(self.type_data)
    }
}
