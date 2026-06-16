//! Errors produced by the EAPOL/PACP codec. Every decode failure is one of
//! these; the codec never panics on malformed input.

/// Codec error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacpError {
    /// Fewer than [`crate::ethernet::HEADER_LEN`] octets remain for an Ethernet header.
    TruncatedEthernet {
        /// Octets actually available.
        available: usize,
    },
    /// The frame's `EtherType` is not EAPOL ([`crate::ethernet::ETHERTYPE_EAPOL`]).
    NotEapol {
        /// The `EtherType` that was found.
        ethertype: u16,
    },
    /// Fewer than [`crate::pdu::HEADER_LEN`] octets remain for an EAPOL PDU header.
    TruncatedEapolHeader {
        /// Octets actually available.
        available: usize,
    },
    /// The EAPOL header's declared body length exceeds the remaining buffer.
    TruncatedEapolBody {
        /// Declared body length.
        declared: usize,
        /// Octets actually available for the body.
        available: usize,
    },
    /// Fewer than [`crate::eap::HEADER_LEN`] octets remain for an EAP header.
    TruncatedEapHeader {
        /// Octets actually available.
        available: usize,
    },
    /// The EAP header's Length field disagrees with the bytes available.
    /// RFC 3748 §4: the Length field counts the entire EAP packet.
    EapLengthMismatch {
        /// Length declared in the EAP header.
        declared: usize,
        /// Octets actually available.
        available: usize,
    },
    /// An EAP packet declared a length below the minimum for its code.
    EapTooShort {
        /// The EAP code (1=Request, 2=Response, 3=Success, 4=Failure).
        code: u8,
        /// The declared length.
        declared: usize,
    },
    /// A value could not be serialized because the body exceeds the 16-bit
    /// EAPOL length field (or the EAP length field).
    BodyTooLong {
        /// The oversized length.
        len: usize,
    },
}

impl core::fmt::Display for PacpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedEthernet { available } => write!(
                f,
                "truncated Ethernet header: {available} octet(s) available, need {}",
                crate::ethernet::HEADER_LEN
            ),
            Self::NotEapol { ethertype } => {
                write!(f, "EtherType {ethertype:#06x} is not EAPOL")
            }
            Self::TruncatedEapolHeader { available } => write!(
                f,
                "truncated EAPOL header: {available} octet(s) available, need {}",
                crate::pdu::HEADER_LEN
            ),
            Self::TruncatedEapolBody {
                declared,
                available,
            } => write!(
                f,
                "truncated EAPOL body: declared {declared}, available {available}"
            ),
            Self::TruncatedEapHeader { available } => write!(
                f,
                "truncated EAP header: {available} octet(s) available, need {}",
                crate::eap::HEADER_LEN
            ),
            Self::EapLengthMismatch {
                declared,
                available,
            } => write!(
                f,
                "EAP length field {declared} disagrees with {available} available octet(s)"
            ),
            Self::EapTooShort { code, declared } => {
                write!(
                    f,
                    "EAP packet (code {code}) length {declared} is below minimum"
                )
            }
            Self::BodyTooLong { len } => {
                write!(f, "body length {len} exceeds the 16-bit length field")
            }
        }
    }
}

impl std::error::Error for PacpError {}
