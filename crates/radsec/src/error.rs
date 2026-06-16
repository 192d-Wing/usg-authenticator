//! Errors from the `RadSec` transport.

use radius_proto::PacketError;

/// A `RadSec` error.
#[derive(Debug)]
pub enum RadSecError {
    /// Underlying socket / TLS I/O error.
    Io(std::io::Error),
    /// rustls configuration or handshake error.
    Tls(rustls::Error),
    /// The crypto provider is not FIPS-validated (the `fips` build feature is
    /// off, or the platform module failed its power-on self-test).
    NotFips,
    /// The negotiated/offered crypto policy is not the locked one: key exchange
    /// must be ML-KEM-1024 only and the cipher suite `TLS_AES_256_GCM_SHA384`.
    CryptoPolicyViolation,
    /// A PEM input held no usable certificate or private key.
    NoCredential,
    /// A RADIUS frame declared a length outside the valid 20..=4096 range.
    BadFrameLength(usize),
    /// The framed bytes did not decode as a RADIUS packet.
    Proto(PacketError),
    /// A DNS name for the server certificate was invalid.
    BadServerName,
}

impl core::fmt::Display for RadSecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Tls(e) => write!(f, "TLS error: {e}"),
            Self::NotFips => write!(f, "crypto provider is not FIPS-validated"),
            Self::CryptoPolicyViolation => {
                write!(
                    f,
                    "crypto policy is not ML-KEM-1024 + TLS_AES_256_GCM_SHA384 only"
                )
            }
            Self::NoCredential => write!(f, "PEM held no usable certificate or key"),
            Self::BadFrameLength(n) => write!(f, "RADIUS frame length {n} outside 20..=4096"),
            Self::Proto(e) => write!(f, "RADIUS codec error: {e}"),
            Self::BadServerName => write!(f, "invalid server DNS name"),
        }
    }
}

impl std::error::Error for RadSecError {}

impl From<std::io::Error> for RadSecError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustls::Error> for RadSecError {
    fn from(e: rustls::Error) -> Self {
        Self::Tls(e)
    }
}

impl From<PacketError> for RadSecError {
    fn from(e: PacketError) -> Self {
        Self::Proto(e)
    }
}
