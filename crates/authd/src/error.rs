//! The daemon's top-level error type.

use crate::config::ConfigError;
use radius_client::RadiusClientError;

/// An error from the authenticator daemon.
#[derive(Debug)]
pub enum AuthdError {
    /// Invalid configuration.
    Config(ConfigError),
    /// Building or parsing a RADIUS packet failed.
    Radius(RadiusClientError),
    /// A RADIUS reply arrived with no request outstanding for the session.
    NoPendingRequest,
    /// A RADIUS reply failed Response/Message-Authenticator verification.
    ReplyVerificationFailed,
    /// The RadSec transport failed.
    RadSec(radsec::RadSecError),
    /// The EAPOL socket layer failed.
    Eapol(eapol_io::EapolError),
    /// The dataplane could not be programmed/confirmed (fail closed).
    Enforce(String),
    /// Building an outbound EAPOL frame failed.
    Frame(pacp::PacpError),
}

impl core::fmt::Display for AuthdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config error: {e}"),
            Self::Radius(e) => write!(f, "RADIUS error: {e}"),
            Self::NoPendingRequest => write!(f, "RADIUS reply with no outstanding request"),
            Self::ReplyVerificationFailed => write!(f, "RADIUS reply failed verification"),
            Self::RadSec(e) => write!(f, "RadSec error: {e}"),
            Self::Eapol(e) => write!(f, "EAPOL socket error: {e}"),
            Self::Enforce(e) => write!(f, "enforcement error: {e}"),
            Self::Frame(e) => write!(f, "EAPOL frame error: {e}"),
        }
    }
}

impl std::error::Error for AuthdError {}

impl From<ConfigError> for AuthdError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}
impl From<radsec::RadSecError> for AuthdError {
    fn from(e: radsec::RadSecError) -> Self {
        Self::RadSec(e)
    }
}
impl From<eapol_io::EapolError> for AuthdError {
    fn from(e: eapol_io::EapolError) -> Self {
        Self::Eapol(e)
    }
}
