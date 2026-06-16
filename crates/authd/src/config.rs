//! Daemon configuration and validation.

use pae::PaeConfig;

/// How to reach the authentication server over RadSec.
#[derive(Debug, Clone)]
pub struct RadiusConfig {
    /// `host:port` of the usg-radius RadSec endpoint (default port 2083).
    pub server_addr: String,
    /// DNS name to validate the server certificate against.
    pub server_name: String,
    /// PEM trust anchor(s) for the server certificate.
    pub ca_pem: Vec<u8>,
    /// PEM NAS client certificate chain.
    pub client_cert_pem: Vec<u8>,
    /// PEM NAS client private key.
    pub client_key_pem: Vec<u8>,
}

/// Per-port configuration: the interface name and its PAE policy.
#[derive(Debug, Clone)]
pub struct PortConfig {
    /// Front-panel interface name (e.g. `Ethernet12`).
    pub name: String,
    /// PAE policy (host mode, timers, MAB, fallback VLANs).
    pub pae: PaeConfig,
}

/// Top-level daemon configuration.
#[derive(Debug, Clone)]
pub struct AuthdConfig {
    /// Authentication-server connection.
    pub radius: RadiusConfig,
    /// Ports to bring into 802.1X service.
    pub ports: Vec<PortConfig>,
    /// Bound on every RadSec connect/read (seconds).
    pub io_timeout_secs: u64,
}

/// A configuration validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No ports were configured.
    NoPorts,
    /// Two ports share the same interface name.
    DuplicatePort(String),
    /// A required field was empty.
    EmptyField(&'static str),
    /// `io_timeout_secs` was zero or above the cap.
    BadTimeout,
    /// `server_addr` is not a `host:port` with a valid port.
    BadServerAddr(String),
}

/// Upper bound on `io_timeout_secs` — a fat-fingered value must not let a single
/// RADIUS round-trip block a port for minutes.
const MAX_IO_TIMEOUT_SECS: u64 = 120;

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoPorts => write!(f, "no ports configured"),
            Self::DuplicatePort(p) => write!(f, "duplicate port {p:?}"),
            Self::EmptyField(field) => write!(f, "required field {field} is empty"),
            Self::BadTimeout => {
                write!(f, "io_timeout_secs must be in 1..={MAX_IO_TIMEOUT_SECS}")
            }
            Self::BadServerAddr(a) => write!(f, "server_addr {a:?} is not host:port"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl AuthdConfig {
    /// Validate the configuration, failing closed on anything that would leave a
    /// port unserviceable or the daemon misconfigured.
    ///
    /// # Errors
    /// A [`ConfigError`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.io_timeout_secs == 0 || self.io_timeout_secs > MAX_IO_TIMEOUT_SECS {
            return Err(ConfigError::BadTimeout);
        }
        if self.radius.server_addr.is_empty() {
            return Err(ConfigError::EmptyField("radius.server_addr"));
        }
        // Require `host:port` with a parseable, non-zero port.
        match self.radius.server_addr.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0) => {
            }
            _ => return Err(ConfigError::BadServerAddr(self.radius.server_addr.clone())),
        }
        if self.radius.server_name.is_empty() {
            return Err(ConfigError::EmptyField("radius.server_name"));
        }
        if self.radius.ca_pem.is_empty() {
            return Err(ConfigError::EmptyField("radius.ca_pem"));
        }
        if self.radius.client_cert_pem.is_empty() {
            return Err(ConfigError::EmptyField("radius.client_cert_pem"));
        }
        if self.radius.client_key_pem.is_empty() {
            return Err(ConfigError::EmptyField("radius.client_key_pem"));
        }
        if self.ports.is_empty() {
            return Err(ConfigError::NoPorts);
        }
        let mut seen = std::collections::HashSet::new();
        for port in &self.ports {
            if port.name.is_empty() {
                return Err(ConfigError::EmptyField("port.name"));
            }
            if !seen.insert(port.name.as_str()) {
                return Err(ConfigError::DuplicatePort(port.name.clone()));
            }
        }
        Ok(())
    }
}
