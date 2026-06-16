//! Building the mutual-TLS 1.3 client configuration for `RadSec`.
//!
//! The switch (NAS) presents a client certificate — in production a TPM-resident
//! key enrolled via usg-est-client (SERVER-CONTRACT §1.2) — and pins usg-radius's
//! server certificate against a configured trust anchor. TLS 1.3 only, with the
//! locked ML-KEM-1024 / AES-256 policy from [`crate::fips`].

use crate::error::RadSecError;
use crate::fips;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// Build a mutual-TLS `RadSec` [`ClientConfig`] from PEM inputs:
/// - `trust_anchors_pem`: the CA(s) that validate usg-radius's server cert;
/// - `client_cert_pem`: the NAS client certificate chain;
/// - `client_key_pem`: the NAS private key.
///
/// TLS 1.3 only; the crypto policy is asserted before the config is returned so
/// a provider drift cannot widen it.
///
/// # Errors
/// - [`RadSecError::NoCredential`] if a PEM yields no cert/key.
/// - [`RadSecError::CryptoPolicyViolation`] if the policy check fails.
/// - [`RadSecError::Tls`] for an invalid key or config.
pub fn client_config(
    trust_anchors_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<ClientConfig, RadSecError> {
    let provider = fips::provider();
    fips::assert_policy(&provider)?;

    let mut roots = RootCertStore::empty();
    let mut any_root = false;
    for cert in load_certs(trust_anchors_pem)? {
        roots.add(cert).map_err(RadSecError::Tls)?;
        any_root = true;
    }
    if !any_root {
        return Err(RadSecError::NoCredential);
    }

    let client_chain = load_certs(client_cert_pem)?;
    if client_chain.is_empty() {
        return Err(RadSecError::NoCredential);
    }
    let key = load_key(client_key_pem)?;

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(client_chain, key)?;
    Ok(config)
}

/// Parse all certificates from a PEM buffer.
fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, RadSecError> {
    let mut reader = pem;
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(RadSecError::Io)
}

/// Parse a single private key from a PEM buffer.
fn load_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, RadSecError> {
    let mut reader = pem;
    rustls_pemfile::private_key(&mut reader)
        .map_err(RadSecError::Io)?
        .ok_or(RadSecError::NoCredential)
}
