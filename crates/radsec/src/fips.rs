//! The locked crypto policy: a rustls [`CryptoProvider`] restricted to
//! ML-KEM-1024 key exchange and the single `TLS_AES_256_GCM_SHA384` suite, plus
//! fail-closed self-checks (DESIGN §7, SERVER-CONTRACT §1.1).

use crate::error::RadSecError;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::{CipherSuite, NamedGroup};

/// Build the authenticator's crypto provider: aws-lc-rs with the key-exchange
/// group and cipher suite pinned to the locked policy. With the `fips` build
/// feature the underlying module is FIPS 140-3 validated.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        // ML-KEM-1024 ONLY — no classical (P-256/X25519) or hybrid groups.
        kx_groups: vec![aws_lc_rs::kx_group::MLKEM1024],
        // AES-256-GCM / SHA-384 ONLY — AES-128 is deliberately not offered.
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        ..aws_lc_rs::default_provider()
    }
}

/// Assert the provider exposes exactly the locked crypto policy. Used at config
/// build time so a drift in the provider can never widen what we offer.
///
/// # Errors
/// [`RadSecError::CryptoPolicyViolation`] if the kx groups or cipher suites are
/// anything other than ML-KEM-1024 and `TLS_AES_256_GCM_SHA384`.
pub fn assert_policy(provider: &CryptoProvider) -> Result<(), RadSecError> {
    let kx_ok = matches!(provider.kx_groups.as_slice(), [g] if g.name() == NamedGroup::MLKEM1024);
    let suite_ok = matches!(
        provider.cipher_suites.as_slice(),
        [s] if s.suite() == CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    if kx_ok && suite_ok {
        Ok(())
    } else {
        Err(RadSecError::CryptoPolicyViolation)
    }
}

/// Fail-closed FIPS self-check: the locked policy **and** a FIPS-validated
/// module. Run at daemon init and before the first connect (the `cli fips-check`
/// of DESIGN §7). Passes only in a `fips`-feature build whose power-on self-test
/// succeeded.
///
/// # Errors
/// [`RadSecError::NotFips`] if the provider is not FIPS-validated;
/// [`RadSecError::CryptoPolicyViolation`] if the policy is not the locked one.
pub fn assert_fips(provider: &CryptoProvider) -> Result<(), RadSecError> {
    if !provider.fips() {
        return Err(RadSecError::NotFips);
    }
    assert_policy(provider)
}
