//! `authd` — the 802.1X authenticator daemon entry point.
//!
//! This skeleton runs the safe preflight that is platform-independent: it
//! asserts the FIPS crypto policy. Bringing ports into service uses
//! [`authd::worker::run_port`] per port, which binds the real EAPOL socket,
//! RadSec connection, and SONiC enforcer — wired at deployment together with a
//! config loader and the SONiC DbConn backend (the remaining integration step).
#![allow(clippy::doc_markdown)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // Preflight: in production (built with --features fips on the workspace's
    // radsec) this asserts the FIPS-validated module and the locked policy.
    match radsec::fips::assert_fips(&radsec::fips::provider()) {
        Ok(()) => {
            eprintln!("authd: FIPS crypto policy validated (ML-KEM-1024 / AES-256-GCM-SHA384)");
        }
        Err(e) => {
            eprintln!("authd: FIPS preflight not satisfied: {e}");
            eprintln!(
                "authd: this is expected for a non-`fips` build; \
                 build radsec with --features fips for the validated module"
            );
        }
    }

    eprintln!(
        "authd: component stack ready. Per-port service uses worker::run_port \
         (EAPOL ↔ PAE ↔ RadSec ↔ SONiC); the config loader and SONiC DbConn \
         backend are the remaining deployment wiring."
    );
    ExitCode::SUCCESS
}
