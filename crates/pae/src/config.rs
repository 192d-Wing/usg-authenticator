//! Static per-port configuration the state machine reads: host mode, timers,
//! and the optional MAB / fallback-VLAN behaviors. The machine never mutates
//! this; the daemon supplies it and owns the clock that backs the timers.

/// How many independent supplicants a single physical port admits, and how
/// authorization is scoped (IEEE 802.1X-2020 §12.4 port operating modes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMode {
    /// Exactly one MAC may authenticate; a second source MAC is a security
    /// violation and is denied without disturbing the first.
    SingleHost,
    /// The first MAC to authenticate opens the port for all MACs (no per-MAC
    /// enforcement). Common for an uplink to a trusted downstream device.
    MultiHost,
    /// Each MAC authenticates independently and gets its own authorization
    /// (enforced per `{port, MAC}`). The secure default.
    MultiAuth,
    /// One data MAC plus one voice MAC (the voice device signaled out of band),
    /// each authenticated independently.
    MultiDomain,
}

/// Authenticator timers, in seconds (IEEE 802.1X-2020 §12.8 defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timers {
    /// Gap between EAP-Request/Identity transmissions while connecting.
    pub tx_period: u32,
    /// How long a port stays held after an authentication failure (backs
    /// [`TimerKind::Held`]; named to match it so the daemon's timer mapping is
    /// unambiguous).
    pub held_period: u32,
    /// Interval between periodic re-authentications (when enabled).
    pub reauth_period: u32,
    /// How long to wait for the authentication server before declaring it
    /// unreachable (drives the critical-VLAN path).
    pub server_timeout: u32,
    /// How long to wait for a supplicant response to a relayed challenge.
    pub supp_timeout: u32,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            tx_period: 30,
            held_period: 60,
            reauth_period: 3600,
            server_timeout: 30,
            supp_timeout: 30,
        }
    }
}

/// The kinds of timer the machine arms; the daemon maps each to a real
/// duration from [`Timers`] and fires [`crate::Event::Timer`] on expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// Re-send EAP-Request/Identity while connecting.
    TxPeriod,
    /// Quiet/held period after a failure before retrying.
    Held,
    /// Periodic re-authentication of an authorized session.
    Reauth,
    /// Authentication-server response deadline.
    ServerTimeout,
    /// Supplicant response deadline for a relayed challenge.
    SuppTimeout,
    /// Session lifetime from a RADIUS `Session-Timeout`.
    SessionTimeout,
}

/// Per-port configuration.
#[derive(Debug, Clone)]
pub struct PaeConfig {
    /// Port operating mode.
    pub host_mode: HostMode,
    /// Timer durations.
    pub timers: Timers,
    /// Number of EAP-Request/Identity transmissions before falling back to MAB
    /// or the guest VLAN (IEEE `maxReauthReq`-style bound).
    pub max_reauth_req: u32,
    /// Whether periodic re-authentication is armed after a successful auth.
    pub reauth_enabled: bool,
    /// Attempt MAC Authentication Bypass when no supplicant appears.
    pub mab_enabled: bool,
    /// VLAN for endpoints with no supplicant and no MAB success.
    pub guest_vlan: Option<String>,
    /// VLAN applied on an `Access-Reject` (instead of staying unauthorized).
    pub auth_fail_vlan: Option<String>,
    /// VLAN applied when the authentication server is unreachable. This is the
    /// one deliberately non-fail-closed path; `None` keeps the port closed.
    pub critical_vlan: Option<String>,
}

impl Default for PaeConfig {
    /// A secure-by-default port: multi-auth, no MAB, no fallback VLANs, periodic
    /// re-auth on. Every fail-open behavior is opt-in.
    fn default() -> Self {
        Self {
            host_mode: HostMode::MultiAuth,
            timers: Timers::default(),
            max_reauth_req: 2,
            reauth_enabled: true,
            mab_enabled: false,
            guest_vlan: None,
            auth_fail_vlan: None,
            critical_vlan: None,
        }
    }
}
