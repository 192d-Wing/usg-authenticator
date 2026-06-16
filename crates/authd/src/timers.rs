//! Mapping PAE [`TimerKind`]s to real durations from the configured [`Timers`].
//!
//! All kinds except `SessionTimeout` are backed by a config field. The
//! `SessionTimeout` duration comes from the RADIUS `Session-Timeout` of the
//! current authorization (per session), so it is supplied by the caller, not
//! here — this function returns `None` for it.

use core::time::Duration;
use pae::{TimerKind, Timers};

/// The configured duration for a timer kind, or `None` for `SessionTimeout`
/// (whose duration is the per-session RADIUS `Session-Timeout`).
#[must_use]
pub fn duration(timers: &Timers, kind: TimerKind) -> Option<Duration> {
    let secs = match kind {
        TimerKind::TxPeriod => timers.tx_period,
        TimerKind::Held => timers.held_period,
        TimerKind::Reauth => timers.reauth_period,
        TimerKind::ServerTimeout => timers.server_timeout,
        TimerKind::SuppTimeout => timers.supp_timeout,
        TimerKind::SessionTimeout => return None,
    };
    Some(Duration::from_secs(u64::from(secs)))
}
