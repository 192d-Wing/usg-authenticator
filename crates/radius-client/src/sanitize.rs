//! `User-Name` sanitization.
//!
//! The EAP-Response/Identity is attacker-influenced and becomes the RADIUS
//! `User-Name`, which usg-radius keys authorization policy on. An identity
//! carrying NUL/CR/LF or other control characters could split or spoof policy
//! conditions, so we **fail closed**: a non-conforming identity is rejected and
//! no Access-Request is sent (carried forward from the Milestone 1 review).

use crate::consts::MAX_ATTR_VALUE;
use crate::error::RadiusClientError;

/// Validate an EAP identity and return it as a `User-Name` string.
///
/// Accepts a non-empty, ≤253-octet, valid-UTF-8 identity with no control
/// characters. Anything else is [`RadiusClientError::InvalidUserName`].
///
/// # Errors
/// Returns [`RadiusClientError::InvalidUserName`] for an empty, over-long,
/// non-UTF-8, or control-character-bearing identity.
pub fn user_name(identity: &[u8]) -> Result<String, RadiusClientError> {
    if identity.is_empty() || identity.len() > MAX_ATTR_VALUE {
        return Err(RadiusClientError::InvalidUserName);
    }
    let s = core::str::from_utf8(identity).map_err(|_| RadiusClientError::InvalidUserName)?;
    if s.chars().any(char::is_control) {
        return Err(RadiusClientError::InvalidUserName);
    }
    Ok(s.to_string())
}
