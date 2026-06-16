//! Shared known-answer-test (KAT) helpers and vectors.
//!
//! This crate is intended to be vendored/shared with `usg-radius` so both ends
//! validate the wire format against byte-identical vectors (see
//! `SERVER-CONTRACT.md` §5 V-5).
#![forbid(unsafe_code)]

/// Error returned when a hex string cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The string had an odd number of hex digits.
    OddLength,
    /// A non-hex, non-whitespace character was encountered.
    BadDigit(char),
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OddLength => write!(f, "hex string has an odd number of digits"),
            Self::BadDigit(c) => write!(f, "invalid hex digit {c:?}"),
        }
    }
}

impl std::error::Error for HexError {}

/// Decode a hex string into bytes, ignoring ASCII whitespace.
///
/// # Errors
/// Returns [`HexError`] on an odd digit count or an invalid character.
pub fn from_hex(s: &str) -> Result<Vec<u8>, HexError> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = c.to_digit(16).ok_or(HexError::BadDigit(c))?;
        // `to_digit(16)` yields 0..=15, so the cast cannot truncate.
        nibbles.push(u8::try_from(v).unwrap_or(0));
    }
    if !nibbles.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|pair| {
            let hi = pair.first().copied().unwrap_or(0);
            let lo = pair.get(1).copied().unwrap_or(0);
            (hi << 4) | lo
        })
        .collect())
}

/// Encode bytes as a lowercase hex string.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        use core::fmt::Write as _;
        // Writing to a String is infallible; ignore the formatter Result.
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = [0x00, 0x01, 0x88, 0x8e, 0xff];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn ignores_whitespace() {
        assert_eq!(from_hex("01 88\n8e").unwrap(), vec![0x01, 0x88, 0x8e]);
    }

    #[test]
    fn rejects_odd_and_bad() {
        assert_eq!(from_hex("abc"), Err(HexError::OddLength));
        assert_eq!(from_hex("zz"), Err(HexError::BadDigit('z')));
    }
}
