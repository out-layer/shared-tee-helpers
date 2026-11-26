//! How a number and a run of bytes are read from text: one spelling each.
//!
//! A value that is signed, stored or compared arrives as text. Each has one
//! accepted spelling, so two texts that read as the same value are the same
//! text.

use std::str::FromStr;

/// Exactly `N` bytes in lowercase hex: no prefix, no capitals, no padding.
pub fn hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0; N];
    ::hex::decode_to_slice(text, &mut bytes).ok()?;
    Some(bytes)
}

/// An unsigned number in decimal digits and nothing else: no sign, no space,
/// no separator. `None` when it is not one or does not fit `T`.
pub fn decimal<T: FromStr>(text: &str) -> Option<T> {
    // `from_str` of the unsigned integers also takes a leading `+`
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_has_one_spelling() {
        assert_eq!(hex::<2>("00ff"), Some([0, 255]));
        for refused in ["00FF", "0x00ff", "00f", "00ff00", " 00ff", "00fg", "", "+0ff"] {
            assert_eq!(hex::<2>(refused), None, "{refused:?}");
        }
        assert_eq!(hex::<0>(""), Some([]));
    }

    #[test]
    fn a_decimal_is_digits_only() {
        assert_eq!(decimal::<u128>("0"), Some(0));
        assert_eq!(decimal::<u128>("007"), Some(7));
        assert_eq!(decimal::<u128>(&u128::MAX.to_string()), Some(u128::MAX));
        for refused in ["", "+1", "-1", " 1", "1 ", "1_000", "1.0", "1e3", "0x1", "١"] {
            assert_eq!(decimal::<u128>(refused), None, "{refused:?}");
        }
        // one past the type's range
        assert_eq!(decimal::<u64>("18446744073709551616"), None);
        assert_eq!(decimal::<u128>("340282366920938463463374607431768211456"), None);
    }
}
