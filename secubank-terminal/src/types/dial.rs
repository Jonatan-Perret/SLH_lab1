//! Dial codes: parsing of the code typed at the terminal and its canonical form.

use std::fmt;
use std::str::FromStr;

/// Direction of a dial step (left or right).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    L,
    R,
}

/// A dial code such as `4L95-3R12-2L20-1R33`: the starting direction and the four numbers. The
/// turns (4, 3, 2, 1) and the alternation of the directions are implied. Secret, so no derived
/// `Debug`, `Clone` or `PartialEq`.
pub struct DialCode {
    /// The direction of the first step. The other steps alternate from it.
    start: Direction,
    /// The four dialed numbers in order, each from 0 to 99.
    numbers: [u8; 4],
}

impl fmt::Debug for DialCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DialCode(***)")
    }
}

/// Error when a string is not a valid dial code.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid dial code")]
pub struct InvalidDialCode;

impl FromStr for DialCode {
    type Err = InvalidDialCode;

    /// Parses a dial code typed at the terminal. Expects exactly four steps joined by a single `-`,
    /// with nothing before, after or between them:
    /// - Each step is `<turns><direction><number>`.
    /// - The turns are the digits `4`, `3`, `2` and `1`, in this order.
    /// - The direction is an uppercase `L` or `R`. The directions alternate and the first one can
    ///   be either.
    /// - The number is one or two ASCII digits (0 to 99), so `5` and `05` are both accepted.
    ///
    /// Anything else gives `InvalidDialCode`.
    ///
    /// * `s`: The dial code as typed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl DialCode {
    /// The canonical form of the code, which is the exact string that `dial_code` hashes and
    /// verifies. It is `4{A}{n1}-3{B}{n2}-2{A}{n3}-1{B}{n4}`, where `A` is the start direction, `B`
    /// the other one, and `n1` to `n4` are the numbers in order, each written with two digits (e.g.
    /// `4L05-3R12-2L20-1R33`). Two spellings of a code, such as `4L5-…` and `4L05-…`, give the same
    /// canonical form.
    pub fn canonical(&self) -> String {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_code_debug_hides_the_secret() {
        let code = DialCode {
            start: Direction::L,
            numbers: [95, 12, 20, 33],
        };
        assert_eq!(format!("{code:?}"), "DialCode(***)");
    }

    #[test]
    fn dial_code_parses_example() {
        let code: DialCode = "4L95-3R12-2L20-1R33".parse().expect("valid code");
        assert_eq!(code.start, Direction::L);
        assert_eq!(code.numbers, [95, 12, 20, 33]);
    }

    #[test]
    fn dial_code_is_canonicalized() {
        let cases = [
            ("4L95-3R12-2L20-1R33", "4L95-3R12-2L20-1R33"),
            ("4R0-3L7-2R0-1L9", "4R00-3L07-2R00-1L09"),
        ];
        for (input, canonical) in cases {
            let code: DialCode = input.parse().expect("valid code");
            assert_eq!(code.canonical(), canonical, "input {input:?}");
        }
    }

    #[test]
    fn dial_code_accepts_both_starting_directions() {
        for input in ["4L95-3R12-2L20-1R33", "4R95-3L12-2R20-1L33"] {
            assert!(input.parse::<DialCode>().is_ok(), "input {input:?}");
        }
    }

    #[test]
    fn dial_code_leading_zero_gives_the_same_canonical_form() {
        let short: DialCode = "4L5-3R12-2L0-1R33".parse().expect("valid code");
        let padded: DialCode = "4L05-3R12-2L00-1R33".parse().expect("valid code");
        assert_eq!(short.canonical(), padded.canonical());
    }

    #[test]
    fn dial_code_rejects_invalid_syntax() {
        let invalid = [
            "",                    // empty
            "3L95-3R12-2L20-1R33", // wrong turns
            "4L95-3L12-2R20-1L33", // not alternating
            "4L95-3R12-2L20",      // 3 steps
            "4L100-3R12-2L20-1R3", // above 99
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }
}
