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
        // check length
        if s.len() < 15 || s.len() > 19 {
            return Err(InvalidDialCode);
        }

        // use a regex to parse the code
        let re = regex::Regex::new(
            r"^4([LR])([0-9]{1,2})-3([LR])([0-9]{1,2})-2([LR])([0-9]{1,2})-1([LR])([0-9]{1,2})$",
        )
        .map_err(|_| InvalidDialCode)?;
        let caps = re.captures(s).ok_or(InvalidDialCode)?;

        // check that the directions alternate
        let dir1 = caps.get(1).ok_or(InvalidDialCode)?.as_str();
        let dir2 = caps.get(3).ok_or(InvalidDialCode)?.as_str();
        let dir3 = caps.get(5).ok_or(InvalidDialCode)?.as_str();
        let dir4 = caps.get(7).ok_or(InvalidDialCode)?.as_str();
        if dir1 == dir2 || dir2 == dir3 || dir3 == dir4 {
            return Err(InvalidDialCode);
        }

        // parse the numbers
        let num1: u8 = caps
            .get(2)
            .ok_or(InvalidDialCode)?
            .as_str()
            .parse()
            .map_err(|_| InvalidDialCode)?;
        let num2: u8 = caps
            .get(4)
            .ok_or(InvalidDialCode)?
            .as_str()
            .parse()
            .map_err(|_| InvalidDialCode)?;
        let num3: u8 = caps
            .get(6)
            .ok_or(InvalidDialCode)?
            .as_str()
            .parse()
            .map_err(|_| InvalidDialCode)?;
        let num4: u8 = caps
            .get(8)
            .ok_or(InvalidDialCode)?
            .as_str()
            .parse()
            .map_err(|_| InvalidDialCode)?;
        Ok(DialCode {
            start: if dir1 == "L" {
                Direction::L
            } else {
                Direction::R
            },
            numbers: [num1, num2, num3, num4],
        })
    }
}

impl DialCode {
    /// The canonical form of the code, which is the exact string that `dial_code` hashes and
    /// verifies. It is `4{A}{n1}-3{B}{n2}-2{A}{n3}-1{B}{n4}`, where `A` is the start direction, `B`
    /// the other one, and `n1` to `n4` are the numbers in order, each written with two digits (e.g.
    /// `4L05-3R12-2L20-1R33`). Two spellings of a code, such as `4L5-…` and `4L05-…`, give the same
    /// canonical form.
    pub fn canonical(&self) -> String {
        let (dir1, dir2) = match self.start {
            Direction::L => ("L", "R"),
            Direction::R => ("R", "L"),
        };
        format!(
            "4{dir1}{:02}-3{dir2}{:02}-2{dir1}{:02}-1{dir2}{:02}",
            self.numbers[0], self.numbers[1], self.numbers[2], self.numbers[3]
        )
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

    #[test]
    fn dial_code_keeps_the_starting_direction_and_numbers() {
        let code: DialCode = "4R0-3L7-2R0-1L9".parse().expect("valid code");
        assert_eq!(code.start, Direction::R);
        assert_eq!(code.numbers, [0, 7, 0, 9]);
    }

    #[test]
    fn dial_code_accepts_bounds_and_mixed_widths() {
        let cases = [
            ("4L0-3R0-2L0-1R0", [0, 0, 0, 0]),
            ("4L99-3R99-2L99-1R99", [99, 99, 99, 99]),
            ("4L00-3R00-2L00-1R00", [0, 0, 0, 0]),
            ("4L5-3R05-2L50-1R9", [5, 5, 50, 9]),
        ];
        for (input, numbers) in cases {
            let code: DialCode = input.parse().expect("valid code");
            assert_eq!(code.numbers, numbers, "input {input:?}");
        }
    }

    #[test]
    fn dial_code_canonical_pads_every_number() {
        let code: DialCode = "4R5-3L0-2R9-1L1".parse().expect("valid code");
        assert_eq!(code.canonical(), "4R05-3L00-2R09-1L01");
    }

    #[test]
    fn dial_code_canonical_is_a_fixed_point() {
        for input in [
            "4L95-3R12-2L20-1R33",
            "4R0-3L7-2R0-1L9",
            "4L5-3R05-2L50-1R9",
        ] {
            let code: DialCode = input.parse().expect("valid code");
            let canonical = code.canonical();
            let again: DialCode = canonical.parse().expect("canonical form parses");
            assert_eq!(again.canonical(), canonical, "input {input:?}");
        }
    }

    #[test]
    fn dial_code_rejects_directions_that_do_not_alternate() {
        let invalid = [
            "4L95-3L12-2L20-1L33", // all left
            "4R95-3R12-2R20-1R33", // all right
            "4L95-3R12-2R20-1L33", // breaks at step 3
            "4L95-3R12-2L20-1L33", // breaks at step 4
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }

    #[test]
    fn dial_code_rejects_bad_directions() {
        let invalid = [
            "4l95-3r12-2l20-1r33",  // lowercase
            "4/95-3/12-2/20-1/33",  // not a direction
            "4X95-3R12-2L20-1R33",  // other letter
            "495-3R12-2L20-1R33",   // missing direction
            "4LR95-3R12-2L20-1R33", // two directions
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }

    #[test]
    fn dial_code_rejects_bad_numbers() {
        let invalid = [
            "4L-3R12-2L20-1R33",     // missing number
            "4L005-3R12-2L20-1R33",  // three digits
            "4L+5-3R12-2L20-1R33",   // sign
            "4L-5-3R12-2L20-1R33",   // negative
            "4L9a-3R12-2L20-1R33",   // letter
            "4L٩٥-3R12-2L20-1R33",   // non-ASCII digits
            "4L９５-3R12-2L20-1R33", // fullwidth digits
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }

    #[test]
    fn dial_code_rejects_bad_turns_and_steps() {
        let invalid = [
            "1L95-2R12-3L20-4R33",      // turns reversed
            "4L95-4R12-2L20-1R33",      // repeated turn
            "5L95-3R12-2L20-1R33",      // turn out of range
            "4L95-3R12-2L20-1R33-0L00", // five steps
            "4L95",                     // one step
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }

    #[test]
    fn dial_code_rejects_bad_separators_and_surroundings() {
        let invalid = [
            " 4L95-3R12-2L20-1R33",  // leading space
            "4L95-3R12-2L20-1R33 ",  // trailing space
            "4L95-3R12-2L20-1R33\n", // trailing newline
            "-4L95-3R12-2L20-1R33",  // leading dash
            "4L95-3R12-2L20-1R33-",  // trailing dash
            "4L95--3R12-2L20-1R33",  // double dash
            "4L95 3R12 2L20 1R33",   // spaces instead of dashes
            "4L95_3R12_2L20_1R33",   // underscores
            "4L95-3R12-2L20-1R33x",  // trailing garbage
            "4L95‐3R12‐2L20‐1R33",   // Unicode hyphen
        ];
        for input in invalid {
            assert!(input.parse::<DialCode>().is_err(), "input {input:?}");
        }
    }
}
