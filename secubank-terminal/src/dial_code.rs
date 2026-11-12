//! Argon2id hashing and verification of dial codes.

use std::fmt;
use std::str::FromStr;

use argon2::password_hash::phc::{Output, PasswordHash};
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use secrecy::{ExposeSecret, SecretSlice};

use crate::types::DialCode;

/// A dummy hash of a random value, verified when there is no stored hash (so `verify` always takes
/// the same time).
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZhIa9tE8DQLa/cXUQefZWg$nSboUi05AKT3WqD7nES7GkiK3S1tTZRpbtot1q7tAU4";

/// An Argon2id PHC string as stored in `vaults.toml` (e.g.
/// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`). Sensitive, so no derived `Debug`, and `==` in
/// tests only.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct DialCodeHash(String);

/// Secret key mixed into every dial code hash (the decoded `DIAL_CODE_PEPPER` from `.env`).
pub struct DialCodePepper(SecretSlice<u8>);

/// Error when a string is not a valid Argon2id PHC string.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid dial code hash")]
pub struct InvalidDialCodeHash;

/// Error when the pepper is not base64 of 32 to 96 bytes.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid dial code pepper")]
pub struct InvalidPepper;

/// Error when hashing fails.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("dial code hashing failed")]
pub struct HashingFailed;

impl FromStr for DialCodeHash {
    type Err = InvalidDialCodeHash;

    /// Parses a stored hash. Accepts only an Argon2id PHC string with a salt and a 32-byte output.
    /// The vault file is in the TCB, so this only checks that a hand edit didn't break the hash,
    /// not that it is honest. Whoever can edit the file can change the owner anyway.
    ///
    /// * `s`: The PHC string from `vaults.toml`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = PasswordHash::new(s).map_err(|_| InvalidDialCodeHash)?;
        let output_len = parsed.hash.as_ref().map(Output::len);
        let argon2id = parsed.algorithm.as_str() == "argon2id";
        if !argon2id || parsed.salt.is_none() || output_len != Some(32) {
            return Err(InvalidDialCodeHash);
        }
        Ok(DialCodeHash(String::from(s)))
    }
}

impl DialCodeHash {
    /// The PHC string as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DialCodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DialCodeHash(***)")
    }
}

impl FromStr for DialCodePepper {
    type Err = InvalidPepper;

    /// Parses the pepper from padded standard base64 (e.g. `openssl rand -base64 32`) of 32 to 96
    /// bytes. The decoded bytes are kept in a `SecretSlice`, so they are zeroized when dropped and
    /// never printed.
    ///
    /// * `s`: The `DIAL_CODE_PEPPER` value from `.env`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 128 {
            return Err(InvalidPepper);
        }
        let bytes = SecretSlice::from(STANDARD.decode(s).map_err(|_| InvalidPepper)?);
        if bytes.expose_secret().len() < 32 {
            return Err(InvalidPepper);
        }
        Ok(DialCodePepper(bytes))
    }
}

impl fmt::Debug for DialCodePepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DialCodePepper(***)")
    }
}

/// Builds Argon2id with the default parameters (`Params::default()`) and the pepper as secret key,
/// or `None` if Argon2 refuses the pepper. The result borrows the pepper, which is why there is a
/// `'_`.
///
/// * `pepper`: The secret key mixed into every dial code hash.
fn argon2(pepper: &DialCodePepper) -> Option<Argon2<'_>> {
    Argon2::new_with_secret(
        pepper.0.expose_secret(),
        Algorithm::Argon2id,
        Version::V0x13,
        Params::default(),
    )
    .ok()
}

/// Hashes the canonical form of `code` with Argon2id and a fresh random salt.
///
/// * `code`: The dial code to hash.
/// * `pepper`: The secret key mixed into every dial code hash.
pub fn hash(code: &DialCode, pepper: &DialCodePepper) -> Result<DialCodeHash, HashingFailed> {
    let argon2 = argon2(pepper).ok_or(HashingFailed)?;
    let phc = argon2
        .hash_password(code.canonical().as_bytes())
        .map_err(|_| HashingFailed)?;
    Ok(DialCodeHash(phc.to_string()))
}

/// Checks whether `code` matches `stored`. Always runs one Argon2 verification (against
/// `DUMMY_HASH` when `stored` is `None`) so the timing is the same in every case. The comparison is
/// constant time and any error counts as a mismatch.
///
/// * `code`: The dial code to verify.
/// * `stored`: The stored hash to compare against, or `None` if there is no stored hash.
/// * `pepper`: The secret key mixed into every dial code hash.
pub fn verify(code: &DialCode, stored: Option<&DialCodeHash>, pepper: &DialCodePepper) -> bool {
    let Some(argon2) = argon2(pepper) else {
        return false;
    };
    let target = match stored {
        Some(hash) => hash.as_str(),
        None => DUMMY_HASH,
    };
    let matches = argon2
        .verify_password(code.canonical().as_bytes(), target)
        .is_ok();
    matches && stored.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The PHC prefix of the parameters that `hash` uses.
    const PHC_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

    // Base64 of `secubank-very-long-pepper-string`.
    const PEPPER: &str = "c2VjdWJhbmstdmVyeS1sb25nLXBlcHBlci1zdHJpbmc=";

    fn pepper() -> DialCodePepper {
        PEPPER.parse::<DialCodePepper>().expect("valid pepper")
    }

    fn code(s: &str) -> DialCode {
        s.parse().expect("valid code")
    }

    fn hashed(s: &str) -> DialCodeHash {
        hash(&code(s), &pepper()).expect("hashing works")
    }

    #[test]
    fn hash_then_verify_round_trips() {
        let p = pepper();
        let stored = hashed("4L05-3R12-2L20-1R33");
        assert!(stored.as_str().starts_with(PHC_PREFIX));
        assert!(stored.as_str().parse::<DialCodeHash>().is_ok());
        assert!(verify(&code("4L05-3R12-2L20-1R33"), Some(&stored), &p));
        // Same canonical form so the short spelling must also be accepted.
        assert!(verify(&code("4L5-3R12-2L20-1R33"), Some(&stored), &p));
    }

    #[test]
    fn verify_rejects_a_wrong_code() {
        let p = pepper();
        let stored = hashed("4L95-3R12-2L20-1R33");
        assert!(!verify(&code("4L95-3R12-2L20-1R34"), Some(&stored), &p));
        assert!(!verify(&code("4R95-3L12-2R20-1L33"), Some(&stored), &p));
    }

    #[test]
    fn verify_rejects_another_pepper() {
        let stored = hashed("4L95-3R12-2L20-1R33");
        let other = "b3RoZXItcGVwcGVyLWZvci11bml0LXRlc3RzLW9ubHk="
            .parse::<DialCodePepper>()
            .expect("valid pepper");
        assert!(!verify(&code("4L95-3R12-2L20-1R33"), Some(&stored), &other));
    }

    #[test]
    fn verify_without_a_hash_is_false() {
        assert!(!verify(&code("4L95-3R12-2L20-1R33"), None, &pepper()));
    }

    #[test]
    fn dummy_hash_uses_the_default_parameters() {
        // Same parameters as real hashes (see the round trip), so `verify(.., None, ..)` costs the
        // same.
        assert!(DUMMY_HASH.starts_with(PHC_PREFIX));
        assert!(DUMMY_HASH.parse::<DialCodeHash>().is_ok());
    }

    #[test]
    fn same_code_gives_different_hashes() {
        assert_ne!(hashed("4L5-3R5-2L5-1R5"), hashed("4L5-3R5-2L5-1R5"));
    }

    #[test]
    fn dial_code_hash_rejects_broken_values() {
        let stored = hashed("4L95-3R12-2L20-1R33");
        let valid = stored.as_str();
        let invalid = [
            "",
            "not a hash",
            "$argon2id$v=19$m=19456,t=2,p=1", // no salt, no output
            &valid[..valid.len() - 4],        // truncated output
        ];
        for input in invalid {
            assert_eq!(
                input.parse::<DialCodeHash>(),
                Err(InvalidDialCodeHash),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn pepper_accepts_32_to_96_bytes() {
        let longest = "A".repeat(128); // 96 bytes
        for input in [PEPPER, longest.as_str()] {
            assert!(input.parse::<DialCodePepper>().is_ok(), "input {input:?}");
        }
    }

    #[test]
    fn pepper_rejects_weak_values() {
        let too_long = "A".repeat(132); // 99 bytes
        let with_space = format!("{PEPPER} ");
        let with_newline = format!("{PEPPER}\n");
        let middle_padding = format!("{}={}", &PEPPER[..12], &PEPPER[13..]);
        let invalid = [
            "",
            "short",
            "dGVzdC1wZXBwZXItZm9yLXVuaXQtdGVzdHMtb25seQ==", // 31 bytes
            "dGVzdC1wZXBwZXItZm9yLXVuaXQtdGVzdHMtb25seQ=",  // bad padding
            "c2VjdWJhbmstdmVyeS1sb25nLXBlcHBlci1zdHJpbmc",  // no padding
            "c2VjdWJhbmstdmVyeS1sb25nLXBlcHBlci1zdHJpbm_=", // URL-safe alphabet
            middle_padding.as_str(),
            with_space.as_str(),
            with_newline.as_str(),
            too_long.as_str(),
        ];
        for input in invalid {
            assert!(input.parse::<DialCodePepper>().is_err(), "input {input:?}");
        }
    }

    #[test]
    fn debug_hides_hash_and_pepper() {
        let stored = hashed("4L95-3R12-2L20-1R33");
        assert_eq!(format!("{stored:?}"), "DialCodeHash(***)");
        assert_eq!(format!("{:?}", pepper()), "DialCodePepper(***)");
    }
}
