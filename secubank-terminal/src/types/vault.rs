//! Vaults: IDs, ownership, and parsing of a `vaults.toml` entry.

use std::str::FromStr;

use crate::dial_code::DialCodeHash;
use crate::store::RawVault;
use crate::types::{Classification, Sub};

/// A vault ID such as `V-001`, typed at the keyboard or read from `vaults.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultId(String);

/// Error when a string is not a valid vault ID.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid vault id")]
pub struct InvalidVaultId;

impl FromStr for VaultId {
    type Err = InvalidVaultId;

    /// Parses a vault ID. Expects exactly an uppercase `V`, a `-` and three ASCII digits (`V-000`
    /// to `V-999`), with nothing before or after. The ID is kept as written. Anything else gives
    /// `InvalidVaultId`.
    ///
    /// * `s`: The ID as typed at the terminal or read from `vaults.toml`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl VaultId {
    /// The ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who owns a vault. A dial code only exists with an owner, so a code without an owner can't be
/// represented.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Ownership {
    Unowned,
    Owned {
        owner: Sub,
        dial_code_hash: Option<DialCodeHash>,
    },
}

/// A vault parsed from its `vaults.toml` entry. Every field is already a checked type, so any
/// `Vault` is valid.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Vault {
    pub id: VaultId,
    pub classification: Classification,
    pub ownership: Ownership,
}

/// Error when an entry is not a valid vault. Any such entry denies every action.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid vault entry")]
pub struct InvalidVault;

impl TryFrom<RawVault> for Vault {
    type Error = InvalidVault;

    /// Parses a vault from its raw entry. A missing classification means Standard, and a dial code
    /// hash without an owner is refused.
    ///
    /// * `raw`: The entry as read from `vaults.toml`.
    fn try_from(raw: RawVault) -> Result<Self, Self::Error> {
        let id = raw.id.parse::<VaultId>().map_err(|_| InvalidVault)?;
        let classification = match raw.classification {
            None => Classification::Standard,
            Some(name) => name.parse().map_err(|_| InvalidVault)?,
        };
        let owner = match raw.owner {
            None => None,
            Some(owner) => Some(owner.parse::<Sub>().map_err(|_| InvalidVault)?),
        };
        let hash = match raw.dial_code_hash {
            None => None,
            Some(hash) => Some(hash.parse::<DialCodeHash>().map_err(|_| InvalidVault)?),
        };
        let ownership = match (owner, hash) {
            (None, None) => Ownership::Unowned,
            (None, Some(_)) => return Err(InvalidVault),
            (Some(owner), dial_code_hash) => Ownership::Owned {
                owner,
                dial_code_hash,
            },
        };
        Ok(Vault {
            id,
            classification,
            ownership,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_id_accepts_v_and_three_digits() {
        for input in ["V-000", "V-001", "V-999"] {
            let id = input.parse::<VaultId>().expect("valid id");
            assert_eq!(id.as_str(), input);
        }
    }

    #[test]
    fn vault_id_rejects_other_shapes() {
        let invalid = [
            "",       // empty
            "V-01",   // two digits
            "V-0001", // four digits
            "v-001",  // lowercase
            "V001",   // no dash
            "V-00a",  // not a digit
        ];
        for input in invalid {
            assert_eq!(
                input.parse::<VaultId>(),
                Err(InvalidVaultId),
                "input {input:?}"
            );
        }
    }

    const OWNER: &str = "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b";

    // Any well-formed Argon2id PHC string.
    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZhIa9tE8DQLa/cXUQefZWg$nSboUi05AKT3WqD7nES7GkiK3S1tTZRpbtot1q7tAU4";

    /// A raw entry as the store would read it.
    fn raw(
        id: &str,
        classification: Option<&str>,
        owner: Option<&str>,
        hash: Option<&str>,
    ) -> RawVault {
        RawVault {
            id: String::from(id),
            classification: classification.map(String::from),
            owner: owner.map(String::from),
            dial_code_hash: hash.map(String::from),
        }
    }

    fn vault_id() -> VaultId {
        "V-001".parse::<VaultId>().expect("valid id")
    }

    fn owner() -> Sub {
        OWNER.parse::<Sub>().expect("valid sub")
    }

    #[test]
    fn vault_without_classification_is_standard_and_unowned() {
        let vault = Vault::try_from(raw("V-001", None, None, None)).expect("valid entry");
        let expected = Vault {
            id: vault_id(),
            classification: Classification::Standard,
            ownership: Ownership::Unowned,
        };
        assert_eq!(vault, expected);
    }

    #[test]
    fn vault_reads_classification_owner_and_hash() {
        let entry = raw("V-001", Some("high-security"), Some(OWNER), Some(HASH));
        let vault = Vault::try_from(entry).expect("valid entry");
        let expected = Vault {
            id: vault_id(),
            classification: Classification::HighSecurity,
            ownership: Ownership::Owned {
                owner: owner(),
                dial_code_hash: Some(HASH.parse::<DialCodeHash>().expect("valid hash")),
            },
        };
        assert_eq!(vault, expected);
    }

    #[test]
    fn vault_owner_without_code_has_no_hash() {
        let vault = Vault::try_from(raw("V-001", None, Some(OWNER), None)).expect("valid entry");
        let expected = Ownership::Owned {
            owner: owner(),
            dial_code_hash: None,
        };
        assert_eq!(vault.ownership, expected);
    }

    #[test]
    fn vault_rejects_invalid_entries() {
        let invalid = [
            raw("V-001", None, None, Some(HASH)),     // hash without owner
            raw("V-1", None, None, None),             // bad id
            raw("V-001", Some("secret"), None, None), // unknown classification
            raw("V-001", Some(""), None, None),       // empty classification
            raw("V-001", None, Some("alice"), None),  // owner is not a sub
            raw("V-001", None, Some(OWNER), Some("not a hash")), // broken hash
        ];
        for (case, entry) in invalid.into_iter().enumerate() {
            assert_eq!(Vault::try_from(entry), Err(InvalidVault), "case {case}");
        }
    }
}
