//! Security labels: client clearances and vault classifications.

use std::str::FromStr;

/// A client's clearance (subject label) granted by the admin in Keycloak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clearance {
    Standard,
    Elite,
    Premium,
}

/// A vault's classification (object label), as set by the admin in `vaults.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Standard,
    Reinforced,
    HighSecurity,
}

impl Clearance {
    /// Checks whether this clearance may open a vault of this classification (no read up). Only
    /// used by tests, as the reference for the policy.
    ///
    /// * `classification`: The vault classification.
    #[cfg(test)]
    pub fn covers(self, classification: Classification) -> bool {
        match (self, classification) {
            (Clearance::Standard, Classification::Standard) => true,
            (Clearance::Standard, Classification::Reinforced) => false,
            (Clearance::Standard, Classification::HighSecurity) => false,
            (Clearance::Elite, Classification::Standard) => true,
            (Clearance::Elite, Classification::Reinforced) => true,
            (Clearance::Elite, Classification::HighSecurity) => false,
            (Clearance::Premium, Classification::Standard) => true,
            (Clearance::Premium, Classification::Reinforced) => true,
            (Clearance::Premium, Classification::HighSecurity) => true,
        }
    }
}

impl FromStr for Classification {
    type Err = LabelError;

    /// Parses a classification. Accepts only the exact names used in `vaults.toml`: `standard`,
    /// `reinforced` and `high-security`.
    ///
    /// * `s`: The classification from `vaults.toml`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard" => Ok(Classification::Standard),
            "reinforced" => Ok(Classification::Reinforced),
            "high-security" => Ok(Classification::HighSecurity),
            _ => Err(LabelError::UnknownClassification),
        }
    }
}

/// Error when a string is not a valid classification.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("unknown classification")]
    UnknownClassification,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_parses_valid_names() {
        assert_eq!("standard".parse(), Ok(Classification::Standard));
        assert_eq!("reinforced".parse(), Ok(Classification::Reinforced));
        assert_eq!("high-security".parse(), Ok(Classification::HighSecurity));
    }

    #[test]
    fn classification_rejects_invalid_names() {
        let invalid = [
            "Standard",
            "High-Security",
            "",
            " standard",
            "standard\n",
            "high_security",
            "secret",
        ];
        for input in invalid {
            assert_eq!(
                input.parse::<Classification>(),
                Err(LabelError::UnknownClassification),
                "input {input:?}"
            );
        }
    }
}
