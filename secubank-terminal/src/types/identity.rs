//! Identity types: Keycloak user IDs and application roles.

use std::str::FromStr;

use crate::types::Clearance;

/// A Keycloak user ID (the token's `sub` claim), used to identify users and vault owners.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sub(String);

/// Error when a string is not a valid Keycloak user ID.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid user id")]
pub struct InvalidSub;

impl FromStr for Sub {
    type Err = InvalidSub;

    /// Parses a Keycloak user ID. Accepts exactly the shape of the IDs that Keycloak generates (a
    /// UUID in 8-4-4-4-12 lowercase hex).
    ///
    /// * `s`: The ID from a token, from Keycloak or from `vaults.toml`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 36 {
            return Err(InvalidSub);
        }
        for (i, c) in s.chars().enumerate() {
            let ok = match i {
                8 | 13 | 18 | 23 => c == '-',
                _ => matches!(c, '0'..='9' | 'a'..='f'),
            };
            if !ok {
                return Err(InvalidSub);
            }
        }
        Ok(Sub(String::from(s)))
    }
}

impl Sub {
    /// The ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An application role, read from the token's `realm_access.roles` or from Keycloak's role
/// mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRole {
    Client,
    Officer,
    Clearance(Clearance),
}

impl AppRole {
    /// Maps a Keycloak realm role name to its app role, or `None` for any other realm role. Names
    /// are exact and case sensitive.
    ///
    /// * `name`: The Keycloak realm role name.
    pub fn from_role_name(name: &str) -> Option<AppRole> {
        match name {
            "client" => Some(AppRole::Client),
            "bank-security-officer" => Some(AppRole::Officer),
            "clearance-standard" => Some(AppRole::Clearance(Clearance::Standard)),
            "clearance-elite" => Some(AppRole::Clearance(Clearance::Elite)),
            "clearance-premium" => Some(AppRole::Clearance(Clearance::Premium)),
            _ => None,
        }
    }
}

/// A Keycloak user as `find_user` returns it, for a new owner lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub sub: Sub,
    pub enabled: bool,
    pub roles: Vec<AppRole>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_accepts_wellformed_keycloak_id() {
        const A_SUB: &str = "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b";

        let sub = A_SUB.parse::<Sub>().expect("valid id");
        assert_eq!(sub.as_str(), A_SUB);
    }

    #[test]
    fn sub_rejects_invalid_shapes() {
        let invalid = [
            "",
            "alice",
            "0B8C2A4E-5F1D-4C3A-9E7B-2D6F8A1C3E5B",
            "0b8c2a4e5f1d4c3a9e7b2d6f8a1c3e5b",
            "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5",
            "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5bb",
            "0b8c2a4e5-f1d-4c3a-9e7b-2d6f8a1c3e5b",
            "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5g",
            " b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b",
            "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3eé",
        ];
        for input in invalid {
            assert_eq!(input.parse::<Sub>(), Err(InvalidSub), "input {input:?}");
        }
    }

    #[test]
    fn app_role_maps_valid_role_names() {
        let expected = [
            ("client", AppRole::Client),
            ("bank-security-officer", AppRole::Officer),
            (
                "clearance-standard",
                AppRole::Clearance(Clearance::Standard),
            ),
            ("clearance-elite", AppRole::Clearance(Clearance::Elite)),
            ("clearance-premium", AppRole::Clearance(Clearance::Premium)),
        ];
        for (name, role) in expected {
            assert_eq!(AppRole::from_role_name(name), Some(role), "role {name:?}");
        }
    }

    #[test]
    fn app_role_ignores_invalid_roles() {
        let others = [
            "default-roles-secubank",
            "offline_access",
            "Client",
            "clearance-STANDARD",
            "clearance-",
            "officer",
            "",
        ];
        for name in others {
            assert_eq!(AppRole::from_role_name(name), None, "role {name:?}");
        }
    }
}
