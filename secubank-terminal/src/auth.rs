//! Password grant and token verification used to build identities.

use jsonwebtoken::DecodingKey;

use crate::config::{Config, ConfigError};
use crate::http;
use crate::types::{AppRole, Clearance, Password, Sub, Username};

/// An identity that `verify` builds from a verified access token: the user's `sub` and app roles.
#[derive(Debug)]
pub struct VerifiedIdentity {
    sub: Sub,
    roles: Vec<AppRole>,
}

impl VerifiedIdentity {
    /// The Keycloak user ID.
    pub fn sub(&self) -> &Sub {
        &self.sub
    }

    /// The app roles, in token order.
    pub fn roles(&self) -> &[AppRole] {
        &self.roles
    }

    /// The clearance when the token has exactly one, `None` otherwise.
    pub fn single_clearance(&self) -> Option<Clearance> {
        let mut clearances = self.roles.iter().filter_map(|role| match role {
            AppRole::Clearance(clearance) => Some(*clearance),
            _ => None,
        });
        match (clearances.next(), clearances.next()) {
            (Some(clearance), None) => Some(clearance),
            _ => None,
        }
    }

    /// Builds an identity without a token, to test `authorize`.
    #[cfg(test)]
    pub(crate) fn for_tests(sub: Sub, roles: Vec<AppRole>) -> Self {
        VerifiedIdentity { sub, roles }
    }
}

/// The pinned realm signing key containing its `kid` and its RSA public key.
pub struct RealmKey {
    kid: String,
    key: DecodingKey,
}

impl RealmKey {
    /// Builds the key from the pinned values in the config. Fails with `ConfigError::Invalid` if
    /// the public key is not a valid RSA key.
    ///
    /// * `config`: The terminal configuration, for `KEYCLOAK_REALM_KID` and
    ///   `KEYCLOAK_REALM_PUBLIC_KEY`.
    pub fn from_config(config: &Config) -> Result<RealmKey, ConfigError> {
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            config.realm_public_key
        );
        let key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|_| ConfigError::Invalid(String::from("KEYCLOAK_REALM_PUBLIC_KEY")))?;
        Ok(RealmKey {
            kid: config.realm_kid.clone(),
            key,
        })
    }

    /// The pinned key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The pinned public key.
    pub fn key(&self) -> &DecodingKey {
        &self.key
    }
}

/// Reason why a login fails. The user only ever sees a generic message.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Keycloak is unavailable")]
    Unavailable,
    #[error("login refused")]
    Refused,
    #[error("invalid token")]
    InvalidToken,
}

/// The field used from a Keycloak token response.
#[derive(serde::Deserialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
}

/// Runs a password grant on the public client and returns the raw access token, which the caller
/// verifies and then drops. Gives `AuthError::Refused` when Keycloak rejects the credentials and
/// `AuthError::Unavailable` on any other failure.
///
/// * `config`: The terminal configuration, for the Keycloak URL, the realm and the terminal client
///   ID.
/// * `username`: The username to log in with.
/// * `password`: The password to log in with.
pub fn password_grant(
    config: &Config,
    username: &Username,
    password: &Password,
) -> Result<String, AuthError> {
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        config.keycloak_url, config.realm
    );
    let form = [
        ("grant_type", "password"),
        ("client_id", config.terminal_client_id.as_str()),
        ("username", username.as_str()),
        ("password", password.expose_secret()),
    ];

    let runtime = http::runtime().ok_or(AuthError::Unavailable)?;
    let client = http::client().ok_or(AuthError::Unavailable)?;
    runtime.block_on(async {
        let response = client
            .post(url)
            .form(&form)
            .send()
            .await
            .map_err(|_| AuthError::Unavailable)?;
        if !response.status().is_success() {
            return Err(AuthError::Refused);
        }
        let body: TokenResponse = response.json().await.map_err(|_| AuthError::Unavailable)?;
        Ok(body.access_token)
    })
}

/// The access token claims that `verify` reads.
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    azp: String,
    typ: String,
    realm_access: RealmAccess,
}

/// The `realm_access` claim, which holds the realm role names.
#[derive(serde::Deserialize)]
struct RealmAccess {
    roles: Vec<String>,
}

/// Verifies an access token from the Keycloak realm and builds the identity it carries. Any
/// failure gives `AuthError::InvalidToken`.
///
/// The roles are the names in `realm_access.roles` mapped with `AppRole::from_role_name`, in token
/// order. Names that are not app roles are dropped.
///
/// * `token`: The raw access token from `password_grant`.
/// * `realm_key`: The pinned realm key.
/// * `config`: The terminal configuration.
pub fn verify(
    token: &str,
    realm_key: &RealmKey,
    config: &Config,
) -> Result<VerifiedIdentity, AuthError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_key_loads_from_config() {
        let realm_key = RealmKey::from_config(&Config::for_tests()).expect("key");
        assert_eq!(realm_key.kid(), "test-kid");
    }

    #[test]
    fn broken_public_key_is_refused() {
        for bad in ["AAAA", "not base64!", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"] {
            let mut config = Config::for_tests();
            config.realm_public_key = String::from(bad);
            let error = RealmKey::from_config(&config).err();
            let expected = ConfigError::Invalid(String::from("KEYCLOAK_REALM_PUBLIC_KEY"));
            assert_eq!(error, Some(expected), "{bad}");
        }
    }
}
