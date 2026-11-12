//! Configuration from `.env`. Checks the required environment variables at startup.

use std::collections::HashMap;
use std::path::PathBuf;

use secrecy::SecretString;

use crate::dial_code::DialCodePepper;

/// The variables read from the environment.
const NAMES: [&str; 9] = [
    "KEYCLOAK_URL",
    "KEYCLOAK_REALM",
    "KEYCLOAK_TERMINAL_CLIENT_ID",
    "KEYCLOAK_SA_CLIENT_ID",
    "KEYCLOAK_SA_CLIENT_SECRET",
    "VAULTS_PATH",
    "KEYCLOAK_REALM_KID",
    "KEYCLOAK_REALM_PUBLIC_KEY",
    "DIAL_CODE_PEPPER",
];

/// The checked values of the variables from `.env`.
#[derive(Debug)]
pub struct Config {
    pub keycloak_url: String,
    pub realm: String,
    pub terminal_client_id: String,
    pub sa_client_id: String,
    pub sa_client_secret: SecretString,
    pub vaults_path: PathBuf,
    pub realm_kid: String,
    pub realm_public_key: String,
    pub dial_code_pepper: DialCodePepper,
}

/// Reason why the config fails to load.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read .env in the current directory")]
    EnvFile,
    #[error("missing variable {0}")]
    Missing(String),
    #[error("invalid value for {0}")]
    Invalid(String),
}

impl Config {
    /// Reads `.env` from the current directory, then checks the variables.
    pub fn load() -> Result<Config, ConfigError> {
        dotenvy::from_filename(".env").map_err(|_| ConfigError::EnvFile)?;

        // Only our variables, so an unrelated non-UTF-8 variable can't break startup.
        let mut vars = HashMap::new();
        for name in NAMES {
            if let Ok(value) = std::env::var(name) {
                vars.insert(String::from(name), value);
            }
        }
        Config::from_vars(&vars)
    }

    /// Builds the config from a name -> value map. Separated from `load` so tests don't change the
    /// process environment.
    ///
    /// * `vars`: The value of each variable by name, as `load` reads them from the environment.
    pub fn from_vars(vars: &HashMap<String, String>) -> Result<Config, ConfigError> {
        // `verify` expects the issuer `KEYCLOAK_URL` + `/realms/` + `KEYCLOAK_REALM`, hence no
        // trailing `/`. Only `http://` is accepted because the build has no TLS (accepted risk).
        let keycloak_url = required(vars, "KEYCLOAK_URL")?;
        if !keycloak_url.starts_with("http://") || keycloak_url.ends_with('/') {
            return Err(ConfigError::Invalid(String::from("KEYCLOAK_URL")));
        }

        let pepper = required(vars, "DIAL_CODE_PEPPER")?;
        let dial_code_pepper = pepper
            .parse::<DialCodePepper>()
            .map_err(|_| ConfigError::Invalid(String::from("DIAL_CODE_PEPPER")))?;

        let sa_client_secret = SecretString::from(required(vars, "KEYCLOAK_SA_CLIENT_SECRET")?);

        Ok(Config {
            keycloak_url,
            realm: required(vars, "KEYCLOAK_REALM")?,
            terminal_client_id: required(vars, "KEYCLOAK_TERMINAL_CLIENT_ID")?,
            sa_client_id: required(vars, "KEYCLOAK_SA_CLIENT_ID")?,
            sa_client_secret,
            vaults_path: PathBuf::from(required(vars, "VAULTS_PATH")?),
            realm_kid: required(vars, "KEYCLOAK_REALM_KID")?,
            realm_public_key: required(vars, "KEYCLOAK_REALM_PUBLIC_KEY")?,
            dial_code_pepper,
        })
    }
}

/// Returns the value of a variable, or `ConfigError::Missing` if it is absent or blank.
///
/// * `vars`: The value of each variable by name.
/// * `name`: The name of the variable to read.
fn required(vars: &HashMap<String, String>, name: &str) -> Result<String, ConfigError> {
    match vars.get(name) {
        Some(value) if !value.trim().is_empty() => Ok(value.clone()),
        _ => Err(ConfigError::Missing(String::from(name))),
    }
}

#[cfg(test)]
impl Config {
    /// Builds a valid config for unit tests, pinned to `TEST_REALM_PUBLIC_KEY` (`kid` =
    /// `test-kid`).
    pub fn for_tests() -> Config {
        Config::from_vars(&test_vars()).expect("valid test config")
    }
}

/// Base64 string of a test RSA public key (its private key is not kept), for testing use.
#[cfg(test)]
const TEST_REALM_PUBLIC_KEY: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Shm7v1XY16QVs+IzVwf",
    "lSsZAwWYA+eQd803xtTqwKtVCOJl+hvQAYe2v76r9aQ5NtSQLshxdNj2+E0kIb15",
    "FxBQRzHlB3ZsUglYvMYP5SlIrvl0zO7YYi+igXDSnlo7EBwgfACCmtkZjOcng/+B",
    "8zEGZZ8O44+rbvT5Su89fAk3NW1rzaK3snaXKBio0iRXvkRxvyiDylgo1+Roo4lH",
    "SAEt3bu8++u/EHkKydwpvj12NM6vpImduEMIhJ78Qu46uOldJtEJaFVV1SEySSnL",
    "tu4KT3KWmbr3+aQQnUX3yiSKUIKL3CJlFAkL+ntsO0sX7GaM2dLyE/gy8fiMJUa8",
    "8wIDAQAB",
);

/// Valid values for every variable, used by `Config::for_tests`.
#[cfg(test)]
fn test_vars() -> HashMap<String, String> {
    let public_key = String::from(TEST_REALM_PUBLIC_KEY);
    let values = [
        ("KEYCLOAK_URL", String::from("http://localhost:7080")),
        ("KEYCLOAK_REALM", String::from("secubank")),
        (
            "KEYCLOAK_TERMINAL_CLIENT_ID",
            String::from("secubank-terminal"),
        ),
        (
            "KEYCLOAK_SA_CLIENT_ID",
            String::from("secubank-terminal-service-account"),
        ),
        ("KEYCLOAK_SA_CLIENT_SECRET", String::from("secret")),
        ("VAULTS_PATH", String::from("vaults.toml")),
        ("KEYCLOAK_REALM_KID", String::from("test-kid")),
        ("KEYCLOAK_REALM_PUBLIC_KEY", public_key),
        ("DIAL_CODE_PEPPER", "A".repeat(44)),
    ];
    values
        .into_iter()
        .map(|(name, value)| (String::from(name), value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_loads() {
        let config = Config::from_vars(&test_vars()).expect("valid config");
        assert_eq!(config.keycloak_url, "http://localhost:7080");
    }

    #[test]
    fn missing_or_blank_variable_is_refused() {
        let mut vars = test_vars();
        vars.remove("KEYCLOAK_REALM_KID");
        let error = Config::from_vars(&vars).expect_err("missing");
        assert_eq!(
            error,
            ConfigError::Missing(String::from("KEYCLOAK_REALM_KID"))
        );

        let mut vars = test_vars();
        vars.insert(String::from("KEYCLOAK_REALM"), String::from("  "));
        let error = Config::from_vars(&vars).expect_err("blank");
        assert_eq!(error, ConfigError::Missing(String::from("KEYCLOAK_REALM")));
    }

    #[test]
    fn bad_url_is_refused() {
        for url in [
            "localhost:7080",
            "http://localhost:7080/",
            "https://localhost:7080",
            "ftp://localhost",
        ] {
            let mut vars = test_vars();
            vars.insert(String::from("KEYCLOAK_URL"), String::from(url));
            let error = Config::from_vars(&vars).expect_err(url);
            assert_eq!(error, ConfigError::Invalid(String::from("KEYCLOAK_URL")));
        }
    }

    #[test]
    fn weak_pepper_is_refused() {
        let mut vars = test_vars();
        vars.insert(String::from("DIAL_CODE_PEPPER"), String::from("short"));
        let error = Config::from_vars(&vars).expect_err("weak pepper");
        assert_eq!(
            error,
            ConfigError::Invalid(String::from("DIAL_CODE_PEPPER"))
        );
    }
}
