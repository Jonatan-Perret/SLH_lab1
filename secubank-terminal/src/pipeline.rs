//! The actions behind the TUI forms. Each one parses the fields, logs in, authorizes, then lets the
//! policy decide on the vault.

use crate::auth::{self, RealmKey};
use crate::config::Config;
use crate::keycloak_admin::{self, AdminError};
use crate::policy::{self, Decision, Engine, Principal, Request};
use crate::types::{DialCode, Email, NewUser, Password, PersonName, Username, VaultId};
use crate::{dial_code, store};

/// Result of an action (shown on the result screen).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A successful action with a message.
    Done(String),
    /// Any access-control failure.
    Denied,
    /// A parsing failure which names the field.
    InvalidInput(String),
    /// A failed registration, with the reason to show.
    Failed(String),
}

impl Outcome {
    /// The text shown on a result screen.
    pub fn message(&self) -> String {
        match self {
            Outcome::Done(message) | Outcome::Failed(message) => message.clone(),
            Outcome::Denied => String::from("Access denied."),
            Outcome::InvalidInput(field) => format!("Invalid {field}."),
        }
    }
}

/// Logs in and authorizes the user. Fails with `None` without saying which step failed.
///
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key, to verify the token.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `username`: The username to log in with.
/// * `password`: The password to log in with.
fn login(
    config: &Config,
    realm_key: &RealmKey,
    engine: &Engine,
    username: &Username,
    password: &Password,
) -> Option<Principal> {
    let token = auth::password_grant(config, username, password).ok()?;
    let identity = auth::verify(&token, realm_key, config).ok()?;
    policy::authorize(engine, &identity).ok()
}

/// Builds the `InvalidInput` outcome of a field that failed to parse.
///
/// * `field`: The name of the field, as shown to the user.
fn invalid(field: &str) -> Outcome {
    Outcome::InvalidInput(String::from(field))
}

/// Parses the fields every vault action starts with. The first field that fails gives its
/// `InvalidInput` outcome.
///
/// * `username`: The typed username.
/// * `password`: The typed password.
/// * `vault_id`: The typed vault ID.
fn parse_login(
    username: &str,
    password: &str,
    vault_id: &str,
) -> Result<(Username, Password, VaultId), Outcome> {
    let username = username
        .parse::<Username>()
        .map_err(|_| invalid("username"))?;
    let password = Password::try_from(String::from(password)).map_err(|_| invalid("password"))?;
    let vault_id = vault_id
        .parse::<VaultId>()
        .map_err(|_| invalid("vault ID"))?;
    Ok((username, password, vault_id))
}

/// Loads the vault, asks the policy and applies the effect. A broken vault file counts as a missing
/// vault, which the policy denies, and a failed write also gives `Denied`.
///
/// * `config`: The terminal configuration.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `vault_id`: The vault to act on.
/// * `request`: The request to decide on and apply.
/// * `done`: The message to show when the effect is applied.
fn decide_and_apply(
    config: &Config,
    engine: &Engine,
    vault_id: &VaultId,
    request: &Request,
    done: String,
) -> Outcome {
    let vault = store::find(&config.vaults_path, vault_id).ok().flatten();
    let applied = match policy::decide(engine, request, vault.as_ref(), &config.dial_code_pepper) {
        Decision::Allow(effect) => store::apply(&config.vaults_path, vault_id, &effect).is_ok(),
        Decision::Deny => false,
    };
    if applied {
        Outcome::Done(done)
    } else {
        Outcome::Denied
    }
}

/// Opens a vault. Needs a client who owns the vault, with a clearance that covers its
/// classification, and the correct dial code.
///
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key, to verify the token.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `username`: The typed username.
/// * `password`: The typed password.
/// * `vault_id`: The typed vault ID.
/// * `dial_code`: The typed dial code.
pub fn open_vault(
    config: &Config,
    realm_key: &RealmKey,
    engine: &Engine,
    username: &str,
    password: &str,
    vault_id: &str,
    dial_code: &str,
) -> Outcome {
    let (username, password, vault_id) = match parse_login(username, password, vault_id) {
        Ok(fields) => fields,
        Err(outcome) => return outcome,
    };
    let Ok(code) = dial_code.parse::<DialCode>() else {
        return invalid("dial code");
    };

    let Some(Principal::Client(client)) = login(config, realm_key, engine, &username, &password)
    else {
        // Same Argon2 cost as a real attempt, so a failed login isn't faster.
        dial_code::verify(&code, None, &config.dial_code_pepper);
        return Outcome::Denied;
    };
    let request = Request::Open { by: client, code };
    let done = format!("Vault {} is open.", vault_id.as_str());
    decide_and_apply(config, engine, &vault_id, &request, done)
}

/// Sets the first dial code of a vault the client owns.
///
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key, to verify the token.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `username`: The typed username.
/// * `password`: The typed password.
/// * `vault_id`: The typed vault ID.
/// * `dial_code`: The typed new dial code.
pub fn set_dial_code(
    config: &Config,
    realm_key: &RealmKey,
    engine: &Engine,
    username: &str,
    password: &str,
    vault_id: &str,
    dial_code: &str,
) -> Outcome {
    let (username, password, vault_id) = match parse_login(username, password, vault_id) {
        Ok(fields) => fields,
        Err(outcome) => return outcome,
    };
    let Ok(code) = dial_code.parse::<DialCode>() else {
        return invalid("dial code");
    };

    let Some(Principal::Client(client)) = login(config, realm_key, engine, &username, &password)
    else {
        // Same Argon2 cost as a real attempt, so a failed login isn't faster.
        dial_code::verify(&code, None, &config.dial_code_pepper);
        return Outcome::Denied;
    };
    // Hash only after `authorize` so unauthorized users can't make the terminal run Argon2.
    let Ok(hash) = dial_code::hash(&code, &config.dial_code_pepper) else {
        return Outcome::Denied;
    };
    let request = Request::SetDialCode { by: client, hash };
    let done = format!("Dial code set for vault {}.", vault_id.as_str());
    decide_and_apply(config, engine, &vault_id, &request, done)
}

/// Gives a vault to a new owner. Officers only.
///
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key, to verify the token.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `username`: The typed username.
/// * `password`: The typed password.
/// * `vault_id`: The typed vault ID.
/// * `new_owner`: The typed username of the new owner.
pub fn assign_owner(
    config: &Config,
    realm_key: &RealmKey,
    engine: &Engine,
    username: &str,
    password: &str,
    vault_id: &str,
    new_owner: &str,
) -> Outcome {
    let (username, password, vault_id) = match parse_login(username, password, vault_id) {
        Ok(fields) => fields,
        Err(outcome) => return outcome,
    };
    let Ok(new_owner) = new_owner.parse::<Username>() else {
        return invalid("new owner");
    };

    let Some(Principal::Officer(officer)) = login(config, realm_key, engine, &username, &password)
    else {
        return Outcome::Denied;
    };
    let new_owner = keycloak_admin::find_user(config, &officer, &new_owner);
    let request = Request::AssignOwner {
        by: officer,
        new_owner,
    };
    let done = format!("Vault {} has a new owner.", vault_id.as_str());
    decide_and_apply(config, engine, &vault_id, &request, done)
}

/// Creates a client account. Keycloak gives it `client` (default roles) and the Standard clearance
/// (default group `standard-clients`) until an admin changes it.
///
/// * `config`: The terminal configuration.
/// * `username`: The typed username.
/// * `email`: The typed email address.
/// * `first_name`: The typed first name.
/// * `last_name`: The typed last name.
/// * `password`: The typed new password.
pub fn register(
    config: &Config,
    username: &str,
    email: &str,
    first_name: &str,
    last_name: &str,
    password: &str,
) -> Outcome {
    let Ok(username) = username.parse::<Username>() else {
        return invalid("username");
    };
    let Ok(email) = email.parse::<Email>() else {
        return invalid("email");
    };
    let Ok(first_name) = first_name.parse::<PersonName>() else {
        return invalid("first name");
    };
    let Ok(last_name) = last_name.parse::<PersonName>() else {
        return invalid("last name");
    };
    // The reason is about the user's own new password, so it can be shown.
    let password = match Password::try_from(String::from(password)) {
        Ok(password) => password,
        Err(reason) => return new_password_refused(reason),
    };
    let user = match NewUser::new(username, email, first_name, last_name, password) {
        Ok(user) => user,
        Err(reason) => return new_password_refused(reason),
    };

    match keycloak_admin::create_user(config, &user) {
        Ok(()) => Outcome::Done(String::from("Account created.")),
        Err(AdminError::Taken) => Outcome::Failed(String::from("Username or email already taken.")),
        Err(AdminError::Refused) => Outcome::Failed(String::from("Registration refused.")),
        Err(AdminError::Unavailable) => Outcome::Failed(String::from("Registration unavailable.")),
    }
}

/// Builds the `InvalidInput` outcome of a refused new password, with the reason in the message.
///
/// * `reason`: The reason from `Password::try_from` or `NewUser::new`.
fn new_password_refused(reason: impl std::fmt::Display) -> Outcome {
    Outcome::InvalidInput(format!("password ({reason})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_stay_generic() {
        assert_eq!(Outcome::Denied.message(), "Access denied.");
        assert_eq!(
            Outcome::InvalidInput(String::from("vault ID")).message(),
            "Invalid vault ID."
        );
    }

    #[test]
    fn bad_fields_are_named() {
        // Every case fails while parsing, before any call to Keycloak.
        let config = Config::for_tests();
        let realm_key = RealmKey::from_config(&config).expect("realm key");
        let engine = Engine::load().expect("policy");
        let open = |vault: &str, code: &str| {
            open_vault(
                &config,
                &realm_key,
                &engine,
                "boris",
                "secubank-test-password",
                vault,
                code,
            )
        };
        assert_eq!(open("V-1", "4L95-3R12-2L20-1R33"), invalid("vault ID"));
        assert_eq!(open("V-002", "1234"), invalid("dial code"));
        assert_eq!(
            register(
                &config,
                "boris",
                "boris@example.com",
                "Boris",
                "Clarke",
                "short"
            ),
            Outcome::InvalidInput(String::from(
                "password (the password must have 15 to 64 characters)"
            ))
        );
    }
}
