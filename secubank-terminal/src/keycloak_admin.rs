//! Facade for the Keycloak Admin API to create and find users.

use secrecy::ExposeSecret;

use crate::auth::TokenResponse;
use crate::config::Config;
use crate::http;
use crate::policy::Officer;
use crate::types::{AppRole, NewUser, Sub, UserInfo, Username};

/// Reason why an admin API call fails. Each reason is shown as a fixed message, without Keycloak's
/// details.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Keycloak is unavailable")]
    Unavailable,
    #[error("username or email already taken")]
    Taken,
    #[error("registration refused")]
    Refused,
}

/// Gets an access token for the service account with the client credentials grant.
///
/// * `client`: The HTTP client to use for the request.
/// * `config`: The terminal configuration, for Keycloak and the service account credentials.
async fn service_account_token(
    client: &reqwest::Client,
    config: &Config,
) -> Result<String, AdminError> {
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        config.keycloak_url, config.realm
    );
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", config.sa_client_id.as_str()),
        ("client_secret", config.sa_client_secret.expose_secret()),
    ];
    let response = client
        .post(url)
        .form(&form)
        .send()
        .await
        .map_err(|_| AdminError::Unavailable)?;
    if !response.status().is_success() {
        return Err(AdminError::Unavailable);
    }
    let body: TokenResponse = response.json().await.map_err(|_| AdminError::Unavailable)?;
    Ok(body.access_token)
}

/// The user representation sent to Keycloak. Only these fields are sent.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct UserBody {
    username: String,
    email: String,
    first_name: String,
    last_name: String,
    enabled: bool,
    credentials: [CredentialBody; 1],
}

/// A password credential of the user representation.
#[derive(serde::Serialize)]
struct CredentialBody {
    #[serde(rename = "type")]
    kind: String,
    value: String,
    temporary: bool,
}

/// Creates an enabled user with a permanent password. Gives `AdminError::Taken` when Keycloak
/// answers 409 (username or email taken), `AdminError::Refused` when it answers 400, and
/// `AdminError::Unavailable` on any other failure.
///
/// * `config`: The terminal configuration, for Keycloak and the service account credentials.
/// * `user`: The checked registration request.
pub fn create_user(config: &Config, user: &NewUser) -> Result<(), AdminError> {
    let body = UserBody {
        username: String::from(user.username().as_str()),
        email: String::from(user.email().as_str()),
        first_name: String::from(user.first_name().as_str()),
        last_name: String::from(user.last_name().as_str()),
        enabled: true,
        credentials: [CredentialBody {
            kind: String::from("password"),
            value: String::from(user.password().expose_secret()),
            temporary: false,
        }],
    };
    let url = format!(
        "{}/admin/realms/{}/users",
        config.keycloak_url, config.realm
    );

    let runtime = http::runtime().ok_or(AdminError::Unavailable)?;
    let client = http::client().ok_or(AdminError::Unavailable)?;
    runtime.block_on(async {
        let token = service_account_token(&client, config).await?;
        let response = client
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|_| AdminError::Unavailable)?;
        match response.status().as_u16() {
            201 => Ok(()),
            409 => Err(AdminError::Taken),
            400 => Err(AdminError::Refused),
            _ => Err(AdminError::Unavailable),
        }
    })
}

/// Sends an authenticated GET. Network errors and error statuses give `None`.
///
/// * `client`: The HTTP client to use for the request.
/// * `url`: The URL to GET.
/// * `token`: The bearer token to use for authentication.
async fn get(
    client: &reqwest::Client,
    url: reqwest::Url,
    token: &str,
) -> Option<reqwest::Response> {
    let response = client.get(url).bearer_auth(token).send().await.ok()?;
    response.error_for_status().ok()
}

/// A user from the search results, with only the fields used here.
#[derive(serde::Deserialize)]
struct FoundUser {
    id: String,
    username: String,
    enabled: bool,
}

/// A role from the role mappings.
#[derive(serde::Deserialize)]
struct RoleBody {
    name: String,
}

/// Finds a user and their effective realm roles. Gives `None` when Keycloak is unavailable or when
/// the search doesn't give exactly one user with this exact username.
///
/// * `config`: The terminal configuration, for Keycloak and the service account credentials.
/// * `_by`: The officer capability. Unused, but only an identity that `authorize` let through as an
///   officer can call this.
/// * `username`: The username to look up.
pub fn find_user(config: &Config, _by: &Officer, username: &Username) -> Option<UserInfo> {
    let users_url = format!(
        "{}/admin/realms/{}/users",
        config.keycloak_url, config.realm
    );

    let runtime = http::runtime()?;
    let client = http::client()?;
    runtime.block_on(async {
        let token = service_account_token(&client, config).await.ok()?;

        // The query is encoded here, so it doesn't rely on the `Username` charset.
        let search_url = reqwest::Url::parse_with_params(
            &users_url,
            [("username", username.as_str()), ("exact", "true")],
        )
        .ok()?;
        let found: Vec<FoundUser> = get(&client, search_url, &token).await?.json().await.ok()?;
        let [user] = found.as_slice() else {
            return None;
        };
        if user.username != username.as_str() {
            return None;
        }
        // Data from Keycloak is input too, so the ID must be a valid `Sub`.
        let sub = user.id.parse::<Sub>().ok()?;

        // The direct mappings miss the roles inherited from composite roles and groups, so
        // `/composite` is needed for the effective roles.
        let roles_url = format!("{users_url}/{}/role-mappings/realm/composite", sub.as_str());
        let roles_url = reqwest::Url::parse(&roles_url).ok()?;
        let roles: Vec<RoleBody> = get(&client, roles_url, &token).await?.json().await.ok()?;

        Some(UserInfo {
            sub,
            enabled: user.enabled,
            roles: roles
                .iter()
                .filter_map(|role| AppRole::from_role_name(&role.name))
                .collect(),
        })
    })
}
