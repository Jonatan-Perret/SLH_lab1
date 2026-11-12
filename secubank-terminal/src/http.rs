//! HTTP plumbing shared by `auth` and `keycloak_admin`.

use std::time::Duration;

/// Builds a new single-threaded Tokio runtime to run the async HTTP requests, or `None` if it can't
/// be created.
pub fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()
}

/// Builds a new HTTP client with a 10 s timeout, so a hanging Keycloak won't freeze the terminal,
/// or `None` if it can't be created.
pub fn client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()
}
