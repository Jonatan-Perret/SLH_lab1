//! SecuBank terminal main entry point.

#![forbid(unsafe_code)]

mod auth;
mod config;
mod dial_code;
mod http;
mod keycloak_admin;
mod pipeline;
mod policy;
mod store;
mod tui;
mod types;

use std::error::Error;
use std::process::ExitCode;

use auth::RealmKey;
use config::Config;
use policy::Engine;

/// Entry point of the terminal. Loads the configuration, the policy engine and the realm key, then
/// runs the TUI. If any of them fails to load, prints the error and exits with a failure code.
fn main() -> ExitCode {
    // Fail before the TUI takes the screen so the message stays visible.
    let (config, engine, realm_key) = match load() {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("secubank-terminal: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut terminal = ratatui::init();
    let result = tui::run(&mut terminal, config, realm_key, engine);
    ratatui::restore();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("secubank-terminal: terminal error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Loads the configuration, the policy engine and the realm key, in this order. Stops at the first
/// one that fails.
fn load() -> Result<(Config, Engine, RealmKey), Box<dyn Error>> {
    let config = Config::load()?;
    let engine = Engine::load()?;
    let realm_key = RealmKey::from_config(&config)?;
    Ok((config, engine, realm_key))
}
