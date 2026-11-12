//! Actions that can be performed in the terminal.
//!
//! The actions are shown in the menu and have a form with fields. When the user submits a form, it
//! is sent to the pipeline and the outcome is returned.

use crate::auth::RealmKey;
use crate::config::Config;
use crate::pipeline::{self, Outcome};
use crate::policy::Engine;

use super::field::Field;

/// The actions available at the terminal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Register,
    SetDialCode,
    OpenVault,
    AssignOwner,
}

/// The actions in menu order. The menu adds "Quit" after them.
pub const ACTIONS: [Action; 4] = [
    Action::Register,
    Action::SetDialCode,
    Action::OpenVault,
    Action::AssignOwner,
];

/// Number of menu entries: the four actions plus "Quit".
pub const MENU_LEN: usize = ACTIONS.len() + 1;

impl Action {
    /// The name shown in the menu and as the form title.
    pub fn title(self) -> &'static str {
        match self {
            Action::Register => "Register",
            Action::SetDialCode => "Set dial code",
            Action::OpenVault => "Open vault",
            Action::AssignOwner => "Assign owner (officers)",
        }
    }

    /// The empty fields of this action's form: label and whether it is masked.
    pub fn fields(self) -> Vec<Field> {
        match self {
            Action::Register => vec![
                Field::new("Username", false),
                Field::new("Email", false),
                Field::new("First name", false),
                Field::new("Last name", false),
                Field::new("Password", true),
            ],
            Action::SetDialCode | Action::OpenVault => vec![
                Field::new("Username", false),
                Field::new("Password", true),
                Field::new("Vault ID", false),
                Field::new("Dial code", true),
            ],
            Action::AssignOwner => vec![
                Field::new("Username", false),
                Field::new("Password", true),
                Field::new("Vault ID", false),
                Field::new("New owner", false),
            ],
        }
    }
}

/// Sends a submitted form to the pipeline and returns its outcome. The values are only borrowed
/// here and the caller clears them afterwards.
///
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key.
/// * `engine`: The Cedar engine with the schema and policies.
/// * `action`: The action of the form.
/// * `fields`: The filled fields, in the order of `Action::fields`.
pub fn submit(
    config: &Config,
    realm_key: &RealmKey,
    engine: &Engine,
    action: Action,
    fields: &[Field],
) -> Outcome {
    // Fields are in the order of `Action::fields`.
    let value = |index: usize| fields.get(index).map_or("", |field| field.value());
    match action {
        Action::Register => {
            pipeline::register(config, value(0), value(1), value(2), value(3), value(4))
        }
        Action::SetDialCode => pipeline::set_dial_code(
            config,
            realm_key,
            engine,
            value(0),
            value(1),
            value(2),
            value(3),
        ),
        Action::OpenVault => pipeline::open_vault(
            config,
            realm_key,
            engine,
            value(0),
            value(1),
            value(2),
            value(3),
        ),
        Action::AssignOwner => pipeline::assign_owner(
            config,
            realm_key,
            engine,
            value(0),
            value(1),
            value(2),
            value(3),
        ),
    }
}
