//! Text user interface using `ratatui`.
//!
//! This module holds the state of the screens and handles the keyboard. `action::submit` passes
//! the fields to the pipeline, which does all the access control, and `draw` draws the screens.

mod action;
mod draw;
mod field;
mod vault_door;

use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::ListState;

use crate::auth::RealmKey;
use crate::config::Config;
use crate::pipeline::Outcome;
use crate::policy::Engine;
use action::{ACTIONS, Action, MENU_LEN, submit};
use field::{Field, clear_fields};
use vault_door::VaultDoor;

/// Which screen is shown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    Menu,
    Form,
    Working,
    VaultDoor,
    Result,
}

/// The whole state of the user interface.
struct App {
    /// The current screen.
    screen: Screen,
    /// Which menu entry is selected.
    menu: ListState,
    /// The action of the last opened form.
    action: Action,
    /// The fields of the last opened form.
    fields: Vec<Field>,
    /// Index of the focused field in `fields`.
    focus: usize,
    /// The message shown on the result screen.
    message: String,
    /// The vault door animation, while it is on screen.
    vault_door: Option<VaultDoor>,
    /// Set to true to leave the program.
    quit: bool,
    /// The terminal configuration, passed to the pipeline.
    config: Config,
    /// The pinned realm key, passed to the pipeline.
    realm_key: RealmKey,
    /// The Cedar engine, passed to the pipeline.
    engine: Engine,
}

impl App {
    /// Builds the app on the menu, with the first entry selected.
    ///
    /// * `config`: The terminal configuration.
    /// * `realm_key`: The pinned realm key.
    /// * `engine`: The Cedar engine with the schema and policies.
    fn new(config: Config, realm_key: RealmKey, engine: Engine) -> App {
        App {
            screen: Screen::Menu,
            menu: ListState::default().with_selected(Some(0)),
            action: Action::Register,
            fields: Vec::new(),
            focus: 0,
            message: String::new(),
            vault_door: None,
            quit: false,
            config,
            realm_key,
            engine,
        }
    }

    /// Updates the state after one key press.
    ///
    /// * `key`: The pressed key.
    fn handle_key(&mut self, key: KeyEvent) {
        match self.screen {
            Screen::Menu => self.menu_key(key),
            Screen::Form => self.form_key(key),
            // Keys are not read while working (see `run`).
            Screen::Working => {}
            Screen::VaultDoor => {
                let next = self.vault_door.as_mut().map(|door| door.handle_key(key));
                if next != Some(vault_door::Next::Stay) {
                    self.vault_door = None;
                    self.screen = Screen::Result;
                }
            }
            // Any key goes back to the menu.
            Screen::Result => self.screen = Screen::Menu,
        }
    }

    /// Handles a key on the menu.
    ///
    /// * `key`: The pressed key.
    fn menu_key(&mut self, key: KeyEvent) {
        let selected = self.menu.selected().unwrap_or(0);
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.menu.select(Some(next_index(selected, MENU_LEN)));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.menu.select(Some(previous_index(selected, MENU_LEN)));
            }
            KeyCode::Enter => match ACTIONS.get(selected) {
                Some(action) => self.open_form(*action),
                // The entry after the actions is "Quit".
                None => self.quit = true,
            },
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            _ => {}
        }
    }

    /// Shows the empty form of an action, with the first field focused.
    ///
    /// * `action`: The action whose form to show.
    fn open_form(&mut self, action: Action) {
        clear_fields(&mut self.fields);
        self.action = action;
        self.fields = action.fields();
        self.focus = 0;
        self.screen = Screen::Form;
    }

    /// Handles a key on a form. Here `q`, `j` and `k` are ordinary text.
    ///
    /// * `key`: The pressed key.
    fn form_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                clear_fields(&mut self.fields);
                self.focus = 0;
                self.screen = Screen::Menu;
            }
            // `run` sees the Working screen, draws it, then submits.
            KeyCode::Enter => self.screen = Screen::Working,
            KeyCode::Tab | KeyCode::Down => {
                self.focus = next_index(self.focus, self.fields.len());
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = previous_index(self.focus, self.fields.len());
            }
            KeyCode::Backspace => {
                if let Some(field) = self.fields.get_mut(self.focus) {
                    field.pop();
                }
            }
            KeyCode::Char(c) if !is_ctrl_shortcut(key) => {
                if let Some(field) = self.fields.get_mut(self.focus) {
                    field.push(c);
                }
            }
            _ => {}
        }
    }

    /// Submits the form, empties it, and shows the result. An opened vault first shows the vault
    /// door.
    fn finish_submission(&mut self) {
        let outcome = submit(
            &self.config,
            &self.realm_key,
            &self.engine,
            self.action,
            &self.fields,
        );
        clear_fields(&mut self.fields);
        self.focus = 0;
        self.message = outcome.message();
        // Only after the pipeline said yes: the door shows the result, it does not decide it.
        if self.action == Action::OpenVault && matches!(outcome, Outcome::Done(_)) {
            self.vault_door = Some(VaultDoor::new());
            self.screen = Screen::VaultDoor;
        } else {
            self.screen = Screen::Result;
        }
    }
}

/// Checks whether a key is a Ctrl+key shortcut and not text. On Windows, AltGr (needed for `@` on
/// some keyboards) arrives as Ctrl+Alt, so that still types.
///
/// * `key`: The pressed key.
fn is_ctrl_shortcut(key: KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && !key.modifiers.contains(KeyModifiers::ALT)
}

/// Returns the index after `index` in a list of `len` items, going back to the first after the
/// last.
///
/// * `index`: The current index.
/// * `len`: The number of items.
fn next_index(index: usize, len: usize) -> usize {
    if index + 1 < len { index + 1 } else { 0 }
}

/// Returns the index before `index` in a list of `len` items, going to the last before the first.
///
/// * `index`: The current index.
/// * `len`: The number of items.
fn previous_index(index: usize, len: usize) -> usize {
    if index > 0 {
        index - 1
    } else {
        len.saturating_sub(1)
    }
}

/// Runs the terminal until the user quits.
///
/// * `terminal`: The terminal to draw on.
/// * `config`: The terminal configuration.
/// * `realm_key`: The pinned realm key.
/// * `engine`: The Cedar engine with the schema and policies.
pub fn run(
    terminal: &mut DefaultTerminal,
    config: Config,
    realm_key: RealmKey,
    engine: Engine,
) -> std::io::Result<()> {
    let mut app = App::new(config, realm_key, engine);
    while !app.quit {
        terminal.draw(|frame| draw::draw(frame, &mut app))?;
        if app.screen == Screen::Working {
            // "Working..." is on screen now, so the slow submission can run.
            app.finish_submission();
            discard_pending_events()?;
        } else if app.screen == Screen::VaultDoor {
            // The door moves on its own, so wait at most one frame for a key.
            if event::poll(vault_door::TICK)?
                && let Some(key) = read_key_press()?
            {
                app.handle_key(key);
            }
            if let Some(door) = app.vault_door.as_mut() {
                door.tick(Instant::now());
            }
        } else if let Some(key) = read_key_press()? {
            app.handle_key(key);
        }
    }
    Ok(())
}

/// Waits for the next event and returns it if it is a key press. Key releases, resizes and other
/// events give `None` and the loop draws again.
fn read_key_press() -> std::io::Result<Option<KeyEvent>> {
    match event::read()? {
        Event::Key(key) if key.kind == KeyEventKind::Press => Ok(Some(key)),
        _ => Ok(None),
    }
}

/// Throws away keys typed while the terminal was busy, so they can't skip the result screen.
fn discard_pending_events() -> std::io::Result<()> {
    while event::poll(Duration::ZERO)? {
        event::read()?;
    }
    Ok(())
}
