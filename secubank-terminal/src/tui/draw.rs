//! Drawing of the screens from the state of the app.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};

use super::action::ACTIONS;
use super::{App, Screen};

/// The style of the selected menu entry and the focused field.
fn highlight() -> Style {
    Style::new().add_modifier(Modifier::REVERSED)
}

/// Draws the whole screen: title bar, main area and help line.
///
/// * `frame`: The frame to draw on.
/// * `app`: The state to draw.
pub fn draw(frame: &mut Frame, app: &mut App) {
    let [title_area, main_area, help_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let title = Paragraph::new("SecuBank terminal")
        .style(Style::new().add_modifier(Modifier::BOLD))
        .centered();
    frame.render_widget(title, title_area);

    match app.screen {
        Screen::Menu => draw_menu(frame, main_area, &mut app.menu),
        Screen::Form => draw_form(frame, main_area, app),
        Screen::Working => draw_message(frame, main_area, "Working", "Working..."),
        Screen::VaultDoor => match &app.vault_door {
            Some(door) => door.draw(frame, main_area, &app.message),
            None => draw_message(frame, main_area, "Result", &app.message),
        },
        Screen::Result => draw_message(frame, main_area, "Result", &app.message),
    }

    let help = match (&app.vault_door, app.screen) {
        (Some(door), Screen::VaultDoor) => door.help_text(),
        _ => help_text(app.screen),
    };
    frame.render_widget(Paragraph::new(help), help_area);
}

/// Draws the menu, with the selected entry highlighted.
///
/// * `frame`: The frame to draw on.
/// * `area`: The area of the frame to draw in.
/// * `state`: The menu state, with the selected entry.
fn draw_menu(frame: &mut Frame, area: Rect, state: &mut ListState) {
    let mut items = Vec::new();
    for action in ACTIONS {
        items.push(ListItem::new(action.title()));
    }
    items.push(ListItem::new("Quit"));

    let list = List::new(items)
        .block(Block::bordered().title("Menu"))
        .highlight_style(highlight())
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, state);
}

/// Draws the open form, one field per line, with the focused field highlighted.
///
/// * `frame`: The frame to draw on.
/// * `area`: The area of the frame to draw in.
/// * `app`: The state, with the fields and the focus.
fn draw_form(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    for (index, field) in app.fields.iter().enumerate() {
        // `shown_value` gives stars for a masked field, so no secret reaches the screen.
        if index == app.focus {
            let text = format!("> {:>10}: {}", field.label(), field.shown_value());
            lines.push(Line::styled(text, highlight()));
        } else {
            let text = format!("  {:>10}: {}", field.label(), field.shown_value());
            lines.push(Line::from(text));
        }
    }

    let form = Paragraph::new(lines)
        .block(Block::bordered().title(app.action.title()))
        .wrap(Wrap { trim: false });
    frame.render_widget(form, area);
}

/// Draws a bordered box with a title and a message.
///
/// * `frame`: The frame to draw on.
/// * `area`: The area of the frame to draw in.
/// * `title`: The title of the box.
/// * `message`: The message in the box.
fn draw_message(frame: &mut Frame, area: Rect, title: &str, message: &str) {
    let text = Paragraph::new(message)
        .block(Block::bordered().title(title))
        .wrap(Wrap { trim: false });
    frame.render_widget(text, area);
}

/// Returns the help line for a screen.
///
/// * `screen`: The shown screen.
fn help_text(screen: Screen) -> &'static str {
    match screen {
        Screen::Menu => "Up/Down or j/k: move   Enter: select   q or Esc: quit",
        Screen::Form => "Tab/Down: next   Shift+Tab/Up: previous   Enter: submit   Esc: menu",
        Screen::Working => "Please wait...",
        Screen::VaultDoor => "Enter/Esc: skip",
        Screen::Result => "Press any key to return to the menu",
    }
}
