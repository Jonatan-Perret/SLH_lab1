//! Text fields of the forms that hold what the user types.

use secrecy::zeroize::Zeroize;

/// Maximum number of characters in a field. It is above every input limit, so a too long input
/// reaches the validators and is refused instead of truncated.
const MAX_FIELD_LEN: usize = 256;

/// One text field of a form. No `Clone` or `Debug`, so a secret can't be copied or printed by
/// mistake.
pub struct Field {
    /// The name shown before the value.
    label: String,
    /// What the user typed.
    value: String,
    /// True for secrets, which are drawn as stars.
    masked: bool,
}

impl Field {
    /// Creates an empty field.
    ///
    /// * `label`: The name shown before the value.
    /// * `masked`: True for secrets, which are drawn as stars.
    pub fn new(label: &str, masked: bool) -> Field {
        Field {
            label: String::from(label),
            // Room for the longest value (4 bytes per character), so typing never moves it to a
            // bigger buffer, which would leave an old copy behind in memory.
            value: String::with_capacity(MAX_FIELD_LEN * 4),
            masked,
        }
    }

    /// The name shown before the value.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// What the user typed, borrowed so it is never copied.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Appends a typed character, unless it is a control character or the field is full.
    ///
    /// * `c`: The typed character.
    pub fn push(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        if self.value.chars().count() >= MAX_FIELD_LEN {
            return;
        }
        self.value.push(c);
    }

    /// Removes the last character, if any.
    pub fn pop(&mut self) {
        self.value.pop();
    }

    /// The value as drawn on screen: one `*` per character when the field is masked.
    pub fn shown_value(&self) -> String {
        if self.masked {
            "*".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }
}

/// Empties every field and wipes its memory, secrets included.
///
/// * `fields`: The fields to clear.
pub fn clear_fields(fields: &mut [Field]) {
    for field in fields {
        field.value.zeroize();
    }
}
