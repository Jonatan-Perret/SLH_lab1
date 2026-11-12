//! Input newtypes for the registration and action forms.

use std::fmt;
use std::str::FromStr;

use passwords::analyzer::is_common_password;
use secrecy::{ExposeSecret, SecretString};
use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::is_combining_mark;
use zxcvbn::{Score, zxcvbn};

/// A Keycloak username of 3 to 32 characters from `[a-z0-9._-]`, lowercased on parse (Keycloak
/// lowercases usernames).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username(String);

/// Error when a string is not a valid username.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid username")]
pub struct InvalidUsername;

impl FromStr for Username {
    type Err = InvalidUsername;

    /// Parses a username. Expects 3 to 32 ASCII letters, digits, `.`, `_` or `-`. Uppercase letters
    /// are lowercased.
    ///
    /// * `s`: The username as typed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 3 || s.len() > 32 {
            return Err(InvalidUsername);
        }
        let lower = s.to_ascii_lowercase();
        let allowed =
            |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-');
        if !lower.chars().all(allowed) {
            return Err(InvalidUsername);
        }
        Ok(Username(lower))
    }
}

impl Username {
    /// The username as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A first or last name in Unicode composed form: 1 to 64 characters among letters, combining
/// marks, spaces, `'` and `-`, with at least one letter and no space at either end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonName(String);

/// Error when a string is not a valid name.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid name")]
pub struct InvalidPersonName;

impl FromStr for PersonName {
    type Err = InvalidPersonName;

    /// Parses a person name. Composes it first, then expects 1 to 64 characters among letters,
    /// combining marks, spaces, `'` and `-`, with at least one letter and no space at either end.
    /// The limit of 1024 bytes keeps huge inputs away from `nfc()`.
    ///
    /// * `s`: The name as typed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 1024 {
            return Err(InvalidPersonName);
        }
        let name: String = s.nfc().collect();
        let count = name.chars().count();
        if count == 0 || count > 64 {
            return Err(InvalidPersonName);
        }
        let allowed =
            |c: char| c.is_alphabetic() || is_combining_mark(c) || matches!(c, ' ' | '\'' | '-');
        if !name.chars().all(allowed) || !name.chars().any(char::is_alphabetic) {
            return Err(InvalidPersonName);
        }
        if name.starts_with(' ') || name.ends_with(' ') {
            return Err(InvalidPersonName);
        }
        Ok(PersonName(name))
    }
}

impl PersonName {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An email address in Unicode composed form and lowercase (as Keycloak stores it), with at most
/// 254 characters, exactly one `@` with something on both sides, and no whitespace or control
/// characters. Keycloak checks the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

/// Error when a string is not a valid email address.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid email")]
pub struct InvalidEmail;

impl FromStr for Email {
    type Err = InvalidEmail;

    /// Parses an email address. Composes and lowercases it before the checks, so two spellings of
    /// one address can't become two accounts. The limit of 1024 bytes keeps huge inputs away from
    /// `nfc()`.
    ///
    /// * `s`: The email address as typed.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 1024 {
            return Err(InvalidEmail);
        }
        let email = s.nfc().collect::<String>().to_lowercase();
        if email.chars().count() > 254 {
            return Err(InvalidEmail);
        }
        let Some((local, domain)) = email.split_once('@') else {
            return Err(InvalidEmail);
        };
        if local.is_empty() || domain.is_empty() || domain.contains('@') {
            return Err(InvalidEmail);
        }
        if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(InvalidEmail);
        }
        Ok(Email(email))
    }
}

impl Email {
    /// The address as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A password of 15 to 64 characters. Held in a `SecretString`, so it is zeroized when dropped and
/// never printed.
pub struct Password(SecretString);

/// Error when a string is not a valid password.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the password must have 15 to 64 characters")]
pub struct InvalidPassword;

impl TryFrom<String> for Password {
    type Error = InvalidPassword;

    /// Parses a password. Expects 15 to 64 characters of any kind. Takes the `String` itself and
    /// wraps it before any check, so the input is zeroized even when it is refused.
    ///
    /// * `s`: The password as typed.
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let secret = SecretString::from(s);
        let count = secret.expose_secret().chars().count();
        if !(15..=64).contains(&count) {
            return Err(InvalidPassword);
        }
        Ok(Password(secret))
    }
}

impl Password {
    /// The password in clear.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(***)")
    }
}

/// Reason why a new password is refused at registration. Unlike a login, registration may say why.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidNewPassword {
    #[error("the password is too common")]
    Common,
    #[error("the password is too easy to guess")]
    Weak,
}

/// Checks the strength of a new password, on top of the length check of `Password::try_from`. A
/// common password gives `InvalidNewPassword::Common`, and otherwise a password that is too easy to
/// guess gives `InvalidNewPassword::Weak`.
///
/// * `password`: The new password.
/// * `username`: The username of the new user.
/// * `email`: The email address of the new user.
/// * `first_name`: The first name of the new user.
/// * `last_name`: The last name of the new user.
fn check_new_password(
    password: &Password,
    username: &Username,
    email: &Email,
    first_name: &PersonName,
    last_name: &PersonName,
) -> Result<(), InvalidNewPassword> {
    // check common password
    if is_common_password(password.expose_secret()) {
        return Err(InvalidNewPassword::Common);
    }
    // check weak password
    let estimate = zxcvbn(
        password.expose_secret(),
        &[
            username.as_str(),
            email.as_str(),
            first_name.as_str(),
            last_name.as_str(),
        ],
    );
    if estimate.score() < Score::Three {
        return Err(InvalidNewPassword::Weak);
    }
    Ok(())
}

/// A registration request made only of checked inputs, so nothing else can reach Keycloak's user
/// representation (no mass assignment). The fields are private because the password was checked
/// against these details.
#[derive(Debug)]
pub struct NewUser {
    username: Username,
    email: Email,
    first_name: PersonName,
    last_name: PersonName,
    password: Password,
}

impl NewUser {
    /// Builds the request and checks the new password against the user's details with
    /// `check_new_password`.
    ///
    /// * `username`: The checked username.
    /// * `email`: The checked email address.
    /// * `first_name`: The checked first name.
    /// * `last_name`: The checked last name.
    /// * `password`: The new password, already checked for length.
    pub fn new(
        username: Username,
        email: Email,
        first_name: PersonName,
        last_name: PersonName,
        password: Password,
    ) -> Result<NewUser, InvalidNewPassword> {
        check_new_password(&password, &username, &email, &first_name, &last_name)?;
        Ok(NewUser {
            username,
            email,
            first_name,
            last_name,
            password,
        })
    }

    /// The username.
    pub fn username(&self) -> &Username {
        &self.username
    }

    /// The email address.
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The first name.
    pub fn first_name(&self) -> &PersonName {
        &self.first_name
    }

    /// The last name.
    pub fn last_name(&self) -> &PersonName {
        &self.last_name
    }

    /// The password.
    pub fn password(&self) -> &Password {
        &self.password
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_accepts_and_lowercases() {
        let longest = "a".repeat(32);
        let cases = [
            ("alice", "alice"),
            ("Alice", "alice"),
            ("BOB.smith_2-x", "bob.smith_2-x"),
            ("abc", "abc"),
            (longest.as_str(), longest.as_str()),
        ];
        for (input, expected) in cases {
            let username = input.parse::<Username>().expect("valid username");
            assert_eq!(username.as_str(), expected, "input {input:?}");
        }
    }

    #[test]
    fn username_rejects_invalid_input() {
        let too_long = "a".repeat(33);
        let invalid = [
            "",
            "ab",
            too_long.as_str(),
            "alice@example.com",
            "alice smith",
            "alice\n",
            "élodie",
            "\u{212a}elvin",
        ];
        for input in invalid {
            assert_eq!(
                input.parse::<Username>(),
                Err(InvalidUsername),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn person_name_accepts_names_in_any_script() {
        let valid = [
            "Alice",
            "Zoë", // precomposed letter
            "Jean-Luc",
            "O'Connor",
            "van der Berg",
            "N\u{308}",   // mark with no precomposed form
            "Αλέξανδρος", // Greek
            "李",         // Chinese
        ];
        for input in valid {
            assert!(input.parse::<PersonName>().is_ok(), "input {input:?}");
        }
    }

    #[test]
    fn person_name_is_composed() {
        let decomposed = "Zoe\u{308}".parse::<PersonName>().expect("valid name");
        assert_eq!(decomposed.as_str(), "Zoë");
    }

    #[test]
    fn person_name_counts_characters_after_composition() {
        let longest = "a".repeat(64);
        assert!(longest.parse::<PersonName>().is_ok());
        // 128 characters before composition, 64 after.
        let decomposed = "e\u{301}".repeat(64);
        assert!(decomposed.parse::<PersonName>().is_ok());
    }

    #[test]
    fn person_name_rejects_invalid_input() {
        let too_long = "a".repeat(65);
        let invalid = [
            "",
            too_long.as_str(),
            "Alice\n",
            "Alice\tSmith",
            "Alice\u{a0}Smith",
            "\u{202e}ecilA",
            "Alice1",
            "   ",
            "-",
            "'",
            "\u{308}", // mark without a letter
            " Alice",
            "Alice ",
        ];
        for input in invalid {
            assert_eq!(
                input.parse::<PersonName>(),
                Err(InvalidPersonName),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn email_accepts_simple_addresses() {
        let longest = format!("{}@example.com", "é".repeat(242));
        let valid = [
            "alice@example.com",
            "alice+vaults@example.org",
            "élodie@exemple.ch",
            "a@b",
            longest.as_str(),
        ];
        for input in valid {
            assert!(input.parse::<Email>().is_ok(), "input {input:?}");
        }
    }

    #[test]
    fn email_is_composed_and_lowercase() {
        let email = "Zoe\u{308}@Example.COM"
            .parse::<Email>()
            .expect("valid email");
        assert_eq!(email.as_str(), "zoë@example.com");
    }

    #[test]
    fn email_rejects_invalid_input() {
        let too_long = format!("{}@example.com", "a".repeat(243));
        let invalid = [
            "",
            too_long.as_str(),
            "alice",
            "@example.com",
            "alice@",
            "alice@@example.com",
            "a@b@c",
            "alice @example.com",
            "alice\u{a0}@example.com",
            "alice@example.com\n",
        ];
        for input in invalid {
            assert_eq!(input.parse::<Email>(), Err(InvalidEmail), "input {input:?}");
        }
    }

    #[test]
    fn password_accepts_any_characters() {
        let longest = "é".repeat(64);
        let valid = [
            "fifteen chars!!",
            "correct horse battery staple",
            "pässwörd 🔑 pässwörd",
            longest.as_str(), // 64 characters, 128 bytes
        ];
        for input in valid {
            let password = Password::try_from(String::from(input)).expect("valid password");
            assert_eq!(password.expose_secret(), input);
        }
    }

    #[test]
    fn password_rejects_bad_lengths() {
        let invalid = [
            String::new(),
            String::from("password123"),
            String::from("Tr0ub4dor&3xyz"), // 14 characters
            "a".repeat(65),
        ];
        for input in invalid {
            assert!(Password::try_from(input).is_err());
        }
    }

    #[test]
    fn password_debug_hides_the_secret() {
        let password =
            Password::try_from(String::from("hunter2-hunter2-hunter2")).expect("valid password");
        assert_eq!(format!("{password:?}"), "Password(***)");
    }

    /// Checks a new password for a user whose details are in no dictionary, so zxcvbn only knows
    /// them through the user inputs.
    fn new_password(password: &str) -> Result<(), InvalidNewPassword> {
        let username = "zorvak".parse::<Username>().expect("valid username");
        let email = "zorvak@example.com".parse::<Email>().expect("valid email");
        let first_name = "Quillon".parse::<PersonName>().expect("valid name");
        let last_name = "Vexmorth".parse::<PersonName>().expect("valid name");
        check_new_password(
            &Password::try_from(String::from(password)).expect("valid password"),
            &username,
            &email,
            &first_name,
            &last_name,
        )
    }

    #[test]
    fn new_password_accepts_strong_passphrases() {
        let valid = ["correct horse battery staple", "vault-lamp-orbit-cactus"];
        for input in valid {
            assert_eq!(new_password(input), Ok(()), "input {input:?}");
        }
    }

    #[test]
    fn new_password_rejects_common_passwords() {
        let error = new_password("Somanypickles27").err();
        assert_eq!(error, Some(InvalidNewPassword::Common));
    }

    #[test]
    fn new_password_rejects_weak_passwords() {
        let error = new_password("alice2024!alice2024!").err();
        assert_eq!(error, Some(InvalidNewPassword::Weak));
    }

    /// A registration with the same made-up details as `new_password`.
    fn new_user(password: &str) -> Result<NewUser, InvalidNewPassword> {
        NewUser::new(
            "zorvak".parse::<Username>().expect("valid username"),
            "zorvak@example.com".parse::<Email>().expect("valid email"),
            "Quillon".parse::<PersonName>().expect("valid name"),
            "Vexmorth".parse::<PersonName>().expect("valid name"),
            Password::try_from(String::from(password)).expect("valid password"),
        )
    }

    #[test]
    fn new_user_keeps_the_checked_details() {
        let user = new_user("correct horse battery staple").expect("valid user");
        assert_eq!(user.username().as_str(), "zorvak");
        assert_eq!(user.email().as_str(), "zorvak@example.com");
        assert_eq!(user.first_name().as_str(), "Quillon");
        assert_eq!(user.last_name().as_str(), "Vexmorth");
        assert_eq!(
            user.password().expose_secret(),
            "correct horse battery staple"
        );
    }

    #[test]
    fn new_user_debug_hides_the_password() {
        let user = new_user("correct horse battery staple").expect("valid user");
        let printed = format!("{user:?}");
        assert!(printed.contains("Password(***)"));
        assert!(!printed.contains("horse"));
    }
}
