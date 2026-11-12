//! Reads and writes `vaults.toml`. Every access checks the whole file.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::policy::Effect;
use crate::types::{InvalidVault, Vault, VaultId};

/// A `[[vault]]` entry as written in `vaults.toml`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawVault {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dial_code_hash: Option<String>,
}

/// The full vault file.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    vault: Vec<RawVault>,
}

/// Reason why the vault file can't be read or written.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("cannot read or write the vault file")]
    Io(#[from] std::io::Error),
    #[error("the vault file is not a valid list of vaults")]
    Format,
    #[error("two vaults have the same id")]
    DuplicateId,
    #[error("no vault with this id")]
    UnknownVault,
    #[error("invalid vault entry")]
    InvalidVault(#[from] InvalidVault),
}

/// Reads and checks the whole vault file. Every entry must parse into a `Vault` and every ID must
/// be unique.
///
/// * `path`: The path to `vaults.toml`.
pub fn load(path: &Path) -> Result<Vec<Vault>, StoreError> {
    check(&read(path)?)
}

/// Reads the vault file as TOML, without checking the entries.
///
/// * `path`: The path to `vaults.toml`.
fn read(path: &Path) -> Result<VaultFile, StoreError> {
    let text = fs::read_to_string(path)?;
    toml::from_str(&text).map_err(|_| StoreError::Format)
}

/// Parses every entry of a vault file into a `Vault` and checks that the IDs are unique.
///
/// * `file`: The vault file to check.
fn check(file: &VaultFile) -> Result<Vec<Vault>, StoreError> {
    let mut ids = HashSet::new();
    let mut vaults = Vec::new();
    for raw in &file.vault {
        let vault = Vault::try_from(raw.clone())?;
        if !ids.insert(String::from(vault.id.as_str())) {
            return Err(StoreError::DuplicateId);
        }
        vaults.push(vault);
    }
    Ok(vaults)
}

/// Finds the vault with this ID, or `None` when there is none. Still checks the whole file.
///
/// * `path`: The path to `vaults.toml`.
/// * `id`: The vault to find.
pub fn find(path: &Path, id: &VaultId) -> Result<Option<Vault>, StoreError> {
    let vaults = load(path)?;
    Ok(vaults.into_iter().find(|vault| &vault.id == id))
}

/// Applies an allowed effect to the vault file. The file is checked before and after the change,
/// then replaced through a temporary file and a rename.
///
/// * `path`: The path to `vaults.toml`.
/// * `id`: The vault to change.
/// * `effect`: The effect to apply. `SetOwner` writes the new owner and removes the dial code hash
///   in the same write so a new owner never gets the old code, `SetDialCode` writes the new hash,
///   and `OpenLock` writes nothing.
pub fn apply(path: &Path, id: &VaultId, effect: &Effect) -> Result<(), StoreError> {
    if let Effect::OpenLock = effect {
        return Ok(());
    }
    let mut file = read(path)?;
    check(&file)?;
    let raw = file
        .vault
        .iter_mut()
        .find(|raw| raw.id == id.as_str())
        .ok_or(StoreError::UnknownVault)?;
    match effect {
        Effect::SetOwner(owner) => {
            raw.owner = Some(String::from(owner.as_str()));
            raw.dial_code_hash = None;
        }
        Effect::SetDialCode(hash) => raw.dial_code_hash = Some(String::from(hash.as_str())),
        Effect::OpenLock => {}
    }
    // The changed file must still be valid before it is written.
    check(&file)?;
    let new_text = toml::to_string_pretty(&file).map_err(|_| StoreError::Format)?;
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, new_text)?;
    fs::set_permissions(&tmp, fs::metadata(path)?.permissions())?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;
    use crate::dial_code::DialCodeHash;
    use crate::types::{Classification, Ownership, Sub};

    const OWNER: &str = "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b";
    const NEW_OWNER: &str = "1c9d3b5f-6a2e-4d4b-8f8c-3e7a9b2d4f6c";

    // Any well-formed Argon2id PHC string.
    const HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZhIa9tE8DQLa/cXUQefZWg$nSboUi05AKT3WqD7nES7GkiK3S1tTZRpbtot1q7tAU4";

    /// V-001 owned with a dial code, V-002 unowned and without classification.
    fn owned_file() -> String {
        format!(
            "[[vault]]\nid = \"V-001\"\nclassification = \"reinforced\"\nowner = \"{OWNER}\"\ndial_code_hash = \"{HASH}\"\n\n[[vault]]\nid = \"V-002\"\n"
        )
    }

    /// Writes text as `vaults.toml` in a temporary directory.
    fn vault_file(text: &str) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("vaults.toml");
        fs::write(&path, text).expect("write the vault file");
        (dir, path)
    }

    fn v001() -> VaultId {
        "V-001".parse::<VaultId>().expect("valid id")
    }

    fn sub_of(id: &str) -> Sub {
        id.parse::<Sub>().expect("valid sub")
    }

    fn hash() -> DialCodeHash {
        HASH.parse::<DialCodeHash>().expect("valid hash")
    }

    #[test]
    fn raw_vault_reads_a_full_entry() {
        let raw: RawVault = toml::from_str(
            r#"
            id = "V-001"
            classification = "reinforced"
            owner = "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b"
            dial_code_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"
            "#,
        )
        .expect("valid entry");
        assert_eq!(raw.id, "V-001");
        assert_eq!(raw.classification.as_deref(), Some("reinforced"));
        assert!(raw.owner.is_some());
        assert!(raw.dial_code_hash.is_some());
    }

    #[test]
    fn raw_vault_optional_fields_default_to_none() {
        let raw: RawVault = toml::from_str(r#"id = "V-001""#).expect("valid entry");
        assert!(raw.classification.is_none());
        assert!(raw.owner.is_none());
        assert!(raw.dial_code_hash.is_none());
    }

    #[test]
    fn raw_vault_rejects_bad_entries() {
        let invalid = [
            "",
            "id = \"V-001\"\nclearance = \"premium\"",
            "id = \"V-001\"\nonwer = \"x\"",
            "id = 1",
            "id = \"V-001\"\nid = \"V-002\"",
        ];
        for input in invalid {
            assert!(
                toml::from_str::<RawVault>(input).is_err(),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn load_reads_the_example_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vaults.example.toml");
        let vaults = load(&path).expect("the example file is valid");
        let ids: Vec<&str> = vaults.iter().map(|vault| vault.id.as_str()).collect();
        assert_eq!(ids, ["V-001", "V-002", "V-003", "V-004"]);
    }

    #[test]
    fn find_returns_the_vault_or_none() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("vaults.example.toml");
        let id = "V-003".parse::<VaultId>().expect("valid id");
        let vault = find(&path, &id).expect("valid file").expect("V-003 exists");
        assert_eq!(vault.classification, Classification::HighSecurity);
        let missing = "V-999".parse::<VaultId>().expect("valid id");
        assert!(find(&path, &missing).expect("valid file").is_none());
    }

    #[test]
    fn load_rejects_files_that_are_not_a_list_of_vaults() {
        let invalid = [
            "",                                                   // no vault
            "[[vault",                                            // not TOML
            "[[vault]]\nid = \"V-001\"\nclearance = \"premium\"", // unknown field
            "admin = true\n\n[[vault]]\nid = \"V-001\"",          // unknown top-level key
        ];
        for text in invalid {
            let (_dir, path) = vault_file(text);
            let result = load(&path);
            assert!(matches!(result, Err(StoreError::Format)), "text {text:?}");
        }
    }

    #[test]
    fn load_rejects_a_duplicate_id() {
        let (_dir, path) = vault_file("[[vault]]\nid = \"V-001\"\n\n[[vault]]\nid = \"V-001\"\n");
        assert!(matches!(load(&path), Err(StoreError::DuplicateId)));
    }

    #[test]
    fn load_rejects_invalid_entries() {
        let invalid = [
            // Hash without owner, unknown classification and bad ID.
            format!("[[vault]]\nid = \"V-001\"\ndial_code_hash = \"{HASH}\""),
            String::from("[[vault]]\nid = \"V-001\"\nclassification = \"secret\""),
            String::from("[[vault]]\nid = \"V-1\""),
        ];
        for text in &invalid {
            let (_dir, path) = vault_file(text);
            let result = load(&path);
            assert!(
                matches!(result, Err(StoreError::InvalidVault(_))),
                "text {text:?}"
            );
        }
    }

    #[test]
    fn load_rejects_a_missing_file() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let result = load(&dir.path().join("vaults.toml"));
        assert!(matches!(result, Err(StoreError::Io(_))));
    }

    #[test]
    fn apply_set_owner_clears_the_dial_code() {
        let (_dir, path) = vault_file(&owned_file());
        apply(&path, &v001(), &Effect::SetOwner(sub_of(NEW_OWNER))).expect("applied");
        let vault = find(&path, &v001()).expect("valid file").expect("V-001");
        let expected = Ownership::Owned {
            owner: sub_of(NEW_OWNER),
            dial_code_hash: None,
        };
        assert_eq!(vault.ownership, expected);
    }

    #[test]
    fn apply_set_dial_code_writes_the_hash() {
        let text = format!("[[vault]]\nid = \"V-001\"\nowner = \"{OWNER}\"\n");
        let (_dir, path) = vault_file(&text);
        apply(&path, &v001(), &Effect::SetDialCode(hash())).expect("applied");
        let vault = find(&path, &v001()).expect("valid file").expect("V-001");
        let expected = Ownership::Owned {
            owner: sub_of(OWNER),
            dial_code_hash: Some(hash()),
        };
        assert_eq!(vault.ownership, expected);
    }

    #[test]
    fn apply_open_lock_writes_nothing() {
        // Any rewrite would drop the admin's comment.
        let text = format!("# Admin notes.\n{}", owned_file());
        let (_dir, path) = vault_file(&text);
        apply(&path, &v001(), &Effect::OpenLock).expect("applied");
        assert_eq!(fs::read_to_string(&path).expect("read"), text);
    }

    #[test]
    fn apply_keeps_the_other_vaults_as_written() {
        let (dir, path) = vault_file(&owned_file());
        apply(&path, &v001(), &Effect::SetOwner(sub_of(NEW_OWNER))).expect("applied");
        let text = fs::read_to_string(&path).expect("read");
        // V-002 still has no classification line, and no temporary file is left.
        assert_eq!(text.matches("classification").count(), 1);
        assert!(!dir.path().join("vaults.toml.tmp").exists());
    }

    #[test]
    fn apply_leaves_a_broken_file_untouched() {
        let broken = [
            String::from("[[vault]]\nid = \"V-001\"\n\n[[vault]]\nid = \"V-001\"\n"),
            // `SetOwner` would repair this, so only the check before writing refuses it.
            format!("[[vault]]\nid = \"V-001\"\ndial_code_hash = \"{HASH}\"\n"),
        ];
        for text in &broken {
            let (_dir, path) = vault_file(text);
            let result = apply(&path, &v001(), &Effect::SetOwner(sub_of(OWNER)));
            assert!(result.is_err(), "text {text:?}");
            assert_eq!(fs::read_to_string(&path).expect("read"), *text);
        }
    }

    #[test]
    fn apply_never_writes_a_file_that_load_would_refuse() {
        // A code for an unowned vault (the admin removed the owner after `decide`).
        let text = "[[vault]]\nid = \"V-001\"\n";
        let (_dir, path) = vault_file(text);
        let result = apply(&path, &v001(), &Effect::SetDialCode(hash()));
        assert!(matches!(result, Err(StoreError::InvalidVault(_))));
        assert_eq!(fs::read_to_string(&path).expect("read"), text);
    }

    #[test]
    fn apply_to_an_unknown_vault_writes_nothing() {
        let (_dir, path) = vault_file(&owned_file());
        let v999 = "V-999".parse::<VaultId>().expect("valid id");
        let result = apply(&path, &v999, &Effect::SetOwner(sub_of(NEW_OWNER)));
        assert!(matches!(result, Err(StoreError::UnknownVault)));
        assert_eq!(fs::read_to_string(&path).expect("read"), owned_file());
    }
}
