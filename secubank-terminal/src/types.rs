//! Domain types: dial codes, identities, form inputs, security labels and vaults.

mod dial;
mod identity;
mod input;
mod labels;
mod vault;

pub use dial::DialCode;
pub use identity::{AppRole, Sub, UserInfo};
pub use input::{Email, NewUser, Password, PersonName, Username};
pub use labels::{Classification, Clearance};
pub use vault::{InvalidVault, Ownership, Vault, VaultId};
