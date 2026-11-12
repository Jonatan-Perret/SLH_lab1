//! Policy decision point. The Cedar policy (`policy/secubank.cedar`) holds the rules.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Context, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, RestrictedExpression, Schema,
    ValidationMode, Validator,
};

use crate::auth::VerifiedIdentity;
use crate::dial_code::{self, DialCodeHash, DialCodePepper};
use crate::types::{AppRole, Classification, Clearance, DialCode, Ownership, Sub, UserInfo, Vault};

/// The Cedar schema.
const SCHEMA: &str = include_str!("../policy/secubank.cedarschema");

/// The Cedar policies.
const POLICIES: &str = include_str!("../policy/secubank.cedar");

/// Capability: the holder passed the officer check in `authorize`.
#[derive(Debug, PartialEq, Eq)]
pub struct Officer {
    sub: Sub,
}

/// Capability: the holder passed the client check in `authorize` and has exactly one clearance.
#[derive(Debug, PartialEq, Eq)]
pub struct Client {
    sub: Sub,
    clearance: Clearance,
}

/// The principal that `authorize` gives for an identity.
#[derive(Debug, PartialEq, Eq)]
pub enum Principal {
    Officer(Officer),
    Client(Client),
}

/// Identity refused by `authorize`.
#[derive(Debug, PartialEq, Eq)]
pub struct Deny;

impl Officer {
    /// The Keycloak user ID.
    pub fn sub(&self) -> &Sub {
        &self.sub
    }

    /// Builds an officer without `authorize`, to test `decide`.
    #[cfg(test)]
    pub(crate) fn for_tests(sub: Sub) -> Self {
        Officer { sub }
    }
}

impl Client {
    /// The Keycloak user ID.
    pub fn sub(&self) -> &Sub {
        &self.sub
    }

    /// The only clearance.
    pub fn clearance(&self) -> Clearance {
        self.clearance
    }

    /// Builds a client without `authorize`, to test `decide`.
    #[cfg(test)]
    pub(crate) fn for_tests(sub: Sub, clearance: Clearance) -> Self {
        Client { sub, clearance }
    }
}

/// What a principal asks for. Each request carries the capability it needs.
#[derive(Debug)]
pub enum Request {
    /// First assignment or transfer of a vault. `new_owner` is `None` when the lookup found no
    /// single user.
    AssignOwner {
        by: Officer,
        new_owner: Option<UserInfo>,
    },
    /// Setting the first dial code of a vault, as a hash. The code itself is never stored.
    SetDialCode { by: Client, hash: DialCodeHash },
    /// Opening a vault with the dial code typed by the client.
    Open { by: Client, code: DialCode },
}

/// The change the store applies when a request is allowed.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Effect {
    /// Writes the new owner and removes the dial code hash.
    SetOwner(Sub),
    /// Writes the dial code hash.
    SetDialCode(DialCodeHash),
    /// Actuates the lock.
    OpenLock,
}

/// The outcome of `decide`.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Decision {
    Allow(Effect),
    Deny,
}

/// The parsed schema and the validated policies.
pub struct Engine {
    schema: Schema,
    policies: PolicySet,
}

/// Reason why the policy engine fails to load.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid Cedar schema: {0}")]
    Schema(String),
    #[error("invalid Cedar policies: {0}")]
    Policies(String),
    #[error("Cedar policies fail validation: {0}")]
    Validation(String),
}

impl Engine {
    /// Parses the schema and the policies, then validates the policies against the schema. Any
    /// warning is an error, so a broken policy stops the terminal at startup.
    pub fn load() -> Result<Engine, PolicyError> {
        let (schema, mut warnings) = Schema::from_cedarschema_str(SCHEMA)
            .map_err(|error| PolicyError::Schema(error.to_string()))?;
        if let Some(warning) = warnings.next() {
            return Err(PolicyError::Schema(warning.to_string()));
        }
        let policies = POLICIES
            .parse::<PolicySet>()
            .map_err(|error| PolicyError::Policies(error.to_string()))?;
        // Level 1 means policies can only read attributes of the principal, the resource and the
        // context entities.
        let result = Validator::new(schema.clone()).validate_with_level(
            &policies,
            ValidationMode::Strict,
            1,
        );
        if !result.validation_passed_without_warnings() {
            return Err(PolicyError::Validation(result.to_string()));
        }
        Ok(Engine { schema, policies })
    }
}

/// Builds a Cedar entity UID (`Type::"id"`), or `None` if the type name is invalid.
///
/// * `type_name`: The entity type, e.g. `User`, `Vault`, `Role` or `Action`.
/// * `id`: The entity ID, e.g. a Keycloak user ID, a vault ID or a role name.
fn uid(type_name: &str, id: &str) -> Option<EntityUid> {
    let type_name = EntityTypeName::from_str(type_name).ok()?;
    Some(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

/// Builds the UID of the Cedar parent entity of an app role: a `Role` or a `Clearance`.
///
/// * `role`: The app role.
fn role_uid(role: AppRole) -> Option<EntityUid> {
    match role {
        AppRole::Client => uid("Role", "client"),
        AppRole::Officer => uid("Role", "bank-security-officer"),
        AppRole::Clearance(Clearance::Standard) => uid("Clearance", "standard"),
        AppRole::Clearance(Clearance::Elite) => uid("Clearance", "elite"),
        AppRole::Clearance(Clearance::Premium) => uid("Clearance", "premium"),
    }
}

/// Builds the UID of the Cedar `Classification` entity of a vault classification.
///
/// * `classification`: The vault classification.
fn classification_uid(classification: Classification) -> Option<EntityUid> {
    match classification {
        Classification::Standard => uid("Classification", "standard"),
        Classification::Reinforced => uid("Classification", "reinforced"),
        Classification::HighSecurity => uid("Classification", "high-security"),
    }
}

/// Builds a `User` entity whose parents are its roles and clearances, or `None` if a UID can't be
/// built.
///
/// * `sub`: The Keycloak user ID, used as the entity ID.
/// * `roles`: The app roles, which become the parent `Role` and `Clearance` entities.
/// * `enabled`: Whether the Keycloak account is enabled, stored as the `enabled` attribute. A
///   disabled user still gets an entity, with `enabled` set to false.
fn user_entity(sub: &Sub, roles: &[AppRole], enabled: bool) -> Option<Entity> {
    let mut parents = HashSet::new();
    for role in roles {
        parents.insert(role_uid(*role)?);
    }
    let attrs = HashMap::from([(
        String::from("enabled"),
        RestrictedExpression::new_bool(enabled),
    )]);
    Entity::new(uid("User", sub.as_str())?, attrs, parents).ok()
}

/// Builds a `Vault` entity with its `classification`, its `owner` (only when owned) and
/// `has_dial_code`, or `None` if a UID can't be built. The hash itself never goes to Cedar.
///
/// * `vault`: The vault to describe.
fn vault_entity(vault: &Vault) -> Option<Entity> {
    let mut attrs = HashMap::from([(
        String::from("classification"),
        RestrictedExpression::new_entity_uid(classification_uid(vault.classification)?),
    )]);
    let has_dial_code = match &vault.ownership {
        Ownership::Unowned => false,
        Ownership::Owned {
            owner,
            dial_code_hash,
        } => {
            let owner = RestrictedExpression::new_entity_uid(uid("User", owner.as_str())?);
            attrs.insert(String::from("owner"), owner);
            dial_code_hash.is_some()
        }
    };
    attrs.insert(
        String::from("has_dial_code"),
        RestrictedExpression::new_bool(has_dial_code),
    );
    Entity::new(uid("Vault", vault.id.as_str())?, attrs, HashSet::new()).ok()
}

/// Asks Cedar whether `principal` may do `action` on `resource`. Gives `true` only if the request
/// is allowed, and `false` in every other case.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `principal`: The UID of the requesting `User`.
/// * `action`: The ID of the Cedar action (`Open` stands for `Action::"Open"`): `ActAsOfficer`,
///   `ActAsClient`, `AssignOwner`, `SetDialCode` or `Open`.
/// * `resource`: The UID of the target: the `Terminal` for `ActAsOfficer` and `ActAsClient`, a
///   `Vault` for the other actions.
/// * `context`: The request context: `new_owner` for `AssignOwner`, empty for the other actions.
/// * `entities`: The entities the policies may read: the principal, the vault if any, and the new
///   owner for `AssignOwner` (unless they are the principal).
fn is_allowed(
    engine: &Engine,
    principal: EntityUid,
    action: &str,
    resource: EntityUid,
    context: Context,
    entities: Vec<Entity>,
) -> bool {
    todo!()
}

/// Maps a verified identity to a principal by asking Cedar for `ActAsOfficer` and `ActAsClient` on
/// the terminal. Gives an `Officer` when only the first is allowed, a `Client` when only the second
/// is allowed and the identity has exactly one clearance, and `Deny` otherwise.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `identity`: The verified identity from the token, with its `sub` and roles.
pub fn authorize(engine: &Engine, identity: &VerifiedIdentity) -> Result<Principal, Deny> {
    let as_officer = can_act_as(engine, identity, "ActAsOfficer");
    let as_client = can_act_as(engine, identity, "ActAsClient");
    let sub = identity.sub().clone();
    match (as_officer, as_client) {
        (true, false) => Ok(Principal::Officer(Officer { sub })),
        // Cedar already refuses zero or several clearances.
        (false, true) => match identity.single_clearance() {
            Some(clearance) => Ok(Principal::Client(Client { sub, clearance })),
            None => Err(Deny),
        },
        _ => Err(Deny),
    }
}

/// Consults Cedar to check whether the identity may act as an officer or as a client at the
/// terminal.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `identity`: The verified identity from the token, with its `sub` and roles.
/// * `action`: `ActAsOfficer` or `ActAsClient`.
fn can_act_as(engine: &Engine, identity: &VerifiedIdentity, action: &str) -> bool {
    // Keycloak only issues tokens to enabled accounts.
    let Some(user) = user_entity(identity.sub(), identity.roles(), true) else {
        return false;
    };
    let (Some(principal), Some(terminal)) = (
        uid("User", identity.sub().as_str()),
        uid("Terminal", "vault-room"),
    ) else {
        return false;
    };
    is_allowed(
        engine,
        principal,
        action,
        terminal,
        Context::empty(),
        vec![user],
    )
}

/// Decides on a request for a vault. A missing vault (`None`) is denied.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `request`: The request to decide on, with the capability of its principal.
/// * `vault`: The target vault, or `None` if it is unknown or the vault file is broken.
/// * `pepper`: The dial code pepper, used only to verify the code of an `Open`.
pub fn decide(
    engine: &Engine,
    request: &Request,
    vault: Option<&Vault>,
    pepper: &DialCodePepper,
) -> Decision {
    match request {
        Request::AssignOwner { by, new_owner } => {
            assign_owner(engine, by, new_owner.as_ref(), vault)
        }
        Request::SetDialCode { by, hash } => set_dial_code(engine, by, hash, vault),
        Request::Open { by, code } => open(engine, by, code, vault, pepper),
    }
}

/// Decides on `AssignOwner`. When allowed, the effect sets the new owner, which also removes the
/// dial code hash.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `by`: The officer making the request.
/// * `new_owner`: The user that `find_user` found, or `None` if the lookup found no single user. A
///   disabled user or a user without `client` is still `Some` and left to Cedar.
/// * `vault`: The target vault, or `None` if it is unknown or the vault file is broken.
fn assign_owner(
    engine: &Engine,
    by: &Officer,
    new_owner: Option<&UserInfo>,
    vault: Option<&Vault>,
) -> Decision {
    let (Some(vault), Some(new_owner)) = (vault, new_owner) else {
        return Decision::Deny;
    };
    if can_assign(engine, by, new_owner, vault) == Some(true) {
        Decision::Allow(Effect::SetOwner(new_owner.sub.clone()))
    } else {
        Decision::Deny
    }
}

/// Consults Cedar to check whether an officer may give a vault to a new owner, or `None` if an
/// entity or the context can't be built.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `by`: The officer making the request.
/// * `new_owner`: The new owner, sent as an entity and as the `new_owner` context attribute.
/// * `vault`: The target vault.
fn can_assign(engine: &Engine, by: &Officer, new_owner: &UserInfo, vault: &Vault) -> Option<bool> {
    let mut entities = vec![
        user_entity(by.sub(), &[AppRole::Officer], true)?,
        vault_entity(vault)?,
    ];
    if &new_owner.sub != by.sub() {
        entities.push(user_entity(
            &new_owner.sub,
            &new_owner.roles,
            new_owner.enabled,
        )?);
    }
    let new_owner_uid = RestrictedExpression::new_entity_uid(uid("User", new_owner.sub.as_str())?);
    let context = Context::from_pairs([(String::from("new_owner"), new_owner_uid)]).ok()?;
    Some(is_allowed(
        engine,
        uid("User", by.sub().as_str())?,
        "AssignOwner",
        uid("Vault", vault.id.as_str())?,
        context,
        entities,
    ))
}

/// Decides on `SetDialCode`. When allowed, the effect writes the new hash.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `by`: The client making the request.
/// * `hash`: The hash of the new dial code. Cedar never sees it.
/// * `vault`: The target vault, or `None` if it is unknown or the vault file is broken.
fn set_dial_code(
    engine: &Engine,
    by: &Client,
    hash: &DialCodeHash,
    vault: Option<&Vault>,
) -> Decision {
    let Some(vault) = vault else {
        return Decision::Deny;
    };
    if client_can(engine, by, "SetDialCode", vault) == Some(true) {
        Decision::Allow(Effect::SetDialCode(hash.clone()))
    } else {
        Decision::Deny
    }
}

/// Consults Cedar to check whether a client may do `action` on a vault, or `None` if an entity
/// can't be built.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `by`: The client making the request.
/// * `action`: `SetDialCode` or `Open`.
/// * `vault`: The target vault.
fn client_can(engine: &Engine, by: &Client, action: &str, vault: &Vault) -> Option<bool> {
    // The capability guarantees `client` and the single clearance, and Keycloak only issues tokens
    // to enabled accounts.
    let roles = [AppRole::Client, AppRole::Clearance(by.clearance())];
    let entities = vec![user_entity(by.sub(), &roles, true)?, vault_entity(vault)?];
    Some(is_allowed(
        engine,
        uid("User", by.sub().as_str())?,
        action,
        uid("Vault", vault.id.as_str())?,
        Context::empty(),
        entities,
    ))
}

/// Decides on `Open`. Always runs exactly one Argon2 verification so the timing doesn't reveal the
/// ownership, the clearance or whether a code is set: against the stored hash when Cedar allows the
/// client to try a code, and against `DUMMY_HASH` (always a mismatch) otherwise.
///
/// * `engine`: The Cedar engine with the schema and policies.
/// * `by`: The client making the request.
/// * `code`: The dial code typed by the client.
/// * `vault`: The target vault, or `None` if it is unknown or the vault file is broken.
/// * `pepper`: The dial code pepper, used to verify the code.
fn open(
    engine: &Engine,
    by: &Client,
    code: &DialCode,
    vault: Option<&Vault>,
    pepper: &DialCodePepper,
) -> Decision {
    // Use the real hash only when Cedar allows trying a code, otherwise use `None` so `verify` runs
    // on a dummy hash.
    let stored_hash = if let Some(vault) = vault
        && client_can(engine, by, "Open", vault) == Some(true)
        && let Ownership::Owned { dial_code_hash, .. } = &vault.ownership
    {
        dial_code_hash.as_ref()
    } else {
        None
    };
    if dial_code::verify(code, stored_hash, pepper) {
        Decision::Allow(Effect::OpenLock)
    } else {
        Decision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Classification, VaultId};

    const SUB: &str = "0b8c2a4e-5f1d-4c3a-9e7b-2d6f8a1c3e5b";

    fn sub() -> Sub {
        SUB.parse::<Sub>().expect("valid sub")
    }

    /// The engine with the shipped policy.
    fn engine() -> Engine {
        Engine::load().expect("shipped policy loads")
    }

    /// An identity with these roles, as `verify` would build it.
    fn identity(roles: Vec<AppRole>) -> VerifiedIdentity {
        VerifiedIdentity::for_tests(sub(), roles)
    }

    #[test]
    fn no_role_is_denied() {
        assert_eq!(authorize(&engine(), &identity(vec![])), Err(Deny));
    }

    #[test]
    fn client_without_clearance_is_denied() {
        assert_eq!(
            authorize(&engine(), &identity(vec![AppRole::Client])),
            Err(Deny)
        );
    }

    #[test]
    fn client_with_one_clearance_is_a_client() {
        for clearance in [Clearance::Standard, Clearance::Elite, Clearance::Premium] {
            let id = identity(vec![AppRole::Client, AppRole::Clearance(clearance)]);
            let expected = Principal::Client(Client::for_tests(sub(), clearance));
            assert_eq!(authorize(&engine(), &id), Ok(expected));
        }
    }

    #[test]
    fn role_order_does_not_matter() {
        let id = identity(vec![AppRole::Clearance(Clearance::Elite), AppRole::Client]);
        let expected = Principal::Client(Client::for_tests(sub(), Clearance::Elite));
        assert_eq!(authorize(&engine(), &id), Ok(expected));
    }

    #[test]
    fn officer_alone_is_an_officer() {
        let expected = Principal::Officer(Officer::for_tests(sub()));
        assert_eq!(
            authorize(&engine(), &identity(vec![AppRole::Officer])),
            Ok(expected)
        );
    }

    // `decide` tests. Alice and Bob are clients, the officer assigns vaults.
    const ALICE: &str = "00000000-0000-4000-8000-00000000000a";
    const BOB: &str = "00000000-0000-4000-8000-00000000000b";
    const OFFICER: &str = "00000000-0000-4000-8000-00000000000f";
    const CODE: &str = "4L95-3R12-2L20-1R33";
    const WRONG_CODE: &str = "4L95-3R12-2L20-1R34";

    fn sub_of(id: &str) -> Sub {
        id.parse::<Sub>().expect("valid sub")
    }

    fn pepper() -> DialCodePepper {
        // Base64 of `test-pepper-for-the-policy-tests`.
        "dGVzdC1wZXBwZXItZm9yLXRoZS1wb2xpY3ktdGVzdHM="
            .parse::<DialCodePepper>()
            .expect("valid pepper")
    }

    fn code(s: &str) -> DialCode {
        s.parse().expect("valid code")
    }

    /// The stored hash of `CODE`, as `hash` would write it.
    fn code_hash() -> DialCodeHash {
        dial_code::hash(&code(CODE), &pepper()).expect("hashing works")
    }

    fn vault(classification: Classification, ownership: Ownership) -> Vault {
        Vault {
            id: "V-001".parse::<VaultId>().expect("valid id"),
            classification,
            ownership,
        }
    }

    fn owned_by(id: &str, dial_code_hash: Option<DialCodeHash>) -> Ownership {
        Ownership::Owned {
            owner: sub_of(id),
            dial_code_hash,
        }
    }

    /// A user as `find_user` returns it.
    fn user(id: &str, enabled: bool, roles: Vec<AppRole>) -> UserInfo {
        UserInfo {
            sub: sub_of(id),
            enabled,
            roles,
        }
    }

    fn client_roles() -> Vec<AppRole> {
        vec![AppRole::Client, AppRole::Clearance(Clearance::Standard)]
    }

    fn assign(new_owner: Option<UserInfo>, vault: Option<&Vault>) -> Decision {
        let request = Request::AssignOwner {
            by: Officer::for_tests(sub_of(OFFICER)),
            new_owner,
        };
        decide(&engine(), &request, vault, &pepper())
    }

    fn set_code(clearance: Clearance, vault: Option<&Vault>) -> Decision {
        let request = Request::SetDialCode {
            by: Client::for_tests(sub_of(ALICE), clearance),
            hash: code_hash(),
        };
        decide(&engine(), &request, vault, &pepper())
    }

    fn open_with(clearance: Clearance, typed: &str, vault: Option<&Vault>) -> Decision {
        let request = Request::Open {
            by: Client::for_tests(sub_of(ALICE), clearance),
            code: code(typed),
        };
        decide(&engine(), &request, vault, &pepper())
    }

    #[test]
    fn assign_owner_of_an_unowned_vault_is_allowed() {
        let unowned = vault(Classification::Standard, Ownership::Unowned);
        let bob = user(BOB, true, client_roles());
        let expected = Decision::Allow(Effect::SetOwner(sub_of(BOB)));
        assert_eq!(assign(Some(bob), Some(&unowned)), expected);
    }

    #[test]
    fn assign_owner_transfers_an_owned_vault() {
        let alices = vault(Classification::Standard, owned_by(ALICE, Some(code_hash())));
        let bob = user(BOB, true, client_roles());
        let expected = Decision::Allow(Effect::SetOwner(sub_of(BOB)));
        assert_eq!(assign(Some(bob), Some(&alices)), expected);
    }

    #[test]
    fn assign_owner_of_a_missing_vault_is_denied() {
        let bob = user(BOB, true, client_roles());
        assert_eq!(assign(Some(bob), None), Decision::Deny);
    }

    #[test]
    fn set_dial_code_on_own_vault_without_code_is_allowed() {
        let alices = vault(Classification::Standard, owned_by(ALICE, None));
        let decision = set_code(Clearance::Standard, Some(&alices));
        assert!(matches!(decision, Decision::Allow(Effect::SetDialCode(_))));
    }

    #[test]
    fn set_dial_code_is_denied_to_others() {
        let bobs = vault(Classification::Standard, owned_by(BOB, None));
        let invalid = [Some(&bobs), None];
        for (case, vault) in invalid.into_iter().enumerate() {
            assert_eq!(
                set_code(Clearance::Premium, vault),
                Decision::Deny,
                "case {case}"
            );
        }
    }

    #[test]
    fn open_own_vault_with_the_right_code_is_allowed() {
        let cases = [
            (Clearance::Standard, Classification::Standard),
            (Clearance::Elite, Classification::Reinforced),
            (Clearance::Premium, Classification::HighSecurity),
        ];
        for (clearance, classification) in cases {
            let alices = vault(classification, owned_by(ALICE, Some(code_hash())));
            let decision = open_with(clearance, CODE, Some(&alices));
            assert_eq!(decision, Decision::Allow(Effect::OpenLock), "{clearance:?}");
        }
    }

    #[test]
    fn open_with_a_wrong_code_is_denied() {
        let alices = vault(Classification::Standard, owned_by(ALICE, Some(code_hash())));
        let decision = open_with(Clearance::Standard, WRONG_CODE, Some(&alices));
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn open_with_a_clearance_too_low_is_denied() {
        let high = vault(
            Classification::HighSecurity,
            owned_by(ALICE, Some(code_hash())),
        );
        let decision = open_with(Clearance::Standard, CODE, Some(&high));
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn open_is_denied_to_others() {
        let bobs = vault(Classification::Standard, owned_by(BOB, Some(code_hash())));
        let invalid = [Some(&bobs), None];
        for (case, vault) in invalid.into_iter().enumerate() {
            let decision = open_with(Clearance::Premium, CODE, vault);
            assert_eq!(decision, Decision::Deny, "case {case}");
        }
    }

    #[test]
    fn shipped_policy_loads() {
        let result = Engine::load();
        assert!(result.is_ok(), "{:?}", result.err());
    }

    /// Checks whether Alice (a Standard client) may try to open her Standard vault under the
    /// policies of `engine`.
    fn alice_can_open(engine: &Engine) -> bool {
        let roles = client_roles();
        let alices = vault(Classification::Standard, owned_by(ALICE, Some(code_hash())));
        let entities = vec![
            user_entity(&sub_of(ALICE), &roles, true).expect("valid user"),
            vault_entity(&alices).expect("valid vault"),
        ];
        let principal = uid("User", ALICE).expect("valid uid");
        let resource = uid("Vault", "V-001").expect("valid uid");
        is_allowed(
            engine,
            principal,
            "Open",
            resource,
            Context::empty(),
            entities,
        )
    }

    /// An engine with the shipped schema and the given policies.
    fn engine_with(policies: &str) -> Engine {
        let shipped = Engine::load().expect("shipped policy loads");
        let policies = policies.parse::<PolicySet>().expect("policies parse");
        Engine {
            schema: shipped.schema,
            policies,
        }
    }

    #[test]
    fn shipped_policy_allows_the_owner_to_try() {
        assert!(alice_can_open(
            &Engine::load().expect("shipped policy loads")
        ));
    }

    #[test]
    fn empty_policy_set_denies() {
        assert!(!alice_can_open(&engine_with("")));
    }

    /// Checks that the shipped policy gives the same result as `covers` for every pair of labels.
    /// Alice owns the vault and a code is set, so only the labels change.
    #[test]
    fn no_read_up_matches_covers() {
        let engine = engine();
        let hash = code_hash();
        let clearances = [Clearance::Standard, Clearance::Elite, Clearance::Premium];
        let classifications = [
            Classification::Standard,
            Classification::Reinforced,
            Classification::HighSecurity,
        ];
        for clearance in clearances {
            for classification in classifications {
                let alice = Client::for_tests(sub_of(ALICE), clearance);
                let alices = vault(classification, owned_by(ALICE, Some(hash.clone())));
                let allowed = client_can(&engine, &alice, "Open", &alices);
                let expected = Some(clearance.covers(classification));
                assert_eq!(allowed, expected, "{clearance:?} {classification:?}");
            }
        }
    }

    /// An engine that allows everything, so only the schema can refuse a request.
    fn permit_all() -> Engine {
        engine_with("permit (principal, action, resource);")
    }

    fn terminal() -> EntityUid {
        uid("Terminal", "vault-room").expect("valid uid")
    }

    #[test]
    fn permit_all_allows_a_valid_request() {
        let officer = user_entity(&sub_of(OFFICER), &[AppRole::Officer], true).expect("valid user");
        let principal = uid("User", OFFICER).expect("valid uid");
        let context = Context::empty();
        let allowed = is_allowed(
            &permit_all(),
            principal,
            "ActAsOfficer",
            terminal(),
            context,
            vec![officer],
        );
        assert!(allowed);
    }
}
