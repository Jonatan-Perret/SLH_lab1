//! Password grant and token verification used to build identities.

use std::str::FromStr;

use jsonwebtoken::DecodingKey;

use crate::config::{Config, ConfigError};
use crate::http;
use crate::types::{AppRole, Clearance, Password, Sub, Username};

/// An identity that `verify` builds from a verified access token: the user's `sub` and app roles.
#[derive(Debug)]
pub struct VerifiedIdentity {
    sub: Sub,
    roles: Vec<AppRole>,
}

impl VerifiedIdentity {
    /// The Keycloak user ID.
    pub fn sub(&self) -> &Sub {
        &self.sub
    }

    /// The app roles, in token order.
    pub fn roles(&self) -> &[AppRole] {
        &self.roles
    }

    /// The clearance when the token has exactly one, `None` otherwise.
    pub fn single_clearance(&self) -> Option<Clearance> {
        let mut clearances = self.roles.iter().filter_map(|role| match role {
            AppRole::Clearance(clearance) => Some(*clearance),
            _ => None,
        });
        match (clearances.next(), clearances.next()) {
            (Some(clearance), None) => Some(clearance),
            _ => None,
        }
    }

    /// Builds an identity without a token, to test `authorize`.
    #[cfg(test)]
    pub(crate) fn for_tests(sub: Sub, roles: Vec<AppRole>) -> Self {
        VerifiedIdentity { sub, roles }
    }
}

/// The pinned realm signing key containing its `kid` and its RSA public key.
pub struct RealmKey {
    kid: String,
    key: DecodingKey,
}

impl RealmKey {
    /// Builds the key from the pinned values in the config. Fails with `ConfigError::Invalid` if
    /// the public key is not a valid RSA key.
    ///
    /// * `config`: The terminal configuration, for `KEYCLOAK_REALM_KID` and
    ///   `KEYCLOAK_REALM_PUBLIC_KEY`.
    pub fn from_config(config: &Config) -> Result<RealmKey, ConfigError> {
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            config.realm_public_key
        );
        let key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|_| ConfigError::Invalid(String::from("KEYCLOAK_REALM_PUBLIC_KEY")))?;
        Ok(RealmKey {
            kid: config.realm_kid.clone(),
            key,
        })
    }

    /// The pinned key ID.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The pinned public key.
    pub fn key(&self) -> &DecodingKey {
        &self.key
    }
}

/// Reason why a login fails. The user only ever sees a generic message.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Keycloak is unavailable")]
    Unavailable,
    #[error("login refused")]
    Refused,
    #[error("invalid token")]
    InvalidToken,
}

/// The field used from a Keycloak token response.
#[derive(serde::Deserialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
}

/// Runs a password grant on the public client and returns the raw access token, which the caller
/// verifies and then drops. Gives `AuthError::Refused` when Keycloak rejects the credentials and
/// `AuthError::Unavailable` on any other failure.
///
/// * `config`: The terminal configuration, for the Keycloak URL, the realm and the terminal client
///   ID.
/// * `username`: The username to log in with.
/// * `password`: The password to log in with.
pub fn password_grant(
    config: &Config,
    username: &Username,
    password: &Password,
) -> Result<String, AuthError> {
    let url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        config.keycloak_url, config.realm
    );
    let form = [
        ("grant_type", "password"),
        ("client_id", config.terminal_client_id.as_str()),
        ("username", username.as_str()),
        ("password", password.expose_secret()),
    ];

    let runtime = http::runtime().ok_or(AuthError::Unavailable)?;
    let client = http::client().ok_or(AuthError::Unavailable)?;
    runtime.block_on(async {
        let response = client
            .post(url)
            .form(&form)
            .send()
            .await
            .map_err(|_| AuthError::Unavailable)?;
        if !response.status().is_success() {
            return Err(AuthError::Refused);
        }
        let body: TokenResponse = response.json().await.map_err(|_| AuthError::Unavailable)?;
        Ok(body.access_token)
    })
}

/// The access token claims that `verify` reads.
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    azp: String,
    typ: String,
    realm_access: RealmAccess,
}

/// The `realm_access` claim, which holds the realm role names.
#[derive(serde::Deserialize)]
struct RealmAccess {
    roles: Vec<String>,
}

/// Verifies an access token from the Keycloak realm and builds the identity it carries. Any
/// failure gives `AuthError::InvalidToken`.
///
/// The roles are the names in `realm_access.roles` mapped with `AppRole::from_role_name`, in token
/// order. Names that are not app roles are dropped.
///
/// * `token`: The raw access token from `password_grant`.
/// * `realm_key`: The pinned realm key.
/// * `config`: The terminal configuration.
pub fn verify(
    token: &str,
    realm_key: &RealmKey,
    config: &Config,
) -> Result<VerifiedIdentity, AuthError> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[config.terminal_client_id.as_str()]);
    validation.set_issuer(&[format!("{}/realms/{}", config.keycloak_url, config.realm)]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "azp", "typ", "realm_access"]);
    jsonwebtoken::decode_header(token)
        .map_err(|_| AuthError::InvalidToken)
        .and_then(|header| {
            if header.kid.as_deref() != Some(realm_key.kid()) {
                Err(AuthError::InvalidToken)
            } else {
                Ok(())
            }
        })?;
    let claims = jsonwebtoken::decode::<Claims>(token, realm_key.key(), &validation)
        .map_err(|_| AuthError::InvalidToken)?
        .claims;
    if claims.typ != "Bearer" {
        return Err(AuthError::InvalidToken);
    }
    if claims.azp != config.terminal_client_id {
        return Err(AuthError::InvalidToken);
    }
    if claims.realm_access.roles.is_empty() {
        return Err(AuthError::InvalidToken);
    }

    let sub = Sub::from_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?;
    let roles = claims
        .realm_access
        .roles
        .into_iter()
        .filter_map(|name| AppRole::from_role_name(&name))
        .collect();
    Ok(VerifiedIdentity { sub, roles })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_key_loads_from_config() {
        let realm_key = RealmKey::from_config(&Config::for_tests()).expect("key");
        assert_eq!(realm_key.kid(), "test-kid");
    }

    #[test]
    fn broken_public_key_is_refused() {
        for bad in ["AAAA", "not base64!", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"] {
            let mut config = Config::for_tests();
            config.realm_public_key = String::from(bad);
            let error = RealmKey::from_config(&config).err();
            let expected = ConfigError::Invalid(String::from("KEYCLOAK_REALM_PUBLIC_KEY"));
            assert_eq!(error, Some(expected), "{bad}");
        }
    }

    // ----- verify -----
    //
    // The tokens below are signed with test RSA keys generated for these tests only. They have no
    // link to the realm.

    use crate::types::Clearance;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Private half of the key that `test_realm_key` pins.
    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+yb8oLuhuwwaG
ptrH+5Bc5B0gX2uMKt2Xrlm7W2V5OZjuFdD/37CwmIWsQkAmpAdMkhE5Gyl18naG
p8BMzRkXHhLsldsiNr/1KBG1DAKU0GwyTLgP6colf09Fi21Sk7Fr2BsKN3kaoJlY
XfXVVGYnq6i736kHpqm8uKpyKdmdSjiWepZWU89ltdlY6Mbp2QAAhrjdsF19criI
nKOQ5xA8LUIw7juayoAmuWGPiauNSwny+Ke6rtO2VXZJBuvlLAYvebCFvyGbCJw2
H+SC6SgtcqQX2pPLhqAKbryNtEt+6YKgHXE2tuE5XZ1ou3etbPuMC90ddzhYN9Rl
zdpN2DXfAgMBAAECggEAEIE4ebvxHJ/fgSePFqzTFM4hHOtUTPhqWhRZq+Ugtqd+
bN5TScdqrCRNsBS9IvqerQeX2NZaNFto2IZLkvlNOdw+q9vc7K1K1uUD/yMOWBxd
t84+QBYsCClmzK/eob2oJBm6YRxibCTHj0b1nOJjwfvOKY6UO1a2KV7aU+z95+bc
zwgUSJy8ZjGS9kB/z11RJ0YTRo37LJXN8y4B7MFr9K0sDw6e3kWK8wIIVDQO3jGF
GFOQqb7Z8dG/eaLKf2cW+CLBwH48UjksqwRcGMOIdd5h3nNWidc7nkBbVmXROzT0
L8CnCm1oq5W8bOixVG6TAzA7E16eWEA/xffsP1JmmQKBgQD5y6+61r8RFSWcIZC5
KaRZjMIx87njOGgWG9HwYzqtmu3XiXZtyWg2e0W8PERc2/kFYCAr+1LM8LaImvj7
IOhgdQ/CG+KOvWp59w3hqBrB5QsdhICdEXkxbod8dCO1tZ1bRd1Pg6vkd3fesXS3
GbPqumNC7b11JVWHo0UVCjtB2QKBgQDDht0KSq6vDk0iJ38neNtVwhOoL7yOsubk
wbpqzrL32+tf5a6UOp59kmRkIo4GRuuYhvxKeHebXZ9pbeyFROGUMsLjuSzMR91x
xrvlxSBjjjJkMs2UsIkK7rd5OwoWocHDCKopjXRfQssgVQQjtPAcXdPwJ6gqVg38
Mg42kRcqdwKBgQChEjFPRffQORWWVqJucyaRw8zYzvMXTCD52JiH7ERC+3rQF8hw
xIVZVCXEWgwu4HzzdWdpVNawZasd7OgNbsvIntM5dCejqQoGeULPNkmCq4F+WBli
roi6Ui41FuKL4f8EgslQ43Osj0iRJVZAVueHvQYSeyBGcHt1Sdda2M0bCQKBgHXA
RmXoTAMIrdMfzifLVOv0kTn8ZaXaf8rMEKQ6DvXN75Y1EEocc05UVzkmxjlphIC6
6j0/B2j9nP81P/eSX/eMCmpyHlR4Axh+ArKBYNwTyq0lG0GsfxuiX8QWliDDEZmP
Iksb8TVdWE8EZBXM5b1vlC9Q8qlsYce7rWuXPUhJAoGAUJkyOkYr/rKaC9kNrg/9
Vz7oRsdAw+l0OzpaE5ZI+BU/WJJKuWjSBmWIXZiNlypj97O3CNbIdyCh32lSsd/e
Cw4IuIWO1q2DCuzXOSCeGRbKsJlj99XBFgup51vpoK0lwgGVmB4nOohbFpGibzTi
zbYawTLkI6vY2ygxp2GcCoc=
-----END PRIVATE KEY-----
";

    /// Public half of `TEST_PRIVATE_KEY`.
    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvsm/KC7obsMGhqbax/uQ
XOQdIF9rjCrdl65Zu1tleTmY7hXQ/9+wsJiFrEJAJqQHTJIRORspdfJ2hqfATM0Z
Fx4S7JXbIja/9SgRtQwClNBsMky4D+nKJX9PRYttUpOxa9gbCjd5GqCZWF311VRm
J6uou9+pB6apvLiqcinZnUo4lnqWVlPPZbXZWOjG6dkAAIa43bBdfXK4iJyjkOcQ
PC1CMO47msqAJrlhj4mrjUsJ8vinuq7TtlV2SQbr5SwGL3mwhb8hmwicNh/kguko
LXKkF9qTy4agCm68jbRLfumCoB1xNrbhOV2daLt3rWz7jAvdHXc4WDfUZc3aTdg1
3wIDAQAB
-----END PUBLIC KEY-----
";

    /// An attacker's key, unknown to the terminal.
    const OTHER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9YtUx6pIr6bBM
IMDeepBuJ2zj2Lb4CXm+FObR/yRNoOiyYW1oTKoxzEajzRU+4Bs241k3DnvLUzzf
CI3Aor3S6zgkvL5EPqzADL46QOWHiNOANmZ9eXEOUcOIfHCvfTsPhu5MEVrYbQmW
/Nd8Y6emk5comuXVeUaRwyAzvPO1ALgYNLnqeGw2ellYH3NLlj4kV899nDmrOyYd
/YOsnkonpaLshozXagt6scnCh/Tc1LAEzdNNNx1QFrbPDVPKV6kl0zXNfdvjNYHQ
aDbiuQstklSM4K5kcf83QJYHqTORfxiFpb2vJZN9pgDR0rxYPvAJa4y+nqL8NIco
nnnbXXtBAgMBAAECggEAATTCfOQRBQj55TTGYzk33LYPYpmcYRSMUAY7UQBeqzoI
AZEX5frRu4R4HOR7H385zc9JY2E9stmeIIFa9gcbvcXNc6sNvh5W3lg1/JB5B/Yc
PorHe4X1eax15LGedtjdnt/29ocYZ9ORcS9BIbNaaPfawJQ/H88VwJz8xA/Op5oz
tNRgOTu84nySZaHSogkIUZGJRbzjt4Ad7fq/1cmAmiOu5Hd9QSbOeF+LUjtx6zd2
pdipZ/qWxmAWcTPbKNiIefO4vNsEKZ7iNPQivCswf26k3X+C6S/Gi5s5sJpGjX5p
Lgq8ngP1G08A50mWl55inU+ox/hl9vyqVhQZv23jcQKBgQDwHdYbUSIAs8yN8Tyb
Bgeba/iz+17HlU0eMPW+AsQrrtfmU+W3Uwt5mdAYxYslnkMBY+golH1i+u+RJebk
zPyQ1Hel06u7GYvi5/BAa8VVhSAylP62laBTXXprQcLe8DNpwZWjM63Xfe5rwrrn
7C+/Ql7nTYKXAKwFUtskZrG1EQKBgQDJ6euL4164wmOmAZWBIOeq85UVWg8P3plF
g7PXetmnj+Ga0fT7Ir82FSDVijA8S3vQ6jNas535lR3sFgTQDxszatTfGYwf+ssI
E68fXF0aOPXTAyXoTReqd2NpgYSFv0iWBG/LGddRuR7ra7Dr9OjTuS/q+9rV2/4k
xM1X/BCjMQKBgE/ofgJlQ72cGGz8ZUDqBsoQapnrA6XD6AAuJvnvDb3D2BHMxdv2
hREYwQodY6tHOeFSkEZA9GFmRSe2x1pJZZwFOTQ0dygy3jzLF0c5FljZjteGgiXd
MZfMuhrLrcBni5ScWeIQJsBaJmgyS+U20sUBn3e2ccky7gxvgIJisq0hAoGAGuMa
aaNaXrIMAPQfC3XtQ5dyF8jJTqyurlIOZbhHOYfwW+Rvge2rlrETkTv4ll7a2wQE
2KQoei7AMEryUx5f2eX0+Mx3G18TID02ya9L+ozxNyspJhj1+M4zH76OfhzttoRa
uqnzQT+sfV72zUTsqBz1442sI2RLIGxQh9HaCVECgYBGxRT6fk69Af7Kc2DF9Ni9
jcKMA8RnSwFPX11AuZj7Y4m/Uke9BOIbY2TIaSWdQpMW9aBFkLzKs54hWITIBNSf
9dG87XpcW9YnxIMp2XsO/FJzasGZHYq8mb4bQU8MVh+LTWVgBdZzMP6OVqBCGGyC
WTtWvfkGAXTQi/WhiM6FkQ==
-----END PRIVATE KEY-----
";

    const TEST_KID: &str = "test-kid";
    const TEST_SUB: &str = "3f2b6c1e-8a4d-4e2f-9b1a-7c5d0e6f1a2b";
    const TEST_ISSUER: &str = "http://localhost:7080/realms/secubank";

    /// The realm key pinned by the tests, with `TEST_KID` and `TEST_PUBLIC_KEY`.
    fn test_realm_key() -> RealmKey {
        RealmKey {
            kid: String::from(TEST_KID),
            key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY.as_bytes()).expect("public key"),
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs()
    }

    /// The claims of a valid access token, shaped like the ones Keycloak issues to the terminal.
    fn valid_claims() -> Value {
        let now = now();
        json!({
            "exp": now + 300,
            "iat": now,
            "iss": TEST_ISSUER,
            "aud": ["secubank-terminal", "account"],
            "sub": TEST_SUB,
            "typ": "Bearer",
            "azp": "secubank-terminal",
            "realm_access": { "roles": ["client", "clearance-standard", "offline_access"] },
        })
    }

    /// Signs `claims` with RS256, the `kid` given and the private key given.
    fn sign_with(kid: Option<&str>, claims: &Value, private_pem: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(String::from);
        let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("private key");
        jsonwebtoken::encode(&header, claims, &key).expect("signed token")
    }

    /// Signs `claims` like the realm would.
    fn sign(claims: &Value) -> String {
        sign_with(Some(TEST_KID), claims, TEST_PRIVATE_KEY)
    }

    /// A valid token with one claim replaced.
    fn token_with(claim: &str, value: Value) -> String {
        let mut claims = valid_claims();
        claims[claim] = value;
        sign(&claims)
    }

    /// A valid token with one claim removed.
    fn token_without(claim: &str) -> String {
        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove(claim);
        sign(&claims)
    }

    fn check(token: &str) -> Result<VerifiedIdentity, AuthError> {
        verify(token, &test_realm_key(), &Config::for_tests())
    }

    fn assert_refused(token: &str, why: &str) {
        assert!(
            matches!(check(token), Err(AuthError::InvalidToken)),
            "should be refused: {why}"
        );
    }

    #[test]
    fn verify_accepts_a_valid_token() {
        let identity = check(&sign(&valid_claims())).expect("valid token");
        assert_eq!(identity.sub().as_str(), TEST_SUB);
        assert_eq!(
            identity.roles(),
            [AppRole::Client, AppRole::Clearance(Clearance::Standard)]
        );
    }

    #[test]
    fn verify_maps_roles_in_token_order_and_drops_others() {
        let roles = json!({ "roles": [
            "offline_access",
            "clearance-elite",
            "uma_authorization",
            "client",
            "bank-security-officer",
            "Client",
            "default-roles-secubank",
        ]});
        let identity = check(&token_with("realm_access", roles)).expect("valid token");
        assert_eq!(
            identity.roles(),
            [
                AppRole::Clearance(Clearance::Elite),
                AppRole::Client,
                AppRole::Officer
            ]
        );
    }

    #[test]
    fn verify_accepts_a_token_without_app_roles() {
        // Not a token failure: the identity simply has no app role, and `authorize` denies it.
        let roles = json!({ "roles": ["offline_access", "uma_authorization"] });
        let identity = check(&token_with("realm_access", roles)).expect("valid token");
        assert!(identity.roles().is_empty());
    }

    #[test]
    fn verify_accepts_a_single_string_audience() {
        let identity = check(&token_with("aud", json!("secubank-terminal"))).expect("valid token");
        assert_eq!(identity.sub().as_str(), TEST_SUB);
    }

    #[test]
    fn verify_refuses_a_wrong_or_missing_kid() {
        let claims = valid_claims();
        assert_refused(&sign_with(Some("other-kid"), &claims, TEST_PRIVATE_KEY), "wrong kid");
        assert_refused(&sign_with(Some(""), &claims, TEST_PRIVATE_KEY), "empty kid");
        assert_refused(&sign_with(None, &claims, TEST_PRIVATE_KEY), "no kid");
    }

    #[test]
    fn verify_refuses_a_token_signed_with_another_key() {
        let claims = valid_claims();
        assert_refused(&sign_with(Some(TEST_KID), &claims, OTHER_PRIVATE_KEY), "other key");
    }

    #[test]
    fn verify_refuses_a_tampered_payload() {
        let token = sign(&valid_claims());
        let parts: Vec<&str> = token.split('.').collect();
        let mut claims = valid_claims();
        claims["realm_access"] = json!({ "roles": ["bank-security-officer"] });
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let forged = format!("{}.{}.{}", parts[0], payload, parts[2]);
        assert_refused(&forged, "payload changed after signing");
    }

    #[test]
    fn verify_refuses_alg_none() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT","kid":"test-kid"}"#);
        let payload = URL_SAFE_NO_PAD.encode(valid_claims().to_string());
        assert_refused(&format!("{header}.{payload}."), "alg none, empty signature");
        assert_refused(&format!("{header}.{payload}"), "alg none, no signature part");
    }

    #[test]
    fn verify_refuses_hs256_signed_with_the_public_key() {
        // Algorithm confusion: an HMAC keyed with the public key, which the attacker knows.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(String::from(TEST_KID));
        let key = EncodingKey::from_secret(TEST_PUBLIC_KEY.as_bytes());
        let token = jsonwebtoken::encode(&header, &valid_claims(), &key).expect("signed token");
        assert_refused(&token, "HS256 keyed with the public key");
    }

    #[test]
    fn verify_refuses_malformed_tokens() {
        for token in ["", "abc", "a.b", "a.b.c", "..", "not.a.jwt.at.all"] {
            assert_refused(token, token);
        }
    }

    #[test]
    fn verify_refuses_an_expired_token() {
        // Further in the past than the default leeway of 60 seconds.
        assert_refused(&token_with("exp", json!(now() - 600)), "expired");
        assert_refused(&token_without("exp"), "no exp");
        assert_refused(&token_with("exp", json!("tomorrow")), "exp not a number");
    }

    #[test]
    fn verify_refuses_a_wrong_or_missing_issuer() {
        for iss in [
            "http://127.0.0.1:7080/realms/secubank",
            "http://localhost:7080/realms/master",
            "http://localhost:7080/realms/secubank/",
            "http://localhost:7080/realms/secubankx",
            "https://localhost:7080/realms/secubank",
            "http://evil.example/http://localhost:7080/realms/secubank",
            "",
        ] {
            assert_refused(&token_with("iss", json!(iss)), iss);
        }
        assert_refused(&token_without("iss"), "no iss");
    }

    #[test]
    fn verify_refuses_a_wrong_or_missing_audience() {
        for aud in [
            json!("account"),
            json!(["account"]),
            json!("secubank-terminal-service-account"),
            json!("Secubank-Terminal"),
            json!([]),
            json!(""),
        ] {
            let why = aud.to_string();
            assert_refused(&token_with("aud", aud), &why);
        }
        assert_refused(&token_without("aud"), "no aud");
    }

    #[test]
    fn verify_refuses_a_wrong_or_missing_azp() {
        for azp in ["secubank-terminal-service-account", "account", "admin-cli", ""] {
            assert_refused(&token_with("azp", json!(azp)), azp);
        }
        assert_refused(&token_without("azp"), "no azp");
    }

    #[test]
    fn verify_refuses_tokens_that_are_not_access_tokens() {
        for typ in ["ID", "Refresh", "bearer", ""] {
            assert_refused(&token_with("typ", json!(typ)), typ);
        }
        assert_refused(&token_without("typ"), "no typ");
    }

    #[test]
    fn verify_refuses_an_invalid_or_missing_sub() {
        for sub in [
            "not-a-uuid",
            "3F2B6C1E-8A4D-4E2F-9B1A-7C5D0E6F1A2B",
            "3f2b6c1e8a4d4e2f9b1a7c5d0e6f1a2b",
            "",
        ] {
            assert_refused(&token_with("sub", json!(sub)), sub);
        }
        assert_refused(&token_without("sub"), "no sub");
    }

    #[test]
    fn verify_refuses_malformed_realm_access() {
        assert_refused(&token_without("realm_access"), "no realm_access");
        assert_refused(&token_with("realm_access", json!({})), "no roles");
        assert_refused(
            &token_with("realm_access", json!({ "roles": "client" })),
            "roles not a list",
        );
    }
}
