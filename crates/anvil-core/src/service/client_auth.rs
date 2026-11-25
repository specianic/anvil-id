//! Client authentication at the token endpoint: the single implementation (RFC 6749 §2.3,
//! RFC 7523 §2.2, OIDC Core §9).
//!
//! Supported methods: `client_secret_basic`, `client_secret_post`, `private_key_jwt` and `none`
//! (public clients). A request that presents more than one method is rejected. The method used
//! must equal the client's registered `auth_method`.
//!
//! Every credential failure returns the same `invalid_client` description, so a caller cannot
//! tell an unknown client from a wrong secret or a mismatched method. An unknown client still
//! runs the constant-time secret comparison (against a fixed dummy hash). Secrets, assertions
//! and tokens are never logged or put into error messages.

use std::sync::Arc;

use anvil_jose::client_assertion::{AssertionRules, verify_client_assertion};
use anvil_jose::encoding::{b64std_decode, b64url_decode, ct_eq, secret_hash};
use anvil_jose::jwk::Jwks;
use anvil_jose::jws::MAX_JWS_LEN;
use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{Client, ClientAuthMethod, ClientType, ReplayKind, SecretHash, Tenant};
use crate::ports::{Clock, JtiOutcome, Storage};

/// RFC 7523 `client_assertion_type` for JWT bearer client assertions.
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Maximum distance of an assertion's `exp` into the future.
pub const ASSERTION_MAX_LIFETIME: Duration = Duration::minutes(5);
/// Clock-skew allowance for client assertions.
pub const ASSERTION_LEEWAY: Duration = Duration::seconds(30);

/// The one description used for every credential failure.
const AUTH_FAILED: &str = "client authentication failed";

/// Compared against when the client is unknown or has no secret, so every path does the same
/// constant-time work. SHA-256 of no realistic secret.
const DUMMY_SECRET_HASH: [u8; 32] = [0x5a; 32];

/// Client credentials as received at the token endpoint.
#[derive(Clone, Default)]
pub struct ClientAuthInput {
    /// Raw `Authorization` header value.
    pub basic: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

impl std::fmt::Debug for ClientAuthInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("ClientAuthInput")
            .field("basic", &redact(&self.basic))
            .field("client_id", &self.client_id)
            .field("client_secret", &redact(&self.client_secret))
            .field("client_assertion_type", &self.client_assertion_type)
            .field("client_assertion", &redact(&self.client_assertion))
            .finish()
    }
}

fn invalid_client(reason: &str, basic_auth_used: bool) -> CoreError {
    CoreError::InvalidClient {
        reason: reason.to_owned(),
        basic_auth_used,
    }
}

/// `application/x-www-form-urlencoded` decoding of one component (`+` is a space).
fn form_urldecode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = b.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Parses an HTTP Basic `Authorization` header per RFC 6749 §2.3.1: `Basic` +
/// base64(urlencode(client_id) ":" urlencode(secret)). Any malformation is `invalid_client`
/// with `basic_auth_used: true`.
pub fn parse_basic(header: &str) -> Result<(String, String), CoreError> {
    let bad = || invalid_client("invalid Basic authorization header", true);
    let header = header.trim();
    let (scheme, rest) = header.split_once(' ').ok_or_else(bad)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(bad());
    }
    let decoded = b64std_decode(rest.trim()).map_err(|_| bad())?;
    let decoded = String::from_utf8(decoded).map_err(|_| bad())?;
    let (id, secret) = decoded.split_once(':').ok_or_else(bad)?;
    let id = form_urldecode(id).ok_or_else(bad)?;
    let secret = form_urldecode(secret).ok_or_else(bad)?;
    if id.is_empty() || secret.is_empty() {
        return Err(bad());
    }
    Ok((id, secret))
}

/// The authentication method a request presents, before any client lookup.
#[derive(Clone, PartialEq, Eq)]
pub enum PresentedAuth {
    Basic {
        client_id: String,
        secret: String,
    },
    Post {
        client_id: String,
        secret: String,
    },
    PrivateKeyJwt {
        client_id: String,
        assertion: String,
    },
    None {
        client_id: String,
    },
}

impl std::fmt::Debug for PresentedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}({})", self.method(), self.client_id())
    }
}

impl PresentedAuth {
    /// The registered method this presentation corresponds to.
    pub fn method(&self) -> ClientAuthMethod {
        match self {
            Self::Basic { .. } => ClientAuthMethod::ClientSecretBasic,
            Self::Post { .. } => ClientAuthMethod::ClientSecretPost,
            Self::PrivateKeyJwt { .. } => ClientAuthMethod::PrivateKeyJwt,
            Self::None { .. } => ClientAuthMethod::None,
        }
    }

    pub fn client_id(&self) -> &str {
        match self {
            Self::Basic { client_id, .. }
            | Self::Post { client_id, .. }
            | Self::PrivateKeyJwt { client_id, .. }
            | Self::None { client_id } => client_id,
        }
    }

    pub fn basic_auth_used(&self) -> bool {
        matches!(self, Self::Basic { .. })
    }
}

/// The `sub` of an (unverified) assertion, used only to find the client whose keys then verify
/// it. The verified `iss`/`sub` must equal this id.
fn unverified_assertion_sub(assertion: &str) -> Option<String> {
    if assertion.len() > MAX_JWS_LEN {
        return None;
    }
    let mut it = assertion.split('.');
    let (Some(_), Some(payload), Some(_), None) = (it.next(), it.next(), it.next(), it.next())
    else {
        return None;
    };
    let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(payload).ok()?).ok()?;
    claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Decides which single method a request presents. More than one method, a body `client_id`
/// contradicting the credentials, an unknown assertion type or no client id at all is
/// `invalid_client`.
pub fn select_method(input: &ClientAuthInput) -> Result<PresentedAuth, CoreError> {
    let basic_used = input.basic.is_some();
    let has_assertion = input.client_assertion.is_some() || input.client_assertion_type.is_some();
    let methods = usize::from(basic_used)
        + usize::from(input.client_secret.is_some())
        + usize::from(has_assertion);
    if methods > 1 {
        return Err(invalid_client(
            "more than one client authentication method",
            basic_used,
        ));
    }
    let body_id = input.client_id.as_deref().filter(|s| !s.is_empty());

    if let Some(header) = &input.basic {
        let (client_id, secret) = parse_basic(header)?;
        if body_id.is_some_and(|b| b != client_id) {
            return Err(invalid_client(AUTH_FAILED, true));
        }
        return Ok(PresentedAuth::Basic { client_id, secret });
    }
    if let Some(secret) = &input.client_secret {
        let client_id = body_id.ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
        if secret.is_empty() {
            return Err(invalid_client(AUTH_FAILED, false));
        }
        return Ok(PresentedAuth::Post {
            client_id: client_id.to_owned(),
            secret: secret.clone(),
        });
    }
    if has_assertion {
        if input.client_assertion_type.as_deref() != Some(JWT_BEARER_ASSERTION_TYPE) {
            return Err(invalid_client("unsupported client_assertion_type", false));
        }
        let assertion = input
            .client_assertion
            .as_deref()
            .filter(|a| !a.is_empty())
            .ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
        let client_id = unverified_assertion_sub(assertion)
            .ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
        if body_id.is_some_and(|b| b != client_id) {
            return Err(invalid_client(AUTH_FAILED, false));
        }
        return Ok(PresentedAuth::PrivateKeyJwt {
            client_id,
            assertion: assertion.to_owned(),
        });
    }
    let client_id = body_id.ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
    Ok(PresentedAuth::None {
        client_id: client_id.to_owned(),
    })
}

/// The method used must be the one registered, and `none` is only for public clients while
/// every other method is only for confidential clients.
pub fn check_method(client: &Client, presented: &PresentedAuth) -> Result<(), CoreError> {
    let basic = presented.basic_auth_used();
    if client.auth_method != presented.method() {
        return Err(invalid_client(AUTH_FAILED, basic));
    }
    let type_ok = match presented.method() {
        ClientAuthMethod::None => client.client_type == ClientType::Public,
        _ => client.client_type == ClientType::Confidential,
    };
    if !type_ok {
        return Err(invalid_client(AUTH_FAILED, basic));
    }
    Ok(())
}

/// Constant-time secret check. `stored` is `None` for an unknown client or a client without a
/// secret; the comparison still runs (against a dummy) and then fails.
pub fn secret_matches(stored: Option<&SecretHash>, presented: &str) -> bool {
    let presented = secret_hash(presented);
    let (expected, known) = match stored {
        Some(h) => (h.as_bytes(), true),
        None => (&DUMMY_SECRET_HASH, false),
    };
    ct_eq(expected, &presented) && known
}

/// Replay-guard key of a client assertion: `secret_hash(client_id ‖ "\0" ‖ jti)`.
pub fn assertion_jti_hash(client_id: &str, jti: &str) -> SecretHash {
    SecretHash(secret_hash(&format!("{client_id}\0{jti}")))
}

/// Verifies a `private_key_jwt` assertion against the client's registered inline JWKS.
/// Returns the replay-guard hash and the time until which it must be recorded.
pub fn verify_assertion(
    client: &Client,
    issuer: &str,
    assertion: &str,
    now: OffsetDateTime,
) -> Result<(SecretHash, OffsetDateTime), CoreError> {
    let fail = || invalid_client(AUTH_FAILED, false);
    // Jwks::parse rejects JWKS carrying private members.
    let jwks = client
        .jwks
        .as_deref()
        .and_then(|j| Jwks::parse(j).ok())
        .ok_or_else(fail)?;
    let verified = verify_client_assertion(
        assertion,
        &jwks,
        &AssertionRules {
            issuer,
            client_id: &client.client_id,
            now,
            max_lifetime: ASSERTION_MAX_LIFETIME,
            leeway: ASSERTION_LEEWAY,
        },
    )
    .map_err(|_| fail())?;
    // Accepted while exp > now - leeway, so remember it until exp + leeway.
    Ok((
        assertion_jti_hash(&client.client_id, &verified.jti),
        verified.exp + ASSERTION_LEEWAY,
    ))
}

/// The token endpoint's client authenticator.
#[derive(Clone)]
pub struct ClientAuthenticator {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl ClientAuthenticator {
    /// Authenticates the client of a token request in `tenant`.
    pub async fn authenticate(
        &self,
        tenant: &Tenant,
        issuer: &str,
        input: &ClientAuthInput,
    ) -> Result<Client, CoreError> {
        let presented = select_method(input)?;
        let basic = presented.basic_auth_used();
        let client = self
            .storage
            .clients()
            .get(tenant.id, presented.client_id())
            .await?;

        match &presented {
            PresentedAuth::Basic { secret, .. } | PresentedAuth::Post { secret, .. } => {
                // Same work whether or not the client exists.
                let ok =
                    secret_matches(client.as_ref().and_then(|c| c.secret_hash.as_ref()), secret);
                let client = client.ok_or_else(|| invalid_client(AUTH_FAILED, basic))?;
                check_method(&client, &presented)?;
                if !ok {
                    return Err(invalid_client(AUTH_FAILED, basic));
                }
                Ok(client)
            }
            PresentedAuth::PrivateKeyJwt { assertion, .. } => {
                let client = client.ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
                check_method(&client, &presented)?;
                let now = self.clock.now();
                let (hash, until) = verify_assertion(&client, issuer, assertion, now)?;
                match self
                    .storage
                    .grants()
                    .record_jti(tenant.id, ReplayKind::ClientAssertionJti, &hash, until, now)
                    .await?
                {
                    JtiOutcome::Recorded => Ok(client),
                    JtiOutcome::Replayed => Err(invalid_client(AUTH_FAILED, false)),
                }
            }
            PresentedAuth::None { .. } => {
                let client = client.ok_or_else(|| invalid_client(AUTH_FAILED, false))?;
                check_method(&client, &presented)?;
                Ok(client)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{ApplicationType, ClientId, GrantType, TenantId};
    use anvil_jose::encoding::b64url;
    use anvil_jose::generate_rs256;
    use anvil_jose::keys::{Alg, SigningKey};

    fn b64_std(s: &str) -> String {
        anvil_jose::encoding::b64std(s.as_bytes())
    }

    pub(crate) fn client(method: ClientAuthMethod) -> Client {
        let now = OffsetDateTime::UNIX_EPOCH;
        Client {
            id: ClientId::new_v7(),
            tenant_id: TenantId::new_v7(),
            client_id: "rp".into(),
            name: "RP".into(),
            client_type: if method == ClientAuthMethod::None {
                ClientType::Public
            } else {
                ClientType::Confidential
            },
            application_type: ApplicationType::Web,
            auth_method: method,
            secret_hash: Some(SecretHash(secret_hash("s3cret"))),
            jwks: None,
            redirect_uris: vec!["https://rp.test/cb".into()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            require_pkce: true,
            created_at: now,
            updated_at: now,
            token_format: crate::model::TokenFormat::Jwt,
            consent_mode: crate::model::ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![],
            mfa_policy: None,
        }
    }

    fn is_invalid_client(r: &Result<impl std::fmt::Debug, CoreError>, basic: bool) -> bool {
        matches!(r, Err(CoreError::InvalidClient { basic_auth_used, .. }) if *basic_auth_used == basic)
    }

    #[test]
    fn parse_basic_url_decodes_after_base64() {
        let h = format!("Basic {}", b64_std("my%3Aclient:p%40ss"));
        assert_eq!(
            parse_basic(&h).unwrap(),
            ("my:client".to_owned(), "p@ss".to_owned())
        );
        let h = format!("basic {}", b64_std("a+b:c%2Bd"));
        assert_eq!(
            parse_basic(&h).unwrap(),
            ("a b".to_owned(), "c+d".to_owned())
        );
    }

    #[test]
    fn parse_basic_rejects_malformed() {
        for h in [
            format!("Basic {}", b64_std("nocolon")),
            "Basic !!!not-base64!!!".to_owned(),
            format!("Bearer {}", b64_std("a:b")),
            format!("Basic {}", b64_std(":secret")),
            format!("Basic {}", b64_std("id:")),
            format!("Basic {}", b64_std("id:%zz")),
            "Basic".to_owned(),
            "Basic YQ".to_owned(),
            "Basic YWI=6".to_owned(),
        ] {
            assert!(
                is_invalid_client(&parse_basic(&h), true),
                "{h:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_basic_accepts_padded_and_unpadded_and_rejects_non_canonical_base64() {
        for padded in [b64_std("ab:c"), b64_std("abc:de"), b64_std("rp:s3cret")] {
            let unpadded = padded.trim_end_matches('=').to_owned();
            for h in [&padded, &unpadded] {
                let (id, secret) = parse_basic(&format!("Basic {h}")).unwrap();
                assert!(!id.is_empty() && !secret.is_empty());
            }
        }
        // "a:b" = YTpi; non-canonical, URL-alphabet, partial and excess padding are rejected.
        for bad in [
            "YTpj=",
            "YTo=",
            "YT-i",
            "YTpi=",
            "YTpiYQ=",
            "YTpiYQ===",
            "YTpiYR==",
        ] {
            assert!(
                is_invalid_client(&parse_basic(&format!("Basic {bad}")), true),
                "{bad:?} must be rejected"
            );
        }
    }

    fn input() -> ClientAuthInput {
        ClientAuthInput::default()
    }

    #[test]
    fn select_method_rejects_multiple_methods() {
        let basic = Some(format!("Basic {}", b64_std("rp:s3cret")));
        let both_secrets = ClientAuthInput {
            basic: basic.clone(),
            client_secret: Some("s3cret".into()),
            client_id: Some("rp".into()),
            ..input()
        };
        assert!(is_invalid_client(&select_method(&both_secrets), true));
        let basic_and_assertion = ClientAuthInput {
            basic,
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.into()),
            client_assertion: Some("a.b.c".into()),
            ..input()
        };
        assert!(is_invalid_client(
            &select_method(&basic_and_assertion),
            true
        ));
        let post_and_assertion = ClientAuthInput {
            client_id: Some("rp".into()),
            client_secret: Some("s3cret".into()),
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.into()),
            client_assertion: Some("a.b.c".into()),
            ..input()
        };
        assert!(is_invalid_client(
            &select_method(&post_and_assertion),
            false
        ));
    }

    #[test]
    fn select_method_none_and_errors() {
        let none = ClientAuthInput {
            client_id: Some("spa".into()),
            ..input()
        };
        assert_eq!(
            select_method(&none).unwrap(),
            PresentedAuth::None {
                client_id: "spa".into()
            }
        );
        assert!(
            is_invalid_client(&select_method(&input()), false),
            "no client id"
        );
        let wrong_type = ClientAuthInput {
            client_assertion_type: Some("urn:example:other".into()),
            client_assertion: Some("a.b.c".into()),
            ..input()
        };
        assert!(is_invalid_client(&select_method(&wrong_type), false));
        let post_without_id = ClientAuthInput {
            client_secret: Some("s3cret".into()),
            ..input()
        };
        assert!(is_invalid_client(&select_method(&post_without_id), false));
        let basic_with_other_body_id = ClientAuthInput {
            basic: Some(format!("Basic {}", b64_std("rp:s3cret"))),
            client_id: Some("other".into()),
            ..input()
        };
        assert!(is_invalid_client(
            &select_method(&basic_with_other_body_id),
            true
        ));
    }

    #[test]
    fn method_must_match_registration() {
        let basic_client = client(ClientAuthMethod::ClientSecretBasic);
        let post = PresentedAuth::Post {
            client_id: "rp".into(),
            secret: "s3cret".into(),
        };
        assert!(is_invalid_client(
            &check_method(&basic_client, &post),
            false
        ));
        let basic = PresentedAuth::Basic {
            client_id: "rp".into(),
            secret: "s3cret".into(),
        };
        assert!(check_method(&basic_client, &basic).is_ok());
        let none = PresentedAuth::None {
            client_id: "rp".into(),
        };
        assert!(is_invalid_client(
            &check_method(&basic_client, &none),
            false
        ));
    }

    #[test]
    fn public_client_presenting_a_secret_is_rejected() {
        let public = client(ClientAuthMethod::None);
        for p in [
            PresentedAuth::Post {
                client_id: "rp".into(),
                secret: "s3cret".into(),
            },
            PresentedAuth::Basic {
                client_id: "rp".into(),
                secret: "s3cret".into(),
            },
        ] {
            assert!(check_method(&public, &p).is_err(), "{p:?}");
        }
        assert!(
            check_method(
                &public,
                &PresentedAuth::None {
                    client_id: "rp".into()
                }
            )
            .is_ok()
        );
        // A confidential client misregistered with `none` is still refused.
        let mut conf_none = client(ClientAuthMethod::None);
        conf_none.client_type = ClientType::Confidential;
        assert!(
            check_method(
                &conf_none,
                &PresentedAuth::None {
                    client_id: "rp".into()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn secret_comparison() {
        let h = SecretHash(secret_hash("s3cret"));
        assert!(secret_matches(Some(&h), "s3cret"));
        assert!(!secret_matches(Some(&h), "s3cre"));
        assert!(!secret_matches(None, "s3cret"));
        // The dummy itself never matches, even if someone presents its preimage-looking value.
        assert!(!secret_matches(None, ""));
    }

    #[test]
    fn credential_failures_share_one_description() {
        let a = invalid_client(AUTH_FAILED, false).description();
        let c = client(ClientAuthMethod::ClientSecretBasic);
        let b = check_method(
            &c,
            &PresentedAuth::Post {
                client_id: "rp".into(),
                secret: "x".into(),
            },
        )
        .unwrap_err()
        .description();
        assert_eq!(a, b);
        assert!(!a.contains("secret") && !a.contains("unknown"));
    }

    fn assertion(signer: &SigningKey, claims: serde_json::Value) -> String {
        signer.sign_jwt(None, &claims).unwrap()
    }

    #[test]
    fn private_key_jwt_assertion_verification() {
        const ISS: &str = "https://op.test";
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let g = generate_rs256().unwrap();
        let signer = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        let mut c = client(ClientAuthMethod::PrivateKeyJwt);
        c.jwks = Some(serde_json::json!({ "keys": [g.public_jwk] }).to_string());

        let good = assertion(
            &signer,
            serde_json::json!({"iss": "rp", "sub": "rp", "aud": ISS, "jti": "j1",
                               "exp": now.unix_timestamp() + 60}),
        );
        let sel = select_method(&ClientAuthInput {
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.into()),
            client_assertion: Some(good.clone()),
            ..input()
        })
        .unwrap();
        assert_eq!(sel.client_id(), "rp");
        let (hash, until) = verify_assertion(&c, ISS, &good, now).unwrap();
        assert_eq!(hash, assertion_jti_hash("rp", "j1"));
        assert_eq!(until.unix_timestamp(), now.unix_timestamp() + 90);
        assert_ne!(
            assertion_jti_hash("rp", "j1"),
            assertion_jti_hash("rp2", "j1")
        );

        let wrong_aud = assertion(
            &signer,
            serde_json::json!({"iss": "rp", "sub": "rp", "aud": "https://op.test/token",
                               "jti": "j2", "exp": now.unix_timestamp() + 60}),
        );
        assert!(is_invalid_client(
            &verify_assertion(&c, ISS, &wrong_aud, now),
            false
        ));

        let other = generate_rs256().unwrap();
        let other_signer = SigningKey::from_pkcs8(&other.kid, Alg::RS256, &other.pkcs8).unwrap();
        let foreign = assertion(
            &other_signer,
            serde_json::json!({"iss": "rp", "sub": "rp", "aud": ISS, "jti": "j3",
                               "exp": now.unix_timestamp() + 60}),
        );
        assert!(is_invalid_client(
            &verify_assertion(&c, ISS, &foreign, now),
            false
        ));

        // A registered JWKS that carries private members is refused.
        let mut leaked = c.clone();
        leaked.jwks =
            Some(r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}]}"#.to_owned());
        assert!(is_invalid_client(
            &verify_assertion(&leaked, ISS, &good, now),
            false
        ));
        let mut no_jwks = c.clone();
        no_jwks.jwks = None;
        assert!(is_invalid_client(
            &verify_assertion(&no_jwks, ISS, &good, now),
            false
        ));
    }

    #[test]
    fn unverified_sub_extraction() {
        let payload = b64url(br#"{"sub":"rp"}"#);
        assert_eq!(
            unverified_assertion_sub(&format!("e30.{payload}.sig")).as_deref(),
            Some("rp")
        );
        assert!(unverified_assertion_sub("e30.e30.sig").is_none());
        assert!(unverified_assertion_sub("only.two").is_none());
        assert!(unverified_assertion_sub(&"a".repeat(MAX_JWS_LEN + 1)).is_none());
    }

    #[test]
    fn debug_redacts_secrets() {
        let i = ClientAuthInput {
            basic: Some("Basic c2VjcmV0".into()),
            client_id: Some("rp".into()),
            client_secret: Some("hunter2".into()),
            client_assertion_type: None,
            client_assertion: Some("eyJhbGciOi".into()),
        };
        let s = format!("{i:?}");
        assert!(!s.contains("hunter2") && !s.contains("c2VjcmV0") && !s.contains("eyJ"));
        let p = PresentedAuth::Post {
            client_id: "rp".into(),
            secret: "hunter2".into(),
        };
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
