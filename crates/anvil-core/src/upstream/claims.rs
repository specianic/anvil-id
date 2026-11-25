//! Upstream ID-token validation and claim normalisation (ID token, Apple first-login user JSON,
//! GitHub profile + emails, generic OAuth2 profile mapping).
//!
//! [`validate_id_token`] checks, in this fixed order (research Pattern 5):
//! 1. algorithm allow-list and signature (anvil-jose: `none`/HMAC never pass),
//! 2. `iss` by the provider's [`IssuerRule`] (Google/Microsoft rules only for those presets) and,
//!    for Microsoft, `tid` (canonical UUID, optional allowed-tenants list); Google `hd` when an
//!    allow-list is configured,
//! 3. `aud` contains the client id (several audiences or any `azp` => `azp` == client id),
//! 4. `exp > now - 60 s`, `iat <= now + 60 s` (and `nbf` when present),
//! 5. `nonce` equality when one is expected.
//!
//! Normalisation produces one [`UpstreamIdentity`] whose `email_verified` is already AND-ed with
//! the connection's trust, so callers can never link on an untrusted address by accident.
//!
//! Pure: no I/O.

use anvil_jose::{JoseError, Jwks, verify_jwt};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::providers::{GOOGLE_ISSUER, IssuerRule, ResolvedProvider, TENANT_PLACEHOLDER};
use crate::model::{ClaimMapping, ConnectionKind};

/// Accepted clock skew for `exp`, `iat` and `nbf` (seconds).
pub const CLOCK_SKEW_SECS: i64 = 60;

/// Maximum length (characters) of a normalised name part.
pub const MAX_NAME_CHARS: usize = 200;

/// Maximum length (characters) of a normalised email address.
pub const MAX_EMAIL_CHARS: usize = 320;

/// Why an upstream ID token or profile was rejected. `Display` is fixed text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamTokenError {
    /// Malformed token, algorithm outside the allow-list, or bad signature.
    #[error("upstream token signature is invalid")]
    Signature,
    /// No key in the JWK Set matches the token's `kid` (callers may refresh the JWKS once).
    #[error("upstream token key is unknown")]
    UnknownKey,
    /// `iss` (or Microsoft `tid`) does not match the provider's rule.
    #[error("upstream token issuer is invalid")]
    Issuer,
    /// Google `hd` outside the configured hosted domains.
    #[error("upstream hosted domain is not allowed")]
    HostedDomain,
    /// `aud` / `azp` does not name this client.
    #[error("upstream token audience is invalid")]
    Audience,
    #[error("upstream token has expired")]
    Expired,
    /// `iat` or `nbf` lies in the future (beyond the skew).
    #[error("upstream token is not yet valid")]
    IssuedInFuture,
    /// `nonce` missing or different from the one sent.
    #[error("upstream token nonce is invalid")]
    Nonce,
    /// A required claim is absent or has the wrong type.
    #[error("upstream token lacks a required claim: {0}")]
    MissingClaim(&'static str),
}

/// The provider-independent identity of an upstream login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamIdentity {
    /// Upstream subject (`sub`, GitHub numeric id, mapped subject). Never an email or login.
    pub subject: String,
    pub email: Option<String>,
    /// `true` only when the upstream asserted it AND the connection trusts it AND there is an
    /// email.
    pub email_verified: bool,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name: Option<String>,
    /// Provider identifiers kept on the link (Microsoft `tid`/`oid`, Google `hd`, GitHub
    /// `login`). Never tokens or secrets.
    pub metadata: Map<String, Value>,
}

/// Validate an upstream ID token and return its claims.
pub fn validate_id_token(
    token: &str,
    jwks: &Jwks,
    resolved: &ResolvedProvider,
    client_id: &str,
    expected_nonce: Option<&str>,
    now: OffsetDateTime,
) -> Result<Map<String, Value>, UpstreamTokenError> {
    // 1. Algorithm allow-list + signature. Plain OAuth2 providers have an empty allow-list.
    let rule = resolved
        .issuer_rule
        .as_ref()
        .ok_or(UpstreamTokenError::Signature)?;
    if resolved.allowed_algs.is_empty() {
        return Err(UpstreamTokenError::Signature);
    }
    let claims = verify_jwt(token, jwks, &resolved.allowed_algs)
        .map_err(|e| match e {
            JoseError::UnknownKey => UpstreamTokenError::UnknownKey,
            _ => UpstreamTokenError::Signature,
        })?
        .claims;

    // 2. Issuer (+ Microsoft tid, Google hd).
    check_issuer(&claims, rule, resolved)?;
    if !resolved.hosted_domains.is_empty() {
        let hd = str_claim(&claims, "hd").map(str::to_ascii_lowercase);
        if !hd.is_some_and(|hd| resolved.hosted_domains.contains(&hd)) {
            return Err(UpstreamTokenError::HostedDomain);
        }
    }

    // 3. Audience / authorized party.
    check_audience(&claims, client_id)?;

    // 4. Time.
    let now = now.unix_timestamp();
    let exp = time_claim(&claims, "exp")?.ok_or(UpstreamTokenError::MissingClaim("exp"))?;
    if exp <= now - CLOCK_SKEW_SECS {
        return Err(UpstreamTokenError::Expired);
    }
    let iat = time_claim(&claims, "iat")?.ok_or(UpstreamTokenError::MissingClaim("iat"))?;
    if iat > now + CLOCK_SKEW_SECS {
        return Err(UpstreamTokenError::IssuedInFuture);
    }
    if let Some(nbf) = time_claim(&claims, "nbf")?
        && nbf > now + CLOCK_SKEW_SECS
    {
        return Err(UpstreamTokenError::IssuedInFuture);
    }

    // 5. Nonce.
    if let Some(expected) = expected_nonce
        && str_claim(&claims, "nonce") != Some(expected)
    {
        return Err(UpstreamTokenError::Nonce);
    }

    match str_claim(&claims, "sub") {
        Some(sub) if !sub.is_empty() => Ok(claims),
        _ => Err(UpstreamTokenError::MissingClaim("sub")),
    }
}

fn str_claim<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

/// A NumericDate claim: `None` when absent, `MissingClaim` when not a number.
fn time_claim(
    claims: &Map<String, Value>,
    name: &'static str,
) -> Result<Option<i64>, UpstreamTokenError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| {
                v.as_f64()
                    .filter(|f| f.is_finite() && f.abs() < 1e15)
                    .map(|f| f.floor() as i64)
            })
            .map(Some)
            .ok_or(UpstreamTokenError::MissingClaim(name)),
    }
}

/// A Microsoft `tid` in canonical (lowercase, hyphenated) UUID form.
fn canonical_tid(claims: &Map<String, Value>) -> Result<&str, UpstreamTokenError> {
    let tid = str_claim(claims, "tid").ok_or(UpstreamTokenError::Issuer)?;
    match uuid::Uuid::try_parse(tid) {
        Ok(u) if u.hyphenated().to_string() == tid => Ok(tid),
        _ => Err(UpstreamTokenError::Issuer),
    }
}

fn check_issuer(
    claims: &Map<String, Value>,
    rule: &IssuerRule,
    resolved: &ResolvedProvider,
) -> Result<(), UpstreamTokenError> {
    let iss = str_claim(claims, "iss").ok_or(UpstreamTokenError::Issuer)?;
    let ok = match rule {
        IssuerRule::Exact(expected) => iss == expected,
        IssuerRule::Google => iss == GOOGLE_ISSUER || iss == "accounts.google.com",
        IssuerRule::MicrosoftTemplate(template) => {
            let tid = canonical_tid(claims)?;
            iss == template.replace(TENANT_PLACEHOLDER, tid)
        }
    };
    if !ok {
        return Err(UpstreamTokenError::Issuer);
    }
    if resolved.kind == ConnectionKind::Microsoft {
        let tid = canonical_tid(claims)?;
        if !resolved.allowed_tenants.is_empty()
            && !resolved.allowed_tenants.iter().any(|t| t == tid)
        {
            return Err(UpstreamTokenError::Issuer);
        }
    }
    Ok(())
}

fn check_audience(claims: &Map<String, Value>, client_id: &str) -> Result<(), UpstreamTokenError> {
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(a)) => vec![a.as_str()],
        Some(Value::Array(list)) => list
            .iter()
            .map(|v| v.as_str().ok_or(UpstreamTokenError::Audience))
            .collect::<Result<_, _>>()?,
        _ => return Err(UpstreamTokenError::Audience),
    };
    if !audiences.contains(&client_id) {
        return Err(UpstreamTokenError::Audience);
    }
    let azp = claims.get("azp");
    if (audiences.len() > 1 || azp.is_some()) && azp.and_then(Value::as_str) != Some(client_id) {
        return Err(UpstreamTokenError::Audience);
    }
    Ok(())
}

/// Trim, strip control characters, cap at [`MAX_NAME_CHARS`]; empty -> `None`.
fn clean_name(v: Option<&Value>) -> Option<String> {
    let raw = v?.as_str()?;
    let stripped: String = raw.chars().filter(|c| !c.is_control()).collect();
    let capped: String = stripped.trim().chars().take(MAX_NAME_CHARS).collect();
    let out = capped.trim_end();
    (!out.is_empty()).then(|| out.to_owned())
}

/// Trimmed address with exactly one `@`, no control characters or whitespace, at most
/// [`MAX_EMAIL_CHARS`]; anything else -> `None`.
fn clean_email(v: Option<&Value>) -> Option<String> {
    let e = v?.as_str()?.trim();
    let valid = !e.is_empty()
        && e.chars().count() <= MAX_EMAIL_CHARS
        && !e.chars().any(|c| c.is_control() || c.is_whitespace())
        && e.matches('@').count() == 1
        && !e.starts_with('@')
        && !e.ends_with('@');
    valid.then(|| e.to_owned())
}

fn subject(claims: &Map<String, Value>) -> Result<String, UpstreamTokenError> {
    match str_claim(claims, "sub") {
        Some(s) if !s.is_empty() => Ok(s.to_owned()),
        _ => Err(UpstreamTokenError::MissingClaim("sub")),
    }
}

fn copy_ids(claims: &Map<String, Value>, names: &[&str]) -> Map<String, Value> {
    names
        .iter()
        .filter_map(|n| {
            str_claim(claims, n).map(|v| ((*n).to_owned(), Value::String(v.to_owned())))
        })
        .collect()
}

/// Normalise validated OIDC claims (Google, Microsoft, generic OIDC, UserInfo).
pub fn normalise_oidc(
    claims: &Map<String, Value>,
    resolved: &ResolvedProvider,
    trust: bool,
) -> Result<UpstreamIdentity, UpstreamTokenError> {
    let subject = subject(claims)?;
    let email = clean_email(claims.get("email"));
    let asserted = claims.get("email_verified") == Some(&Value::Bool(true));
    let metadata = match resolved.kind {
        ConnectionKind::Microsoft => copy_ids(claims, &["tid", "oid"]),
        ConnectionKind::Google => copy_ids(claims, &["hd"]),
        _ => Map::new(),
    };
    Ok(UpstreamIdentity {
        subject,
        email_verified: email.is_some() && asserted && trust && resolved.email_trusted,
        email,
        given_name: clean_name(claims.get("given_name")),
        family_name: clean_name(claims.get("family_name")),
        name: clean_name(claims.get("name")),
        metadata,
    })
}

/// Apple sends `email_verified` as a boolean or as the strings `"true"` / `"false"`.
fn apple_bool(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true))) || matches!(v, Some(Value::String(s)) if s == "true")
}

/// Normalise validated Apple ID-token claims plus the optional first-authorization `user` JSON
/// (`{"name":{"firstName","lastName"},"email"}`). Only names are taken from the unsigned user
/// JSON; a malformed value is ignored.
pub fn normalise_apple(
    claims: &Map<String, Value>,
    user_json: Option<&str>,
    trust: bool,
) -> Result<UpstreamIdentity, UpstreamTokenError> {
    let subject = subject(claims)?;
    let email = clean_email(claims.get("email"));
    let asserted = apple_bool(claims.get("email_verified"));
    let user: Option<Value> = user_json.and_then(|j| serde_json::from_str(j).ok());
    let name_obj = user.as_ref().and_then(|u| u.get("name"));
    let given_name = clean_name(name_obj.and_then(|n| n.get("firstName")));
    let family_name = clean_name(name_obj.and_then(|n| n.get("lastName")));
    let name = match (&given_name, &family_name) {
        (None, None) => None,
        (g, f) => {
            let joined = [g.as_deref(), f.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            clean_name(Some(&Value::String(joined)))
        }
    };
    let mut metadata = Map::new();
    if apple_bool(claims.get("is_private_email")) {
        metadata.insert("is_private_email".into(), Value::Bool(true));
    }
    Ok(UpstreamIdentity {
        subject,
        email_verified: email.is_some() && asserted && trust,
        email,
        given_name,
        family_name,
        name,
        metadata,
    })
}

/// Normalise a GitHub `/user` profile and `/user/emails` list: subject = numeric `id`, email only
/// from the entry that is both `primary` and `verified`.
pub fn normalise_github(
    user: &Value,
    emails: &Value,
    trust: bool,
) -> Result<UpstreamIdentity, UpstreamTokenError> {
    let id = user
        .get("id")
        .and_then(Value::as_u64)
        .ok_or(UpstreamTokenError::MissingClaim("id"))?;
    let email = emails
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| {
            e.get("primary") == Some(&Value::Bool(true))
                && e.get("verified") == Some(&Value::Bool(true))
        })
        .and_then(|e| clean_email(e.get("email")));
    let mut metadata = Map::new();
    if let Some(login) = user.get("login").and_then(Value::as_str) {
        metadata.insert("login".into(), Value::String(login.to_owned()));
    }
    Ok(UpstreamIdentity {
        subject: id.to_string(),
        email_verified: email.is_some() && trust,
        email,
        given_name: None,
        family_name: None,
        name: clean_name(user.get("name")),
        metadata,
    })
}

/// Normalise a generic OAuth2 profile through JSON pointers. `email_verified` requires a mapped
/// boolean `true` and trust.
pub fn normalise_oauth2(
    profile: &Value,
    mapping: &ClaimMapping,
    trust: bool,
) -> Result<UpstreamIdentity, UpstreamTokenError> {
    let subject = match profile.pointer(&mapping.subject) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Number(n)) if n.is_u64() || n.is_i64() => n.to_string(),
        _ => return Err(UpstreamTokenError::MissingClaim("subject")),
    };
    let at = |ptr: &Option<String>| ptr.as_deref().and_then(|p| profile.pointer(p));
    let email = clean_email(at(&mapping.email));
    let asserted = at(&mapping.email_verified) == Some(&Value::Bool(true));
    Ok(UpstreamIdentity {
        subject,
        email_verified: email.is_some() && asserted && trust,
        email,
        given_name: None,
        family_name: None,
        name: clean_name(at(&mapping.name)),
        metadata: Map::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Connection, EndpointOverrides, OidcConfig};
    use crate::model::{
        ConnectionConfig, ConnectionId, ConnectionKind, SocialConfig, SocialProvider, TenantId,
    };
    use crate::ports::ProviderMetadata;
    use crate::upstream::providers::{APPLE_ISSUER, GOOGLE_ISSUER, resolve};
    use anvil_jose::encoding::b64url;
    use anvil_jose::{Alg, SigningKey, generate_es256, generate_rs256};
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const CLIENT: &str = "client-1";
    const TID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";

    struct Key {
        signer: SigningKey,
        jwks: Jwks,
    }

    fn rsa_key() -> Key {
        let g = generate_rs256().unwrap();
        Key {
            signer: SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap(),
            jwks: Jwks {
                keys: vec![g.public_jwk],
            },
        }
    }

    fn es_key() -> Key {
        let g = generate_es256().unwrap();
        Key {
            signer: SigningKey::from_pkcs8(&g.kid, Alg::ES256, &g.pkcs8).unwrap(),
            jwks: Jwks {
                keys: vec![g.public_jwk],
            },
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW).unwrap()
    }

    fn connection(config: ConnectionConfig, trust: bool) -> Connection {
        Connection {
            id: ConnectionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            slug: "c".into(),
            display_name: "C".into(),
            enabled: true,
            config,
            secret_enc: None,
            trust_email_verified: trust,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn social(provider: SocialProvider) -> SocialConfig {
        SocialConfig {
            provider,
            client_id: CLIENT.into(),
            scopes: vec![],
            endpoints: EndpointOverrides::default(),
            microsoft_tenant: None,
            allowed_tenants: vec![],
            hosted_domains: vec![],
            apple: (provider == SocialProvider::Apple).then(|| crate::model::AppleConfig {
                team_id: "T".into(),
                key_id: "K".into(),
            }),
        }
    }

    fn resolved(s: SocialConfig) -> ResolvedProvider {
        let trust = s.provider.kind().default_email_trust();
        resolve(&connection(ConnectionConfig::Social(s), trust), None).unwrap()
    }

    fn generic(algs: &[&str], trust: bool) -> ResolvedProvider {
        let c = connection(
            ConnectionConfig::Oidc(OidcConfig {
                issuer: "https://idp.example".into(),
                client_id: CLIENT.into(),
                scopes: vec![],
                use_pkce: true,
                fetch_userinfo: false,
            }),
            trust,
        );
        let md = ProviderMetadata {
            issuer: "https://idp.example".into(),
            authorization_endpoint: "https://idp.example/a".into(),
            token_endpoint: "https://idp.example/t".into(),
            userinfo_endpoint: None,
            jwks_uri: "https://idp.example/k".into(),
            id_token_signing_alg_values_supported: algs.iter().map(|a| (*a).into()).collect(),
            authorization_response_iss_parameter_supported: false,
            code_challenge_methods_supported: vec![],
        };
        resolve(&c, Some(&md)).unwrap()
    }

    fn base(iss: &str) -> Map<String, Value> {
        let Value::Object(m) = json!({
            "iss": iss,
            "sub": "upstream-sub",
            "aud": CLIENT,
            "exp": NOW + 300,
            "iat": NOW,
            "nonce": "n-1",
        }) else {
            unreachable!()
        };
        m
    }

    fn sign(k: &Key, claims: &Map<String, Value>) -> String {
        k.signer.sign_jwt(Some("JWT"), claims).unwrap()
    }

    fn raw(header: &Value, claims: &Map<String, Value>, sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            b64url(&serde_json::to_vec(header).unwrap()),
            b64url(&serde_json::to_vec(claims).unwrap()),
            b64url(sig)
        )
    }

    fn check(
        k: &Key,
        r: &ResolvedProvider,
        claims: &Map<String, Value>,
    ) -> Result<Map<String, Value>, UpstreamTokenError> {
        validate_id_token(&sign(k, claims), &k.jwks, r, CLIENT, Some("n-1"), now())
    }

    // --- validate_id_token ---------------------------------------------------------------

    #[test]
    fn valid_google_token_both_issuer_forms() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        for iss in [GOOGLE_ISSUER, "accounts.google.com"] {
            let c = check(&k, &r, &base(iss)).unwrap();
            assert_eq!(c["sub"], "upstream-sub");
        }
    }

    #[test]
    fn google_rule_rejects_other_issuers() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        for iss in [
            "https://evil",
            "http://accounts.google.com",
            "https://accounts.google.com/",
        ] {
            assert_eq!(
                check(&k, &r, &base(iss)),
                Err(UpstreamTokenError::Issuer),
                "{iss}"
            );
        }
    }

    #[test]
    fn google_issuer_forms_only_for_google_preset() {
        let k = rsa_key();
        let r = generic(&["RS256"], false);
        assert_eq!(
            check(&k, &r, &base("accounts.google.com")),
            Err(UpstreamTokenError::Issuer)
        );
        assert!(check(&k, &r, &base("https://idp.example")).is_ok());
    }

    #[test]
    fn google_hosted_domain_allow_list() {
        let k = rsa_key();
        let mut s = social(SocialProvider::Google);
        s.hosted_domains = vec!["example.com".into()];
        let r = resolved(s);
        let mut c = base(GOOGLE_ISSUER);
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::HostedDomain));
        c.insert("hd".into(), json!("other.com"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::HostedDomain));
        c.insert("hd".into(), json!("Example.com"));
        assert!(check(&k, &r, &c).is_ok());
    }

    #[test]
    fn alg_none_rejected() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let t = raw(&json!({"alg": "none"}), &base(GOOGLE_ISSUER), b"");
        let t = t.trim_end_matches('.').to_string() + ".";
        assert_eq!(
            validate_id_token(&t, &k.jwks, &r, CLIENT, Some("n-1"), now()),
            Err(UpstreamTokenError::Signature)
        );
    }

    #[test]
    fn hs256_with_public_key_bytes_rejected() {
        // Classic key-confusion attack: HS256 "signed" with the RSA public key. anvil-jose has no
        // HMAC algorithm at all, so the allow-list rejects the header before any key lookup or
        // crypto; the signature bytes (here the public modulus) are therefore irrelevant.
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let n = k.jwks.keys[0].n.clone().unwrap();
        let t = raw(
            &json!({"alg": "HS256", "kid": k.signer.kid()}),
            &base(GOOGLE_ISSUER),
            n.as_bytes(),
        );
        assert_eq!(
            validate_id_token(&t, &k.jwks, &r, CLIENT, Some("n-1"), now()),
            Err(UpstreamTokenError::Signature)
        );
    }

    #[test]
    fn alg_outside_allow_list_rejected() {
        // Google allows RS256 only; an ES256 token with a matching key is still refused.
        let k = es_key();
        let r = resolved(social(SocialProvider::Google));
        assert_eq!(
            check(&k, &r, &base(GOOGLE_ISSUER)),
            Err(UpstreamTokenError::Signature)
        );
        let r = generic(&["ES256"], false);
        assert!(check(&k, &r, &base("https://idp.example")).is_ok());
    }

    #[test]
    fn unknown_kid_and_bad_signature_rejected() {
        let k = rsa_key();
        let other = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let t = sign(&other, &base(GOOGLE_ISSUER));
        assert_eq!(
            validate_id_token(&t, &k.jwks, &r, CLIENT, Some("n-1"), now()),
            Err(UpstreamTokenError::UnknownKey)
        );
        // Right kid, tampered payload.
        let t = sign(&k, &base(GOOGLE_ISSUER));
        let mut parts: Vec<&str> = t.split('.').collect();
        let mut evil = base(GOOGLE_ISSUER);
        evil.insert("sub".into(), json!("admin"));
        let payload = b64url(&serde_json::to_vec(&evil).unwrap());
        parts[1] = &payload;
        assert_eq!(
            validate_id_token(&parts.join("."), &k.jwks, &r, CLIENT, Some("n-1"), now()),
            Err(UpstreamTokenError::Signature)
        );
        assert_eq!(
            validate_id_token("garbage", &k.jwks, &r, CLIENT, None, now()),
            Err(UpstreamTokenError::Signature)
        );
    }

    #[test]
    fn oauth2_provider_accepts_no_id_token() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Github));
        assert_eq!(
            check(&k, &r, &base("https://github.com")),
            Err(UpstreamTokenError::Signature)
        );
    }

    #[test]
    fn microsoft_tid_template() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Microsoft));
        let iss = format!("https://login.microsoftonline.com/{TID}/v2.0");
        let mut c = base(&iss);
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::Issuer),
            "missing tid"
        );
        c.insert("tid".into(), json!(TID));
        assert!(check(&k, &r, &c).is_ok());

        // tid not matching iss.
        c.insert("tid".into(), json!("72f988bf-86f1-41af-91ab-2d7cd011db47"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer));

        // tid not a canonical UUID (would otherwise make the template match an attacker iss).
        for bad in [
            "evil",
            "",
            "{9188040d-6c67-4c5b-b112-36a304b66dad}",
            "9188040D-6C67-4C5B-B112-36A304B66DAD",
            "urn:uuid:9188040d-6c67-4c5b-b112-36a304b66dad",
        ] {
            let mut c = base(&format!("https://login.microsoftonline.com/{bad}/v2.0"));
            c.insert("tid".into(), json!(bad));
            assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer), "{bad}");
        }
        let mut c = base(&iss);
        c.insert("tid".into(), json!(42));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer));
    }

    #[test]
    fn microsoft_allowed_tenants() {
        let k = rsa_key();
        let mut s = social(SocialProvider::Microsoft);
        s.allowed_tenants = vec!["72f988bf-86f1-41af-91ab-2d7cd011db47".into()];
        let r = resolved(s);
        let mut c = base(&format!("https://login.microsoftonline.com/{TID}/v2.0"));
        c.insert("tid".into(), json!(TID));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer));
        let ok = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        let mut c = base(&format!("https://login.microsoftonline.com/{ok}/v2.0"));
        c.insert("tid".into(), json!(ok));
        assert!(check(&k, &r, &c).is_ok());
    }

    #[test]
    fn microsoft_single_tenant_still_checks_tid() {
        let k = rsa_key();
        let mut s = social(SocialProvider::Microsoft);
        s.microsoft_tenant = Some(TID.into());
        let r = resolved(s);
        let c = base(&format!("https://login.microsoftonline.com/{TID}/v2.0"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer));
        let mut c = c;
        c.insert("tid".into(), json!(TID));
        assert!(check(&k, &r, &c).is_ok());
    }

    #[test]
    fn audience_rules() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let mut c = base(GOOGLE_ISSUER);
        c.insert("aud".into(), json!("other"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.insert("aud".into(), json!(["other", "x"]));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.insert("aud".into(), json!([CLIENT, "other"]));
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::Audience),
            "several audiences require azp"
        );
        c.insert("azp".into(), json!("other"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.insert("azp".into(), json!(CLIENT));
        assert!(check(&k, &r, &c).is_ok());
        c.insert("aud".into(), json!([CLIENT]));
        assert!(check(&k, &r, &c).is_ok());
        let mut c = base(GOOGLE_ISSUER);
        c.insert("azp".into(), json!("someone-else"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.remove("azp");
        c.remove("aud");
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.insert("aud".into(), json!(7));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
    }

    #[test]
    fn time_rules() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let mut c = base(GOOGLE_ISSUER);
        c.insert("exp".into(), json!(NOW - 61));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Expired));
        c.insert("exp".into(), json!(NOW - 60));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Expired));
        c.insert("exp".into(), json!(NOW - 59));
        assert!(check(&k, &r, &c).is_ok(), "within skew");
        c.remove("exp");
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::MissingClaim("exp"))
        );

        let mut c = base(GOOGLE_ISSUER);
        c.insert("iat".into(), json!(NOW + 61));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::IssuedInFuture));
        c.insert("iat".into(), json!(NOW + 60));
        assert!(check(&k, &r, &c).is_ok());
        c.remove("iat");
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::MissingClaim("iat"))
        );
        c.insert("iat".into(), json!("now"));
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::MissingClaim("iat"))
        );

        let mut c = base(GOOGLE_ISSUER);
        c.insert("nbf".into(), json!(NOW + 120));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::IssuedInFuture));
    }

    #[test]
    fn nonce_rules() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let mut c = base(GOOGLE_ISSUER);
        c.insert("nonce".into(), json!("other"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Nonce));
        c.remove("nonce");
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Nonce));
        // No nonce expected (e.g. Apple without nonce): absence accepted.
        let t = sign(&k, &c);
        assert!(validate_id_token(&t, &k.jwks, &r, CLIENT, None, now()).is_ok());
    }

    #[test]
    fn subject_required() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let mut c = base(GOOGLE_ISSUER);
        c.insert("sub".into(), json!(""));
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::MissingClaim("sub"))
        );
        c.insert("sub".into(), json!(12));
        assert_eq!(
            check(&k, &r, &c),
            Err(UpstreamTokenError::MissingClaim("sub"))
        );
    }

    #[test]
    fn check_order_signature_before_issuer_before_audience() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Google));
        let mut c = base("https://evil");
        c.insert("aud".into(), json!("other"));
        c.insert("exp".into(), json!(0));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Issuer));
        let other = rsa_key();
        assert_eq!(
            validate_id_token(&sign(&other, &c), &k.jwks, &r, CLIENT, Some("n-1"), now()),
            Err(UpstreamTokenError::UnknownKey)
        );
        let mut c = base(GOOGLE_ISSUER);
        c.insert("aud".into(), json!("other"));
        c.insert("exp".into(), json!(0));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Audience));
        c.insert("aud".into(), json!(CLIENT));
        c.insert("nonce".into(), json!("x"));
        assert_eq!(check(&k, &r, &c), Err(UpstreamTokenError::Expired));
    }

    #[test]
    fn apple_issuer_and_override() {
        let k = rsa_key();
        let r = resolved(social(SocialProvider::Apple));
        assert!(check(&k, &r, &base(APPLE_ISSUER)).is_ok());
        assert_eq!(
            check(&k, &r, &base("http://127.0.0.1:9000/apple")),
            Err(UpstreamTokenError::Issuer)
        );
        let mut s = social(SocialProvider::Apple);
        s.endpoints.issuer = Some("http://127.0.0.1:9000/apple".into());
        let r = resolved(s);
        assert!(check(&k, &r, &base("http://127.0.0.1:9000/apple")).is_ok());
        assert_eq!(
            check(&k, &r, &base(APPLE_ISSUER)),
            Err(UpstreamTokenError::Issuer)
        );
    }

    // --- normalisation ---------------------------------------------------------------------

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn oidc_email_verified_requires_trust_and_boolean_true() {
        let r = resolved(social(SocialProvider::Google));
        let c = obj(
            json!({"sub": "s", "email": "A@Example.com ", "email_verified": true,
            "given_name": "Ada", "family_name": "Lovelace", "name": "Ada Lovelace", "hd": "example.com"}),
        );
        let id = normalise_oidc(&c, &r, true).unwrap();
        assert_eq!(id.subject, "s");
        assert_eq!(id.email.as_deref(), Some("A@Example.com"));
        assert!(id.email_verified);
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(id.metadata["hd"], "example.com");

        assert!(
            !normalise_oidc(&c, &r, false).unwrap().email_verified,
            "untrusted"
        );
        let c2 = obj(json!({"sub": "s", "email": "a@b.example", "email_verified": "true"}));
        assert!(
            !normalise_oidc(&c2, &r, true).unwrap().email_verified,
            "string booleans only for Apple"
        );
        let c3 = obj(json!({"sub": "s", "email_verified": true}));
        let id = normalise_oidc(&c3, &r, true).unwrap();
        assert_eq!(id.email, None);
        assert!(!id.email_verified, "no email -> not verified");
        assert_eq!(
            normalise_oidc(&obj(json!({"email": "a@b"})), &r, true),
            Err(UpstreamTokenError::MissingClaim("sub"))
        );
    }

    #[test]
    fn microsoft_email_never_verified_and_ids_kept() {
        let s = social(SocialProvider::Microsoft);
        let r = resolve(&connection(ConnectionConfig::Social(s), true), None).unwrap();
        assert_eq!(r.kind, ConnectionKind::Microsoft);
        let c = obj(
            json!({"sub": "s", "email": "a@b.example", "email_verified": true,
            "tid": TID, "oid": "00000000-0000-0000-0000-000000000001"}),
        );
        let id = normalise_oidc(&c, &r, true).unwrap();
        assert!(!id.email_verified);
        assert_eq!(id.metadata["tid"], TID);
        assert_eq!(id.metadata["oid"], "00000000-0000-0000-0000-000000000001");
    }

    #[test]
    fn generic_oidc_trust_flag() {
        let r = generic(&["RS256"], false);
        let c = obj(json!({"sub": "s", "email": "a@b.example", "email_verified": true}));
        assert!(!normalise_oidc(&c, &r, false).unwrap().email_verified);
        let r = generic(&["RS256"], true);
        assert!(normalise_oidc(&c, &r, true).unwrap().email_verified);
    }

    #[test]
    fn names_sanitised() {
        let r = resolved(social(SocialProvider::Google));
        let long = "x".repeat(500);
        let c = obj(
            json!({"sub": "s", "given_name": "  A\u{0}d\u{1b}a\n ", "family_name": long, "name": "   "}),
        );
        let id = normalise_oidc(&c, &r, true).unwrap();
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(
            id.family_name.as_ref().map(|s| s.chars().count()),
            Some(MAX_NAME_CHARS)
        );
        assert_eq!(id.name, None);
    }

    #[test]
    fn emails_with_control_chars_or_too_long_dropped() {
        let r = resolved(social(SocialProvider::Google));
        let c = obj(json!({"sub": "s", "email": "a@b.example\r\nBcc: x", "email_verified": true}));
        let id = normalise_oidc(&c, &r, true).unwrap();
        assert_eq!(id.email, None);
        assert!(!id.email_verified);
        let long = format!("{}@b.example", "a".repeat(400));
        let c = obj(json!({"sub": "s", "email": long, "email_verified": true}));
        assert_eq!(normalise_oidc(&c, &r, true).unwrap().email, None);
        let c = obj(json!({"sub": "s", "email": "no-at-sign", "email_verified": true}));
        assert_eq!(normalise_oidc(&c, &r, true).unwrap().email, None);
    }

    #[test]
    fn apple_string_booleans() {
        for (v, expect) in [
            (json!(true), true),
            (json!("true"), true),
            (json!(false), false),
            (json!("false"), false),
            (json!("TRUE"), false),
            (json!(1), false),
            (Value::Null, false),
        ] {
            let c = obj(
                json!({"sub": "001.abc", "email": "x@privaterelay.appleid.com", "email_verified": v}),
            );
            let id = normalise_apple(&c, None, true).unwrap();
            assert_eq!(id.email_verified, expect, "{v:?}");
            assert!(!normalise_apple(&c, None, false).unwrap().email_verified);
        }
    }

    #[test]
    fn apple_user_json_first_login() {
        let c = obj(json!({"sub": "001.abc", "email": "x@b.example", "email_verified": "true"}));
        let user = r#"{"name":{"firstName":"  Ada ","lastName":"Love\u0007lace"},"email":"attacker@evil.example"}"#;
        let id = normalise_apple(&c, Some(user), true).unwrap();
        assert_eq!(id.given_name.as_deref(), Some("Ada"));
        assert_eq!(id.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(id.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(
            id.email.as_deref(),
            Some("x@b.example"),
            "email only from the signed ID token"
        );

        let long = format!(r#"{{"name":{{"firstName":"{}"}}}}"#, "y".repeat(1000));
        let id = normalise_apple(&c, Some(&long), true).unwrap();
        assert_eq!(
            id.given_name.map(|s| s.chars().count()),
            Some(MAX_NAME_CHARS)
        );
        assert_eq!(id.family_name, None);

        for bad in [
            "not json",
            "[]",
            r#"{"name":"Ada"}"#,
            r#"{"name":{"firstName":5}}"#,
        ] {
            let id = normalise_apple(&c, Some(bad), true).unwrap();
            assert_eq!(id.given_name, None, "{bad}");
            assert_eq!(id.name, None, "{bad}");
        }
        assert_eq!(
            normalise_apple(&obj(json!({"email": "x@b"})), None, true),
            Err(UpstreamTokenError::MissingClaim("sub"))
        );
    }

    #[test]
    fn github_numeric_id_and_verified_primary_email() {
        let user = json!({"id": 583231, "login": "octocat", "name": "The Octocat"});
        let emails = json!([
            {"email": "unverified-primary@x.example", "primary": true, "verified": false},
            {"email": "other@x.example", "primary": false, "verified": true},
        ]);
        let id = normalise_github(&user, &emails, true).unwrap();
        assert_eq!(id.subject, "583231");
        assert_eq!(id.email, None, "no entry is primary AND verified");
        assert!(!id.email_verified);
        assert_eq!(id.name.as_deref(), Some("The Octocat"));
        assert_eq!(id.metadata["login"], "octocat");

        let emails = json!([
            {"email": "other@x.example", "primary": false, "verified": true},
            {"email": "octo@x.example", "primary": true, "verified": true},
        ]);
        let id = normalise_github(&user, &emails, true).unwrap();
        assert_eq!(id.email.as_deref(), Some("octo@x.example"));
        assert!(id.email_verified);
        assert!(
            !normalise_github(&user, &emails, false)
                .unwrap()
                .email_verified
        );

        // Profile `email` is never used.
        let user2 = json!({"id": 1, "login": "x", "email": "profile@x.example"});
        assert_eq!(
            normalise_github(&user2, &json!([]), true).unwrap().email,
            None
        );
        // Garbage emails payload: no email.
        assert_eq!(
            normalise_github(&user2, &json!({"message": "x"}), true)
                .unwrap()
                .email,
            None
        );

        for bad in [
            json!({"login": "octocat"}),
            json!({"id": "583231", "login": "o"}),
            json!({"id": -1}),
            json!({"id": 1.5}),
        ] {
            assert_eq!(
                normalise_github(&bad, &emails, true),
                Err(UpstreamTokenError::MissingClaim("id")),
                "{bad}"
            );
        }
    }

    fn mapping(verified: Option<&str>) -> ClaimMapping {
        ClaimMapping {
            subject: "/data/id".into(),
            email: Some("/data/mail".into()),
            email_verified: verified.map(Into::into),
            name: Some("/data/display".into()),
        }
    }

    #[test]
    fn oauth2_mapping() {
        let p = json!({"data": {"id": 42, "mail": "a@b.example", "ok": true, "display": "A B"}});
        let id = normalise_oauth2(&p, &mapping(None), true).unwrap();
        assert_eq!(id.subject, "42");
        assert_eq!(id.email.as_deref(), Some("a@b.example"));
        assert!(!id.email_verified, "verified not mapped");
        assert_eq!(id.name.as_deref(), Some("A B"));

        let id = normalise_oauth2(&p, &mapping(Some("/data/ok")), true).unwrap();
        assert!(id.email_verified);
        let id = normalise_oauth2(&p, &mapping(Some("/data/ok")), false).unwrap();
        assert!(!id.email_verified, "untrusted");
        let id = normalise_oauth2(&p, &mapping(Some("/data/mail")), true).unwrap();
        assert!(!id.email_verified, "non-boolean");

        let p2 = json!({"data": {"id": "abc"}});
        assert_eq!(
            normalise_oauth2(&p2, &mapping(None), true).unwrap().subject,
            "abc"
        );
        for bad in [
            json!({"data": {}}),
            json!({"data": {"id": ""}}),
            json!({"data": {"id": true}}),
            json!({"data": {"id": 1.5}}),
        ] {
            assert_eq!(
                normalise_oauth2(&bad, &mapping(None), true),
                Err(UpstreamTokenError::MissingClaim("subject")),
                "{bad}"
            );
        }
        let mut m = mapping(None);
        m.subject = "data/id".into();
        assert_eq!(
            normalise_oauth2(&p, &m, true),
            Err(UpstreamTokenError::MissingClaim("subject")),
            "invalid pointer"
        );
    }

    proptest::proptest! {
        #[test]
        fn untrusted_never_verified(sub in "[a-z0-9]{1,16}", email in "[a-z]{1,8}@[a-z]{1,8}\\.example", ev in proptest::bool::ANY) {
            let r = generic(&["RS256"], true);
            let c = obj(json!({"sub": sub, "email": email, "email_verified": ev}));
            proptest::prop_assert!(!normalise_oidc(&c, &r, false).unwrap().email_verified);
            proptest::prop_assert!(!normalise_apple(&c, None, false).unwrap().email_verified);
            let p = json!({"data": {"id": sub, "mail": email, "ok": ev}});
            proptest::prop_assert!(!normalise_oauth2(&p, &mapping(Some("/data/ok")), false).unwrap().email_verified);
        }

        #[test]
        fn sanitised_names_bounded_and_clean(s in "\\PC{0,400}|[\\x00-\\x1f\\x7f]{0,20}") {
            let r = generic(&["RS256"], true);
            let c = obj(json!({"sub": "s", "name": s}));
            if let Some(n) = normalise_oidc(&c, &r, true).unwrap().name {
                proptest::prop_assert!(n.chars().count() <= MAX_NAME_CHARS);
                proptest::prop_assert!(!n.chars().any(char::is_control));
                proptest::prop_assert_eq!(n.trim(), n.as_str());
                proptest::prop_assert!(!n.is_empty());
            }
        }
    }
}
