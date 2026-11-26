//! Claim builders for ID tokens, access tokens and UserInfo (OIDC Core §2, §5; RFC 9068).
//!
//! Pure functions: no I/O, no clock, no randomness. Callers pass `now` and the `jti`.
//! Scope claims (`profile`, `email`, `address`, `phone`) go to UserInfo only; the ID token
//! carries the protocol claims plus whatever `claims.id_token` requested.

use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use crate::model::{RequestedClaim, Scope, TokenFamilyId, User};
use crate::oauth::resource::audience;
use crate::policy::claims_mapping::is_reserved_claim;

/// ID token lifetime (1 hour).
pub const ID_TOKEN_TTL: Duration = Duration::hours(1);
/// Access token lifetime (10 minutes).
pub const ACCESS_TOKEN_TTL: Duration = Duration::minutes(10);

/// `profile` scope claims (OIDC Core §5.4), excluding `updated_at` which is added separately.
const PROFILE_CLAIMS: &[&str] = &[
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
];

/// The other claims the standard scopes release (OIDC Core §5.4): `updated_at` (`profile`),
/// `email`, `address` and `phone` claims.
const CONTACT_CLAIMS: &[&str] = &[
    "updated_at",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
];

/// Whether `name` is a user claim the standard scopes release ([`scope_claims`]).
fn is_standard_user_claim(name: &str) -> bool {
    PROFILE_CLAIMS.contains(&name) || CONTACT_CLAIMS.contains(&name)
}

/// Whether `name` is a protocol claim the token builders always control: a reserved claim
/// ([`is_reserved_claim`], the single list in `policy::claims_mapping`) that is not a standard
/// user claim. ID token extras (`claims.id_token` requests, mapped claims) never set these.
fn is_protocol_claim(name: &str) -> bool {
    is_reserved_claim(name) && !is_standard_user_claim(name)
}

/// Adds `extra` (mapped role, permission and attribute claims) to built access token claims.
/// Reserved claims ([`is_reserved_claim`]) and names already present are skipped, so extras
/// can never change `sub`, `scope`, `aud`, ... or add user profile claims to an access token.
pub fn merge_access_token_extras(claims: &mut Map<String, Value>, extra: Map<String, Value>) {
    for (k, v) in extra {
        if !is_reserved_claim(&k) && !claims.contains_key(&k) {
            claims.insert(k, v);
        }
    }
}

fn opt_str(v: Option<&String>) -> Option<Value> {
    v.map(|s| Value::String(s.clone()))
}

fn address_value(user: &User) -> Option<Value> {
    let a = user.claims.address.as_ref()?;
    let mut m = Map::new();
    for (k, v) in [
        ("formatted", &a.formatted),
        ("street_address", &a.street_address),
        ("locality", &a.locality),
        ("region", &a.region),
        ("postal_code", &a.postal_code),
        ("country", &a.country),
    ] {
        if let Some(v) = v {
            m.insert(k.to_owned(), Value::String(v.clone()));
        }
    }
    if m.is_empty() {
        None
    } else {
        Some(Value::Object(m))
    }
}

/// The value of one standard claim for `user`, or `None` when the user has no value.
/// `sub` is not handled here: callers always set it themselves.
fn claim_value(user: &User, name: &str) -> Option<Value> {
    let c = &user.claims;
    match name {
        "name" => opt_str(c.name.as_ref()),
        "family_name" => opt_str(c.family_name.as_ref()),
        "given_name" => opt_str(c.given_name.as_ref()),
        "middle_name" => opt_str(c.middle_name.as_ref()),
        "nickname" => opt_str(c.nickname.as_ref()),
        "preferred_username" => opt_str(c.preferred_username.as_ref().or(user.username.as_ref())),
        "profile" => opt_str(c.profile.as_ref()),
        "picture" => opt_str(c.picture.as_ref()),
        "website" => opt_str(c.website.as_ref()),
        "gender" => opt_str(c.gender.as_ref()),
        "birthdate" => opt_str(c.birthdate.as_ref()),
        "zoneinfo" => opt_str(c.zoneinfo.as_ref()),
        "locale" => opt_str(c.locale.as_ref()),
        "updated_at" => Some(Value::from(user.updated_at.unix_timestamp())),
        "email" => Some(Value::String(user.email.clone())),
        "email_verified" => Some(Value::Bool(user.email_verified)),
        "address" => address_value(user),
        "phone_number" => opt_str(c.phone_number.as_ref()),
        "phone_number_verified" => c
            .phone_number
            .as_ref()
            .map(|_| Value::Bool(c.phone_number_verified)),
        _ => None,
    }
}

fn put(map: &mut Map<String, Value>, user: &User, name: &str) {
    if let Some(v) = claim_value(user, name) {
        map.insert(name.to_owned(), v);
    }
}

/// Claims released by the standard scopes (OIDC Core §5.4). Fields without a value are omitted,
/// never `null`. `email_verified` and `phone_number_verified` are booleans, `address` is an
/// object and `updated_at` is a number (seconds since the epoch).
pub fn scope_claims(user: &User, scope: &Scope) -> Map<String, Value> {
    let mut m = Map::new();
    if scope.contains("profile") {
        for name in PROFILE_CLAIMS {
            put(&mut m, user, name);
        }
        put(&mut m, user, "updated_at");
    }
    if scope.contains("email") {
        put(&mut m, user, "email");
        put(&mut m, user, "email_verified");
    }
    if scope.contains("address") {
        put(&mut m, user, "address");
    }
    if scope.contains("phone") {
        put(&mut m, user, "phone_number");
        put(&mut m, user, "phone_number_verified");
    }
    m
}

/// Claims individually requested through the `claims` parameter (OIDC Core §5.5). Unknown claims
/// and claims without a value are omitted. `sub` is never produced here.
pub fn requested_claims(user: &User, req: &[RequestedClaim]) -> Map<String, Value> {
    let mut m = Map::new();
    for r in req {
        if r.name != "sub" {
            put(&mut m, user, &r.name);
        }
    }
    m
}

/// Input of [`id_token_claims`].
#[derive(Debug, Clone)]
pub struct IdTokenInput<'a> {
    pub issuer: &'a str,
    pub sub: &'a str,
    pub client_id: &'a str,
    pub now: OffsetDateTime,
    pub auth_time: Option<OffsetDateTime>,
    /// Only on the first ID token of an authorization; refreshed ID tokens carry no nonce.
    pub nonce: Option<&'a str>,
    pub acr: Option<&'a str>,
    pub amr: &'a [String],
    pub sid: Option<String>,
    pub at_hash: Option<String>,
    /// `claims.id_token` requests; protocol claims are never overridden by these.
    pub extra: Map<String, Value>,
}

/// ID token claims: `iss`, `sub`, `aud` (array with the client id), `azp`, `iat`,
/// `exp` (= `iat` + 1 h), `auth_time`, `nonce`, `acr`, `amr`, `sid`, `at_hash` when known.
pub fn id_token_claims(input: &IdTokenInput) -> Map<String, Value> {
    let mut m = Map::new();
    for (k, v) in &input.extra {
        if !is_protocol_claim(k) {
            m.insert(k.clone(), v.clone());
        }
    }
    let iat = input.now.unix_timestamp();
    m.insert("iss".into(), input.issuer.into());
    m.insert("sub".into(), input.sub.into());
    m.insert(
        "aud".into(),
        Value::Array(vec![Value::String(input.client_id.to_owned())]),
    );
    m.insert("azp".into(), input.client_id.into());
    m.insert("iat".into(), iat.into());
    m.insert(
        "exp".into(),
        (input.now + ID_TOKEN_TTL).unix_timestamp().into(),
    );
    if let Some(t) = input.auth_time {
        m.insert("auth_time".into(), t.unix_timestamp().into());
    }
    if let Some(n) = input.nonce {
        m.insert("nonce".into(), n.into());
    }
    if let Some(acr) = input.acr {
        m.insert("acr".into(), acr.into());
    }
    if !input.amr.is_empty() {
        m.insert(
            "amr".into(),
            Value::Array(input.amr.iter().cloned().map(Value::String).collect()),
        );
    }
    if let Some(sid) = &input.sid {
        m.insert("sid".into(), sid.clone().into());
    }
    if let Some(h) = &input.at_hash {
        m.insert("at_hash".into(), h.clone().into());
    }
    m
}

/// Input of [`access_token_claims`].
#[derive(Debug, Clone)]
pub struct AccessTokenInput<'a> {
    pub issuer: &'a str,
    /// The user id, or the client id for client credentials.
    pub sub: &'a str,
    pub client_id: &'a str,
    pub scope: &'a Scope,
    pub now: OffsetDateTime,
    /// Random token id (the caller generates it).
    pub jti: String,
    /// The token family; `None` for client credentials.
    pub family_id: Option<TokenFamilyId>,
    pub auth_time: Option<OffsetDateTime>,
    pub acr: Option<&'a str>,
    /// The RFC 8707 resources selected for this token (empty = none requested).
    pub resource: &'a [String],
}

/// RFC 9068 access token claims. `aud` is the selected resource (a string), several resources
/// (an array), or the client id when no resource was selected (RFC 8707 §2, RFC 9068 §3);
/// `fid` carries the token family so revoking the family invalidates the token. The `at+jwt`
/// `typ` header is set by the signer call, not here.
pub fn access_token_claims(input: &AccessTokenInput) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("iss".into(), input.issuer.into());
    m.insert("sub".into(), input.sub.into());
    m.insert(
        "aud".into(),
        serde_json::to_value(audience(input.resource, input.client_id))
            .unwrap_or_else(|_| Value::String(input.client_id.to_owned())),
    );
    m.insert("client_id".into(), input.client_id.into());
    m.insert("scope".into(), input.scope.to_string().into());
    m.insert("iat".into(), input.now.unix_timestamp().into());
    m.insert(
        "exp".into(),
        (input.now + ACCESS_TOKEN_TTL).unix_timestamp().into(),
    );
    m.insert("jti".into(), input.jti.clone().into());
    if let Some(fid) = input.family_id {
        m.insert("fid".into(), fid.to_string().into());
    }
    if let Some(t) = input.auth_time {
        m.insert("auth_time".into(), t.unix_timestamp().into());
    }
    if let Some(acr) = input.acr {
        m.insert("acr".into(), acr.into());
    }
    m
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{ACR_PWD, AMR_PWD, Address, StandardClaims, TenantId, UserId, UserStatus};

    pub(crate) fn user(claims: StandardClaims) -> User {
        User {
            id: UserId::new_v7(),
            tenant_id: TenantId::new_v7(),
            email: "alice@example.test".into(),
            email_verified: true,
            username: None,
            claims,
            status: UserStatus::Active,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            updated_at: OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap(),
            last_login_at: None,
        }
    }

    fn full_claims() -> StandardClaims {
        StandardClaims {
            name: Some("Alice A".into()),
            given_name: Some("Alice".into()),
            phone_number: Some("+15550100".into()),
            phone_number_verified: true,
            address: Some(Address {
                locality: Some("Springfield".into()),
                country: Some("US".into()),
                ..Address::default()
            }),
            ..StandardClaims::default()
        }
    }

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    #[test]
    fn email_scope_releases_email_and_bool_verified_only() {
        let u = user(full_claims());
        let m = scope_claims(&u, &scope("openid email"));
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m["email"], "alice@example.test");
        assert_eq!(m["email_verified"], Value::Bool(true));
    }

    #[test]
    fn profile_scope_updated_at_is_a_number() {
        let u = user(full_claims());
        let m = scope_claims(&u, &scope("openid profile"));
        assert_eq!(m["updated_at"], Value::from(1_700_000_500_i64));
        assert!(m["updated_at"].is_number());
        assert_eq!(m["name"], "Alice A");
        assert_eq!(m["given_name"], "Alice");
        assert!(!m.contains_key("family_name"), "absent claims are omitted");
        assert!(!m.contains_key("email"));
    }

    #[test]
    fn address_scope_is_an_object() {
        let u = user(full_claims());
        let m = scope_claims(&u, &scope("address"));
        let a = m["address"].as_object().expect("address is an object");
        assert_eq!(a["locality"], "Springfield");
        assert!(!a.contains_key("region"));
    }

    #[test]
    fn phone_scope_bool_verified() {
        let u = user(full_claims());
        let m = scope_claims(&u, &scope("phone"));
        assert_eq!(m["phone_number"], "+15550100");
        assert_eq!(m["phone_number_verified"], Value::Bool(true));
    }

    #[test]
    fn empty_claims_are_omitted_not_null() {
        let u = user(StandardClaims::default());
        let m = scope_claims(&u, &scope("openid profile address phone"));
        assert_eq!(m.len(), 1, "only updated_at remains: {m:?}");
        assert!(m.contains_key("updated_at"));
        assert!(m.values().all(|v| !v.is_null()));
    }

    #[test]
    fn preferred_username_falls_back_to_username() {
        let mut u = user(StandardClaims::default());
        u.username = Some("alice".into());
        let m = scope_claims(&u, &scope("profile"));
        assert_eq!(m["preferred_username"], "alice");
    }

    #[test]
    fn requested_claims_known_with_value_only() {
        let u = user(full_claims());
        let req = |n: &str| RequestedClaim {
            name: n.into(),
            essential: false,
            values: vec![],
        };
        let m = requested_claims(
            &u,
            &[
                req("email"),
                req("family_name"),
                req("bogus"),
                req("sub"),
                req("name"),
            ],
        );
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!(m["email"], "alice@example.test");
        assert_eq!(m["name"], "Alice A");
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn id_token_has_all_protocol_claims_with_types() {
        let amr = vec![AMR_PWD.to_owned()];
        let mut extra = Map::new();
        extra.insert("email".into(), "x@example.test".into());
        extra.insert("iss".into(), "https://evil.test".into());
        let m = id_token_claims(&IdTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            now: now(),
            auth_time: Some(now() - Duration::minutes(5)),
            nonce: Some("n-0S6"),
            acr: Some(ACR_PWD),
            amr: &amr,
            sid: Some("sid-1".into()),
            at_hash: Some("hash".into()),
            extra,
        });
        assert_eq!(
            m["iss"], "https://op.test",
            "extras never override protocol claims"
        );
        assert_eq!(m["sub"], "user-1");
        assert_eq!(m["aud"], serde_json::json!(["rp"]));
        assert_eq!(m["azp"], "rp");
        assert!(m["iat"].is_i64() && m["exp"].is_i64() && m["auth_time"].is_i64());
        assert_eq!(
            m["exp"].as_i64().unwrap() - m["iat"].as_i64().unwrap(),
            3600
        );
        assert_eq!(m["auth_time"], now().unix_timestamp() - 300);
        assert_eq!(m["nonce"], "n-0S6");
        assert_eq!(m["acr"], ACR_PWD);
        assert_eq!(m["amr"], serde_json::json!(["pwd"]));
        assert_eq!(m["sid"], "sid-1");
        assert_eq!(m["at_hash"], "hash");
        assert_eq!(m["email"], "x@example.test");
    }

    #[test]
    fn id_token_extras_never_set_reserved_protocol_claims() {
        // Every reserved claim that is not a standard user claim is dropped from the extras,
        // even when the builder itself leaves it unset (no nonce, sid, acr, ... here).
        let mut extra = Map::new();
        for k in crate::policy::claims_mapping::RESERVED_CLAIMS {
            extra.insert((*k).to_owned(), Value::from("forged"));
        }
        extra.insert("roles".into(), serde_json::json!(["editor"]));
        let m = id_token_claims(&IdTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            now: now(),
            auth_time: None,
            nonce: None,
            acr: None,
            amr: &[],
            sid: None,
            at_hash: None,
            extra,
        });
        for k in [
            "nonce",
            "sid",
            "acr",
            "amr",
            "auth_time",
            "s_hash",
            "client_id",
            "scope",
            "fid",
            "nbf",
            "cnf",
        ] {
            assert!(!m.contains_key(k), "{k} must not come from the extras");
        }
        assert_eq!(m["sub"], "user-1");
        assert_eq!(m["roles"], serde_json::json!(["editor"]));
        // Standard user claims requested through `claims.id_token` still pass.
        assert_eq!(m["email"], "forged");
    }

    #[test]
    fn access_token_extras_never_override_or_add_reserved_claims() {
        let s = scope("openid");
        let mut m = access_token_claims(&AccessTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            scope: &s,
            now: now(),
            jti: "j".into(),
            family_id: None,
            auth_time: None,
            acr: None,
            resource: &[],
        });
        let mut extra = Map::new();
        for k in ["sub", "scope", "aud", "email", "Sub", "acr"] {
            extra.insert(k.into(), Value::from("forged"));
        }
        extra.insert("permissions".into(), serde_json::json!(["docs:write"]));
        merge_access_token_extras(&mut m, extra);
        assert_eq!(m["sub"], "user-1");
        assert_eq!(m["scope"], "openid");
        assert!(!m.contains_key("email"));
        assert!(!m.contains_key("Sub"));
        assert!(!m.contains_key("acr"));
        assert_eq!(m["permissions"], serde_json::json!(["docs:write"]));
    }

    #[test]
    fn id_token_omits_nonce_when_none() {
        let m = id_token_claims(&IdTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            now: now(),
            auth_time: None,
            nonce: None,
            acr: None,
            amr: &[],
            sid: None,
            at_hash: None,
            extra: Map::new(),
        });
        for k in ["nonce", "auth_time", "acr", "amr", "sid", "at_hash"] {
            assert!(!m.contains_key(k), "{k} must be omitted");
        }
    }

    #[test]
    fn access_token_claims_user_and_client_credentials() {
        let s = scope("openid profile");
        let fid = TokenFamilyId::new_v7();
        let m = access_token_claims(&AccessTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            scope: &s,
            now: now(),
            jti: "j1".into(),
            family_id: Some(fid),
            auth_time: Some(now()),
            acr: Some(ACR_PWD),
            resource: &[],
        });
        assert_eq!(m["aud"], "rp");
        assert_eq!(m["client_id"], "rp");
        assert_eq!(m["scope"], "openid profile");
        assert_eq!(m["fid"], fid.to_string());
        assert_eq!(m["jti"], "j1");
        assert_eq!(m["exp"].as_i64().unwrap() - m["iat"].as_i64().unwrap(), 600);
        assert_eq!(m["acr"], ACR_PWD);

        let cc_scope = scope("api");
        let cc = access_token_claims(&AccessTokenInput {
            issuer: "https://op.test",
            sub: "svc",
            client_id: "svc",
            scope: &cc_scope,
            now: now(),
            jti: "j2".into(),
            family_id: None,
            auth_time: None,
            acr: None,
            resource: &[],
        });
        assert_eq!(cc["sub"], "svc");
        assert_eq!(cc["aud"], "svc");
        assert!(!cc.contains_key("fid"));
        assert!(!cc.contains_key("auth_time"));
    }

    #[test]
    fn access_token_aud_follows_the_selected_resources() {
        let s = scope("openid");
        let api = "https://api.example.test".to_owned();
        let mcp = "https://mcp.example.test/mcp".to_owned();
        let claims = |resource: &[String]| {
            access_token_claims(&AccessTokenInput {
                issuer: "https://op.test",
                sub: "user-1",
                client_id: "rp",
                scope: &s,
                now: now(),
                jti: "j".into(),
                family_id: None,
                auth_time: None,
                acr: None,
                resource,
            })
        };
        assert_eq!(claims(&[])["aud"], serde_json::json!("rp"));
        assert_eq!(
            claims(std::slice::from_ref(&api))["aud"],
            serde_json::json!(api)
        );
        let both = claims(&[api.clone(), mcp.clone()]);
        assert_eq!(both["aud"], serde_json::json!([api, mcp]));
        // client_id stays the client whatever the audience.
        assert_eq!(both["client_id"], "rp");
    }

    #[test]
    fn id_token_aud_is_always_the_client() {
        // The ID token input has no resources at all: its aud is the client (OIDC Core §2).
        let m = id_token_claims(&IdTokenInput {
            issuer: "https://op.test",
            sub: "user-1",
            client_id: "rp",
            now: now(),
            auth_time: None,
            nonce: None,
            acr: None,
            amr: &[],
            sid: None,
            at_hash: None,
            extra: Map::new(),
        });
        assert_eq!(m["aud"], serde_json::json!(["rp"]));
    }
}
