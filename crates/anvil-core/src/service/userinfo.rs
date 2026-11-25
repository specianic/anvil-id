//! Access-token verification (the single implementation, shared by UserInfo, introspection and
//! the admin API) and the UserInfo endpoint (OIDC Core §5.3, RFC 6750, RFC 9068 §4).
//!
//! Access tokens are either RFC 9068 JWTs or opaque 256-bit random strings (per client
//! `token_format`). A token with the compact JWS shape (two dots) takes the JWT path; anything
//! else is looked up by its SHA-256 in the access-token table ([`AccessTokenVerifier::verify`]).

use std::sync::Arc;

use anvil_jose::encoding::secret_hash;
use anvil_jose::jwk::Jwks;
use anvil_jose::op_token::{ExpiryCheck, verify_op_token};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::error::CoreError;
use crate::model::{
    AccessTokenRecord, Scope, SecretHash, Tenant, TenantId, TokenFamily, TokenFamilyId, UserStatus,
};
use crate::ports::{Clock, Storage};
use crate::service::claims::{requested_claims, scope_claims};
use crate::service::key::published_jwks;
use crate::service::token::ACCESS_TOKEN_TYP;

/// The verified contents of an access token this OP issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenClaims {
    /// User id, or the client id for client-credentials tokens.
    pub sub: String,
    pub client_id: String,
    pub scope: Scope,
    /// Token family; `None` for client-credentials tokens (no user).
    pub family_id: Option<TokenFamilyId>,
    pub exp: OffsetDateTime,
    /// Issue time (`iat`, or the creation time of an opaque token).
    pub iat: Option<OffsetDateTime>,
    /// `jti` of a JWT access token; `None` for opaque tokens.
    pub jti: Option<String>,
}

/// Whether `token` has the compact JWS shape (three dot-separated parts). Opaque access tokens
/// are base64url and never contain a dot.
pub fn is_jwt_shaped(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Parses a token's `fid` claim.
pub fn parse_family_id(raw: &str) -> Option<TokenFamilyId> {
    uuid::Uuid::parse_str(raw).ok().map(TokenFamilyId)
}

fn invalid_token() -> CoreError {
    // One description: never tell a caller why a token was refused.
    CoreError::InvalidToken("the access token is invalid or expired".to_owned())
}

/// Signature, `typ` (`at+jwt`, so ID tokens are refused), `iss` (other tenants' tokens are
/// refused) and `exp`, then the claim shapes. Pure; storage checks follow in
/// [`AccessTokenVerifier::verify`].
pub fn verify_access_token_jwt(
    token: &str,
    published: &Jwks,
    issuer: &str,
    now: OffsetDateTime,
) -> Result<AccessTokenClaims, CoreError> {
    let jwt = verify_op_token(
        token,
        published,
        issuer,
        Some(ACCESS_TOKEN_TYP),
        ExpiryCheck::Enforce,
        now,
    )
    .map_err(|_| invalid_token())?;
    let c = &jwt.claims;
    let str_claim = |name: &str| {
        c.get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(invalid_token)
    };
    let sub = str_claim("sub")?;
    let client_id = str_claim("client_id")?;
    let scope = match c.get("scope") {
        None => Scope::default(),
        Some(Value::String(s)) if s.is_empty() => Scope::default(),
        Some(Value::String(s)) => Scope::parse(s).map_err(|_| invalid_token())?,
        Some(_) => return Err(invalid_token()),
    };
    let family_id = match c.get("fid") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .and_then(parse_family_id)
                .ok_or_else(invalid_token)?,
        ),
    };
    let time_claim = |name: &str| {
        c.get(name)
            .and_then(Value::as_i64)
            .and_then(|e| OffsetDateTime::from_unix_timestamp(e).ok())
    };
    let exp = time_claim("exp").ok_or_else(invalid_token)?;
    let iat = time_claim("iat");
    let jti = c
        .get("jti")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok(AccessTokenClaims {
        sub,
        client_id,
        scope,
        family_id,
        exp,
        iat,
        jti,
    })
}

/// Validity of a stored opaque access token: not revoked, not expired, and — when it belongs to
/// a family — the family exists, is not revoked and belongs to the token's client. Client
/// credentials tokens (no family) carry the client id as `sub`. Pure.
pub fn opaque_claims(
    record: &AccessTokenRecord,
    family: Option<&TokenFamily>,
    now: OffsetDateTime,
) -> Result<AccessTokenClaims, CoreError> {
    if record.revoked_at.is_some() || record.expires_at <= now {
        return Err(invalid_token());
    }
    let scope = if record.scope.is_empty() {
        Scope::default()
    } else {
        Scope::parse(&record.scope).map_err(|_| invalid_token())?
    };
    let sub = match (record.family_id, record.user_id) {
        (Some(fid), Some(user)) => {
            match family {
                Some(f)
                    if f.id == fid
                        && f.revoked_at.is_none()
                        && f.client_id == record.client_id
                        && f.user_id == Some(user) => {}
                _ => return Err(invalid_token()),
            }
            user.to_string()
        }
        (None, None) => record.client_id.clone(),
        // A family without a user or a user without a family is never minted.
        _ => return Err(invalid_token()),
    };
    Ok(AccessTokenClaims {
        sub,
        client_id: record.client_id.clone(),
        scope,
        family_id: record.family_id,
        exp: record.expires_at,
        iat: Some(record.created_at),
        jti: None,
    })
}

/// A token carrying a family must point at a live family of the same client.
pub fn check_family(
    claims: &AccessTokenClaims,
    family: Option<&TokenFamily>,
) -> Result<(), CoreError> {
    match family {
        Some(f) if f.revoked_at.is_none() && f.client_id == claims.client_id => Ok(()),
        _ => Err(invalid_token()),
    }
}

/// UserInfo needs `openid` (else `insufficient_scope`) and a user token (client-credentials
/// tokens have no family and are refused as `invalid_token`). Returns the family id.
pub fn userinfo_requirements(claims: &AccessTokenClaims) -> Result<TokenFamilyId, CoreError> {
    if !claims.scope.contains("openid") {
        return Err(CoreError::InsufficientScope(
            "the access token lacks the openid scope".to_owned(),
        ));
    }
    claims.family_id.ok_or_else(invalid_token)
}

/// Verifies access tokens issued by this OP.
#[derive(Clone)]
pub struct AccessTokenVerifier {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl AccessTokenVerifier {
    /// Full verification of a JWT or opaque access token of `tenant`.
    ///
    /// - JWT: signature against the tenant's published keys, `typ`, `iss`, `exp`; then the family
    ///   (when present) must exist, belong to the token's client and not be revoked.
    /// - opaque: the SHA-256 must name a stored token of this tenant, checked by
    ///   [`opaque_claims`] (not revoked, not expired, live family).
    ///
    /// Every refusal is the same `invalid_token`.
    pub async fn verify(
        &self,
        tenant: TenantId,
        issuer: &str,
        token: &str,
    ) -> Result<AccessTokenClaims, CoreError> {
        if !is_jwt_shaped(token) {
            let found = self
                .storage
                .grants()
                .find_access_token(tenant, &SecretHash(secret_hash(token)))
                .await?;
            let (record, family) = found.ok_or_else(invalid_token)?;
            return opaque_claims(&record, family.as_ref(), self.clock.now());
        }
        let jwks = published_jwks(self.storage.as_ref(), self.clock.as_ref(), tenant).await?;
        let claims = verify_access_token_jwt(token, &jwks, issuer, self.clock.now())?;
        if let Some(fid) = claims.family_id {
            let family = self.storage.grants().get_family(tenant, fid).await?;
            check_family(&claims, family.as_ref())?;
        }
        Ok(claims)
    }
}

/// The UserInfo endpoint.
#[derive(Clone)]
pub struct UserInfoService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl UserInfoService {
    /// `sub`, the claims of the token's scopes and the family's `claims.userinfo` requests.
    pub async fn userinfo(
        &self,
        tenant: &Tenant,
        issuer: &str,
        token: &str,
    ) -> Result<Map<String, Value>, CoreError> {
        let claims = AccessTokenVerifier {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .verify(tenant.id, issuer, token)
        .await?;
        let fid = userinfo_requirements(&claims)?;
        let family = self
            .storage
            .grants()
            .get_family(tenant.id, fid)
            .await?
            .ok_or_else(invalid_token)?;
        check_family(&claims, Some(&family))?;
        let user_id = family.user_id.ok_or_else(invalid_token)?;
        if user_id.to_string() != claims.sub {
            return Err(invalid_token());
        }
        let user = match self.storage.users().get(tenant.id, user_id).await? {
            Some(u) if u.status == UserStatus::Active => u,
            _ => return Err(invalid_token()),
        };
        let mut out = Map::new();
        if let Some(req) = &family.claims {
            out.extend(requested_claims(&user, &req.userinfo));
        }
        out.extend(scope_claims(&user, &claims.scope));
        out.insert("sub".to_owned(), Value::String(claims.sub));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ACR_PWD, SessionId, UserId};
    use crate::service::claims::{AccessTokenInput, IdTokenInput};
    use crate::service::token::{sign_access_token, sign_id_token};
    use anvil_jose::generate_rs256;
    use anvil_jose::keys::{Alg, SigningKey};
    use time::Duration;

    const ISS: &str = "https://op.test/t/acme";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn key() -> (SigningKey, Jwks) {
        let g = generate_rs256().unwrap();
        let s = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        (
            s,
            Jwks {
                keys: vec![g.public_jwk],
            },
        )
    }

    fn at(
        s: &SigningKey,
        issuer: &str,
        scope: &str,
        fid: Option<TokenFamilyId>,
        at: OffsetDateTime,
    ) -> String {
        let scope = Scope::parse(scope).unwrap();
        sign_access_token(
            s,
            &AccessTokenInput {
                issuer,
                sub: "user-1",
                client_id: "rp",
                scope: &scope,
                now: at,
                jti: "j".into(),
                family_id: fid,
                auth_time: None,
                acr: None,
            },
        )
        .unwrap()
    }

    fn is_invalid_token<T: std::fmt::Debug>(r: &Result<T, CoreError>) -> bool {
        matches!(r, Err(CoreError::InvalidToken(_)))
    }

    #[test]
    fn valid_access_token_parses() {
        let (s, jwks) = key();
        let fid = TokenFamilyId::new_v7();
        let c = verify_access_token_jwt(
            &at(&s, ISS, "openid email", Some(fid), now()),
            &jwks,
            ISS,
            now(),
        )
        .unwrap();
        assert_eq!(c.sub, "user-1");
        assert_eq!(c.client_id, "rp");
        assert_eq!(c.scope.to_string(), "email openid");
        assert_eq!(c.family_id, Some(fid));
        assert_eq!(c.exp, now() + Duration::minutes(10));
        assert_eq!(c.iat, Some(now()));
        assert_eq!(c.jti.as_deref(), Some("j"));
    }

    #[test]
    fn jwt_shape_detection() {
        assert!(is_jwt_shaped("a.b.c"));
        assert!(!is_jwt_shaped(&anvil_jose::encoding::random_token()));
        assert!(!is_jwt_shaped("a.b"));
        assert!(!is_jwt_shaped("a.b.c.d"));
        assert!(!is_jwt_shaped(""));
    }

    fn record(fid: Option<TokenFamilyId>, user: Option<UserId>) -> AccessTokenRecord {
        AccessTokenRecord {
            token_hash: SecretHash([7; 32]),
            tenant_id: TenantId::new_v7(),
            family_id: fid,
            client_id: "rp".into(),
            user_id: user,
            scope: "openid email".into(),
            created_at: now() - Duration::minutes(1),
            expires_at: now() + Duration::minutes(9),
            revoked_at: None,
        }
    }

    #[test]
    fn opaque_token_valid_with_live_family() {
        let f = family("rp");
        let r = record(Some(f.id), f.user_id);
        let c = opaque_claims(&r, Some(&f), now()).unwrap();
        assert_eq!(c.sub, f.user_id.unwrap().to_string());
        assert_eq!(c.client_id, "rp");
        assert_eq!(c.scope.to_string(), "email openid");
        assert_eq!(c.family_id, Some(f.id));
        assert_eq!(c.exp, r.expires_at);
        assert_eq!(c.iat, Some(r.created_at));
        assert!(c.jti.is_none());
    }

    #[test]
    fn opaque_client_credentials_token_has_client_as_sub() {
        let c = opaque_claims(&record(None, None), None, now()).unwrap();
        assert_eq!(c.sub, "rp");
        assert!(c.family_id.is_none());
    }

    #[test]
    fn opaque_token_revoked_expired_or_dead_family_rejected() {
        let f = family("rp");
        let good = record(Some(f.id), f.user_id);

        let mut revoked = good.clone();
        revoked.revoked_at = Some(now());
        assert!(is_invalid_token(&opaque_claims(&revoked, Some(&f), now())));

        let mut expired = good.clone();
        expired.expires_at = now();
        assert!(is_invalid_token(&opaque_claims(&expired, Some(&f), now())));

        let mut dead = f.clone();
        dead.revoked_at = Some(now());
        assert!(is_invalid_token(&opaque_claims(&good, Some(&dead), now())));
        assert!(is_invalid_token(&opaque_claims(&good, None, now())));
        assert!(is_invalid_token(&opaque_claims(
            &good,
            Some(&family("other")),
            now()
        )));
        // Inconsistent rows are refused rather than trusted.
        assert!(is_invalid_token(&opaque_claims(
            &record(Some(f.id), None),
            Some(&f),
            now()
        )));
        assert!(is_invalid_token(&opaque_claims(
            &record(None, f.user_id),
            None,
            now()
        )));
    }

    #[test]
    fn id_token_is_not_an_access_token() {
        let (s, jwks) = key();
        let id = sign_id_token(
            &s,
            &IdTokenInput {
                issuer: ISS,
                sub: "user-1",
                client_id: "rp",
                now: now(),
                auth_time: None,
                nonce: None,
                acr: Some(ACR_PWD),
                amr: &[],
                sid: None,
                at_hash: None,
                extra: Map::new(),
            },
        )
        .unwrap();
        assert!(is_invalid_token(&verify_access_token_jwt(
            &id,
            &jwks,
            ISS,
            now()
        )));
        // typ "JWT" on a token that otherwise looks like an access token is refused too.
        let fake = s
            .sign_jwt(
                Some("JWT"),
                &serde_json::json!({"iss": ISS, "sub": "u", "client_id": "rp", "scope": "openid",
                                    "exp": now().unix_timestamp() + 60}),
            )
            .unwrap();
        assert!(is_invalid_token(&verify_access_token_jwt(
            &fake,
            &jwks,
            ISS,
            now()
        )));
    }

    #[test]
    fn other_tenant_expired_and_foreign_key_rejected() {
        let (s, jwks) = key();
        let other = at(&s, "https://op.test/t/other", "openid", None, now());
        assert!(is_invalid_token(&verify_access_token_jwt(
            &other,
            &jwks,
            ISS,
            now()
        )));
        let old = at(&s, ISS, "openid", None, now() - Duration::minutes(11));
        assert!(is_invalid_token(&verify_access_token_jwt(
            &old,
            &jwks,
            ISS,
            now()
        )));
        let (s2, _) = key();
        let foreign = at(&s2, ISS, "openid", None, now());
        assert!(is_invalid_token(&verify_access_token_jwt(
            &foreign,
            &jwks,
            ISS,
            now()
        )));
        assert!(is_invalid_token(&verify_access_token_jwt(
            "garbage",
            &jwks,
            ISS,
            now()
        )));
    }

    #[test]
    fn malformed_fid_rejected() {
        let (s, jwks) = key();
        let t = s
            .sign_jwt(
                Some("at+jwt"),
                &serde_json::json!({"iss": ISS, "sub": "u", "client_id": "rp", "scope": "openid",
                                    "fid": "not-a-uuid", "exp": now().unix_timestamp() + 60}),
            )
            .unwrap();
        assert!(is_invalid_token(&verify_access_token_jwt(
            &t,
            &jwks,
            ISS,
            now()
        )));
    }

    fn claims(scope: &str, fid: Option<TokenFamilyId>) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: "user-1".into(),
            client_id: "rp".into(),
            scope: Scope::parse(scope).unwrap(),
            family_id: fid,
            exp: now(),
            iat: None,
            jti: None,
        }
    }

    #[test]
    fn userinfo_scope_and_user_requirements() {
        let fid = TokenFamilyId::new_v7();
        assert_eq!(
            userinfo_requirements(&claims("openid", Some(fid))).unwrap(),
            fid
        );
        assert!(matches!(
            userinfo_requirements(&claims("profile", Some(fid))),
            Err(CoreError::InsufficientScope(_))
        ));
        // Client credentials: no openid, no family.
        assert!(matches!(
            userinfo_requirements(&claims("api", None)),
            Err(CoreError::InsufficientScope(_))
        ));
        assert!(is_invalid_token(&userinfo_requirements(&claims(
            "openid", None
        ))));
    }

    fn family(client_id: &str) -> TokenFamily {
        TokenFamily {
            id: TokenFamilyId::new_v7(),
            tenant_id: TenantId::new_v7(),
            client_id: client_id.into(),
            user_id: Some(UserId::new_v7()),
            scope: "openid".into(),
            auth_time: None,
            acr: None,
            amr: vec![],
            session_id: Some(SessionId::new_v7()),
            claims: None,
            created_at: now(),
            absolute_expires_at: now() + Duration::days(30),
            revoked_at: None,
            revoked_reason: None,
        }
    }

    #[test]
    fn revoked_missing_or_foreign_family_rejected() {
        let c = claims("openid", Some(TokenFamilyId::new_v7()));
        assert!(check_family(&c, Some(&family("rp"))).is_ok());
        assert!(is_invalid_token(&check_family(&c, None)));
        assert!(is_invalid_token(&check_family(&c, Some(&family("other")))));
        let mut revoked = family("rp");
        revoked.revoked_at = Some(now());
        assert!(is_invalid_token(&check_family(&c, Some(&revoked))));
    }
}
