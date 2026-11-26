//! RFC 7662 token introspection.
//!
//! The caller is authenticated by the web layer with the single
//! [`ClientAuthenticator`](crate::service::client_auth::ClientAuthenticator); public clients are
//! refused with `invalid_client` ([`require_confidential`]). A confidential caller sees tokens
//! issued to itself, and any token of the tenant only with `can_introspect` ([`is_visible`]).
//!
//! Everything else — unknown, malformed, expired, revoked, another tenant's or a token the caller
//! may not see — is exactly `{"active":false}`, so the response never tells a caller why.
//!
//! Access tokens are checked by the single
//! [`AccessTokenVerifier`](crate::service::userinfo::AccessTokenVerifier); refresh tokens by
//! [`refresh_active`]. `token_type_hint` only changes the lookup order; an unknown hint value is
//! ignored (RFC 7662 §2.1).

use std::sync::Arc;

use anvil_jose::encoding::secret_hash;
use serde::Serialize;
use time::OffsetDateTime;

use crate::error::CoreError;
use crate::model::{Client, ClientType, RefreshToken, SecretHash, Tenant, TokenFamily};
use crate::oauth::resource::{Audience, audience};
use crate::ports::{Clock, Storage};
use crate::service::userinfo::{AccessTokenClaims, AccessTokenVerifier};

/// The token types a client can name in `token_type_hint` (RFC 7009 §2.1 registry values we
/// issue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    AccessToken,
    RefreshToken,
}

impl TokenTypeHint {
    /// `access_token` / `refresh_token`; anything else is `None`.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "access_token" => Some(Self::AccessToken),
            "refresh_token" => Some(Self::RefreshToken),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// Introspection reads the hint leniently: an unknown value is ignored (RFC 7662 §2.1).
pub fn introspection_hint(raw: Option<&str>) -> Option<TokenTypeHint> {
    raw.and_then(TokenTypeHint::parse)
}

/// The order in which the token tables are searched: the hinted type first, access tokens first
/// without a hint.
pub fn lookup_order(hint: Option<TokenTypeHint>) -> [TokenTypeHint; 2] {
    match hint {
        Some(TokenTypeHint::RefreshToken) => {
            [TokenTypeHint::RefreshToken, TokenTypeHint::AccessToken]
        }
        _ => [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken],
    }
}

/// Only confidential clients may introspect (public clients cannot keep the credential that
/// would make the answer meaningful). Same `invalid_client` description as every client
/// authentication failure.
pub fn require_confidential(caller: &Client) -> Result<(), CoreError> {
    if caller.client_type == ClientType::Confidential {
        Ok(())
    } else {
        Err(CoreError::InvalidClient {
            reason: "client authentication failed".to_owned(),
            basic_auth_used: false,
        })
    }
}

/// A caller sees tokens issued to itself, and every token of the tenant with `can_introspect`.
pub fn is_visible(caller: &Client, token_client_id: &str) -> bool {
    caller.client_id == token_client_id || caller.can_introspect
}

/// A refresh token is active when it is unconsumed and unexpired and its family is not revoked
/// and within its absolute lifetime.
pub fn refresh_active(token: &RefreshToken, family: &TokenFamily, now: OffsetDateTime) -> bool {
    token.family_id == family.id
        && token.consumed_at.is_none()
        && token.expires_at > now
        && family.revoked_at.is_none()
        && family.absolute_expires_at > now
}

/// An RFC 7662 §2.2 response. An inactive token serialises to exactly `{"active":false}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// A string for one audience, an array for several (RFC 7662 §2.2, RFC 7519 §4.1.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// `Bearer` for access tokens, `refresh_token` for refresh tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
    /// Only for JWT access tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self::default()
    }

    /// An active access token. `aud` is the token's audience: the JWT `aud` or the opaque
    /// token's resources, the client id when there are none (RFC 8707, RFC 9068 §3).
    pub fn access(claims: AccessTokenClaims, issuer: &str) -> Self {
        Self {
            active: true,
            scope: Some(claims.scope.to_string()),
            aud: Some(audience(&claims.aud, &claims.client_id)),
            client_id: Some(claims.client_id),
            sub: Some(claims.sub),
            iss: Some(issuer.to_owned()),
            exp: Some(claims.exp.unix_timestamp()),
            iat: claims.iat.map(OffsetDateTime::unix_timestamp),
            token_type: Some("Bearer"),
            jti: claims.jti,
        }
    }

    /// An active refresh token.
    pub fn refresh(token: &RefreshToken, family: &TokenFamily, issuer: &str) -> Self {
        Self {
            active: true,
            scope: Some(token.scope.clone()),
            client_id: Some(family.client_id.clone()),
            sub: family.user_id.map(|u| u.to_string()),
            // A refresh token is only ever presented to this AS by its client.
            aud: Some(Audience::One(family.client_id.clone())),
            iss: Some(issuer.to_owned()),
            exp: Some(token.expires_at.unix_timestamp()),
            iat: Some(token.created_at.unix_timestamp()),
            token_type: Some("refresh_token"),
            jti: None,
        }
    }
}

/// The introspection endpoint service.
#[derive(Clone)]
pub struct IntrospectionService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl IntrospectionService {
    /// Introspects `token` for the authenticated `caller` in `tenant` (whose issuer is `issuer`).
    /// `Err` only for a public caller (`invalid_client`) or a server error; every token outcome
    /// is an `Ok` response.
    pub async fn introspect(
        &self,
        tenant: &Tenant,
        issuer: &str,
        caller: &Client,
        token: &str,
        hint: Option<&str>,
    ) -> Result<IntrospectionResponse, CoreError> {
        require_confidential(caller)?;
        for kind in lookup_order(introspection_hint(hint)) {
            let found = match kind {
                TokenTypeHint::AccessToken => self.access(tenant, issuer, token).await?,
                TokenTypeHint::RefreshToken => self.refresh(tenant, issuer, token).await?,
            };
            if let Some(resp) = found {
                let owner = resp.client_id.as_deref().unwrap_or_default();
                return Ok(if is_visible(caller, owner) {
                    resp
                } else {
                    IntrospectionResponse::inactive()
                });
            }
        }
        Ok(IntrospectionResponse::inactive())
    }

    async fn access(
        &self,
        tenant: &Tenant,
        issuer: &str,
        token: &str,
    ) -> Result<Option<IntrospectionResponse>, CoreError> {
        let verifier = AccessTokenVerifier {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        };
        match verifier.verify(tenant.id, issuer, token).await {
            Ok(claims) => Ok(Some(IntrospectionResponse::access(claims, issuer))),
            Err(CoreError::InvalidToken(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn refresh(
        &self,
        tenant: &Tenant,
        issuer: &str,
        token: &str,
    ) -> Result<Option<IntrospectionResponse>, CoreError> {
        let found = self
            .storage
            .grants()
            .find_refresh_token(tenant.id, &SecretHash(secret_hash(token)))
            .await?;
        Ok(found.and_then(|(rt, family)| {
            refresh_active(&rt, &family, self.clock.now())
                .then(|| IntrospectionResponse::refresh(&rt, &family, issuer))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClientAuthMethod, Scope, SessionId, TenantId, TokenFamilyId, UserId};
    use crate::service::client_auth::tests::client;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
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
            created_at: now() - Duration::hours(1),
            absolute_expires_at: now() + Duration::days(30),
            revoked_at: None,
            revoked_reason: None,
            resource: vec![],
            org_id: None,
        }
    }

    fn rt(f: &TokenFamily) -> RefreshToken {
        RefreshToken {
            token_hash: SecretHash([3; 32]),
            tenant_id: f.tenant_id,
            family_id: f.id,
            parent_hash: None,
            scope: "openid".into(),
            created_at: now() - Duration::minutes(5),
            expires_at: now() + Duration::days(14),
            consumed_at: None,
        }
    }

    #[test]
    fn inactive_is_exactly_active_false() {
        assert_eq!(
            serde_json::to_string(&IntrospectionResponse::inactive()).unwrap(),
            r#"{"active":false}"#
        );
    }

    #[test]
    fn hints() {
        assert_eq!(
            introspection_hint(Some("refresh_token")),
            Some(TokenTypeHint::RefreshToken)
        );
        assert_eq!(
            introspection_hint(Some("access_token")),
            Some(TokenTypeHint::AccessToken)
        );
        // Unknown values are ignored at introspection.
        assert_eq!(introspection_hint(Some("id_token")), None);
        assert_eq!(introspection_hint(None), None);
        assert_eq!(
            lookup_order(None),
            [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
        );
        assert_eq!(
            lookup_order(Some(TokenTypeHint::AccessToken)),
            [TokenTypeHint::AccessToken, TokenTypeHint::RefreshToken]
        );
        assert_eq!(
            lookup_order(Some(TokenTypeHint::RefreshToken)),
            [TokenTypeHint::RefreshToken, TokenTypeHint::AccessToken]
        );
    }

    #[test]
    fn public_callers_are_invalid_client() {
        let public = client(ClientAuthMethod::None);
        assert!(matches!(
            require_confidential(&public),
            Err(CoreError::InvalidClient { .. })
        ));
        assert!(require_confidential(&client(ClientAuthMethod::ClientSecretBasic)).is_ok());
        assert!(require_confidential(&client(ClientAuthMethod::PrivateKeyJwt)).is_ok());
    }

    #[test]
    fn visibility_matrix() {
        let mut caller = client(ClientAuthMethod::ClientSecretBasic);
        caller.client_id = "rs".into();
        // Own token: always.
        assert!(is_visible(&caller, "rs"));
        // Another client's token without can_introspect: never.
        assert!(!is_visible(&caller, "rp"));
        assert!(!is_visible(&caller, ""));
        // With can_introspect: any token of the tenant (tenant isolation is the lookup's job).
        caller.can_introspect = true;
        assert!(is_visible(&caller, "rp"));
    }

    #[test]
    fn refresh_token_activity() {
        let f = family("rp");
        assert!(refresh_active(&rt(&f), &f, now()));

        let mut consumed = rt(&f);
        consumed.consumed_at = Some(now() - Duration::seconds(1));
        assert!(!refresh_active(&consumed, &f, now()));

        let mut expired = rt(&f);
        expired.expires_at = now();
        assert!(!refresh_active(&expired, &f, now()));

        let mut revoked = f.clone();
        revoked.revoked_at = Some(now());
        assert!(!refresh_active(&rt(&f), &revoked, now()));

        let mut old = f.clone();
        old.absolute_expires_at = now();
        assert!(!refresh_active(&rt(&f), &old, now()));

        assert!(
            !refresh_active(&rt(&f), &family("rp"), now()),
            "other family"
        );
    }

    #[test]
    fn active_access_response_fields() {
        let fid = TokenFamilyId::new_v7();
        let claims = AccessTokenClaims {
            sub: "u1".into(),
            client_id: "rp".into(),
            scope: Scope::parse("openid email").unwrap(),
            aud: vec!["rp".into()],
            family_id: Some(fid),
            exp: now() + Duration::minutes(10),
            iat: Some(now()),
            jti: Some("j1".into()),
        };
        let v =
            serde_json::to_value(IntrospectionResponse::access(claims, "https://op.test")).unwrap();
        assert_eq!(v["active"], true);
        assert_eq!(v["scope"], "email openid");
        assert_eq!(v["client_id"], "rp");
        assert_eq!(v["aud"], "rp");
        assert_eq!(v["sub"], "u1");
        assert_eq!(v["iss"], "https://op.test");
        assert_eq!(v["exp"], (now() + Duration::minutes(10)).unix_timestamp());
        assert_eq!(v["iat"], now().unix_timestamp());
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["jti"], "j1");
        assert!(v.get("fid").is_none());
    }

    #[test]
    fn access_response_aud_follows_the_token_audience() {
        let base = AccessTokenClaims {
            sub: "u1".into(),
            client_id: "rp".into(),
            scope: Scope::parse("openid").unwrap(),
            aud: vec!["https://api.example.test".into()],
            family_id: None,
            exp: now() + Duration::minutes(10),
            iat: Some(now()),
            jti: None,
        };
        let v = serde_json::to_value(IntrospectionResponse::access(base.clone(), "https://op"))
            .unwrap();
        assert_eq!(v["aud"], "https://api.example.test");
        assert_eq!(v["client_id"], "rp");
        let mut many = base.clone();
        many.aud.push("https://b.example.test".into());
        let v = serde_json::to_value(IntrospectionResponse::access(many, "https://op")).unwrap();
        assert_eq!(
            v["aud"],
            serde_json::json!(["https://api.example.test", "https://b.example.test"])
        );
        let mut none = base;
        none.aud.clear();
        let v = serde_json::to_value(IntrospectionResponse::access(none, "https://op")).unwrap();
        assert_eq!(v["aud"], "rp");
    }

    #[test]
    fn active_refresh_response_fields() {
        let f = family("rp");
        let t = rt(&f);
        let v = serde_json::to_value(IntrospectionResponse::refresh(&t, &f, "https://op.test"))
            .unwrap();
        assert_eq!(v["active"], true);
        assert_eq!(v["token_type"], "refresh_token");
        assert_eq!(v["client_id"], "rp");
        assert_eq!(v["sub"], f.user_id.unwrap().to_string());
        assert_eq!(v["exp"], t.expires_at.unix_timestamp());
        assert!(v.get("jti").is_none());
    }
}
