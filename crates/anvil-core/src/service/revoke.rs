//! RFC 7009 token revocation.
//!
//! The caller is authenticated by the web layer with the single
//! [`ClientAuthenticator`](crate::service::client_auth::ClientAuthenticator); public clients may
//! revoke their own tokens (they authenticate with `client_id` only).
//!
//! | presented token                         | effect                                         |
//! |-----------------------------------------|------------------------------------------------|
//! | refresh token of the caller             | its family is revoked                          |
//! | opaque access token of the caller       | the token and its family (if any) are revoked  |
//! | JWT access token of the caller with fid | its family is revoked                          |
//! | JWT access token without fid (client credentials) | `unsupported_token_type` (a self-contained JWT cannot be revoked) |
//! | another client's token, unknown, invalid | nothing (200, RFC 7009 §2.2; no oracle)       |
//!
//! An unsupported `token_type_hint` value is `unsupported_token_type` (RFC 7009 §2.2.1). Every
//! revocation is audited as `token_revoked` with the family as target, never the token.

use std::sync::Arc;

use anvil_jose::encoding::secret_hash;

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, Client, RequestContext, RevokeReason,
    SecretHash, Tenant, TokenFamilyId,
};
use crate::ports::{Clock, Storage};
use crate::service::audit::AuditService;
use crate::service::introspect::{TokenTypeHint, lookup_order};
use crate::service::key::published_jwks;
use crate::service::userinfo::{AccessTokenClaims, is_jwt_shaped, verify_access_token_jwt};

/// Revocation reads the hint strictly: an unknown value is `unsupported_token_type`.
pub fn revocation_hint(raw: Option<&str>) -> Result<Option<TokenTypeHint>, CoreError> {
    match raw {
        None => Ok(None),
        Some(s) => TokenTypeHint::parse(s)
            .map(Some)
            .ok_or(CoreError::UnsupportedTokenType),
    }
}

/// What revoking a verified JWT access token does for `caller`: another client's token →
/// `Ok(None)` (no effect); the caller's token with a family → `Ok(Some(family))`; the caller's
/// token without a family (client credentials) → `unsupported_token_type`, because a
/// self-contained JWT has nothing server-side to revoke.
pub fn jwt_revocation_target(
    claims: &AccessTokenClaims,
    caller: &Client,
) -> Result<Option<TokenFamilyId>, CoreError> {
    if claims.client_id != caller.client_id {
        return Ok(None);
    }
    claims
        .family_id
        .map(Some)
        .ok_or(CoreError::UnsupportedTokenType)
}

/// Whether a stored token of `owner` may be revoked by `caller`.
pub fn owned_by(caller: &Client, owner: &str) -> bool {
    caller.client_id == owner
}

/// The revocation endpoint service.
#[derive(Clone)]
pub struct RevocationService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

/// Outcome of looking for the token in one table.
enum Found {
    /// Not a token of that kind.
    No,
    /// Handled (revoked, or ignored because it belongs to another client).
    Done,
}

impl RevocationService {
    /// Revokes `token` for the authenticated `caller` in `tenant`. `Ok(())` also when nothing
    /// was revoked (unknown token, another client's token).
    pub async fn revoke(
        &self,
        tenant: &Tenant,
        issuer: &str,
        caller: &Client,
        token: &str,
        hint: Option<&str>,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let hint = revocation_hint(hint)?;
        for kind in lookup_order(hint) {
            let found = match kind {
                TokenTypeHint::RefreshToken => self.refresh(tenant, caller, token, ctx).await?,
                TokenTypeHint::AccessToken => {
                    self.access(tenant, issuer, caller, token, ctx).await?
                }
            };
            if let Found::Done = found {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn refresh(
        &self,
        tenant: &Tenant,
        caller: &Client,
        token: &str,
        ctx: &RequestContext,
    ) -> Result<Found, CoreError> {
        let Some((_, family)) = self
            .storage
            .grants()
            .find_refresh_token(tenant.id, &SecretHash(secret_hash(token)))
            .await?
        else {
            return Ok(Found::No);
        };
        if owned_by(caller, &family.client_id) && family.revoked_at.is_none() {
            self.revoke_family(tenant, caller, family.id, TokenTypeHint::RefreshToken, ctx)
                .await?;
        }
        Ok(Found::Done)
    }

    async fn access(
        &self,
        tenant: &Tenant,
        issuer: &str,
        caller: &Client,
        token: &str,
        ctx: &RequestContext,
    ) -> Result<Found, CoreError> {
        let now = self.clock.now();
        let grants = self.storage.grants();
        if !is_jwt_shaped(token) {
            let hash = SecretHash(secret_hash(token));
            let Some((record, family)) = grants.find_access_token(tenant.id, &hash).await? else {
                return Ok(Found::No);
            };
            if !owned_by(caller, &record.client_id) {
                return Ok(Found::Done);
            }
            let token_revoked = grants.revoke_access_token(tenant.id, &hash, now).await?;
            match family {
                Some(f) if f.revoked_at.is_none() => {
                    self.revoke_family(tenant, caller, f.id, TokenTypeHint::AccessToken, ctx)
                        .await?;
                }
                Some(_) => {}
                None if token_revoked => {
                    self.audit(tenant, caller, None, TokenTypeHint::AccessToken, ctx)
                        .await?;
                }
                None => {}
            }
            return Ok(Found::Done);
        }
        let jwks = published_jwks(self.storage.as_ref(), self.clock.as_ref(), tenant.id).await?;
        let Ok(claims) = verify_access_token_jwt(token, &jwks, issuer, now) else {
            // Invalid, expired or another tenant's: nothing to revoke.
            return Ok(Found::No);
        };
        if let Some(fid) = jwt_revocation_target(&claims, caller)? {
            let live = grants
                .get_family(tenant.id, fid)
                .await?
                .is_some_and(|f| f.revoked_at.is_none() && f.client_id == caller.client_id);
            if live {
                self.revoke_family(tenant, caller, fid, TokenTypeHint::AccessToken, ctx)
                    .await?;
            }
        }
        Ok(Found::Done)
    }

    async fn revoke_family(
        &self,
        tenant: &Tenant,
        caller: &Client,
        family: TokenFamilyId,
        kind: TokenTypeHint,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        self.storage
            .grants()
            .revoke_family(tenant.id, family, RevokeReason::TokenRevoked, self.clock.now())
            .await?;
        self.audit(tenant, caller, Some(family), kind, ctx).await
    }

    async fn audit(
        &self,
        tenant: &Tenant,
        caller: &Client,
        family: Option<TokenFamilyId>,
        kind: TokenTypeHint,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant.id,
            AuditActor::client(&caller.client_id),
            AuditAction::TokenRevoked,
            family.map(|f| f.to_string()),
            AuditOutcome::Success,
            ctx,
            AuditDetails::reason(kind.as_str()),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClientAuthMethod, Scope};
    use crate::service::client_auth::tests::client;
    use time::OffsetDateTime;

    fn claims(client_id: &str, fid: Option<TokenFamilyId>) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: "u".into(),
            client_id: client_id.into(),
            scope: Scope::parse("openid").unwrap(),
            family_id: fid,
            exp: OffsetDateTime::UNIX_EPOCH,
            iat: None,
            jti: None,
        }
    }

    #[test]
    fn hint_is_strict_at_revocation() {
        assert_eq!(revocation_hint(None).unwrap(), None);
        assert_eq!(
            revocation_hint(Some("refresh_token")).unwrap(),
            Some(TokenTypeHint::RefreshToken)
        );
        assert_eq!(
            revocation_hint(Some("access_token")).unwrap(),
            Some(TokenTypeHint::AccessToken)
        );
        for bad in ["id_token", "ACCESS_TOKEN", "urn:x", ""] {
            assert!(
                matches!(
                    revocation_hint(Some(bad)),
                    Err(CoreError::UnsupportedTokenType)
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn jwt_targets() {
        let caller = client(ClientAuthMethod::ClientSecretBasic); // client_id "rp"
        let fid = TokenFamilyId::new_v7();
        assert_eq!(
            jwt_revocation_target(&claims("rp", Some(fid)), &caller).unwrap(),
            Some(fid)
        );
        // Another client's token: no effect, no error (no oracle).
        assert_eq!(
            jwt_revocation_target(&claims("other", Some(fid)), &caller).unwrap(),
            None
        );
        assert_eq!(
            jwt_revocation_target(&claims("other", None), &caller).unwrap(),
            None
        );
        // Own client-credentials JWT: cannot be revoked.
        assert!(matches!(
            jwt_revocation_target(&claims("rp", None), &caller),
            Err(CoreError::UnsupportedTokenType)
        ));
    }

    #[test]
    fn ownership() {
        let mut caller = client(ClientAuthMethod::None);
        assert!(owned_by(&caller, "rp"));
        assert!(!owned_by(&caller, "other"));
        // can_introspect grants visibility, never revocation of other clients' tokens.
        caller.can_introspect = true;
        assert!(!owned_by(&caller, "other"));
    }
}
