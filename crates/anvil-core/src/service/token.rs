//! The token endpoint (RFC 6749 §3.2, §4.1.3, §4.4, §6; OIDC Core §3.1.3, §12; RFC 9700 §2.1,
//! §4.8, §4.14). The single implementation of token minting.
//!
//! Every rule is a pure function ([`parse_grant_type`], [`validate_code_exchange`],
//! [`validate_refresh`], [`check_client_credentials`], ...) unit-tested here; [`TokenService`]
//! orchestrates them over the storage ports.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_jose::keys::{Alg, SigningKey};
use anvil_jose::token_hash;
use serde::Serialize;
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthorizationCode, Client, ClientType,
    GrantType, NewAccessToken, NewRefreshToken, RefreshToken, RequestContext, RevokeReason,
    SYSTEM_TENANT_SLUG, Scope, SecretHash, Tenant, TenantId, TokenFamily, TokenFamilyId,
    TokenFormat, TokenTarget, User, UserId, UserStatus,
};
use crate::oauth::resource;
use crate::policy::org_claims::bound_org_admin_scope;
use crate::ports::{
    AttributeSchemaCheck, ClientMetadataFetcher, Clock, ConsumeOutcome, RotateOutcome, Storage,
};
use crate::service::audit::AuditService;
use crate::service::claims::{
    ACCESS_TOKEN_TTL, AccessTokenInput, IdTokenInput, access_token_claims, id_token_claims,
    merge_access_token_extras, merge_org_claims, requested_claims,
};
use crate::service::client_auth::{ClientAuthInput, ClientAuthenticator};
use crate::service::key::{KeyService, TOKEN_ALG};
use crate::service::key_rotation::enabled_algs;
use crate::service::role::{UserClaimSource, bound_admin_scope};

/// Refresh token idle lifetime; a child never outlives its family's absolute expiry.
pub const REFRESH_TOKEN_IDLE_TTL: Duration = Duration::days(14);

/// JWS `typ` of access tokens (RFC 9068 §2.1).
pub const ACCESS_TOKEN_TYP: &str = "at+jwt";
/// JWS `typ` of ID tokens.
pub const ID_TOKEN_TYP: &str = "JWT";

/// A token request as parsed from the form body and the `Authorization` header.
#[derive(Clone, Default)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Every non-empty `resource` value (RFC 8707 §2.2; the only parameter that may repeat).
    pub resource: Vec<String>,
    pub auth: ClientAuthInput,
    /// Request context (client IP, user agent, request id) recorded with the audit events this
    /// request can raise (code and refresh-token reuse detection).
    pub context: RequestContext,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &redact(&self.code))
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &redact(&self.code_verifier))
            .field("refresh_token", &redact(&self.refresh_token))
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("auth", &self.auth)
            .field("context", &self.context)
            .finish()
    }
}

/// A successful token response (RFC 6749 §5.1). The web layer adds `Cache-Control: no-store`.
#[derive(Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------------------------
// Pure rules
// ---------------------------------------------------------------------------------------------

/// `grant_type` → [`GrantType`]. Missing is `invalid_request`; anything else we do not support
/// (`password`, `implicit`, device code, ...) is `unsupported_grant_type`.
pub fn parse_grant_type(raw: Option<&str>) -> Result<GrantType, CoreError> {
    match raw.filter(|s| !s.is_empty()) {
        None => Err(CoreError::InvalidRequest(
            "grant_type is required".to_owned(),
        )),
        Some(s) => GrantType::parse(s).ok_or(CoreError::UnsupportedGrantType),
    }
}

/// The client must be registered for the grant (`unauthorized_client`).
pub fn check_client_grant(client: &Client, grant: GrantType) -> Result<(), CoreError> {
    if client.grant_types.contains(&grant) {
        Ok(())
    } else {
        Err(CoreError::UnauthorizedClient(format!(
            "the client is not allowed to use the {} grant",
            grant.as_str()
        )))
    }
}

fn invalid_grant() -> CoreError {
    // One description for every grant failure: never say which binding failed.
    CoreError::InvalidGrant(crate::error::INVALID_GRANT_DESCRIPTION.to_owned())
}

/// Binds a consumed code to the request: same client, same `redirect_uri` (required, exact),
/// and PKCE — a code with a challenge needs a matching S256 verifier, and a code without one must
/// not receive a verifier (downgrade defence, RFC 9700 §4.8.2). All failures are `invalid_grant`.
pub fn validate_code_exchange(
    code: &AuthorizationCode,
    client: &Client,
    redirect_uri: Option<&str>,
    code_verifier: Option<&str>,
) -> Result<(), CoreError> {
    if code.client_id != client.client_id {
        return Err(invalid_grant());
    }
    if redirect_uri != Some(code.redirect_uri.as_str()) {
        return Err(invalid_grant());
    }
    match (code.code_challenge.as_deref(), code_verifier) {
        (Some(challenge), Some(verifier)) => {
            if !anvil_jose::pkce::is_valid_verifier(verifier)
                || !anvil_jose::pkce::verify_s256(verifier, challenge)
            {
                return Err(invalid_grant());
            }
        }
        (Some(_), None) | (None, Some(_)) => return Err(invalid_grant()),
        (None, None) => {
            if client.require_pkce || client.client_type == ClientType::Public {
                // The authorize endpoint never issues such a code; refuse defensively.
                return Err(invalid_grant());
            }
        }
    }
    Ok(())
}

/// Checks a refresh request **before anything is consumed**. Every `Err` means: do not rotate,
/// do not revoke. Returns the scope of the new tokens.
///
/// - the family must belong to the authenticated client (`invalid_grant`, so a client cannot
///   burn another client's refresh token);
/// - a requested scope may only narrow the family's granted scope (`invalid_scope`);
/// - no scope requested → the family's scope.
///
/// An already-consumed token from the right client passes, so that `rotate_refresh` detects the
/// reuse and revokes the family.
pub fn validate_refresh(
    token: &RefreshToken,
    family: &TokenFamily,
    client: &Client,
    requested_scope: Option<&str>,
    now: OffsetDateTime,
) -> Result<Scope, CoreError> {
    if family.client_id != client.client_id || token.family_id != family.id {
        return Err(invalid_grant());
    }
    let granted = Scope::parse(&family.scope).unwrap_or_default();
    if token.consumed_at.is_some() {
        return Ok(granted);
    }
    if family.revoked_at.is_some() || token.expires_at <= now || family.absolute_expires_at <= now {
        return Err(invalid_grant());
    }
    match requested_scope {
        None => Ok(granted),
        Some(raw) => {
            let requested = Scope::parse(raw)?;
            if requested.is_subset(&granted) {
                Ok(requested)
            } else {
                Err(CoreError::InvalidScope(
                    "the requested scope exceeds the granted scope".to_owned(),
                ))
            }
        }
    }
}

/// Resources of the access token minted by a refresh (RFC 8707 §2.2): the request may only
/// downscope the family's granted resources. The refresh token itself always keeps the full
/// grant (the family is never changed). An already-consumed token passes with the family's
/// resources so that `rotate_refresh` detects the reuse and revokes the family, exactly like
/// [`validate_refresh`] does for the scope.
pub fn refresh_resources(
    token: &RefreshToken,
    family: &TokenFamily,
    requested: &[String],
) -> Result<Vec<String>, CoreError> {
    if token.consumed_at.is_some() {
        return Ok(family.resource.clone());
    }
    resource::downscope(&family.resource, requested)
}

/// Resources of a client credentials token: each requested resource must be one of the client's
/// allowed resources (RFC 8707 §2.2; no grant exists to downscope from).
pub fn client_credentials_resources(
    client: &Client,
    requested: &[String],
) -> Result<Vec<String>, CoreError> {
    resource::validate_resources(requested, &client.allowed_resources)?;
    Ok(requested.to_vec())
}

/// Rules of the client credentials grant: confidential clients registered for it only; `openid`
/// is never allowed (there is no user); the scope must be within the client's registered scopes.
/// No scope requested → every registered scope except `openid`.
pub fn check_client_credentials(client: &Client, scope: Option<&str>) -> Result<Scope, CoreError> {
    if client.client_type != ClientType::Confidential {
        return Err(CoreError::UnauthorizedClient(
            "public clients cannot use client_credentials".to_owned(),
        ));
    }
    check_client_grant(client, GrantType::ClientCredentials)?;
    let allowed: Scope = client.scopes.iter().cloned().collect();
    let scope = match scope {
        Some(raw) => Scope::parse(raw)?,
        None => client
            .scopes
            .iter()
            .filter(|s| s.as_str() != "openid")
            .cloned()
            .collect(),
    };
    if scope.contains("openid") {
        return Err(CoreError::InvalidScope(
            "openid is not allowed with client_credentials".to_owned(),
        ));
    }
    if !scope.is_subset(&allowed) {
        return Err(CoreError::InvalidScope(
            "the requested scope is not registered for the client".to_owned(),
        ));
    }
    Ok(scope)
}

/// Expiry of a new refresh token: idle lifetime, capped by the family's absolute expiry.
pub fn refresh_expiry(now: OffsetDateTime, family: &TokenFamily) -> OffsetDateTime {
    (now + REFRESH_TOKEN_IDLE_TTL).min(family.absolute_expires_at)
}

/// The family's user must still exist and be active.
pub fn check_user(user: Option<User>) -> Result<User, CoreError> {
    match user {
        Some(u) if u.status == UserStatus::Active => Ok(u),
        _ => Err(invalid_grant()),
    }
}

/// ID token input for a token family: the authentication context comes from the family, so a
/// refreshed ID token repeats `auth_time`, `acr`, `amr` and `sid`. `nonce` is only passed for the
/// first ID token of an authorization (`None` on refresh, OIDC Core §12.2). `at_hash` uses the
/// hash of the ID token's algorithm (`id_token_alg`).
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is a distinct input of the ID token"
)]
pub fn family_id_token_input<'a>(
    issuer: &'a str,
    sub: &'a str,
    family: &'a TokenFamily,
    user: &User,
    now: OffsetDateTime,
    nonce: Option<&'a str>,
    access_token: &str,
    id_token_alg: Alg,
) -> IdTokenInput<'a> {
    let extra = family
        .claims
        .as_ref()
        .map(|c| requested_claims(user, &c.id_token))
        .unwrap_or_default();
    IdTokenInput {
        issuer,
        sub,
        client_id: &family.client_id,
        now,
        auth_time: family.auth_time,
        nonce,
        acr: family.acr.as_deref(),
        amr: &family.amr,
        sid: family.session_id.map(|s| s.to_string()),
        at_hash: Some(token_hash(id_token_alg, access_token)),
        extra,
    }
}

/// The algorithm the client's ID tokens are signed with: its `id_token_signed_response_alg`, or
/// RS256. An algorithm that is unknown or not enabled for the tenant is a server error; there is
/// never a fallback to another algorithm.
pub fn id_token_alg(tenant: &Tenant, client: &Client) -> Result<Alg, CoreError> {
    let Some(raw) = client.id_token_signed_response_alg.as_deref() else {
        return Ok(TOKEN_ALG);
    };
    let alg: Alg = raw.parse().map_err(|_| {
        CoreError::Internal(format!(
            "client {} requests unknown ID token alg {raw}",
            client.client_id
        ))
    })?;
    if !enabled_algs(tenant)?.contains(&alg) {
        return Err(CoreError::Internal(format!(
            "client {} requests ID token alg {raw}, which the tenant has not enabled",
            client.client_id
        )));
    }
    Ok(alg)
}

fn signing_error(_: anvil_jose::JoseError) -> CoreError {
    CoreError::Internal("token signing failed".to_owned())
}

/// Signs an access token (`typ: at+jwt`).
pub fn sign_access_token(
    signer: &SigningKey,
    input: &AccessTokenInput,
) -> Result<String, CoreError> {
    sign_access_token_with(signer, input, Map::new(), Map::new())
}

/// Signs an access token with mapped extra claims (roles, permissions, attributes) and the
/// active org's claims. Extras never override or add reserved claims
/// ([`merge_access_token_extras`]); the org claims come only from
/// [`org_claims_json`](crate::policy::org_claims::org_claims_json) ([`merge_org_claims`]).
pub fn sign_access_token_with(
    signer: &SigningKey,
    input: &AccessTokenInput,
    extra: Map<String, Value>,
    org: Map<String, Value>,
) -> Result<String, CoreError> {
    let mut claims = access_token_claims(input);
    merge_org_claims(&mut claims, org);
    merge_access_token_extras(&mut claims, extra);
    signer
        .sign_jwt(Some(ACCESS_TOKEN_TYP), &claims)
        .map_err(signing_error)
}

/// The scope user tokens are issued with. In the system tenant admin scopes are bounded by the
/// user's roles (decision Q3, [`bound_admin_scope`]); in every tenant `org:admin` stays only
/// when the user holds the `org:admin` permission in the grant's active org
/// ([`UserClaimSource::bound_org_admin`], decision Q1). The refresh token keeps the full grant,
/// so a role change applies at the next refresh (in both directions, never beyond the grant).
pub fn issued_scope(tenant: &Tenant, granted: &Scope, source: &UserClaimSource) -> Scope {
    let scope = if tenant.slug == SYSTEM_TENANT_SLUG {
        bound_admin_scope(granted, &source.effective_admin_scopes(tenant))
    } else {
        granted.clone()
    };
    source.bound_org_admin(&scope)
}

/// The stored form of a new opaque access token: only the SHA-256 of `raw` is kept, linked to
/// the family (`None` for client credentials), with the same lifetime as a JWT access token.
pub fn new_opaque_access_token(
    raw: &str,
    client_id: &str,
    family_id: Option<TokenFamilyId>,
    user_id: Option<UserId>,
    scope: &Scope,
    resource: &[String],
    now: OffsetDateTime,
) -> NewAccessToken {
    NewAccessToken {
        token_hash: SecretHash(secret_hash(raw)),
        family_id,
        client_id: client_id.to_owned(),
        user_id,
        scope: scope.to_string(),
        created_at: now,
        expires_at: now + ACCESS_TOKEN_TTL,
        resource: resource.to_vec(),
    }
}

/// Signs an ID token (`typ: JWT`).
pub fn sign_id_token(signer: &SigningKey, input: &IdTokenInput) -> Result<String, CoreError> {
    sign_id_token_with(signer, input, Map::new())
}

/// Signs an ID token carrying the active org's claims ([`merge_org_claims`]).
pub fn sign_id_token_with(
    signer: &SigningKey,
    input: &IdTokenInput,
    org: Map<String, Value>,
) -> Result<String, CoreError> {
    let mut claims = id_token_claims(input);
    merge_org_claims(&mut claims, org);
    signer
        .sign_jwt(Some(ID_TOKEN_TYP), &claims)
        .map_err(signing_error)
}

// ---------------------------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------------------------

/// The token endpoint service.
#[derive(Clone)]
pub struct TokenService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
    /// Attribute schema check for mapped attribute claims; `None` omits attribute claims
    /// (values are never emitted unvalidated).
    pub attribute_check: Option<Arc<dyn AttributeSchemaCheck>>,
    /// Client ID Metadata Document fetcher, passed to the [`ClientAuthenticator`] this service
    /// builds (used from plan 05-15; `None` = URL client ids are not resolved).
    pub metadata_fetcher: Option<Arc<dyn ClientMetadataFetcher>>,
}

/// Tokens minted for one user family.
struct Minted {
    access_token: String,
    id_token: Option<String>,
}

impl TokenService {
    fn keys(&self) -> KeyService {
        KeyService {
            storage: self.storage.clone(),
            kek: self.kek.clone(),
            clock: self.clock.clone(),
        }
    }

    /// Audits a detected code or refresh-token replay with the request's context; the actor is
    /// the authenticated client and the target the revoked family (never the token).
    async fn audit_reuse(
        &self,
        tenant: TenantId,
        client: &Client,
        action: AuditAction,
        family_id: Option<TokenFamilyId>,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
        .record(
            tenant,
            AuditActor::client(&client.client_id),
            action,
            family_id.map(|f| f.to_string()),
            AuditOutcome::Failure,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }

    /// Stores a new opaque access token and returns its plaintext.
    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper; every argument is a distinct field of the stored token"
    )]
    async fn opaque_access_token(
        &self,
        tenant: TenantId,
        client: &Client,
        family_id: Option<TokenFamilyId>,
        user_id: Option<UserId>,
        scope: &Scope,
        resource: &[String],
        now: OffsetDateTime,
    ) -> Result<String, CoreError> {
        let raw = random_token();
        self.storage
            .grants()
            .create_access_token(
                tenant,
                &new_opaque_access_token(
                    &raw,
                    &client.client_id,
                    family_id,
                    user_id,
                    scope,
                    resource,
                    now,
                ),
            )
            .await?;
        Ok(raw)
    }

    /// Handles a token request for `tenant` (whose issuer is `issuer`).
    pub async fn token(
        &self,
        tenant: &Tenant,
        issuer: &str,
        req: TokenRequest,
    ) -> Result<TokenResponse, CoreError> {
        let grant = parse_grant_type(req.grant_type.as_deref())?;
        let client = ClientAuthenticator {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
            metadata_fetcher: self.metadata_fetcher.clone(),
        }
        .authenticate(tenant, issuer, &req.auth)
        .await?;
        // Malformed resources are refused before anything (a code) is consumed.
        let requested = resource::parse_resources(&req.resource)?;
        match grant {
            GrantType::AuthorizationCode => {
                check_client_grant(&client, grant)?;
                self.authorization_code(tenant, issuer, &client, &req, &requested)
                    .await
            }
            GrantType::RefreshToken => {
                check_client_grant(&client, grant)?;
                self.refresh(tenant, issuer, &client, &req, &requested)
                    .await
            }
            GrantType::ClientCredentials => {
                let scope = check_client_credentials(&client, req.scope.as_deref())?;
                let selected = client_credentials_resources(&client, &requested)?;
                self.client_credentials(tenant, issuer, &client, scope, &selected)
                    .await
            }
        }
    }

    async fn authorization_code(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        req: &TokenRequest,
        requested: &[String],
    ) -> Result<TokenResponse, CoreError> {
        let raw = req
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| CoreError::InvalidRequest("code is required".to_owned()))?;
        let now = self.clock.now();
        let grants = self.storage.grants();
        let code = match grants
            .consume_code(tenant.id, &SecretHash(secret_hash(raw)), now)
            .await?
        {
            ConsumeOutcome::Consumed(code) => code,
            ConsumeOutcome::AlreadyConsumed { family_id } => {
                // RFC 9700 §4.14: a replayed code revokes everything issued from it.
                if let Some(fid) = family_id {
                    grants
                        .revoke_family(tenant.id, fid, RevokeReason::CodeReuse, now)
                        .await?;
                }
                self.audit_reuse(
                    tenant.id,
                    client,
                    AuditAction::CodeReuseDetected,
                    family_id,
                    &req.context,
                )
                .await?;
                return Err(invalid_grant());
            }
            ConsumeOutcome::NotFound => return Err(invalid_grant()),
        };
        let family_id = code.token_family_id;
        if let Err(e) = validate_code_exchange(
            &code,
            client,
            req.redirect_uri.as_deref(),
            req.code_verifier.as_deref(),
        ) {
            // The code is burned; the family must never become usable.
            grants
                .revoke_family(tenant.id, family_id, RevokeReason::CodeReuse, now)
                .await?;
            return Err(e);
        }
        let family = match grants.get_family(tenant.id, family_id).await? {
            Some(f) if f.revoked_at.is_none() && f.client_id == client.client_id => f,
            _ => return Err(invalid_grant()),
        };
        // RFC 8707 §2.2: the token request may only downscope the resources of the grant. The
        // code is already burned, so its family must never become usable.
        let selected = match resource::downscope(&code.resource, requested) {
            Ok(selected) => selected,
            Err(e) => {
                grants
                    .revoke_family(tenant.id, family_id, RevokeReason::CodeReuse, now)
                    .await?;
                return Err(e);
            }
        };
        let user = check_user(self.storage.users().get(tenant.id, code.user_id).await?)?;
        let scope = Scope::parse(&code.scope).unwrap_or_default();
        if code.org_id != family.org_id {
            return Err(invalid_grant());
        }
        let source = self.claim_source(tenant, &user, &family, now).await?;
        let issued = issued_scope(tenant, &scope, &source);

        let minted = self
            .mint_user_tokens(
                tenant,
                issuer,
                client,
                &family,
                &user,
                &issued,
                &source,
                &selected,
                now,
                code.nonce.as_deref(),
            )
            .await?;
        let refresh_token = if client.grant_types.contains(&GrantType::RefreshToken) {
            let rt = random_token();
            grants
                .create_refresh_token(
                    tenant.id,
                    &NewRefreshToken {
                        token_hash: SecretHash(secret_hash(&rt)),
                        family_id,
                        parent_hash: None,
                        scope: scope.to_string(),
                        created_at: now,
                        expires_at: refresh_expiry(now, &family),
                    },
                )
                .await?;
            Some(rt)
        } else {
            None
        };
        Ok(response(minted, issued, refresh_token))
    }

    async fn refresh(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        req: &TokenRequest,
        requested: &[String],
    ) -> Result<TokenResponse, CoreError> {
        let raw = req
            .refresh_token
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| CoreError::InvalidRequest("refresh_token is required".to_owned()))?;
        let now = self.clock.now();
        let grants = self.storage.grants();
        let presented = SecretHash(secret_hash(raw));
        let (token, family) = grants
            .find_refresh_token(tenant.id, &presented)
            .await?
            .ok_or_else(invalid_grant)?;
        let scope = validate_refresh(&token, &family, client, req.scope.as_deref(), now)?;
        let selected = refresh_resources(&token, &family, requested)?;
        let user_id = family.user_id.ok_or_else(invalid_grant)?;
        let user = check_user(self.storage.users().get(tenant.id, user_id).await?)?;

        let rt = random_token();
        let child = NewRefreshToken {
            token_hash: SecretHash(secret_hash(&rt)),
            family_id: family.id,
            parent_hash: Some(presented),
            scope: scope.to_string(),
            created_at: now,
            expires_at: refresh_expiry(now, &family),
        };
        let family = match grants
            .rotate_refresh(tenant.id, &presented, &child, now)
            .await?
        {
            RotateOutcome::Rotated(f) => f,
            RotateOutcome::ReuseDetected { family_id } => {
                self.audit_reuse(
                    tenant.id,
                    client,
                    AuditAction::RefreshReuseDetected,
                    Some(family_id),
                    &req.context,
                )
                .await?;
                // Same wire response as invalid_grant; the variant feeds the reuse metric.
                return Err(CoreError::RefreshTokenReuse);
            }
            RotateOutcome::NotFound => return Err(invalid_grant()),
        };
        // Roles, attributes and the org membership are read again at every refresh: changes
        // apply here.
        let source = self.claim_source(tenant, &user, &family, now).await?;
        let issued = issued_scope(tenant, &scope, &source);
        let minted = self
            .mint_user_tokens(
                tenant, issuer, client, &family, &user, &issued, &source, &selected, now, None,
            )
            .await?;
        Ok(response(minted, issued, Some(rt)))
    }

    async fn client_credentials(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        scope: Scope,
        selected: &[String],
    ) -> Result<TokenResponse, CoreError> {
        let now = self.clock.now();
        // No user, so no org: `org:admin` is never issued to a client on its own behalf, even
        // when the client is allowed to request it, and no org claim is ever set.
        let scope = bound_org_admin_scope(&scope, None);
        let access_token = match client.token_format {
            TokenFormat::Opaque => {
                self.opaque_access_token(tenant.id, client, None, None, &scope, selected, now)
                    .await?
            }
            TokenFormat::Jwt => {
                let signer = self.keys().signer(tenant.id).await?;
                sign_access_token(
                    &signer,
                    &AccessTokenInput {
                        issuer,
                        sub: &client.client_id,
                        client_id: &client.client_id,
                        scope: &scope,
                        now,
                        jti: random_token(),
                        family_id: None,
                        auth_time: None,
                        acr: None,
                        resource: selected,
                    },
                )?
            }
        };
        Ok(response(
            Minted {
                access_token,
                id_token: None,
            },
            scope,
            None,
        ))
    }

    /// The user's roles, (when the schema check is wired) attribute data and the family's org
    /// claims for this issuance. A family whose org is gone or which the user left is revoked
    /// and refused with the single `invalid_grant` (belt and braces: removing a member already
    /// revokes the member's families in that org).
    async fn claim_source(
        &self,
        tenant: &Tenant,
        user: &User,
        family: &TokenFamily,
        now: OffsetDateTime,
    ) -> Result<UserClaimSource, CoreError> {
        let source = UserClaimSource::load(
            self.storage.as_ref(),
            tenant.id,
            user.id,
            self.attribute_check.is_some(),
            family.org_id,
        )
        .await?;
        if source.lost_active_org() {
            self.storage
                .grants()
                .revoke_family(tenant.id, family.id, RevokeReason::Admin, now)
                .await?;
            return Err(invalid_grant());
        }
        Ok(source)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper; every argument is a distinct input of the minted tokens"
    )]
    async fn mint_user_tokens(
        &self,
        tenant: &Tenant,
        issuer: &str,
        client: &Client,
        family: &TokenFamily,
        user: &User,
        scope: &Scope,
        source: &UserClaimSource,
        selected: &[String],
        now: OffsetDateTime,
        nonce: Option<&str>,
    ) -> Result<Minted, CoreError> {
        let check = self.attribute_check.as_deref();
        let sub = user.id.to_string();
        let mut at_signer = None;
        let access_token = match client.token_format {
            TokenFormat::Opaque => {
                self.opaque_access_token(
                    tenant.id,
                    client,
                    Some(family.id),
                    Some(user.id),
                    scope,
                    selected,
                    now,
                )
                .await?
            }
            TokenFormat::Jwt => {
                let signer = self.keys().signer(tenant.id).await?;
                let token = sign_access_token_with(
                    &signer,
                    &AccessTokenInput {
                        issuer,
                        sub: &sub,
                        client_id: &family.client_id,
                        scope,
                        now,
                        jti: random_token(),
                        family_id: Some(family.id),
                        auth_time: family.auth_time,
                        acr: family.acr.as_deref(),
                        resource: selected,
                    },
                    source.claims(tenant, scope, TokenTarget::AccessToken, check),
                    source.org_claims(tenant, scope, TokenTarget::AccessToken),
                )?;
                at_signer = Some(signer);
                token
            }
        };
        let id_token = if scope.contains("openid") {
            let alg = id_token_alg(tenant, client)?;
            let id_signer = match at_signer {
                Some(signer) if signer.alg() == alg => signer,
                _ => self.keys().signer_for(tenant.id, alg).await?,
            };
            let mut input = family_id_token_input(
                issuer,
                &sub,
                family,
                user,
                now,
                nonce,
                &access_token,
                id_signer.alg(),
            );
            for (k, v) in source.claims(tenant, scope, TokenTarget::IdToken, check) {
                input.extra.entry(k).or_insert(v);
            }
            Some(sign_id_token_with(
                &id_signer,
                &input,
                source.org_claims(tenant, scope, TokenTarget::IdToken),
            )?)
        } else {
            None
        };
        Ok(Minted {
            access_token,
            id_token,
        })
    }
}

fn response(minted: Minted, scope: Scope, refresh_token: Option<String>) -> TokenResponse {
    TokenResponse {
        access_token: minted.access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.whole_seconds(),
        scope: scope.to_string(),
        id_token: minted.id_token,
        refresh_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClientAuthMethod;
    use crate::model::{
        ACR_PWD, AMR_PWD, ClaimsRequest, RequestedClaim, SessionId, StandardClaims, TenantId,
        TokenFamilyId, UserId,
    };
    use crate::service::claims::tests::user;
    use crate::service::client_auth::tests::client;
    use crate::service::userinfo::parse_family_id;
    use anvil_jose::encoding::b64url;
    use anvil_jose::generate_rs256;
    use anvil_jose::jws::decode_header;
    use anvil_jose::keys::Alg;
    use anvil_jose::pkce::verify_s256;
    use serde_json::{Map, Value};

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn code(client_id: &str, challenge: Option<&str>) -> AuthorizationCode {
        AuthorizationCode {
            tenant_id: TenantId::new_v7(),
            code_hash: SecretHash([1; 32]),
            client_id: client_id.into(),
            user_id: UserId::new_v7(),
            session_id: SessionId::new_v7(),
            redirect_uri: "https://rp.test/cb".into(),
            scope: "openid profile".into(),
            nonce: Some("n".into()),
            code_challenge: challenge.map(str::to_owned),
            auth_time: now(),
            acr: ACR_PWD.into(),
            amr: vec![AMR_PWD.into()],
            token_family_id: TokenFamilyId::new_v7(),
            expires_at: now() + Duration::seconds(60),
            created_at: now(),
            resource: vec![],
            org_id: None,
        }
    }

    fn is_invalid_grant<T: std::fmt::Debug>(r: &Result<T, CoreError>) -> bool {
        matches!(r, Err(CoreError::InvalidGrant(_)))
    }

    #[test]
    fn rfc7636_vector_sanity() {
        assert!(verify_s256(VERIFIER, CHALLENGE));
    }

    #[test]
    fn code_exchange_bindings() {
        let c = client(ClientAuthMethod::ClientSecretBasic);
        let cb = Some("https://rp.test/cb");
        let good = code("rp", Some(CHALLENGE));
        assert!(validate_code_exchange(&good, &c, cb, Some(VERIFIER)).is_ok());

        assert!(is_invalid_grant(&validate_code_exchange(
            &code("other", Some(CHALLENGE)),
            &c,
            cb,
            Some(VERIFIER)
        )));
        assert!(is_invalid_grant(&validate_code_exchange(
            &good,
            &c,
            None,
            Some(VERIFIER)
        )));
        assert!(is_invalid_grant(&validate_code_exchange(
            &good,
            &c,
            Some("https://rp.test/cb/"),
            Some(VERIFIER)
        )));
        assert!(is_invalid_grant(&validate_code_exchange(
            &good, &c, cb, None
        )));
        assert!(is_invalid_grant(&validate_code_exchange(
            &good,
            &c,
            cb,
            Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX")
        )));
        assert!(is_invalid_grant(&validate_code_exchange(
            &good,
            &c,
            cb,
            Some("short")
        )));

        // Downgrade: no challenge at authorize, verifier at token.
        let mut lax = c.clone();
        lax.require_pkce = false;
        let no_pkce = code("rp", None);
        assert!(is_invalid_grant(&validate_code_exchange(
            &no_pkce,
            &lax,
            cb,
            Some(VERIFIER)
        )));
        assert!(validate_code_exchange(&no_pkce, &lax, cb, None).is_ok());
        // A PKCE-requiring client never accepts a code without a challenge.
        assert!(is_invalid_grant(&validate_code_exchange(
            &no_pkce, &c, cb, None
        )));
    }

    fn family(client_id: &str, scope: &str) -> TokenFamily {
        TokenFamily {
            id: TokenFamilyId::new_v7(),
            tenant_id: TenantId::new_v7(),
            client_id: client_id.into(),
            user_id: Some(UserId::new_v7()),
            scope: scope.into(),
            auth_time: Some(now() - Duration::hours(2)),
            acr: Some(ACR_PWD.into()),
            amr: vec![AMR_PWD.into()],
            session_id: Some(SessionId::new_v7()),
            claims: None,
            created_at: now() - Duration::hours(2),
            absolute_expires_at: now() + Duration::days(30),
            revoked_at: None,
            revoked_reason: None,
            resource: vec![],
            org_id: None,
        }
    }

    fn rt(f: &TokenFamily) -> RefreshToken {
        RefreshToken {
            token_hash: SecretHash([2; 32]),
            tenant_id: f.tenant_id,
            family_id: f.id,
            parent_hash: None,
            scope: f.scope.clone(),
            created_at: now() - Duration::hours(1),
            expires_at: now() + Duration::days(13),
            consumed_at: None,
        }
    }

    #[test]
    fn refresh_wrong_client_rejected_before_consume() {
        let f = family("someone-else", "openid profile");
        let c = client(ClientAuthMethod::ClientSecretBasic);
        // Even an already-consumed token from another client must not reach rotate_refresh.
        let mut consumed = rt(&f);
        consumed.consumed_at = Some(now());
        for t in [rt(&f), consumed] {
            assert!(is_invalid_grant(&validate_refresh(&t, &f, &c, None, now())));
        }
    }

    #[test]
    fn refresh_scope_may_only_narrow() {
        let f = family("rp", "openid profile");
        let c = client(ClientAuthMethod::ClientSecretBasic);
        let t = rt(&f);
        assert_eq!(
            validate_refresh(&t, &f, &c, None, now())
                .unwrap()
                .to_string(),
            "openid profile"
        );
        assert_eq!(
            validate_refresh(&t, &f, &c, Some("openid"), now())
                .unwrap()
                .to_string(),
            "openid"
        );
        assert!(matches!(
            validate_refresh(&t, &f, &c, Some("openid email"), now()),
            Err(CoreError::InvalidScope(_))
        ));
    }

    #[test]
    fn refresh_consumed_token_passes_to_reuse_detection() {
        let f = family("rp", "openid profile");
        let c = client(ClientAuthMethod::ClientSecretBasic);
        let mut t = rt(&f);
        t.consumed_at = Some(now() - Duration::minutes(1));
        // Even with a widened scope: the reuse path must run and revoke the family.
        assert!(validate_refresh(&t, &f, &c, Some("openid email"), now()).is_ok());
    }

    #[test]
    fn refresh_expired_or_revoked_rejected() {
        let c = client(ClientAuthMethod::ClientSecretBasic);
        let mut f = family("rp", "openid");
        f.revoked_at = Some(now());
        assert!(is_invalid_grant(&validate_refresh(
            &rt(&f),
            &f,
            &c,
            None,
            now()
        )));
        let f = family("rp", "openid");
        let mut t = rt(&f);
        t.expires_at = now();
        assert!(is_invalid_grant(&validate_refresh(&t, &f, &c, None, now())));
        let mut f2 = family("rp", "openid");
        f2.absolute_expires_at = now();
        assert!(is_invalid_grant(&validate_refresh(
            &rt(&f2),
            &f2,
            &c,
            None,
            now()
        )));
    }

    #[test]
    fn refresh_expiry_capped_by_family() {
        let mut f = family("rp", "openid");
        assert_eq!(refresh_expiry(now(), &f), now() + Duration::days(14));
        f.absolute_expires_at = now() + Duration::days(3);
        assert_eq!(refresh_expiry(now(), &f), now() + Duration::days(3));
    }

    const API: &str = "https://api.example.test";
    const MCP: &str = "https://mcp.example.test/mcp";

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn refresh_resources_downscope_within_the_family_grant() {
        let mut f = family("rp", "openid");
        f.resource = strs(&[API, MCP]);
        let t = rt(&f);
        assert_eq!(refresh_resources(&t, &f, &[]).unwrap(), strs(&[API, MCP]));
        assert_eq!(
            refresh_resources(&t, &f, &strs(&[MCP])).unwrap(),
            strs(&[MCP])
        );
        for bad in [
            strs(&["https://other.example.test"]),
            strs(&[API, "https://x.example.test"]),
        ] {
            assert!(matches!(
                refresh_resources(&t, &f, &bad),
                Err(CoreError::InvalidTarget(_))
            ));
        }
        // A family without resources cannot gain one at refresh.
        let plain = family("rp", "openid");
        assert!(matches!(
            refresh_resources(&rt(&plain), &plain, &strs(&[API])),
            Err(CoreError::InvalidTarget(_))
        ));
    }

    #[test]
    fn refresh_resources_let_a_consumed_token_reach_reuse_detection() {
        let mut f = family("rp", "openid");
        f.resource = strs(&[API]);
        let mut t = rt(&f);
        t.consumed_at = Some(now() - Duration::minutes(1));
        assert_eq!(
            refresh_resources(&t, &f, &strs(&["https://other.example.test"])).unwrap(),
            strs(&[API])
        );
    }

    #[test]
    fn client_credentials_resources_must_be_allowed() {
        let mut c = client(ClientAuthMethod::ClientSecretBasic);
        assert_eq!(
            client_credentials_resources(&c, &[]).unwrap(),
            Vec::<String>::new()
        );
        assert!(matches!(
            client_credentials_resources(&c, &strs(&[API])),
            Err(CoreError::InvalidTarget(_))
        ));
        c.allowed_resources = strs(&[API, MCP]);
        assert_eq!(
            client_credentials_resources(&c, &strs(&[MCP])).unwrap(),
            strs(&[MCP])
        );
        assert!(matches!(
            client_credentials_resources(&c, &strs(&[API, "https://api.example.test/"])),
            Err(CoreError::InvalidTarget(_))
        ));
    }

    #[test]
    fn client_credentials_rules() {
        let mut c = client(ClientAuthMethod::ClientSecretBasic);
        c.scopes = vec!["openid".into(), "api.read".into(), "api.write".into()];
        assert!(matches!(
            check_client_credentials(&c, None),
            Err(CoreError::UnauthorizedClient(_))
        ));
        c.grant_types.push(GrantType::ClientCredentials);
        assert_eq!(
            check_client_credentials(&c, None).unwrap().to_string(),
            "api.read api.write"
        );
        assert_eq!(
            check_client_credentials(&c, Some("api.read"))
                .unwrap()
                .to_string(),
            "api.read"
        );
        assert!(matches!(
            check_client_credentials(&c, Some("openid api.read")),
            Err(CoreError::InvalidScope(_))
        ));
        assert!(matches!(
            check_client_credentials(&c, Some("admin")),
            Err(CoreError::InvalidScope(_))
        ));
        let mut public = client(ClientAuthMethod::None);
        public.grant_types.push(GrantType::ClientCredentials);
        assert!(matches!(
            check_client_credentials(&public, None),
            Err(CoreError::UnauthorizedClient(_))
        ));
    }

    #[test]
    fn grant_type_parsing() {
        assert!(matches!(
            parse_grant_type(None),
            Err(CoreError::InvalidRequest(_))
        ));
        assert!(matches!(
            parse_grant_type(Some("")),
            Err(CoreError::InvalidRequest(_))
        ));
        for g in [
            "password",
            "implicit",
            "urn:ietf:params:oauth:grant-type:device_code",
            "AUTHORIZATION_CODE",
        ] {
            assert!(
                matches!(
                    parse_grant_type(Some(g)),
                    Err(CoreError::UnsupportedGrantType)
                ),
                "{g}"
            );
        }
        assert_eq!(
            parse_grant_type(Some("refresh_token")).unwrap(),
            GrantType::RefreshToken
        );
    }

    #[test]
    fn client_must_hold_the_grant() {
        let c = client(ClientAuthMethod::ClientSecretBasic);
        assert!(check_client_grant(&c, GrantType::AuthorizationCode).is_ok());
        assert!(matches!(
            check_client_grant(&c, GrantType::ClientCredentials),
            Err(CoreError::UnauthorizedClient(_))
        ));
    }

    #[test]
    fn blocked_or_missing_user_is_invalid_grant() {
        assert!(is_invalid_grant(&check_user(None)));
        let mut u = user(StandardClaims::default());
        u.status = UserStatus::Blocked;
        assert!(is_invalid_grant(&check_user(Some(u))));
        assert!(check_user(Some(user(StandardClaims::default()))).is_ok());
    }

    fn signer() -> SigningKey {
        let g = generate_rs256().unwrap();
        SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap()
    }

    fn claims_of(token: &str) -> Map<String, Value> {
        let payload = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&anvil_jose::encoding::b64url_decode(payload).unwrap()).unwrap()
    }

    #[test]
    fn refreshed_id_token_reuses_family_context_without_nonce() {
        let mut f = family("rp", "openid email");
        f.claims = Some(ClaimsRequest {
            userinfo: vec![],
            id_token: vec![RequestedClaim {
                name: "email".into(),
                essential: true,
                values: vec![],
            }],
        });
        let u = user(StandardClaims::default());
        let sub = u.id.to_string();
        let input = family_id_token_input(
            "https://op.test",
            &sub,
            &f,
            &u,
            now(),
            None,
            "at",
            Alg::RS256,
        );
        assert_eq!(input.auth_time, f.auth_time);
        assert_eq!(input.acr, Some(ACR_PWD));
        assert_eq!(input.amr, f.amr.as_slice());
        assert_eq!(input.client_id, "rp");
        assert!(input.nonce.is_none());
        assert_eq!(input.sid, f.session_id.map(|s| s.to_string()));
        assert_eq!(
            input.at_hash.as_deref(),
            Some(anvil_jose::encoding::at_hash("at").as_str())
        );

        let s = signer();
        let id = sign_id_token(&s, &input).unwrap();
        let header = decode_header(&id).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let c = claims_of(&id);
        assert!(!c.contains_key("nonce"));
        assert_eq!(c["iss"], "https://op.test");
        assert_eq!(c["sub"], sub.as_str());
        assert_eq!(c["aud"], serde_json::json!(["rp"]));
        assert_eq!(c["azp"], "rp");
        assert_eq!(c["auth_time"], f.auth_time.unwrap().unix_timestamp());
        assert_eq!(c["email"], "alice@example.test", "claims.id_token honoured");
    }

    #[test]
    fn at_hash_follows_the_id_token_alg() {
        let f = family("rp", "openid");
        let u = user(StandardClaims::default());
        let sub = u.id.to_string();
        for alg in [Alg::RS256, Alg::ES256, Alg::Ed25519] {
            let input =
                family_id_token_input("https://op.test", &sub, &f, &u, now(), None, "at", alg);
            assert_eq!(input.at_hash, Some(token_hash(alg, "at")));
        }
        let sha256 = family_id_token_input("i", &sub, &f, &u, now(), None, "at", Alg::ES256);
        let sha512 = family_id_token_input("i", &sub, &f, &u, now(), None, "at", Alg::Ed25519);
        assert_ne!(sha256.at_hash, sha512.at_hash);
    }

    fn tenant(algs: &[&str]) -> Tenant {
        Tenant {
            id: crate::model::TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings: crate::model::TenantSettings {
                signing_algs: algs.iter().map(|a| (*a).to_owned()).collect(),
                ..crate::model::TenantSettings::default()
            },
            created_at: now(),
        }
    }

    #[test]
    fn id_token_alg_defaults_to_rs256_and_never_falls_back() {
        let mut c = client(ClientAuthMethod::None);
        assert_eq!(id_token_alg(&tenant(&[]), &c).unwrap(), Alg::RS256);

        c.id_token_signed_response_alg = Some("ES256".into());
        assert_eq!(
            id_token_alg(&tenant(&["RS256", "ES256"]), &c).unwrap(),
            Alg::ES256
        );
        // Not enabled for the tenant: server error, not RS256.
        assert!(matches!(
            id_token_alg(&tenant(&["RS256"]), &c),
            Err(CoreError::Internal(_))
        ));

        c.id_token_signed_response_alg = Some("Ed25519".into());
        assert_eq!(
            id_token_alg(&tenant(&["Ed25519"]), &c).unwrap(),
            Alg::Ed25519
        );
        for bad in ["EdDSA", "HS256", "none", ""] {
            c.id_token_signed_response_alg = Some(bad.into());
            assert!(matches!(
                id_token_alg(&tenant(&["RS256", "ES256", "Ed25519"]), &c),
                Err(CoreError::Internal(_))
            ));
        }
    }

    #[test]
    fn access_token_signed_with_at_jwt_typ_and_kid() {
        let s = signer();
        let scope = Scope::parse("openid").unwrap();
        let fid = TokenFamilyId::new_v7();
        let at = sign_access_token(
            &s,
            &AccessTokenInput {
                issuer: "https://op.test",
                sub: "u1",
                client_id: "rp",
                scope: &scope,
                now: now(),
                jti: "j".into(),
                family_id: Some(fid),
                auth_time: None,
                acr: None,
                resource: &[],
            },
        )
        .unwrap();
        let h = decode_header(&at).unwrap();
        assert_eq!(h.typ.as_deref(), Some("at+jwt"));
        assert_eq!(h.kid.as_deref(), Some(s.kid()));
        let c = claims_of(&at);
        assert_eq!(c["aud"], "rp");
        assert_eq!(parse_family_id(c["fid"].as_str().unwrap()), Some(fid));
    }

    #[test]
    fn opaque_access_token_is_stored_as_sha256_with_family_and_lifetime() {
        let scope = Scope::parse("openid profile").unwrap();
        let fid = TokenFamilyId::new_v7();
        let uid = UserId::new_v7();
        let raw = random_token();
        assert!(!raw.contains('.'), "opaque tokens are never JWT-shaped");
        assert_eq!(raw.len(), 43, "256 bits, base64url without padding");
        let rec = new_opaque_access_token(&raw, "rp", Some(fid), Some(uid), &scope, &[], now());
        assert_eq!(rec.token_hash, SecretHash(secret_hash(&raw)));
        assert_eq!(rec.family_id, Some(fid));
        assert_eq!(rec.user_id, Some(uid));
        assert_eq!(rec.client_id, "rp");
        assert_eq!(rec.scope, "openid profile");
        assert_eq!(rec.created_at, now());
        assert_eq!(rec.expires_at, now() + ACCESS_TOKEN_TTL);
        // Client credentials: no family, no user.
        let cc = new_opaque_access_token(&raw, "svc", None, None, &scope, &[], now());
        assert!(cc.family_id.is_none() && cc.user_id.is_none());
        assert!(rec.resource.is_empty() && cc.resource.is_empty());
        // The selected resources are stored on the opaque token row (introspection aud).
        let api = vec!["https://api.example.test".to_owned()];
        let bound = new_opaque_access_token(&raw, "rp", Some(fid), Some(uid), &scope, &api, now());
        assert_eq!(bound.resource, api);
    }

    #[test]
    fn token_response_serialisation() {
        let r = response(
            Minted {
                access_token: "at".into(),
                id_token: None,
            },
            Scope::parse("api").unwrap(),
            None,
        );
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["expires_in"], 600);
        assert_eq!(v["scope"], "api");
        assert!(v.get("id_token").is_none() && v.get("refresh_token").is_none());
        assert!(!format!("{r:?}").contains("\"at\""));
    }

    #[test]
    fn token_request_debug_redacts() {
        let r = TokenRequest {
            code: Some("c0de-secret".into()),
            refresh_token: Some("rt-secret".into()),
            code_verifier: Some(b64url(b"verifier-secret")),
            resource: vec![API.to_owned()],
            ..TokenRequest::default()
        };
        let s = format!("{r:?}");
        assert!(!s.contains("c0de-secret") && !s.contains("rt-secret"));
        assert!(!s.contains(&b64url(b"verifier-secret")));
        assert!(s.contains(API), "resources are not secret");
    }
}
