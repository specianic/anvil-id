//! Authentication and request plumbing of the management API.
//!
//! - [`AdminAuth`]: the bearer-token extractor. The token must be an access token issued by the
//!   system tenant (`iss` = the system issuer, `typ` = `at+jwt`, family not revoked), checked by
//!   the single access-token validator [`AccessTokenVerifier`]. Handlers then demand their admin
//!   scope with [`AdminAuth::require`]. Its principal is always [`Principal::SystemAdmin`].
//! - [`OrgAdminAuth`]: the same extractor for the organization sub-routes
//!   (`/tenants/{slug}/organizations/{org}/…`, decision Q1). It accepts a system-tenant token
//!   ([`Principal::SystemAdmin`], admin scopes checked by the handler) or an access token issued
//!   by tenant `{slug}` itself ([`Principal::OrgAdmin`]): a JWT (opaque org-admin tokens are
//!   refused; org admins need a JWT access-token client) verified against the tenant's canonical
//!   issuer with the same verifier, whose `aud` contains the management API resource
//!   `{public_url}/api/admin/v1` (requested with RFC 8707 `resource`; the client must still
//!   allow it), whose client still exists, carrying scope `org:admin` and an `org_id` claim equal
//!   to `{org}`, with a live family bound to that org and user; the user must be active, a
//!   member, and still hold `org:admin` in the org ([`OrgService::org_admin_principal`],
//!   re-checked on every request). Such a token is refused everywhere else: every route outside
//!   the org sub-routes uses [`AdminAuth`], and [`AdminAuth::require`] refuses an org admin.
//! - [`AdminError`]: every failure leaves as RFC 9457 problem JSON through
//!   [`errors::problem_json`]; authentication failures add an RFC 6750 `WWW-Authenticate`.
//! - [`AdminJson`] / [`AdminQuery`]: body and query extractors whose rejections are problems too.
//!
//! The API is installation-level: requests addressed to a tenant base other than the root
//! (`/t/{slug}/api/admin/v1/…`, custom hosts) get 404. Bearer-authenticated, no cookies, so the
//! browser CSRF layer does not apply.

use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditActor, Organization, SYSTEM_TENANT_SLUG, Tenant, TenantBase, UserId, issuer,
};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::service::admin_scope::{ADMIN_WRITE, Access, Resource, scope_satisfies};
use anvil_core::service::client::ClientService;
use anvil_core::service::org_invitation::OrgInvitationService;
use anvil_core::service::organization::{OrgActor, OrgService};
use anvil_core::service::tenant::TenantService;
use anvil_core::service::user::UserService;
use anvil_core::service::userinfo::{AccessTokenClaims, AccessTokenVerifier, is_jwt_shaped};
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Query, RawPathParams, Request};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::errors;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Service constructors for the admin handlers (handlers never touch storage directly).
impl AppState {
    pub(crate) fn admin_tenants(&self) -> TenantService {
        TenantService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
        }
    }

    pub(crate) fn admin_clients(&self) -> ClientService {
        ClientService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            redirect_validator: validate_redirect_uri,
        }
    }

    pub(crate) fn admin_users(&self) -> UserService {
        UserService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            hasher: self.hasher_arc(),
            policy: self.config().password_policy,
            kek: self.kek_arc(),
        }
    }

    pub(crate) fn admin_orgs(&self) -> OrgService {
        OrgService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }

    pub(crate) fn admin_org_invitations(&self) -> OrgInvitationService {
        OrgInvitationService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
        }
    }

    /// The management API as an RFC 8707 resource: `{public_url}/api/admin/v1`. An org admin's
    /// token must carry it in `aud`.
    pub(crate) fn admin_api_resource(&self) -> String {
        format!("{}{}", self.config().public_url.as_str(), super::BASE_PATH)
    }

    fn admin_verifier(&self) -> AccessTokenVerifier {
        AccessTokenVerifier {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }

    /// The canonical issuer of a managed tenant (used in emailed links): its custom host, the
    /// public URL for `default`, else `/t/{slug}`.
    pub(crate) fn admin_issuer_of(&self, tenant: &anvil_core::model::Tenant) -> String {
        anvil_core::service::logout::canonical_issuer(&self.config().public_url, tenant)
    }
}

/// A management API failure.
#[derive(Debug)]
pub(crate) enum AdminError {
    /// No bearer token was presented (RFC 6750 §3.1: challenge without an error code).
    MissingToken,
    /// The body was over the request body limit (also when streamed without `Content-Length`):
    /// a 413 problem.
    PayloadTooLarge(String),
    Core(CoreError),
}

impl From<CoreError> for AdminError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

fn invalid_token() -> CoreError {
    CoreError::InvalidToken("the access token is invalid or expired".to_owned())
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (err, challenge) = match self {
            Self::PayloadTooLarge(detail) => return payload_too_large(&detail),
            Self::MissingToken => (
                CoreError::InvalidToken("a bearer access token is required".to_owned()),
                "Bearer realm=\"anvilid\"",
            ),
            Self::Core(e) => {
                let challenge = match &e {
                    CoreError::InvalidToken(_) => {
                        "Bearer realm=\"anvilid\", error=\"invalid_token\""
                    }
                    CoreError::InsufficientScope(_) => {
                        "Bearer realm=\"anvilid\", error=\"insufficient_scope\""
                    }
                    _ => "",
                };
                (e, challenge)
            }
        };
        let mut resp = errors::problem_json(&err);
        if !challenge.is_empty() {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        resp
    }
}

/// The 413 problem: the [`errors::problem_json`] document of an `invalid_request` with the
/// status replaced (`CoreError` has no 413 kind; this is the only body-size answer of the API).
fn payload_too_large(detail: &str) -> Response {
    let status = StatusCode::PAYLOAD_TOO_LARGE;
    let body = serde_json::json!({
        "type": format!(
            "urn:anvilid:problem:{}",
            CoreError::InvalidRequest(String::new()).oauth_error()
        ),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "detail": detail,
        "errors": [],
    });
    let mut resp = (status, body.to_string()).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

pub(crate) type AdminResult<T> = Result<T, AdminError>;

/// Rejects requests that address a tenant instead of the installation root.
pub(crate) fn installation_level(parts: &Parts) -> AdminResult<()> {
    match parts.extensions.get::<ResolvedTenant>() {
        Some(t) if t.base == TenantBase::Root => Ok(()),
        _ => Err(CoreError::NotFound.into()),
    }
}

/// The bearer token of the `Authorization` header (scheme case-insensitive). Tokens in the query
/// string or body are not accepted.
fn bearer(parts: &Parts) -> AdminResult<&str> {
    let mut values = parts.headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(AdminError::MissingToken);
    };
    if values.next().is_some() {
        return Err(invalid_token().into());
    }
    let raw = value.to_str().map_err(|_| invalid_token())?;
    let (scheme, token) = raw.split_once(' ').ok_or_else(invalid_token)?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || token.contains(' ') {
        return Err(invalid_token().into());
    }
    Ok(token)
}

/// Who an authenticated management API caller is.
#[derive(Debug, Clone)]
pub(crate) enum Principal {
    /// A system-tenant access token; its admin scopes decide what it may do.
    SystemAdmin,
    /// An org admin of `org` in `tenant` (an access token issued by `tenant`, decision Q1). Only
    /// the org sub-routes accept it ([`OrgAdminAuth`]); the tenant and org are the path's, already
    /// resolved and checked by the extractor.
    OrgAdmin {
        tenant: Box<Tenant>,
        org: Box<Organization>,
        user: UserId,
    },
}

/// An authenticated management API caller.
#[derive(Debug, Clone)]
pub(crate) struct AdminAuth {
    pub(crate) claims: AccessTokenClaims,
    pub(crate) principal: Principal,
}

fn org_admin_refused() -> AdminError {
    CoreError::InsufficientScope("this operation requires a tenant administrator".to_owned()).into()
}

impl AdminAuth {
    /// The audit actor of this caller: kind `admin`, id = the token subject (the client id for
    /// client-credentials tokens, the administrator's user id for console tokens); an org admin
    /// is recorded as the tenant user they are.
    pub(crate) fn actor(&self) -> AuditActor {
        self.org_actor().audit_actor()
    }

    /// The actor of an organization administration call (the lockout guard applies to org
    /// admins only).
    pub(crate) fn org_actor(&self) -> OrgActor {
        match &self.principal {
            Principal::SystemAdmin => OrgActor::TenantAdmin(AuditActor::admin(&self.claims.sub)),
            Principal::OrgAdmin { user, .. } => OrgActor::OrgAdmin(*user),
        }
    }

    /// Refuses an org admin (403): org creation, update and deletion, and adding members
    /// directly, are for tenant administrators only.
    pub(crate) fn require_system_admin(&self) -> AdminResult<()> {
        match self.principal {
            Principal::SystemAdmin => Ok(()),
            Principal::OrgAdmin { .. } => Err(org_admin_refused()),
        }
    }

    /// Demands the admin scope for `access` on `resource` (403 `insufficient_scope` otherwise).
    /// An org admin never satisfies an admin scope.
    pub(crate) fn require(&self, resource: Resource, access: Access) -> AdminResult<()> {
        self.require_system_admin()?;
        if scope_satisfies(&self.claims.scope, resource, access) {
            Ok(())
        } else {
            Err(CoreError::InsufficientScope(format!(
                "this operation requires {} access to {}",
                match access {
                    Access::Read => "read",
                    Access::Write => "write",
                },
                resource.as_str()
            ))
            .into())
        }
    }

    /// Demands `admin:write`. Used for changes to the system tenant's clients: a system client
    /// can carry admin scopes, so writing them is equivalent to full administration and a
    /// narrower scope (e.g. `admin:clients:write`) must not escalate to it.
    pub(crate) fn require_full_admin(&self) -> AdminResult<()> {
        self.require_system_admin()?;
        if self.claims.scope.contains(ADMIN_WRITE) {
            Ok(())
        } else {
            Err(CoreError::InsufficientScope(
                "changing clients of the system tenant requires admin:write".to_owned(),
            )
            .into())
        }
    }
}

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AdminResult<Self> {
        installation_level(parts)?;
        let token = bearer(parts)?;
        let claims = system_claims(state, token).await?;
        Ok(Self {
            claims,
            principal: Principal::SystemAdmin,
        })
    }
}

/// Verifies a system-tenant access token whose client still exists.
async fn system_claims(state: &AppState, token: &str) -> AdminResult<AccessTokenClaims> {
    let system = state
        .admin_tenants()
        .get(SYSTEM_TENANT_SLUG)
        .await
        .map_err(|e| match e {
            CoreError::NotFound => CoreError::Internal("the system tenant is missing".into()),
            other => other,
        })?;
    let system_issuer = issuer(
        &state.config().public_url,
        &TenantBase::Path(SYSTEM_TENANT_SLUG.to_owned()),
    );
    let claims = state
        .admin_verifier()
        .verify(system.id, &system_issuer, token)
        .await?;
    // The token's client must still exist: deleting an admin client cuts off its tokens
    // immediately instead of at expiry.
    match state
        .admin_clients()
        .get(system.id, &claims.client_id)
        .await
    {
        Ok(_) => {}
        Err(CoreError::NotFound) => return Err(invalid_token().into()),
        Err(e) => return Err(e.into()),
    }
    Ok(claims)
}

/// The caller of an organization sub-route: a system administrator or the org admin of the path's
/// org (see the module documentation).
#[derive(Debug, Clone)]
pub(crate) struct OrgAdminAuth(pub(crate) AdminAuth);

/// A string claim of a JWT whose signature, `typ`, `iss` and `exp` were already verified by
/// [`AccessTokenVerifier`] (never used on an unverified token).
fn verified_str_claim(token: &str, name: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = anvil_jose::encoding::b64url_decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get(name)?.as_str().map(str::to_owned)
}

impl FromRequestParts<AppState> for OrgAdminAuth {
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AdminResult<Self> {
        installation_level(parts)?;
        let token = bearer(parts)?.to_owned();
        match system_claims(state, &token).await {
            Ok(claims) => {
                return Ok(Self(AdminAuth {
                    claims,
                    principal: Principal::SystemAdmin,
                }));
            }
            Err(AdminError::Core(CoreError::InvalidToken(_))) => {}
            Err(e) => return Err(e),
        }
        // Not a system token: it may be an org admin's token of the path's tenant.
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(|_| CoreError::NotFound)?;
        let param = |name: &str| {
            params
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_owned())
        };
        let (Some(slug), Some(org_key)) = (param("slug"), param("org")) else {
            return Err(invalid_token().into());
        };
        // Opaque org-admin tokens are refused: the org binding is read from the JWT.
        if slug == SYSTEM_TENANT_SLUG || !is_jwt_shaped(&token) {
            return Err(invalid_token().into());
        }
        let tenant = match state.admin_tenants().get(&slug).await {
            Ok(t) => t,
            Err(CoreError::NotFound) => return Err(invalid_token().into()),
            Err(e) => return Err(e.into()),
        };
        let claims = state
            .admin_verifier()
            .verify(tenant.id, &state.admin_issuer_of(&tenant), &token)
            .await?;
        // Audience: only tokens minted for the management API (an RP's token is not replayable).
        let resource = state.admin_api_resource();
        if !claims.aud.contains(&resource) {
            return Err(invalid_token().into());
        }
        // The client must still exist and still be allowed the management API resource.
        match state
            .admin_clients()
            .get(tenant.id, &claims.client_id)
            .await
        {
            Ok(c) if c.allowed_resources.contains(&resource) => {}
            Ok(_) | Err(CoreError::NotFound) => return Err(invalid_token().into()),
            Err(e) => return Err(e.into()),
        }
        let org_claim = verified_str_claim(&token, "org_id");
        let (org, user) = state
            .admin_orgs()
            .org_admin_principal(&tenant, &org_key, &claims, org_claim.as_deref())
            .await?;
        Ok(Self(AdminAuth {
            claims,
            principal: Principal::OrgAdmin {
                tenant: Box::new(tenant),
                org: Box::new(org),
                user,
            },
        }))
    }
}

/// A JSON body whose rejection is a problem response (422 for a body that does not match the
/// schema, 400 for malformed JSON or a missing `Content-Type: application/json`).
pub(crate) struct AdminJson<T>(pub(crate) T);

impl<T, S> FromRequest<S> for AdminJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AdminError;

    async fn from_request(req: Request, state: &S) -> AdminResult<Self> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(v)) => Ok(Self(v)),
            Err(JsonRejection::JsonDataError(e)) => Err(CoreError::Validation {
                field: "body",
                message: e.body_text(),
            }
            .into()),
            Err(e) if crate::ui::rejection_is_too_large(&e) => {
                Err(AdminError::PayloadTooLarge(e.body_text()))
            }
            Err(e) => Err(CoreError::InvalidRequest(e.body_text()).into()),
        }
    }
}

/// Query parameters whose rejection is a 422 problem.
pub(crate) struct AdminQuery<T>(pub(crate) T);

impl<T, S> FromRequestParts<S> for AdminQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> AdminResult<Self> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(v)) => Ok(Self(v)),
            Err(e) => {
                let message = match e {
                    QueryRejection::FailedToDeserializeQueryString(e) => e.body_text(),
                    other => other.body_text(),
                };
                Err(CoreError::Validation {
                    field: "query",
                    message,
                }
                .into())
            }
        }
    }
}

/// A JSON response with `Cache-Control: no-store` (responses can carry client secrets).
pub(crate) fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let mut resp = (status, axum::Json(body)).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `201 Created` with a `Location` header.
pub(crate) fn created<T: Serialize>(location: &str, body: &T) -> Response {
    let mut resp = json(StatusCode::CREATED, body);
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// `204 No Content`.
pub(crate) fn no_content() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

/// Validates a list query (`limit` 1..=200).
pub(crate) fn page_request(
    q: crate::admin::dto::ListQuery,
) -> AdminResult<anvil_core::model::PageRequest> {
    let limit = match q.limit {
        None => 0,
        Some(l @ 1..=200) => l,
        Some(_) => {
            return Err(CoreError::Validation {
                field: "limit",
                message: "must be between 1 and 200".to_owned(),
            }
            .into());
        }
    };
    Ok(anvil_core::model::PageRequest {
        after: q.after,
        limit,
    })
}
