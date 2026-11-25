//! Authentication and request plumbing of the management API.
//!
//! - [`AdminAuth`]: the bearer-token extractor. The token must be an access token issued by the
//!   system tenant (`iss` = the system issuer, `typ` = `at+jwt`, family not revoked), checked by
//!   the single access-token validator [`AccessTokenVerifier`]. Handlers then demand their admin
//!   scope with [`AdminAuth::require`].
//! - [`AdminError`]: every failure leaves as RFC 9457 problem JSON through
//!   [`errors::problem_json`]; authentication failures add an RFC 6750 `WWW-Authenticate`.
//! - [`AdminJson`] / [`AdminQuery`]: body and query extractors whose rejections are problems too.
//!
//! The API is installation-level: requests addressed to a tenant base other than the root
//! (`/t/{slug}/api/admin/v1/…`, custom hosts) get 404. Bearer-authenticated, no cookies, so the
//! browser CSRF layer does not apply.

use anvil_core::error::CoreError;
use anvil_core::model::{AuditActor, SYSTEM_TENANT_SLUG, TenantBase, issuer};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::service::admin_scope::{ADMIN_WRITE, Access, Resource, scope_satisfies};
use anvil_core::service::client::ClientService;
use anvil_core::service::tenant::TenantService;
use anvil_core::service::user::UserService;
use anvil_core::service::userinfo::{AccessTokenClaims, AccessTokenVerifier};
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Query, Request};
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

    fn admin_verifier(&self) -> AccessTokenVerifier {
        AccessTokenVerifier {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }

    /// The canonical issuer of a managed tenant (used in emailed links): its custom host, the
    /// public URL for `default`, else `/t/{slug}`.
    pub(crate) fn admin_issuer_of(&self, tenant: &anvil_core::model::Tenant) -> String {
        let base = match &tenant.host {
            Some(h) => TenantBase::Host(h.clone()),
            None if tenant.slug == anvil_core::model::DEFAULT_TENANT_SLUG => TenantBase::Root,
            None => TenantBase::Path(tenant.slug.clone()),
        };
        issuer(&self.config().public_url, &base)
    }
}

/// A management API failure.
#[derive(Debug)]
pub(crate) enum AdminError {
    /// No bearer token was presented (RFC 6750 §3.1: challenge without an error code).
    MissingToken,
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

/// An authenticated management API caller.
#[derive(Debug, Clone)]
pub(crate) struct AdminAuth {
    pub(crate) claims: AccessTokenClaims,
}

impl AdminAuth {
    /// The audit actor of this caller: kind `admin`, id = the token subject (the client id for
    /// client-credentials tokens, the administrator's user id for console tokens).
    pub(crate) fn actor(&self) -> AuditActor {
        AuditActor::admin(&self.claims.sub)
    }

    /// Demands the admin scope for `access` on `resource` (403 `insufficient_scope` otherwise).
    pub(crate) fn require(&self, resource: Resource, access: Access) -> AdminResult<()> {
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
        Ok(Self { claims })
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
