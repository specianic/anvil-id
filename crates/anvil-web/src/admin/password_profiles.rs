//! Password hash profiles of a tenant for imported hashes (ADM-08).
//!
//! - `GET /api/admin/v1/tenants/{slug}/password-hash-profiles` (`admin:settings:read`): every
//!   profile, public parameters only.
//! - `POST …/password-hash-profiles` (`admin:settings:write`): creates a Firebase scrypt profile
//!   from the project's hash parameters (`signer_key` and `salt_separator` as standard base64,
//!   as Firebase shows them). The signer key is write-only: it is sealed with the KEK by
//!   [`HashProfileService`] and never appears in any response, log or OpenAPI response schema.
//! - `DELETE …/password-hash-profiles/{id}` (`admin:settings:write`): 409 while imported
//!   password hashes still reference the profile.
//!
//! Imported Firebase records name the profile by its `id` (docs/IMPORT-EXPORT.md). Creation and
//! deletion are audited by the service (`password_profile_created`, `password_profile_deleted`).

use std::fmt;

use anvil_core::error::CoreError;
use anvil_core::model::{ProfileKind, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::hash_profile::{HashProfileService, HashProfileSummary, NewHashProfile};
use anvil_jose::encoding::{b64std, b64std_decode};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use zeroize::Zeroize as _;

use super::auth::{AdminAuth, AdminJson, AdminResult, created, json, no_content};
use super::dto::Problem;
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    /// The hash profile service.
    fn admin_hash_profiles(&self) -> HashProfileService {
        HashProfileService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
        }
    }
}

/// The routes of this resource.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_hash_profiles, create_hash_profile))
        .routes(routes!(delete_hash_profile))
}

/// A new hash profile. `Debug` never prints the signer key.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateHashProfile {
    /// Unique name in the tenant (1-64 characters).
    pub name: String,
    /// The hash algorithm family; only `firebase_scrypt` today.
    pub kind: String,
    /// Firebase `base64_signer_key` (standard base64, 1-256 bytes decoded). Write-only: never
    /// returned.
    #[schema(write_only)]
    pub signer_key: String,
    /// Firebase `base64_salt_separator` (standard base64, at most 64 bytes decoded).
    pub salt_separator: String,
    /// Firebase `rounds`.
    pub rounds: u32,
    /// Firebase `mem_cost`.
    pub mem_cost: u8,
}

impl fmt::Debug for CreateHashProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateHashProfile")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("signer_key", &"[redacted]")
            .field("salt_separator", &self.salt_separator)
            .field("rounds", &self.rounds)
            .field("mem_cost", &self.mem_cost)
            .finish()
    }
}

impl Drop for CreateHashProfile {
    fn drop(&mut self) {
        self.signer_key.zeroize();
    }
}

/// A hash profile: public parameters only (the signer key is never returned).
#[derive(Debug, Serialize, ToSchema)]
pub struct HashProfileView {
    /// Referenced by imported Firebase records (`"profile": "<id>"`).
    pub id: uuid::Uuid,
    pub name: String,
    /// `firebase_scrypt`.
    pub kind: String,
    /// Standard base64.
    pub salt_separator: String,
    pub rounds: u32,
    pub mem_cost: u8,
    /// RFC 3339.
    pub created_at: String,
}

impl From<HashProfileSummary> for HashProfileView {
    fn from(p: HashProfileSummary) -> Self {
        Self {
            id: p.id,
            name: p.name,
            kind: p.kind.as_str().to_owned(),
            salt_separator: b64std(&p.salt_separator),
            rounds: p.rounds,
            mem_cost: p.mem_cost,
            created_at: p.created_at.format(&Rfc3339).unwrap_or_default(),
        }
    }
}

/// Every hash profile of a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct HashProfileList {
    pub items: Vec<HashProfileView>,
}

async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Settings, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// A profile id from the path; anything that is not a UUID names no profile (404).
fn profile_id(raw: &str) -> AdminResult<uuid::Uuid> {
    uuid::Uuid::parse_str(raw).map_err(|_| CoreError::NotFound.into())
}

/// List the password hash profiles of a tenant (no key material).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/password-hash-profiles",
    tag = "users",
    operation_id = "listPasswordHashProfiles",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "Every profile, in name order", body = HashProfileList),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn list_hash_profiles(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let items = state.admin_hash_profiles().list(tenant.id).await?;
    Ok(json(
        StatusCode::OK,
        &HashProfileList {
            items: items.into_iter().map(Into::into).collect(),
        },
    ))
}

/// Create a Firebase scrypt hash profile. The signer key is sealed and never returned.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/password-hash-profiles",
    tag = "users",
    operation_id = "createPasswordHashProfile",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = CreateHashProfile,
    responses(
        (status = 201, description = "Created (without the signer key)", body = HashProfileView, headers(("Location" = String, description = "URL of the new profile"))),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "A profile with this name exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn create_hash_profile(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<CreateHashProfile>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let kind = ProfileKind::parse(&body.kind).ok_or_else(|| CoreError::Validation {
        field: "kind",
        message: "must be firebase_scrypt".to_owned(),
    })?;
    let signer_key = b64std_decode(&body.signer_key).map_err(|_| CoreError::Validation {
        field: "signer_key",
        message: "must be standard base64".to_owned(),
    })?;
    let salt_separator =
        b64std_decode(&body.salt_separator).map_err(|_| CoreError::Validation {
            field: "salt_separator",
            message: "must be standard base64".to_owned(),
        })?;
    let profile = state
        .admin_hash_profiles()
        .create(
            tenant.id,
            NewHashProfile {
                name: body.name.clone(),
                kind,
                signer_key: SecretBox::from(signer_key.into_boxed_slice()),
                salt_separator,
                rounds: body.rounds,
                mem_cost: body.mem_cost,
            },
            auth.actor(),
            &ctx,
        )
        .await?;
    let location = format!(
        "/api/admin/v1/tenants/{}/password-hash-profiles/{}",
        tenant.slug, profile.id
    );
    Ok(created(&location, &HashProfileView::from(profile)))
}

/// Delete a hash profile (409 while imported password hashes reference it).
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/password-hash-profiles/{id}",
    tag = "users",
    operation_id = "deletePasswordHashProfile",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("id" = uuid::Uuid, Path, description = "Profile id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or profile", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Imported password hashes still reference the profile", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_hash_profile(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, id)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let id = profile_id(&id)?;
    state
        .admin_hash_profiles()
        .delete(tenant.id, id, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_debug_redacts_the_signer_key() {
        let body: CreateHashProfile = serde_json::from_value(serde_json::json!({
            "name": "fb", "kind": "firebase_scrypt", "signer_key": "c2VjcmV0LWtleS1ieXRlcw==",
            "salt_separator": "Bw==", "rounds": 8, "mem_cost": 14
        }))
        .unwrap();
        let dbg = format!("{body:?}");
        assert!(!dbg.contains("c2VjcmV0"), "{dbg}");
        assert!(dbg.contains("[redacted]"));
    }
}
