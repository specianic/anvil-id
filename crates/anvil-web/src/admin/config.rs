//! Declarative tenant configuration: export, plan and apply (ADM-06, ADM-07).
//!
//! - `GET …/tenants/{slug}/config` (`admin:read`): the tenant's `TenantConfig` document (JSON;
//!   secrets as `{configured: bool}`, natural keys only).
//! - `POST …/tenants/{slug}/config/plan` (`admin:write`): validates a document and returns the
//!   plan against the stored state without changing anything.
//! - `POST …/tenants/{slug}/config/apply[?prune=true]` (`admin:write`): validates, plans and
//!   applies through the services ([`ConfigService`]); deletes only with `prune`. Secrets the
//!   server generated (new clients or webhooks without an inline secret) are returned once.
//!
//! The API takes JSON with inline secrets only (`{value: "…"}`). Secret references
//! (`{env: NAME}`, `{file: path}`) are resolved by the `anvilid tenant` CLI on the operator's
//! machine; the server never reads its own environment or files for a document and refuses
//! such references with a 422 naming the field. The document schema is published as
//! `docs/schemas/tenant-config-v1.json` (see docs/CONFIG-YAML.md).
//!
//! An invalid document is a 422 problem listing every issue by path
//! (`clients[2].redirect_uris[0]`); nothing is changed. Removing the last administrator of the
//! system tenant is a 409, also with nothing changed.

use std::sync::Arc;

use anvil_core::error::CoreError;
use anvil_core::model::{ConfigChange, ConfigObjectKind, ConfigPlan, TenantConfigDocument};
use anvil_core::service::admin_scope::{ADMIN_READ, ADMIN_WRITE};
use anvil_core::service::config::{
    ApplyOutcome, ApplyRequest, ConfigError, ConfigIssue, ConfigService, render,
};
use anvil_core::service::connection::ConnectionService;
use anvil_core::service::mail_settings::MailSettingsService;
use anvil_core::service::role::RoleService;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::auth::{AdminAuth, AdminError, AdminJson, AdminQuery, AdminResult, json};
use super::dto::Problem;
use crate::request_context::AuditContext;
use crate::state::AppState;

impl AppState {
    /// The declarative configuration service, wired to the same services the other admin
    /// routes use.
    fn admin_config(&self) -> Result<ConfigService, CoreError> {
        Ok(ConfigService {
            tenants: self.admin_tenants(),
            clients: self.admin_clients(),
            connections: ConnectionService {
                storage: self.storage_arc(),
                clock: self.clock_arc(),
                kek: self.kek_arc(),
                saml_enabled: self.config().saml_experimental,
                saml_xml: Some(self.saml_xml()),
                upstream: Some(Arc::new(self.upstream().clone())),
            },
            branding: self.branding(),
            roles: RoleService {
                storage: self.storage_arc(),
                clock: self.clock_arc(),
            },
            attributes: self.attribute_service()?,
            webhooks: self.webhook_service(),
            mail: MailSettingsService {
                storage: self.storage_arc(),
                clock: self.clock_arc(),
                kek: self.kek_arc(),
                checker: Arc::new(anvil_mail::TemplateChecker),
                tester: Arc::new(anvil_mail::LettreSmtpTester::default()),
            },
            installation_smtp: self.config().installation_smtp,
            dev_mode: self.config().dev_mode(),
        })
    }
}

/// The documented routes of this module, merged into the management API by `api_router`.
pub(crate) fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_tenant_config))
        .routes(routes!(plan_tenant_config))
        .routes(routes!(apply_tenant_config))
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// A `TenantConfig` document, version 1 (JSON form). The full schema is published as
/// `docs/schemas/tenant-config-v1.json`. Secrets: `{configured: bool}` keeps (true) or clears
/// (false) a stored secret, `{value: "…"}` sets it; exports always carry `{configured: …}`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = Object)]
pub struct TenantConfigJson(pub Value);

/// One changed field. Secret fields carry no values (`secret: true`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigFieldDiff {
    /// Dotted path inside the object (`settings.claims.permissions`).
    pub field: String,
    #[schema(value_type = Option<Object>)]
    pub before: Option<Value>,
    #[schema(value_type = Option<Object>)]
    pub after: Option<Value>,
    pub secret: bool,
}

/// One object to create, update or delete, by natural key.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigChangeDto {
    /// `tenant`, `client`, `connection`, `branding`, `role`, `attribute`, `email_template`,
    /// `smtp` or `webhook`.
    pub kind: String,
    /// The natural key (`client_id`, slug, name, template kind, `(tenant)` for tenant-wide
    /// branding, `smtp`).
    pub key: String,
    pub fields: Vec<ConfigFieldDiff>,
}

/// The plan of a document against the stored state. `deletes` happen only with `prune`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigPlanDto {
    pub creates: Vec<ConfigChangeDto>,
    pub updates: Vec<ConfigChangeDto>,
    pub deletes: Vec<ConfigChangeDto>,
    /// Nothing to create, update or delete.
    pub empty: bool,
    /// The plan as text (the CLI's rendering; secrets print as `(secret changed)`).
    pub text: String,
}

/// A secret generated while applying, shown once.
#[derive(Debug, Serialize, ToSchema)]
pub struct GeneratedSecretDto {
    pub kind: String,
    pub key: String,
    pub field: String,
    pub value: String,
}

/// The result of an apply.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConfigApplyResult {
    /// The plan that was applied (computed before the changes).
    pub plan: ConfigPlanDto,
    /// Whether anything was written.
    pub applied: bool,
    /// Whether the plan's deletes were performed.
    pub pruned: bool,
    /// Secrets the server generated (client secrets, webhook signing secrets); never readable
    /// again.
    pub generated_secrets: Vec<GeneratedSecretDto>,
}

/// Query of `POST …/config/apply`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ApplyQuery {
    /// Also delete the objects the document no longer lists (default false).
    #[serde(default)]
    pub prune: Option<bool>,
}

fn kind_str(kind: ConfigObjectKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn change_dto(c: &ConfigChange) -> ConfigChangeDto {
    ConfigChangeDto {
        kind: kind_str(c.kind),
        key: c.key.clone(),
        fields: c
            .fields
            .iter()
            .map(|f| ConfigFieldDiff {
                field: f.field.clone(),
                secret: f.before.is_none() && f.after.is_none(),
                before: f.before.clone(),
                after: f.after.clone(),
            })
            .collect(),
    }
}

fn plan_dto(p: &ConfigPlan) -> ConfigPlanDto {
    ConfigPlanDto {
        creates: p.creates.iter().map(change_dto).collect(),
        updates: p.updates.iter().map(change_dto).collect(),
        deletes: p.deletes.iter().map(change_dto).collect(),
        empty: p.is_empty(),
        text: render(p),
    }
}

fn apply_dto(o: &ApplyOutcome) -> ConfigApplyResult {
    ConfigApplyResult {
        plan: plan_dto(&o.plan),
        applied: o.applied,
        pruned: o.pruned,
        generated_secrets: o
            .generated
            .iter()
            .map(|g| GeneratedSecretDto {
                kind: kind_str(g.kind),
                key: g.key.clone(),
                field: g.field.to_owned(),
                value: g.value.expose_secret().to_owned(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// The 422 problem listing every issue of a document.
fn issues_problem(issues: &[ConfigIssue]) -> Response {
    let errors: Vec<Value> = issues
        .iter()
        .map(|i| json!({ "field": i.path, "message": i.message }))
        .collect();
    let body = json!({
        "type": "urn:anvilid:problem:invalid_request",
        "title": "Unprocessable Entity",
        "status": 422,
        "detail": format!("the document is invalid ({} issue(s))", issues.len()),
        "errors": errors,
    });
    let mut resp = (StatusCode::UNPROCESSABLE_ENTITY, body.to_string()).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ConfigIssue {
    ConfigIssue {
        path: path.into(),
        message: message.into(),
    }
}

/// Secret fields holding a reference (`{env: …}` / `{file: …}`) instead of an inline value.
/// The server never resolves them.
fn secret_references(body: &Value) -> Vec<ConfigIssue> {
    let is_reference = |v: Option<&Value>| {
        v.and_then(Value::as_object)
            .is_some_and(|o| o.contains_key("env") || o.contains_key("file"))
    };
    let message = "secret references ({env: …}, {file: …}) are resolved by the anvilid CLI; \
                   the API accepts inline secrets ({value: …}) only";
    let mut out = Vec::new();
    for section in ["clients", "connections", "webhooks"] {
        if let Some(items) = body.get(section).and_then(Value::as_array) {
            for (i, item) in items.iter().enumerate() {
                if is_reference(item.get("secret")) {
                    out.push(issue(format!("{section}[{i}].secret"), message));
                }
            }
        }
    }
    if is_reference(body.get("smtp").and_then(|s| s.get("password"))) {
        out.push(issue("smtp.password", message));
    }
    out
}

/// Parses the body into a document for the tenant `slug`, or the issues of the 422 problem.
fn parse_document(slug: &str, body: Value) -> Result<TenantConfigDocument, Vec<ConfigIssue>> {
    let refs = secret_references(&body);
    if !refs.is_empty() {
        return Err(refs);
    }
    let doc: TenantConfigDocument =
        serde_json::from_value(body).map_err(|e| vec![issue("body", e.to_string())])?;
    if doc.tenant.slug != slug {
        return Err(vec![issue(
            "tenant.slug",
            "must equal the tenant slug of the URL",
        )]);
    }
    Ok(doc)
}

fn require_scope(auth: &AdminAuth, scopes: &[&str], message: &str) -> AdminResult<()> {
    if scopes.iter().any(|s| auth.claims.scope.contains(s)) {
        Ok(())
    } else {
        Err(CoreError::InsufficientScope(message.to_owned()).into())
    }
}

fn config_error(e: ConfigError) -> Response {
    match e {
        ConfigError::Invalid(issues) => issues_problem(&issues),
        ConfigError::Core(e) => AdminError::Core(e).into_response(),
    }
}

async fn run(
    state: &AppState,
    auth: &AdminAuth,
    ctx: &anvil_core::model::RequestContext,
    slug: &str,
    body: Value,
    prune: bool,
    dry_run: bool,
) -> AdminResult<Result<ApplyOutcome, Response>> {
    require_scope(
        auth,
        &[ADMIN_WRITE],
        "planning or applying a tenant configuration requires admin:write",
    )?;
    let doc = match parse_document(slug, body) {
        Ok(doc) => doc,
        Err(issues) => return Ok(Err(issues_problem(&issues))),
    };
    let service = state.admin_config()?;
    let actor = auth.actor();
    Ok(service
        .apply(ApplyRequest {
            actor: &actor,
            caller: &auth.claims.scope,
            document: &doc,
            prune,
            dry_run,
            ctx,
        })
        .await
        .map_err(config_error))
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Export a tenant's configuration as a `TenantConfig` document.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/config",
    tag = "config",
    operation_id = "getTenantConfig",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The tenant's document: static clients, connections, branding, roles, attributes, email templates, SMTP and webhooks by natural key; secrets as {configured: bool}", body = TenantConfigJson),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_tenant_config(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    require_scope(
        &auth,
        &[ADMIN_READ, ADMIN_WRITE],
        "exporting a tenant configuration requires admin:read",
    )?;
    let doc = state.admin_config()?.export(&slug).await?;
    Ok(json(StatusCode::OK, &doc))
}

/// Validate a document and show the plan against the stored state (nothing is changed).
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/config/plan",
    tag = "config",
    operation_id = "planTenantConfig",
    params(("slug" = String, Path, description = "Tenant slug (must equal tenant.slug of the document)")),
    request_body = TenantConfigJson,
    responses(
        (status = 200, description = "The plan; deletes are applied only with prune", body = ConfigPlanDto),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or role changes beyond the caller's admin scopes", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The document would remove the last administrator of the system tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid document (errors list every issue by path)", body = Problem, content_type = "application/problem+json"),
    ),
    security(("oauth2" = ["admin:write"]))
)]
pub(crate) async fn plan_tenant_config(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<Value>,
) -> AdminResult<Response> {
    Ok(
        match run(&state, &auth, &ctx, &slug, body, false, true).await? {
            Ok(outcome) => json(StatusCode::OK, &plan_dto(&outcome.plan)),
            Err(resp) => resp,
        },
    )
}

/// Apply a document: validate everything first, then write through the services. Re-applying
/// an applied document changes nothing.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/config/apply",
    tag = "config",
    operation_id = "applyTenantConfig",
    params(
        ("slug" = String, Path, description = "Tenant slug (must equal tenant.slug of the document; a missing tenant is created)"),
        ApplyQuery,
    ),
    request_body = TenantConfigJson,
    responses(
        (status = 200, description = "Applied (or nothing to do); generated secrets are shown once", body = ConfigApplyResult),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope, or role changes beyond the caller's admin scopes", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The document would remove the last administrator of the system tenant, or a name is taken", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid document (errors list every issue by path); nothing was changed", body = Problem, content_type = "application/problem+json"),
    ),
    security(("oauth2" = ["admin:write"]))
)]
pub(crate) async fn apply_tenant_config(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminQuery(query): AdminQuery<ApplyQuery>,
    AdminJson(body): AdminJson<Value>,
) -> AdminResult<Response> {
    let prune = query.prune.unwrap_or(false);
    Ok(
        match run(&state, &auth, &ctx, &slug, body, prune, false).await? {
            Ok(outcome) => json(StatusCode::OK, &apply_dto(&outcome)),
            Err(resp) => resp,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_references_are_found_at_secret_positions_only() {
        let body = json!({
            "clients": [{"secret": {"value": "x"}}, {"secret": {"env": "CLIENT_SECRET"}}],
            "connections": [{"secret": {"file": "/etc/shadow"}}],
            "webhooks": [{"secret": {"configured": true}}],
            "smtp": {"password": {"env": "SMTP_PASSWORD"}},
            "attributes": [{"name": "env", "schema": {"properties": {"env": {"type": "string"}}}}],
        });
        let paths: Vec<String> = secret_references(&body)
            .into_iter()
            .map(|i| i.path)
            .collect();
        assert_eq!(
            paths,
            [
                "clients[1].secret",
                "connections[0].secret",
                "smtp.password"
            ]
        );
    }
}
