//! Tenant email templates and SMTP settings (UI-07):
//!
//! - `GET …/email-templates`, `GET|PUT|DELETE …/email-templates/{kind}`: the tenant override of a
//!   transactional email, or the theme default (`customized: false`). An override is compiled,
//!   checked for unknown variables and sample-rendered before it is saved; a failure is a 422
//!   problem whose errors name the part (`subject`, `body_html`, `body_text`) and the line.
//! - `GET|PUT|DELETE …/smtp`: the tenant's SMTP server. The password is write-only (sealed with
//!   the KEK by `MailSettingsService`); reads report `password_set`.
//! - `POST …/smtp/test`: a synchronous test send with the stored settings. SMTP failures are a
//!   successful call with `delivered: false` and the (credential-redacted) error.
//!
//! Scope: `admin:settings:{read,write}` (or `admin:read` / `admin:write`). All mutations are
//! audited by the service.

use std::borrow::Cow;
use std::sync::Arc;

use anvil_core::error::CoreError;
use anvil_core::model::{EmailKind as CoreEmailKind, EmailTemplate, Tenant};
use anvil_core::service::admin_scope::{Access, Resource};
use anvil_core::service::mail_settings::{MailSettingsService, TemplateError};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::auth::{AdminAuth, AdminJson, AdminResult, json, no_content};
use super::dto::{
    EmailKind, EmailTemplateList, EmailTemplateView, Problem, PutEmailTemplate, PutSmtpSettings,
    SmtpSettingsView, SmtpTestRequest, SmtpTestResult,
};
use crate::request_context::AuditContext;
use crate::state::AppState;

/// The default email templates (the same files the outbox renderer embeds).
#[derive(rust_embed::Embed)]
#[folder = "../../themes/default/emails/"]
struct DefaultEmails;

impl AppState {
    fn admin_mail_settings(&self) -> MailSettingsService {
        MailSettingsService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
            checker: Arc::new(anvil_mail::TemplateChecker),
            tester: Arc::new(anvil_mail::LettreSmtpTester::default()),
        }
    }
}

/// Checks the settings scope for `access` and resolves the tenant.
async fn authorize(
    state: &AppState,
    auth: &AdminAuth,
    slug: &str,
    access: Access,
) -> AdminResult<Tenant> {
    auth.require(Resource::Settings, access)?;
    Ok(state.admin_tenants().get(slug).await?)
}

/// A template kind from the path; unknown kinds are 404, and so are kinds without a template
/// contract yet (TRANSITIONAL(06-20): `org_invitation`).
fn kind_of(raw: &str) -> AdminResult<CoreEmailKind> {
    CoreEmailKind::parse(raw)
        .filter(|k| anvil_mail::check::has_contract(*k))
        .ok_or_else(|| CoreError::NotFound.into())
}

/// One default template file: the operator theme's copy when it has one, else the embedded
/// default.
fn default_file(state: &AppState, name: &str) -> Result<String, CoreError> {
    if let Some(dir) = &state.config().theme_dir {
        let path = dir.join("emails").join(name);
        if let Ok(s) = std::fs::read_to_string(&path) {
            return Ok(s);
        }
    }
    let file = DefaultEmails::get(name)
        .ok_or_else(|| CoreError::Internal(format!("default email template {name} missing")))?;
    match String::from_utf8_lossy(&file.data) {
        Cow::Borrowed(s) => Ok(s.to_owned()),
        Cow::Owned(s) => Ok(s),
    }
}

/// The theme default of `kind` in override form: the text file's first line is the subject
/// (an optional `Subject:` prefix is dropped), the rest is the text body.
fn default_view(state: &AppState, kind: CoreEmailKind) -> Result<EmailTemplateView, CoreError> {
    let text = default_file(state, &format!("{}.txt", kind.as_str()))?;
    let html = default_file(state, &format!("{}.html", kind.as_str()))?;
    let (first, rest) = text.split_once('\n').unwrap_or((text.as_str(), ""));
    let first = first.trim();
    let subject = first.strip_prefix("Subject:").unwrap_or(first).trim();
    Ok(EmailTemplateView {
        kind: kind.into(),
        customized: false,
        subject: subject.to_owned(),
        body_html: html,
        body_text: rest.trim_start_matches(['\r', '\n']).to_owned(),
        variables: variables(kind),
        updated_at: None,
    })
}

fn variables(kind: CoreEmailKind) -> Vec<String> {
    anvil_mail::check::variables(kind)
        .iter()
        .map(|v| (*v).to_owned())
        .collect()
}

fn override_view(t: EmailTemplate) -> EmailTemplateView {
    EmailTemplateView {
        kind: t.kind.into(),
        customized: true,
        variables: variables(t.kind),
        subject: t.subject,
        body_html: t.body_html,
        body_text: t.body_text,
        updated_at: Some(
            t.updated_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        ),
    }
}

/// The 422 problem for an invalid template: one error naming the part and, when known, the
/// line.
fn template_problem(field: &str, line: Option<u32>, message: &str) -> Response {
    let mut error = json!({ "field": field, "message": message });
    if let Some(line) = line {
        error["line"] = json!(line);
    }
    let body = json!({
        "type": "urn:anvilid:problem:invalid_request",
        "title": "Unprocessable Entity",
        "status": 422,
        "detail": match line {
            Some(l) => format!("{field}: line {l}: {message}"),
            None => format!("{field}: {message}"),
        },
        "errors": [error],
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

/// List every email template of a tenant (overrides and defaults).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/email-templates",
    tag = "email",
    operation_id = "listEmailTemplates",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "One entry per email kind", body = EmailTemplateList),
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
pub(crate) async fn list_email_templates(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let mut overrides = state
        .admin_mail_settings()
        .list_templates(tenant.id)
        .await?;
    let mut items = Vec::with_capacity(CoreEmailKind::ALL.len());
    // TRANSITIONAL(06-20): kinds without a contract (no default template) are not listed.
    for kind in CoreEmailKind::ALL
        .iter()
        .filter(|k| anvil_mail::check::has_contract(**k))
    {
        let view = match overrides.iter().position(|t| t.kind == *kind) {
            Some(i) => override_view(overrides.swap_remove(i)),
            None => default_view(&state, *kind)?,
        };
        items.push(view);
    }
    Ok(json(StatusCode::OK, &EmailTemplateList { items }))
}

/// Get one email template: the tenant override, or the theme default (`customized: false`).
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/email-templates/{kind}",
    tag = "email",
    operation_id = "getEmailTemplate",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("kind" = EmailKind, Path, description = "Email kind"),
    ),
    responses(
        (status = 200, description = "The template", body = EmailTemplateView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or kind", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_email_template(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path((slug, kind)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let kind = kind_of(&kind)?;
    let view = match state
        .admin_mail_settings()
        .get_template(tenant.id, kind)
        .await?
    {
        Some(t) => override_view(t),
        None => default_view(&state, kind)?,
    };
    Ok(json(StatusCode::OK, &view))
}

/// Save a tenant override of an email template. The template is compiled, checked for
/// unknown variables and test-rendered first.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/email-templates/{kind}",
    tag = "email",
    operation_id = "putEmailTemplate",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("kind" = EmailKind, Path, description = "Email kind"),
    ),
    request_body = PutEmailTemplate,
    responses(
        (status = 200, description = "The saved override", body = EmailTemplateView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or kind", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid template (errors carry field and line)", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_email_template(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, kind)): Path<(String, String)>,
    AdminJson(body): AdminJson<PutEmailTemplate>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let kind = kind_of(&kind)?;
    match state
        .admin_mail_settings()
        .put_template(tenant.id, kind, body.into(), auth.actor(), &ctx)
        .await
    {
        Ok(t) => Ok(json(StatusCode::OK, &override_view(t))),
        Err(TemplateError::Invalid {
            field,
            line,
            message,
        }) => Ok(template_problem(field, line, &message)),
        Err(TemplateError::Core(e)) => Err(e.into()),
    }
}

/// Remove the tenant override (back to the theme default). Idempotent.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/email-templates/{kind}",
    tag = "email",
    operation_id = "resetEmailTemplate",
    params(
        ("slug" = String, Path, description = "Tenant slug"),
        ("kind" = EmailKind, Path, description = "Email kind"),
    ),
    responses(
        (status = 204, description = "The theme default is used"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant or kind", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn reset_email_template(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path((slug, kind)): Path<(String, String)>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let kind = kind_of(&kind)?;
    state
        .admin_mail_settings()
        .reset_template(tenant.id, kind, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Get the tenant's SMTP settings (never the password). 404 when the tenant uses the
/// installation SMTP server.
#[utoipa::path(
    get,
    path = "/api/admin/v1/tenants/{slug}/smtp",
    tag = "email",
    operation_id = "getSmtpSettings",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 200, description = "The tenant's SMTP settings", body = SmtpSettingsView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant, or no tenant SMTP settings", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:read"]),
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:read"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn get_smtp(
    auth: AdminAuth,
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Read).await?;
    let view = state
        .admin_mail_settings()
        .get_smtp(tenant.id)
        .await?
        .ok_or(CoreError::NotFound)?;
    Ok(json(StatusCode::OK, &SmtpSettingsView::from(view)))
}

/// Set the tenant's SMTP settings. An absent or empty password keeps the stored one.
#[utoipa::path(
    put,
    path = "/api/admin/v1/tenants/{slug}/smtp",
    tag = "email",
    operation_id = "putSmtpSettings",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = PutSmtpSettings,
    responses(
        (status = 200, description = "The stored settings (without the password)", body = SmtpSettingsView),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn put_smtp(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<PutSmtpSettings>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let view = state
        .admin_mail_settings()
        .put_smtp(tenant.id, body.into(), auth.actor(), &ctx)
        .await?;
    Ok(json(StatusCode::OK, &SmtpSettingsView::from(view)))
}

/// Remove the tenant's SMTP settings (back to the installation SMTP server). Idempotent.
#[utoipa::path(
    delete,
    path = "/api/admin/v1/tenants/{slug}/smtp",
    tag = "email",
    operation_id = "deleteSmtpSettings",
    params(("slug" = String, Path, description = "Tenant slug")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn delete_smtp(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    state
        .admin_mail_settings()
        .delete_smtp(tenant.id, auth.actor(), &ctx)
        .await?;
    Ok(no_content())
}

/// Send a test email with the stored SMTP settings (synchronous, bounded by a 10 s timeout).
/// An SMTP failure is reported in the body (`delivered: false`), not as an error status.
#[utoipa::path(
    post,
    path = "/api/admin/v1/tenants/{slug}/smtp/test",
    tag = "email",
    operation_id = "testSmtpSettings",
    params(("slug" = String, Path, description = "Tenant slug")),
    request_body = SmtpTestRequest,
    responses(
        (status = 200, description = "The SMTP outcome", body = SmtpTestResult),
        (status = 401, description = "Missing or invalid access token", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Insufficient scope", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown tenant", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid recipient, or no tenant SMTP settings", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = Problem, content_type = "application/problem+json"),
    ),
    security(
        ("oauth2" = ["admin:settings:write"]),
        ("oauth2" = ["admin:write"]),
    )
)]
pub(crate) async fn test_smtp(
    auth: AdminAuth,
    State(state): State<AppState>,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    AdminJson(body): AdminJson<SmtpTestRequest>,
) -> AdminResult<Response> {
    let tenant = authorize(&state, &auth, &slug, Access::Write).await?;
    let result = state
        .admin_mail_settings()
        .test_send(tenant.id, &body.to, auth.actor(), &ctx)
        .await?;
    Ok(json(
        StatusCode::OK,
        &SmtpTestResult {
            delivered: result.delivered,
            error: result.error,
        },
    ))
}
