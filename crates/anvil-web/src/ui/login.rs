//! Login pages (`GET/POST /ui/login[?request=]`) and the helpers shared by every self-service
//! page (flow start, submission, outcome mapping, rendering).
//!
//! Status codes: a form with an error message → 400; message pages → 200; a successful sign-in
//! → 303 See Other to `{issuer}/authorize/continue?request=…` (or the signed-in message page when
//! the login is not bound to an authorization request). `CoreError::Forbidden` (wrong or missing
//! CSRF token or flow cookie) → the `csrf` error page with 403. Form values are never logged.
//!
//! Submissions carry the request context (client IP, user agent, request id; [`AuditContext`])
//! into the flow service, which records it on sessions and audit events.

use anvil_core::error::CoreError;
use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::{FormDescription, MessageLevel};
use std::sync::Arc;

use anvil_core::model::{
    AuthRequestId, FlowId, FlowKind, RegistrationMode, RequestContext, SessionId,
};
use anvil_core::ports::RelyingParty;
use anvil_core::service::flow::{FlowContext, FlowOutcome, FlowService, StartedFlow};
use anvil_core::service::session::SessionService;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use minijinja::value::{Serde, Value};
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use crate::adapters::passkey::{WebauthnPasskeys, relying_party};
use crate::errors::{core_error_page, error_page};
use crate::render::{PageContext, PageLinks};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The flow service for the self-service pages.
    pub(crate) fn ui_flow_service(&self) -> FlowService {
        FlowService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            hasher: self.hasher_arc(),
            breach: self.breach_arc(),
            policy: self.config().password_policy,
            kek: self.kek_arc(),
            passkeys: Arc::new(WebauthnPasskeys),
        }
    }

    /// The browser session service for the self-service pages.
    pub(crate) fn ui_session_service(&self) -> SessionService {
        SessionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/ui/login", get(show).post(submit))
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    Query(q): Query<UiQuery>,
) -> Response {
    let request = match q.auth_request() {
        Ok(r) => r,
        Err(resp) => return resp.into_response(&state, Some(&tenant)),
    };
    start_page(&state, &tenant, FlowKind::Login, request, None).await
}

async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    submit_page(&state, &tenant, &ctx, &jar, &q, &form, login_input(&form)).await
}

/// The login input a form posts: a recovery code or a TOTP code (second-factor form), else the
/// email/password form. The engine refuses inputs that do not belong to the current step.
fn login_input(form: &UiForm) -> FlowInput {
    let present = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());
    if let Some(code) = present(&form.recovery_code) {
        FlowInput::RecoveryCode { code }
    } else if let Some(code) = form.code.clone() {
        FlowInput::Totp { code }
    } else {
        FlowInput::Login {
            identifier: form.identifier.clone().unwrap_or_default(),
            password: form.password.clone().unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Shared by the self-service pages
// ---------------------------------------------------------------------------------------------

/// Query parameters of the self-service pages.
#[derive(Debug, Default, Deserialize)]
pub(super) struct UiQuery {
    /// Authorization request the page continues (`/ui/login?request=…`).
    pub(super) request: Option<String>,
    /// Self-service token from an emailed link (`/ui/verification?token=…`).
    pub(super) token: Option<String>,
    /// Flow id on form POSTs.
    pub(super) flow: Option<String>,
}

/// A malformed query value: the page answers with an error page instead of a form.
pub(super) struct BadQuery;

impl BadQuery {
    pub(super) fn into_response(
        self,
        state: &AppState,
        tenant: Option<&ResolvedTenant>,
    ) -> Response {
        error_page(
            state,
            tenant,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "",
        )
    }
}

impl UiQuery {
    /// The `request` parameter as an authorization request id. Absent → `None`; malformed →
    /// `Err` (invalid request page).
    pub(super) fn auth_request(&self) -> Result<Option<AuthRequestId>, BadQuery> {
        match self.request.as_deref() {
            None | Some("") => Ok(None),
            Some(s) => uuid::Uuid::parse_str(s)
                .map(|u| Some(AuthRequestId(u)))
                .map_err(|_| BadQuery),
        }
    }

    /// The `flow` parameter. `None` when absent or malformed (the submission cannot be bound
    /// to a flow and is rejected like a CSRF failure).
    pub(super) fn flow_id(&self) -> Option<FlowId> {
        self.flow
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(FlowId)
    }

    /// The emailed token, if present and non-empty.
    pub(super) fn token(&self) -> Option<String> {
        self.token.clone().filter(|t| !t.is_empty())
    }
}

/// Every field any self-service form posts. Missing fields are empty input for the engine.
#[derive(Default, Deserialize)]
pub(super) struct UiForm {
    pub(super) csrf_token: Option<String>,
    pub(super) identifier: Option<String>,
    pub(super) password: Option<String>,
    pub(super) email: Option<String>,
    pub(super) name: Option<String>,
    pub(super) token: Option<String>,
    /// TOTP code (second-factor form).
    pub(super) code: Option<String>,
    /// Recovery code (second-factor form).
    pub(super) recovery_code: Option<String>,
}

/// An unparseable form body.
pub(super) fn bad_form(state: &AppState, tenant: &ResolvedTenant) -> Response {
    error_page(
        state,
        Some(tenant),
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "",
    )
}

/// The CSRF rejection page (missing or wrong token, missing flow cookie, unbound submission).
pub(super) fn csrf_page(state: &AppState, tenant: Option<&ResolvedTenant>) -> Response {
    error_page(state, tenant, StatusCode::FORBIDDEN, "csrf", "")
}

/// `{issuer}/ui`: base of the self-service pages and the emailed links.
pub(super) fn ui_base(tenant: &ResolvedTenant) -> String {
    format!("{}/ui", tenant.issuer)
}

/// `true` if the form carries an error message (form- or field-level).
pub(super) fn has_error(form: &FormDescription) -> bool {
    form.messages
        .iter()
        .chain(form.fields.iter().flat_map(|f| f.messages.iter()))
        .any(|m| m.level == MessageLevel::Error)
}

/// The status of a rendered form: 400 if it carries an error message, else 200.
pub(super) fn form_status(form: &FormDescription) -> StatusCode {
    if has_error(form) {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    }
}

/// Template and title of a form, by form id (themes/default/README.md).
pub(super) fn form_template(form_id: &str) -> (&'static str, &'static str) {
    match form_id {
        "login" => ("login.html", "Sign in"),
        // Rendered with the generic sign-in template until the dedicated second-factor page
        // lands (03-20).
        "second-factor" => ("login.html", "Two-step verification"),
        "registration" => ("registration.html", "Create an account"),
        "verification" => ("verification.html", "Confirm your email address"),
        "recovery" => ("recovery.html", "Reset your password"),
        "recovery-reset" => ("recovery_reset.html", "Choose a new password"),
        _ => ("setup.html", "Set up AnvilID"),
    }
}

/// Links between the tenant's self-service pages for a form. The registration link only exists
/// when self-registration is open. `request` is carried along so the user can switch pages
/// without losing the authorization request.
pub(super) fn links_for(
    tenant: &ResolvedTenant,
    form_id: &str,
    request: Option<AuthRequestId>,
) -> PageLinks {
    let with_request = |path: &str| match request {
        Some(r) => tenant.ui_url(&format!("{path}?request={r}")),
        None => tenant.ui_url(path),
    };
    match form_id {
        "login" => PageLinks {
            login: None,
            registration: (tenant.tenant.settings.registration == RegistrationMode::Open)
                .then(|| with_request("/ui/registration")),
            recovery: Some(tenant.ui_url("/ui/recovery")),
        },
        _ => PageLinks {
            login: Some(with_request("/ui/login")),
            registration: None,
            recovery: None,
        },
    }
}

/// Renders a form page with the given page context.
pub(super) fn render_form(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    page: PageContext,
    form: &FormDescription,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let (template, _) = form_template(&form.id);
    let ctx = minijinja::context! {
        page => page.into_value(),
        form => Value::from(Serde(form)),
    };
    match state.renderer().page(template, ctx) {
        Ok(html) => (status, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, template, "rendering a form page failed");
            core_error_page(state, tenant, &CoreError::Internal("render".into()))
        }
    }
}

/// Renders a tenant form page (title and links derived from the form).
fn render_tenant_form(
    state: &AppState,
    tenant: &ResolvedTenant,
    form: &FormDescription,
    request: Option<AuthRequestId>,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let (_, title) = form_template(&form.id);
    let mut page = PageContext::for_tenant(state, tenant, title);
    page.links = links_for(tenant, &form.id, request);
    render_form(state, Some(tenant), page, form, status, jar)
}

/// Heading of a message page, by message key.
fn message_heading(key: &str) -> &'static str {
    match key {
        "recovery.sent" | "registration.check_email" => "Check your email",
        "recovery.done" => "Password changed",
        "verification.done" => "Email address confirmed",
        "registration.disabled" => "Registration unavailable",
        SIGNED_IN => "Signed in",
        _ => "Done",
    }
}

/// Message key of the page shown after a login that is not bound to an authorization request
/// (there is no account page in release 0.1).
pub(super) const SIGNED_IN: &str = "login.signed_in";

fn message_body(key: &str) -> &'static str {
    match key {
        SIGNED_IN => "You are signed in.",
        other => anvil_core::flow::engine::message_text(other),
    }
}

/// Renders `message.html` (200) with a link to the tenant's sign-in page.
pub(super) fn message_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    key: &str,
    jar: CookieJar,
) -> Response {
    let mut page = PageContext::for_tenant(state, tenant, message_heading(key));
    if key != SIGNED_IN {
        page.links.login = Some(tenant.ui_url("/ui/login"));
    }
    let ctx = minijinja::context! {
        page => page.into_value(),
        heading => message_heading(key),
        body_key => key,
        body => message_body(key),
    };
    match state.renderer().page("message.html", ctx) {
        Ok(html) => (StatusCode::OK, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the message page failed");
            core_error_page(state, Some(tenant), &CoreError::Internal("render".into()))
        }
    }
}

/// Response for a newly started flow: sets the flow cookie and renders its form.
fn started_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    started: &StartedFlow,
    request: Option<AuthRequestId>,
    status: StatusCode,
) -> Response {
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_tenant_form(state, tenant, &started.form, request, status, jar)
}

/// `GET` of a self-service page: starts a flow of `kind` and renders its form.
pub(super) async fn start_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    kind: FlowKind,
    request: Option<AuthRequestId>,
    token: Option<String>,
) -> Response {
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
    // Starting a flow records nothing (no session, no audit event), so no request context.
    let ctx = RequestContext::default();
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    match state
        .ui_flow_service()
        .start(&cx, kind, request, token)
        .await
    {
        Ok(started) => started_response(state, tenant, &started, request, StatusCode::OK),
        Err(e) => core_error_page(state, Some(tenant), &e),
    }
}

/// The caller's current session id (from the session cookie), if any.
async fn current_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<SessionId>, CoreError> {
    let name = state.cookies().session_name(&tenant.tenant);
    let token = jar.get(&name).map(|c| c.value().to_owned());
    Ok(state
        .ui_session_service()
        .current(tenant.tenant.id, token.as_deref())
        .await?
        .map(|s| s.id))
}

/// The tenant's WebAuthn relying party. An issuer that cannot be one is an error only for the
/// passkey steps (the flow service propagates it there).
pub(super) fn tenant_relying_party(tenant: &ResolvedTenant) -> Result<RelyingParty, CoreError> {
    relying_party(&tenant.tenant, &tenant.issuer)
}

/// `POST` of a self-service page: binds the submission to its flow, runs it and maps the
/// outcome to a response.
pub(super) async fn submit_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    jar: &CookieJar,
    query: &UiQuery,
    form: &UiForm,
    input: FlowInput,
) -> Response {
    let (Some(flow_id), Some(csrf)) = (query.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(state, Some(tenant));
    };
    let cookie_name = state.cookies().flow_name(&tenant.tenant);
    let cookie = jar.get(&cookie_name).map(|c| c.value().to_owned());
    let session = match current_session(state, tenant, jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page(state, Some(tenant), &e),
    };
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx,
    };
    let outcome = state
        .ui_flow_service()
        .submit(&cx, flow_id, cookie.as_deref(), csrf, input, session)
        .await;
    // `result.attempt` drives the brute-force limiter once the login routes use it (03-20).
    match outcome {
        Ok(result) => outcome_response(state, tenant, result.outcome),
        Err(CoreError::Forbidden) => csrf_page(state, Some(tenant)),
        Err(e) => core_error_page(state, Some(tenant), &e),
    }
}

/// Maps a flow outcome of a tenant self-service page to a response.
fn outcome_response(state: &AppState, tenant: &ResolvedTenant, outcome: FlowOutcome) -> Response {
    let cookies = state.cookies();
    match outcome {
        FlowOutcome::Render(form) => render_tenant_form(
            state,
            tenant,
            &form,
            None,
            form_status(&form),
            CookieJar::new(),
        ),
        FlowOutcome::Restarted(started) => {
            let status = form_status(&started.form);
            started_response(state, tenant, &started, None, status)
        }
        FlowOutcome::Message { key } => {
            let jar = CookieJar::new().add(cookies.clear_flow(&tenant.tenant));
            message_page(state, tenant, key, jar)
        }
        FlowOutcome::SignedIn {
            cookie,
            continue_to,
        } => {
            let jar = CookieJar::new()
                .add(cookies.clear_flow(&tenant.tenant))
                .add(cookies.session_cookie(&tenant.tenant, cookie.token.expose_secret()));
            match continue_to {
                Some(request) => {
                    let location =
                        format!("{}/authorize/continue?request={request}", tenant.issuer);
                    (StatusCode::SEE_OTHER, jar, [(header::LOCATION, location)]).into_response()
                }
                None => message_page(state, tenant, SIGNED_IN, jar),
            }
        }
        FlowOutcome::SetupSubmitted { .. } => core_error_page(
            state,
            Some(tenant),
            &CoreError::Internal("setup outcome on a tenant page".into()),
        ),
    }
}
