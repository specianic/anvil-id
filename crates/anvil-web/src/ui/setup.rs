//! First-run setup page (`GET/POST /setup?token=…`, ADM-03). Installation-level: the page ignores
//! the addressed tenant (only the root answers it) and keeps its flow row in the `system` tenant.
//!
//! - GET shows the form only for a usable (unknown, unused, unexpired) setup token; otherwise the
//!   `invalid_request` error page with 403 and no form.
//! - POST validates the input through the setup flow, then calls
//!   `BootstrapService::complete_setup`, which consumes the token atomically: of concurrent
//!   submissions exactly one succeeds. The page then shows the management client id and secret
//!   once (`Cache-Control: no-store`).
//! - A fresh installation has no users at all: there are no default credentials.
//! - Completing setup is audited (`admin_setup_completed`) with the request context.

use anvil_core::error::CoreError;
use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::{FieldKind, FormDescription, FormField};
use anvil_core::model::{FlowKind, RequestContext, SYSTEM_TENANT_SLUG, Tenant, TenantBase, issuer};
use anvil_core::service::bootstrap::BootstrapService;
use anvil_core::service::flow::{FlowContext, FlowOutcome};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;

use super::login::{UiForm, UiQuery, csrf_page, form_status, render_form};
use crate::adapters::passkey::relying_party;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

impl AppState {
    /// The bootstrap service for the setup page.
    pub(crate) fn ui_bootstrap_service(&self) -> BootstrapService {
        BootstrapService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
            hasher: self.hasher_arc(),
            policy: self.config().password_policy,
            public_url: self.config().public_url.clone(),
        }
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/setup", get(show).post(submit))
}

/// The page answers only at the installation root (not below a path or host tenant).
fn at_root(tenant: Option<&ResolvedTenant>) -> bool {
    tenant.is_none_or(|t| matches!(t.base, TenantBase::Root))
}

fn invalid_token(state: &AppState, loc: &Locale) -> Response {
    error_page_in(
        state,
        None,
        loc,
        StatusCode::FORBIDDEN,
        "invalid_request",
        "",
    )
}

fn not_found(state: &AppState, tenant: Option<&ResolvedTenant>, loc: &Locale) -> Response {
    error_page_in(state, tenant, loc, StatusCode::NOT_FOUND, "not_found", "")
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `Ok(true)` if `token` is a usable setup token.
async fn token_usable(state: &AppState, token: Option<&str>) -> Result<bool, CoreError> {
    match token.filter(|t| !t.is_empty()) {
        Some(t) => state.ui_bootstrap_service().peek(t).await,
        None => Ok(false),
    }
}

/// The system tenant (holds the setup flow and the first administrator).
async fn system_tenant(state: &AppState) -> Result<Option<Tenant>, CoreError> {
    Ok(state
        .storage()
        .tenants()
        .get_by_slug(SYSTEM_TENANT_SLUG)
        .await?)
}

/// Adds the setup token to the form as a hidden field (it is only consumed by a successful POST).
fn with_token(mut form: FormDescription, token: &str) -> FormDescription {
    form.fields.retain(|f| f.name != "token");
    form.fields.push(FormField {
        name: "token".to_owned(),
        kind: FieldKind::Hidden,
        label_key: String::new(),
        label: String::new(),
        value: Some(token.to_owned()),
        required: false,
        autocomplete: None,
        messages: Vec::new(),
    });
    form
}

fn render_setup(
    state: &AppState,
    loc: &Locale,
    form: &FormDescription,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let page = PageContext::installation(state, loc, "title.setup");
    no_store(render_form(state, None, loc, page, form, status, jar))
}

async fn show(
    State(state): State<AppState>,
    tenant: Option<ResolvedTenant>,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    if !at_root(tenant.as_ref()) {
        return not_found(&state, tenant.as_ref(), &loc);
    }
    let token = q.token();
    match token_usable(&state, token.as_deref()).await {
        Ok(true) => {}
        Ok(false) => return invalid_token(&state, &loc),
        Err(e) => return core_error_page_in(&state, None, &loc, &e),
    }
    let Some(token) = token else {
        return invalid_token(&state, &loc);
    };
    let system = match system_tenant(&state).await {
        Ok(Some(t)) => t,
        Ok(None) => return invalid_token(&state, &loc),
        Err(e) => return core_error_page_in(&state, None, &loc, &e),
    };
    let iss = issuer(
        &state.config().public_url,
        &TenantBase::Path(SYSTEM_TENANT_SLUG.to_owned()),
    );
    let base = state.config().public_url.as_str().to_owned();
    let rp = relying_party(&system, &iss);
    // The setup flow creates no session and records no audit event (bootstrap does that), so
    // it carries no request context.
    let ctx = RequestContext::default();
    let cx = FlowContext {
        tenant: &system,
        issuer: &iss,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    match state
        .ui_flow_service()
        .start(&cx, FlowKind::Setup, None, None)
        .await
    {
        Ok(started) => {
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .flow_cookie(&system, started.cookie_token.expose_secret()),
            );
            render_setup(
                &state,
                &loc,
                &with_token(started.form, &token),
                StatusCode::OK,
                jar,
            )
        }
        Err(e) => core_error_page_in(&state, None, &loc, &e),
    }
}

async fn submit(
    State(state): State<AppState>,
    tenant: Option<ResolvedTenant>,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !at_root(tenant.as_ref()) {
        return not_found(&state, tenant.as_ref(), &loc);
    }
    let Ok(Form(form)) = form else {
        return error_page_in(
            &state,
            None,
            &loc,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "",
        );
    };
    // An unusable token is refused before any flow work or password hashing.
    match token_usable(&state, form.token.as_deref()).await {
        Ok(true) => {}
        Ok(false) => return invalid_token(&state, &loc),
        Err(e) => return core_error_page_in(&state, None, &loc, &e),
    }
    let token = form.token.clone().unwrap_or_default();
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, None, &loc);
    };
    let system = match system_tenant(&state).await {
        Ok(Some(t)) => t,
        Ok(None) => return invalid_token(&state, &loc),
        Err(e) => return core_error_page_in(&state, None, &loc, &e),
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&system))
        .map(|c| c.value().to_owned());
    let iss = issuer(
        &state.config().public_url,
        &TenantBase::Path(SYSTEM_TENANT_SLUG.to_owned()),
    );
    let base = state.config().public_url.as_str().to_owned();
    let rp = relying_party(&system, &iss);
    let cx = FlowContext {
        tenant: &system,
        issuer: &iss,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let input = FlowInput::Setup {
        email: form.email.clone().unwrap_or_default(),
        password: form.password.clone().unwrap_or_default(),
    };
    let outcome = state
        .ui_flow_service()
        .submit(&cx, flow_id, cookie.as_deref(), csrf, input, None)
        .await;
    match outcome.map(|r| r.outcome) {
        Ok(FlowOutcome::SetupSubmitted { email, password }) => {
            complete(&state, &loc, &system, &token, &email, &password, &ctx).await
        }
        Ok(FlowOutcome::Render(f)) => {
            let status = form_status(&f);
            render_setup(
                &state,
                &loc,
                &with_token(f, &token),
                status,
                CookieJar::new(),
            )
        }
        Ok(FlowOutcome::Restarted(started)) => {
            let status = form_status(&started.form);
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .flow_cookie(&system, started.cookie_token.expose_secret()),
            );
            render_setup(&state, &loc, &with_token(started.form, &token), status, jar)
        }
        Ok(FlowOutcome::Message { .. } | FlowOutcome::SignedIn { .. }) => core_error_page_in(
            &state,
            None,
            &loc,
            &CoreError::Internal("unexpected setup flow outcome".into()),
        ),
        Err(CoreError::Forbidden) => csrf_page(&state, None, &loc),
        Err(e) => core_error_page_in(&state, None, &loc, &e),
    }
}

async fn complete(
    state: &AppState,
    loc: &Locale,
    system: &Tenant,
    token: &str,
    email: &str,
    password: &secrecy::SecretString,
    ctx: &RequestContext,
) -> Response {
    match state
        .ui_bootstrap_service()
        .complete_setup(token, email, password, ctx)
        .await
    {
        Ok(result) => {
            if let Some(e) = &result.audit_error {
                // Setup has committed; the one-time secret is still shown.
                tracing::error!(error = %e, "recording admin_setup_completed failed");
            }
            let public = state.config().public_url.as_str();
            let ctx = minijinja::context! {
                page => PageContext::installation(state, loc, "title.setup_done").into_value(),
                admin_email => result.admin.email,
                mgmt_client_id => result.mgmt_client_id,
                mgmt_client_secret => result.mgmt_client_secret.expose_secret(),
                token_endpoint => format!("{public}/t/{SYSTEM_TENANT_SLUG}/token"),
                admin_api_base => format!("{public}/api/admin/v1"),
            };
            let jar = CookieJar::new().add(state.cookies().clear_flow(system));
            match state.renderer().page("setup_done.html", ctx) {
                Ok(html) => no_store((StatusCode::OK, jar, html).into_response()),
                Err(e) => {
                    tracing::error!(error = %e, "rendering the setup result failed");
                    core_error_page_in(state, None, loc, &CoreError::Internal("render".into()))
                }
            }
        }
        Err(CoreError::Forbidden) => invalid_token(state, loc),
        Err(e) => core_error_page_in(state, None, loc, &e),
    }
}
