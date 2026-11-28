//! Account security page (AUTH-04, AUTH-05): passkeys, authenticator app (TOTP) and recovery
//! codes of the signed-in user.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/security` | page; starts a settings flow (flow cookie + CSRF token) |
//! | `POST /ui/account/security/passkey/options?flow=` | WebAuthn creation options (JSON, for webauthn.js) |
//! | `POST /ui/account/security/passkey?flow=` | finishes the passkey registration |
//! | `POST /ui/account/security/totp?flow=` | starts TOTP enrolment (QR code + key) |
//! | `POST /ui/account/security/totp/confirm?flow=` | confirms it; shows the recovery codes once |
//! | `POST /ui/account/security/recovery-codes?flow=` | new recovery codes (old set invalidated) |
//! | `POST /ui/account/security/credentials/{id}/delete?flow=` | removes a passkey or the TOTP |
//!
//! Without a session every route answers 303 to the sign-in page (the options endpoint: 401
//! JSON). Every POST is behind the Fetch-Metadata layer and must carry the flow cookie and the
//! CSRF token (form field `csrf_token`, or header `X-CSRF-Token` on the options endpoint);
//! otherwise the `csrf` error page (403). Changes need a sign-in within the last 15 minutes
//! (`AccountService`); a refusal re-renders the page with a message (400). Everything but adding a
//! passkey works without JavaScript.
//!
//! Pages of this module allow `script-src 'self'` (webauthn.js) and `connect-src 'self'` (its
//! options request); every other directive equals the default CSP.

use std::sync::Arc;

use anvil_core::error::CoreError;
use anvil_core::model::{BrowserSession, CredentialId, CredentialSummary, FlowId};
use anvil_core::service::account::{
    AccountError, AccountFailure, AccountService, SettingsBinding, TotpEnrolment,
};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::account_attributes::attributes_nav_or_page;
use super::consent::{PageMessage, account_locale, localized};
use super::format::{human, iso};
use super::login::{UiQuery, csrf_page, rejected_form, rejection_is_too_large};
use super::nav::{AccountSection, NavContext};
use crate::adapters::passkey::{WebauthnPasskeys, relying_party};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// CSP of the account security pages: the default policy plus webauthn.js and its fetch.
pub const ACCOUNT_CSP: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; \
     style-src 'self'; font-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'";

const PAGE: &str = "/ui/account/security";

impl AppState {
    /// The account service for the self-service pages.
    pub(crate) fn ui_account_service(&self) -> AccountService {
        AccountService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
            passkeys: Arc::new(WebauthnPasskeys::new()),
        }
    }
}

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PAGE, get(show))
        .route(
            "/ui/account/security/passkey/options",
            post(passkey_options),
        )
        .route("/ui/account/security/passkey", post(passkey_finish))
        .route("/ui/account/security/totp", post(totp_begin))
        .route("/ui/account/security/totp/confirm", post(totp_confirm))
        .route("/ui/account/security/recovery-codes", post(recovery_codes))
        .route(
            "/ui/account/security/credentials/{id}/delete",
            post(remove_credential),
        )
}

/// Every field the account security forms post.
#[derive(Default, Deserialize)]
struct SecurityForm {
    csrf_token: Option<String>,
    label: Option<String>,
    response: Option<String>,
    code: Option<String>,
}

/// A submission resolved to its session, page locale and settings flow binding.
struct Submission {
    session: BrowserSession,
    locale: Locale,
    flow_id: FlowId,
    cookie: Option<String>,
    csrf: String,
}

impl Submission {
    fn binding(&self) -> SettingsBinding<'_> {
        SettingsBinding {
            flow_id: self.flow_id,
            cookie_token: self.cookie.as_deref(),
            csrf_token: &self.csrf,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Sets the account CSP and `Cache-Control: no-store` (pages show secrets and recovery codes).
fn with_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ACCOUNT_CSP),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn to_login(tenant: &ResolvedTenant) -> Response {
    let location = NavContext::login_returning_to(tenant, AccountSection::Security);
    with_headers((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

/// The caller's active session, if any.
async fn session(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<BrowserSession>, CoreError> {
    let name = state.cookies().session_name(&tenant.tenant);
    let token = jar.get(&name).map(|c| c.value().to_owned());
    state
        .ui_session_service()
        .current(tenant.tenant.id, token.as_deref())
        .await
}

/// Resolves the session (303 to sign-in without one) and the flow binding (csrf page when the
/// flow id or the CSRF token is missing).
async fn submission(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: &RequestLocale,
    jar: &CookieJar,
    query: &UiQuery,
    csrf: Option<String>,
) -> Result<Submission, Box<Response>> {
    let session = match session(state, tenant, jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Box::new(to_login(tenant))),
        Err(e) => {
            return Err(Box::new(core_error_page_in(
                state,
                Some(tenant),
                &locale.0,
                &e,
            )));
        }
    };
    let loc = account_locale(state, tenant, locale, &session).await;
    let (Some(flow_id), Some(csrf)) = (query.flow_id(), csrf.filter(|c| !c.is_empty())) else {
        return Err(Box::new(csrf_page(state, Some(tenant), &loc)));
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    Ok(Submission {
        session,
        locale: loc,
        flow_id,
        cookie,
        csrf,
    })
}

fn flow_url(tenant: &ResolvedTenant, path: &str, flow: FlowId) -> String {
    tenant.ui_url(&format!("{path}?flow={flow}"))
}

#[derive(Serialize)]
struct CredentialRow {
    id: String,
    label: String,
    created: String,
    created_iso: String,
    last_used: Option<String>,
    last_used_iso: Option<String>,
    delete_url: String,
}

fn row(tenant: &ResolvedTenant, flow: FlowId, c: &CredentialSummary) -> CredentialRow {
    let t = c.created_at.to_offset(time::UtcOffset::UTC);
    let used = c.last_used_at.map(|u| u.to_offset(time::UtcOffset::UTC));
    CredentialRow {
        id: c.id.to_string(),
        label: c.label.clone(),
        created: human(t),
        created_iso: iso(t),
        last_used: used.map(human),
        last_used_iso: used.map(iso),
        delete_url: flow_url(
            tenant,
            &format!("/ui/account/security/credentials/{}/delete", c.id),
            flow,
        ),
    }
}

fn account_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    title_key: &str,
) -> minijinja::Value {
    PageContext::for_tenant(state, tenant, loc, title_key).into_value()
}

fn render(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    template: &str,
    ctx: minijinja::Value,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    match state.renderer().page(template, ctx) {
        Ok(html) => with_headers((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, template, "rendering an account page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

/// Renders the security overview bound to `flow` / `csrf`.
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding"
)]
async fn render_overview(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    flow: FlowId,
    csrf: &str,
    messages: Vec<PageMessage>,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let overview = match state
        .ui_account_service()
        .overview(tenant.tenant.id, session)
        .await
    {
        Ok(o) => o,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let passkeys: Vec<CredentialRow> = overview
        .passkeys
        .iter()
        .map(|c| row(tenant, flow, c))
        .collect();
    let totp = overview.totp.as_ref().map(|c| row(tenant, flow, c));
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let messages = localized(state, loc, messages);
    let ctx = minijinja::context! {
        page => account_page(state, tenant, loc, "title.account_security"),
        account_base => tenant.base_path(),
        account_nav => "security",
        account_attributes_nav => attributes_nav,
        csrf_token => csrf,
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        recent_auth => overview.recent_auth,
        login_url => NavContext::login_returning_to(tenant, AccountSection::Security),
        passkeys => minijinja::Value::from(minijinja::value::Serde(&passkeys)),
        totp => minijinja::Value::from(minijinja::value::Serde(&totp)),
        recovery_codes_remaining => overview.recovery_codes_remaining,
        passkey_url => flow_url(tenant, "/ui/account/security/passkey", flow),
        passkey_options_url => flow_url(tenant, "/ui/account/security/passkey/options", flow),
        totp_url => flow_url(tenant, "/ui/account/security/totp", flow),
        recovery_codes_url => flow_url(tenant, "/ui/account/security/recovery-codes", flow),
    };
    render(
        state,
        tenant,
        loc,
        "account_security.html",
        ctx,
        status,
        jar,
    )
}

/// Starts a fresh settings flow (sets its cookie) and renders the overview with `messages`.
async fn fresh_overview(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let started = match state
        .ui_account_service()
        .start(tenant.tenant.id, session)
        .await
    {
        Ok(s) => s,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_overview(
        state,
        tenant,
        loc,
        session,
        started.flow_id,
        started.csrf_token.expose_secret(),
        messages,
        status,
        jar,
    )
    .await
}

/// Maps a refused or failed change to a response. Nothing changed in any of these cases.
async fn refused(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    err: AccountError,
) -> Response {
    match err {
        AccountError::Core(CoreError::Forbidden) => csrf_page(state, Some(tenant), &sub.locale),
        AccountError::Core(e) => core_error_page_in(state, Some(tenant), &sub.locale, &e),
        AccountError::Failure(AccountFailure::FlowExpired) => {
            fresh_overview(
                state,
                tenant,
                &sub.locale,
                &sub.session,
                vec![PageMessage::error(AccountFailure::FlowExpired.key())],
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        AccountError::Failure(f) => {
            render_overview(
                state,
                tenant,
                &sub.locale,
                &sub.session,
                sub.flow_id,
                &sub.csrf,
                vec![PageMessage::error(f.key())],
                StatusCode::BAD_REQUEST,
                CookieJar::new(),
            )
            .await
        }
    }
}

fn json_error(status: StatusCode, error: &str) -> Response {
    with_headers((status, axum::Json(serde_json::json!({ "error": error }))).into_response())
}

/// Groups a base32 key in blocks of four for manual entry.
pub(super) fn grouped(base32: &str) -> String {
    base32
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_enrolment(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    enrolment: &TotpEnrolment,
    error: Option<PageMessage>,
    attributes_nav: bool,
) -> Response {
    let loc = &sub.locale;
    let svg = match crate::adapters::qr::qr_svg(enrolment.otpauth_uri.expose_secret()) {
        Ok(svg) => svg,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let error = error.map(|m| m.localized(state, loc));
    let status = if error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let ctx = minijinja::context! {
        page => account_page(state, tenant, loc, "title.totp_enroll"),
        account_base => tenant.base_path(),
        account_nav => "security",
        account_attributes_nav => attributes_nav,
        csrf_token => &sub.csrf,
        qr_svg => minijinja::Value::from_safe_string(svg),
        secret_groups => grouped(enrolment.secret_base32.expose_secret()),
        confirm_url => flow_url(tenant, "/ui/account/security/totp/confirm", sub.flow_id),
        security_url => tenant.ui_url(PAGE),
        code_error => minijinja::Value::from(minijinja::value::Serde(&error)),
    };
    render(
        state,
        tenant,
        loc,
        "totp_enroll.html",
        ctx,
        status,
        CookieJar::new(),
    )
}

fn render_codes(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    codes: &[secrecy::SecretString],
    message: PageMessage,
    attributes_nav: bool,
) -> Response {
    let message = message.localized(state, loc);
    let codes: Vec<String> = codes.iter().map(|c| c.expose_secret().to_owned()).collect();
    let codes_text = codes.join("\n");
    let ctx = minijinja::context! {
        page => account_page(state, tenant, loc, "title.recovery_codes"),
        account_base => tenant.base_path(),
        account_nav => "security",
        account_attributes_nav => attributes_nav,
        message => minijinja::Value::from(minijinja::value::Serde(&message)),
        codes => codes,
        codes_text => codes_text,
        security_url => tenant.ui_url(PAGE),
    };
    render(
        state,
        tenant,
        loc,
        "recovery_codes.html",
        ctx,
        StatusCode::OK,
        CookieJar::new(),
    )
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
) -> Response {
    match session(&state, &tenant, &jar).await {
        Ok(Some(s)) => {
            let loc = account_locale(&state, &tenant, &locale, &s).await;
            fresh_overview(&state, &tenant, &loc, &s, Vec::new(), StatusCode::OK).await
        }
        Ok(None) => to_login(&tenant),
        Err(e) => core_error_page_in(&state, Some(&tenant), &locale.0, &e),
    }
}

async fn passkey_options(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    // The CSRF token may come in the form or the header; a body over the limit is refused.
    let form_csrf = match form {
        Ok(Form(f)) => f.csrf_token,
        Err(e) if rejection_is_too_large(&e) => {
            return json_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request");
        }
        Err(_) => None,
    };
    let header_csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    match session(&state, &tenant, &jar).await {
        Ok(Some(_)) => {}
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "login_required"),
        Err(e) => return core_error_page_in(&state, Some(&tenant), &locale.0, &e),
    }
    let sub = match submission(
        &state,
        &tenant,
        &locale,
        &jar,
        &q,
        form_csrf.or(header_csrf),
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let rp = match relying_party(&tenant.tenant, &tenant.issuer) {
        Ok(rp) => rp,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &sub.locale, &e),
    };
    match state
        .ui_account_service()
        .begin_passkey(&tenant.tenant, &sub.session, &sub.binding(), &rp)
        .await
    {
        Ok(options) => with_headers(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                options,
            )
                .into_response(),
        ),
        Err(AccountError::Core(CoreError::Forbidden)) => {
            csrf_page(&state, Some(&tenant), &sub.locale)
        }
        Err(AccountError::Core(e)) => core_error_page_in(&state, Some(&tenant), &sub.locale, &e),
        Err(AccountError::Failure(f)) => json_error(StatusCode::BAD_REQUEST, f.key()),
    }
}

async fn passkey_finish(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token.clone()).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let rp = match relying_party(&tenant.tenant, &tenant.issuer) {
        Ok(rp) => rp,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &sub.locale, &e),
    };
    let result = state
        .ui_account_service()
        .finish_passkey(
            &tenant.tenant,
            &sub.session,
            &sub.binding(),
            &rp,
            form.response.as_deref().unwrap_or_default(),
            form.label.as_deref().unwrap_or_default(),
            &ctx,
        )
        .await;
    match result {
        Ok(_) => {
            render_overview(
                &state,
                &tenant,
                &sub.locale,
                &sub.session,
                sub.flow_id,
                &sub.csrf,
                vec![PageMessage::info("account.passkey_registered")],
                StatusCode::OK,
                CookieJar::new(),
            )
            .await
        }
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

async fn totp_begin(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    // Computed before the change, so a failure here never loses its one-time result.
    let attributes_nav = match attributes_nav_or_page(&state, &tenant, &sub.locale).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    match state
        .ui_account_service()
        .begin_totp(&tenant.tenant, &sub.session, &sub.binding())
        .await
    {
        Ok(enrolment) => render_enrolment(&state, &tenant, &sub, &enrolment, None, attributes_nav),
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

async fn totp_confirm(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token.clone()).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    // Computed before the change, so a failure here never loses its one-time result.
    let attributes_nav = match attributes_nav_or_page(&state, &tenant, &sub.locale).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let service = state.ui_account_service();
    let result = service
        .confirm_totp(
            &tenant.tenant,
            &sub.session,
            &sub.binding(),
            form.code.as_deref().unwrap_or_default(),
            &ctx,
        )
        .await;
    match result {
        Ok(codes) => render_codes(
            &state,
            &tenant,
            &sub.locale,
            &codes,
            PageMessage::info("account.totp_enrolled"),
            attributes_nav,
        ),
        Err(AccountError::Failure(AccountFailure::TotpInvalidCode)) => {
            // The pending secret is kept: show the same QR code again with the error.
            match service
                .pending_totp(&tenant.tenant, &sub.session, &sub.binding())
                .await
            {
                Ok(enrolment) => render_enrolment(
                    &state,
                    &tenant,
                    &sub,
                    &enrolment,
                    Some(PageMessage::error(AccountFailure::TotpInvalidCode.key())),
                    attributes_nav,
                ),
                Err(e) => refused(&state, &tenant, &sub, e).await,
            }
        }
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

async fn recovery_codes(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    // Computed before the change, so a failure here never loses its one-time result.
    let attributes_nav = match attributes_nav_or_page(&state, &tenant, &sub.locale).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    match state
        .ui_account_service()
        .regenerate_recovery_codes(&tenant.tenant, &sub.session, &sub.binding(), &ctx)
        .await
    {
        Ok(codes) => render_codes(
            &state,
            &tenant,
            &sub.locale,
            &codes,
            PageMessage::info("account.recovery_codes_regenerated"),
            attributes_nav,
        ),
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn remove_credential(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Path(id): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<SecurityForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let Ok(id) = uuid::Uuid::parse_str(&id).map(CredentialId) else {
        return refused(
            &state,
            &tenant,
            &sub,
            AccountFailure::CredentialNotFound.into(),
        )
        .await;
    };
    match state
        .ui_account_service()
        .remove_credential(&tenant.tenant, &sub.session, &sub.binding(), id, &ctx)
        .await
    {
        Ok(kind) => {
            let key = match kind {
                anvil_core::model::CredentialKind::Totp => "account.totp_removed",
                _ => "account.passkey_removed",
            };
            render_overview(
                &state,
                &tenant,
                &sub.locale,
                &sub.session,
                sub.flow_id,
                &sub.csrf,
                vec![PageMessage::info(key)],
                StatusCode::OK,
                CookieJar::new(),
            )
            .await
        }
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_is_grouped_in_fours() {
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
        assert_eq!(grouped(""), "");
    }

    #[test]
    fn account_csp_only_adds_self_script_and_connect() {
        let default: Vec<&str> = crate::layers::security_headers::CSP.split("; ").collect();
        let account: Vec<&str> = ACCOUNT_CSP.split("; ").collect();
        for d in &default {
            assert!(account.contains(d), "{d}");
        }
        let extra: Vec<&&str> = account.iter().filter(|d| !default.contains(d)).collect();
        assert_eq!(extra, vec![&"script-src 'self'", &"connect-src 'self'"]);
        assert!(!ACCOUNT_CSP.contains("unsafe"));
    }
}
