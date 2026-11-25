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
//!
//! # Sign-in routes (AUTH-04, AUTH-05, AUTH-09)
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/login[?request=]` | password form plus the passkey button (hidden until webauthn.js runs) |
//! | `POST /ui/login?flow=` | email + password |
//! | `POST /ui/login/passkey/options?flow=` | discoverable WebAuthn request options (JSON, for webauthn.js) |
//! | `POST /ui/login/passkey?flow=` | the passkey assertion (`response`) |
//! | `GET/POST /ui/login/second-factor?flow=` | TOTP or recovery code ([`super::mfa`]) |
//!
//! Brute-force protection goes through the one limiter ([`guard_attempt`] / [`record_attempt`]):
//! a password POST is keyed by (identifier, client IP) and by identifier, a passkey assertion by
//! client IP, a second factor by user. Order of a password POST: binding fields present →
//! brute-force gate (a lock answers 429 with `Retry-After` and an in-page "try again in N
//! seconds"; when the identifier tier asks for a CAPTCHA and the tenant has one, the CAPTCHA is
//! verified server-side here, before the password is looked at) → flow service (Argon2, dummy
//! hash for unknown identifiers) → record the attempt. Nothing sleeps. Unknown identifiers go
//! through exactly the same steps as known ones.
//!
//! The login page allows `script-src 'self'` and `connect-src 'self'` (webauthn.js and its
//! options request); a page that shows the CAPTCHA widget sends the provider's CSP instead
//! ([`captcha_csp`]).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anvil_cache::limiter::Decision;
use anvil_core::error::CoreError;
use anvil_core::flow::engine::{FlowEnv, FlowInput, FlowState};
use anvil_core::flow::form::{FormDescription, FormMessage, MessageLevel};
use anvil_core::flow::login::SECOND_FACTOR_FORM_ID;
use anvil_core::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, CaptchaSettings,
    FlowId, FlowKind, RegistrationMode, RequestContext, SessionId, UserId,
};
use anvil_core::ports::RelyingParty;
use anvil_core::service::audit::AuditService;
use anvil_core::service::flow::{
    AuthAttempt, FlowContext, FlowOutcome, FlowService, StartedFlow, SubmitResult, bind_form,
};
use anvil_core::service::session::SessionService;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use minijinja::value::{Serde, Value};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::account_security::ACCOUNT_CSP;
use super::mfa::seal_factor_token;
use crate::adapters::captcha::{
    CaptchaError, CaptchaVerifier, DEFAULT_TIMEOUT, captcha_csp, open_secret,
};
use crate::adapters::passkey::{WebauthnPasskeys, relying_party};
use crate::client_ip::ClientIp;
use crate::errors::{core_error_page, error_page};
use crate::layers::ratelimit::{attempt_keys, guard_attempt, record_attempt};
use crate::render::{PageContext, PageLinks};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// CSP of the sign-in page: the default policy plus webauthn.js (`script-src 'self'`) and its
/// options request (`connect-src 'self'`). The same policy as the account security pages.
pub const LOGIN_CSP: &str = ACCOUNT_CSP;

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
    Router::new()
        .route("/ui/login", get(show).post(submit))
        .route("/ui/login/passkey/options", post(passkey_options))
        .route("/ui/login/passkey", post(passkey_submit))
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

/// `POST /ui/login?flow=`: email and password, behind the brute-force gate (module docs).
async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant));
    };
    let identifier = form.identifier.clone().unwrap_or_default();
    let posted = Posted {
        flow_id,
        csrf,
        identifier: &identifier,
    };
    let (strict, loose) = attempt_keys(tenant.tenant.id, &identifier, ip);
    let captcha = tenant.tenant.settings.captcha.as_ref();

    match guard_attempt(&state, &strict, &loose, captcha.is_some()).await {
        Decision::Deny { retry_after } => {
            return match posted_login_form(&state, &tenant, &posted) {
                Ok(form) => locked_page(&state, &tenant, form, retry_after, None),
                Err(e) => core_error_page(&state, Some(&tenant), &e),
            };
        }
        Decision::RequireCaptcha => {
            if let Some(settings) = captcha
                && let Err(key) = verify_captcha(&state, &tenant, &ctx, settings, &form, ip).await
            {
                return match posted_login_form(&state, &tenant, &posted) {
                    Ok(mut form) => {
                        form.messages = vec![error_message(key, captcha_text(key))];
                        let extras = Extras {
                            captcha: Some(settings),
                            ..Extras::default()
                        };
                        render_tenant_form_with(
                            &state,
                            &tenant,
                            &form,
                            None,
                            StatusCode::BAD_REQUEST,
                            CookieJar::new(),
                            &extras,
                        )
                    }
                    Err(e) => core_error_page(&state, Some(&tenant), &e),
                };
            }
        }
        Decision::Allow => {}
    }

    let input = FlowInput::Login {
        identifier: identifier.clone(),
        password: form.password.clone().unwrap_or_default(),
    };
    let result = match submit_flow(&state, &tenant, &ctx, &jar, flow_id, csrf, input).await {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let keys = [strict.clone(), loose.clone()];
    let mut extras = Extras::default();
    match result.attempt {
        Some(AuthAttempt::PasswordFailed { .. }) => {
            record_attempt(&state, tenant.tenant.id, &ctx, &keys, false).await;
            match guard_attempt(&state, &strict, &loose, captcha.is_some()).await {
                Decision::Deny { retry_after } => {
                    if let FlowOutcome::Render(form) = result.outcome {
                        return locked_page(&state, &tenant, form, retry_after, None);
                    }
                }
                Decision::RequireCaptcha => extras.captcha = captcha,
                Decision::Allow => {}
            }
        }
        Some(AuthAttempt::PasswordSucceeded { user, .. }) => {
            record_attempt(&state, tenant.tenant.id, &ctx, &keys, true).await;
            extras.factor_token = factor_token(&state, &tenant, flow_id, user);
        }
        _ => {}
    }
    outcome_response_with(&state, &tenant, result.outcome, &extras)
}

/// The binding fields of a password POST, for pages rendered without running the flow (lock,
/// CAPTCHA). The CSRF token is the submitted one; the flow service checks it on the next POST.
struct Posted<'a> {
    flow_id: FlowId,
    csrf: &'a str,
    identifier: &'a str,
}

/// The sign-in form of the identify step bound to the posted flow, with the identifier echoed.
/// Used when the brute-force gate answers before the flow runs, so the response is the same
/// whether or not the account exists.
fn posted_login_form(
    state: &AppState,
    tenant: &ResolvedTenant,
    posted: &Posted<'_>,
) -> Result<FormDescription, CoreError> {
    let env = FlowEnv {
        registration: tenant.tenant.settings.registration,
        require_verified_email: tenant.tenant.settings.require_verified_email,
        policy: state.config().password_policy,
    };
    let (_, form) = FlowState::initial(FlowKind::Login, None, &env)?;
    let base = ui_base(tenant);
    let rp = Err(CoreError::Internal("not used".into()));
    let ctx = RequestContext::default();
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let mut form = bind_form(form, &cx, posted.flow_id, posted.csrf);
    let echoed = posted.identifier.trim();
    if let Some(field) = form.fields.iter_mut().find(|f| f.name == "identifier")
        && !echoed.is_empty()
    {
        field.value = Some(echoed.to_owned());
    }
    Ok(form)
}

/// Message key of a locked sign-in or second factor.
pub(super) const TOO_MANY_ATTEMPTS: &str = "login.too_many_attempts";

/// `Retry-After` in whole seconds, rounded up, at least 1 (the rounding of the limiter's 429).
pub(super) fn whole_seconds(d: Duration) -> u64 {
    (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
}

/// "Too many attempts. Try again in N seconds." for a lock of `retry_after`.
pub(super) fn too_many_attempts(retry_after: Duration) -> FormMessage {
    let n = whole_seconds(retry_after);
    let unit = if n == 1 { "second" } else { "seconds" };
    FormMessage {
        level: MessageLevel::Error,
        key: TOO_MANY_ATTEMPTS.to_owned(),
        text: format!("Too many attempts. Try again in {n} {unit}."),
    }
}

/// A form page answering a locked attempt: 429 with `Retry-After`, `Cache-Control: no-store`
/// and the lock message in place of the form's messages. The form stays usable once the lock
/// window has passed.
pub(super) fn locked_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    mut form: FormDescription,
    retry_after: Duration,
    factor_token: Option<String>,
) -> Response {
    form.messages = vec![too_many_attempts(retry_after)];
    let extras = Extras {
        factor_token,
        ..Extras::default()
    };
    let mut resp = render_tenant_form_with(
        state,
        tenant,
        &form,
        None,
        StatusCode::TOO_MANY_REQUESTS,
        CookieJar::new(),
        &extras,
    );
    let headers = resp.headers_mut();
    headers.insert(
        header::RETRY_AFTER,
        HeaderValue::from(whole_seconds(retry_after)),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn error_message(key: &str, text: &str) -> FormMessage {
    FormMessage {
        level: MessageLevel::Error,
        key: key.to_owned(),
        text: text.to_owned(),
    }
}

/// CAPTCHA message keys.
const CAPTCHA_REQUIRED: &str = "login.captcha_required";
const CAPTCHA_FAILED: &str = "login.captcha_failed";

fn captcha_text(key: &str) -> &'static str {
    if key == CAPTCHA_FAILED {
        "The security check did not succeed. Please complete it again, then sign in."
    } else {
        "Please complete the security check, then sign in."
    }
}

/// Verifies the CAPTCHA response of a password POST server-side (fail closed). `Err` carries the
/// message key: no response submitted, or a response the provider did not accept (or could not
/// be checked). A submitted response that fails is audited as `captcha_failed`.
async fn verify_captcha(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    settings: &CaptchaSettings,
    form: &UiForm,
    ip: IpAddr,
) -> Result<(), &'static str> {
    let token = match settings.provider {
        anvil_core::model::CaptchaProvider::Turnstile => form.turnstile_response.as_deref(),
        anvil_core::model::CaptchaProvider::Hcaptcha => form.hcaptcha_response.as_deref(),
    }
    .unwrap_or_default();
    if token.trim().is_empty() {
        return Err(CAPTCHA_REQUIRED);
    }
    let result = match (
        open_secret(state.kek(), tenant.tenant.id, settings),
        CaptchaVerifier::new(state.config().captcha_endpoints.clone(), DEFAULT_TIMEOUT),
    ) {
        (Ok(secret), Ok(verifier)) => verifier.verify(settings, &secret, token, Some(ip)).await,
        (Err(e), _) | (_, Err(e)) => Err(e),
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            if let CaptchaError::Config(msg) = &e {
                tracing::error!(error = %msg, "CAPTCHA configuration error; rejecting");
            }
            let audit = AuditService {
                storage: state.storage_arc(),
                clock: state.clock_arc(),
            };
            let reason = match e {
                CaptchaError::MissingToken | CaptchaError::Rejected => "rejected",
                CaptchaError::Unavailable(_) => "unavailable",
                CaptchaError::Config(_) => "configuration",
            };
            if let Err(e) = audit
                .record(
                    tenant.tenant.id,
                    AuditActor::anonymous(ActorKind::User),
                    AuditAction::CaptchaFailed,
                    None,
                    AuditOutcome::Failure,
                    ctx,
                    AuditDetails::reason(reason),
                )
                .await
            {
                tracing::error!(error = %e, "recording the captcha_failed audit event failed");
            }
            Err(CAPTCHA_FAILED)
        }
    }
}

/// The second-factor binding token for `user` in `flow` (see [`super::mfa`]); `None` (logged)
/// if sealing fails, in which case the second-factor POST restarts the sign-in.
fn factor_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: FlowId,
    user: UserId,
) -> Option<String> {
    seal_factor_token(state.kek(), tenant.tenant.id, flow, user)
        .inspect_err(|e| tracing::error!(error = %e, "sealing the second-factor token failed"))
        .ok()
}

// ---------------------------------------------------------------------------------------------
// Passkey sign-in
// ---------------------------------------------------------------------------------------------

/// `POST /ui/login/passkey/options?flow=`: discoverable request options for webauthn.js (JSON,
/// no `allowCredentials`). Bound to the flow (cookie + `csrf_token` field). Errors are JSON
/// `{"error": key}`: 403 `csrf`, 400 `login.passkey_failed` (expired or unsuitable flow), 500.
async fn passkey_options(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let json_error = |status: StatusCode, key: &str| {
        no_store((status, axum::Json(serde_json::json!({ "error": key }))).into_response())
    };
    let Ok(Form(form)) = form else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return json_error(StatusCode::FORBIDDEN, "csrf");
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    // Creating a challenge records nothing, so no request context.
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
        .passkey_options(&cx, flow_id, cookie.as_deref(), csrf)
        .await
    {
        Ok(options) => no_store(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                options,
            )
                .into_response(),
        ),
        Err(CoreError::Forbidden) => json_error(StatusCode::FORBIDDEN, "csrf"),
        Err(CoreError::InvalidRequest(_)) => {
            json_error(StatusCode::BAD_REQUEST, "login.passkey_failed")
        }
        Err(e) => {
            tracing::error!(error = %e, "creating passkey request options failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// `POST /ui/login/passkey?flow=`: the assertion from webauthn.js (`response`). Every failure is
/// the sign-in form with `login.passkey_failed` (400). Failures are counted per client IP only
/// (a passkey names no identifier before it is verified).
async fn passkey_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant));
    };
    let key = anvil_cache::limiter::LimitKey::Ip(ip);
    if let Decision::Deny { retry_after } = guard_attempt(&state, &key, &key, false).await {
        let posted = Posted {
            flow_id,
            csrf,
            identifier: "",
        };
        return match posted_login_form(&state, &tenant, &posted) {
            Ok(form) => locked_page(&state, &tenant, form, retry_after, None),
            Err(e) => core_error_page(&state, Some(&tenant), &e),
        };
    }
    let input = FlowInput::PasskeyAssertion {
        response_json: form.response.clone().unwrap_or_default(),
    };
    let result = match submit_flow(&state, &tenant, &ctx, &jar, flow_id, csrf, input).await {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    match result.attempt {
        Some(AuthAttempt::PasskeyFailed) => {
            record_attempt(
                &state,
                tenant.tenant.id,
                &ctx,
                std::slice::from_ref(&key),
                false,
            )
            .await;
            if let (Decision::Deny { retry_after }, FlowOutcome::Render(form)) = (
                guard_attempt(&state, &key, &key, false).await,
                &result.outcome,
            ) {
                return locked_page(&state, &tenant, form.clone(), retry_after, None);
            }
        }
        Some(AuthAttempt::PasskeySucceeded { .. }) => {
            record_attempt(
                &state,
                tenant.tenant.id,
                &ctx,
                std::slice::from_ref(&key),
                true,
            )
            .await;
        }
        _ => {}
    }
    outcome_response(&state, &tenant, result.outcome)
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
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
    /// Second-factor binding token (second-factor form, [`super::mfa`]).
    pub(super) factor_token: Option<String>,
    /// Passkey assertion JSON (webauthn.js).
    pub(super) response: Option<String>,
    /// Turnstile widget response.
    #[serde(rename = "cf-turnstile-response")]
    pub(super) turnstile_response: Option<String>,
    /// hCaptcha widget response.
    #[serde(rename = "h-captcha-response")]
    pub(super) hcaptcha_response: Option<String>,
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
        SECOND_FACTOR_FORM_ID => ("second_factor.html", "Two-step verification"),
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
    render_page(state, tenant, template, ctx, status, jar)
}

fn render_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    template: &str,
    ctx: Value,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    match state.renderer().page(template, ctx) {
        Ok(html) => (status, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, template, "rendering a form page failed");
            core_error_page(state, tenant, &CoreError::Internal("render".into()))
        }
    }
}

/// Page extras of the sign-in pages that the flow outcome does not carry.
#[derive(Default)]
pub(super) struct Extras<'a> {
    /// Show the tenant's CAPTCHA widget on the sign-in form (the brute-force gate asks for it).
    pub(super) captcha: Option<&'a CaptchaSettings>,
    /// Second-factor binding token of the user who just passed the password step.
    pub(super) factor_token: Option<String>,
}

/// URLs of the passkey sign-in form (webauthn.js `data-options-url` and form action).
#[derive(Serialize)]
struct PasskeyView {
    options_url: String,
    action: String,
}

/// Values of the `captcha.html` partial.
#[derive(Serialize)]
struct CaptchaView {
    provider: &'static str,
    site_key: String,
}

/// The flow id of a bound form (`…?flow={id}` action).
fn flow_of(form: &FormDescription) -> Option<FlowId> {
    let (_, id) = form.action.rsplit_once("?flow=")?;
    uuid::Uuid::parse_str(id).ok().map(FlowId)
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
    render_tenant_form_with(
        state,
        tenant,
        form,
        request,
        status,
        jar,
        &Extras::default(),
    )
}

/// Renders a tenant form page with sign-in extras. The sign-in form gets the passkey form (when
/// the issuer can be a WebAuthn relying party) and the CAPTCHA widget when asked for; the
/// second-factor form posts to `/ui/login/second-factor` and carries the binding token.
pub(super) fn render_tenant_form_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    form: &FormDescription,
    request: Option<AuthRequestId>,
    status: StatusCode,
    jar: CookieJar,
    extras: &Extras<'_>,
) -> Response {
    let (template, title) = form_template(&form.id);
    let mut page = PageContext::for_tenant(state, tenant, title);
    page.links = links_for(tenant, &form.id, request);
    let base = ui_base(tenant);
    let mut form = form.clone();
    let mut passkey = None;
    let mut captcha = None;
    let mut factor_token = None;
    match (form.id.as_str(), flow_of(&form)) {
        ("login", Some(flow)) => {
            if tenant_relying_party(tenant).is_ok() {
                passkey = Some(PasskeyView {
                    options_url: format!("{base}/login/passkey/options?flow={flow}"),
                    action: format!("{base}/login/passkey?flow={flow}"),
                });
            }
            captcha = extras.captcha;
        }
        (SECOND_FACTOR_FORM_ID, Some(flow)) => {
            form.action = format!("{base}/login/second-factor?flow={flow}");
            factor_token = extras.factor_token.clone();
        }
        _ => {}
    }
    let ctx = minijinja::context! {
        page => page.into_value(),
        form => Value::from(Serde(&form)),
        passkey => Value::from(Serde(&passkey)),
        captcha => Value::from(Serde(captcha.map(|c| CaptchaView {
            provider: c.provider.as_str(),
            site_key: c.site_key.clone(),
        }))),
        factor_token => factor_token,
    };
    let mut resp = render_page(state, Some(tenant), template, ctx, status, jar);
    let csp = match (captcha, &passkey) {
        (Some(c), _) => HeaderValue::from_str(&captcha_csp(c.provider).header_value()).ok(),
        (None, Some(_)) => Some(HeaderValue::from_static(LOGIN_CSP)),
        (None, None) => None,
    };
    if let Some(csp) = csp {
        resp.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    resp
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

/// A new sign-in flow with the `flow.expired` message (400): the answer to a submission that
/// cannot continue its flow (for example a second-factor POST without a valid binding token).
pub(super) async fn restart_login(state: &AppState, tenant: &ResolvedTenant) -> Response {
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
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
        .start(&cx, FlowKind::Login, None, None)
        .await
    {
        Ok(mut started) => {
            started.form.messages.insert(
                0,
                error_message(
                    "flow.expired",
                    anvil_core::flow::engine::message_text("flow.expired"),
                ),
            );
            started_response(state, tenant, &started, None, StatusCode::BAD_REQUEST)
        }
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
    match submit_flow(state, tenant, ctx, jar, flow_id, csrf, input).await {
        Ok(result) => outcome_response(state, tenant, result.outcome),
        Err(resp) => *resp,
    }
}

/// Runs a bound submission through the flow service. `Err` is the finished error response
/// (`csrf` page for a binding failure, the error page otherwise).
pub(super) async fn submit_flow(
    state: &AppState,
    tenant: &ResolvedTenant,
    ctx: &RequestContext,
    jar: &CookieJar,
    flow_id: FlowId,
    csrf: &str,
    input: FlowInput,
) -> Result<SubmitResult, Box<Response>> {
    let cookie_name = state.cookies().flow_name(&tenant.tenant);
    let cookie = jar.get(&cookie_name).map(|c| c.value().to_owned());
    let session = current_session(state, tenant, jar)
        .await
        .map_err(|e| Box::new(core_error_page(state, Some(tenant), &e)))?;
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx,
    };
    match state
        .ui_flow_service()
        .submit(&cx, flow_id, cookie.as_deref(), csrf, input, session)
        .await
    {
        Ok(result) => Ok(result),
        Err(CoreError::Forbidden) => Err(Box::new(csrf_page(state, Some(tenant)))),
        Err(e) => Err(Box::new(core_error_page(state, Some(tenant), &e))),
    }
}

/// Maps a flow outcome of a tenant self-service page to a response.
fn outcome_response(state: &AppState, tenant: &ResolvedTenant, outcome: FlowOutcome) -> Response {
    outcome_response_with(state, tenant, outcome, &Extras::default())
}

/// [`outcome_response`] with sign-in page extras for a rendered form.
pub(super) fn outcome_response_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    outcome: FlowOutcome,
    extras: &Extras<'_>,
) -> Response {
    let cookies = state.cookies();
    match outcome {
        FlowOutcome::Render(form) => render_tenant_form_with(
            state,
            tenant,
            &form,
            None,
            form_status(&form),
            CookieJar::new(),
            extras,
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
