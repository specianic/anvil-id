//! Login pages (`GET/POST /ui/login[?request=][&return_to=]`) and the helpers shared by every
//! self-service page (flow start, submission, outcome mapping, rendering).
//!
//! Status codes: a form with an error message → 400; message pages → 200; a successful sign-in
//! → 303 See Other to `{issuer}/authorize/continue?request=…`, or to the login's return target
//! (below), or the signed-in message page when the login has neither. `CoreError::Forbidden` (wrong or missing
//! CSRF token or flow cookie) → the `csrf` error page with 403. Form values are never logged.
//!
//! Submissions carry the request context (client IP, user agent, request id; [`AuditContext`])
//! into the flow service, which records it on sessions and audit events.
//!
//! # Sign-in routes (AUTH-04, AUTH-05, AUTH-09)
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/login[?request=][&return_to=]` | password form plus the passkey button (hidden until webauthn.js runs) |
//! | `POST /ui/login?flow=` | email + password |
//! | `POST /ui/login/passkey/options?flow=` | discoverable WebAuthn request options (JSON, for webauthn.js) |
//! | `POST /ui/login/passkey?flow=` | the passkey assertion (`response`) |
//! | `GET/POST /ui/login/second-factor?flow=` | TOTP or recovery code, or the enrolment code ([`super::mfa`]) |
//! | `POST /ui/login/enroll/passkey/start?flow=` | enrolment step: WebAuthn creation options (JSON, for webauthn.js) |
//! | `POST /ui/login/enroll/passkey/finish?flow=` | enrolment step: the registration response (`response`) |
//! | `POST /ui/login/second-factor/passkey/start?flow=` | second-factor step: WebAuthn request options (JSON, for webauthn.js) |
//! | `POST /ui/login/second-factor/passkey/finish?flow=` | second-factor step: the assertion of one of the step user's passkeys (`response`) |
//! | `/ui/login/email-code[/verify]`, `/ui/login/email-link` | email code and magic link ([`super::email_code`]) |
//! | `POST /ui/login/identify?flow=` | email-first page and single-sign-on choice (`identifier`, `choice` = `sso` / `password` / `change`) |
//!
//! # Identifier-first sign-in (ORG-04)
//!
//! A tenant with a verified, routed domain whose connection can route (enabled, org-owned, OIDC,
//! or SAML only while `saml_experimental` is on: the same rule as routing) starts at the
//! email-first page (`login_identify.html`, form `login-identify`, passkey and upstream buttons
//! included); every other tenant keeps the combined form. The brute-force lock and CAPTCHA pages
//! answered before the flow runs follow the same decision (`FlowService::initial_login_form`); the
//! password step reached from the email page carries the CAPTCHA widget while the address's
//! brute-force tier asks for one. The email is routed by its domain only (`FlowService::identify`): an org IdP
//! (303 to the IdP through the same start as its own route, with the binding cookie), the
//! single-sign-on choice (form `login-sso-choice`) or the password step (`login.html` with the
//! email in a hidden field, shown read-only with a "change" button). `login_hint` and
//! `organization` can skip the email page (`FlowService::start_login`). Plain form posts and 303s
//! only: no JavaScript is needed.
//!
//! # Return target (`return_to`, ORG-02)
//!
//! The invitation page links signed-out users to `/ui/login?return_to=/ui/invitation?token=…`.
//! `return_to` is an exact allowlist (`policy::return_to::parse_return_target`: that path with one
//! base64url `token` of at most 128 characters, nothing else); any other value is ignored silently
//! and never logged. The flow service keeps it sealed in the flow state, only when the login has
//! no authorization request (the request always wins), and every sign-in that finishes the login
//! (password, passkey, second factor, email code or link, upstream, SAML) answers 303 to
//! `{issuer}` + the path, the tenant's own origin; a host is never taken from the request. The
//! login page is `no-store` and, like every page, `Referrer-Policy: no-referrer` (the URL carries
//! the token).
//!
//! When the tenant enables email sign-in (`email_otp` or `magic_link`) the sign-in form is followed
//! by the "Email me a sign-in code" form (`email_code` template variable), its address prefilled
//! like the identifier.
//!
//! # MFA policy, step-up and `login_hint` (AUTH-08, OIDC-14)
//!
//! `GET /ui/login?request=` starts the flow with `FlowService::start_login`: for a signed-in
//! single-factor session that the stored request wants stepped up, the page is directly the
//! second-factor (or enrolment) form for that session's user, without the password. Otherwise
//! it is the sign-in form, with the identifier prefilled from the request's `login_hint` only
//! when the hint normalises to an email address (the value is auto-escaped like every field).
//! The enrolment page (`mfa_enroll.html`) offers a choice: a passkey (button hidden until
//! webauthn.js runs; the registration state lives in the flow and is used once) or the
//! authenticator-app QR code and key (works without JavaScript). After the confirming code it
//! shows the new recovery codes once, then continues the request; a stored passkey signs in
//! directly (`amr [hwk|swk, user, mfa]`). A user with a passkey sees a passkey option on the
//! second-factor page (`passkey_second_factor` template variable); an assertion of one of that
//! user's own passkeys signs in the same way (or upgrades the step-up session). The passkey
//! routes are bound to the flow (cookie + `csrf_token`) like every flow form.
//!
//! Brute-force protection goes through the one limiter, driven by [`super::flow_driver`] (the
//! single place that gates, records and decides locks for every renderer): a password POST is
//! keyed by (identifier, client IP) and by identifier, a passkey assertion by client IP, a second
//! factor by user. Order of a password POST: binding fields present → brute-force gate (a lock
//! answers 429 with `Retry-After` and an in-page "try again in N seconds"; when the identifier
//! tier asks for a CAPTCHA and the tenant has one, the CAPTCHA is verified server-side by the
//! driver, before the password is looked at) → flow service (Argon2, dummy hash for unknown
//! identifiers) → record the attempt. Nothing sleeps. Unknown identifiers go
//! through exactly the same steps as known ones.
//!
//! The login page allows `script-src 'self'` and `connect-src 'self'` (webauthn.js and its
//! options request); a page that shows the CAPTCHA widget sends the provider's CSP instead
//! ([`captcha_csp`]).

use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::flow::email_code::{EMAIL_CODE_FORM_ID, LINK_INVALID, OTHER_BROWSER};
use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::FieldKind;
use anvil_core::flow::form::{FormDescription, FormMessage, MessageLevel};
use anvil_core::flow::login::{
    ENROLL_FORM_ID, IDENTIFY_FORM_ID, IdentifyInput, PASSKEY_ENROLMENT_FAILED,
    SECOND_FACTOR_FORM_ID, SECOND_FACTOR_PASSKEY_FAILED, SECOND_FACTOR_PASSKEY_FIELD,
    SSO_CHOICE_FORM_ID, UPSTREAM_LINK_FORM_ID,
};
use anvil_core::model::{
    AuthRequestId, BrowserSession, CaptchaSettings, FlowId, FlowKind, RequestContext, UserId,
    normalize_email,
};
use anvil_core::policy::return_to::{ReturnTarget, parse_return_target};
use anvil_core::ports::RelyingParty;
use anvil_core::service::account::{SettingsBinding, TotpEnrolment};
use anvil_core::service::flow::{
    AuthAttempt, Continue, FlowContext, FlowOutcome, FlowService, IdpStart, LoginStart,
    StartedFlow, start_idp,
};
use anvil_core::service::saml::SamlService;
use anvil_core::service::session::SessionService;
use anvil_core::service::upstream::{StartResult, UpstreamService};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use minijinja::value::{Serde, Value};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::account_security::{ACCOUNT_CSP, grouped};
use super::flow_driver::{
    self, CaptchaAnswer, DriveOutcome, DriveRejection, FlowBinding, Identified, InFlowPasskey,
    LoginMethod, PasskeyStep, Throttle, login_methods,
};
use super::mfa::seal_factor_token;
use super::nav::{AccountSection, NavContext, StaleRequest, UiPage};
use crate::adapters::captcha::captcha_csp;
use crate::adapters::passkey::{WebauthnPasskeys, relying_party};
use crate::client_ip::ClientIp;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales, locale_for_request};
use crate::layers::ratelimit::{Surface, too_many_requests};
use crate::render::PageContext;
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
            saml_enabled: self.config().saml_experimental,
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
        .route("/ui/login/identify", post(identify))
        .route("/ui/login/passkey/options", post(passkey_options))
        .route("/ui/login/passkey", post(passkey_submit))
        .route(
            "/ui/login/enroll/passkey/start",
            post(passkey_enrolment_start),
        )
        .route(
            "/ui/login/enroll/passkey/finish",
            post(passkey_enrolment_finish),
        )
        .route(
            "/ui/login/second-factor/passkey/start",
            post(passkey_second_factor_start),
        )
        .route(
            "/ui/login/second-factor/passkey/finish",
            post(passkey_second_factor_finish),
        )
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    let nav = match NavContext::from_query(&state, &tenant, q.request.as_deref()).await {
        Ok(nav) => nav.with_return_to(q.return_target()),
        Err(StaleRequest::Unknown) => return stale_request_page(&state, &tenant, &locale.0),
    };
    let request = nav.request().map(|r| r.id);
    let loc = page_locale(&state, &tenant, locale, &headers, request).await;
    let current = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let mut started = match flow_driver::start_login(
        &state,
        &tenant,
        request,
        current.as_ref(),
        q.return_target(),
    )
    .await
    {
        Ok(LoginStart::Form(s)) => s,
        Ok(LoginStart::Idp { started, idp }) => {
            // Bound to the new flow: its cookie goes out with the redirect to the IdP.
            let binding = SettingsBinding {
                flow_id: started.flow_id,
                cookie_token: Some(started.cookie_token.expose_secret()),
                csrf_token: &started.form.csrf_token,
            };
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
            );
            // Starting at the IdP records nothing yet, so no request context.
            return idp_redirect(
                &state,
                &tenant,
                &loc,
                &RequestContext::default(),
                &binding,
                &idp,
                current.as_ref(),
                jar,
            )
            .await;
        }
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    if started.form.id == "login"
        && let Some(hint) = login_hint(&state, &tenant, request).await
        && let Some(field) = started
            .form
            .fields
            .iter_mut()
            .find(|f| f.name == "identifier")
    {
        field.value = Some(hint);
    }
    let extras = Extras {
        factor_token: started
            .factor_user
            .and_then(|user| factor_token(&state, &tenant, started.flow_id, user)),
        totp: started.totp.as_ref(),
        upstream: identify_buttons(&state, &tenant, &loc, &started.form).await,
        ..Extras::default()
    };
    started_response_with(
        &state,
        &tenant,
        &loc,
        &started,
        &nav,
        StatusCode::OK,
        &extras,
    )
}

/// The answer to a `GET` whose `request=` cannot be continued (unknown, expired, malformed or
/// another tenant's; [`StaleRequest`] says which only as "unknown"): the `flow_expired` error
/// page (400) with a way to start again at the plain sign-in page and no credential form. The
/// id is never echoed into a link.
pub(super) fn stale_request_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
) -> Response {
    let mut page = PageContext::for_tenant(state, tenant, loc, "title.error");
    page.links.login = Some(NavContext::none().url(tenant, loc, UiPage::Login));
    let ctx = minijinja::context! {
        page => page.into_value(),
        status => StatusCode::BAD_REQUEST.as_u16(),
        error_key => "flow_expired",
        heading => state.renderer().text(loc, "nav.request_expired"),
        detail => Value::from(()),
    };
    no_store(render_page(
        state,
        Some(tenant),
        loc,
        "error.html",
        ctx,
        StatusCode::BAD_REQUEST,
        CookieJar::new(),
    ))
}

/// The request's `login_hint`, normalised, if it is an email address (OIDC Core §3.1.2.1: a
/// hint, never trusted; anything else is ignored).
async fn login_hint(
    state: &AppState,
    tenant: &ResolvedTenant,
    request: Option<AuthRequestId>,
) -> Option<String> {
    let request = state
        .storage()
        .grants()
        .get_authorization_request(tenant.tenant.id, request?, state.clock().now())
        .await
        .inspect_err(
            |e| tracing::warn!(error = %e, "loading the request for its login_hint failed"),
        )
        .ok()??;
    normalize_email(request.params.login_hint.as_deref()?.trim()).ok()
}

/// The locale of a page that may continue an authorization request: an explicit `ui_locales`
/// query parameter wins; otherwise the request's stored `ui_locales`, then `Accept-Language`
/// and the tenant default ([`locale_for_request`]). An unknown or expired request is no input.
pub(super) async fn page_locale(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: RequestLocale,
    headers: &HeaderMap,
    request: Option<AuthRequestId>,
) -> Locale {
    if locale.0.ui_locales.is_some() {
        return locale.0;
    }
    let Some(id) = request else {
        return locale.0;
    };
    match state
        .storage()
        .grants()
        .get_authorization_request(tenant.tenant.id, id, state.clock().now())
        .await
    {
        Ok(Some(r)) => locale_for_request(state, tenant, headers, Some(&r.params)),
        Ok(None) => locale.0,
        Err(e) => {
            tracing::warn!(error = %e, "loading the authorization request for its ui_locales failed");
            locale.0
        }
    }
}

/// `POST /ui/login?flow=`: email and password, behind the brute-force gate (module docs).
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let identifier = form.identifier.clone().unwrap_or_default();
    let throttle = Throttle::Password {
        identifier: &identifier,
        ip,
        captcha: CaptchaAnswer {
            turnstile: form.turnstile_response.as_deref(),
            hcaptcha: form.hcaptcha_response.as_deref(),
        },
    };
    let input = FlowInput::Login {
        identifier: identifier.clone(),
        password: form.password.clone().unwrap_or_default(),
    };
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let outcome =
        flow_driver::submit(&state, &tenant, &ctx, flow_id, binding, throttle, input).await;
    match outcome {
        DriveOutcome::Flow {
            outcome,
            attempt,
            captcha,
        } => {
            let mut extras = Extras {
                captcha: tenant.tenant.settings.captcha.as_ref().filter(|_| captcha),
                ..Extras::default()
            };
            if let Some(AuthAttempt::PasswordSucceeded { user, .. }) = attempt {
                extras.factor_token = factor_token(&state, &tenant, flow_id, user);
            }
            if let FlowOutcome::Render(form) = &outcome {
                extras.upstream = identify_buttons(&state, &tenant, &loc, form).await;
            }
            outcome_response_with(&state, &tenant, &loc, &nav, outcome, &extras)
        }
        other => sign_in_gate_page(&state, &tenant, &loc, &nav, other).await,
    }
}

/// The page of a sign-in submission the brute-force gate answered (lock, CAPTCHA demand) or the
/// driver refused, shared by the password and passkey sign-in. The sign-in form keeps its
/// upstream buttons, so a locked or CAPTCHA-gated user still sees the other ways to sign in.
async fn sign_in_gate_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    outcome: DriveOutcome,
) -> Response {
    match outcome {
        DriveOutcome::Flow { outcome, .. } => {
            let mut extras = Extras::default();
            if let FlowOutcome::Render(form) = &outcome {
                extras.upstream = identify_buttons(state, tenant, loc, form).await;
            }
            outcome_response_with(state, tenant, loc, nav, outcome, &extras)
        }
        DriveOutcome::Locked {
            form, retry_after, ..
        } => {
            let extras = Extras {
                upstream: identify_buttons(state, tenant, loc, &form).await,
                ..Extras::default()
            };
            locked_page_with(state, tenant, loc, nav, form, retry_after, extras)
        }
        DriveOutcome::CaptchaRejected { form } => {
            // The widget goes with the password form only: the email-first form (routed
            // tenants) is not gated, and the password step after it carries the widget
            // (`flow_driver::identify`).
            let extras = Extras {
                captcha: tenant
                    .tenant
                    .settings
                    .captcha
                    .as_ref()
                    .filter(|_| form.id == "login"),
                upstream: identify_buttons(state, tenant, loc, &form).await,
                ..Extras::default()
            };
            render_tenant_form_with(
                state,
                tenant,
                loc,
                &form,
                nav,
                StatusCode::BAD_REQUEST,
                CookieJar::new(),
                &extras,
            )
        }
        DriveOutcome::Throttled { retry_after } => {
            too_many_requests(state, Some(tenant), Surface::Browser, retry_after)
        }
        DriveOutcome::Rejected(r) => rejection_page(state, tenant, loc, r),
    }
}

/// The page of a refused step: the `csrf` page (403) for a binding failure, the error page
/// otherwise.
pub(super) fn rejection_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    rejection: DriveRejection,
) -> Response {
    match rejection {
        DriveRejection::Binding => csrf_page(state, Some(tenant), loc),
        DriveRejection::Failed(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// `POST /ui/login/identify?flow=`: the email-first page (`identifier`) or the single-sign-on
/// choice (`choice` = `sso`, `password` or `change`). No account is looked up, so there is no
/// brute-force gate: the answer depends on the email's domain only. When the answer is the
/// password step and the email's brute-force tier asks for a CAPTCHA, the page carries the
/// widget, so a user sent back to the email-first page by a CAPTCHA demand can complete it.
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn identify(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let input = match form.choice.as_deref() {
        Some("sso") => IdentifyInput::Sso,
        Some("password") => IdentifyInput::Password,
        Some("change") => IdentifyInput::Change,
        _ => IdentifyInput::Email(form.identifier.clone().unwrap_or_default()),
    };
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    match flow_driver::identify(&state, &tenant, &ctx, flow_id, &binding, input, ip).await {
        Ok(Identified::Done { outcome, captcha }) => {
            let mut extras = Extras::default();
            if let FlowOutcome::Render(f) = outcome.as_ref() {
                extras.upstream = identify_buttons(&state, &tenant, &loc, f).await;
                extras.captcha = tenant.tenant.settings.captcha.as_ref().filter(|_| captcha);
            }
            outcome_response_with(&state, &tenant, &loc, &nav, *outcome, &extras)
        }
        Ok(Identified::StartIdp(idp)) => {
            let current = match current_browser_session(&state, &tenant, &jar).await {
                Ok(s) => s,
                Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
            };
            let cookie = binding.flow_token(&state, &tenant);
            let binding = SettingsBinding {
                flow_id,
                cookie_token: cookie.as_deref(),
                csrf_token: csrf,
            };
            idp_redirect(
                &state,
                &tenant,
                &loc,
                &ctx,
                &binding,
                &idp,
                current.as_ref(),
                CookieJar::new(),
            )
            .await
        }
        Err(DriveRejection::Binding) => csrf_page(&state, Some(&tenant), &loc),
        Err(DriveRejection::Failed(CoreError::InvalidRequest(_))) => {
            restart_login_in(&state, &tenant, &loc, &nav).await
        }
        Err(DriveRejection::Failed(e)) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// Starts the sign-in at the org IdP home-realm discovery chose (`start_idp`: the same starts as
/// `POST /ui/login/upstream/{slug}` and `POST /ui/login/saml/{slug}/start`) and answers 303 to
/// the IdP with the binding cookie, added to `jar`.
#[expect(
    clippy::too_many_arguments,
    reason = "threads the request's locale, context and binding"
)]
async fn idp_redirect(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    ctx: &RequestContext,
    binding: &SettingsBinding<'_>,
    idp: &IdpStart,
    current: Option<&BrowserSession>,
    jar: CookieJar,
) -> Response {
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
    let cx = &FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx,
    };
    let flows = state.ui_flow_service();
    let accounts = state.ui_account_service();
    let xml = state.saml_xml();
    let upstream = UpstreamService {
        flows: &flows,
        accounts: &accounts,
        client: state.upstream(),
    };
    let saml = SamlService {
        flows: &flows,
        accounts: &accounts,
        client: state.upstream(),
        saml_xml: xml.as_ref(),
        enabled: state.config().saml_experimental,
    };
    match start_idp(idp, &upstream, &saml, cx, binding, current).await {
        Ok(StartResult::Redirect(r)) => {
            let Ok(location) = HeaderValue::from_str(&r.url) else {
                return core_error_page_in(
                    state,
                    Some(tenant),
                    loc,
                    &CoreError::Internal("unusable identity provider URL".into()),
                );
            };
            let jar = jar.add(
                state
                    .cookies()
                    .upstream_binding_cookie(&tenant.tenant, r.binding_cookie.expose_secret()),
            );
            (
                StatusCode::SEE_OTHER,
                jar,
                [
                    (header::LOCATION, location),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
            )
                .into_response()
        }
        Ok(StartResult::Done(outcome)) => {
            super::upstream::outcome_page(state, tenant, loc, *outcome, false).await
        }
        Err(CoreError::Forbidden) => csrf_page(state, Some(tenant), loc),
        Err(CoreError::InvalidRequest(_) | CoreError::NotFound | CoreError::FeatureDisabled(_)) => {
            let nav = NavContext::from_flow(state, tenant, binding.flow_id).await;
            restart_login_in(state, tenant, loc, &nav).await
        }
        Err(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// The upstream sign-in buttons of a sign-in form ([`super::upstream::upstream_buttons`]: only
/// the identify step lists them). Every page that re-renders the sign-in form passes them, so a
/// locked or CAPTCHA-gated user still sees the other ways to sign in.
async fn identify_buttons(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    form: &FormDescription,
) -> super::upstream::SignInChoices {
    super::upstream::upstream_buttons(state, tenant, loc, form).await
}

/// Message key of a locked sign-in or second factor.
pub(super) const TOO_MANY_ATTEMPTS: &str = "login.too_many_attempts";

/// `Retry-After` in whole seconds, rounded up, at least 1 (the rounding of the limiter's 429).
pub(super) fn whole_seconds(d: Duration) -> u64 {
    (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
}

/// "Too many attempts. Try again in N seconds." for a lock of `retry_after` (argument
/// `seconds`, a Fluent plural).
pub(super) fn too_many_attempts(retry_after: Duration) -> FormMessage {
    FormMessage::error(TOO_MANY_ATTEMPTS).with_arg("seconds", whole_seconds(retry_after))
}

/// A form page answering a locked attempt: 429 with `Retry-After`, `Cache-Control: no-store`
/// and the lock message in place of the form's messages. The form stays usable once the lock
/// window has passed.
pub(super) fn locked_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    form: FormDescription,
    retry_after: Duration,
    factor_token: Option<String>,
) -> Response {
    let extras = Extras {
        factor_token,
        ..Extras::default()
    };
    locked_page_with(state, tenant, loc, nav, form, retry_after, extras)
}

/// [`locked_page`] with sign-in page extras (the sign-in form's upstream buttons).
fn locked_page_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    mut form: FormDescription,
    retry_after: Duration,
    extras: Extras<'_>,
) -> Response {
    form.messages = vec![too_many_attempts(retry_after)];
    let mut resp = render_tenant_form_with(
        state,
        tenant,
        loc,
        &form,
        nav,
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

/// The second-factor binding token for `user` in `flow` (see [`super::mfa`]); `None` (logged)
/// if sealing fails, in which case the second-factor POST restarts the sign-in.
pub(super) fn factor_token(
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
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return json_error(rejection_status(&e), "invalid_request"),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return json_error(StatusCode::FORBIDDEN, "csrf");
    };
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    match flow_driver::passkey_options(&state, &tenant, flow_id, &binding, PasskeyStep::SignIn)
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
        Err(DriveRejection::Binding) => json_error(StatusCode::FORBIDDEN, "csrf"),
        Err(DriveRejection::Failed(CoreError::InvalidRequest(_))) => {
            json_error(StatusCode::BAD_REQUEST, "login.passkey_failed")
        }
        Err(DriveRejection::Failed(e)) => {
            tracing::error!(error = %e, "creating passkey request options failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// `POST /ui/login/passkey?flow=`: the assertion from webauthn.js (`response`). Every failure is
/// the sign-in form with `login.passkey_failed` (400). Failures are counted per client IP only
/// (a passkey names no identifier before it is verified).
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn passkey_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let input = FlowInput::PasskeyAssertion {
        response_json: form.response.clone().unwrap_or_default(),
    };
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let outcome = flow_driver::submit(
        &state,
        &tenant,
        &ctx,
        flow_id,
        binding,
        Throttle::Passkey { ip },
        input,
    )
    .await;
    sign_in_gate_page(&state, &tenant, &loc, &nav, outcome).await
}

// ---------------------------------------------------------------------------------------------
// In-flow passkeys: enrolment (MFA policy `required`) and the second-factor step
// ---------------------------------------------------------------------------------------------

/// The message key of a refused in-flow passkey ceremony (also the JSON error of a refused
/// options request).
fn passkey_failed_key(step: InFlowPasskey) -> &'static str {
    match step {
        InFlowPasskey::Enrolment => PASSKEY_ENROLMENT_FAILED,
        InFlowPasskey::SecondFactor => SECOND_FACTOR_PASSKEY_FAILED,
    }
}

/// `POST /ui/login/enroll/passkey/start?flow=`: creation options for webauthn.js (JSON) for the
/// user of the flow's enrolment step. Bound to the flow (cookie + `csrf_token` field). Errors
/// are JSON `{"error": key}`: 403 `csrf`, 400 `mfa_enroll.passkey_failed` (expired flow, not in
/// the enrolment step), 500.
async fn passkey_enrolment_start(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    flow_passkey_options(&state, &tenant, &jar, &q, form, InFlowPasskey::Enrolment).await
}

/// `POST /ui/login/second-factor/passkey/start?flow=`: discoverable request options for
/// webauthn.js (JSON) at the second-factor step of a user with a passkey. Bound to the flow
/// (cookie + `csrf_token` field). Errors are JSON `{"error": key}`: 403 `csrf`, 400
/// `second_factor.passkey_failed` (expired flow, not in a second-factor step that offers a
/// passkey), 500.
async fn passkey_second_factor_start(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    flow_passkey_options(&state, &tenant, &jar, &q, form, InFlowPasskey::SecondFactor).await
}

async fn flow_passkey_options(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
    q: &UiQuery,
    form: Result<Form<UiForm>, FormRejection>,
    which: InFlowPasskey,
) -> Response {
    let json_error = |status: StatusCode, key: &str| {
        no_store((status, axum::Json(serde_json::json!({ "error": key }))).into_response())
    };
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return json_error(rejection_status(&e), "invalid_request"),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return json_error(StatusCode::FORBIDDEN, "csrf");
    };
    let binding = FlowBinding::Cookie { jar, csrf };
    let step = match which {
        InFlowPasskey::Enrolment => PasskeyStep::Enrolment,
        InFlowPasskey::SecondFactor => PasskeyStep::SecondFactor,
    };
    match flow_driver::passkey_options(state, tenant, flow_id, &binding, step).await {
        Ok(options) => no_store(
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                options,
            )
                .into_response(),
        ),
        Err(DriveRejection::Binding) => json_error(StatusCode::FORBIDDEN, "csrf"),
        Err(DriveRejection::Failed(CoreError::InvalidRequest(_))) => {
            json_error(StatusCode::BAD_REQUEST, passkey_failed_key(which))
        }
        Err(DriveRejection::Failed(e)) => {
            tracing::error!(error = %e, "creating in-flow passkey options failed");
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// `POST /ui/login/enroll/passkey/finish?flow=`: the registration response from webauthn.js
/// (`response`). Success signs in (or upgrades the step-up session) like a passkey sign-in; every
/// failure is the enrolment page with `mfa_enroll.passkey_failed` (400), the authenticator-app
/// choice still on it. The posted `factor_token` is handed back to that page unchanged (the
/// second-factor route checks it).
async fn passkey_enrolment_finish(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    flow_passkey_finish(
        &state,
        &tenant,
        &loc,
        &ctx,
        &jar,
        &q,
        form,
        InFlowPasskey::Enrolment,
    )
    .await
}

/// `POST /ui/login/second-factor/passkey/finish?flow=`: the assertion from webauthn.js
/// (`response`) at the second-factor step. Success signs in (or upgrades the step-up session)
/// like a passkey sign-in; every failure is the second-factor page with
/// `second_factor.passkey_failed` (400), with no session. The posted `factor_token` is handed
/// back to that page unchanged (the TOTP route checks it).
async fn passkey_second_factor_finish(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    flow_passkey_finish(
        &state,
        &tenant,
        &loc,
        &ctx,
        &jar,
        &q,
        form,
        InFlowPasskey::SecondFactor,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the two finish routes share one body; the extractors travel with it"
)]
async fn flow_passkey_finish(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    ctx: &RequestContext,
    jar: &CookieJar,
    q: &UiQuery,
    form: Result<Form<UiForm>, FormRejection>,
    which: InFlowPasskey,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(state, Some(tenant), loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(state, Some(tenant), loc);
    };
    let nav = NavContext::from_flow(state, tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar, csrf };
    let response = form.response.as_deref().unwrap_or_default();
    let result =
        match flow_driver::passkey_finish(state, tenant, ctx, flow_id, &binding, which, response)
            .await
        {
            Ok(r) => r,
            Err(r) => return rejection_page(state, tenant, loc, r),
        };
    let extras = Extras {
        factor_token: form.factor_token.clone().filter(|t| !t.is_empty()),
        ..Extras::default()
    };
    outcome_response_with(state, tenant, loc, &nav, result.outcome, &extras)
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
    /// Where the sign-in returns without an authorization request (`/ui/login?return_to=`).
    /// Only an allowlisted target is used ([`parse_return_target`]); anything else is ignored.
    pub(super) return_to: Option<String>,
}

/// A malformed query value: the page answers with an error page instead of a form.
pub(super) struct BadQuery;

impl BadQuery {
    pub(super) fn into_response(
        self,
        state: &AppState,
        tenant: Option<&ResolvedTenant>,
        loc: &Locale,
    ) -> Response {
        error_page_in(
            state,
            tenant,
            loc,
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

    /// The `return_to` parameter if it is an allowlisted target; anything else is ignored
    /// silently (no error page, the value is never logged).
    pub(super) fn return_target(&self) -> Option<ReturnTarget> {
        self.return_to.as_deref().and_then(parse_return_target)
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
    /// The single-sign-on choice of the email-first sign-in (`sso`, `password`, `change`).
    pub(super) choice: Option<String>,
    /// Turnstile widget response.
    #[serde(rename = "cf-turnstile-response")]
    pub(super) turnstile_response: Option<String>,
    /// hCaptcha widget response.
    #[serde(rename = "h-captcha-response")]
    pub(super) hcaptcha_response: Option<String>,
}

/// An invalid form submission or page request (400).
pub(super) fn bad_form(state: &AppState, tenant: &ResolvedTenant, loc: &Locale) -> Response {
    error_page_in(
        state,
        Some(tenant),
        loc,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "",
    )
}

/// The page for a form body the extractor refused: 413 when the body was over the request body
/// limit (also when it was streamed without `Content-Length` and refused while read), else 400.
/// Every page handler with a `Result<Form<_>, FormRejection>` answers its rejection here.
pub(super) fn rejected_form(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
    rejection: &FormRejection,
) -> Response {
    error_page_in(
        state,
        tenant,
        loc,
        rejection_status(rejection),
        "invalid_request",
        "",
    )
}

/// The status for a refused form body: 413 over the body limit, else 400. The JSON-answering
/// form endpoints (passkey ceremonies) use it directly; pages go through [`rejected_form`].
pub(super) fn rejection_status(rejection: &FormRejection) -> StatusCode {
    if rejection_is_too_large(rejection) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// The `Display` text of `http_body_util::LengthLimitError`, the error the body limit layers
/// (`DefaultBodyLimit`, `RequestBodyLimitLayer`) put at the bottom of a refused body read. The
/// crate is not a normal dependency here, so it is matched by its message;
/// `tests/security_body_limit.rs` breaks if an upgrade changes it.
const LENGTH_LIMIT_EXCEEDED: &str = "length limit exceeded";

/// `true` if an extractor rejection (form or JSON body) was caused by the request body limit.
/// The single rejection-to-413 check for the UI form pages ([`rejected_form`]) and the admin
/// API's JSON bodies (`admin::auth::AdminJson`).
pub(crate) fn rejection_is_too_large(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(e) = current {
        if e.to_string() == LENGTH_LIMIT_EXCEEDED {
            return true;
        }
        current = e.source();
    }
    false
}

/// The CSRF rejection page (missing or wrong token, missing flow cookie, unbound submission).
pub(super) fn csrf_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
) -> Response {
    error_page_in(state, tenant, loc, StatusCode::FORBIDDEN, "csrf", "")
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

/// Template and title message key of a form, by form id (themes/default/README.md).
pub(super) fn form_template(form_id: &str) -> (&'static str, &'static str) {
    match form_id {
        "login" => ("login.html", "title.login"),
        IDENTIFY_FORM_ID | SSO_CHOICE_FORM_ID => ("login_identify.html", "title.login"),
        UPSTREAM_LINK_FORM_ID => ("upstream_link.html", "title.upstream_link"),
        SECOND_FACTOR_FORM_ID => ("second_factor.html", "title.second_factor"),
        ENROLL_FORM_ID => ("mfa_enroll.html", "title.mfa_enroll"),
        EMAIL_CODE_FORM_ID => ("email_code.html", "title.email_code"),
        "registration" => ("registration.html", "title.registration"),
        "verification" => ("verification.html", "title.verification"),
        "recovery" => ("recovery.html", "title.recovery"),
        "recovery-reset" => ("recovery_reset.html", "title.recovery_reset"),
        _ => ("setup.html", "title.setup"),
    }
}

/// Renders a form page with the given page context; the form is localized in `loc`.
pub(super) fn render_form(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
    page: PageContext,
    form: &FormDescription,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let (template, _) = form_template(&form.id);
    let mut form = form.clone();
    state.renderer().localize_form(loc, &mut form);
    form.action = carry_ui_locales(&form.action, loc);
    let ctx = minijinja::context! {
        page => page.into_value(),
        form => Value::from(Serde(&form)),
    };
    render_page(state, tenant, loc, template, ctx, status, jar)
}

fn render_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
    template: &str,
    ctx: Value,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    match state.renderer().page(template, ctx) {
        Ok(html) => (status, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, template, "rendering a form page failed");
            core_error_page_in(state, tenant, loc, &CoreError::Internal("render".into()))
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
    /// The pending authenticator-app secret of the enrolment form.
    pub(super) totp: Option<&'a TotpEnrolment>,
    /// Upstream choices of the sign-in form ([`super::upstream::upstream_buttons`]).
    pub(super) upstream: super::upstream::SignInChoices,
}

/// URLs of a passkey form (webauthn.js `data-options-url` and form action): the sign-in form,
/// the enrolment page's registration form, or the second-factor page's assertion form.
#[derive(Serialize)]
struct PasskeyView {
    options_url: String,
    action: String,
}

/// The "Email me a sign-in code" form of the sign-in page.
#[derive(Serialize)]
struct EmailCodeView {
    action: String,
    /// Prefilled address (the identifier field's value: echoed input or `login_hint`).
    value: Option<String>,
    /// Link confirmation whose matching account may not be revealed: a plain "Email me a code"
    /// button without an address field (the code goes to the matching account's verified
    /// address, if any, which is never shown).
    hidden: bool,
}

/// The email entered on the email-first page, shown read-only on the password step and the
/// single-sign-on choice, with the "change" form (posts `choice=change`).
#[derive(Serialize)]
struct ChangeEmailView {
    action: String,
    email: String,
}

/// Values of the `captcha.html` partial.
#[derive(Serialize)]
struct CaptchaView {
    provider: &'static str,
    site_key: String,
}

/// The flow id of a bound form (`…?flow={id}` action, possibly followed by more parameters).
pub(super) fn flow_of(form: &FormDescription) -> Option<FlowId> {
    let (_, rest) = form.action.rsplit_once("?flow=")?;
    let id = rest.split('&').next().unwrap_or_default();
    uuid::Uuid::parse_str(id).ok().map(FlowId)
}

/// Renders a tenant form page with sign-in extras. The sign-in form gets the passkey form (when
/// the issuer can be a WebAuthn relying party) and the CAPTCHA widget when asked for; the
/// second-factor form posts to `/ui/login/second-factor` and carries the binding token. Labels
/// and messages are localized in `loc`; an explicit `ui_locales` is carried on the actions.
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's locale and binding"
)]
pub(super) fn render_tenant_form_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    form: &FormDescription,
    nav: &NavContext,
    status: StatusCode,
    jar: CookieJar,
    extras: &Extras<'_>,
) -> Response {
    let (template, title) = form_template(&form.id);
    let mut page = PageContext::for_tenant(state, tenant, loc, title);
    page.links = nav.links(tenant, loc, &form.id);
    let base = ui_base(tenant);
    // The sign-in choices come from the one list of methods (`flow_driver::login_methods`).
    let methods = login_methods(form, tenant, &extras.upstream);
    let has = |m: &LoginMethod| methods.contains(m);
    let upstream: Vec<super::upstream::UpstreamButton> = methods
        .iter()
        .filter_map(|m| match m {
            LoginMethod::Upstream { slug, name } => extras
                .upstream
                .buttons
                .iter()
                .find(|b| &b.slug == slug)
                .map(|b| super::upstream::UpstreamButton {
                    slug: slug.clone(),
                    name: name.clone(),
                    action: b.action.clone(),
                }),
            _ => None,
        })
        .collect();
    let mut form = form.clone();
    state.renderer().localize_form(loc, &mut form);
    let mut passkey = None;
    let mut passkey_enroll = None;
    let mut passkey_second_factor = None;
    let mut captcha = None;
    let mut factor_token = None;
    let mut qr_svg = None;
    let mut secret_groups = None;
    let mut email_code = None;
    let mut resend_action = None;
    let mut change_email = None;
    match (form.id.as_str(), flow_of(&form)) {
        (EMAIL_CODE_FORM_ID, Some(flow)) => {
            factor_token = extras.factor_token.clone();
            resend_action = Some(carry_ui_locales(
                &format!("{base}/login/email-code?flow={flow}"),
                loc,
            ));
        }
        ("login" | UPSTREAM_LINK_FORM_ID | IDENTIFY_FORM_ID, Some(flow)) => {
            if has(&LoginMethod::Passkey) {
                passkey = Some(PasskeyView {
                    options_url: format!("{base}/login/passkey/options?flow={flow}"),
                    action: carry_ui_locales(&format!("{base}/login/passkey?flow={flow}"), loc),
                });
            }
            captcha = extras.captcha;
        }
        (SECOND_FACTOR_FORM_ID, Some(flow)) => {
            form.action = format!("{base}/login/second-factor?flow={flow}");
            factor_token = extras.factor_token.clone();
            if form
                .fields
                .iter()
                .any(|f| f.name == SECOND_FACTOR_PASSKEY_FIELD)
                && tenant_relying_party(tenant).is_ok()
            {
                passkey_second_factor = Some(PasskeyView {
                    options_url: format!("{base}/login/second-factor/passkey/start?flow={flow}"),
                    action: carry_ui_locales(
                        &format!("{base}/login/second-factor/passkey/finish?flow={flow}"),
                        loc,
                    ),
                });
            }
        }
        (ENROLL_FORM_ID, Some(flow)) => {
            form.action = format!("{base}/login/second-factor?flow={flow}");
            factor_token = extras.factor_token.clone();
            if tenant_relying_party(tenant).is_ok() {
                passkey_enroll = Some(PasskeyView {
                    options_url: format!("{base}/login/enroll/passkey/start?flow={flow}"),
                    action: carry_ui_locales(
                        &format!("{base}/login/enroll/passkey/finish?flow={flow}"),
                        loc,
                    ),
                });
            }
            if let Some(totp) = extras.totp {
                match crate::adapters::qr::qr_svg(totp.otpauth_uri.expose_secret()) {
                    Ok(svg) => qr_svg = Some(Value::from_safe_string(svg)),
                    Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
                }
                secret_groups = Some(grouped(totp.secret_base32.expose_secret()));
            }
        }
        _ => {}
    }
    if (has(&LoginMethod::EmailCode) || has(&LoginMethod::MagicLink))
        && let Some(flow) = flow_of(&form)
    {
        let hidden = form.id == UPSTREAM_LINK_FORM_ID && extras.upstream.link_email_hidden;
        email_code = Some(EmailCodeView {
            action: carry_ui_locales(&format!("{base}/login/email-code?flow={flow}"), loc),
            value: form
                .fields
                .iter()
                .find(|f| f.name == "identifier" && !hidden)
                .and_then(|f| f.value.clone()),
            hidden,
        });
    }
    // After the email page the address is fixed (hidden field): show it with a way back.
    if matches!(form.id.as_str(), "login" | SSO_CHOICE_FORM_ID)
        && let Some(flow) = flow_of(&form)
        && let Some(email) = form
            .fields
            .iter()
            .find(|f| f.name == "identifier" && f.kind == FieldKind::Hidden)
            .and_then(|f| f.value.clone())
    {
        change_email = Some(ChangeEmailView {
            action: carry_ui_locales(&format!("{base}/login/identify?flow={flow}"), loc),
            email,
        });
    }
    // Link confirmation: the way out when the page cannot confirm (sign in another way, then
    // connect the provider from the account page).
    let account_linked = (form.id == UPSTREAM_LINK_FORM_ID)
        .then(|| nav.url(tenant, loc, UiPage::Account(AccountSection::Linked)));
    form.action = carry_ui_locales(&form.action, loc);
    let ctx = minijinja::context! {
        page => page.into_value(),
        form => Value::from(Serde(&form)),
        account_linked => account_linked,
        change_email => Value::from(Serde(&change_email)),
        passkey => Value::from(Serde(&passkey)),
        passkey_enroll => Value::from(Serde(&passkey_enroll)),
        passkey_second_factor => Value::from(Serde(&passkey_second_factor)),
        captcha => Value::from(Serde(captcha.map(|c| CaptchaView {
            provider: c.provider.as_str(),
            site_key: c.site_key.clone(),
        }))),
        factor_token => factor_token,
        enroll => qr_svg.is_some(),
        qr_svg => qr_svg,
        secret_groups => secret_groups,
        upstream => Value::from(Serde(&upstream)),
        email_code => Value::from(Serde(&email_code)),
        resend_action => resend_action,
    };
    let mut resp = render_page(state, Some(tenant), loc, template, ctx, status, jar);
    let csp = match (captcha, &passkey) {
        (Some(c), _) => HeaderValue::from_str(&captcha_csp(c.provider).header_value()).ok(),
        (None, Some(_)) => Some(HeaderValue::from_static(LOGIN_CSP)),
        // The enrolment page (inline QR code, webauthn.js for the passkey choice) and the
        // second-factor page with a passkey option need no more than the account pages' policy.
        (None, None) if form.id == ENROLL_FORM_ID || passkey_second_factor.is_some() => {
            Some(HeaderValue::from_static(LOGIN_CSP))
        }
        (None, None) => None,
    };
    if let Some(csp) = csp {
        resp.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    resp
}

/// Message key of the heading of a message page, by body message key.
fn message_heading(key: &str) -> &'static str {
    match key {
        "recovery.sent" | "registration.check_email" => "heading.check_email",
        "recovery.done" => "heading.password_changed",
        "verification.done" => "heading.email_confirmed",
        "registration.disabled" => "heading.registration_unavailable",
        OTHER_BROWSER | LINK_INVALID => "title.magic_link",
        SIGNED_IN => "heading.signed_in",
        _ => "heading.done",
    }
}

/// Message key of the page shown after a login that is not bound to an authorization request.
/// It is a page, not a redirect (a stable contract); its way forward is the account page and
/// the sign-out form ([`NavContext::way_forward`]).
pub(super) const SIGNED_IN: &str = "login.signed_in";

/// Message key of the page after a registration that must confirm its address.
const CHECK_EMAIL: &str = "registration.check_email";

/// Renders `message.html` (200) with the way forward of `nav` ([`NavContext::way_forward`]):
/// "Continue to <app>" while the flow's request is live, the account page and sign-out form
/// after a sign-in, otherwise the tenant's sign-in page.
pub(super) fn message_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    key: &str,
    nav: &NavContext,
    jar: CookieJar,
) -> Response {
    message_page_with(state, tenant, loc, key, nav, None, jar)
}

/// [`message_page`] naming the address a confirmation email was sent to (`sent_to`: the
/// address the user just typed in this browser, so nothing is revealed).
fn message_page_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    key: &str,
    nav: &NavContext,
    sent_to: Option<&str>,
    jar: CookieJar,
) -> Response {
    let mut page = PageContext::for_tenant(state, tenant, loc, message_heading(key));
    page.links = nav
        .way_forward(state, tenant, loc, key == SIGNED_IN)
        .into_links();
    let heading = page.title.clone();
    let ctx = minijinja::context! {
        page => page.into_value(),
        heading => heading,
        body_key => key,
        body => state.renderer().text(loc, key),
        sent_to => sent_to,
    };
    match state.renderer().page("message.html", ctx) {
        Ok(html) => (StatusCode::OK, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the message page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

/// Response for a newly started flow: sets the flow cookie and renders its form.
fn started_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    started: &StartedFlow,
    nav: &NavContext,
    status: StatusCode,
) -> Response {
    started_response_with(state, tenant, loc, started, nav, status, &Extras::default())
}

/// [`started_response`] with sign-in page extras (step-up binding token, enrolment secret).
pub(super) fn started_response_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    started: &StartedFlow,
    nav: &NavContext,
    status: StatusCode,
    extras: &Extras<'_>,
) -> Response {
    started_response_in(
        state,
        tenant,
        loc,
        started,
        nav,
        status,
        extras,
        CookieJar::new(),
    )
}

/// [`started_response_with`] adding the flow cookie to `jar` (which may carry other cookies).
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's locale and binding"
)]
pub(super) fn started_response_in(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    started: &StartedFlow,
    nav: &NavContext,
    status: StatusCode,
    extras: &Extras<'_>,
    jar: CookieJar,
) -> Response {
    let jar = jar.add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_tenant_form_with(state, tenant, loc, &started.form, nav, status, jar, extras)
}

/// `GET` of a self-service page: starts a flow of `kind` for the live request of `nav` and
/// renders its form.
pub(super) async fn start_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    kind: FlowKind,
    nav: &NavContext,
    token: Option<String>,
) -> Response {
    let request = nav.request().map(|r| r.id);
    match flow_driver::start(state, tenant, kind, request, token).await {
        Ok(started) => started_response(state, tenant, loc, &started, nav, StatusCode::OK),
        Err(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// A new sign-in flow with the `flow.expired` message (400) for the live request of `nav` (the
/// request of the flow that could not continue, so "Start over" keeps the app): the answer to a
/// submission that cannot continue its flow (for example a second-factor POST without a valid
/// binding token).
pub(super) async fn restart_login_in(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
) -> Response {
    let request = nav.request().map(|r| r.id);
    match flow_driver::start(state, tenant, FlowKind::Login, request, None).await {
        Ok(mut started) => {
            started
                .form
                .messages
                .insert(0, FormMessage::error("flow.expired"));
            started_response(state, tenant, loc, &started, nav, StatusCode::BAD_REQUEST)
        }
        Err(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// [`restart_login_in`] without a flow context, for callers that have no flow to read the
/// request from.
pub(super) async fn restart_login(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
) -> Response {
    restart_login_in(state, tenant, loc, &NavContext::none()).await
}

/// The caller's active session (from the session cookie), if any.
pub(super) async fn current_browser_session(
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

/// The tenant's WebAuthn relying party. An issuer that cannot be one is an error only for the
/// passkey steps (the flow service propagates it there).
pub(super) fn tenant_relying_party(tenant: &ResolvedTenant) -> Result<RelyingParty, CoreError> {
    relying_party(&tenant.tenant, &tenant.issuer)
}

/// `POST` of a self-service page that is not an authentication attempt (registration,
/// recovery, verification): binds the submission to its flow, runs it through the driver and
/// maps the outcome to a response.
#[expect(
    clippy::too_many_arguments,
    reason = "threads the request's locale, context and binding"
)]
pub(super) async fn submit_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    ctx: &RequestContext,
    jar: &CookieJar,
    query: &UiQuery,
    form: &UiForm,
    input: FlowInput,
) -> Response {
    let (Some(flow_id), Some(csrf)) = (query.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(state, Some(tenant), loc);
    };
    let nav = NavContext::from_flow(state, tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar, csrf };
    let outcome =
        flow_driver::submit(state, tenant, ctx, flow_id, binding, Throttle::None, input).await;
    // A registration that must confirm its address names the address it was sent to.
    if let DriveOutcome::Flow {
        outcome: FlowOutcome::Message { key: CHECK_EMAIL },
        ..
    } = &outcome
        && let Some(email) = form
            .email
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
    {
        let shown = normalize_email(email).unwrap_or_else(|_| email.to_owned());
        let jar = CookieJar::new().add(state.cookies().clear_flow(&tenant.tenant));
        return message_page_with(state, tenant, loc, CHECK_EMAIL, &nav, Some(&shown), jar);
    }
    drive_response(state, tenant, loc, &nav, outcome, &Extras::default(), None)
}

/// Encodes a [`DriveOutcome`] of a page that shows no sign-in extras of its own beyond
/// `extras` (the factor token of the email-code and second-factor pages). `locked_token` is the
/// factor token a locked form keeps.
pub(super) fn drive_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    outcome: DriveOutcome,
    extras: &Extras<'_>,
    locked_token: Option<String>,
) -> Response {
    match outcome {
        DriveOutcome::Flow { outcome, .. } => {
            outcome_response_with(state, tenant, loc, nav, outcome, extras)
        }
        DriveOutcome::Locked {
            form, retry_after, ..
        } => locked_page(state, tenant, loc, nav, form, retry_after, locked_token),
        DriveOutcome::Throttled { retry_after } => {
            too_many_requests(state, Some(tenant), Surface::Browser, retry_after)
        }
        DriveOutcome::CaptchaRejected { form } => render_tenant_form_with(
            state,
            tenant,
            loc,
            &form,
            nav,
            StatusCode::BAD_REQUEST,
            CookieJar::new(),
            &Extras::default(),
        ),
        DriveOutcome::Rejected(r) => rejection_page(state, tenant, loc, r),
    }
}

/// After a sign-in or step-up: continue the authorization request (303), return to the login's
/// allowlisted return target on the tenant's own UI origin (303), or show the signed-in page.
/// Recovery codes of a second factor enrolled in the flow are shown once first, with a link that
/// continues.
pub(super) fn signed_in_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    continue_to: Option<Continue>,
    recovery_codes: &[SecretString],
    jar: CookieJar,
) -> Response {
    // Every sign-in can switch away from another user's session in this browser (the flow
    // revokes it and enqueues its back-channel logouts). Waking on each sign-in is cheaper than
    // threading a "revoked" flag out of the flow engine.
    state.wake_logout_worker();
    let continue_url = continue_to.map(|next| match next {
        Continue::Authorize(request) => {
            format!("{}/authorize/continue?request={request}", tenant.issuer)
        }
        // The tenant's own origin and the allowlisted path: nothing from the request.
        Continue::Return(target) => carry_ui_locales(&tenant.ui_url(target.as_path()), loc),
    });
    if !recovery_codes.is_empty() {
        let codes: Vec<String> = recovery_codes
            .iter()
            .map(|c| c.expose_secret().to_owned())
            .collect();
        let codes_text = codes.join("\n");
        let page = PageContext::for_tenant(state, tenant, loc, "title.mfa_codes");
        let ctx = minijinja::context! {
            page => page.into_value(),
            codes => codes,
            codes_text => codes_text,
            continue_url => continue_url.unwrap_or_else(|| {
                NavContext::none().url(tenant, loc, UiPage::Account(AccountSection::Security))
            }),
        };
        let mut resp = render_page(
            state,
            Some(tenant),
            loc,
            "mfa_enroll.html",
            ctx,
            StatusCode::OK,
            jar,
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return resp;
    }
    match continue_url {
        Some(location) => {
            (StatusCode::SEE_OTHER, jar, [(header::LOCATION, location)]).into_response()
        }
        // Without a continuation there is no live request: the way forward is the account.
        None => message_page(state, tenant, loc, SIGNED_IN, &NavContext::none(), jar),
    }
}

/// Maps a flow outcome of a tenant self-service page to a response, with sign-in page extras
/// for a rendered form.
pub(super) fn outcome_response_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    outcome: FlowOutcome,
    extras: &Extras<'_>,
) -> Response {
    let cookies = state.cookies();
    match outcome {
        FlowOutcome::Render(form) => render_tenant_form_with(
            state,
            tenant,
            loc,
            &form,
            nav,
            form_status(&form),
            CookieJar::new(),
            extras,
        ),
        FlowOutcome::Enroll { form, totp } => {
            let extras = Extras {
                factor_token: extras.factor_token.clone(),
                totp: Some(&totp),
                ..Extras::default()
            };
            render_tenant_form_with(
                state,
                tenant,
                loc,
                &form,
                nav,
                form_status(&form),
                CookieJar::new(),
                &extras,
            )
        }
        FlowOutcome::Restarted(started) => {
            let status = form_status(&started.form);
            started_response(state, tenant, loc, &started, nav, status)
        }
        FlowOutcome::Message { key } => {
            let jar = CookieJar::new().add(cookies.clear_flow(&tenant.tenant));
            message_page(state, tenant, loc, key, nav, jar)
        }
        FlowOutcome::SignedIn {
            cookie,
            continue_to,
            recovery_codes,
        } => {
            let jar = CookieJar::new()
                .add(cookies.clear_flow(&tenant.tenant))
                .add(cookies.session_cookie(&tenant.tenant, cookie.token.expose_secret()));
            signed_in_response(state, tenant, loc, continue_to, &recovery_codes, jar)
        }
        FlowOutcome::SteppedUp {
            continue_to,
            recovery_codes,
        } => {
            // The session was upgraded in place: its cookie stays.
            let jar = CookieJar::new().add(cookies.clear_flow(&tenant.tenant));
            signed_in_response(state, tenant, loc, continue_to, &recovery_codes, jar)
        }
        FlowOutcome::SetupSubmitted { .. } => core_error_page_in(
            state,
            Some(tenant),
            loc,
            &CoreError::Internal("setup outcome on a tenant page".into()),
        ),
    }
}
