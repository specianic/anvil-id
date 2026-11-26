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
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, AuthRequestId, BrowserSession,
    CaptchaSettings, FlowId, FlowKind, RegistrationMode, RequestContext, SessionId, UserId,
    normalize_email,
};
use anvil_core::policy::return_to::{ReturnTarget, parse_return_target};
use anvil_core::ports::RelyingParty;
use anvil_core::service::account::{SettingsBinding, TotpEnrolment};
use anvil_core::service::audit::AuditService;
use anvil_core::service::flow::{
    AuthAttempt, Continue, FlowContext, FlowOutcome, FlowService, IdentifyOutcome, IdpStart,
    LoginStart, StartedFlow, SubmitResult, bind_form, email_code_enabled, start_idp,
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
use super::mfa::seal_factor_token;
use crate::adapters::captcha::{
    CaptchaError, CaptchaVerifier, DEFAULT_TIMEOUT, captcha_csp, open_secret,
};
use crate::adapters::passkey::{WebauthnPasskeys, relying_party};
use crate::client_ip::ClientIp;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales, locale_for_request};
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
    let request = match q.auth_request() {
        Ok(r) => r,
        Err(resp) => return resp.into_response(&state, Some(&tenant), &locale.0),
    };
    let loc = page_locale(&state, &tenant, locale, &headers, request).await;
    let current = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    // Starting a flow records nothing (no session, no audit event), so no request context.
    let ctx = RequestContext::default();
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let mut started = match state
        .ui_flow_service()
        .start_login(&cx, request, current.as_ref(), q.return_target())
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
            return idp_redirect(
                &state,
                &tenant,
                &loc,
                &cx,
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
        request,
        StatusCode::OK,
        &extras,
    )
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
    let posted = Posted {
        flow_id,
        csrf,
        identifier: &identifier,
    };
    let (strict, loose) = attempt_keys(tenant.tenant.id, &identifier, ip);
    let captcha = tenant.tenant.settings.captcha.as_ref();

    match guard_attempt(&state, &strict, &loose, captcha.is_some()).await {
        Decision::Deny { retry_after } => {
            return match posted_login_form(&state, &tenant, &posted).await {
                Ok(form) => {
                    let extras = Extras {
                        upstream: identify_buttons(&state, &tenant, &loc, &form).await,
                        ..Extras::default()
                    };
                    locked_page_with(&state, &tenant, &loc, form, retry_after, extras)
                }
                Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
            };
        }
        Decision::RequireCaptcha => {
            if let Some(settings) = captcha
                && let Err(key) = verify_captcha(&state, &tenant, &ctx, settings, &form, ip).await
            {
                return match posted_login_form(&state, &tenant, &posted).await {
                    Ok(mut form) => {
                        form.messages = vec![FormMessage::error(key)];
                        // The widget goes with the password form only: the email-first form
                        // (routed tenants) is not gated, and the password step after it carries
                        // the widget (`password_step_captcha`).
                        let extras = Extras {
                            captcha: (form.id == "login").then_some(settings),
                            upstream: identify_buttons(&state, &tenant, &loc, &form).await,
                            ..Extras::default()
                        };
                        render_tenant_form_with(
                            &state,
                            &tenant,
                            &loc,
                            &form,
                            None,
                            StatusCode::BAD_REQUEST,
                            CookieJar::new(),
                            &extras,
                        )
                    }
                    Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
                };
            }
        }
        Decision::Allow => {}
    }

    let input = FlowInput::Login {
        identifier: identifier.clone(),
        password: form.password.clone().unwrap_or_default(),
    };
    let result = match submit_flow(&state, &tenant, &loc, &ctx, &jar, flow_id, csrf, input).await {
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
                        let extras = Extras {
                            upstream: identify_buttons(&state, &tenant, &loc, &form).await,
                            ..Extras::default()
                        };
                        return locked_page_with(&state, &tenant, &loc, form, retry_after, extras);
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
    if let FlowOutcome::Render(form) = &result.outcome {
        extras.upstream = identify_buttons(&state, &tenant, &loc, form).await;
    }
    outcome_response_with(&state, &tenant, &loc, result.outcome, &extras)
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
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let result = state
        .ui_flow_service()
        .identify(&cx, flow_id, cookie.as_deref(), csrf, input)
        .await;
    match result {
        Ok(IdentifyOutcome::Done(outcome)) => {
            let mut extras = Extras::default();
            if let FlowOutcome::Render(f) = outcome.as_ref() {
                extras.upstream = identify_buttons(&state, &tenant, &loc, f).await;
                extras.captcha = password_step_captcha(&state, &tenant, f, ip).await;
            }
            outcome_response_with(&state, &tenant, &loc, *outcome, &extras)
        }
        Ok(IdentifyOutcome::StartIdp(idp)) => {
            let current = match current_browser_session(&state, &tenant, &jar).await {
                Ok(s) => s,
                Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
            };
            let binding = SettingsBinding {
                flow_id,
                cookie_token: cookie.as_deref(),
                csrf_token: csrf,
            };
            idp_redirect(
                &state,
                &tenant,
                &loc,
                &cx,
                &binding,
                &idp,
                current.as_ref(),
                CookieJar::new(),
            )
            .await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &loc),
        Err(CoreError::InvalidRequest(_)) => restart_login(&state, &tenant, &loc).await,
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// The tenant's CAPTCHA when `form` is the password step and the brute-force gate of its email
/// asks for one (the same keys and decision as the password POST, read only: nothing is
/// recorded). The decision depends on the attempts made with the address, never on whether an
/// account exists.
async fn password_step_captcha<'a>(
    state: &AppState,
    tenant: &'a ResolvedTenant,
    form: &FormDescription,
    ip: IpAddr,
) -> Option<&'a CaptchaSettings> {
    let captcha = tenant.tenant.settings.captcha.as_ref()?;
    if form.id != "login" {
        return None;
    }
    let identifier = form
        .fields
        .iter()
        .find(|f| f.name == "identifier")
        .and_then(|f| f.value.as_deref())?;
    let (strict, loose) = attempt_keys(tenant.tenant.id, identifier, ip);
    matches!(
        guard_attempt(state, &strict, &loose, true).await,
        Decision::RequireCaptcha
    )
    .then_some(captcha)
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
    cx: &FlowContext<'_>,
    binding: &SettingsBinding<'_>,
    idp: &IdpStart,
    current: Option<&BrowserSession>,
    jar: CookieJar,
) -> Response {
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
            restart_login(state, tenant, loc).await
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
) -> Vec<super::upstream::UpstreamButton> {
    super::upstream::upstream_buttons(state, tenant, loc, form).await
}

/// The binding fields of a password POST, for pages rendered without running the flow (lock,
/// CAPTCHA). The CSRF token is the submitted one; the flow service checks it on the next POST.
struct Posted<'a> {
    flow_id: FlowId,
    csrf: &'a str,
    identifier: &'a str,
}

/// The form a new sign-in of this tenant starts with (`FlowService::initial_login_form`: the
/// email-first form in a tenant with a routable domain, the combined form otherwise), bound to the
/// posted flow, with the identifier echoed. Used when the brute-force gate (lock or CAPTCHA
/// demand) answers before the flow runs, so the response is the same whether or not the account
/// exists; the web layer never decides email-first itself.
async fn posted_login_form(
    state: &AppState,
    tenant: &ResolvedTenant,
    posted: &Posted<'_>,
) -> Result<FormDescription, CoreError> {
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
    let form = state.ui_flow_service().initial_login_form(&cx).await?;
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
    form: FormDescription,
    retry_after: Duration,
    factor_token: Option<String>,
) -> Response {
    let extras = Extras {
        factor_token,
        ..Extras::default()
    };
    locked_page_with(state, tenant, loc, form, retry_after, extras)
}

/// [`locked_page`] with sign-in page extras (the sign-in form's upstream buttons).
fn locked_page_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
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

/// CAPTCHA message keys.
const CAPTCHA_REQUIRED: &str = "login.captcha_required";
const CAPTCHA_FAILED: &str = "login.captcha_failed";

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
        CaptchaVerifier::new(
            state.outbound_arc(),
            state.config().captcha_endpoints.clone(),
            DEFAULT_TIMEOUT,
        ),
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
    let key = anvil_cache::limiter::LimitKey::Ip(ip);
    if let Decision::Deny { retry_after } = guard_attempt(&state, &key, &key, false).await {
        let posted = Posted {
            flow_id,
            csrf,
            identifier: "",
        };
        return match posted_login_form(&state, &tenant, &posted).await {
            Ok(form) => {
                let extras = Extras {
                    upstream: identify_buttons(&state, &tenant, &loc, &form).await,
                    ..Extras::default()
                };
                locked_page_with(&state, &tenant, &loc, form, retry_after, extras)
            }
            Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
        };
    }
    let input = FlowInput::PasskeyAssertion {
        response_json: form.response.clone().unwrap_or_default(),
    };
    let result = match submit_flow(&state, &tenant, &loc, &ctx, &jar, flow_id, csrf, input).await {
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
                let extras = Extras {
                    upstream: identify_buttons(&state, &tenant, &loc, form).await,
                    ..Extras::default()
                };
                return locked_page_with(&state, &tenant, &loc, form.clone(), retry_after, extras);
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
    let mut extras = Extras::default();
    if let FlowOutcome::Render(form) = &result.outcome {
        extras.upstream = identify_buttons(&state, &tenant, &loc, form).await;
    }
    outcome_response_with(&state, &tenant, &loc, result.outcome, &extras)
}

// ---------------------------------------------------------------------------------------------
// In-flow passkeys: enrolment (MFA policy `required`) and the second-factor step
// ---------------------------------------------------------------------------------------------

/// Which in-flow passkey ceremony a route runs.
#[derive(Clone, Copy)]
enum FlowPasskey {
    /// Registration at the enrolment step (MFA policy `required`, no second factor yet).
    Enrolment,
    /// Assertion of one of the step user's passkeys at the second-factor step.
    SecondFactor,
}

impl FlowPasskey {
    /// The message key of a refused ceremony (also the JSON error of a refused options request).
    fn failed_key(self) -> &'static str {
        match self {
            Self::Enrolment => PASSKEY_ENROLMENT_FAILED,
            Self::SecondFactor => SECOND_FACTOR_PASSKEY_FAILED,
        }
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
    flow_passkey_options(&state, &tenant, &jar, &q, form, FlowPasskey::Enrolment).await
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
    flow_passkey_options(&state, &tenant, &jar, &q, form, FlowPasskey::SecondFactor).await
}

async fn flow_passkey_options(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
    q: &UiQuery,
    form: Result<Form<UiForm>, FormRejection>,
    which: FlowPasskey,
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
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let base = ui_base(tenant);
    let rp = tenant_relying_party(tenant);
    // Creating a challenge records nothing, so no request context.
    let ctx = RequestContext::default();
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let service = state.ui_flow_service();
    let result = match which {
        FlowPasskey::Enrolment => {
            service
                .passkey_enrolment_options(&cx, flow_id, cookie.as_deref(), csrf)
                .await
        }
        FlowPasskey::SecondFactor => {
            service
                .passkey_second_factor_options(&cx, flow_id, cookie.as_deref(), csrf)
                .await
        }
    };
    match result {
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
            json_error(StatusCode::BAD_REQUEST, which.failed_key())
        }
        Err(e) => {
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
        FlowPasskey::Enrolment,
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
        FlowPasskey::SecondFactor,
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
    which: FlowPasskey,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(state, Some(tenant), loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(state, Some(tenant), loc);
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let session = match current_session(state, tenant, jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
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
    let response = form.response.as_deref().unwrap_or_default();
    let service = state.ui_flow_service();
    let result = match which {
        FlowPasskey::Enrolment => {
            service
                .passkey_enrolment_finish(&cx, flow_id, cookie.as_deref(), csrf, response, session)
                .await
        }
        FlowPasskey::SecondFactor => {
            service
                .passkey_second_factor_finish(
                    &cx,
                    flow_id,
                    cookie.as_deref(),
                    csrf,
                    response,
                    session,
                )
                .await
        }
    };
    let result = match result {
        Ok(r) => r,
        Err(CoreError::Forbidden) => return csrf_page(state, Some(tenant), loc),
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let extras = Extras {
        factor_token: form.factor_token.clone().filter(|t| !t.is_empty()),
        ..Extras::default()
    };
    outcome_response_with(state, tenant, loc, result.outcome, &extras)
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

/// Links between the tenant's self-service pages for a form. The registration link only exists
/// when self-registration is open. `request` is carried along so the user can switch pages
/// without losing the authorization request.
pub(super) fn links_for(
    tenant: &ResolvedTenant,
    loc: &Locale,
    form_id: &str,
    request: Option<AuthRequestId>,
) -> PageLinks {
    let with_request = |path: &str| {
        let url = match request {
            Some(r) => tenant.ui_url(&format!("{path}?request={r}")),
            None => tenant.ui_url(path),
        };
        carry_ui_locales(&url, loc)
    };
    match form_id {
        "login" | IDENTIFY_FORM_ID | SSO_CHOICE_FORM_ID => PageLinks {
            login: None,
            registration: (tenant.tenant.settings.registration == RegistrationMode::Open)
                .then(|| with_request("/ui/registration")),
            recovery: Some(carry_ui_locales(&tenant.ui_url("/ui/recovery"), loc)),
        },
        _ => PageLinks {
            login: Some(with_request("/ui/login")),
            registration: None,
            recovery: None,
        },
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
    /// Upstream sign-in buttons of the sign-in form ([`super::upstream::upstream_buttons`]).
    pub(super) upstream: Vec<super::upstream::UpstreamButton>,
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
    request: Option<AuthRequestId>,
    status: StatusCode,
    jar: CookieJar,
    extras: &Extras<'_>,
) -> Response {
    let (template, title) = form_template(&form.id);
    let mut page = PageContext::for_tenant(state, tenant, loc, title);
    page.links = links_for(tenant, loc, &form.id, request);
    let base = ui_base(tenant);
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
            if tenant_relying_party(tenant).is_ok() {
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
    if form.id == "login"
        && email_code_enabled(&tenant.tenant)
        && let Some(flow) = flow_of(&form)
    {
        email_code = Some(EmailCodeView {
            action: carry_ui_locales(&format!("{base}/login/email-code?flow={flow}"), loc),
            value: form
                .fields
                .iter()
                .find(|f| f.name == "identifier")
                .and_then(|f| f.value.clone()),
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
    form.action = carry_ui_locales(&form.action, loc);
    let ctx = minijinja::context! {
        page => page.into_value(),
        form => Value::from(Serde(&form)),
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
        upstream => Value::from(Serde(&extras.upstream)),
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

/// Message key of the page shown after a login that is not bound to an authorization request
/// (there is no account page in release 0.1).
pub(super) const SIGNED_IN: &str = "login.signed_in";

/// Renders `message.html` (200) with a link to the tenant's sign-in page.
pub(super) fn message_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    key: &str,
    jar: CookieJar,
) -> Response {
    let page = {
        let mut page = PageContext::for_tenant(state, tenant, loc, message_heading(key));
        if key != SIGNED_IN {
            page.links.login = Some(carry_ui_locales(&tenant.ui_url("/ui/login"), loc));
        }
        page
    };
    let heading = page.title.clone();
    let ctx = minijinja::context! {
        page => page.into_value(),
        heading => heading,
        body_key => key,
        body => state.renderer().text(loc, key),
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
    request: Option<AuthRequestId>,
    status: StatusCode,
) -> Response {
    started_response_with(
        state,
        tenant,
        loc,
        started,
        request,
        status,
        &Extras::default(),
    )
}

/// [`started_response`] with sign-in page extras (step-up binding token, enrolment secret).
pub(super) fn started_response_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    started: &StartedFlow,
    request: Option<AuthRequestId>,
    status: StatusCode,
    extras: &Extras<'_>,
) -> Response {
    started_response_in(
        state,
        tenant,
        loc,
        started,
        request,
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
    request: Option<AuthRequestId>,
    status: StatusCode,
    extras: &Extras<'_>,
    jar: CookieJar,
) -> Response {
    let jar = jar.add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_tenant_form_with(
        state,
        tenant,
        loc,
        &started.form,
        request,
        status,
        jar,
        extras,
    )
}

/// `GET` of a self-service page: starts a flow of `kind` and renders its form.
pub(super) async fn start_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
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
        Ok(started) => started_response(state, tenant, loc, &started, request, StatusCode::OK),
        Err(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// A new sign-in flow with the `flow.expired` message (400): the answer to a submission that
/// cannot continue its flow (for example a second-factor POST without a valid binding token).
pub(super) async fn restart_login(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
) -> Response {
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
            started
                .form
                .messages
                .insert(0, FormMessage::error("flow.expired"));
            started_response(state, tenant, loc, &started, None, StatusCode::BAD_REQUEST)
        }
        Err(e) => core_error_page_in(state, Some(tenant), loc, &e),
    }
}

/// The caller's current session id (from the session cookie), if any.
async fn current_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<SessionId>, CoreError> {
    Ok(current_browser_session(state, tenant, jar)
        .await?
        .map(|s| s.id))
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

/// `POST` of a self-service page: binds the submission to its flow, runs it and maps the
/// outcome to a response.
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
    match submit_flow(state, tenant, loc, ctx, jar, flow_id, csrf, input).await {
        Ok(result) => outcome_response(state, tenant, loc, result.outcome),
        Err(resp) => *resp,
    }
}

/// Runs a bound submission through the flow service. `Err` is the finished error response
/// (`csrf` page for a binding failure, the error page otherwise).
#[expect(
    clippy::too_many_arguments,
    reason = "threads the request's locale, context and binding"
)]
pub(super) async fn submit_flow(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
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
        .map_err(|e| Box::new(core_error_page_in(state, Some(tenant), loc, &e)))?;
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
        Err(CoreError::Forbidden) => Err(Box::new(csrf_page(state, Some(tenant), loc))),
        Err(e) => Err(Box::new(core_error_page_in(state, Some(tenant), loc, &e))),
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
            continue_url => continue_url
                .unwrap_or_else(|| carry_ui_locales(&tenant.ui_url("/ui/account/security"), loc)),
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
        None => message_page(state, tenant, loc, SIGNED_IN, jar),
    }
}

/// Maps a flow outcome of a tenant self-service page to a response.
fn outcome_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    outcome: FlowOutcome,
) -> Response {
    outcome_response_with(state, tenant, loc, outcome, &Extras::default())
}

/// [`outcome_response`] with sign-in page extras for a rendered form.
pub(super) fn outcome_response_with(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
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
            None,
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
                None,
                form_status(&form),
                CookieJar::new(),
                &extras,
            )
        }
        FlowOutcome::Restarted(started) => {
            let status = form_status(&started.form);
            started_response(state, tenant, loc, &started, None, status)
        }
        FlowOutcome::Message { key } => {
            let jar = CookieJar::new().add(cookies.clear_flow(&tenant.tenant));
            message_page(state, tenant, loc, key, jar)
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
