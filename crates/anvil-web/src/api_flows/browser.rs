//! Browser-mode handlers of the headless flow API (single-page apps, UI-05).
//!
//! Every handler goes through [`crate::ui::flow_driver`], exactly like the HTML handlers in
//! `ui::login`, `ui::mfa`, `ui::email_code`, `ui::registration`, `ui::recovery` and
//! `ui::verification`: the same flow binding (flow cookie + CSRF token), brute-force gate and
//! limiter keys, CAPTCHA check, attempt recording, lock decision and session switch. Only the
//! encoding differs (the v1 DTO instead of a page).
//!
//! # Binding
//!
//! The start answer sets the flow cookie (`SameSite=Strict`, on the AnvilID origin) and returns
//! the flow's `csrf_token` in JSON. Every later request about the flow carries the cookie
//! (`credentials: "include"`) and the token in the `X-CSRF-Token` header; a missing header is
//! refused before the driver runs (403 `csrf`), a wrong one by the flow service (403 `csrf`).
//! The custom header also forces a CORS preflight for cross-origin callers.
//!
//! # Status codes
//!
//! | Answer | Status |
//! |---|---|
//! | a form without an error message, a message, a completed sign-in, `browser_required` | 200 |
//! | a form with an error message (wrong credentials, validation, expired flow restarted) | 400 |
//! | a locked form (`retry_after`, `Retry-After`) | 429 |
//! | problem `too_many_requests` (second factor and email code locks) | 429 |
//! | problem `captcha_required` / `captcha_failed` (with the site key) | 403 |
//! | problem `csrf` (missing or wrong token or flow cookie), `forbidden_origin` | 403 |
//! | problem `registration_disabled` | 403 |
//! | problem `invalid_request` (malformed JSON or ids), `method_not_available`, `invalid_flow_state`, `passkey_failed` | 400 |
//! | problem `not_found` (unknown kind or path), `flow_not_found` (unknown or expired flow on `GET`) | 404 |
//! | problem `unsupported_media_type` (a `POST` without `application/json`) | 415 |
//!
//! On completion the session cookie is set on the AnvilID origin and the JSON carries
//! `result.continue_to`, an absolute URL on the AnvilID origin (`{issuer}/authorize/continue?request=…`
//! for an authorization request): the app navigates the top-level window there and the normal
//! code redirect follows. Upstream, SAML and enterprise single-sign-on steps answer
//! `step: browser_required` with the built-in sign-in page's URL.

use anvil_core::error::CoreError;
use anvil_core::flow::email_code::EMAIL_CODE_FORM_ID;
use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::{FormDescription, MessageLevel};
use anvil_core::flow::login::{IDENTIFY_FORM_ID, IdentifyInput, SSO_CHOICE_FORM_ID};
use anvil_core::model::{AuthRequestId, FlowId, RegistrationMode, RequestContext, normalize_email};
use anvil_core::service::flow::{
    AuthAttempt, Continue, FlowOutcome, LoginStart, StartedFlow, email_code_enabled,
};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::dto::{
    CaptchaDto, FlowKindDto, FlowRef, FlowResponse, FormExtras, MessageDto, MessageLevelDto,
    PasskeyRequest, ResultDto, StartRequest, Step, SubmitMethod, SubmitRequest, TotpDto, form_dto,
    ts,
};
use super::{problem, problem_with};
use crate::client_ip::ClientIp;
use crate::i18n::{Locale, RequestLocale, carry_ui_locales, localize_form};
use crate::layers::cors::CSRF_HEADER;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;
use crate::ui::flow_driver::{
    self, CaptchaAnswer, DriveOutcome, DriveRejection, FlowBinding, Identified, InFlowPasskey,
    PasskeyStep, Throttle,
};

// ---------------------------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------------------------

/// A refusal before the driver runs: the status and problem code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refused(StatusCode, &'static str);

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        problem(self.0, self.1)
    }
}

/// The `{kind}` path segment (unknown: 404).
fn parse_kind(kind: &str) -> Result<FlowKindDto, Refused> {
    serde_json::from_value(serde_json::Value::String(kind.to_owned()))
        .map_err(|_| Refused(StatusCode::NOT_FOUND, "not_found"))
}

/// The `{flow_id}` path segment (malformed: 404, like an unknown flow).
fn parse_flow(flow: &str) -> Result<FlowId, Refused> {
    uuid::Uuid::parse_str(flow)
        .map(FlowId)
        .map_err(|_| Refused(StatusCode::NOT_FOUND, "flow_not_found"))
}

/// The `X-CSRF-Token` header (missing or blank: 403 `csrf`).
fn csrf_header(headers: &HeaderMap) -> Result<String, Refused> {
    headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or(Refused(StatusCode::FORBIDDEN, "csrf"))
}

/// A JSON body (`Content-Type` is checked by the layer). An empty body is the default value;
/// malformed JSON is 400 `invalid_request`.
fn parse_body<T: DeserializeOwned + Default>(body: &Bytes) -> Result<T, Refused> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    serde_json::from_slice(body).map_err(|_| Refused(StatusCode::BAD_REQUEST, "invalid_request"))
}

/// A JSON answer, never cached.
fn json(status: StatusCode, body: &impl Serialize, jar: CookieJar) -> Response {
    let text = serde_json::to_string(body).unwrap_or_default();
    let mut resp = (
        status,
        jar,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        text,
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The problem of a refused step.
fn rejection(r: DriveRejection) -> Response {
    match r {
        DriveRejection::Binding => problem(StatusCode::FORBIDDEN, "csrf"),
        DriveRejection::Failed(e) => core_problem(&e),
    }
}

fn core_problem(e: &CoreError) -> Response {
    match e {
        CoreError::InvalidRequest(_) => problem(StatusCode::BAD_REQUEST, "invalid_flow_state"),
        CoreError::NotFound => problem(StatusCode::NOT_FOUND, "flow_not_found"),
        CoreError::Forbidden => problem(StatusCode::FORBIDDEN, "csrf"),
        e => {
            tracing::error!(error = %e, "headless flow request failed");
            problem(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

/// The per-request encoding context.
struct Out<'a> {
    state: &'a AppState,
    tenant: &'a ResolvedTenant,
    loc: &'a Locale,
    /// The path's flow kind (used when the flow is gone).
    kind: FlowKindDto,
}

impl Out<'_> {
    /// Display texts are filled only for an explicit `ui_locales`.
    fn localized(&self) -> bool {
        self.loc.ui_locales.is_some()
    }

    /// The flow reference of `flow` (its expiry and kind from storage while it exists).
    async fn flow_ref(&self, flow: FlowId) -> FlowRef {
        let meta = flow_driver::flow_meta(self.state, self.tenant, flow)
            .await
            .inspect_err(|e| tracing::warn!(error = %e, "loading the flow for its expiry failed"))
            .ok()
            .flatten();
        FlowRef {
            id: flow.0.to_string(),
            kind: meta
                .and_then(|m| FlowKindDto::from_core(m.kind))
                .unwrap_or(self.kind),
            expires_at: meta.map(|m| ts(m.expires_at)),
        }
    }

    fn finished_ref(&self, flow: FlowId) -> FlowRef {
        FlowRef {
            id: flow.0.to_string(),
            kind: self.kind,
            expires_at: None,
        }
    }

    /// A form answer: localised for an explicit `ui_locales`, with the sign-in methods of a
    /// sign-in form, the CSRF token it is bound to and the given extras.
    async fn form(
        &self,
        flow: FlowId,
        form: FormDescription,
        status: StatusCode,
        extras: FormExtras,
        jar: CookieJar,
    ) -> Response {
        self.form_with(flow, form, status, extras, jar, None).await
    }

    /// [`Self::form`] with `retry_after` (a locked form).
    async fn form_with(
        &self,
        flow: FlowId,
        mut form: FormDescription,
        status: StatusCode,
        extras: FormExtras,
        jar: CookieJar,
        retry_after: Option<u64>,
    ) -> Response {
        if self.localized() {
            localize_form(self.state.renderer().catalogs(), self.loc, &mut form);
        }
        let methods = if matches!(
            form.id.as_str(),
            "login" | IDENTIFY_FORM_ID | SSO_CHOICE_FORM_ID
        ) {
            flow_driver::offered_methods(self.state, self.tenant, self.loc, &form).await
        } else {
            Vec::new()
        };
        let body = FlowResponse {
            flow: self.flow_ref(flow).await,
            step: Step::Form,
            csrf_token: Some(form.csrf_token.clone()),
            form: Some(form_dto(&form, &methods, self.localized(), extras)),
            message: None,
            result: None,
            url: None,
            retry_after,
        };
        json(status, &body, jar)
    }

    /// A newly started flow: sets its cookie (added to `jar`) and answers its form.
    async fn started(
        &self,
        started: StartedFlow,
        status: StatusCode,
        mut extras: FormExtras,
        jar: CookieJar,
    ) -> Response {
        let jar = jar.add(
            self.state
                .cookies()
                .flow_cookie(&self.tenant.tenant, started.cookie_token.expose_secret()),
        );
        if let Some(user) = started.factor_user {
            extras.factor_token =
                flow_driver::seal_factor_token(self.state, self.tenant, started.flow_id, user);
        }
        if let Some(totp) = &started.totp {
            extras.totp = Some(totp_dto(totp));
        }
        self.form(started.flow_id, started.form, status, extras, jar)
            .await
    }

    /// `browser_required`: the built-in sign-in page continues (upstream, SAML and enterprise
    /// single sign-on need top-level redirects and the provider's callback).
    async fn browser_required(&self, flow: FlowId) -> Response {
        let request = flow_driver::flow_meta(self.state, self.tenant, flow)
            .await
            .ok()
            .flatten()
            .and_then(|m| m.request);
        self.browser_required_for(flow, request, CookieJar::new())
            .await
    }

    async fn browser_required_for(
        &self,
        flow: FlowId,
        request: Option<AuthRequestId>,
        jar: CookieJar,
    ) -> Response {
        let page = match request {
            Some(r) => format!("/ui/login?request={r}"),
            None => "/ui/login".to_owned(),
        };
        let body = FlowResponse {
            flow: self.flow_ref(flow).await,
            step: Step::BrowserRequired,
            csrf_token: None,
            form: None,
            message: None,
            result: None,
            url: Some(carry_ui_locales(&self.tenant.ui_url(&page), self.loc)),
            retry_after: None,
        };
        json(StatusCode::OK, &body, jar)
    }

    /// A completed sign-in or step-up: `continue_to` on the AnvilID origin.
    fn completed(
        &self,
        flow: FlowId,
        continue_to: Option<Continue>,
        recovery_codes: &[secrecy::SecretString],
        jar: CookieJar,
    ) -> Response {
        // As the pages do: a sign-in may have revoked another user's session in this browser.
        self.state.wake_logout_worker();
        let continue_to = continue_to.map(|next| match next {
            Continue::Authorize(request) => {
                format!(
                    "{}/authorize/continue?request={request}",
                    self.tenant.issuer
                )
            }
            Continue::Return(target) => {
                carry_ui_locales(&self.tenant.ui_url(target.as_path()), self.loc)
            }
        });
        let body = FlowResponse {
            flow: self.finished_ref(flow),
            step: Step::Completed,
            csrf_token: None,
            form: None,
            message: None,
            result: Some(ResultDto {
                continue_to,
                recovery_codes: recovery_codes
                    .iter()
                    .map(|c| c.expose_secret().to_owned())
                    .collect(),
            }),
            url: None,
            retry_after: None,
        };
        json(StatusCode::OK, &body, jar)
    }

    /// Encodes a flow outcome (the pages' `outcome_response_with`).
    async fn outcome(
        &self,
        flow: FlowId,
        outcome: FlowOutcome,
        mut extras: FormExtras,
    ) -> Response {
        let cookies = self.state.cookies();
        let tenant = &self.tenant.tenant;
        match outcome {
            FlowOutcome::Render(form) => {
                let status = form_status(&form);
                self.form(flow, form, status, extras, CookieJar::new())
                    .await
            }
            FlowOutcome::Enroll { form, totp } => {
                extras.totp = Some(totp_dto(&totp));
                let status = form_status(&form);
                self.form(flow, form, status, extras, CookieJar::new())
                    .await
            }
            FlowOutcome::Restarted(started) => {
                let status = form_status(&started.form);
                self.started(started, status, FormExtras::default(), CookieJar::new())
                    .await
            }
            FlowOutcome::Message { key } => {
                let jar = CookieJar::new().add(cookies.clear_flow(tenant));
                let text = self
                    .localized()
                    .then(|| self.state.renderer().catalogs().text(self.loc, key, &[]));
                let body = FlowResponse {
                    flow: self.finished_ref(flow),
                    step: Step::Message,
                    csrf_token: None,
                    form: None,
                    message: Some(MessageDto {
                        level: MessageLevelDto::Info,
                        key: key.to_owned(),
                        args: Default::default(),
                        text,
                    }),
                    result: None,
                    url: None,
                    retry_after: None,
                };
                json(StatusCode::OK, &body, jar)
            }
            FlowOutcome::SignedIn {
                cookie,
                continue_to,
                recovery_codes,
            } => {
                let jar = CookieJar::new()
                    .add(cookies.clear_flow(tenant))
                    .add(cookies.session_cookie(tenant, cookie.token.expose_secret()));
                self.completed(flow, continue_to, &recovery_codes, jar)
            }
            FlowOutcome::SteppedUp {
                continue_to,
                recovery_codes,
            } => {
                // The session was upgraded in place: its cookie stays.
                let jar = CookieJar::new().add(cookies.clear_flow(tenant));
                self.completed(flow, continue_to, &recovery_codes, jar)
            }
            FlowOutcome::SetupSubmitted { .. } => core_problem(&CoreError::Internal(
                "setup outcome on a tenant flow".into(),
            )),
        }
    }

    /// Encodes a driver outcome (the pages' `drive_response` / `sign_in_gate_page`).
    /// `locked_token`: the binding token a locked form keeps.
    async fn drive(
        &self,
        flow: FlowId,
        outcome: DriveOutcome,
        mut extras: FormExtras,
        locked_token: Option<String>,
    ) -> Response {
        let captcha = self.tenant.tenant.settings.captcha.as_ref();
        match outcome {
            DriveOutcome::Flow {
                outcome,
                captcha: c,
                ..
            } => {
                if c {
                    extras.captcha = captcha.map(CaptchaDto::from);
                }
                self.outcome(flow, outcome, extras).await
            }
            DriveOutcome::Locked {
                mut form,
                retry_after,
                ..
            } => {
                form.messages = vec![flow_driver::lock_message(retry_after)];
                let secs = flow_driver::retry_after_secs(retry_after);
                let extras = FormExtras {
                    factor_token: locked_token,
                    ..FormExtras::default()
                };
                let mut resp = self
                    .form_with(
                        flow,
                        form,
                        StatusCode::TOO_MANY_REQUESTS,
                        extras,
                        CookieJar::new(),
                        Some(secs),
                    )
                    .await;
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(secs));
                resp
            }
            DriveOutcome::Throttled { retry_after } => problem_with(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                Some(flow_driver::retry_after_secs(retry_after)),
                None,
            ),
            DriveOutcome::CaptchaRejected { form } => {
                let code = if form
                    .messages
                    .iter()
                    .any(|m| m.key == flow_driver::CAPTCHA_FAILED)
                {
                    "captcha_failed"
                } else {
                    "captcha_required"
                };
                problem_with(
                    StatusCode::FORBIDDEN,
                    code,
                    None,
                    captcha.map(CaptchaDto::from),
                )
            }
            DriveOutcome::Rejected(r) => rejection(r),
        }
    }
}

fn totp_dto(t: &anvil_core::service::account::TotpEnrolment) -> TotpDto {
    TotpDto {
        secret: t.secret_base32.expose_secret().to_owned(),
        otpauth_uri: t.otpauth_uri.expose_secret().to_owned(),
    }
}

/// 400 when the form carries an error message, 200 otherwise (as the pages).
fn form_status(form: &FormDescription) -> StatusCode {
    let error = form
        .messages
        .iter()
        .chain(form.fields.iter().flat_map(|f| f.messages.iter()))
        .any(|m| m.level == MessageLevel::Error);
    if error {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    }
}

/// Whether a second-factor, enrolment or email step follows (they carry a binding token).
fn carries_token(outcome: &DriveOutcome) -> Option<&str> {
    match outcome {
        DriveOutcome::Flow {
            outcome: FlowOutcome::Render(f) | FlowOutcome::Enroll { form: f, .. },
            ..
        } => Some(f.id.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Start, current step, submit
// ---------------------------------------------------------------------------------------------

/// Starts a flow.
#[utoipa::path(
    post,
    path = "/api/flows/v1/{kind}",
    tag = "flows",
    operation_id = "startFlow",
    params(
        ("kind" = FlowKindDto, Path, description = "Flow kind"),
        ("ui_locales" = Option<String>, Query, description = "Fill `label`/`text` in this locale (space-separated tags)"),
    ),
    request_body(content = StartRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The flow's first step; sets the flow cookie", body = FlowResponse),
        (status = 400, description = "Malformed request id", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 403, description = "Foreign origin, or registration disabled", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown kind", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 415, description = "Body is not application/json", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 429, description = "Rate limited", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    )
)]
pub(crate) async fn start_flow(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
    Path(kind): Path<String>,
    body: Bytes,
) -> Response {
    let kind = match parse_kind(&kind) {
        Ok(k) => k,
        Err(r) => return r.into_response(),
    };
    let req: StartRequest = match parse_body(&body) {
        Ok(r) => r,
        Err(r) => return r.into_response(),
    };
    let request = match req.request.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => match uuid::Uuid::parse_str(s) {
            Ok(u) => Some(AuthRequestId(u)),
            Err(_) => return problem(StatusCode::BAD_REQUEST, "invalid_request"),
        },
    };
    let out = Out {
        state: &state,
        tenant: &tenant,
        loc: &loc,
        kind,
    };
    let started = match kind {
        FlowKindDto::Login => {
            let current = match flow_driver::session_of(&state, &tenant, &jar).await {
                Ok(s) => s,
                Err(e) => return core_problem(&e),
            };
            match flow_driver::start_login(&state, &tenant, request, current.as_ref(), None).await {
                Ok(LoginStart::Form(started)) => started,
                // A direct start at an org IdP (the request's `organization`): the built-in
                // page runs it.
                Ok(LoginStart::Idp { started, .. }) => {
                    return out
                        .browser_required_for(started.flow_id, request, CookieJar::new())
                        .await;
                }
                Err(e) => return core_problem(&e),
            }
        }
        FlowKindDto::Registration => {
            if tenant.tenant.settings.registration != RegistrationMode::Open {
                return problem(StatusCode::FORBIDDEN, "registration_disabled");
            }
            match flow_driver::start(&state, &tenant, kind.core(), request, None).await {
                Ok(s) => s,
                Err(e) => return core_problem(&e),
            }
        }
        FlowKindDto::Recovery | FlowKindDto::Verification => {
            let token = req.token.filter(|t| !t.is_empty());
            match flow_driver::start(&state, &tenant, kind.core(), request, token).await {
                Ok(s) => s,
                Err(e) => return core_problem(&e),
            }
        }
    };
    out.started(
        started,
        StatusCode::OK,
        FormExtras::default(),
        CookieJar::new(),
    )
    .await
}

/// The current step of a flow (without one-time values: keep the hidden fields of the answer
/// that produced the step).
#[utoipa::path(
    get,
    path = "/api/flows/v1/{kind}/{flow_id}",
    tag = "flows",
    operation_id = "getFlow",
    params(
        ("kind" = FlowKindDto, Path, description = "Flow kind"),
        ("flow_id" = String, Path, description = "Flow id"),
        ("ui_locales" = Option<String>, Query, description = "Fill `label`/`text` in this locale"),
    ),
    responses(
        (status = 200, description = "The current step", body = FlowResponse),
        (status = 403, description = "Missing or wrong CSRF token or flow cookie, or foreign origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown or expired flow", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
pub(crate) async fn get_flow(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    Path((kind, flow)): Path<(String, String)>,
) -> Response {
    let (kind, flow, csrf) = match (parse_kind(&kind), parse_flow(&flow), csrf_header(&headers)) {
        (Ok(k), Ok(f), Ok(c)) => (k, f, c),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r.into_response(),
    };
    let binding = FlowBinding::Cookie {
        jar: &jar,
        csrf: &csrf,
    };
    let out = Out {
        state: &state,
        tenant: &tenant,
        loc: &loc,
        kind,
    };
    match flow_driver::current_step(&state, &tenant, flow, &binding).await {
        Ok(Some((form, meta))) if FlowKindDto::from_core(meta.kind) == Some(kind) => {
            out.form(
                flow,
                form,
                StatusCode::OK,
                FormExtras::default(),
                CookieJar::new(),
            )
            .await
        }
        Ok(_) => problem(StatusCode::NOT_FOUND, "flow_not_found"),
        Err(r) => rejection(r),
    }
}

/// Submits the current step.
#[utoipa::path(
    post,
    path = "/api/flows/v1/{kind}/{flow_id}",
    tag = "flows",
    operation_id = "submitFlow",
    params(
        ("kind" = FlowKindDto, Path, description = "Flow kind"),
        ("flow_id" = String, Path, description = "Flow id"),
        ("ui_locales" = Option<String>, Query, description = "Fill `label`/`text` in this locale"),
    ),
    request_body(content = SubmitRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The next step, a message, a completed sign-in (sets the session cookie) or browser_required", body = FlowResponse),
        (status = 400, description = "The form again with an error message, or a problem (invalid_request, method_not_available, invalid_flow_state)", body = FlowResponse),
        (status = 403, description = "csrf, forbidden_origin, captcha_required or captcha_failed", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 404, description = "Unknown kind, or the method's feature is off", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 415, description = "Body is not application/json", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 429, description = "Locked: the form with retry_after, or a too_many_requests problem; Retry-After", body = FlowResponse),
    ),
    security(("csrf" = []))
)]
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
pub(crate) async fn submit_flow(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    jar: CookieJar,
    Path((kind, flow)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let (kind, flow, csrf) = match (parse_kind(&kind), parse_flow(&flow), csrf_header(&headers)) {
        (Ok(k), Ok(f), Ok(c)) => (k, f, c),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r.into_response(),
    };
    let req: SubmitRequest = match parse_body(&body) {
        Ok(r) => r,
        Err(r) => return r.into_response(),
    };
    let method = req.method.unwrap_or(match kind {
        FlowKindDto::Login => SubmitMethod::Password,
        FlowKindDto::Registration => SubmitMethod::Register,
        FlowKindDto::Verification => SubmitMethod::Verify,
        FlowKindDto::Recovery if req.value("token").is_some() => SubmitMethod::RecoveryReset,
        FlowKindDto::Recovery => SubmitMethod::RecoveryRequest,
    });
    if method_kind(method) != kind {
        return problem(StatusCode::BAD_REQUEST, "method_not_available");
    }
    let out = Out {
        state: &state,
        tenant: &tenant,
        loc: &loc,
        kind,
    };
    let binding = FlowBinding::Cookie {
        jar: &jar,
        csrf: &csrf,
    };
    let s = Submission {
        out: &out,
        ctx: &ctx,
        flow,
        ip,
        req: &req,
    };
    match method {
        SubmitMethod::Password => s.password(binding).await,
        SubmitMethod::Identify => s.identify(binding).await,
        SubmitMethod::Totp | SubmitMethod::RecoveryCode => s.second_factor(binding, method).await,
        SubmitMethod::EmailCodeRequest => s.email_code_request(binding).await,
        SubmitMethod::EmailCode => s.email_code(binding).await,
        SubmitMethod::Upstream => out.browser_required(flow).await,
        SubmitMethod::Register => {
            let input = FlowInput::Register {
                email: req.value("email").unwrap_or_default(),
                password: req.values.get("password").cloned().unwrap_or_default(),
                name: req.value("name"),
            };
            s.plain(binding, input).await
        }
        SubmitMethod::RecoveryRequest => {
            let input = FlowInput::RequestRecovery {
                email: req.value("email").unwrap_or_default(),
            };
            s.plain(binding, input).await
        }
        SubmitMethod::RecoveryReset => {
            let input = FlowInput::ResetPassword {
                token: req.value("token").unwrap_or_default(),
                password: req.values.get("password").cloned().unwrap_or_default(),
            };
            // As the page: a reset revokes sessions and enqueues their back-channel logouts.
            let resp = s.plain(binding, input).await;
            state.wake_logout_worker();
            resp
        }
        SubmitMethod::Verify => {
            let input = FlowInput::ConfirmVerification {
                token: req.value("token").unwrap_or_default(),
            };
            s.plain(binding, input).await
        }
    }
}

/// The flow kind a submission method belongs to.
fn method_kind(m: SubmitMethod) -> FlowKindDto {
    match m {
        SubmitMethod::Password
        | SubmitMethod::Identify
        | SubmitMethod::Totp
        | SubmitMethod::RecoveryCode
        | SubmitMethod::EmailCodeRequest
        | SubmitMethod::EmailCode
        | SubmitMethod::Upstream => FlowKindDto::Login,
        SubmitMethod::Register => FlowKindDto::Registration,
        SubmitMethod::RecoveryRequest | SubmitMethod::RecoveryReset => FlowKindDto::Recovery,
        SubmitMethod::Verify => FlowKindDto::Verification,
    }
}

/// One submission: the same driver calls as the page handlers of each step.
struct Submission<'a> {
    out: &'a Out<'a>,
    ctx: &'a RequestContext,
    flow: FlowId,
    ip: std::net::IpAddr,
    req: &'a SubmitRequest,
}

impl Submission<'_> {
    fn state(&self) -> &AppState {
        self.out.state
    }

    fn tenant(&self) -> &ResolvedTenant {
        self.out.tenant
    }

    /// Registration, recovery, verification: not authentication attempts (`Throttle::None`).
    async fn plain(&self, binding: FlowBinding<'_>, input: FlowInput) -> Response {
        let outcome = flow_driver::submit(
            self.state(),
            self.tenant(),
            self.ctx,
            self.flow,
            binding,
            Throttle::None,
            input,
        )
        .await;
        self.out
            .drive(self.flow, outcome, FormExtras::default(), None)
            .await
    }

    /// `ui::login::submit`: identifier and password behind the brute-force gate.
    async fn password(&self, binding: FlowBinding<'_>) -> Response {
        let identifier = self
            .req
            .values
            .get("identifier")
            .cloned()
            .unwrap_or_default();
        let captcha = self.req.captcha.clone().unwrap_or_default();
        let throttle = Throttle::Password {
            identifier: &identifier,
            ip: self.ip,
            captcha: CaptchaAnswer {
                turnstile: captcha.turnstile.as_deref(),
                hcaptcha: captcha.hcaptcha.as_deref(),
            },
        };
        let input = FlowInput::Login {
            identifier: identifier.clone(),
            password: self.req.values.get("password").cloned().unwrap_or_default(),
        };
        let outcome = flow_driver::submit(
            self.state(),
            self.tenant(),
            self.ctx,
            self.flow,
            binding,
            throttle,
            input,
        )
        .await;
        let mut extras = FormExtras::default();
        if let DriveOutcome::Flow {
            attempt: Some(AuthAttempt::PasswordSucceeded { user, .. }),
            ..
        } = &outcome
        {
            extras.factor_token =
                flow_driver::seal_factor_token(self.state(), self.tenant(), self.flow, *user);
        }
        self.out.drive(self.flow, outcome, extras, None).await
    }

    /// `ui::login::identify`: the email-first page and the single-sign-on choice.
    async fn identify(&self, binding: FlowBinding<'_>) -> Response {
        let input = match self.req.value("choice").as_deref() {
            Some("sso") => IdentifyInput::Sso,
            Some("password") => IdentifyInput::Password,
            Some("change") => IdentifyInput::Change,
            _ => IdentifyInput::Email(
                self.req
                    .values
                    .get("identifier")
                    .cloned()
                    .unwrap_or_default(),
            ),
        };
        match flow_driver::identify(
            self.state(),
            self.tenant(),
            self.ctx,
            self.flow,
            &binding,
            input,
            self.ip,
        )
        .await
        {
            Ok(Identified::Done { outcome, captcha }) => {
                let extras = FormExtras {
                    captcha: captcha
                        .then(|| self.tenant().tenant.settings.captcha.as_ref())
                        .flatten()
                        .map(CaptchaDto::from),
                    ..FormExtras::default()
                };
                self.out.outcome(self.flow, *outcome, extras).await
            }
            // Routed to an org IdP: the built-in page runs the redirect and the callback.
            Ok(Identified::StartIdp(_)) => self.out.browser_required(self.flow).await,
            Err(r) => rejection(r),
        }
    }

    /// `ui::mfa::submit`: a TOTP or recovery code, throttled per user named by `factor_token`.
    async fn second_factor(&self, binding: FlowBinding<'_>, method: SubmitMethod) -> Response {
        let Some(user) = self.req.value("factor_token").and_then(|t| {
            flow_driver::open_factor_token(self.state(), self.tenant(), self.flow, &t)
        }) else {
            return problem(StatusCode::BAD_REQUEST, "invalid_flow_state");
        };
        let input = match method {
            SubmitMethod::RecoveryCode => FlowInput::RecoveryCode {
                code: self.req.value("recovery_code").unwrap_or_default(),
            },
            _ => FlowInput::Totp {
                code: self.req.value("code").unwrap_or_default(),
            },
        };
        let outcome = flow_driver::submit(
            self.state(),
            self.tenant(),
            self.ctx,
            self.flow,
            binding,
            Throttle::SecondFactor { user },
            input,
        )
        .await;
        // A lock after a failed code keeps the token of the user the flow counted.
        let token_user = match &outcome {
            DriveOutcome::Locked {
                attempt: Some(AuthAttempt::SecondFactorFailed { user }),
                ..
            } => *user,
            _ => user,
        };
        let token =
            flow_driver::seal_factor_token(self.state(), self.tenant(), self.flow, token_user);
        let extras = FormExtras {
            factor_token: token.clone(),
            ..FormExtras::default()
        };
        self.out.drive(self.flow, outcome, extras, token).await
    }

    /// `ui::email_code::request`: send a sign-in email, counted against the address.
    async fn email_code_request(&self, binding: FlowBinding<'_>) -> Response {
        let (state, tenant) = (self.state(), self.tenant());
        if !email_code_enabled(&tenant.tenant) {
            return problem(StatusCode::NOT_FOUND, "method_not_available");
        }
        let posted = self.req.value("email");
        let posted_token = self.req.value("factor_token");
        let ident = match &posted {
            Some(raw) => normalize_email(raw.trim())
                .ok()
                .map(|e| flow_driver::email_send_ident(&e)),
            None => match posted_token
                .as_deref()
                .and_then(|t| flow_driver::open_email_token(state, tenant, self.flow, t))
            {
                Some((_, ident)) => Some(ident),
                None => return problem(StatusCode::BAD_REQUEST, "invalid_flow_state"),
            },
        };
        let input = FlowInput::EmailCodeRequest { email: posted };
        let throttle = Throttle::EmailCodeSend { ident, ip: self.ip };
        let outcome =
            flow_driver::submit(state, tenant, self.ctx, self.flow, binding, throttle, input).await;
        let mut token = posted_token;
        if let (
            DriveOutcome::Flow {
                attempt: Some(AuthAttempt::EmailCodeSent { subject }),
                ..
            },
            Some(ident),
        ) = (&outcome, ident)
        {
            token = flow_driver::seal_email_token(state, tenant, self.flow, *subject, &ident);
        }
        let extras = FormExtras {
            factor_token: token,
            ..FormExtras::default()
        };
        self.out.drive(self.flow, outcome, extras, None).await
    }

    /// `ui::email_code::verify`: the emailed code, throttled per rate-limit subject.
    async fn email_code(&self, binding: FlowBinding<'_>) -> Response {
        let (state, tenant) = (self.state(), self.tenant());
        if !tenant.tenant.settings.email_otp {
            return problem(StatusCode::NOT_FOUND, "method_not_available");
        }
        let posted_token = self.req.value("factor_token").unwrap_or_default();
        let Some((subject, _)) =
            flow_driver::open_email_token(state, tenant, self.flow, &posted_token)
        else {
            return problem(StatusCode::BAD_REQUEST, "invalid_flow_state");
        };
        let input = FlowInput::EmailCode {
            code: self.req.value("code").unwrap_or_default(),
        };
        let outcome = flow_driver::submit(
            state,
            tenant,
            self.ctx,
            self.flow,
            binding,
            Throttle::EmailCode { subject },
            input,
        )
        .await;
        // The email step keeps its token; a second-factor or enrolment step after a right code
        // gets the second-factor token of the code's subject.
        let token = match carries_token(&outcome) {
            Some(id) if id != EMAIL_CODE_FORM_ID => {
                flow_driver::seal_factor_token(state, tenant, self.flow, subject)
            }
            _ => Some(posted_token.clone()),
        };
        let extras = FormExtras {
            factor_token: token,
            ..FormExtras::default()
        };
        self.out
            .drive(self.flow, outcome, extras, Some(posted_token))
            .await
    }
}

// ---------------------------------------------------------------------------------------------
// Passkeys (mirror `/ui/login/passkey*`, `/ui/login/enroll/passkey/*`,
// `/ui/login/second-factor/passkey/*`)
// ---------------------------------------------------------------------------------------------

/// The common extraction of the passkey routes.
fn passkey_parts(
    flow: &str,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(FlowId, String, PasskeyRequest), Refused> {
    let flow = parse_flow(flow)?;
    let csrf = csrf_header(headers)?;
    let req: PasskeyRequest = parse_body(body)?;
    Ok((flow, csrf, req))
}

/// WebAuthn options for a passkey ceremony of the flow (raw JSON for
/// `navigator.credentials.get/create`, after `PublicKeyCredential.parse*OptionsFromJSON`).
async fn options_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    flow: &str,
    headers: &HeaderMap,
    jar: &CookieJar,
    body: &Bytes,
    step: PasskeyStep,
) -> Response {
    let (flow, csrf, _) = match passkey_parts(flow, headers, body) {
        Ok(p) => p,
        Err(r) => return r.into_response(),
    };
    let binding = FlowBinding::Cookie { jar, csrf: &csrf };
    match flow_driver::passkey_options(state, tenant, flow, &binding, step).await {
        Ok(options) => {
            let mut resp = (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                options,
            )
                .into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            resp
        }
        Err(DriveRejection::Binding) => problem(StatusCode::FORBIDDEN, "csrf"),
        Err(DriveRejection::Failed(CoreError::InvalidRequest(_))) => {
            problem(StatusCode::BAD_REQUEST, "passkey_failed")
        }
        Err(DriveRejection::Failed(e)) => core_problem(&e),
    }
}

/// Discoverable passkey sign-in options (the sign-in or email-first step).
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/passkey/options",
    tag = "flows",
    operation_id = "passkeyOptions",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "WebAuthn request options (JSON)", body = Object),
        (status = 400, description = "passkey_failed (not a sign-in step)", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
pub(crate) async fn passkey_options(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    options_response(
        &state,
        &tenant,
        &flow,
        &headers,
        &jar,
        &body,
        PasskeyStep::SignIn,
    )
    .await
}

/// The passkey assertion of a sign-in (throttled per client IP, as the page).
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/passkey",
    tag = "flows",
    operation_id = "passkeyAssertion",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Completed, or the next step", body = FlowResponse),
        (status = 400, description = "The sign-in form with login.passkey_failed", body = FlowResponse),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 429, description = "Locked", body = FlowResponse),
    ),
    security(("csrf" = []))
)]
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
pub(crate) async fn passkey_assertion(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    let (flow, csrf, req) = match passkey_parts(&flow, &headers, &body) {
        Ok(p) => p,
        Err(r) => return r.into_response(),
    };
    let input = FlowInput::PasskeyAssertion {
        response_json: req.response.map(|v| v.to_string()).unwrap_or_default(),
    };
    let binding = FlowBinding::Cookie {
        jar: &jar,
        csrf: &csrf,
    };
    let outcome = flow_driver::submit(
        &state,
        &tenant,
        &ctx,
        flow,
        binding,
        Throttle::Passkey { ip },
        input,
    )
    .await;
    let out = Out {
        state: &state,
        tenant: &tenant,
        loc: &loc,
        kind: FlowKindDto::Login,
    };
    out.drive(flow, outcome, FormExtras::default(), None).await
}

/// Finishes an in-flow passkey ceremony (enrolment or second factor).
#[expect(
    clippy::too_many_arguments,
    reason = "the two finish routes share one body; the extractors travel with it"
)]
async fn finish_response(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    ctx: &RequestContext,
    headers: &HeaderMap,
    jar: &CookieJar,
    flow: &str,
    body: &Bytes,
    which: InFlowPasskey,
) -> Response {
    let (flow, csrf, req) = match passkey_parts(flow, headers, body) {
        Ok(p) => p,
        Err(r) => return r.into_response(),
    };
    let binding = FlowBinding::Cookie { jar, csrf: &csrf };
    let response = req.response.map(|v| v.to_string()).unwrap_or_default();
    let result =
        match flow_driver::passkey_finish(state, tenant, ctx, flow, &binding, which, &response)
            .await
        {
            Ok(r) => r,
            Err(r) => return rejection(r),
        };
    let out = Out {
        state,
        tenant,
        loc,
        kind: FlowKindDto::Login,
    };
    // A refused ceremony shows the step again; it keeps the posted token.
    let extras = FormExtras {
        factor_token: req.factor_token.filter(|t| !t.is_empty()),
        ..FormExtras::default()
    };
    out.outcome(flow, result.outcome, extras).await
}

/// Passkey creation options at the enrolment step.
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/enroll/passkey/start",
    tag = "flows",
    operation_id = "enrolmentPasskeyStart",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "WebAuthn creation options (JSON)", body = Object),
        (status = 400, description = "passkey_failed (not the enrolment step)", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
pub(crate) async fn enrolment_passkey_start(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    options_response(
        &state,
        &tenant,
        &flow,
        &headers,
        &jar,
        &body,
        PasskeyStep::Enrolment,
    )
    .await
}

/// The registration response at the enrolment step.
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/enroll/passkey/finish",
    tag = "flows",
    operation_id = "enrolmentPasskeyFinish",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Completed", body = FlowResponse),
        (status = 400, description = "The enrolment form with mfa_enroll.passkey_failed", body = FlowResponse),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
pub(crate) async fn enrolment_passkey_finish(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    finish_response(
        &state,
        &tenant,
        &loc,
        &ctx,
        &headers,
        &jar,
        &flow,
        &body,
        InFlowPasskey::Enrolment,
    )
    .await
}

/// Passkey request options at the second-factor step.
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/second-factor/passkey/start",
    tag = "flows",
    operation_id = "secondFactorPasskeyStart",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "WebAuthn request options (JSON)", body = Object),
        (status = 400, description = "passkey_failed (not a second-factor step with a passkey)", body = super::dto::FlowProblem, content_type = "application/problem+json"),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
pub(crate) async fn second_factor_passkey_start(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    options_response(
        &state,
        &tenant,
        &flow,
        &headers,
        &jar,
        &body,
        PasskeyStep::SecondFactor,
    )
    .await
}

/// The assertion at the second-factor step.
#[utoipa::path(
    post,
    path = "/api/flows/v1/login/{flow_id}/second-factor/passkey/finish",
    tag = "flows",
    operation_id = "secondFactorPasskeyFinish",
    params(("flow_id" = String, Path, description = "Flow id")),
    request_body(content = PasskeyRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Completed", body = FlowResponse),
        (status = 400, description = "The second-factor form with second_factor.passkey_failed", body = FlowResponse),
        (status = 403, description = "csrf or forbidden_origin", body = super::dto::FlowProblem, content_type = "application/problem+json"),
    ),
    security(("csrf" = []))
)]
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
pub(crate) async fn second_factor_passkey_finish(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    headers: HeaderMap,
    jar: CookieJar,
    Path(flow): Path<String>,
    body: Bytes,
) -> Response {
    finish_response(
        &state,
        &tenant,
        &loc,
        &ctx,
        &headers,
        &jar,
        &flow,
        &body,
        InFlowPasskey::SecondFactor,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse_and_unknown_is_not_found() {
        assert_eq!(parse_kind("login").ok(), Some(FlowKindDto::Login));
        assert_eq!(parse_kind("recovery").ok(), Some(FlowKindDto::Recovery));
        assert!(parse_kind("setup").is_err());
        assert!(parse_kind("settings").is_err());
    }

    #[test]
    fn every_method_belongs_to_one_kind() {
        assert_eq!(method_kind(SubmitMethod::Password), FlowKindDto::Login);
        assert_eq!(
            method_kind(SubmitMethod::Register),
            FlowKindDto::Registration
        );
        assert_eq!(
            method_kind(SubmitMethod::RecoveryReset),
            FlowKindDto::Recovery
        );
        assert_eq!(method_kind(SubmitMethod::Verify), FlowKindDto::Verification);
    }

    #[test]
    fn csrf_header_is_required_and_not_blank() {
        let mut h = HeaderMap::new();
        assert!(csrf_header(&h).is_err());
        h.insert(CSRF_HEADER, HeaderValue::from_static("  "));
        assert!(csrf_header(&h).is_err());
        h.insert(CSRF_HEADER, HeaderValue::from_static("tok"));
        assert_eq!(csrf_header(&h).ok().as_deref(), Some("tok"));
    }

    #[test]
    fn empty_body_is_the_default_and_bad_json_is_refused() {
        let r: StartRequest = parse_body(&Bytes::from_static(b"  ")).expect("default");
        assert!(r.request.is_none());
        assert!(parse_body::<StartRequest>(&Bytes::from_static(b"{nope")).is_err());
    }
}
