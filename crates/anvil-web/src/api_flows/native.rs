//! Native-app mode of the headless flow API (UI-05, decision Q6): a first-party native app
//! drives sign-in through the same `/api/flows/v1` routes without cookies, CSRF tokens or a
//! browser session. See docs/HEADLESS.md ("Native apps").
//!
//! The shape follows the IETF draft "OAuth 2.0 for First-Party Applications" (an Internet-Draft,
//! not an RFC; this is AnvilID's own API and claims no conformance to it):
//!
//! 1. The app pushes its authorization request with a PKCE challenge to `POST {issuer}/par`
//!    (RFC 9126) and receives a single-use `request_uri`.
//! 2. `POST /api/flows/v1/login` with `{"client_id", "request_uri"}` starts a token-bound login
//!    flow. The client must be eligible (`service::authorize::native_eligible`: flagged
//!    `headless_native` by an administrator, first-party, PKCE required, never DCR or CIMD).
//!    The pushed request is resumed through `AuthorizeService::start_native`, which calls the
//!    same `resume_pushed_request` as `/authorize`, so it is consumed once. The answer carries
//!    the `flow_token` once.
//! 3. `GET`/`POST /api/flows/v1/login/{flow_id}` with `Authorization: AnvilFlow <flow_token>`
//!    read and submit the steps. Every submission runs through `ui::flow_driver` with
//!    `FlowBinding::Token`: the same brute-force gate, limiter keys, lockout and audit as the
//!    pages and the browser mode. The flow stores only the token's hash and refuses the cookie
//!    binding.
//! 4. The completed sign-in answers `result: {code, iss, state}` (`AuthorizeService::complete`,
//!    the same decision and code issuance as the redirect). The app redeems the code at
//!    `/token` with its `code_verifier`. No session cookie is ever sent.
//!
//! # Mode selection
//!
//! A start body with `client_id` or `request_uri`, or any request with an
//! `Authorization: AnvilFlow …` header, is native; everything else is browser mode. Native
//! requests must carry no browser signal (`Origin`, `Sec-Fetch-Site`): a browser page cannot use
//! this mode, and the browser CORS allow-list never applies to it (a native request has no
//! `Origin`, and a cross-origin page could not send `Authorization` past the preflight).
//!
//! # What needs a browser
//!
//! CAPTCHA demands, upstream, SAML and enterprise single sign-on, passkeys, the emailed sign-in
//! link, registration (`prompt=create`) and every authorization page after sign-in (consent,
//! account or organization choice, step-up) answer `step: browser_required` with
//! `{issuer}/authorize/continue?request=…`: the app opens it in the system browser (RFC 8252)
//! and the same authorization request finishes there, delivering the code to the app's
//! redirect URI.

use std::net::IpAddr;

use anvil_core::model::{AuthRequestId, BrowserSession, FlowId, RequestContext};
use anvil_core::oauth::authorize_request::PROMPT_CREATE;
use anvil_core::service::authorize::{Completion, NativeStartRefused};
use anvil_core::service::flow::{Continue, LoginStart};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use secrecy::{ExposeSecret as _, SecretString};

use super::browser::{Out, core_problem, dispatch, json, parse_body, parse_flow, parse_kind};
use super::dto::{FlowKindDto, FlowResponse, FormExtras, ResultDto, StartRequest, Step};
use super::problem;
use crate::i18n::{Locale, carry_ui_locales};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;
use crate::ui::flow_driver::{self, FlowBinding};

/// The `Authorization` scheme of the flow token.
pub const SCHEME: &str = "AnvilFlow";

/// Problem code of a missing, malformed or wrong flow token.
pub(super) const FLOW_TOKEN_PROBLEM: &str = "flow_token";

/// The request parts every native handler needs.
pub(super) struct NativeRequest<'a> {
    pub(super) state: &'a AppState,
    pub(super) tenant: &'a ResolvedTenant,
    pub(super) loc: &'a Locale,
    pub(super) headers: &'a HeaderMap,
}

impl<'a> NativeRequest<'a> {
    /// The native encoding context for a flow of `kind`.
    fn out(&self, kind: FlowKindDto) -> Out<'a> {
        Out {
            state: self.state,
            tenant: self.tenant,
            loc: self.loc,
            kind,
            native: true,
        }
    }
}

/// Whether an `Authorization` header with the [`SCHEME`] scheme selects native mode.
pub(super) fn selected(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .any(|v| scheme_of(v.as_bytes()).is_some())
}

/// The credentials after the [`SCHEME`] scheme (case-insensitive) and one or more spaces.
fn scheme_of(value: &[u8]) -> Option<&[u8]> {
    let n = SCHEME.len();
    if value.len() < n || !value[..n].eq_ignore_ascii_case(SCHEME.as_bytes()) {
        return None;
    }
    let rest = &value[n..];
    match rest.first() {
        None => Some(rest),
        Some(b' ') => Some(rest.trim_ascii_start()),
        Some(_) => None,
    }
}

/// A native request refused before the driver runs: the status and problem code. A 401 also
/// names the [`SCHEME`] in `WWW-Authenticate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal(StatusCode, &'static str);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut resp = problem(self.0, self.1);
        if self.0 == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static(SCHEME),
            );
        }
        resp
    }
}

impl From<super::browser::Refused> for Refusal {
    fn from(r: super::browser::Refused) -> Self {
        Self(r.0, r.1)
    }
}

/// The flow token of the single `Authorization: AnvilFlow <token>` header. A repeated header,
/// an empty token, or a token with characters outside base64url is 401 `flow_token`.
fn flow_token(headers: &HeaderMap) -> Result<String, Refusal> {
    let refused = Refusal(StatusCode::UNAUTHORIZED, FLOW_TOKEN_PROBLEM);
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(refused);
    };
    let token = scheme_of(value.as_bytes()).ok_or(refused)?;
    let valid = !token.is_empty()
        && token.len() <= 128
        && token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_');
    if !valid {
        return Err(refused);
    }
    // Checked as ASCII above.
    Ok(String::from_utf8_lossy(token).into_owned())
}

/// Native mode refuses requests a browser would send (`Origin` or `Sec-Fetch-Site`).
fn browser_signals(headers: &HeaderMap) -> bool {
    headers.contains_key(header::ORIGIN) || headers.contains_key("sec-fetch-site")
}

/// Problem code of a native request with a browser signal.
const BROWSER_SIGNALS_PROBLEM: &str = "browser_signals";

/// 403 `browser_signals`.
fn browser_refused() -> Response {
    problem(StatusCode::FORBIDDEN, BROWSER_SIGNALS_PROBLEM)
}

// ---------------------------------------------------------------------------------------------
// Start, current step, submit
// ---------------------------------------------------------------------------------------------

/// `POST /api/flows/v1/login` with `{client_id, request_uri}`: the PAR-bound native start.
pub(super) async fn start(
    req: NativeRequest<'_>,
    kind: FlowKindDto,
    body: &StartRequest,
) -> Response {
    if browser_signals(req.headers) {
        return browser_refused();
    }
    let (Some(client_id), Some(request_uri)) = (
        body.client_id
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty()),
        body.request_uri
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty()),
    ) else {
        return problem(StatusCode::BAD_REQUEST, "invalid_request");
    };
    // Login only, and nothing of the browser start mixed in.
    if kind != FlowKindDto::Login || body.request.is_some() || body.token.is_some() {
        return problem(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let (state, tenant) = (req.state, req.tenant);
    let resumed = match state
        .authorize_service()
        .start_native(&tenant.tenant, &tenant.issuer, client_id, request_uri)
        .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(NativeStartRefused::NotEligible)) => {
            return problem(StatusCode::FORBIDDEN, "client_not_eligible");
        }
        Ok(Err(NativeStartRefused::PkceRequired)) => {
            return problem(StatusCode::BAD_REQUEST, "pkce_required");
        }
        Ok(Err(NativeStartRefused::Pushed(_))) => {
            return problem(StatusCode::BAD_REQUEST, "invalid_request_uri");
        }
        Err(e) => return core_problem(&e),
    };
    let out = req.out(kind);
    let prompt = &resumed.params.prompt;
    if prompt.iter().any(|p| p == "none") {
        // An interactive sign-in can never answer prompt=none.
        return problem(StatusCode::BAD_REQUEST, "login_required");
    }
    if prompt.iter().any(|p| p == PROMPT_CREATE) {
        return browser_required_url(&out, None, Some(resumed.request_id)).await;
    }
    match flow_driver::start_native_login(state, tenant, resumed.request_id).await {
        Ok(LoginStart::Form(started)) => {
            let extras = FormExtras {
                flow_token: Some(started.cookie_token.expose_secret().to_owned()),
                ..FormExtras::default()
            };
            out.form(
                started.flow_id,
                started.form,
                StatusCode::OK,
                extras,
                CookieJar::new(),
            )
            .await
        }
        // A direct start at an org IdP: the system browser runs it.
        Ok(LoginStart::Idp { started, .. }) => {
            browser_required_url(&out, Some(started.flow_id), Some(resumed.request_id)).await
        }
        Err(e) => core_problem(&e),
    }
}

/// The checks every native request about a flow makes: no browser signals, the flow token, the
/// login kind and a well-formed flow id.
fn flow_request(
    headers: &HeaderMap,
    kind: &str,
    flow: &str,
) -> Result<(String, FlowKindDto, FlowId), Refusal> {
    if browser_signals(headers) {
        return Err(Refusal(StatusCode::FORBIDDEN, BROWSER_SIGNALS_PROBLEM));
    }
    let token = flow_token(headers)?;
    let kind = parse_kind(kind)?;
    if kind != FlowKindDto::Login {
        return Err(Refusal(StatusCode::BAD_REQUEST, "method_not_available"));
    }
    let flow = parse_flow(flow)?;
    Ok((token, kind, flow))
}

/// `GET /api/flows/v1/login/{flow_id}` with the flow token: the current step.
pub(super) async fn get_flow(req: NativeRequest<'_>, kind: &str, flow: &str) -> Response {
    let (token, kind, flow) = match flow_request(req.headers, kind, flow) {
        Ok(parts) => parts,
        Err(refusal) => return refusal.into_response(),
    };
    let out = req.out(kind);
    let binding = FlowBinding::Token { token: &token };
    match flow_driver::current_step(req.state, req.tenant, flow, &binding).await {
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
        Err(r) => out.reject(r),
    }
}

/// `POST /api/flows/v1/login/{flow_id}` with the flow token: submits the current step through
/// the same dispatch (driver calls, throttle classes) as the browser mode.
pub(super) async fn submit_flow(
    req: NativeRequest<'_>,
    ip: IpAddr,
    ctx: &RequestContext,
    kind: &str,
    flow: &str,
    body: &Bytes,
) -> Response {
    let (token, kind, flow) = match flow_request(req.headers, kind, flow) {
        Ok(parts) => parts,
        Err(refusal) => return refusal.into_response(),
    };
    let submission = match parse_body(body) {
        Ok(s) => s,
        Err(r) => return r.into_response(),
    };
    let out = req.out(kind);
    dispatch(
        &out,
        ctx,
        flow,
        ip,
        &submission,
        FlowBinding::Token { token: &token },
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Encoding (called by the shared `Out` in native mode)
// ---------------------------------------------------------------------------------------------

/// `browser_required` in native mode: the authorization URL of the flow's request, opened in the
/// system browser (RFC 8252). `request` is the flow's authorization request when the caller
/// knows it (otherwise it is read from the flow).
pub(super) async fn browser_required(
    out: &Out<'_>,
    flow: FlowId,
    request: Option<AuthRequestId>,
) -> Response {
    let request = match request {
        Some(r) => Some(r),
        None => flow_driver::flow_meta(out.state, out.tenant, flow)
            .await
            .ok()
            .flatten()
            .and_then(|m| m.request),
    };
    browser_required_url(out, Some(flow), request).await
}

/// The `browser_required` answer for `request` (`flow`: the flow it belongs to, if any).
async fn browser_required_url(
    out: &Out<'_>,
    flow: Option<FlowId>,
    request: Option<AuthRequestId>,
) -> Response {
    let url = match request {
        Some(r) => format!("{}/authorize/continue?request={r}", out.tenant.issuer),
        None => out.tenant.ui_url("/ui/login"),
    };
    let flow_ref = match flow {
        Some(f) => out.flow_ref(f).await,
        None => super::dto::FlowRef {
            id: String::new(),
            kind: out.kind,
            expires_at: None,
        },
    };
    let body = FlowResponse {
        flow: flow_ref,
        step: Step::BrowserRequired,
        csrf_token: None,
        flow_token: None,
        form: None,
        message: None,
        result: None,
        url: Some(carry_ui_locales(&url, out.loc)),
        retry_after: None,
    };
    json(StatusCode::OK, &body, CookieJar::new())
}

/// A completed native sign-in: completes the flow's authorization request with the server-side
/// session the sign-in created (`AuthorizeService::complete`, the redirect's code issuance) and
/// answers the code as JSON. The session cookie is never sent.
pub(super) async fn completed(
    out: &Out<'_>,
    flow: FlowId,
    session: BrowserSession,
    continue_to: Option<Continue>,
    recovery_codes: &[SecretString],
) -> Response {
    let Some(Continue::Authorize(request)) = continue_to else {
        return core_problem(&anvil_core::error::CoreError::Internal(
            "a native sign-in without its authorization request".into(),
        ));
    };
    let tenant = out.tenant;
    let completion = match out
        .state
        .authorize_service()
        .complete(&tenant.tenant, &tenant.issuer, request, session)
        .await
    {
        Ok(c) => c,
        Err(e) => return core_problem(&e),
    };
    let recovery_codes: Vec<String> = recovery_codes
        .iter()
        .map(|c| c.expose_secret().to_owned())
        .collect();
    let (status, result) = match completion {
        Completion::Code { code, iss, state } => (
            StatusCode::OK,
            ResultDto {
                code: Some(code.expose_secret().to_owned()),
                iss: Some(iss),
                state,
                recovery_codes,
                ..ResultDto::default()
            },
        ),
        Completion::Error {
            error,
            error_description,
            state,
            iss,
        } => (
            StatusCode::BAD_REQUEST,
            ResultDto {
                iss: Some(iss),
                state,
                error: Some(error),
                error_description,
                recovery_codes,
                ..ResultDto::default()
            },
        ),
        Completion::Interaction(anvil_core::service::authorize::AuthorizeOutcome::ErrorPage {
            ..
        }) => return problem(StatusCode::BAD_REQUEST, "authorization_failed"),
        // Consent, an account or organization choice, a step-up: the system browser continues.
        Completion::Interaction(_) => {
            return browser_required_url(out, None, Some(request)).await;
        }
    };
    let body = FlowResponse {
        flow: super::dto::FlowRef {
            id: flow.0.to_string(),
            kind: out.kind,
            expires_at: None,
        },
        step: Step::Completed,
        csrf_token: None,
        flow_token: None,
        form: None,
        message: None,
        result: Some(result),
        url: None,
        retry_after: None,
    };
    json(status, &body, CookieJar::new())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn the_anvilflow_scheme_selects_native_mode() {
        assert!(selected(&headers(&[("authorization", "AnvilFlow abc")])));
        assert!(selected(&headers(&[("authorization", "anvilflow abc")])));
        assert!(selected(&headers(&[("authorization", "AnvilFlow")])));
        assert!(!selected(&headers(&[("authorization", "Bearer abc")])));
        assert!(!selected(&headers(&[("authorization", "AnvilFlowabc")])));
        assert!(!selected(&HeaderMap::new()));
    }

    #[test]
    fn flow_token_must_be_a_single_base64url_value() {
        let ok = flow_token(&headers(&[("authorization", "AnvilFlow ab-c_9")])).unwrap();
        assert_eq!(ok, "ab-c_9");
        for bad in [
            "AnvilFlow",
            "AnvilFlow ",
            "AnvilFlow a b",
            "AnvilFlow a=b",
            "Bearer x",
        ] {
            let refused = flow_token(&headers(&[("authorization", bad)])).unwrap_err();
            assert_eq!(refused.0, StatusCode::UNAUTHORIZED, "{bad}");
            let resp = refused.into_response();
            assert_eq!(resp.headers()[header::WWW_AUTHENTICATE], SCHEME);
        }
        let twice = headers(&[
            ("authorization", "AnvilFlow a"),
            ("authorization", "AnvilFlow a"),
        ]);
        assert!(flow_token(&twice).is_err());
        let long = format!("AnvilFlow {}", "a".repeat(129));
        assert!(flow_token(&headers(&[("authorization", &long)])).is_err());
    }

    #[test]
    fn browser_signals_are_origin_and_fetch_metadata() {
        assert!(browser_signals(&headers(&[(
            "origin",
            "https://app.example"
        )])));
        assert!(browser_signals(&headers(&[("sec-fetch-site", "none")])));
        assert!(!browser_signals(&headers(&[("user-agent", "MyApp/1.0")])));
    }
}
