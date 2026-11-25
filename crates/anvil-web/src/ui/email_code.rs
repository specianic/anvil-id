//! Email one-time code and magic-link sign-in (AUTH-06).
//!
//! | Route | |
//! |---|---|
//! | `POST /ui/login/email-code?flow=` | `email` (from the sign-in page), or nothing plus `factor_token` (a new code from the email page) |
//! | `POST /ui/login/email-code/verify?flow=` | `code` plus `factor_token` |
//! | `GET  /ui/login/email-link?flow=&token=` | the emailed link: only a "Continue signing in" button (consumes nothing) |
//! | `POST /ui/login/email-link?flow=` | `token` plus the page's `csrf_token`: consumes the link in the browser holding the flow cookie |
//!
//! Every route answers 404 unless the tenant enables `email_otp` or `magic_link`. The sign-in
//! page offers "Email me a sign-in code" (prefilled from a `login_hint` email address). Asking
//! for a code always shows the same "if an account exists for that address, we sent a code" page;
//! only an active account gets the email (`flow::email_code`, `FlowService` module docs).
//!
//! # Limiter
//!
//! Through the one limiter ([`guard_attempt`] / [`record_attempt`]); the route-class layer limits
//! every POST here per IP (auth class). A send is counted against the address: the strict tier
//! keyed by (address, IP) locks progressively, the loose tier keyed by the address alone (from any
//! IP) escalates to a delay and never locks. Code attempts are counted per user
//! ([`LimitKey::User`], shared with the second factor). The handlers cannot read the flow state,
//! so the email page carries a `factor_token`: the rate-limit subject (the user, or a keyed pseudo
//! id for an address without an account) and the address hash, sealed with the KEK (purpose
//! [`EMAIL_TOKEN_PURPOSE`], AAD tenant and flow). It names limiter keys only; the flow state
//! decides everything else. A missing or tampered token restarts the sign-in.
//!
//! # Magic link
//!
//! The link page is `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the URL carries
//! the token). Its form posts the token with a CSRF token derived from the flow and the token
//! (`flow::email_code::link_csrf`); the flow cookie (SameSite=Strict, not sent when the email
//! client opens the link, sent with the page's own POST) proves the browser. Without it the answer
//! is "open the link in the browser where you started, or type the code" and nothing is consumed.

use anvil_cache::limiter::{Decision, LimitKey};
use anvil_core::error::CoreError;
use anvil_core::flow::email_code::{EMAIL_CODE_FORM_ID, OTHER_BROWSER, link_csrf};
use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{FlowId, TenantId, UserId, normalize_email};
use anvil_core::service::flow::{
    AuthAttempt, EmailLinkOutcome, FlowContext, FlowOutcome, email_code_enabled,
};
use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;

use super::login::{
    Extras, UiForm, UiQuery, bad_form, csrf_page, current_browser_session, factor_token,
    locked_page, message_page, outcome_response_with, restart_login, started_response_with,
    submit_flow, tenant_relying_party, ui_base,
};
use crate::client_ip::ClientIp;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::layers::ratelimit::{
    Surface, guard_attempt, identifier_hash, record_attempt, too_many_requests,
};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// KEK purpose of the email page's limiter token.
pub const EMAIL_TOKEN_PURPOSE: &str = "anvilid/email-code-limit/v1";

/// Email code routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/ui/login/email-code", post(request))
        .route("/ui/login/email-code/verify", post(verify))
        .route("/ui/login/email-link", get(link_page).post(link_submit))
}

fn token_aad(tenant: TenantId, flow: FlowId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(flow.0.as_bytes());
    aad
}

/// Seals the limiter subject and the address hash for the email page of `flow`.
fn seal_email_token(
    kek: &Kek,
    tenant: TenantId,
    flow: FlowId,
    subject: UserId,
    ident: &[u8; 32],
) -> Option<String> {
    let mut plain = Vec::with_capacity(48);
    plain.extend_from_slice(subject.0.as_bytes());
    plain.extend_from_slice(ident);
    kek.seal(EMAIL_TOKEN_PURPOSE, &token_aad(tenant, flow), &plain)
        .inspect_err(|e| tracing::error!(error = %e, "sealing the email code token failed"))
        .ok()
        .map(|s| b64url(&s))
}

/// The subject and address hash an email page token names, if it opens for this tenant and flow.
fn open_email_token(
    kek: &Kek,
    tenant: TenantId,
    flow: FlowId,
    token: &str,
) -> Option<(UserId, [u8; 32])> {
    let sealed = b64url_decode(token).ok()?;
    let plain = kek
        .open(EMAIL_TOKEN_PURPOSE, &token_aad(tenant, flow), &sealed)
        .ok()?;
    if plain.len() != 48 {
        return None;
    }
    let subject = UserId(uuid::Uuid::from_slice(&plain[..16]).ok()?);
    let mut ident = [0u8; 32];
    ident.copy_from_slice(&plain[16..]);
    Some((subject, ident))
}

/// The limiter hash of a normalised address for sends (its own namespace: sends never count
/// against the password sign-in of the same identifier).
fn send_ident(email: &str) -> [u8; 32] {
    identifier_hash(&format!("email-code:{email}"))
}

fn not_found(state: &AppState, tenant: &ResolvedTenant, loc: &Locale) -> Response {
    error_page_in(
        state,
        Some(tenant),
        loc,
        StatusCode::NOT_FOUND,
        "not_found",
        "",
    )
}

/// `POST /ui/login/email-code?flow=`: send a sign-in email (module docs).
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn request(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    ClientIp(ip): ClientIp,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !email_code_enabled(&tenant.tenant) {
        return not_found(&state, &tenant, &loc);
    }
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &loc);
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let tenant_id = tenant.tenant.id;
    let posted = form.email.clone().filter(|e| !e.trim().is_empty());
    // The address the send counts against: the posted one, or (a new code) the token's.
    let ident = match &posted {
        Some(raw) => normalize_email(raw.trim()).ok().map(|e| send_ident(&e)),
        None => match form
            .factor_token
            .as_deref()
            .and_then(|t| open_email_token(state.kek(), tenant_id, flow_id, t))
        {
            Some((_, ident)) => Some(ident),
            None => return restart_login(&state, &tenant, &loc).await,
        },
    };
    let keys = ident.map(|ident| {
        [
            LimitKey::IdentIp {
                tenant: tenant_id,
                ident,
                ip,
            },
            LimitKey::Identifier {
                tenant: tenant_id,
                ident,
            },
        ]
    });
    if let Some([strict, loose]) = &keys
        && let Decision::Deny { retry_after } = guard_attempt(&state, strict, loose, false).await
    {
        return too_many_requests(&state, Some(&tenant), Surface::Browser, retry_after);
    }
    let input = FlowInput::EmailCodeRequest { email: posted };
    let result = match submit_flow(&state, &tenant, &loc, &ctx, &jar, flow_id, csrf, input).await {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let mut token = form.factor_token.clone();
    if let (Some(AuthAttempt::EmailCodeSent { subject }), Some(keys), Some(ident)) =
        (result.attempt, &keys, ident)
    {
        // Every send counts against the address (it never "succeeds" for the limiter).
        record_attempt(&state, tenant_id, &ctx, keys, false).await;
        token = seal_email_token(state.kek(), tenant_id, flow_id, subject, &ident);
    }
    let extras = Extras {
        factor_token: token,
        ..Extras::default()
    };
    outcome_response_with(&state, &tenant, &loc, result.outcome, &extras)
}

/// `POST /ui/login/email-code/verify?flow=`: the code from the email (module docs).
async fn verify(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !email_code_enabled(&tenant.tenant) {
        return not_found(&state, &tenant, &loc);
    }
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &loc);
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let tenant_id = tenant.tenant.id;
    let posted_token = form.factor_token.clone().unwrap_or_default();
    let Some((subject, _)) = open_email_token(state.kek(), tenant_id, flow_id, &posted_token)
    else {
        return restart_login(&state, &tenant, &loc).await;
    };
    let key = LimitKey::User {
        tenant: tenant_id,
        user: subject,
    };
    if let Decision::Deny { retry_after } = guard_attempt(&state, &key, &key, false).await {
        return too_many_requests(&state, Some(&tenant), Surface::Browser, retry_after);
    }
    let input = FlowInput::EmailCode {
        code: form.code.clone().unwrap_or_default(),
    };
    let result = match submit_flow(&state, &tenant, &loc, &ctx, &jar, flow_id, csrf, input).await {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    match result.attempt {
        Some(AuthAttempt::EmailCodeFailed { .. }) => {
            record_attempt(&state, tenant_id, &ctx, std::slice::from_ref(&key), false).await;
            if let (Decision::Deny { retry_after }, FlowOutcome::Render(form)) = (
                guard_attempt(&state, &key, &key, false).await,
                &result.outcome,
            ) {
                return locked_page(
                    &state,
                    &tenant,
                    &loc,
                    form.clone(),
                    retry_after,
                    Some(posted_token),
                );
            }
        }
        Some(AuthAttempt::EmailCodeSucceeded { .. }) => {
            record_attempt(&state, tenant_id, &ctx, std::slice::from_ref(&key), true).await;
        }
        _ => {}
    }
    // The email page keeps its token; a second-factor or enrolment page that follows a right
    // code gets the second-factor token of the user (the subject of a right code).
    let next_form_id = match &result.outcome {
        FlowOutcome::Render(f) | FlowOutcome::Enroll { form: f, .. } => Some(f.id.as_str()),
        _ => None,
    };
    let token = match next_form_id {
        Some(id) if id != EMAIL_CODE_FORM_ID => factor_token(&state, &tenant, flow_id, subject),
        _ => Some(posted_token),
    };
    let extras = Extras {
        factor_token: token,
        ..Extras::default()
    };
    outcome_response_with(&state, &tenant, &loc, result.outcome, &extras)
}

/// `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the page URL carries the token).
fn link_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// `GET /ui/login/email-link?flow=&token=`: the "Continue signing in" button. Consumes nothing.
async fn link_page(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    if !email_code_enabled(&tenant.tenant) {
        return link_headers(not_found(&state, &tenant, &loc));
    }
    let (Some(flow_id), Some(token)) = (q.flow_id(), q.token()) else {
        return link_headers(bad_form(&state, &tenant, &loc));
    };
    if token.len() > 128 {
        return link_headers(bad_form(&state, &tenant, &loc));
    }
    let csrf = link_csrf(state.kek(), flow_id, &token);
    let mut page = PageContext::for_tenant(&state, &tenant, &loc, "title.magic_link");
    page.links.login = Some(carry_ui_locales(&tenant.ui_url("/ui/login"), &loc));
    let action = carry_ui_locales(
        &format!("{}/login/email-link?flow={flow_id}", ui_base(&tenant)),
        &loc,
    );
    let ctx = minijinja::context! {
        page => page.into_value(),
        action => action,
        csrf_token => csrf,
        token => token,
    };
    let resp = match state.renderer().page("magic_link.html", ctx) {
        Ok(html) => axum::response::IntoResponse::into_response((StatusCode::OK, html)),
        Err(e) => {
            tracing::error!(error = %e, "rendering the magic link page failed");
            core_error_page_in(
                &state,
                Some(&tenant),
                &loc,
                &CoreError::Internal("render".into()),
            )
        }
    };
    link_headers(resp)
}

/// `POST /ui/login/email-link?flow=`: consume the link in the browser that started the sign-in.
async fn link_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !email_code_enabled(&tenant.tenant) {
        return not_found(&state, &tenant, &loc);
    }
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &loc);
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let token = form.token.clone().unwrap_or_default();
    if token.is_empty() || token.len() > 128 {
        return bad_form(&state, &tenant, &loc);
    }
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let session = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s.map(|s| s.id),
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let outcome = match state
        .ui_flow_service()
        .email_link(&cx, flow_id, cookie.as_deref(), csrf, &token, session)
        .await
    {
        Ok(o) => o,
        Err(CoreError::Forbidden) => return csrf_page(&state, Some(&tenant), &loc),
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    match outcome {
        EmailLinkOutcome::Done(outcome) => {
            outcome_response_with(&state, &tenant, &loc, outcome, &Extras::default())
        }
        EmailLinkOutcome::Continue(started) => {
            let extras = Extras {
                factor_token: started
                    .factor_user
                    .and_then(|user| factor_token(&state, &tenant, started.flow_id, user)),
                totp: started.totp.as_ref(),
                ..Extras::default()
            };
            started_response_with(
                &state,
                &tenant,
                &loc,
                &started,
                None,
                StatusCode::OK,
                &extras,
            )
        }
        EmailLinkOutcome::OtherBrowser => rejected(&state, &tenant, &loc, OTHER_BROWSER),
        EmailLinkOutcome::Rejected(key) => rejected(&state, &tenant, &loc, key),
    }
}

/// A link that does not sign in: the message page with `key`, 400, nothing changed.
fn rejected(state: &AppState, tenant: &ResolvedTenant, loc: &Locale, key: &str) -> Response {
    let mut resp = message_page(state, tenant, loc, key, CookieJar::new());
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_token_is_bound_to_tenant_flow_and_kek() {
        let kek = Kek::generate();
        let (t, f, u) = (TenantId::new_v7(), FlowId::new_v7(), UserId::new_v7());
        let ident = [7u8; 32];
        let tok = seal_email_token(&kek, t, f, u, &ident).expect("seal");
        assert_eq!(open_email_token(&kek, t, f, &tok), Some((u, ident)));
        assert_eq!(open_email_token(&kek, t, FlowId::new_v7(), &tok), None);
        assert_eq!(open_email_token(&kek, TenantId::new_v7(), f, &tok), None);
        assert_eq!(open_email_token(&Kek::generate(), t, f, &tok), None);
        assert_eq!(open_email_token(&kek, t, f, "garbage"), None);
        // The second-factor token does not open as an email token.
        let other = super::super::mfa::seal_factor_token(&kek, t, f, u).expect("seal");
        assert_eq!(open_email_token(&kek, t, f, &other), None);
    }

    #[test]
    fn send_ident_is_namespaced_and_normalised() {
        assert_eq!(send_ident("a@b.c"), send_ident("A@B.C"));
        assert_ne!(send_ident("a@b.c"), identifier_hash("a@b.c"));
    }
}
