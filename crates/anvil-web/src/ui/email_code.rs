//! Email one-time code and magic-link sign-in (AUTH-06).
//!
//! | Route | |
//! |---|---|
//! | `POST /ui/login/email-code?flow=` | `email` (from the sign-in page), or nothing plus `factor_token` (a new code from the email page), or nothing at all (the "Email me a code" button of a link confirmation whose matching account may not be revealed: counted against the pending link's upstream address) |
//! | `POST /ui/login/email-code/verify?flow=` | `code` plus `factor_token` |
//! | `GET  /ui/login/email-link?flow=&token=` | the emailed link: only a "Continue signing in" button (consumes nothing) |
//! | `POST /ui/login/email-link?flow=` | `token` plus the page's `csrf_token`: consumes the link in the browser holding the flow cookie |
//!
//! The two tenant settings are enforced separately: sending (and "Send a new email") answers 404
//! unless `email_otp` or `magic_link` is on, the code route unless `email_otp` is on, and both
//! link routes unless `magic_link` is on. The email carries only the enabled methods, and the core
//! refuses a method the email did not carry (`flow::email_code`). The sign-in page offers email
//! sign-in when either is on (prefilled from a `login_hint` email address). Asking for an email
//! always shows the same "if an account exists for that address, we sent a sign-in email" page;
//! only an active account gets the email (`FlowService` module docs). With the link only, that
//! page has no code field.
//!
//! # Limiter
//!
//! Through the one limiter, driven by [`super::flow_driver`]; the route-class layer limits
//! every POST here per IP (auth class). A send is counted against the address: the strict tier
//! keyed by (address, IP) locks progressively, the loose tier keyed by the address alone (from any
//! IP) escalates to a delay and never locks. Code attempts are counted per user
//! ([`LimitKey::User`], shared with the second factor). The handlers cannot read the flow state,
//! so the email page carries a `factor_token`: the rate-limit subject (the user, or a keyed pseudo
//! id for an address without an account) and the address hash, sealed with the KEK (purpose
//! [`EMAIL_TOKEN_PURPOSE`], AAD tenant and flow). It names limiter keys only; the flow state
//! decides everything else. A missing or tampered token restarts the sign-in. The "Email me a
//! code" button of a link confirmation whose matching account may not be revealed carries no
//! address: the handler asks the core for the pending link's upstream address
//! (`anvil_core::service::upstream::unrevealed_link_address`), so the send counts against the
//! same keys as a code requested for that address on the sign-in page, whether or not an account
//! gets it.
//!
//! # Magic link
//!
//! The link page is `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the URL carries
//! the token). Its form posts the token with a CSRF token derived from the flow and the token
//! (`flow::email_code::link_csrf`); the flow cookie (SameSite=Strict, not sent when the email
//! client opens the link, sent with the page's own POST) proves the browser. Without it the answer
//! is "open the link in the browser where you started, or type the code" and nothing is consumed.

use anvil_core::error::CoreError;
use anvil_core::flow::email_code::{EMAIL_CODE_FORM_ID, OTHER_BROWSER, link_csrf};
use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{FlowId, TenantId, UserId, normalize_email};
use anvil_core::service::flow::{AuthAttempt, EmailLinkOutcome, FlowOutcome, email_code_enabled};
use anvil_core::service::upstream::unrevealed_link_address;
use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;

use super::flow_driver::{self, DriveOutcome, FlowBinding, Throttle};
use super::login::{
    Extras, UiForm, UiQuery, bad_form, csrf_page, drive_response, factor_token, message_page,
    outcome_response_with, rejected_form, rejection_page, restart_login_in, started_response_with,
    ui_base,
};
use super::nav::{NavContext, UiPage};
use crate::client_ip::ClientIp;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::layers::ratelimit::identifier_hash;
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
pub(super) fn seal_email_token(
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
pub(super) fn open_email_token(
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
pub(super) fn send_ident(email: &str) -> [u8; 32] {
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
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let tenant_id = tenant.tenant.id;
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let posted = form.email.clone().filter(|e| !e.trim().is_empty());
    // The address the send counts against: the posted one, (a new code) the token's, or (the
    // "Email me a code" button of a link confirmation that may not reveal the account) the
    // pending link's upstream address, never shown.
    let ident = match &posted {
        Some(raw) => normalize_email(raw.trim()).ok().map(|e| send_ident(&e)),
        None => match form
            .factor_token
            .as_deref()
            .and_then(|t| open_email_token(state.kek(), tenant_id, flow_id, t))
        {
            Some((_, ident)) => Some(ident),
            None => match unrevealed_link_address(
                state.storage(),
                state.kek(),
                tenant_id,
                flow_id,
                state.clock().now(),
            )
            .await
            {
                Ok(Some(email)) => Some(send_ident(&email)),
                Ok(None) => return restart_login_in(&state, &tenant, &loc, &nav).await,
                Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
            },
        },
    };
    let input = FlowInput::EmailCodeRequest { email: posted };
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let throttle = Throttle::EmailCodeSend { ident, ip };
    let outcome =
        flow_driver::submit(&state, &tenant, &ctx, flow_id, binding, throttle, input).await;
    let mut token = form.factor_token.clone();
    if let (
        DriveOutcome::Flow {
            attempt: Some(AuthAttempt::EmailCodeSent { subject }),
            ..
        },
        Some(ident),
    ) = (&outcome, ident)
    {
        // The send was counted against the address by the driver; the new token names it.
        token = seal_email_token(state.kek(), tenant_id, flow_id, *subject, &ident);
    }
    let extras = Extras {
        factor_token: token,
        ..Extras::default()
    };
    drive_response(&state, &tenant, &loc, &nav, outcome, &extras, None)
}

/// `POST /ui/login/email-code/verify?flow=`: the code from the email (module docs). 404 unless
/// `email_otp` is on.
async fn verify(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !tenant.tenant.settings.email_otp {
        return not_found(&state, &tenant, &loc);
    }
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let tenant_id = tenant.tenant.id;
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let posted_token = form.factor_token.clone().unwrap_or_default();
    let Some((subject, _)) = open_email_token(state.kek(), tenant_id, flow_id, &posted_token)
    else {
        return restart_login_in(&state, &tenant, &loc, &nav).await;
    };
    let input = FlowInput::EmailCode {
        code: form.code.clone().unwrap_or_default(),
    };
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let throttle = Throttle::EmailCode { subject };
    let outcome =
        flow_driver::submit(&state, &tenant, &ctx, flow_id, binding, throttle, input).await;
    // The email page keeps its token; a second-factor or enrolment page that follows a right
    // code gets the second-factor token of the user (the subject of a right code).
    let next_form_id = match &outcome {
        DriveOutcome::Flow {
            outcome: FlowOutcome::Render(f) | FlowOutcome::Enroll { form: f, .. },
            ..
        } => Some(f.id.as_str()),
        _ => None,
    };
    let token = match next_form_id {
        Some(id) if id != EMAIL_CODE_FORM_ID => factor_token(&state, &tenant, flow_id, subject),
        _ => Some(posted_token.clone()),
    };
    let extras = Extras {
        factor_token: token,
        ..Extras::default()
    };
    drive_response(
        &state,
        &tenant,
        &loc,
        &nav,
        outcome,
        &extras,
        Some(posted_token),
    )
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
/// 404 unless `magic_link` is on.
async fn link_page(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    if !tenant.tenant.settings.magic_link {
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
    // "Use another way": the sign-in of the flow's own request (none once it expired).
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    page.links.login = Some(nav.url(&tenant, &loc, UiPage::Login));
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
/// 404 unless `magic_link` is on.
async fn link_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    if !tenant.tenant.settings.magic_link {
        return not_found(&state, &tenant, &loc);
    }
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let token = form.token.clone().unwrap_or_default();
    if token.is_empty() || token.len() > 128 {
        return bad_form(&state, &tenant, &loc);
    }
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let outcome =
        match flow_driver::email_link(&state, &tenant, &ctx, flow_id, &binding, &token).await {
            Ok(o) => o,
            Err(r) => return rejection_page(&state, &tenant, &loc, r),
        };
    match outcome {
        EmailLinkOutcome::Done(outcome) => {
            outcome_response_with(&state, &tenant, &loc, &nav, outcome, &Extras::default())
        }
        EmailLinkOutcome::Continue(started) => {
            let extras = Extras {
                factor_token: started
                    .factor_user
                    .and_then(|user| factor_token(&state, &tenant, started.flow_id, user)),
                totp: started.totp.as_ref(),
                ..Extras::default()
            };
            let next = NavContext::from_flow(&state, &tenant, started.flow_id).await;
            started_response_with(
                &state,
                &tenant,
                &loc,
                &started,
                &next,
                StatusCode::OK,
                &extras,
            )
        }
        EmailLinkOutcome::OtherBrowser => rejected(&state, &tenant, &loc, &nav, OTHER_BROWSER),
        EmailLinkOutcome::Rejected(key) => rejected(&state, &tenant, &loc, &nav, key),
    }
}

/// A link that does not sign in: the message page with `key`, 400, nothing changed.
fn rejected(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    key: &str,
) -> Response {
    let mut resp = message_page(state, tenant, loc, key, nav, CookieJar::new());
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
