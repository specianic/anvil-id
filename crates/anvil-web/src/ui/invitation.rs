//! `/ui/invitation`: accepting an organization invitation (ORG-02, plan 06-20).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/invitation?token=` | the emailed link: the organization name and an "Accept invitation" button. Consumes nothing |
//! | `POST /ui/invitation` | `token` plus `csrf_token`: accept as the signed-in user, or (signed out) the sign-in / registration offer |
//! | `POST /ui/invitation/register` | `token`, `password`, optional `name`, `csrf_token`: create an account for the invited address and join |
//!
//! The decisions live in `OrgInvitationService` (core): only an open invitation is described;
//! unknown, used, revoked and expired tokens all get the same "invitation not valid" page (400).
//!
//! - **Signed in** (session cookie): the invitation is accepted for that user if their verified
//!   email is the invited address; the token is consumed and the membership created in one
//!   storage intent (one winner among concurrent posts). Any other account gets "this invitation
//!   is for a different account" with a sign-out link; neither the invited nor the current address
//!   is named. An unverified account for the invited address is asked to confirm its email first.
//!   The token stays usable in all of these cases.
//! - **Signed out**: a sign-in link and, unless the tenant's registration is `disabled`, a
//!   registration form whose address is the invited one, shown read-only and never read from the
//!   form. The sign-in link is `/ui/login?return_to=/ui/invitation?token=…` (percent-encoded):
//!   the login carries the allowlisted target sealed in its flow state, and every sign-in method
//!   (password, passkey, email code or link, upstream OIDC or SAML, with or without a second
//!   factor) ends back on this page, where the user accepts with one click. A login bound to an
//!   authorization request never returns here (the request wins).
//! - **Registering** creates a user with a verified email (password policy and breach check as
//!   for self-registration) and the membership in one storage intent, then signs the new user in
//!   (`FlowService::sign_in_registered_user`, the same session code as every sign-in: another
//!   user's session in this browser is replaced, `login_succeeded` is audited with method
//!   `invitation_registration`). A refused registration (address taken, password refused,
//!   registration disabled, invalid token, CSRF failure) creates no session.
//!
//! # CSRF
//!
//! Besides the Fetch-Metadata layer, every POST carries a CSRF token bound to the browser: the GET
//! sets a random nonce in the cookie [`cookie_name`] (HttpOnly, SameSite=Strict, `__Host-` on
//! https) and the form carries `HMAC(KEK-derived key, tenant ‖ nonce ‖ token)` (purpose
//! [`CSRF_PURPOSE`]). A POST without the cookie, without the field or with a mismatch gets the
//! `csrf` error page (403) and nothing is consumed. An existing nonce is reused, so several open
//! invitation tabs stay valid.
//!
//! Every response is `Cache-Control: no-store` and `Referrer-Policy: no-referrer` (the URL and
//! the forms carry the token). The page keeps the default CSP and needs no JavaScript.

use anvil_core::error::CoreError;
use anvil_core::model::{RegistrationMode, TenantId};
use anvil_core::service::flow::FlowContext;
use anvil_core::service::org_invitation::{
    AcceptOutcome, MAX_TOKEN_LEN, OrgInvitationService, RegisterOutcome, RegistrationChecks,
};
use anvil_jose::encoding::{b64url, ct_eq, random_token};
use anvil_jose::hmac::hmac_sha256;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::login::{
    UiQuery, csrf_page, current_browser_session, rejected_form, tenant_relying_party, ui_base,
};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// KEK derivation info of the CSRF key.
pub const CSRF_PURPOSE: &str = "anvilid/invitation-csrf/v1";
/// Lifetime of the CSRF nonce cookie.
const NONCE_MAX_AGE: time::Duration = time::Duration::hours(1);
/// Length of a nonce ([`random_token`]: 32 bytes, base64url).
const NONCE_LEN: usize = 43;

impl AppState {
    /// The invitation service for the acceptance pages.
    pub(crate) fn ui_org_invitations(&self) -> OrgInvitationService {
        OrgInvitationService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            kek: self.kek_arc(),
        }
    }
}

/// Invitation routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/ui/invitation", get(show).post(accept))
        .route("/ui/invitation/register", post(register))
}

/// The fields the invitation forms post.
#[derive(Default, Deserialize)]
struct InvitationForm {
    csrf_token: Option<String>,
    token: Option<String>,
    password: Option<String>,
    name: Option<String>,
}

/// The CSRF nonce cookie name (one per browser; the tenant is bound in the MAC).
pub fn cookie_name(state: &AppState) -> &'static str {
    if state.cookies().is_secure() {
        "__Host-anvil_invitation"
    } else {
        "anvil_invitation"
    }
}

fn nonce_cookie(state: &AppState, nonce: &str) -> Cookie<'static> {
    Cookie::build((cookie_name(state), nonce.to_owned()))
        .http_only(true)
        .secure(state.cookies().is_secure())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(NONCE_MAX_AGE)
        .build()
}

/// The CSRF token of `token` for the browser holding `nonce`.
fn csrf_for(state: &AppState, tenant: TenantId, nonce: &str, token: &str) -> String {
    let key = state.kek().derive_key(CSRF_PURPOSE);
    let nonce_len = u32::try_from(nonce.len()).unwrap_or(u32::MAX).to_be_bytes();
    b64url(&hmac_sha256(
        key.as_ref(),
        &[
            tenant.0.as_bytes(),
            &nonce_len,
            nonce.as_bytes(),
            token.as_bytes(),
        ],
    ))
}

/// The browser's nonce, if it has a well-formed one.
fn current_nonce(state: &AppState, jar: &CookieJar) -> Option<String> {
    jar.get(cookie_name(state))
        .map(|c| c.value().to_owned())
        .filter(|v| v.len() == NONCE_LEN)
}

/// `true` if the posted CSRF token matches the browser's nonce and the posted invitation token.
fn csrf_ok(
    state: &AppState,
    tenant: TenantId,
    jar: &CookieJar,
    form: &InvitationForm,
    token: &str,
) -> bool {
    let (Some(nonce), Some(posted)) = (current_nonce(state, jar), form.csrf_token.as_deref())
    else {
        return false;
    };
    ct_eq(
        csrf_for(state, tenant, &nonce, token).as_bytes(),
        posted.as_bytes(),
    )
}

/// `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
fn private(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// The views of `invitation.html` (template docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Offer,
    Invalid,
    SignedOut,
    WrongAccount,
    VerifyEmail,
    AlreadyMember,
    Accepted,
    Registered,
    EmailTaken,
}

impl View {
    fn name(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Invalid => "invalid",
            Self::SignedOut => "signed_out",
            Self::WrongAccount => "wrong_account",
            Self::VerifyEmail => "verify_email",
            Self::AlreadyMember => "already_member",
            Self::Accepted => "accepted",
            Self::Registered => "registered",
            Self::EmailTaken => "email_taken",
        }
    }

    fn message_key(self) -> String {
        format!("invitation.{}", self.name())
    }

    fn title_key(self) -> &'static str {
        match self {
            Self::Invalid => "title.invitation_invalid",
            Self::Accepted | Self::Registered => "title.invitation_accepted",
            _ => "title.invitation",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        }
    }
}

#[derive(Serialize)]
struct PasswordError {
    key: &'static str,
    text: String,
}

/// Everything a view may show.
#[derive(Default)]
struct Page<'a> {
    org: Option<&'a str>,
    email: Option<&'a str>,
    token: Option<&'a str>,
    csrf: Option<String>,
    registration_allowed: bool,
    password_error: Option<&'static str>,
    name: Option<&'a str>,
}

fn render(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    view: View,
    p: &Page<'_>,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let base = ui_base(tenant);
    let page = PageContext::for_tenant(state, tenant, loc, view.title_key());
    let password_error = p.password_error.map(|key| PasswordError {
        key,
        text: state.renderer().text(loc, key),
    });
    let ctx = minijinja::context! {
        page => page.into_value(),
        view => view.name(),
        message_key => view.message_key(),
        org => p.org.unwrap_or_default(),
        email => p.email.unwrap_or_default(),
        token => p.token.unwrap_or_default(),
        csrf_token => p.csrf.clone().unwrap_or_default(),
        action => carry_ui_locales(&format!("{base}/invitation"), loc),
        register_action => carry_ui_locales(&format!("{base}/invitation/register"), loc),
        registration_allowed => p.registration_allowed,
        password_error => minijinja::Value::from(minijinja::value::Serde(&password_error)),
        name => p.name.unwrap_or_default(),
        login_url => carry_ui_locales(&login_url(&base, p.token), loc),
        logout_url => carry_ui_locales(&format!("{base}/logout"), loc),
        continue_url => carry_ui_locales(&format!("{base}/account/profile"), loc),
    };
    let resp = match state.renderer().page("invitation.html", ctx) {
        Ok(html) => (status, jar, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering the invitation page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    };
    private(resp)
}

/// The sign-in link: with the invitation token, it returns to this page after signing in
/// (`return_to`, allowlisted by the login page).
fn login_url(base: &str, token: Option<&str>) -> String {
    match token {
        Some(token) => {
            let target = format!("/ui/invitation?token={token}");
            let encoded: String = url::form_urlencoded::byte_serialize(target.as_bytes()).collect();
            format!("{base}/login?return_to={encoded}")
        }
        None => format!("{base}/login"),
    }
}

/// A view that shows only its message (and its links).
fn simple(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    view: View,
    org: Option<&str>,
) -> Response {
    let p = Page {
        org,
        ..Page::default()
    };
    render(
        state,
        tenant,
        loc,
        view,
        &p,
        view.status(),
        CookieJar::new(),
    )
}

fn invalid(state: &AppState, tenant: &ResolvedTenant, loc: &Locale) -> Response {
    simple(state, tenant, loc, View::Invalid, None)
}

fn error_page(state: &AppState, tenant: &ResolvedTenant, loc: &Locale, e: &CoreError) -> Response {
    private(core_error_page_in(state, Some(tenant), loc, e))
}

/// The posted token, if it can be one.
fn posted_token(form: &InvitationForm) -> Option<String> {
    form.token
        .clone()
        .filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN_LEN)
}

/// `GET /ui/invitation?token=`: the organization name and the accept button. Reads only.
async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    let Some(token) = q.token().filter(|t| t.len() <= MAX_TOKEN_LEN) else {
        return invalid(&state, &tenant, &loc);
    };
    let preview = match state
        .ui_org_invitations()
        .preview(tenant.tenant.id, &token)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => return invalid(&state, &tenant, &loc),
        Err(e) => return error_page(&state, &tenant, &loc, &e),
    };
    let (nonce, jar) = match current_nonce(&state, &jar) {
        Some(n) => (n, CookieJar::new()),
        None => {
            let n = random_token();
            let jar = CookieJar::new().add(nonce_cookie(&state, &n));
            (n, jar)
        }
    };
    let p = Page {
        org: Some(&preview.org_name),
        token: Some(&token),
        csrf: Some(csrf_for(&state, tenant.tenant.id, &nonce, &token)),
        ..Page::default()
    };
    render(&state, &tenant, &loc, View::Offer, &p, StatusCode::OK, jar)
}

/// Checks the form and its CSRF binding; `Err` is the response to send.
fn checked_token(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    jar: &CookieJar,
    form: &InvitationForm,
) -> Result<String, Box<Response>> {
    let Some(token) = posted_token(form) else {
        return Err(Box::new(invalid(state, tenant, loc)));
    };
    if !csrf_ok(state, tenant.tenant.id, jar, form, &token) {
        return Err(Box::new(private(csrf_page(state, Some(tenant), loc))));
    }
    Ok(token)
}

/// The signed-out offer: sign in, or register for the invited address.
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding and echo values"
)]
async fn signed_out_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    jar: &CookieJar,
    form: &InvitationForm,
    token: &str,
    password_error: Option<&'static str>,
    status: StatusCode,
) -> Response {
    let preview = match state
        .ui_org_invitations()
        .preview(tenant.tenant.id, token)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => return invalid(state, tenant, loc),
        Err(e) => return error_page(state, tenant, loc, &e),
    };
    let csrf = current_nonce(state, jar).map(|n| csrf_for(state, tenant.tenant.id, &n, token));
    let p = Page {
        org: Some(&preview.org_name),
        email: Some(&preview.email),
        token: Some(token),
        csrf,
        registration_allowed: tenant.tenant.settings.registration != RegistrationMode::Disabled,
        password_error,
        name: form.name.as_deref(),
    };
    render(
        state,
        tenant,
        loc,
        View::SignedOut,
        &p,
        status,
        CookieJar::new(),
    )
}

/// `POST /ui/invitation`: accept as the signed-in user, or show the signed-out offer.
async fn accept(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    form: Result<Form<InvitationForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return private(rejected_form(&state, Some(&tenant), &loc, &e)),
    };
    let token = match checked_token(&state, &tenant, &loc, &jar, &form) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let session = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return error_page(&state, &tenant, &loc, &e),
    };
    let Some(session) = session else {
        return signed_out_page(
            &state,
            &tenant,
            &loc,
            &jar,
            &form,
            &token,
            None,
            StatusCode::OK,
        )
        .await;
    };
    let outcome = match state
        .ui_org_invitations()
        .accept(&tenant.tenant, &token, session.user_id, &ctx)
        .await
    {
        Ok(o) => o,
        Err(e) => return error_page(&state, &tenant, &loc, &e),
    };
    match outcome {
        AcceptOutcome::Accepted { org_name } => {
            simple(&state, &tenant, &loc, View::Accepted, Some(&org_name))
        }
        AcceptOutcome::Invalid => invalid(&state, &tenant, &loc),
        AcceptOutcome::WrongAccount => simple(&state, &tenant, &loc, View::WrongAccount, None),
        AcceptOutcome::VerifyEmailFirst => simple(&state, &tenant, &loc, View::VerifyEmail, None),
        AcceptOutcome::AlreadyMember { org_name } => {
            simple(&state, &tenant, &loc, View::AlreadyMember, Some(&org_name))
        }
    }
}

/// `POST /ui/invitation/register`: create an account for the invited address and join.
async fn register(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    form: Result<Form<InvitationForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return private(rejected_form(&state, Some(&tenant), &loc, &e)),
    };
    let token = match checked_token(&state, &tenant, &loc, &jar, &form) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let checks = RegistrationChecks {
        policy: state.config().password_policy,
        hasher: state.hasher(),
        breach: state.breach(),
    };
    let outcome = match state
        .ui_org_invitations()
        .accept_with_registration(
            &tenant.tenant,
            &token,
            form.password.as_deref().unwrap_or_default(),
            form.name.as_deref(),
            &checks,
            &ctx,
        )
        .await
    {
        Ok(o) => o,
        Err(e) => return error_page(&state, &tenant, &loc, &e),
    };
    match outcome {
        RegisterOutcome::Registered { org_name, user } => {
            let current = match current_browser_session(&state, &tenant, &jar).await {
                Ok(s) => s,
                Err(e) => return error_page(&state, &tenant, &loc, &e),
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
            let cookie = match state
                .ui_flow_service()
                .sign_in_registered_user(&cx, user, current.as_ref())
                .await
            {
                Ok(c) => c,
                Err(e) => return error_page(&state, &tenant, &loc, &e),
            };
            // As after every sign-in: another user's session may have been revoked.
            state.wake_logout_worker();
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .session_cookie(&tenant.tenant, cookie.token.expose_secret()),
            );
            let p = Page {
                org: Some(&org_name),
                ..Page::default()
            };
            render(
                &state,
                &tenant,
                &loc,
                View::Registered,
                &p,
                StatusCode::OK,
                jar,
            )
        }
        RegisterOutcome::Invalid => invalid(&state, &tenant, &loc),
        // The signed-out page without the form (registration is disabled), and nothing written.
        RegisterOutcome::RegistrationDisabled => {
            signed_out_page(
                &state,
                &tenant,
                &loc,
                &jar,
                &form,
                &token,
                None,
                StatusCode::FORBIDDEN,
            )
            .await
        }
        // Sign in instead: the link returns here.
        RegisterOutcome::EmailTaken => {
            let p = Page {
                token: Some(&token),
                ..Page::default()
            };
            render(
                &state,
                &tenant,
                &loc,
                View::EmailTaken,
                &p,
                StatusCode::OK,
                CookieJar::new(),
            )
        }
        RegisterOutcome::PasswordRejected(key) => {
            signed_out_page(
                &state,
                &tenant,
                &loc,
                &jar,
                &form,
                &token,
                Some(key),
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        RegisterOutcome::Overloaded => {
            signed_out_page(
                &state,
                &tenant,
                &loc,
                &jar,
                &form,
                &token,
                Some("service.overloaded"),
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_have_distinct_message_keys_and_one_invalid_status() {
        let all = [
            View::Offer,
            View::Invalid,
            View::SignedOut,
            View::WrongAccount,
            View::VerifyEmail,
            View::AlreadyMember,
            View::Accepted,
            View::Registered,
            View::EmailTaken,
        ];
        let keys: std::collections::BTreeSet<String> =
            all.iter().map(|v| v.message_key()).collect();
        assert_eq!(keys.len(), all.len());
        for v in all {
            let expected = if v == View::Invalid {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            };
            assert_eq!(v.status(), expected, "{v:?}");
        }
    }
}
