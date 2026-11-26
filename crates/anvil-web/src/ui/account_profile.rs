//! Account profile, email and password pages (AUTH-13).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/profile` | profile form (name, given/family name, language); starts a settings flow |
//! | `POST /ui/account/profile?flow=` | saves it (audited `profile_updated`) |
//! | `GET  /ui/account/email` | current address and the change form; starts a settings flow |
//! | `POST /ui/account/email?flow=` | sends a confirmation link to the new address (re-auth) |
//! | `GET  /ui/account/email/confirm?token=` | shows a "Confirm new email" button only |
//! | `POST /ui/account/email/confirm` | consumes the link token and switches the address |
//! | `GET  /ui/account/password` | set or change the password; starts a settings flow |
//! | `POST /ui/account/password?flow=` | sets it (re-auth, policy, breach check) |
//!
//! Without a session the account pages answer 303 to the sign-in page (the email confirmation
//! needs no session: the link token is the proof). Every POST is behind the Fetch-Metadata layer;
//! the settings-flow POSTs must carry the flow cookie and the CSRF token, otherwise the `csrf`
//! error page (403). Email and password changes need a sign-in within the last 15 minutes
//! (`AccountService`). A refusal re-renders the page with a message (400; an address taken at
//! confirmation: 409). The confirmation link is consumed only by the POST, so mail scanners that
//! fetch the link never use it up. No page needs JavaScript; the default CSP applies.

use anvil_core::error::CoreError;
use anvil_core::model::{BrowserSession, FlowId};
use anvil_core::service::account::{
    AccountError, AccountFailure, PasswordDeps, ProfileInput, SettingsBinding,
};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::account_attributes::attributes_nav_or_page;
use super::consent::{PageMessage, account_locale, localized};
use super::login::{UiQuery, csrf_page, rejected_form};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PROFILE: &str = "/ui/account/profile";
const EMAIL: &str = "/ui/account/email";
const EMAIL_CONFIRM: &str = "/ui/account/email/confirm";
const PASSWORD: &str = "/ui/account/password";

/// Account profile routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(PROFILE, get(profile_show).post(profile_submit))
        .route(EMAIL, get(email_show).post(email_submit))
        .route(EMAIL_CONFIRM, get(confirm_show).post(confirm_submit))
        .route(PASSWORD, get(password_show).post(password_submit))
}

/// Every field the forms of this module post.
#[derive(Default, Deserialize)]
struct AccountForm {
    csrf_token: Option<String>,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    locale: Option<String>,
    new_email: Option<String>,
    token: Option<String>,
    new_password: Option<String>,
    revoke_others: Option<String>,
}

/// The profile fields as shown in the form.
#[derive(Default, Serialize)]
struct ProfileView {
    name: String,
    given_name: String,
    family_name: String,
    locale: String,
}

/// A settings-flow submission resolved to its session, page locale and binding.
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

/// The settings flow a page is bound to: its id, CSRF token and (for a fresh flow) the cookie.
struct Bound {
    flow_id: FlowId,
    csrf: String,
    jar: CookieJar,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `Cache-Control: no-store` (per-user pages with a CSRF token or a link token).
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn to_login(tenant: &ResolvedTenant) -> Response {
    let location = tenant.ui_url("/ui/login");
    no_store((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

fn flow_url(tenant: &ResolvedTenant, path: &str, flow: FlowId) -> String {
    tenant.ui_url(&format!("{path}?flow={flow}"))
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

/// The session and its page locale for a GET (303 to sign-in without a session).
async fn page_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: &RequestLocale,
    jar: &CookieJar,
) -> Result<(BrowserSession, Locale), Box<Response>> {
    match session(state, tenant, jar).await {
        Ok(Some(s)) => {
            let loc = account_locale(state, tenant, locale, &s).await;
            Ok((s, loc))
        }
        Ok(None) => Err(Box::new(to_login(tenant))),
        Err(e) => Err(Box::new(core_error_page_in(
            state,
            Some(tenant),
            &locale.0,
            &e,
        ))),
    }
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
    let (session, loc) = page_session(state, tenant, locale, jar).await?;
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

/// Starts a settings flow for `session` (its cookie goes into the returned jar).
async fn start_flow(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
) -> Result<Bound, Box<Response>> {
    match state
        .ui_account_service()
        .start(tenant.tenant.id, session)
        .await
    {
        Ok(started) => Ok(Bound {
            flow_id: started.flow_id,
            csrf: started.csrf_token.expose_secret().to_owned(),
            jar: CookieJar::new().add(
                state
                    .cookies()
                    .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
            ),
        }),
        Err(e) => Err(Box::new(core_error_page_in(state, Some(tenant), loc, &e))),
    }
}

impl Submission {
    /// The submission's own flow (no new cookie).
    fn bound(&self) -> Bound {
        Bound {
            flow_id: self.flow_id,
            csrf: self.csrf.clone(),
            jar: CookieJar::new(),
        }
    }
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
        Ok(html) => no_store((status, jar, html).into_response()),
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

fn messages_value(state: &AppState, loc: &Locale, messages: Vec<PageMessage>) -> minijinja::Value {
    let messages = localized(state, loc, messages);
    minijinja::Value::from(minijinja::value::Serde(&messages))
}

/// The status of a refusal shown on the page.
fn refusal_status(f: AccountFailure) -> StatusCode {
    match f {
        AccountFailure::EmailTaken => StatusCode::CONFLICT,
        AccountFailure::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    }
}

/// What a settings-flow page does with a refusal: core errors become error pages, a broken
/// binding the `csrf` page; `Ok` carries the refusal and its status.
fn classify(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    err: AccountError,
) -> Result<(AccountFailure, StatusCode), Box<Response>> {
    match err {
        AccountError::Core(CoreError::Forbidden) => {
            Err(Box::new(csrf_page(state, Some(tenant), loc)))
        }
        AccountError::Core(e) => Err(Box::new(core_error_page_in(state, Some(tenant), loc, &e))),
        AccountError::Failure(f) => Ok((f, refusal_status(f))),
    }
}

/// The binding to render a refusal with: a fresh flow when the old one expired.
async fn rebind(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    failure: AccountFailure,
) -> Result<Bound, Box<Response>> {
    if failure == AccountFailure::FlowExpired {
        start_flow(state, tenant, &sub.locale, &sub.session).await
    } else {
        Ok(sub.bound())
    }
}

// ---------------------------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding"
)]
async fn render_profile(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    bound: Bound,
    view: Option<ProfileView>,
    session: &BrowserSession,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let view = match view {
        Some(v) => v,
        None => match state
            .ui_account_service()
            .profile(tenant.tenant.id, session)
            .await
        {
            Ok(p) => ProfileView {
                name: p.name.unwrap_or_default(),
                given_name: p.given_name.unwrap_or_default(),
                family_name: p.family_name.unwrap_or_default(),
                locale: p.locale.unwrap_or_default(),
            },
            Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
        },
    };
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_profile").into_value(),
        account_base => tenant.base_path(),
        account_nav => "profile",
        account_attributes_nav => attributes_nav,
        csrf_token => &bound.csrf,
        messages => messages_value(state, loc, messages),
        action => flow_url(tenant, PROFILE, bound.flow_id),
        profile => minijinja::Value::from(minijinja::value::Serde(&view)),
    };
    render(
        state,
        tenant,
        loc,
        "account_profile.html",
        ctx,
        status,
        bound.jar,
    )
}

async fn profile_show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
) -> Response {
    let (session, loc) = match page_session(&state, &tenant, &locale, &jar).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let bound = match start_flow(&state, &tenant, &loc, &session).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    render_profile(
        &state,
        &tenant,
        &loc,
        bound,
        None,
        &session,
        Vec::new(),
        StatusCode::OK,
    )
    .await
}

async fn profile_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<AccountForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token.clone()).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let input = ProfileInput {
        name: form.name.as_deref().unwrap_or_default(),
        given_name: form.given_name.as_deref().unwrap_or_default(),
        family_name: form.family_name.as_deref().unwrap_or_default(),
        locale: form.locale.as_deref().unwrap_or_default(),
    };
    let result = state
        .ui_account_service()
        .update_profile(tenant.tenant.id, &sub.session, &sub.binding(), &input, &ctx)
        .await;
    match result {
        Ok(_) => {
            // The saved language applies to this response already.
            let loc = account_locale(&state, &tenant, &locale, &sub.session).await;
            render_profile(
                &state,
                &tenant,
                &loc,
                sub.bound(),
                None,
                &sub.session,
                vec![PageMessage::info("account.profile_saved")],
                StatusCode::OK,
            )
            .await
        }
        Err(e) => {
            let (failure, status) = match classify(&state, &tenant, &sub.locale, e) {
                Ok(c) => c,
                Err(resp) => return *resp,
            };
            let bound = match rebind(&state, &tenant, &sub, failure).await {
                Ok(b) => b,
                Err(resp) => return *resp,
            };
            // Keep what the user typed so they can correct it.
            let view = ProfileView {
                name: input.name.to_owned(),
                given_name: input.given_name.to_owned(),
                family_name: input.family_name.to_owned(),
                locale: input.locale.to_owned(),
            };
            render_profile(
                &state,
                &tenant,
                &sub.locale,
                bound,
                Some(view),
                &sub.session,
                vec![PageMessage::error(failure.key())],
                status,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Email change
// ---------------------------------------------------------------------------------------------

async fn render_email(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    bound: Bound,
    session: &BrowserSession,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let profile = match state
        .ui_account_service()
        .profile(tenant.tenant.id, session)
        .await
    {
        Ok(p) => p,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_email").into_value(),
        account_base => tenant.base_path(),
        account_nav => "email",
        account_attributes_nav => attributes_nav,
        mode => "change",
        csrf_token => &bound.csrf,
        messages => messages_value(state, loc, messages),
        action => flow_url(tenant, EMAIL, bound.flow_id),
        email => profile.email,
        email_verified => profile.email_verified,
        recent_auth => profile.recent_auth,
        login_url => tenant.ui_url("/ui/login"),
    };
    render(
        state,
        tenant,
        loc,
        "account_email.html",
        ctx,
        status,
        bound.jar,
    )
}

async fn email_show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
) -> Response {
    let (session, loc) = match page_session(&state, &tenant, &locale, &jar).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let bound = match start_flow(&state, &tenant, &loc, &session).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    render_email(
        &state,
        &tenant,
        &loc,
        bound,
        &session,
        Vec::new(),
        StatusCode::OK,
    )
    .await
}

async fn email_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<AccountForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token.clone()).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let result = state
        .ui_account_service()
        .request_email_change(
            &tenant.tenant,
            &sub.session,
            &sub.binding(),
            form.new_email.as_deref().unwrap_or_default(),
            &tenant.ui_url(EMAIL_CONFIRM),
            &ctx,
        )
        .await;
    let (bound, message, status) = match result {
        Ok(()) => (
            sub.bound(),
            PageMessage::info("account.email_change_sent"),
            StatusCode::OK,
        ),
        Err(e) => {
            let (failure, status) = match classify(&state, &tenant, &sub.locale, e) {
                Ok(c) => c,
                Err(resp) => return *resp,
            };
            match rebind(&state, &tenant, &sub, failure).await {
                Ok(b) => (b, PageMessage::error(failure.key()), status),
                Err(resp) => return *resp,
            }
        }
    };
    render_email(
        &state,
        &tenant,
        &sub.locale,
        bound,
        &sub.session,
        vec![message],
        status,
    )
    .await
}

/// The confirmation page: `mode` "confirm" (with the token in a hidden field) or "done".
/// `attributes_nav` is computed by the handler before any change (the confirmation is one-time).
fn render_confirm(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    token: Option<&str>,
    messages: Vec<PageMessage>,
    status: StatusCode,
    attributes_nav: bool,
) -> Response {
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_email_confirm")
            .into_value(),
        account_base => tenant.base_path(),
        account_nav => "email",
        account_attributes_nav => attributes_nav,
        mode => if token.is_some() { "confirm" } else { "done" },
        messages => messages_value(state, loc, messages),
        confirm_action => tenant.ui_url(EMAIL_CONFIRM),
        token => token.unwrap_or_default(),
    };
    render(
        state,
        tenant,
        loc,
        "account_email.html",
        ctx,
        status,
        CookieJar::new(),
    )
}

async fn confirm_show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    let attributes_nav = match attributes_nav_or_page(&state, &tenant, &loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    // Showing the page consumes nothing (link scanners fetch it).
    match q.token() {
        Some(token) => render_confirm(
            &state,
            &tenant,
            &loc,
            Some(&token),
            Vec::new(),
            StatusCode::OK,
            attributes_nav,
        ),
        None => render_confirm(
            &state,
            &tenant,
            &loc,
            None,
            vec![PageMessage::error(AccountFailure::EmailTokenInvalid.key())],
            StatusCode::BAD_REQUEST,
            attributes_nav,
        ),
    }
}

async fn confirm_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    form: Result<Form<AccountForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let token = form.token.unwrap_or_default();
    // Computed before the change: the confirmation is one-time.
    let attributes_nav = match attributes_nav_or_page(&state, &tenant, &loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    match state
        .ui_account_service()
        .complete_email_change(&tenant.tenant, &token, &ctx)
        .await
    {
        Ok(_) => render_confirm(
            &state,
            &tenant,
            &loc,
            None,
            vec![PageMessage::info("account.email_changed")],
            StatusCode::OK,
            attributes_nav,
        ),
        // The token stays usable: offer the button again.
        Err(AccountError::Failure(AccountFailure::EmailTaken)) => render_confirm(
            &state,
            &tenant,
            &loc,
            Some(&token),
            vec![PageMessage::error(AccountFailure::EmailTaken.key())],
            StatusCode::CONFLICT,
            attributes_nav,
        ),
        Err(AccountError::Failure(f)) => render_confirm(
            &state,
            &tenant,
            &loc,
            None,
            vec![PageMessage::error(f.key())],
            refusal_status(f),
            attributes_nav,
        ),
        Err(AccountError::Core(e)) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

// ---------------------------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding"
)]
async fn render_password(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    bound: Bound,
    session: &BrowserSession,
    revoke_others: bool,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let profile = match state
        .ui_account_service()
        .profile(tenant.tenant.id, session)
        .await
    {
        Ok(p) => p,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_password").into_value(),
        account_base => tenant.base_path(),
        account_nav => "password",
        account_attributes_nav => attributes_nav,
        csrf_token => &bound.csrf,
        messages => messages_value(state, loc, messages),
        action => flow_url(tenant, PASSWORD, bound.flow_id),
        has_password => profile.has_password,
        recent_auth => profile.recent_auth,
        login_url => tenant.ui_url("/ui/login"),
        revoke_others => revoke_others,
    };
    render(
        state,
        tenant,
        loc,
        "account_password.html",
        ctx,
        status,
        bound.jar,
    )
}

async fn password_show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
) -> Response {
    let (session, loc) = match page_session(&state, &tenant, &locale, &jar).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let bound = match start_flow(&state, &tenant, &loc, &session).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    // Signing out the other devices is the default.
    render_password(
        &state,
        &tenant,
        &loc,
        bound,
        &session,
        true,
        Vec::new(),
        StatusCode::OK,
    )
    .await
}

async fn password_submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<AccountForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token.clone()).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let revoke_others = form.revoke_others.as_deref().is_some_and(|v| !v.is_empty());
    let password = SecretString::from(form.new_password.unwrap_or_default());
    let deps = PasswordDeps {
        hasher: state.hasher(),
        breach: state.breach(),
        policy: state.config().password_policy,
    };
    let result = state
        .ui_account_service()
        .change_password(
            &tenant.tenant,
            &sub.session,
            &sub.binding(),
            &password,
            revoke_others,
            &deps,
            &ctx,
        )
        .await;
    let (bound, message, status) = match result {
        Ok(_) => {
            if revoke_others {
                // The change signed out the other sessions; send their back-channel logouts now.
                state.wake_logout_worker();
            }
            (
                sub.bound(),
                PageMessage::info("account.password_changed"),
                StatusCode::OK,
            )
        }
        Err(e) => {
            let (failure, status) = match classify(&state, &tenant, &sub.locale, e) {
                Ok(c) => c,
                Err(resp) => return *resp,
            };
            match rebind(&state, &tenant, &sub, failure).await {
                Ok(b) => (b, PageMessage::error(failure.key()), status),
                Err(resp) => return *resp,
            }
        }
    };
    render_password(
        &state,
        &tenant,
        &sub.locale,
        bound,
        &sub.session,
        revoke_others,
        vec![message],
        status,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_statuses() {
        assert_eq!(
            refusal_status(AccountFailure::EmailTaken),
            StatusCode::CONFLICT
        );
        assert_eq!(
            refusal_status(AccountFailure::ReauthRequired),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            refusal_status(AccountFailure::Overloaded),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
