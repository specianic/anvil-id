//! Consent screen (OIDC-13) for clients with `consent_mode = required`.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/consent?request=` | names the client and lists the requested scopes (and RFC 8707 resources); starts a consent flow (flow cookie + CSRF token) |
//! | `POST /ui/consent?flow=&request=` | `decision=allow` or `decision=deny` (two submit buttons named `decision`), or `choice=other` ("Use another account", its own small form) |
//!
//! `/authorize` sends the signed-in user here when consent is needed
//! (`AuthorizeOutcome::Consent`). Allow stores the grant and continues the authorization request
//! (code); Deny continues it with `access_denied`. Both answers go through the request's
//! response mode ([`AppState::authorize_response`]), so they are a 303 (query) or the form_post
//! page.
//!
//! Without a session the page sends the user to sign in (`/ui/login?request=`), which comes back
//! through `/authorize/continue`. The POST is behind the Fetch-Metadata layer and must carry the
//! flow cookie and the CSRF token; otherwise the `csrf` error page (403). An expired flow shows
//! the screen again with a message; an expired or used request is the `flow_expired` page. The
//! page works without JavaScript and is `Cache-Control: no-store`.
//!
//! The page names the signed-in account (its email address) and offers "Use another account"
//! (U-M15): a POST bound to the consent flow like Allow and Deny (flow cookie, CSRF token, the
//! flow's own user), which takes the flow's single decision without storing anything, then goes
//! to the login page for the request through the same path as the account chooser's "Use
//! another account" ([`AuthorizeService::sign_in_as_other`]). Signing in as someone else
//! revokes the current session, and the next user is asked for their own consent: grants are
//! per user, so one user's Allow is never used for another.
//!
//! [`AuthorizeService::sign_in_as_other`]: anvil_core::service::authorize::AuthorizeService::sign_in_as_other
//!
//! For a client materialised from a Client ID Metadata Document (CIMD) the page names the client
//! by the host of its `client_id` URL, shows the self-asserted `client_name` as unverified and
//! renders the name's initials instead of a logo: the page never loads anything from the client's
//! servers.
//!
//! Agents and step-up (AGT-03): a client with `client_kind = agent` carries an "AI agent /
//! automated client" badge, and every client states its provenance (registered by an
//! administrator, by dynamic registration, or identified by its metadata document at its host).
//! With a stored grant only the scopes and resources it does not cover are listed as new; the
//! already allowed ones are listed in a collapsed `<details>` block. Allow stores the union;
//! Deny leaves the stored grant as it was.

use anvil_core::error::CoreError;
use anvil_core::flow::consent::{Provenance, scope_description};
use anvil_core::model::{AuthRequestId, BrowserSession, ClientKind};
use anvil_core::service::consent::{
    ConsentBinding, ConsentService, ConsentStart, ConsentSubmission,
};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::login::{UiQuery, bad_form, csrf_page, page_locale, rejected_form};
use super::nav::{NavContext, UiPage};
use super::select_account::use_another_account;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales, locale_for_user};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/consent";

/// Message key shown when the consent flow expired before the decision.
const EXPIRED: &str = "consent.expired";

impl AppState {
    /// The consent service for the consent screen and the connected-apps page.
    pub(crate) fn ui_consent_service(&self) -> ConsentService {
        ConsentService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new().route(PAGE, get(show).post(submit))
}

/// The form the consent screen posts.
#[derive(Default, Deserialize)]
struct ConsentForm {
    csrf_token: Option<String>,
    decision: Option<String>,
    /// `other`: the "Use another account" form.
    choice: Option<String>,
}

/// What a consent submission asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Allow,
    Deny,
    OtherAccount,
}

/// A message on the consent and account pages (`data-message-key` like the form messages).
/// `text` is filled for the page's locale by [`localized`] just before rendering.
#[derive(Debug, Clone, Serialize)]
pub(super) struct PageMessage {
    pub(super) level: &'static str,
    pub(super) key: std::borrow::Cow<'static, str>,
    pub(super) text: String,
}

impl PageMessage {
    pub(super) fn error(key: &'static str) -> Self {
        Self {
            level: "error",
            key: key.into(),
            text: String::new(),
        }
    }

    pub(super) fn info(key: &'static str) -> Self {
        Self {
            level: "info",
            key: key.into(),
            text: String::new(),
        }
    }

    /// A message read back from a sealed flash (Post/Redirect/Get of an account form).
    pub(super) fn from_flash(error: bool, key: &str) -> Self {
        Self {
            level: if error { "error" } else { "info" },
            key: key.to_owned().into(),
            text: String::new(),
        }
    }

    /// The message with its text in `loc`.
    pub(super) fn localized(mut self, state: &AppState, loc: &Locale) -> Self {
        self.text = state.renderer().text(loc, &self.key);
        self
    }
}

/// `messages` with their texts in `loc`.
pub(super) fn localized(
    state: &AppState,
    loc: &Locale,
    messages: Vec<PageMessage>,
) -> Vec<PageMessage> {
    messages
        .into_iter()
        .map(|m| m.localized(state, loc))
        .collect()
}

/// A requested scope as shown on the page: its plain-language description, or its name.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ScopeView {
    pub(super) name: String,
    pub(super) description: Option<String>,
}

/// The scopes with the description of each well-known scope (`scope.{name}`) in `loc`.
pub(super) fn scope_views(state: &AppState, loc: &Locale, scopes: &[String]) -> Vec<ScopeView> {
    scopes
        .iter()
        .map(|s| ScopeView {
            name: s.clone(),
            description: scope_description(s)
                .map(|_| state.renderer().text(loc, &format!("scope.{s}"))),
        })
        .collect()
}

/// The locale of an account page: an explicit `ui_locales`, then the user's `locale` claim,
/// then `Accept-Language` and the tenant default ([`locale_for_user`]).
pub(super) async fn account_locale(
    state: &AppState,
    tenant: &ResolvedTenant,
    request: &RequestLocale,
    session: &BrowserSession,
) -> Locale {
    let claim = match state
        .storage()
        .users()
        .get(tenant.tenant.id, session.user_id)
        .await
    {
        Ok(user) => user.and_then(|u| u.claims.locale),
        Err(e) => {
            tracing::warn!(error = %e, "loading the user for the page locale failed");
            None
        }
    };
    locale_for_user(state, tenant, request, claim.as_deref())
}

/// Sets `Cache-Control: no-store` (the pages are per user and carry a CSRF token).
pub(super) fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// The caller's active session of this tenant, if any.
pub(super) async fn current_session(
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

fn see_other(location: &str) -> Response {
    no_store(
        (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location.to_owned())],
        )
            .into_response(),
    )
}

/// The sign-in page for `request` (built by [`NavContext`]; a request that is no longer live
/// gives the plain sign-in page). Shared by the consent screen, the account chooser and the
/// organization pages when there is no session.
pub(super) async fn to_login(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    request: AuthRequestId,
) -> Response {
    let nav = NavContext::from_request(state, tenant, Some(request)).await;
    see_other(&nav.url(tenant, loc, UiPage::Login))
}

fn flow_expired(state: &AppState, tenant: &ResolvedTenant, loc: &Locale) -> Response {
    error_page_in(
        state,
        Some(tenant),
        loc,
        StatusCode::BAD_REQUEST,
        "flow_expired",
        "",
    )
}

/// The `request` parameter; absent or malformed → the invalid request page.
fn request_id(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    q: &UiQuery,
) -> Result<AuthRequestId, Box<Response>> {
    match q.auth_request() {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(Box::new(bad_form(state, tenant, loc))),
        Err(bad) => Err(Box::new(bad.into_response(state, Some(tenant), loc))),
    }
}

/// Up to two initials for the avatar of a CIMD client: the first letter or digit of the first
/// two words of `name`, upper-cased; the first letter or digit of `host` when the name has none.
fn initials(name: &str, host: &str) -> String {
    let first = |word: &str| word.chars().find(|c| c.is_alphanumeric());
    let out: String = name
        .split_whitespace()
        .filter_map(first)
        .take(2)
        .flat_map(char::to_uppercase)
        .collect();
    if out.is_empty() {
        first(host)
            .map(|c| c.to_uppercase().collect())
            .unwrap_or_default()
    } else {
        out
    }
}

/// The `data-provenance` value (and message key suffix) of a client's provenance.
fn provenance_name(p: &Provenance) -> &'static str {
    match p {
        Provenance::Static => "static",
        Provenance::Dynamic => "dynamic",
        Provenance::Cimd { .. } => "cimd",
    }
}

/// Starts a consent flow for `request` (sets its cookie) and renders the screen.
async fn consent_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    request: AuthRequestId,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let (flow, page) = match state
        .ui_consent_service()
        .start(tenant.tenant.id, session, request)
        .await
    {
        Ok(ConsentStart::Started { flow, page }) => (flow, page),
        Ok(ConsentStart::RequestExpired) => return flow_expired(state, tenant, loc),
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, flow.cookie_token.expose_secret()),
    );
    let view = &page.view;
    let new_scopes = scope_views(state, loc, &view.new_scopes);
    let granted_scopes = scope_views(state, loc, &view.granted_scopes);
    let cimd_host = view.cimd_host();
    let messages = localized(state, loc, messages);
    let account_email = match state
        .ui_consent_service()
        .account_email(tenant.tenant.id, session)
        .await
    {
        Ok(email) => email,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.consent").into_value(),
        account_email => account_email,
        client_name => &view.client_name,
        client_id => &page.client_id,
        agent => view.client_kind == ClientKind::Agent,
        provenance => provenance_name(&view.provenance),
        new_scopes => minijinja::Value::from(minijinja::value::Serde(&new_scopes)),
        granted_scopes => minijinja::Value::from(minijinja::value::Serde(&granted_scopes)),
        new_resources => &view.new_resources,
        granted_resources => &view.granted_resources,
        cimd_host => cimd_host,
        client_initials => cimd_host.map(|host| initials(&view.client_name, host)),
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        csrf_token => flow.csrf_token.expose_secret(),
        action => carry_ui_locales(
            &tenant.ui_url(&format!("{PAGE}?flow={}&request={request}", flow.flow_id)),
            loc,
        ),
    };
    match state.renderer().page("consent.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the consent page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    let request = match request_id(&state, &tenant, &locale.0, &q) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let loc = page_locale(&state, &tenant, locale, &headers, Some(request)).await;
    match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => {
            consent_page(
                &state,
                &tenant,
                &loc,
                &s,
                request,
                Vec::new(),
                StatusCode::OK,
            )
            .await
        }
        Ok(None) => to_login(&state, &tenant, &loc, request).await,
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<ConsentForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let answer = match (form.choice.as_deref(), form.decision.as_deref()) {
        (Some("other"), None) => Answer::OtherAccount,
        (None, Some("allow")) => Answer::Allow,
        (None, Some("deny")) => Answer::Deny,
        _ => return bad_form(&state, &tenant, &locale.0),
    };
    let request = match request_id(&state, &tenant, &locale.0, &q) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let loc = page_locale(&state, &tenant, locale, &headers, Some(request)).await;
    let session = match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return to_login(&state, &tenant, &loc, request).await,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.filter(|c| !c.is_empty()))
    else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let binding = ConsentBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: &csrf,
    };
    let consent = state.ui_consent_service();
    let result = match answer {
        Answer::Allow => {
            consent
                .approve(tenant.tenant.id, &session, &binding, &ctx)
                .await
        }
        Answer::Deny => consent.deny(tenant.tenant.id, &session, &binding).await,
        Answer::OtherAccount => {
            consent
                .switch_account(tenant.tenant.id, &session, &binding)
                .await
        }
    };
    let approved = answer == Answer::Allow;
    match result {
        Ok(ConsentSubmission::Decided(decided)) if answer == Answer::OtherAccount => {
            use_another_account(&state, &tenant, &loc, decided).await
        }
        Ok(ConsentSubmission::Decided(decided)) => {
            match state
                .authorize_service()
                .finish_consent(
                    &tenant.tenant,
                    &tenant.issuer,
                    decided,
                    Some(session),
                    approved,
                )
                .await
            {
                Ok(outcome) => no_store(state.authorize_response(&tenant, &loc, outcome)),
                Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
            }
        }
        Ok(ConsentSubmission::Expired) => {
            consent_page(
                &state,
                &tenant,
                &loc,
                &session,
                request,
                vec![PageMessage::error(EXPIRED)],
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &loc),
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::initials;

    #[test]
    fn initials_take_two_words_and_fall_back_to_the_host() {
        assert_eq!(initials("Acme <Bank> Online", "app.example.com"), "AB");
        assert_eq!(initials("acme", "app.example.com"), "A");
        assert_eq!(initials("élan vital", "x.example"), "ÉV");
        assert_eq!(initials("<> !!", "app.example.com"), "A");
        assert_eq!(initials("", ""), "");
    }
}
