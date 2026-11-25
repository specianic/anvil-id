//! Consent screen (OIDC-13) for clients with `consent_mode = required`.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/consent?request=` | names the client and lists the requested scopes; starts a consent flow (flow cookie + CSRF token) |
//! | `POST /ui/consent?flow=&request=` | `decision=allow` or `decision=deny` (two submit buttons named `decision`) |
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

use anvil_core::error::CoreError;
use anvil_core::flow::consent::scope_description;
use anvil_core::model::{AuthRequestId, BrowserSession};
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

use super::login::{UiQuery, bad_form, csrf_page, page_locale};
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
}

/// A message on the consent and account pages (`data-message-key` like the form messages).
/// `text` is filled for the page's locale by [`localized`] just before rendering.
#[derive(Debug, Clone, Serialize)]
pub(super) struct PageMessage {
    pub(super) level: &'static str,
    pub(super) key: &'static str,
    pub(super) text: String,
}

impl PageMessage {
    pub(super) fn error(key: &'static str) -> Self {
        Self {
            level: "error",
            key,
            text: String::new(),
        }
    }

    pub(super) fn info(key: &'static str) -> Self {
        Self {
            level: "info",
            key,
            text: String::new(),
        }
    }

    /// The message with its text in `loc`.
    pub(super) fn localized(mut self, state: &AppState, loc: &Locale) -> Self {
        self.text = state.renderer().text(loc, self.key);
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

fn to_login(tenant: &ResolvedTenant, request: AuthRequestId) -> Response {
    see_other(&tenant.ui_url(&format!("/ui/login?request={request}")))
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
    let scopes = scope_views(state, loc, &page.scopes);
    let messages = localized(state, loc, messages);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.consent").into_value(),
        client_name => &page.client_name,
        client_id => &page.client_id,
        scopes => minijinja::Value::from(minijinja::value::Serde(&scopes)),
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
        Ok(None) => to_login(&tenant, request),
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
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &locale.0);
    };
    let approved = match form.decision.as_deref() {
        Some("allow") => true,
        Some("deny") => false,
        _ => return bad_form(&state, &tenant, &locale.0),
    };
    let request = match request_id(&state, &tenant, &locale.0, &q) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let loc = page_locale(&state, &tenant, locale, &headers, Some(request)).await;
    let session = match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return to_login(&tenant, request),
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
    let result = if approved {
        consent
            .approve(tenant.tenant.id, &session, &binding, &ctx)
            .await
    } else {
        consent.deny(tenant.tenant.id, &session, &binding).await
    };
    match result {
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
                Ok(outcome) => no_store(state.authorize_response(&tenant, outcome)),
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
