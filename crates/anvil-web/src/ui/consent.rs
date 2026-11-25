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
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::login::{UiQuery, bad_form, csrf_page};
use crate::errors::{core_error_page, error_page};
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

/// A message on a consent or connected-apps page (`data-message-key` like the form messages).
#[derive(Debug, Clone, Serialize)]
pub(super) struct PageMessage {
    pub(super) level: &'static str,
    pub(super) key: &'static str,
    pub(super) text: &'static str,
}

impl PageMessage {
    pub(super) fn error(key: &'static str) -> Self {
        Self {
            level: "error",
            key,
            text: message_text(key),
        }
    }

    pub(super) fn info(key: &'static str) -> Self {
        Self {
            level: "info",
            key,
            text: message_text(key),
        }
    }
}

/// Text of a consent or connected-apps message key.
fn message_text(key: &str) -> &'static str {
    match key {
        EXPIRED => "This page expired. Please review the request again.",
        "apps.revoked" => "Access removed. The app can no longer use your account.",
        "apps.not_found" => "That app no longer has access to your account.",
        "apps.expired" => "This page expired. Please try again.",
        _ => "Something went wrong.",
    }
}

/// A requested scope as shown on the page: its plain-language description, or its name.
#[derive(Debug, Clone, Serialize)]
pub(super) struct ScopeView {
    pub(super) name: String,
    pub(super) description: Option<&'static str>,
}

pub(super) fn scope_views(scopes: &[String]) -> Vec<ScopeView> {
    scopes
        .iter()
        .map(|s| ScopeView {
            name: s.clone(),
            description: scope_description(s),
        })
        .collect()
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

fn flow_expired(state: &AppState, tenant: &ResolvedTenant) -> Response {
    error_page(
        state,
        Some(tenant),
        StatusCode::BAD_REQUEST,
        "flow_expired",
        "",
    )
}

/// The `request` parameter; absent or malformed → the invalid request page.
fn request_id(
    state: &AppState,
    tenant: &ResolvedTenant,
    q: &UiQuery,
) -> Result<AuthRequestId, Box<Response>> {
    match q.auth_request() {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(Box::new(bad_form(state, tenant))),
        Err(bad) => Err(Box::new(bad.into_response(state, Some(tenant)))),
    }
}

/// Starts a consent flow for `request` (sets its cookie) and renders the screen.
async fn consent_page(
    state: &AppState,
    tenant: &ResolvedTenant,
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
        Ok(ConsentStart::RequestExpired) => return flow_expired(state, tenant),
        Err(e) => return core_error_page(state, Some(tenant), &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, flow.cookie_token.expose_secret()),
    );
    let scopes = scope_views(&page.scopes);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, "Allow access").into_value(),
        client_name => &page.client_name,
        client_id => &page.client_id,
        scopes => minijinja::Value::from(minijinja::value::Serde(&scopes)),
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        csrf_token => flow.csrf_token.expose_secret(),
        action => tenant.ui_url(&format!("{PAGE}?flow={}&request={request}", flow.flow_id)),
    };
    match state.renderer().page("consent.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the consent page failed");
            core_error_page(state, Some(tenant), &CoreError::Internal("render".into()))
        }
    }
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    let request = match request_id(&state, &tenant, &q) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => consent_page(&state, &tenant, &s, request, Vec::new(), StatusCode::OK).await,
        Ok(None) => to_login(&tenant, request),
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}

async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<ConsentForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    let approved = match form.decision.as_deref() {
        Some("allow") => true,
        Some("deny") => false,
        _ => return bad_form(&state, &tenant),
    };
    let request = match request_id(&state, &tenant, &q) {
        Ok(r) => r,
        Err(resp) => return *resp,
    };
    let session = match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return to_login(&tenant, request),
        Err(e) => return core_error_page(&state, Some(&tenant), &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.filter(|c| !c.is_empty()))
    else {
        return csrf_page(&state, Some(&tenant));
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
                Err(e) => core_error_page(&state, Some(&tenant), &e),
            }
        }
        Ok(ConsentSubmission::Expired) => {
            consent_page(
                &state,
                &tenant,
                &session,
                request,
                vec![PageMessage::error(EXPIRED)],
                StatusCode::BAD_REQUEST,
            )
            .await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant)),
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}
