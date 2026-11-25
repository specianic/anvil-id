//! Account sessions page (AUTH-10): the signed-in user's active sessions, signing out one of
//! them or every other one.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/sessions` | page; starts a settings flow (flow cookie + CSRF token) |
//! | `POST /ui/account/sessions/{id}/revoke?flow=` | signs out one session (the current one: 303 to sign-in) |
//! | `POST /ui/account/sessions/revoke-others?flow=` | signs out every other session |
//!
//! Without a session every route answers 303 to the sign-in page. Every POST is behind the
//! Fetch-Metadata layer and must carry the flow cookie and the CSRF token of a settings flow of
//! the same user (`SessionService::check_settings_binding`); otherwise the `csrf` error page
//! (403). Signing out needs no recent sign-in. Revoking a session also revokes the token families
//! issued under it. The page needs no JavaScript and keeps the default CSP.

use anvil_core::error::CoreError;
use anvil_core::model::{BrowserSession, FlowId, SessionId};
use anvil_core::service::account::{AccountError, SettingsBinding};
use anvil_core::service::session::{
    MSG_OTHERS_REVOKED, MSG_SESSION_NOT_FOUND, MSG_SESSION_REVOKED, SessionInfo, message_text,
};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::format::{human, iso};
use super::login::{UiQuery, bad_form, csrf_page};
use crate::errors::core_error_page;
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/account/sessions";
/// Longest user agent shown (characters); longer ones end in an ellipsis.
const DEVICE_MAX_CHARS: usize = 80;

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PAGE, get(show))
        .route("/ui/account/sessions/{id}/revoke", post(revoke_one))
        .route("/ui/account/sessions/revoke-others", post(revoke_others))
}

#[derive(Default, Deserialize)]
struct SessionsForm {
    csrf_token: Option<String>,
}

/// A message shown on the page (`data-message-key` like the other account pages).
#[derive(Debug, Clone, Serialize)]
struct PageMessage {
    level: &'static str,
    key: &'static str,
    text: &'static str,
}

impl PageMessage {
    fn error(key: &'static str) -> Self {
        let text = match key {
            k if k.starts_with("account.") => anvil_core::service::account::message_text(k),
            k => message_text(k),
        };
        Self {
            level: "error",
            key,
            text,
        }
    }

    fn info(key: &'static str) -> Self {
        Self {
            level: "info",
            key,
            text: message_text(key),
        }
    }
}

/// A submission resolved to its session and settings flow binding.
struct Submission {
    session: BrowserSession,
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

#[derive(Serialize)]
struct SessionRow {
    id: String,
    device: String,
    ip: Option<String>,
    created: String,
    created_iso: String,
    last_seen: String,
    last_seen_iso: String,
    current: bool,
    revoke_url: String,
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `Cache-Control: no-store` (the page lists IP addresses and devices).
fn with_headers(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn to_login(tenant: &ResolvedTenant, jar: CookieJar) -> Response {
    let location = tenant.ui_url("/ui/login");
    with_headers((StatusCode::SEE_OTHER, jar, [(header::LOCATION, location)]).into_response())
}

/// The user agent as shown: trimmed, at most [`DEVICE_MAX_CHARS`] characters (then `…`), or
/// "Unknown device". Escaping is left to the template engine.
fn device_label(user_agent: Option<&str>) -> String {
    let ua = user_agent.map(str::trim).unwrap_or_default();
    if ua.is_empty() {
        return "Unknown device".to_owned();
    }
    if ua.chars().count() <= DEVICE_MAX_CHARS {
        return ua.to_owned();
    }
    let mut short: String = ua.chars().take(DEVICE_MAX_CHARS - 1).collect();
    short.push('…');
    short
}



fn flow_url(tenant: &ResolvedTenant, path: &str, flow: FlowId) -> String {
    tenant.ui_url(&format!("{path}?flow={flow}"))
}

fn row(tenant: &ResolvedTenant, flow: FlowId, s: &SessionInfo) -> SessionRow {
    SessionRow {
        id: s.id.to_string(),
        device: device_label(s.user_agent.as_deref()),
        ip: s.ip.clone(),
        created: human(s.created_at),
        created_iso: iso(s.created_at),
        last_seen: human(s.last_seen_at),
        last_seen_iso: iso(s.last_seen_at),
        current: s.current,
        revoke_url: flow_url(
            tenant,
            &format!("/ui/account/sessions/{}/revoke", s.id),
            flow,
        ),
    }
}

/// The caller's active session, if any (records the activity, throttled).
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

/// Resolves the session (303 to sign-in without one) and the flow binding (csrf page when the
/// flow id or the CSRF token is missing).
async fn submission(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
    query: &UiQuery,
    csrf: Option<String>,
) -> Result<Submission, Box<Response>> {
    let session = match session(state, tenant, jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Box::new(to_login(tenant, CookieJar::new()))),
        Err(e) => return Err(Box::new(core_error_page(state, Some(tenant), &e))),
    };
    let (Some(flow_id), Some(csrf)) = (query.flow_id(), csrf.filter(|c| !c.is_empty())) else {
        return Err(Box::new(csrf_page(state, Some(tenant))));
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    Ok(Submission {
        session,
        flow_id,
        cookie,
        csrf,
    })
}

/// Renders the session list bound to `flow` / `csrf`.
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding"
)]
async fn render_list(
    state: &AppState,
    tenant: &ResolvedTenant,
    session: &BrowserSession,
    flow: FlowId,
    csrf: &str,
    messages: Vec<PageMessage>,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let sessions = match state
        .ui_session_service()
        .list_for_user(tenant.tenant.id, session.user_id, Some(session.id))
        .await
    {
        Ok(s) => s,
        Err(e) => return core_error_page(state, Some(tenant), &e),
    };
    let rows: Vec<SessionRow> = sessions.iter().map(|s| row(tenant, flow, s)).collect();
    let others = rows.iter().filter(|r| !r.current).count();
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, "Sessions").into_value(),
        account_base => tenant.base_path(),
        account_nav => "sessions",
        csrf_token => csrf,
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        sessions => minijinja::Value::from(minijinja::value::Serde(&rows)),
        other_count => others,
        revoke_others_url => flow_url(tenant, "/ui/account/sessions/revoke-others", flow),
    };
    match state.renderer().page("account_sessions.html", ctx) {
        Ok(html) => with_headers((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the sessions page failed");
            core_error_page(state, Some(tenant), &CoreError::Internal("render".into()))
        }
    }
}

/// Starts a fresh settings flow (sets its cookie) and renders the list with `messages`.
async fn fresh_list(
    state: &AppState,
    tenant: &ResolvedTenant,
    session: &BrowserSession,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let started = match state
        .ui_account_service()
        .start(tenant.tenant.id, session)
        .await
    {
        Ok(s) => s,
        Err(e) => return core_error_page(state, Some(tenant), &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_list(
        state,
        tenant,
        session,
        started.flow_id,
        started.csrf_token.expose_secret(),
        messages,
        status,
        jar,
    )
    .await
}

/// Checks the settings binding of a submission; `Err` is the response to send.
async fn check_binding(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
) -> Result<(), Box<Response>> {
    match state
        .ui_session_service()
        .check_settings_binding(tenant.tenant.id, &sub.session, &sub.binding())
        .await
    {
        Ok(()) => Ok(()),
        Err(AccountError::Core(CoreError::Forbidden)) => {
            Err(Box::new(csrf_page(state, Some(tenant))))
        }
        Err(AccountError::Core(e)) => Err(Box::new(core_error_page(state, Some(tenant), &e))),
        Err(AccountError::Failure(f)) => Err(Box::new(
            fresh_list(
                state,
                tenant,
                &sub.session,
                vec![PageMessage::error(f.key())],
                StatusCode::BAD_REQUEST,
            )
            .await,
        )),
    }
}

/// Re-renders the list of a submission (same flow) with one message.
async fn same_flow(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    message: PageMessage,
    status: StatusCode,
) -> Response {
    render_list(
        state,
        tenant,
        &sub.session,
        sub.flow_id,
        &sub.csrf,
        vec![message],
        status,
        CookieJar::new(),
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

async fn show(State(state): State<AppState>, tenant: ResolvedTenant, jar: CookieJar) -> Response {
    match session(&state, &tenant, &jar).await {
        Ok(Some(s)) => fresh_list(&state, &tenant, &s, Vec::new(), StatusCode::OK).await,
        Ok(None) => to_login(&tenant, CookieJar::new()),
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}

async fn revoke_one(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Path(id): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<SessionsForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    let sub = match submission(&state, &tenant, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_binding(&state, &tenant, &sub).await {
        return *resp;
    }
    let not_found = || PageMessage::error(MSG_SESSION_NOT_FOUND);
    let Ok(id) = uuid::Uuid::parse_str(&id).map(SessionId) else {
        return same_flow(&state, &tenant, &sub, not_found(), StatusCode::BAD_REQUEST).await;
    };
    match state
        .ui_session_service()
        .revoke_mine(tenant.tenant.id, sub.session.user_id, id, &ctx)
        .await
    {
        Ok(()) if id == sub.session.id => {
            // Signed out of this browser: drop its cookies and go to the sign-in page.
            let jar = CookieJar::new()
                .add(state.cookies().clear_session(&tenant.tenant))
                .add(state.cookies().clear_flow(&tenant.tenant));
            to_login(&tenant, jar)
        }
        Ok(()) => {
            same_flow(
                &state,
                &tenant,
                &sub,
                PageMessage::info(MSG_SESSION_REVOKED),
                StatusCode::OK,
            )
            .await
        }
        Err(CoreError::NotFound) => {
            same_flow(&state, &tenant, &sub, not_found(), StatusCode::BAD_REQUEST).await
        }
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}

async fn revoke_others(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<SessionsForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant);
    };
    let sub = match submission(&state, &tenant, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    if let Err(resp) = check_binding(&state, &tenant, &sub).await {
        return *resp;
    }
    match state
        .ui_session_service()
        .revoke_others(tenant.tenant.id, sub.session.user_id, sub.session.id, &ctx)
        .await
    {
        Ok(_) => {
            same_flow(
                &state,
                &tenant,
                &sub,
                PageMessage::info(MSG_OTHERS_REVOKED),
                StatusCode::OK,
            )
            .await
        }
        Err(e) => core_error_page(&state, Some(&tenant), &e),
    }
}

#[cfg(test)]
mod tests {
    use anvil_core::service::account::AccountFailure;

    use super::*;

    #[test]
    fn device_label_truncates_long_and_names_missing_agents() {
        assert_eq!(device_label(None), "Unknown device");
        assert_eq!(device_label(Some("  ")), "Unknown device");
        assert_eq!(device_label(Some("Firefox")), "Firefox");
        let long = "x".repeat(200);
        let label = device_label(Some(&long));
        assert_eq!(label.chars().count(), DEVICE_MAX_CHARS);
        assert!(label.ends_with('…'));
        // Multi-byte characters are never split.
        let wide = "é".repeat(100);
        assert_eq!(device_label(Some(&wide)).chars().count(), DEVICE_MAX_CHARS);
    }


    #[test]
    fn flow_expired_has_page_text() {
        let m = PageMessage::error(AccountFailure::FlowExpired.key());
        assert_ne!(m.text, "Something went wrong.");
        assert_ne!(
            PageMessage::info(MSG_SESSION_REVOKED).text,
            "Something went wrong."
        );
    }
}
