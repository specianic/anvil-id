//! Connected apps (OIDC-13, ADM-04): the apps the signed-in user granted access to, and
//! revocation.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/apps` | lists the active grants; starts a consent flow that binds the page (flow cookie + CSRF token) |
//! | `POST /ui/account/apps/{client_id}/revoke?flow=` | revokes the grant and every token family of that app for the user |
//!
//! Without a session both routes answer 303 to the sign-in page. The POST is behind the
//! Fetch-Metadata layer and must carry the flow cookie and the CSRF token; otherwise the `csrf`
//! error page (403). After a revocation the page is shown again with a message. Revoking needs no
//! recent sign-in: it only removes access. The page works without JavaScript and is
//! `Cache-Control: no-store`.

use anvil_core::error::CoreError;
use anvil_core::model::BrowserSession;
use anvil_core::service::consent::{ConsentBinding, RevokeResult};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::account_attributes::attributes_nav_or_page;
use super::consent::{
    PageMessage, ScopeView, account_locale, current_session, localized, no_store, scope_views,
};
use super::login::{UiQuery, csrf_page, rejected_form};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/account/apps";

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PAGE, get(show))
        .route("/ui/account/apps/{client_id}/revoke", post(revoke))
}

#[derive(Default, Deserialize)]
struct RevokeForm {
    csrf_token: Option<String>,
}

/// A connected app as listed on the page.
#[derive(Serialize)]
struct AppRow {
    client_id: String,
    client_name: String,
    scopes: Vec<ScopeView>,
    granted: String,
    granted_iso: String,
    revoke_url: String,
}

/// Percent-encodes a path segment (everything but RFC 3986 unreserved characters).
fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn date(t: OffsetDateTime) -> (String, String) {
    let t = t.to_offset(time::UtcOffset::UTC);
    let d = format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day());
    let iso = format!("{d}T{:02}:{:02}:{:02}Z", t.hour(), t.minute(), t.second());
    (d, iso)
}

fn to_login(tenant: &ResolvedTenant) -> Response {
    no_store(
        (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, tenant.ui_url("/ui/login"))],
        )
            .into_response(),
    )
}

/// Starts a fresh page flow (sets its cookie) and renders the list with `messages`.
async fn apps_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let consent = state.ui_consent_service();
    let flow = match consent.start_apps(tenant.tenant.id, session).await {
        Ok(f) => f,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let apps = match consent.list(tenant.tenant.id, session.user_id).await {
        Ok(a) => a,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let rows: Vec<AppRow> = apps
        .into_iter()
        .map(|a| {
            let (granted, granted_iso) = date(a.granted_at);
            AppRow {
                revoke_url: tenant.ui_url(&format!(
                    "/ui/account/apps/{}/revoke?flow={}",
                    path_segment(&a.client_id),
                    flow.flow_id
                )),
                scopes: scope_views(state, loc, &a.scopes),
                client_id: a.client_id,
                client_name: a.client_name,
                granted,
                granted_iso,
            }
        })
        .collect();
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, flow.cookie_token.expose_secret()),
    );
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let messages = localized(state, loc, messages);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_apps").into_value(),
        account_base => tenant.base_path(),
        account_nav => "apps",
        account_attributes_nav => attributes_nav,
        csrf_token => flow.csrf_token.expose_secret(),
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        apps => minijinja::Value::from(minijinja::value::Serde(&rows)),
    };
    match state.renderer().page("account_apps.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the connected apps page failed");
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
    jar: CookieJar,
) -> Response {
    match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => {
            let loc = account_locale(&state, &tenant, &locale, &s).await;
            apps_page(&state, &tenant, &loc, &s, Vec::new(), StatusCode::OK).await
        }
        Ok(None) => to_login(&tenant),
        Err(e) => core_error_page_in(&state, Some(&tenant), &locale.0, &e),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn revoke(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Path(client_id): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let session = match current_session(&state, &tenant, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return to_login(&tenant),
        Err(e) => return core_error_page_in(&state, Some(&tenant), &locale.0, &e),
    };
    let loc = account_locale(&state, &tenant, &locale, &session).await;
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
    let result = state
        .ui_consent_service()
        .revoke(tenant.tenant.id, &session, &binding, &client_id, &ctx)
        .await;
    let (message, status) = match result {
        Ok(RevokeResult::Revoked) => (PageMessage::info("apps.revoked"), StatusCode::OK),
        Ok(RevokeResult::NoGrant) => (
            PageMessage::error("apps.not_found"),
            StatusCode::BAD_REQUEST,
        ),
        Ok(RevokeResult::FlowExpired) => {
            (PageMessage::error("apps.expired"), StatusCode::BAD_REQUEST)
        }
        Err(CoreError::Forbidden) => return csrf_page(&state, Some(&tenant), &loc),
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    apps_page(&state, &tenant, &loc, &session, vec![message], status).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(path_segment("abc-DEF_1.2~"), "abc-DEF_1.2~");
        assert_eq!(path_segment("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(path_segment("é"), "%C3%A9");
    }
}
