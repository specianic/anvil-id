//! Account chooser for `prompt=select_account` (OIDC-14).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/select-account?request=` | shows the signed-in account ("Continue as …") and "Use another account"; starts a bound flow (flow cookie + CSRF token) |
//! | `POST /ui/select-account?flow=&request=` | `choice=continue` or `choice=other` (two submit buttons named `choice`) |
//!
//! `/authorize` sends the user here when `prompt=select_account` meets a session that was not
//! signed in during the request (`AuthorizeOutcome::SelectAccount`). "Continue" continues the
//! request as the session's user (consent and step-up still apply) and answers through the
//! request's response mode ([`AppState::authorize_response`]); "Use another account" goes to the
//! login page for the request, where signing in as someone else revokes the current session
//! (session switch, plan 04-16).
//!
//! Without a session the page sends the user to sign in (`/ui/login?request=`). The POST is
//! behind the Fetch-Metadata layer and must carry the flow cookie and the CSRF token; otherwise
//! the `csrf` error page (403) and nothing changes. An expired or used chooser flow shows the
//! chooser again with a message; an expired or used request is the `flow_expired` page. The page
//! works without JavaScript and is `Cache-Control: no-store`.

use anvil_core::error::CoreError;
use anvil_core::model::{AuthRequestId, BrowserSession};
use anvil_core::service::authorize::{AccountChoice, AccountChoiceBinding, SelectAccountStart};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use super::consent::{PageMessage, current_session, localized, no_store};
use super::login::{UiQuery, bad_form, csrf_page, page_locale, rejected_form};
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/select-account";

/// Message key shown when the chooser flow expired or was already used.
const EXPIRED: &str = "select_account.expired";

/// Account chooser routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route(PAGE, get(show).post(submit))
}

/// The form the chooser posts.
#[derive(Default, Deserialize)]
struct ChoiceForm {
    csrf_token: Option<String>,
    choice: Option<String>,
}

fn to_login(tenant: &ResolvedTenant, request: AuthRequestId) -> Response {
    no_store(
        (
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                tenant.ui_url(&format!("/ui/login?request={request}")),
            )],
        )
            .into_response(),
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

/// Starts a chooser flow for `request` (sets its cookie) and renders the page.
async fn chooser_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    request: AuthRequestId,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let (flow, page) = match state
        .authorize_service()
        .start_select_account(&tenant.tenant, session, request)
        .await
    {
        Ok(SelectAccountStart::Started { flow, page }) => (flow, page),
        Ok(SelectAccountStart::RequestExpired) => {
            return error_page_in(
                state,
                Some(tenant),
                loc,
                StatusCode::BAD_REQUEST,
                "flow_expired",
                "",
            );
        }
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, flow.cookie_token.expose_secret()),
    );
    let messages = localized(state, loc, messages);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.select_account").into_value(),
        client_name => &page.client_name,
        user_name => &page.user_name,
        user_email => &page.user_email,
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        csrf_token => flow.csrf_token.expose_secret(),
        action => carry_ui_locales(
            &tenant.ui_url(&format!("{PAGE}?flow={}&request={request}", flow.flow_id)),
            loc,
        ),
    };
    match state.renderer().page("select_account.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the account chooser failed");
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
            chooser_page(
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

async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<ChoiceForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let choice = match form.choice.as_deref() {
        Some("continue") => AccountChoice::Continue,
        Some("other") => AccountChoice::Other,
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
    let binding = AccountChoiceBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: &csrf,
    };
    match state
        .authorize_service()
        .choose_account(
            &tenant.tenant,
            &tenant.issuer,
            request,
            session.clone(),
            &binding,
            choice,
        )
        .await
    {
        Ok(Some(outcome)) => no_store(state.authorize_response(&tenant, outcome)),
        Ok(None) => {
            chooser_page(
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
