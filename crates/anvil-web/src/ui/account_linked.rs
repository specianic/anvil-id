//! Linked upstream identities on the account page (AUTH-11, AUTH-13).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/linked` | linked identities and the enabled connections not linked yet; starts a settings flow |
//! | `POST /ui/account/linked/connect/{slug}?flow=` | starts linking `slug` (re-auth): 303 to the provider with the binding cookie |
//! | `POST /ui/account/linked/{id}/unlink?flow=` | disconnects one link (re-auth, last-sign-in-method guard) |
//!
//! Without a session every route answers 303 to the sign-in page. Every POST is behind the
//! Fetch-Metadata layer and must carry the flow cookie and the CSRF token of a settings flow of
//! the same user; otherwise the `csrf` error page (403). Connecting and disconnecting need a
//! sign-in within the last 15 minutes (`AccountService`). Connecting runs the upstream service
//! with the settings flow (purpose `Link`); the provider returns to the upstream callback, which
//! links the signed-in user (audited `identity_linked`, mode `account`). Disconnecting is
//! refused when it would leave the account without a way to sign in
//! (`account.last_sign_in_method`). The page needs no JavaScript and keeps the default CSP.

use anvil_core::error::CoreError;
use anvil_core::model::{BrowserSession, FlowId, IdentityLinkId};
use anvil_core::service::account::{AccountError, AccountFailure, SettingsBinding};
use anvil_core::service::flow::FlowContext;
use anvil_core::service::upstream::{StartResult, UpstreamOutcome, UpstreamService};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::account_attributes::attributes_nav_or_page;
use super::account_security::{AccountHeader, account_header, client_id_param};
use super::consent::{PageMessage, account_locale, localized};
use super::format::{human, iso};
use super::login::{UiQuery, csrf_page, rejected_form, tenant_relying_party, ui_base};
use super::nav::{AccountSection, NavContext};
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/account/linked";
/// Message key after a link was removed.
const MSG_UNLINKED: &str = "linked.unlinked";

/// Linked-identity routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(PAGE, get(show))
        .route("/ui/account/linked/connect/{slug}", post(connect))
        .route("/ui/account/linked/{id}/unlink", post(unlink))
}

#[derive(Default, Deserialize)]
struct LinkedForm {
    csrf_token: Option<String>,
}

#[derive(Serialize)]
struct LinkedRow {
    id: String,
    provider: String,
    email: Option<String>,
    created: String,
    created_iso: String,
    last_used: Option<String>,
    last_used_iso: Option<String>,
    unlink_url: String,
}

#[derive(Serialize)]
struct ConnectButton {
    slug: String,
    name: String,
    connect_url: String,
}

/// A submission resolved to its session, page locale and settings flow binding.
struct Submission {
    session: BrowserSession,
    locale: Locale,
    flow_id: FlowId,
    cookie: Option<String>,
    csrf: String,
    /// The account header (no `client_id` on a form post).
    header: AccountHeader,
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

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// `Cache-Control: no-store` (per-user page with a CSRF token).
fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn to_login(tenant: &ResolvedTenant) -> Response {
    let location = NavContext::login_returning_to(tenant, AccountSection::Linked);
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
    let session = match session(state, tenant, jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Box::new(to_login(tenant))),
        Err(e) => {
            return Err(Box::new(core_error_page_in(
                state,
                Some(tenant),
                &locale.0,
                &e,
            )));
        }
    };
    let loc = account_locale(state, tenant, locale, &session).await;
    let (Some(flow_id), Some(csrf)) = (query.flow_id(), csrf.filter(|c| !c.is_empty())) else {
        return Err(Box::new(csrf_page(state, Some(tenant), &loc)));
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let header = account_header(state, tenant, &loc, &session, None).await?;
    Ok(Submission {
        session,
        locale: loc,
        flow_id,
        cookie,
        csrf,
        header,
    })
}

/// Renders the page bound to `flow` / `csrf`.
#[expect(
    clippy::too_many_arguments,
    reason = "page renderer threads the request's binding"
)]
async fn render_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    header: &AccountHeader,
    flow: FlowId,
    csrf: &str,
    messages: Vec<PageMessage>,
    status: StatusCode,
    jar: CookieJar,
) -> Response {
    let accounts = state.ui_account_service();
    let tid = tenant.tenant.id;
    let (linked, available) = match (
        accounts.linked_identities(tid, session.user_id).await,
        accounts.available_connections(tid, session.user_id).await,
    ) {
        (Ok(l), Ok(a)) => (l, a),
        (Err(e), _) | (_, Err(e)) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let rows: Vec<LinkedRow> = linked
        .into_iter()
        .map(|l| LinkedRow {
            unlink_url: flow_url(tenant, &format!("{PAGE}/{}/unlink", l.id), flow),
            id: l.id.to_string(),
            provider: l.connection_display_name,
            email: l.email_at_link,
            created: human(l.created_at),
            created_iso: iso(l.created_at),
            last_used: l.last_used_at.map(human),
            last_used_iso: l.last_used_at.map(iso),
        })
        .collect();
    let buttons: Vec<ConnectButton> = available
        .into_iter()
        .map(|c| ConnectButton {
            connect_url: flow_url(tenant, &format!("{PAGE}/connect/{}", c.slug), flow),
            slug: c.slug,
            name: c.display_name,
        })
        .collect();
    let recent_auth =
        anvil_core::flow::settings::is_recent_auth(session.auth_time, state.clock().now());
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let messages = localized(state, loc, messages);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_linked").into_value(),
        account_base => tenant.base_path(),
        account_nav => "linked",
        account_attributes_nav => attributes_nav,
        account_header => header.value(),
        csrf_token => csrf,
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        recent_auth => recent_auth,
        login_url => NavContext::login_returning_to(tenant, AccountSection::Linked),
        linked => minijinja::Value::from(minijinja::value::Serde(&rows)),
        available => minijinja::Value::from(minijinja::value::Serde(&buttons)),
    };
    match state.renderer().page("account_linked.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the linked accounts page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

/// Starts a fresh settings flow (sets its cookie) and renders the page with `messages`.
async fn fresh_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    header: &AccountHeader,
    messages: Vec<PageMessage>,
    status: StatusCode,
) -> Response {
    let started = match state
        .ui_account_service()
        .start(tenant.tenant.id, session)
        .await
    {
        Ok(s) => s,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
    );
    render_page(
        state,
        tenant,
        loc,
        session,
        header,
        started.flow_id,
        started.csrf_token.expose_secret(),
        messages,
        status,
        jar,
    )
    .await
}

/// Re-renders the page of a submission with one message: same flow, or a fresh one when the
/// flow expired.
async fn reply(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    message: PageMessage,
    status: StatusCode,
    flow_expired: bool,
) -> Response {
    if flow_expired {
        return fresh_page(
            state,
            tenant,
            &sub.locale,
            &sub.session,
            &sub.header,
            vec![message],
            status,
        )
        .await;
    }
    render_page(
        state,
        tenant,
        &sub.locale,
        &sub.session,
        &sub.header,
        sub.flow_id,
        &sub.csrf,
        vec![message],
        status,
        CookieJar::new(),
    )
    .await
}

/// The status of a refusal shown on the page.
fn refusal_status(f: AccountFailure) -> StatusCode {
    match f {
        AccountFailure::LinkNotFound => StatusCode::NOT_FOUND,
        AccountFailure::LastSignInMethod => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    }
}

/// The response to a refused account change: the `csrf` page for a broken binding, an error
/// page for a core error, else the page with the refusal.
async fn refused(
    state: &AppState,
    tenant: &ResolvedTenant,
    sub: &Submission,
    err: AccountError,
) -> Response {
    match err {
        AccountError::Core(CoreError::Forbidden) => csrf_page(state, Some(tenant), &sub.locale),
        AccountError::Core(e) => core_error_page_in(state, Some(tenant), &sub.locale, &e),
        AccountError::Failure(f) => {
            reply(
                state,
                tenant,
                sub,
                PageMessage::error(f.key()),
                refusal_status(f),
                f == AccountFailure::FlowExpired,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    RawQuery(query): RawQuery,
) -> Response {
    match session(&state, &tenant, &jar).await {
        Ok(Some(s)) => {
            let loc = account_locale(&state, &tenant, &locale, &s).await;
            let client_id = client_id_param(query.as_deref());
            let header = match account_header(&state, &tenant, &loc, &s, client_id.as_deref()).await
            {
                Ok(h) => h,
                Err(page) => return *page,
            };
            fresh_page(
                &state,
                &tenant,
                &loc,
                &s,
                &header,
                Vec::new(),
                StatusCode::OK,
            )
            .await
        }
        Ok(None) => to_login(&tenant),
        Err(e) => core_error_page_in(&state, Some(&tenant), &locale.0, &e),
    }
}

/// `POST /ui/account/linked/connect/{slug}?flow=`: checks the settings flow and the recent
/// sign-in, then starts the upstream flow with purpose `Link` (303 to the provider).
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn connect(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<LinkedForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let accounts = state.ui_account_service();
    // Refusals (expired flow, stale sign-in) are shown on this page, before the upstream
    // service is asked (it would answer an expired flow with a sign-in page).
    if let Err(e) = accounts
        .check_link_start(tenant.tenant.id, &sub.session, &sub.binding())
        .await
    {
        return refused(&state, &tenant, &sub, e).await;
    }
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let flows = state.ui_flow_service();
    let upstream = UpstreamService {
        flows: &flows,
        accounts: &accounts,
        client: state.upstream(),
    };
    let result = upstream
        .start(&cx, &sub.binding(), &slug, Some(&sub.session))
        .await;
    match result {
        Ok(StartResult::Redirect(r)) => {
            let Ok(location) = HeaderValue::from_str(&r.url) else {
                return core_error_page_in(
                    &state,
                    Some(&tenant),
                    &sub.locale,
                    &CoreError::Internal("unusable upstream authorization URL".into()),
                );
            };
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .upstream_binding_cookie(&tenant.tenant, r.binding_cookie.expose_secret()),
            );
            no_store((StatusCode::SEE_OTHER, jar, [(header::LOCATION, location)]).into_response())
        }
        Ok(StartResult::Done(outcome)) => {
            let key = match *outcome {
                UpstreamOutcome::LinkFailed { key } => key,
                // Not an answer to a settings flow (e.g. the flow vanished meanwhile).
                _ => "upstream.link_failed",
            };
            reply(
                &state,
                &tenant,
                &sub,
                PageMessage::error(key),
                StatusCode::BAD_REQUEST,
                false,
            )
            .await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &sub.locale),
        Err(CoreError::NotFound) => error_page_in(
            &state,
            Some(&tenant),
            &sub.locale,
            StatusCode::NOT_FOUND,
            "not_found",
            "",
        ),
        Err(e) => core_error_page_in(&state, Some(&tenant), &sub.locale, &e),
    }
}

/// `POST /ui/account/linked/{id}/unlink?flow=`.
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn unlink(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Path(id): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<LinkedForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let sub = match submission(&state, &tenant, &locale, &jar, &q, form.csrf_token).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let accounts = state.ui_account_service();
    let Ok(id) = uuid::Uuid::parse_str(&id).map(IdentityLinkId) else {
        // A malformed id is checked after the binding like any other: no binding, no answer.
        let refusal = match accounts
            .check_link_start(tenant.tenant.id, &sub.session, &sub.binding())
            .await
        {
            Ok(()) => AccountError::Failure(AccountFailure::LinkNotFound),
            Err(e) => e,
        };
        return refused(&state, &tenant, &sub, refusal).await;
    };
    match accounts
        .unlink(&tenant.tenant, &sub.session, &sub.binding(), id, &ctx)
        .await
    {
        Ok(()) => {
            reply(
                &state,
                &tenant,
                &sub,
                PageMessage::info(MSG_UNLINKED),
                StatusCode::OK,
                false,
            )
            .await
        }
        Err(e) => refused(&state, &tenant, &sub, e).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_message_keys_have_english_text() {
        let catalogs = crate::i18n::Catalogs::load(None).expect("catalogs");
        let en = Locale::fallback();
        for key in [
            AccountFailure::LastSignInMethod.key(),
            AccountFailure::LinkNotFound.key(),
            AccountFailure::ReauthRequired.key(),
            MSG_UNLINKED,
            "title.account_linked",
            "account_nav.linked",
        ] {
            assert_ne!(catalogs.text(&en, key, &[]), key, "{key}");
        }
    }

    #[test]
    fn refusals_have_distinct_statuses() {
        assert_eq!(
            refusal_status(AccountFailure::LinkNotFound),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            refusal_status(AccountFailure::LastSignInMethod),
            StatusCode::CONFLICT
        );
        assert_eq!(
            refusal_status(AccountFailure::ReauthRequired),
            StatusCode::BAD_REQUEST
        );
    }
}
