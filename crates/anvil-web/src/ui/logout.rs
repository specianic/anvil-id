//! Logout confirmation and signed-out pages (OIDC-12, RP-Initiated Logout 1.0 §2).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/logout?client_id=&post_logout_redirect_uri=&state=` | confirmation page: validates the parameters again (no hint, so it never logs out), starts a `FlowKind::Logout` flow (flow cookie + CSRF token). Without a session it does not ask: 303 to the validated post-logout URI, else to the signed-out page |
//! | `POST /ui/logout?flow=` | the user confirmed: logs the current session out, then redirects to the validated post-logout URI or to the signed-out page |
//! | `GET  /ui/signed-out?client_id=` | the signed-out page ("You have been signed out.") with a way forward |
//!
//! The end-session endpoint (`protocol::logout`) sends the browser here when it must ask. The
//! confirmation page lives under `/ui/logout` and the signed-out page does not: the conformance
//! suite's browser tells them apart by URL (tests/conformance/README.md).
//!
//! Every route here is behind the Fetch-Metadata layer; the POST must carry the flow cookie and
//! the CSRF token, otherwise the `csrf` error page (403) and nothing changes. "Stay signed in"
//! keeps the session and goes back to the logout client's app when it is a static client with a
//! home (`initiate_login_uri`, else `client_uri`; never a DCR or CIMD client's URL), else to the
//! account page. All pages work without JavaScript and are `Cache-Control: no-store`.
//!
//! No dead ends: every link onward is built by [`NavContext`] (`ui::nav`). The signed-out page
//! offers "Back to &lt;app&gt;" (the logout client's static home, carried as `client_id` and
//! looked up again, never a URL from the request) and sign-in; the error pages offer the same
//! way forward as the other error pages ([`NavContext::error_way_forward`]).
//!
//! The `impl AppState` block holds the response helpers shared with `protocol::logout`, so both
//! endpoints finish a logout the same way: clear the session cookie, wake the back-channel
//! delivery worker (never waited for), then redirect or show the signed-out page.

use anvil_core::error::CoreError;
use anvil_core::model::BrowserSession;
use anvil_core::oauth::logout::{LogoutError, PostLogoutRedirect};
use anvil_core::service::logout::{
    ConfirmResult, ConfirmationStart, LogoutBinding, LogoutService, RawEndSession,
};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use super::consent::{current_session, no_store};
use super::login::{UiQuery, bad_form, csrf_page, rejected_form};
use super::nav::{AccountSection, NavContext, UiPage};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// The confirmation page (contract: under `/ui/logout`).
const PAGE: &str = "/ui/logout";
/// The signed-out page (contract: not under `/ui/logout`).
const SIGNED_OUT: &str = "/ui/signed-out";

/// Message key of the signed-out page (theme contract).
const MSG_SIGNED_OUT: &str = "logout.signed_out";
/// Message key when the confirmation flow expired or was already used.
const MSG_EXPIRED: &str = "logout.expired";

/// The routes of this module (tenant-relative paths), behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(PAGE, get(show).post(confirm))
        .route(SIGNED_OUT, get(signed_out))
}

impl AppState {
    /// The logout service.
    pub(crate) fn ui_logout_service(&self) -> LogoutService {
        LogoutService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }

    /// The caller's active session of this tenant, if any.
    pub(crate) async fn logout_current_session(
        &self,
        tenant: &ResolvedTenant,
        jar: &CookieJar,
    ) -> Result<Option<BrowserSession>, CoreError> {
        current_session(self, tenant, jar).await
    }

    /// The links of a logout page: the static home of the client the logout named (when known)
    /// through [`NavContext::for_client`], else none.
    async fn logout_nav(&self, tenant: &ResolvedTenant, client_id: Option<&str>) -> NavContext {
        match client_id.filter(|c| !c.is_empty()) {
            Some(c) => NavContext::for_client(self, tenant, c).await,
            None => NavContext::none(),
        }
    }

    /// Finishes a logout: clears the session cookie (and every cookie already in `jar`), wakes
    /// the back-channel delivery worker when a session was revoked, then 303s to `redirect`.
    /// Without a redirect it renders the signed-out page, or 303s to it when
    /// `redirect_to_signed_out` (after a request under `/ui/logout`, which must not render it).
    /// `client_id` is the client the logout named: the signed-out page offers its way back.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn logout_finished(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        jar: CookieJar,
        redirect: Option<String>,
        revoked: bool,
        redirect_to_signed_out: bool,
        client_id: Option<&str>,
    ) -> Response {
        if revoked {
            // Deliveries were enqueued with the revocation; the worker sends them. The redirect
            // never waits for it.
            self.wake_logout_worker();
        }
        let jar = jar.add(self.cookies().clear_session(&tenant.tenant));
        match (redirect, redirect_to_signed_out) {
            (Some(url), _) => see_other(jar, &url),
            (None, true) => see_other(jar, &signed_out_url(tenant, loc, client_id)),
            (None, false) => {
                let nav = self.logout_nav(tenant, client_id).await;
                no_store(
                    (jar, self.logged_out_page(tenant, loc, None, &nav, false)).into_response(),
                )
            }
        }
    }

    /// The error page of a refused end-session request (400): the contract sentence of `err`,
    /// never a redirect, nothing changed. The way forward names `client_id` (the request's
    /// parameter; only a static client's stored home is ever shown) and depends on `signed_in`.
    pub(crate) async fn logout_error_page(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        err: LogoutError,
        client_id: Option<&str>,
        signed_in: bool,
    ) -> Response {
        let nav = self.logout_nav(tenant, client_id).await;
        no_store(
            (
                StatusCode::BAD_REQUEST,
                self.logged_out_page(tenant, loc, Some(err.key()), &nav, signed_in),
            )
                .into_response(),
        )
    }

    /// 303 to the confirmation page with the parameters the decision resolved (no hint).
    pub(crate) fn logout_confirm_redirect(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        client_id: Option<&str>,
        redirect: Option<&PostLogoutRedirect>,
    ) -> Response {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        if let Some(c) = client_id {
            q.append_pair("client_id", c);
        }
        if let Some(r) = redirect {
            q.append_pair("post_logout_redirect_uri", &r.uri);
            if let Some(s) = &r.state {
                q.append_pair("state", s);
            }
        }
        let q = q.finish();
        let url = if q.is_empty() {
            tenant.ui_url(PAGE)
        } else {
            tenant.ui_url(&format!("{PAGE}?{q}"))
        };
        see_other(CookieJar::new(), &carry_ui_locales(&url, loc))
    }

    /// The signed-out page (`error_key: None`) or a sign-out error page, as a body, with the way
    /// forward of `nav`: "Back to &lt;app&gt;" first when the client has a static home, then
    /// sign-in (signed out) or the account page and the sign-out form (`signed_in`, error pages).
    fn logged_out_page(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        error_key: Option<&'static str>,
        nav: &NavContext,
        signed_in: bool,
    ) -> Response {
        let (title, heading, key) = match error_key {
            Some(k) => ("title.logout_error", "logout.error_heading", k),
            None => (
                "title.logged_out",
                "logout.signed_out_heading",
                MSG_SIGNED_OUT,
            ),
        };
        let mut page = PageContext::for_tenant(self, tenant, loc, title);
        page.links = nav
            .error_way_forward(self, tenant, loc, signed_in)
            .into_links();
        let ctx = minijinja::context! {
            page => page.into_value(),
            heading_key => heading,
            message_key => key,
            message => self.renderer().text(loc, key),
            error => error_key.is_some(),
        };
        match self.renderer().page("logged_out.html", ctx) {
            Ok(html) => html.into_response(),
            Err(e) => {
                tracing::error!(error = %e, "rendering the signed-out page failed");
                core_error_page_in(
                    self,
                    Some(tenant),
                    loc,
                    &CoreError::Internal("render".into()),
                )
            }
        }
    }
}

/// The signed-out page's URL (outside `/ui/logout`), carrying the client the logout named.
fn signed_out_url(tenant: &ResolvedTenant, loc: &Locale, client_id: Option<&str>) -> String {
    let url = match client_id.filter(|c| !c.is_empty()) {
        Some(c) => {
            let q = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", c)
                .finish();
            tenant.ui_url(&format!("{SIGNED_OUT}?{q}"))
        }
        None => tenant.ui_url(SIGNED_OUT),
    };
    carry_ui_locales(&url, loc)
}

fn see_other(jar: CookieJar, location: &str) -> Response {
    no_store(
        (
            StatusCode::SEE_OTHER,
            jar,
            [(header::LOCATION, location.to_owned())],
        )
            .into_response(),
    )
}

/// The form the confirmation page posts.
#[derive(Default, Deserialize)]
struct ConfirmForm {
    csrf_token: Option<String>,
}

/// Starts a confirmation flow (sets its cookie) and renders the page. Without a session there is
/// nothing to confirm: 303 to the validated post-logout URI, else to the signed-out page.
async fn confirm_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    raw: &RawEndSession,
    session: Option<&BrowserSession>,
) -> Response {
    let (flow, client_name, client_id) = match state
        .ui_logout_service()
        .start_confirmation(&tenant.tenant, &tenant.issuer, raw, session)
        .await
    {
        Ok(ConfirmationStart::Started {
            flow,
            client_name,
            client_id,
        }) => (flow, client_name, client_id),
        Ok(ConfirmationStart::NotSignedIn {
            redirect,
            client_id,
        }) => {
            // Nothing was revoked, so no session cookie needs clearing; clearing it anyway is
            // harmless and drops a stale one.
            return state
                .logout_finished(
                    tenant,
                    loc,
                    CookieJar::new(),
                    redirect,
                    false,
                    true,
                    client_id.as_deref(),
                )
                .await;
        }
        Ok(ConfirmationStart::Error(e)) => {
            return state
                .logout_error_page(tenant, loc, e, raw.client_id.as_deref(), session.is_some())
                .await;
        }
        Err(e) => return no_store(core_error_page_in(state, Some(tenant), loc, &e)),
    };
    // "Stay signed in": the static client's own home, else the account page.
    let nav = state.logout_nav(tenant, client_id.as_deref()).await;
    let cancel_url = match nav.app_home() {
        Some(home) => home.href,
        None => nav.url(tenant, loc, UiPage::Account(AccountSection::Sessions)),
    };
    let jar = CookieJar::new().add(
        state
            .cookies()
            .flow_cookie(&tenant.tenant, flow.cookie_token.expose_secret()),
    );
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.logout_confirm").into_value(),
        client_name => client_name,
        csrf_token => flow.csrf_token.expose_secret(),
        action => carry_ui_locales(
            &tenant.ui_url(&format!("{PAGE}?flow={}", flow.flow_id)),
            loc,
        ),
        cancel_url => cancel_url,
    };
    match state.renderer().page("logout_confirm.html", ctx) {
        Ok(html) => no_store((jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the logout confirmation page failed");
            no_store(core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            ))
        }
    }
}

/// `GET /ui/logout`: the confirmation page. Repeated parameters are an invalid request.
async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
    uri: Uri,
) -> Response {
    let pairs = url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes());
    let Ok(raw) = RawEndSession::from_pairs(pairs.map(|(k, v)| (k, v.into_owned()))) else {
        return no_store(bad_form(&state, &tenant, &loc));
    };
    let session = match state.logout_current_session(&tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return no_store(core_error_page_in(&state, Some(&tenant), &loc, &e)),
    };
    confirm_page(&state, &tenant, &loc, &raw, session.as_ref()).await
}

/// `POST /ui/logout?flow=`: the user confirmed.
async fn confirm(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    form: Result<Form<ConfirmForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return no_store(rejected_form(&state, Some(&tenant), &loc, &e)),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.filter(|c| !c.is_empty()))
    else {
        return no_store(csrf_page(&state, Some(&tenant), &loc));
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let session = match state.logout_current_session(&tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return no_store(core_error_page_in(&state, Some(&tenant), &loc, &e)),
    };
    let binding = LogoutBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: &csrf,
    };
    match state
        .ui_logout_service()
        .confirm(&tenant.tenant, &binding, session.as_ref(), &ctx)
        .await
    {
        Ok(ConfirmResult::LoggedOut {
            redirect,
            revoked,
            client_id,
        }) => {
            let jar = CookieJar::new().add(state.cookies().clear_flow(&tenant.tenant));
            state
                .logout_finished(
                    &tenant,
                    &loc,
                    jar,
                    redirect,
                    revoked,
                    true,
                    client_id.as_deref(),
                )
                .await
        }
        Ok(ConfirmResult::Expired) => no_store(
            (
                StatusCode::BAD_REQUEST,
                state.logged_out_page(
                    &tenant,
                    &loc,
                    Some(MSG_EXPIRED),
                    &NavContext::none(),
                    session.is_some(),
                ),
            )
                .into_response(),
        ),
        Err(CoreError::Forbidden) => no_store(csrf_page(&state, Some(&tenant), &loc)),
        Err(e) => no_store(core_error_page_in(&state, Some(&tenant), &loc, &e)),
    }
}

/// `GET /ui/signed-out?client_id=`: the signed-out page. Changes nothing. `client_id` only
/// selects which stored static client's home "Back to &lt;app&gt;" shows (none for an unknown,
/// DCR or CIMD client); a repeated or missing value is no client.
async fn signed_out(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    uri: Uri,
) -> Response {
    let mut client_ids = url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .filter(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned());
    let client_id = match (client_ids.next(), client_ids.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    };
    let nav = state.logout_nav(&tenant, client_id.as_deref()).await;
    no_store(state.logged_out_page(&tenant, &loc, None, &nav, false))
}
