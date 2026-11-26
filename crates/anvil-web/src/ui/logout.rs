//! Logout confirmation and signed-out pages (OIDC-12, RP-Initiated Logout 1.0 §2).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/logout?client_id=&post_logout_redirect_uri=&state=` | confirmation page: validates the parameters again (no hint, so it never logs out), starts a `FlowKind::Logout` flow (flow cookie + CSRF token) |
//! | `POST /ui/logout?flow=` | the user confirmed: logs the current session out, then redirects to the validated post-logout URI or to the signed-out page |
//! | `GET  /ui/signed-out` | the signed-out page ("You have been signed out.") |
//!
//! The end-session endpoint (`protocol::logout`) sends the browser here when it must ask. The
//! confirmation page lives under `/ui/logout` and the signed-out page does not: the conformance
//! suite's browser tells them apart by URL (tests/conformance/README.md).
//!
//! Every route here is behind the Fetch-Metadata layer; the POST must carry the flow cookie and
//! the CSRF token, otherwise the `csrf` error page (403) and nothing changes. "Stay signed in"
//! goes to the account page and keeps the session. All pages work without JavaScript and are
//! `Cache-Control: no-store`.
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
use super::login::{UiQuery, bad_form, csrf_page};
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
/// Where "Stay signed in" goes.
const ACCOUNT: &str = "/ui/account/sessions";

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

    /// Finishes a logout: clears the session cookie (and every cookie already in `jar`), wakes
    /// the back-channel delivery worker when a session was revoked, then 303s to `redirect`.
    /// Without a redirect it renders the signed-out page, or 303s to it when
    /// `redirect_to_signed_out` (after a POST under `/ui/logout`, which must not render it).
    pub(crate) fn logout_finished(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        jar: CookieJar,
        redirect: Option<String>,
        revoked: bool,
        redirect_to_signed_out: bool,
    ) -> Response {
        if revoked {
            // Deliveries were enqueued with the revocation; the worker sends them. The redirect
            // never waits for it.
            self.wake_logout_worker();
        }
        let jar = jar.add(self.cookies().clear_session(&tenant.tenant));
        match (redirect, redirect_to_signed_out) {
            (Some(url), _) => see_other(jar, &url),
            (None, true) => see_other(jar, &carry_ui_locales(&tenant.ui_url(SIGNED_OUT), loc)),
            (None, false) => {
                no_store((jar, self.logged_out_page(tenant, loc, None)).into_response())
            }
        }
    }

    /// The error page of a refused end-session request (400): the contract sentence of `err`,
    /// never a redirect, nothing changed.
    pub(crate) fn logout_error_page(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        err: LogoutError,
    ) -> Response {
        no_store(
            (
                StatusCode::BAD_REQUEST,
                self.logged_out_page(tenant, loc, Some(err.key())),
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

    /// The signed-out page (`error_key: None`) or a sign-out error page, as a body.
    fn logged_out_page(
        &self,
        tenant: &ResolvedTenant,
        loc: &Locale,
        error_key: Option<&'static str>,
    ) -> Response {
        let (title, heading, key) = match error_key {
            Some(k) => ("title.logout_error", "logout.error_heading", k),
            None => (
                "title.logged_out",
                "logout.signed_out_heading",
                MSG_SIGNED_OUT,
            ),
        };
        let ctx = minijinja::context! {
            page => PageContext::for_tenant(self, tenant, loc, title).into_value(),
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

/// Starts a confirmation flow (sets its cookie) and renders the page.
async fn confirm_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    raw: &RawEndSession,
) -> Response {
    let (flow, client_name) = match state
        .ui_logout_service()
        .start_confirmation(&tenant.tenant, &tenant.issuer, raw)
        .await
    {
        Ok(ConfirmationStart::Started { flow, client_name }) => (flow, client_name),
        Ok(ConfirmationStart::Error(e)) => return state.logout_error_page(tenant, loc, e),
        Err(e) => return no_store(core_error_page_in(state, Some(tenant), loc, &e)),
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
        cancel_url => carry_ui_locales(&tenant.ui_url(ACCOUNT), loc),
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
    uri: Uri,
) -> Response {
    let pairs = url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes());
    let Ok(raw) = RawEndSession::from_pairs(pairs.map(|(k, v)| (k, v.into_owned()))) else {
        return no_store(bad_form(&state, &tenant, &loc));
    };
    confirm_page(&state, &tenant, &loc, &raw).await
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
    let Ok(Form(form)) = form else {
        return no_store(bad_form(&state, &tenant, &loc));
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
        Ok(ConfirmResult::LoggedOut { redirect, revoked }) => {
            let jar = CookieJar::new().add(state.cookies().clear_flow(&tenant.tenant));
            state.logout_finished(&tenant, &loc, jar, redirect, revoked, true)
        }
        Ok(ConfirmResult::Expired) => no_store(
            (
                StatusCode::BAD_REQUEST,
                state.logged_out_page(&tenant, &loc, Some(MSG_EXPIRED)),
            )
                .into_response(),
        ),
        Err(CoreError::Forbidden) => no_store(csrf_page(&state, Some(&tenant), &loc)),
        Err(e) => no_store(core_error_page_in(&state, Some(&tenant), &loc, &e)),
    }
}

/// `GET /ui/signed-out`: the signed-out page. Changes nothing.
async fn signed_out(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
) -> Response {
    no_store(state.logged_out_page(&tenant, &loc, None))
}
