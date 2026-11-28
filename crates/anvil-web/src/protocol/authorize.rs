//! Authorization endpoint (`GET`/`POST {issuer}/authorize`, OIDC Core §3.1.2) and the
//! continuation after login (`GET {issuer}/authorize/continue?request={id}`).
//!
//! The handlers only translate HTTP into [`AuthorizeService`] calls and outcomes into responses:
//! - `Respond` → the authorization response (success and error, always with `iss`), delivered in
//!   its response mode: `query` → `303 See Other` to the redirect URI with the parameters in the
//!   query; `form_post` → a `200` HTML page whose form auto-submits the parameters to the
//!   redirect URI (self-hosted script, `<noscript>` button, per-response CSP whose `form-action`
//!   allows only the redirect URI's origin);
//! - `Login` → `303` to `{issuer}/ui/login?request={id}`;
//! - `Consent` → `303` to `{issuer}/ui/consent?request={id}` (the consent screen, which continues
//!   the request through [`AppState::authorize_response`]);
//! - `SelectAccount` → `303` to `{issuer}/ui/select-account?request={id}` (the account chooser);
//! - `SelectOrganization` → `303` to `{issuer}/ui/select-organization?request={id}` (the
//!   organization switcher, when the client requires an org and the user belongs to several);
//! - `Register` → `303` to `{issuer}/ui/registration?request={id}` (`prompt=create`; the
//!   registration resumes the request through `/authorize/continue`);
//! - `ErrorPage` → the themed `400` error page, never a redirect (unknown client, unregistered
//!   redirect URI, malformed request before the redirect URI is trusted, expired request).
//!
//! A pushed request (`client_id` + `request_uri=urn:ietf:params:oauth:request_uri:…`, RFC 9126)
//! goes through the same handlers: the service consumes it and every other query parameter is
//! ignored. An unknown, expired, used or mismatched `request_uri` is an `ErrorPage` (no trusted
//! redirect URI yet), rendered like any other.
//!
//! No CORS here, and no browser CSRF layer either: an authorization request is a cross-site
//! front-channel request by design.

use anvil_core::error::CoreError;
use anvil_core::model::{AuthRequestId, BrowserSession};
use anvil_core::oauth::authorize_request::{RawParams, parse_raw};
use anvil_core::oauth::response_mode::{AuthorizationResponse, ResponseMode};
use anvil_core::service::authorize::{AuthorizeOutcome, AuthorizeService};
use anvil_core::service::session::SessionService;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use crate::errors::{ErrorPage, core_error_page_in, error_page_in, error_page_nav};
use crate::i18n::{Locale, LocaleInputs, default_locale, locale_of, negotiate};
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;
use crate::ui::nav::NavContext;

impl AppState {
    /// The authorization endpoint service over this state's storage and clock.
    pub(crate) fn authorize_service(&self) -> AuthorizeService {
        AuthorizeService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            metadata_fetcher: self.cimd_fetcher(),
        }
    }

    /// The HTTP response for an authorization outcome (shared with the consent screen, so the
    /// response modes have one implementation). An `ErrorPage` outcome renders in the tenant's
    /// default language here; the authorization endpoint itself renders its error pages in the
    /// request's language with the client's way forward ([`authorize_error_page`]).
    pub(crate) fn authorize_response(
        &self,
        tenant: &ResolvedTenant,
        outcome: AuthorizeOutcome,
    ) -> Response {
        respond(self, tenant, outcome)
    }

    /// Session lookup for the authorization endpoint.
    pub(crate) fn authorize_session_service(&self) -> SessionService {
        SessionService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
        }
    }
}

/// The active browser session of this tenant, from its session cookie.
async fn current_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
) -> Result<Option<BrowserSession>, CoreError> {
    let name = state.cookies().session_name(&tenant.tenant);
    let token = jar.get(&name).map(|c| c.value());
    state
        .authorize_session_service()
        .current(tenant.tenant.id, token)
        .await
}

fn see_other(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(v) => (StatusCode::SEE_OTHER, [(header::LOCATION, v)]).into_response(),
        Err(_) => {
            // Redirect URIs are validated at registration and built with percent-encoding, so a
            // header-invalid location is a server bug, not client input.
            tracing::error!("authorization redirect is not a valid header value");
            server_error()
        }
    }
}

/// The CSP `form-action` source for a redirect URI: its origin (`scheme://host[:port]`) for
/// http(s), `scheme:` for the custom schemes of native apps. `None` when the URI does not parse.
fn form_action_source(redirect_uri: &str) -> Option<String> {
    let url = url::Url::parse(redirect_uri).ok()?;
    match url.scheme() {
        "http" | "https" => {
            let origin = url.origin();
            origin.is_tuple().then(|| origin.ascii_serialization())
        }
        scheme => Some(format!("{scheme}:")),
    }
}

/// The CSP of a form_post page: only the self-hosted script and stylesheet, and the form may
/// only be submitted to the redirect URI's origin.
fn form_post_csp(form_action: &str) -> String {
    format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; \
         form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
    )
}

fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
}

/// Renders the auto-submitting form of a `form_post` response.
fn form_post(state: &AppState, tenant: &ResolvedTenant, r: &AuthorizationResponse) -> Response {
    // Registered redirect URIs are absolute URLs (validated at registration), so a failure here
    // is a server bug, not client input.
    let Some(csp) = form_action_source(&r.redirect_uri)
        .map(|source| form_post_csp(&source))
        .and_then(|csp| HeaderValue::from_str(&csp).ok())
    else {
        tracing::error!("form_post redirect URI has no usable origin");
        return server_error();
    };
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(
            state,
            tenant,
            &default_locale(state.renderer().catalogs(), Some(tenant)),
            "title.form_post",
        )
        .into_value(),
        action => &r.redirect_uri,
        fields => &r.params,
    };
    match state.renderer().page("form_post.html", ctx) {
        Ok(html) => {
            let mut resp = (StatusCode::OK, html).into_response();
            let headers = resp.headers_mut();
            headers.insert(header::CONTENT_SECURITY_POLICY, csp);
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            headers.insert(
                header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer"),
            );
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "rendering the form_post page failed");
            server_error()
        }
    }
}

fn respond(state: &AppState, tenant: &ResolvedTenant, outcome: AuthorizeOutcome) -> Response {
    match outcome {
        AuthorizeOutcome::Respond(r) => match r.mode {
            ResponseMode::Query => see_other(&r.to_redirect_url()),
            ResponseMode::FormPost => form_post(state, tenant, &r),
        },
        AuthorizeOutcome::Login { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/login?request={request_id}")))
        }
        AuthorizeOutcome::Consent { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/consent?request={request_id}")))
        }
        AuthorizeOutcome::SelectAccount { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/select-account?request={request_id}")))
        }
        AuthorizeOutcome::SelectOrganization { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/select-organization?request={request_id}")))
        }
        AuthorizeOutcome::Register { request_id } => {
            see_other(&tenant.ui_url(&format!("/ui/registration?request={request_id}")))
        }
        AuthorizeOutcome::ErrorPage { error_key, detail } => error_page_in(
            state,
            Some(tenant),
            &default_locale(state.renderer().catalogs(), Some(tenant)),
            StatusCode::BAD_REQUEST,
            error_key,
            &detail,
        ),
    }
}

/// The language of an authorization error page: the request's raw `ui_locales` (OIDC Core
/// §3.1.2.1), then `Accept-Language`, then the tenant default.
fn request_locale(
    state: &AppState,
    tenant: &ResolvedTenant,
    headers: &HeaderMap,
    raw: &RawParams,
) -> Locale {
    negotiate(
        state.renderer().catalogs(),
        &LocaleInputs {
            ui_locales: raw.single("ui_locales").filter(|u| !u.is_empty()),
            user_locale: None,
            accept_language: headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok()),
            tenant_default: &tenant.tenant.settings.default_locale,
        },
    )
}

/// The `400` error page of a refused authorization request, with a way forward: when the
/// request names a registered client, that client's own stored home ("Back to &lt;app&gt;",
/// static clients only, [`NavContext::for_client`]), then sign-in or the account.
async fn authorize_error_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: &Locale,
    client_id: Option<&str>,
    signed_in: bool,
    error_key: &str,
    detail: &str,
) -> Response {
    let nav = match client_id.filter(|c| !c.is_empty()) {
        Some(c) => NavContext::for_client(state, tenant, c).await,
        None => NavContext::none(),
    };
    error_page_nav(
        state,
        Some(tenant),
        locale,
        ErrorPage {
            status: StatusCode::BAD_REQUEST,
            error_key,
            detail,
        },
        &nav,
        signed_in,
    )
}

async fn authorize(
    state: &AppState,
    tenant: &ResolvedTenant,
    jar: &CookieJar,
    headers: &HeaderMap,
    raw: RawParams,
) -> Response {
    let locale = request_locale(state, tenant, headers, &raw);
    let client_id = raw.single("client_id").map(str::to_owned);
    let session = match current_session(state, tenant, jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(state, Some(tenant), &locale, &e),
    };
    let signed_in = session.is_some();
    let result = state
        .authorize_service()
        .authorize(&tenant.tenant, &tenant.issuer, raw, session)
        .await;
    match result {
        Ok(AuthorizeOutcome::ErrorPage { error_key, detail }) => {
            authorize_error_page(
                state,
                tenant,
                &locale,
                client_id.as_deref(),
                signed_in,
                error_key,
                &detail,
            )
            .await
        }
        Ok(outcome) => respond(state, tenant, outcome),
        Err(e) => core_error_page_in(state, Some(tenant), &locale, &e),
    }
}

async fn authorize_get(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let raw = parse_raw(query.unwrap_or_default().as_bytes());
    authorize(&state, &tenant, &jar, &headers, raw).await
}

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

async fn authorize_post(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_form(&headers) {
        let locale = locale_of(&state, Some(&tenant), &headers, None);
        return error_page_in(
            &state,
            Some(&tenant),
            &locale,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the authorization request must be sent as application/x-www-form-urlencoded",
        );
    }
    authorize(&state, &tenant, &jar, &headers, parse_raw(&body)).await
}

async fn authorize_continue(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    jar: CookieJar,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let locale = locale_of(&state, Some(&tenant), &headers, query.as_deref());
    let params = parse_raw(query.unwrap_or_default().as_bytes());
    let session = match current_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &locale, &e),
    };
    let signed_in = session.is_some();
    let Some(request_id) = params
        .single("request")
        .and_then(|r| uuid::Uuid::parse_str(r).ok())
        .map(AuthRequestId)
    else {
        return authorize_error_page(
            &state,
            &tenant,
            &locale,
            None,
            signed_in,
            "flow_expired",
            "",
        )
        .await;
    };
    // The request's client, looked up before resuming (a refused request may be deleted): an
    // error page sends the user back to that app, never into the same continuation again.
    let client_id = NavContext::from_request(&state, &tenant, Some(request_id))
        .await
        .request()
        .map(|r| r.client_id.clone());
    let result = state
        .authorize_service()
        .resume(&tenant.tenant, &tenant.issuer, request_id, session)
        .await;
    match result {
        Ok(AuthorizeOutcome::ErrorPage { error_key, detail }) => {
            authorize_error_page(
                &state,
                &tenant,
                &locale,
                client_id.as_deref(),
                signed_in,
                error_key,
                &detail,
            )
            .await
        }
        Ok(outcome) => respond(&state, &tenant, outcome),
        Err(e) => core_error_page_in(&state, Some(&tenant), &locale, &e),
    }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize_get).post(authorize_post))
        .route("/authorize/continue", get(authorize_continue))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_content_type_detection() {
        let mut h = HeaderMap::new();
        assert!(!is_form(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        assert!(is_form(&h));
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_form(&h));
    }

    #[test]
    fn form_action_is_the_redirect_origin() {
        assert_eq!(
            form_action_source("https://rp.test/cb?x=1").as_deref(),
            Some("https://rp.test")
        );
        assert_eq!(
            form_action_source("https://rp.test:8443/a/b").as_deref(),
            Some("https://rp.test:8443")
        );
        assert_eq!(
            form_action_source("http://127.0.0.1:1234/cb").as_deref(),
            Some("http://127.0.0.1:1234")
        );
        assert_eq!(
            form_action_source("com.example.app:/oauth").as_deref(),
            Some("com.example.app:")
        );
        assert_eq!(form_action_source("not a url"), None);
        let csp = form_post_csp("https://rp.test");
        assert!(csp.contains("form-action https://rp.test;"), "{csp}");
        assert!(csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(HeaderValue::from_str(&csp).is_ok());
    }
}
