//! Tenant root pages: `GET /` and `GET /ui` on every tenant (07.1-08, no dead ends).
//!
//! The issuer root is where people land when they type the address of the sign-in service. It
//! is a small page, never a redirect:
//!
//! - signed out: a sign-in link (`#link-login`);
//! - signed in: the account link (`#link-account`) and the sign-out form (`#form-sign-out`,
//!   the end-session endpoint, which asks for confirmation), plus the admin console in the
//!   system tenant (the shared way forward of [`NavContext::way_forward`]);
//! - the default tenant (the installation root) also shows a discreet "Administration" link to
//!   the console (`#link-administration`); end users keep the root, so it is not redirected
//!   there;
//! - before setup (no administrator yet): "Setup is not complete" naming
//!   `anvilid admin setup-url`, the same page `/console/` shows then
//!   ([`setup_pending_page`]), so nobody has to find the setup line in the server log.
//!
//! Setup state comes from the bootstrap service (`BootstrapService::setup_complete`), the
//! session from the session cookie through the session service; the page is
//! `Cache-Control: no-store` because it depends on both.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use anvil_core::model::DEFAULT_TENANT_SLUG;

use crate::errors::{core_error_page_in, is_signed_in};
use crate::i18n::{Locale, RequestLocale, locale_of};
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;
use crate::ui::nav::NavContext;

/// Title (and heading) of the setup guidance page.
const SETUP_PENDING_TITLE: &str = "errors_friendly.setup_pending_title";
/// Title of the root page.
const ROOT_TITLE: &str = "errors_friendly.root_title";

/// The routes of this module (tenant-relative paths).
pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/", get(show)).route("/ui", get(show))
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `GET /` and `GET /ui`.
async fn show(
    State(state): State<AppState>,
    tenant: Option<ResolvedTenant>,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
) -> Response {
    match state.ui_bootstrap_service().setup_complete().await {
        Ok(true) => {}
        Ok(false) => {
            return no_store(setup_pending_page(&state, tenant.as_ref(), &loc));
        }
        Err(e) => return no_store(core_error_page_in(&state, tenant.as_ref(), &loc, &e)),
    }
    let Some(tenant) = tenant else {
        // Installed with an administrator but without a default tenant cannot happen; answer
        // the guidance page rather than a bare error.
        return no_store(setup_pending_page(&state, None, &loc));
    };
    let signed_in = is_signed_in(&state, &tenant, &jar).await;
    let mut page = PageContext::for_tenant(&state, &tenant, &loc, ROOT_TITLE);
    page.links = NavContext::none()
        .way_forward(&state, &tenant, &loc, signed_in)
        .into_links();
    let administration = (tenant.tenant.slug == DEFAULT_TENANT_SLUG).then(|| console_url(&state));
    let ctx = minijinja::context! {
        page => page.into_value(),
        signed_in => signed_in,
        administration => administration,
    };
    no_store(render(&state, Some(&tenant), &loc, "root.html", ctx))
}

/// `{public_url}/console/`.
pub(crate) fn console_url(state: &AppState) -> String {
    format!(
        "{}/console/",
        state.config().public_url.as_str().trim_end_matches('/')
    )
}

/// "Setup is not complete": names `anvilid admin setup-url`. Shown by the tenant root and by
/// `/console/` before the first administrator exists (200; it is guidance, not an error).
pub(crate) fn setup_pending_page(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
) -> Response {
    let page = match tenant {
        Some(t) => PageContext::for_tenant(state, t, loc, SETUP_PENDING_TITLE),
        None => PageContext::installation(state, loc, SETUP_PENDING_TITLE),
    };
    let ctx = minijinja::context! { page => page.into_value() };
    render(state, tenant, loc, "console_setup_pending.html", ctx)
}

/// The console's guidance page before setup, in the language of the request (the console is
/// installation-wide: no tenant).
pub(crate) fn console_setup_pending(
    state: &AppState,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let loc = locale_of(state, None, headers, query);
    setup_pending_page(state, None, &loc)
}

fn render(
    state: &AppState,
    tenant: Option<&ResolvedTenant>,
    loc: &Locale,
    template: &str,
    ctx: minijinja::Value,
) -> Response {
    match state.renderer().page(template, ctx) {
        Ok(html) => (StatusCode::OK, html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, template, "rendering a root page failed");
            core_error_page_in(
                state,
                tenant,
                loc,
                &anvil_core::error::CoreError::Internal("render".into()),
            )
        }
    }
}
