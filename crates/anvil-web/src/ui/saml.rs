//! SAML 2.0 SP sign-in pages (ORG-03, experimental behind `saml_experimental`). The flow is run
//! by `anvil_core::service::saml::SamlService`.
//!
//! | Route | |
//! |---|---|
//! | `POST /ui/login/saml/{slug}/start?flow=` | start (`csrf_token` + flow cookie): 303 to the IdP with `SAMLRequest` and `RelayState`, sets the binding cookie |
//! | `POST /ui/login/saml/{slug}/acs` | the IdP's HTTP-POST binding (`SAMLResponse`, `RelayState`): 303 to the continue step, or the generic error (400) |
//! | `GET  /ui/login/saml/{slug}/continue?state=` | binding cookie required: the shared upstream completion (session, second factor, link confirmation) |
//! | `GET  /saml/{slug}/metadata` | unsigned SP metadata (`application/samlmetadata+xml`) |
//!
//! With the operator flag off, every route answers 404.
//!
//! Two routers, like [`super::upstream`]:
//!
//! - [`routes`] (start, continue, metadata) sits behind the Fetch-Metadata CSRF layer;
//! - [`callback_routes`] (the ACS) is merged **after** that layer: the IdP's HTTP-POST binding is
//!   a cross-site form post that the layer would refuse, and it carries no cookies. The ACS never
//!   reads a cookie; it is protected by RelayState, `InResponseTo`, the verified signature and the
//!   assertion id replay cache, and the browser continues on a same-site GET bound to the
//!   binding cookie. Its body limit is 256 KiB (`admin::branding::SAML_ACS_BODY_LIMIT`, applied
//!   by the application's one body-limit layer), 413 above.
//!
//! | Cookie | Set | Cleared |
//! |---|---|---|
//! | upstream binding (shared with the upstream sign-in) | start | by the continue step only when its RelayState and the binding cookie matched the flow (`ContinueResult::binding_proved`) |
//!
//! Every refusal renders one generic error page (status 400, error key `saml_login_failed`) and
//! never shows the NameID, attributes or XML.

use anvil_core::error::CoreError;
use anvil_core::service::account::SettingsBinding;
use anvil_core::service::flow::FlowContext;
use anvil_core::service::saml::{AcsOutcome, ContinueOutcome, ContinueResult, SamlService};
use anvil_core::service::upstream::StartResult;
use axum::Router;
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use super::login::{
    UiQuery, csrf_page, current_browser_session, rejected_form, restart_login,
    tenant_relying_party, ui_base,
};
use super::upstream::outcome_page;
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Error key (`data-error-key`) of every refused SAML sign-in.
pub(crate) const FAILED_ERROR_KEY: &str = "saml_login_failed";
/// Message key of the refusal's explanation.
const FAILED_MESSAGE_KEY: &str = "saml.login_failed";

/// SAML start, continue and metadata routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/ui/login/saml/{slug}/start", post(start))
        .route("/ui/login/saml/{slug}/continue", get(continue_get))
        .route("/saml/{slug}/metadata", get(metadata))
}

/// SAML ACS route, outside the Fetch-Metadata layer (module docs).
pub(super) fn callback_routes() -> Router<AppState> {
    Router::new().route("/ui/login/saml/{slug}/acs", post(acs))
}

/// Runs `f` with a [`SamlService`] built for this request.
macro_rules! with_service {
    ($state:expr, |$svc:ident| $body:expr) => {{
        let flows = $state.ui_flow_service();
        let accounts = $state.ui_account_service();
        let xml = $state.saml_xml();
        let $svc = SamlService {
            flows: &flows,
            accounts: &accounts,
            client: $state.upstream(),
            saml_xml: xml.as_ref(),
            enabled: $state.config().saml_experimental,
        };
        $body
    }};
}

fn not_found(state: &AppState, tenant: &ResolvedTenant, loc: &Locale) -> Response {
    error_page_in(
        state,
        Some(tenant),
        loc,
        StatusCode::NOT_FOUND,
        "not_found",
        "",
    )
}

/// The one generic refusal page (400).
fn failed_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    jar: CookieJar,
) -> Response {
    let detail = state.renderer().text(loc, FAILED_MESSAGE_KEY);
    let mut resp = (
        jar,
        error_page_in(
            state,
            Some(tenant),
            loc,
            StatusCode::BAD_REQUEST,
            FAILED_ERROR_KEY,
            &detail,
        ),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn see_other(location: &str, jar: CookieJar) -> Option<Response> {
    let location = HeaderValue::from_str(location).ok()?;
    Some(
        (
            StatusCode::SEE_OTHER,
            jar,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
    )
}

#[derive(Default, Deserialize)]
struct StartForm {
    csrf_token: Option<String>,
}

/// `POST /ui/login/saml/{slug}/start?flow=`: 303 to the IdP with the binding cookie.
#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn start(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Path(slug): Path<String>,
    Query(q): Query<UiQuery>,
    form: Result<Form<StartForm>, FormRejection>,
) -> Response {
    if !state.config().saml_experimental {
        return not_found(&state, &tenant, &loc);
    }
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let binding = SettingsBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: csrf,
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let result = with_service!(state, |svc| svc.start(&cx, &binding, &slug).await);
    match result {
        Ok(StartResult::Redirect(r)) => {
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .upstream_binding_cookie(&tenant.tenant, r.binding_cookie.expose_secret()),
            );
            see_other(&r.url, jar).unwrap_or_else(|| {
                core_error_page_in(
                    &state,
                    Some(&tenant),
                    &loc,
                    &CoreError::Internal("unusable SAML SSO URL".into()),
                )
            })
        }
        Ok(StartResult::Done(outcome)) => {
            outcome_page(&state, &tenant, &loc, *outcome, false).await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &loc),
        Err(CoreError::NotFound | CoreError::FeatureDisabled(_)) => {
            not_found(&state, &tenant, &loc)
        }
        Err(CoreError::InvalidRequest(_)) => restart_login(&state, &tenant, &loc).await,
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// Fields of the IdP's HTTP-POST binding. Unknown fields are ignored.
#[derive(Default, Deserialize)]
struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// `POST /ui/login/saml/{slug}/acs`: validates and seals the identity into the flow, then 303 to
/// the continue step. Reads no cookie and sets none.
async fn acs(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    Path(slug): Path<String>,
    form: Result<Form<AcsForm>, FormRejection>,
) -> Response {
    if !state.config().saml_experimental {
        return not_found(&state, &tenant, &loc);
    }
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let result = with_service!(state, |svc| svc
        .acs(
            &cx,
            &slug,
            form.saml_response.as_deref(),
            form.relay_state.as_deref()
        )
        .await);
    match result {
        Ok(AcsOutcome::Continue { location }) => see_other(&location, CookieJar::new())
            .unwrap_or_else(|| failed_page(&state, &tenant, &loc, CookieJar::new())),
        Ok(AcsOutcome::Refused) => failed_page(&state, &tenant, &loc, CookieJar::new()),
        Err(CoreError::FeatureDisabled(_)) => not_found(&state, &tenant, &loc),
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

#[derive(Default, Deserialize)]
struct ContinueQuery {
    state: Option<String>,
}

/// `GET /ui/login/saml/{slug}/continue?state=`: the binding cookie proves the browser, then the
/// shared completion.
async fn continue_get(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Path(slug): Path<String>,
    query: Result<Query<ContinueQuery>, QueryRejection>,
) -> Response {
    if !state.config().saml_experimental {
        return not_found(&state, &tenant, &loc);
    }
    let q = query.map(|Query(q)| q).unwrap_or_default();
    let binding = jar
        .get(&state.cookies().upstream_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let current = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let result = with_service!(state, |svc| svc
        .continue_login(
            &cx,
            &slug,
            q.state.as_deref(),
            binding.as_deref(),
            current.as_ref()
        )
        .await);
    match result {
        Ok(ContinueResult {
            outcome: ContinueOutcome::Completed(outcome),
            binding_proved,
        }) => outcome_page(&state, &tenant, &loc, *outcome, binding_proved).await,
        Ok(ContinueResult {
            outcome: ContinueOutcome::Refused,
            binding_proved,
        }) => {
            let jar = if binding_proved {
                CookieJar::new().add(state.cookies().clear_upstream_binding(&tenant.tenant))
            } else {
                CookieJar::new()
            };
            failed_page(&state, &tenant, &loc, jar)
        }
        Err(CoreError::FeatureDisabled(_)) => not_found(&state, &tenant, &loc),
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// `GET /saml/{slug}/metadata`: unsigned SP metadata of an enabled SAML connection.
async fn metadata(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Path(slug): Path<String>,
) -> Response {
    if !state.config().saml_experimental {
        return not_found(&state, &tenant, &loc);
    }
    let result = with_service!(state, |svc| svc
        .sp_metadata(tenant.tenant.id, &tenant.issuer, &slug)
        .await);
    match result {
        Ok(xml) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/samlmetadata+xml"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                ),
            ],
            xml,
        )
            .into_response(),
        Err(CoreError::NotFound | CoreError::FeatureDisabled(_)) => {
            not_found(&state, &tenant, &loc)
        }
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}
