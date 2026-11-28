//! Upstream (social / generic OIDC / OAuth2) sign-in: start and callback (AUTH-07, AUTH-11).
//!
//! | Route | |
//! |---|---|
//! | `POST /ui/login/upstream/{slug}?flow=` | start (`csrf_token` + flow cookie): a login flow signs in, the account page's settings flow links |
//! | `GET  /ui/login/upstream/{slug}/callback` | the provider's return (`state`, `code`, `error`, `iss`) |
//! | `POST /ui/login/upstream/{slug}/callback` | `response_mode=form_post` (Apple): kept sealed in the flow, then 303 to the `GET` with `state` only |
//!
//! The start answers 303 to the provider and sets the SameSite=Lax binding cookie
//! (`cookies::CookiePolicy::upstream_binding_cookie`, 10 minutes). The callback is checked and
//! run by `anvil_core::service::upstream::UpstreamService`.
//!
//! | Cookie | Set | Cleared |
//! |---|---|---|
//! | upstream binding | start (303 to the provider) | by the `GET` callback only when its `state` and the binding cookie matched the pending sign-in (`CallbackResult::binding_proved`), on success and on any later failure. A forged or mismatched callback (missing or foreign `state`, no or another binding cookie, replay before the check) leaves it in place, so the genuine callback that follows still succeeds. The `form_post` hop never touches it. |
//!
//! Linking from the account page ends with 303 to `/ui/account/linked`, where the new identity
//! is listed.
//!
//! Two routers:
//! - [`routes`] (the start POST) is merged inside the Fetch-Metadata CSRF layer like every UI route.
//! - [`callback_routes`] is merged in [`super::routes`] *after* `.layer(fetch_metadata_layer())`:
//!   Apple returns with a cross-site `form_post`, which the Fetch-Metadata check would reject.
//!   The callback's protection is the single-use `state`, the browser-binding cookie and the ID
//!   token `nonce` (tested in `tests/security_linking.rs`). The `form_post` handler changes
//!   nothing but the sealed response kept in a flow whose `state` it presents; the sign-in only
//!   happens on the `GET`, with the binding cookie.

use anvil_core::error::CoreError;
use anvil_core::flow::form::FormDescription;
use anvil_core::flow::login::{IDENTIFY_FORM_ID, UPSTREAM_LINK_FORM_ID};
use anvil_core::flow::upstream::PostedResponse;
use anvil_core::model::Connection;
use anvil_core::model::RequestContext;
use anvil_core::service::account::SettingsBinding;
use anvil_core::service::upstream::{
    CallbackParams, CallbackResult, StartResult, UpstreamOutcome, UpstreamService, link_choices,
    sign_in_connections,
};
use axum::Router;
use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum_extra::extract::cookie::CookieJar;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::login::{
    Extras, UiQuery, bad_form, csrf_page, current_browser_session, factor_token, flow_of,
    form_status, message_page, rejected_form, restart_login_in, signed_in_response,
    started_response_in, tenant_relying_party, ui_base,
};
use super::nav::{AccountSection, NavContext, UiPage};
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Upstream start routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/ui/login/upstream/{slug}", post(start))
}

/// Upstream callback routes, outside the Fetch-Metadata layer (see the module docs).
pub(super) fn callback_routes() -> Router<AppState> {
    Router::new().route(
        "/ui/login/upstream/{slug}/callback",
        get(callback_get).post(callback_post),
    )
}

/// One upstream sign-in button of the sign-in page (a separate form per connection, no script).
#[derive(Debug, Clone, Serialize)]
pub(super) struct UpstreamButton {
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) action: String,
}

/// The upstream choices of a bound sign-in form ([`upstream_buttons`]).
#[derive(Debug, Clone, Default)]
pub(super) struct SignInChoices {
    /// One button per connection the form offers.
    pub(super) buttons: Vec<UpstreamButton>,
    /// The link confirmation page offers an emailed code
    /// (`anvil_core::service::upstream::LinkChoices::email_code`).
    pub(super) link_email_code: bool,
    /// ... without an address field: the matching account may not be revealed
    /// (`anvil_core::service::upstream::LinkChoices::address_hidden`).
    pub(super) link_email_hidden: bool,
}

/// The upstream choices of a bound sign-in form:
///
/// - the combined form and the email-first page (`login-identify`): the tenant's offerable
///   (enabled and complete) connections, not org connections
///   (`anvil_core::service::upstream::sign_in_connections`);
/// - the link confirmation page (`upstream-link`), "Continue with … to confirm"
///   (`anvil_core::service::upstream::link_choices`): the revealed candidate's enabled linked
///   connections, or, when the matching account may not be revealed, the tenant's connections
///   above except the one being linked (the same whatever account matched); and whether an
///   emailed code is offered (without an address field when unrevealed).
///
/// A storage failure shows no buttons (logged): password sign-in keeps working.
pub(super) async fn upstream_buttons(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    form: &FormDescription,
) -> SignInChoices {
    let Some(flow) = flow_of(form) else {
        return SignInChoices::default();
    };
    let base = ui_base(tenant);
    let button = |c: Connection| UpstreamButton {
        action: carry_ui_locales(
            &format!("{base}/login/upstream/{}?flow={flow}", c.slug),
            loc,
        ),
        slug: c.slug,
        name: c.display_name,
    };
    if form.id == UPSTREAM_LINK_FORM_ID {
        let choices =
            link_choices(state.storage(), &tenant.tenant, flow, state.clock().now()).await;
        return match choices {
            Ok(c) => SignInChoices {
                buttons: c.connections.into_iter().map(button).collect(),
                link_email_code: c.email_code,
                link_email_hidden: c.address_hidden,
            },
            Err(e) => {
                tracing::warn!(error = %e, "listing link confirmation choices failed");
                SignInChoices::default()
            }
        };
    }
    // The combined form, or the email-first page of home-realm discovery (06-22).
    if form.id != "login" && form.id != IDENTIFY_FORM_ID {
        return SignInChoices::default();
    }
    // Tenant-level, enabled and complete connections only (`Connection::is_offerable`): org
    // connections (enterprise SSO) are reached through home-realm discovery or the
    // `organization` parameter, and an incomplete row never publishes a broken button.
    match sign_in_connections(state.storage(), tenant.tenant.id).await {
        Ok(list) => SignInChoices {
            buttons: list.into_iter().map(button).collect(),
            link_email_code: false,
            link_email_hidden: false,
        },
        Err(e) => {
            tracing::warn!(error = %e, "listing connections for the sign-in page failed");
            SignInChoices::default()
        }
    }
}

impl AppState {
    fn ui_upstream<'a>(
        &'a self,
        flows: &'a anvil_core::service::flow::FlowService,
        accounts: &'a anvil_core::service::account::AccountService,
    ) -> UpstreamService<'a> {
        UpstreamService {
            flows,
            accounts,
            client: self.upstream(),
        }
    }
}

#[derive(Default, Deserialize)]
struct StartForm {
    csrf_token: Option<String>,
}

/// `POST /ui/login/upstream/{slug}?flow=`: 303 to the provider with the binding cookie.
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
    let current = match current_browser_session(&state, &tenant, &jar).await {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let binding = SettingsBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: csrf,
    };
    let base = ui_base(&tenant);
    let rp = tenant_relying_party(&tenant);
    let cx = anvil_core::service::flow::FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let flows = state.ui_flow_service();
    let accounts = state.ui_account_service();
    let result = state
        .ui_upstream(&flows, &accounts)
        .start(&cx, &binding, &slug, current.as_ref())
        .await;
    match result {
        Ok(StartResult::Redirect(r)) => {
            let Ok(location) = HeaderValue::from_str(&r.url) else {
                return core_error_page_in(
                    &state,
                    Some(&tenant),
                    &loc,
                    &CoreError::Internal("unusable upstream authorization URL".into()),
                );
            };
            let jar = CookieJar::new().add(
                state
                    .cookies()
                    .upstream_binding_cookie(&tenant.tenant, r.binding_cookie.expose_secret()),
            );
            (
                StatusCode::SEE_OTHER,
                jar,
                [
                    (header::LOCATION, location),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
            )
                .into_response()
        }
        // Nothing proved a pending sign-in of this browser: the binding cookie stays.
        Ok(StartResult::Done(outcome)) => {
            outcome_page(&state, &tenant, &loc, *outcome, false).await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &loc),
        Err(CoreError::NotFound) => error_page_in(
            &state,
            Some(&tenant),
            &loc,
            StatusCode::NOT_FOUND,
            "not_found",
            "",
        ),
        Err(CoreError::InvalidRequest(_)) => {
            let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
            restart_login_in(&state, &tenant, &loc, &nav).await
        }
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// Query parameters of the provider's return. Unknown parameters are ignored.
#[derive(Default, Deserialize)]
struct CallbackQuery {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

/// Form fields of a `form_post` return (Apple). `id_token` is ignored: the ID token used is the
/// one from the token endpoint.
#[derive(Default, Deserialize)]
struct CallbackForm {
    state: Option<String>,
    code: Option<String>,
    user: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

/// `GET /ui/login/upstream/{slug}/callback`.
async fn callback_get(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Path(slug): Path<String>,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
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
    let cx = anvil_core::service::flow::FlowContext {
        tenant: &tenant.tenant,
        issuer: &tenant.issuer,
        ui_base: &base,
        rp: &rp,
        ctx: &ctx,
    };
    let params = CallbackParams {
        state: q.state,
        code: q.code.map(SecretString::from),
        error: q.error,
        iss: q.iss,
    };
    let flows = state.ui_flow_service();
    let accounts = state.ui_account_service();
    match state
        .ui_upstream(&flows, &accounts)
        .callback(&cx, &slug, params, binding.as_deref(), current.as_ref())
        .await
    {
        Ok(CallbackResult {
            outcome,
            binding_proved,
        }) => outcome_page(&state, &tenant, &loc, outcome, binding_proved).await,
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

/// `POST /ui/login/upstream/{slug}/callback` (`form_post`): keeps the posted response in the
/// flow its `state` names and answers 303 to the `GET` callback with `state` only. Nothing is
/// signed in here: the browser's cross-site POST carries no SameSite=Lax binding cookie.
async fn callback_post(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Path(slug): Path<String>,
    form: Result<Form<CallbackForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let mut location = format!("{}/ui/login/upstream/{slug}/callback", tenant.issuer);
    if let Some(st) = form.state.as_deref() {
        let base = ui_base(&tenant);
        let rp = tenant_relying_party(&tenant);
        // Keeping the response records nothing, so no request context.
        let ctx = RequestContext::default();
        let cx = anvil_core::service::flow::FlowContext {
            tenant: &tenant.tenant,
            issuer: &tenant.issuer,
            ui_base: &base,
            rp: &rp,
            ctx: &ctx,
        };
        let posted = PostedResponse {
            code: form.code,
            user: form.user,
            error: form.error,
            iss: form.iss,
        };
        let flows = state.ui_flow_service();
        let accounts = state.ui_account_service();
        if let Err(e) = state
            .ui_upstream(&flows, &accounts)
            .form_post(&cx, &slug, st, posted)
            .await
        {
            return core_error_page_in(&state, Some(&tenant), &loc, &e);
        }
        let encoded: String = url::form_urlencoded::byte_serialize(st.as_bytes()).collect();
        location = format!("{location}?state={encoded}");
    }
    match HeaderValue::from_str(&location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
        )
            .into_response(),
        Err(_) => bad_form(&state, &tenant, &loc),
    }
}

/// The response to an upstream outcome. The binding cookie is cleared only when
/// `clear_binding` (the callback proved the binding; module docs).
pub(super) async fn outcome_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    outcome: UpstreamOutcome,
    clear_binding: bool,
) -> Response {
    let cookies = state.cookies();
    let jar = if clear_binding {
        CookieJar::new().add(cookies.clear_upstream_binding(&tenant.tenant))
    } else {
        CookieJar::new()
    };
    let mut resp = match outcome {
        UpstreamOutcome::SignedIn {
            cookie,
            continue_to,
        } => {
            let jar = jar
                .add(cookies.clear_flow(&tenant.tenant))
                .add(cookies.session_cookie(&tenant.tenant, cookie.token.expose_secret()));
            signed_in_response(state, tenant, loc, continue_to, jar)
        }
        UpstreamOutcome::Continue { started, request } => {
            let extras = Extras {
                factor_token: started
                    .factor_user
                    .and_then(|user| factor_token(state, tenant, started.flow_id, user)),
                totp: started.totp.as_ref(),
                upstream: upstream_buttons(state, tenant, loc, &started.form).await,
                ..Extras::default()
            };
            let status = form_status(&started.form);
            // The link confirmation's "Cancel" and sign-in links keep the app's request.
            let nav = NavContext::from_request(state, tenant, request).await;
            started_response_in(state, tenant, loc, &started, &nav, status, &extras, jar)
        }
        UpstreamOutcome::Linked => {
            let location =
                NavContext::none().url(tenant, loc, UiPage::Account(AccountSection::Linked));
            match HeaderValue::from_str(&location) {
                Ok(location) => {
                    (StatusCode::SEE_OTHER, jar, [(header::LOCATION, location)]).into_response()
                }
                Err(_) => core_error_page_in(
                    state,
                    Some(tenant),
                    loc,
                    &CoreError::Internal("unusable linked accounts URL".into()),
                ),
            }
        }
        UpstreamOutcome::LinkFailed { key } => {
            // Linking from the account page: no authorization request to continue.
            let mut resp = message_page(state, tenant, loc, key, &NavContext::none(), jar);
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            resp
        }
    };
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}
