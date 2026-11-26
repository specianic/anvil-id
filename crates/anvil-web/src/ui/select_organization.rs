//! Organization switcher (ORG-02): the user picks which of their orgs an authorization's tokens
//! represent.
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/select-organization?request=` | lists the signed-in user's own memberships (display name and slug, one radio each); starts a bound flow (flow cookie + CSRF token) |
//! | `POST /ui/select-organization?flow=&request=` | `organization=<org id>` |
//!
//! `/authorize` sends the user here when the client's organization policy is `required`, the
//! request names no `organization` and the user belongs to several orgs
//! (`AuthorizeOutcome::SelectOrganization`). The choice is written into the stored request
//! ([`AuthorizeService::choose_organization`](anvil_core::service::authorize::AuthorizeService::choose_organization))
//! and the request continues: the org's MFA policy may add a step-up, then the response goes
//! out through the request's response mode ([`AppState::authorize_response`]) with a code bound
//! to the org. Switching orgs later is a new authorization request with `organization=<other>`.
//!
//! The page never shows an org the user is not a member of; posting one is refused (403, the
//! switcher again with a message, the request unchanged). Without a session the page sends the
//! user to sign in (`/ui/login?request=`). The POST is behind the Fetch-Metadata layer and must
//! carry the flow cookie and the CSRF token, and the flow must belong to the signed-in user and
//! to this request; otherwise the `csrf` error page (403) and nothing changes. An expired or used
//! switcher flow shows the switcher again with a message; a request that no longer waits for a
//! choice is the `flow_expired` page. The page works without JavaScript and is
//! `Cache-Control: no-store`.

use anvil_core::error::CoreError;
use anvil_core::model::{AuthRequestId, BrowserSession, OrgId};
use anvil_core::service::authorize::{AccountChoiceBinding, OrgChoice, SelectOrganizationStart};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};

use super::consent::{PageMessage, current_session, localized, no_store};
use super::login::{UiQuery, bad_form, csrf_page, page_locale, rejected_form};
use crate::errors::{core_error_page_in, error_page_in};
use crate::i18n::{Locale, RequestLocale, carry_ui_locales};
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/select-organization";

/// Message key shown when the switcher flow expired or was already used.
const EXPIRED: &str = "select_organization.expired";
/// Message key shown when the submitted org is not one of the user's memberships.
const NOT_MEMBER: &str = "select_organization.not_member";

/// Switcher routes, behind the Fetch-Metadata layer.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route(PAGE, get(show).post(submit))
}

/// The form the switcher posts.
#[derive(Default, Deserialize)]
struct ChoiceForm {
    csrf_token: Option<String>,
    organization: Option<String>,
}

/// One radio on the page.
#[derive(Serialize)]
struct OrgEntry<'a> {
    id: String,
    slug: &'a str,
    display_name: &'a str,
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

/// Starts a switcher flow for `request` (sets its cookie) and renders the page.
async fn switcher_page(
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
        .start_select_organization(&tenant.tenant, session, request)
        .await
    {
        Ok(SelectOrganizationStart::Started { flow, page }) => (flow, page),
        Ok(SelectOrganizationStart::RequestExpired) => {
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
    let organizations: Vec<OrgEntry<'_>> = page
        .organizations
        .iter()
        .map(|o| OrgEntry {
            id: o.id.to_string(),
            slug: &o.slug,
            display_name: &o.display_name,
        })
        .collect();
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.select_organization").into_value(),
        client_name => &page.client_name,
        organizations => minijinja::Value::from(minijinja::value::Serde(&organizations)),
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        csrf_token => flow.csrf_token.expose_secret(),
        action => carry_ui_locales(
            &tenant.ui_url(&format!("{PAGE}?flow={}&request={request}", flow.flow_id)),
            loc,
        ),
    };
    match state.renderer().page("select_organization.html", ctx) {
        Ok(html) => no_store((status, jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the organization switcher failed");
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
            switcher_page(
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
    // A missing or malformed org id names no membership: the same refusal as a foreign org
    // (after the binding check, so nothing is answered to a forged submission).
    let org = form
        .organization
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map_or(OrgId(uuid::Uuid::nil()), OrgId);
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
        .choose_organization(
            &tenant.tenant,
            &tenant.issuer,
            request,
            session.clone(),
            &binding,
            org,
        )
        .await
    {
        Ok(OrgChoice::Continue(outcome)) => no_store(state.authorize_response(&tenant, outcome)),
        Ok(OrgChoice::FlowExpired) => {
            switcher_page(
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
        Ok(OrgChoice::NotAMember) => {
            switcher_page(
                &state,
                &tenant,
                &loc,
                &session,
                request,
                vec![PageMessage::error(NOT_MEMBER)],
                StatusCode::FORBIDDEN,
            )
            .await
        }
        Err(CoreError::Forbidden) => csrf_page(&state, Some(&tenant), &loc),
        Err(e) => core_error_page_in(&state, Some(&tenant), &loc, &e),
    }
}

#[cfg(test)]
mod tests {
    use crate::render::Renderer;

    #[test]
    fn switcher_page_renders_without_script() {
        let r = Renderer::new(None).expect("renderer");
        let html = r
            .page(
                "select_organization.html",
                minijinja::context! {
                    page => minijinja::context! { title => "t", asset_base => "/assets" },
                    client_name => "App",
                    organizations => vec![
                        minijinja::context! { id => "1", slug => "acme", display_name => "Acme" },
                    ],
                    messages => Vec::<minijinja::Value>::new(),
                    csrf_token => "c",
                    action => "/ui/select-organization?flow=f&request=r",
                },
            )
            .expect("renders")
            .0;
        assert!(html.contains("id=\"select-organization-form\""), "{html}");
        assert!(html.contains("id=\"organization-acme\""), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }
}
