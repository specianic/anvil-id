//! Self-registration pages (`GET/POST /ui/registration[?request=]`).
//!
//! When the tenant's registration mode is not `open`, the page shows the `registration.disabled`
//! message and no flow is started (a POST to an existing flow is refused by the engine).
//!
//! A `request=` that is not a live request of this tenant answers the `flow_expired` page
//! ([`super::login::stale_request_page`]) before any form. A registration that must confirm its
//! address answers `registration.check_email` naming the address, and the emailed link carries
//! the request so the verification page can continue to the app.

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{FlowKind, RegistrationMode};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{
    UiForm, UiQuery, message_page, page_locale, rejected_form, stale_request_page, start_page,
    submit_page,
};
use super::nav::{NavContext, StaleRequest};
use crate::i18n::RequestLocale;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/ui/registration", get(show).post(submit))
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    headers: HeaderMap,
    Query(q): Query<UiQuery>,
) -> Response {
    let nav = match NavContext::from_query(&state, &tenant, q.request.as_deref()).await {
        Ok(nav) => nav,
        Err(StaleRequest::Unknown) => return stale_request_page(&state, &tenant, &locale.0),
    };
    let request = nav.request().map(|r| r.id);
    let loc = page_locale(&state, &tenant, locale, &headers, request).await;
    if tenant.tenant.settings.registration != RegistrationMode::Open {
        return message_page(
            &state,
            &tenant,
            &loc,
            "registration.disabled",
            &nav,
            CookieJar::new(),
        );
    }
    start_page(&state, &tenant, &loc, FlowKind::Registration, &nav, None).await
}

async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    AuditContext(ctx): AuditContext,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
    form: Result<Form<UiForm>, FormRejection>,
) -> Response {
    let form = match form {
        Ok(Form(form)) => form,
        Err(e) => return rejected_form(&state, Some(&tenant), &loc, &e),
    };
    let input = FlowInput::Register {
        email: form.email.clone().unwrap_or_default(),
        password: form.password.clone().unwrap_or_default(),
        name: form.name.clone().filter(|n| !n.trim().is_empty()),
    };
    submit_page(&state, &tenant, &loc, &ctx, &jar, &q, &form, input).await
}
