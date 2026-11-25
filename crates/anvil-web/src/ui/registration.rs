//! Self-registration pages (`GET/POST /ui/registration[?request=]`).
//!
//! When the tenant's registration mode is not `open`, the page shows the `registration.disabled`
//! message and no flow is started (a POST to an existing flow is refused by the engine).

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{FlowKind, RegistrationMode};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{UiForm, UiQuery, bad_form, message_page, page_locale, start_page, submit_page};
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
    let request = match q.auth_request() {
        Ok(r) => r,
        Err(bad) => return bad.into_response(&state, Some(&tenant), &locale.0),
    };
    let loc = page_locale(&state, &tenant, locale, &headers, request).await;
    if tenant.tenant.settings.registration != RegistrationMode::Open {
        return message_page(
            &state,
            &tenant,
            &loc,
            "registration.disabled",
            CookieJar::new(),
        );
    }
    start_page(&state, &tenant, &loc, FlowKind::Registration, request, None).await
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
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &loc);
    };
    let input = FlowInput::Register {
        email: form.email.clone().unwrap_or_default(),
        password: form.password.clone().unwrap_or_default(),
        name: form.name.clone().filter(|n| !n.trim().is_empty()),
    };
    submit_page(&state, &tenant, &loc, &ctx, &jar, &q, &form, input).await
}
