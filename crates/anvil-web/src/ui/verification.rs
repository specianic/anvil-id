//! Email verification pages (`GET/POST /ui/verification[?token=]`).
//!
//! Opening the emailed link (GET) only shows a confirmation button; the token travels in a hidden
//! field and is consumed by the POST, so mail scanners that fetch the link never use it up.
//!
//! A link sent by a registration that started from an app carries its `request=`: when it is
//! still a live request of this tenant, the flow continues it and `verification.done` offers
//! "Continue to <app>". A stale request is dropped silently (the token is valid on its own).

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::FlowKind;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{UiForm, UiQuery, rejected_form, start_page, submit_page};
use super::nav::NavContext;
use crate::i18n::RequestLocale;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/ui/verification", get(show).post(submit))
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    let nav = NavContext::from_query(&state, &tenant, q.request.as_deref())
        .await
        .unwrap_or_else(|_| NavContext::none());
    start_page(
        &state,
        &tenant,
        &loc,
        FlowKind::Verification,
        &nav,
        q.token(),
    )
    .await
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
    let input = FlowInput::ConfirmVerification {
        token: form.token.clone().unwrap_or_default(),
    };
    submit_page(&state, &tenant, &loc, &ctx, &jar, &q, &form, input).await
}
