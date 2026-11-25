//! Email verification pages (`GET/POST /ui/verification[?token=]`).
//!
//! Opening the emailed link (GET) only shows a confirmation button; the token travels in a hidden
//! field and is consumed by the POST, so mail scanners that fetch the link never use it up.

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::FlowKind;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{UiForm, UiQuery, bad_form, start_page, submit_page};
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
    start_page(
        &state,
        &tenant,
        &loc,
        FlowKind::Verification,
        None,
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
    let Ok(Form(form)) = form else {
        return bad_form(&state, &tenant, &loc);
    };
    let input = FlowInput::ConfirmVerification {
        token: form.token.clone().unwrap_or_default(),
    };
    submit_page(&state, &tenant, &loc, &ctx, &jar, &q, &form, input).await
}
