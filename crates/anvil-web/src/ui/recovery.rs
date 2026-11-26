//! Password recovery pages (`GET/POST /ui/recovery[?token=]`).
//!
//! Without a token the page asks for an email address and always answers `recovery.sent`, whether
//! or not an account exists. With a token (the emailed link) it shows the reset form; the token is
//! consumed only by the POST that sets the new password.

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
    Router::new().route("/ui/recovery", get(show).post(submit))
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    Query(q): Query<UiQuery>,
) -> Response {
    start_page(&state, &tenant, &loc, FlowKind::Recovery, None, q.token()).await
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
    // The reset form posts the token; the request form does not.
    let input = match form.token.clone() {
        Some(token) => FlowInput::ResetPassword {
            token,
            password: form.password.clone().unwrap_or_default(),
        },
        None => FlowInput::RequestRecovery {
            email: form.email.clone().unwrap_or_default(),
        },
    };
    let resets = matches!(input, FlowInput::ResetPassword { .. });
    let response = submit_page(&state, &tenant, &loc, &ctx, &jar, &q, &form, input).await;
    if resets {
        // A completed recovery revokes all of the user's sessions and enqueues their back-channel
        // logouts. The flow outcome is opaque behind the page response, so every reset POST wakes
        // the worker; a spurious wake costs one claim query.
        state.wake_logout_worker();
    }
    response
}
