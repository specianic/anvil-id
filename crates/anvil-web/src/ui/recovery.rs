//! Password recovery pages (`GET/POST /ui/recovery[?token=]`).
//!
//! Without a token the page asks for an email address and always answers `recovery.sent`, whether
//! or not an account exists. With a token (the emailed link) it shows the reset form; the token is
//! consumed only by the POST that sets the new password.
//!
//! The page keeps the authorization request it was opened for (`request=`, also on the emailed
//! link of a recovery started from an app's sign-in): after the reset, `recovery.done` offers
//! "Continue to &lt;app&gt;" while the request is live. Without a token, a `request=` that is not a live
//! request of this tenant answers the `flow_expired` page; with a token the reset still works
//! (the token is valid on its own) and the stale request is simply dropped.
//!
//! A reset link that was used, expired or never existed answers on `GET`, before any input:
//! the request form with "This link has expired or was already used" above it (400), so a new
//! link is one click away. Invitation links use this page too (the invited user sets the first
//! password), so a usable `Recovery` or `Invitation` token passes. The check only reads
//! (`FlowService::reset_link_usable`); a
//! `GET` never consumes a token. A failed POST answers 303 to `GET /ui/recovery?flow=`
//! (Post/Redirect/Get); a failed reset keeps the token in the sealed flash, never in the flow
//! state or in plaintext.

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::FlowKind;
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{
    UiForm, UiQuery, expired_reset_link_page, rejected_form, show_step, stale_request_page,
    start_page, submit_page,
};
use super::nav::NavContext;
use crate::errors::core_error_page_in;
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
    locale: RequestLocale,
    headers: HeaderMap,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    // Post/Redirect/Get: the form a failed POST redirected to.
    if let Some(flow) = q.flow_id()
        && let Some(resp) = show_step(
            &state,
            &tenant,
            locale.clone(),
            &headers,
            &jar,
            flow,
            "recovery",
        )
        .await
    {
        return resp;
    }
    let loc = locale.0;
    let token = q.token();
    let nav = match NavContext::from_query(&state, &tenant, q.request.as_deref()).await {
        Ok(nav) => nav,
        Err(_) if token.is_some() => NavContext::none(),
        Err(_) => return stale_request_page(&state, &tenant, &loc),
    };
    // A used, expired or unknown reset link fails here, before the user types a new password,
    // without consuming anything.
    if let Some(t) = token.as_deref() {
        match state
            .ui_flow_service()
            .reset_link_usable(tenant.tenant.id, t)
            .await
        {
            Ok(true) => {}
            Ok(false) => return expired_reset_link_page(&state, &tenant, &loc, &nav).await,
            Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
        }
    }
    start_page(&state, &tenant, &loc, FlowKind::Recovery, &nav, token).await
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
