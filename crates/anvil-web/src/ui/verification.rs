//! Email verification pages (`GET/POST /ui/verification[?token=]`).
//!
//! Opening the emailed link (GET) only shows a confirmation button; the token travels in a hidden
//! field and is consumed by the POST, so mail scanners that fetch the link never use it up.
//!
//! A link sent by a registration that started from an app carries its `request=`: when it is
//! still a live request of this tenant, the flow continues it and `verification.done` offers
//! "Continue to &lt;app&gt;". A stale request is dropped silently (the token is valid on its own).
//!
//! A link that was used, expired or never existed answers on `GET` with "This link has expired or
//! was already used" (400) and the way to the sign-in page instead of the button; the check only
//! reads (`FlowService::self_service_link_usable`). A failed POST answers 303 to
//! `GET /ui/verification?flow=` (Post/Redirect/Get).

use anvil_core::flow::engine::FlowInput;
use anvil_core::model::{FlowKind, SelfServiceKind};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::login::{
    UiForm, UiQuery, expired_verification_link_page, link_usable, rejected_form, show_step,
    start_page, submit_page,
};
use super::nav::NavContext;
use crate::errors::core_error_page_in;
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
            "verification",
        )
        .await
    {
        return resp;
    }
    let loc = locale.0;
    let nav = NavContext::from_query(&state, &tenant, q.request.as_deref())
        .await
        .unwrap_or_else(|_| NavContext::none());
    // A used, expired or unknown link fails here, before the confirmation button, without
    // consuming anything.
    if let Some(t) = q.token() {
        match link_usable(&state, &tenant, SelfServiceKind::Verification, &t).await {
            Ok(true) => {}
            Ok(false) => return expired_verification_link_page(&state, &tenant, &loc, &nav),
            Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
        }
    }
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
