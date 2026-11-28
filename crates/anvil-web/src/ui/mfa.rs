//! Second-factor sign-in page (AUTH-05): a TOTP code or a recovery code after a correct password,
//! and the in-flow enrolment and step-up of the MFA policy (AUTH-08).
//!
//! | Route | |
//! |---|---|
//! | `POST /ui/login/second-factor?flow=` | `code` (TOTP) or `recovery_code`, plus `factor_token`; in the enrolment step `code` confirms the new authenticator app |
//! | `GET  /ui/login/second-factor[?flow=]` | 303 to the sign-in page (the page only exists as a POST answer), keeping the flow's request when the flow cookie is present |
//!
//! The same route serves the three steps of the login flow that come after the user is known:
//! the second factor (`second_factor.html`), the enrolment required by a `required` policy
//! (`mfa_enroll.html`: QR code, key, confirming code; the recovery codes are shown once after
//! it), and step-up of a signed-in session (the flow upgrades the session instead of creating
//! one). The flow state decides which step a code belongs to; a step-up page is the answer to
//! `GET /ui/login?request=` and carries its `factor_token` like the password answer does.
//!
//! The page is the answer to a password POST whose user has a second factor; no session exists
//! until the second factor succeeds (the flow service creates it). The form is bound to the
//! login flow (flow cookie + CSRF token, checked by the flow service).
//!
//! Attempts are throttled per user through the one limiter, driven by [`super::flow_driver`]
//! (`Throttle::SecondFactor`, limiter key `LimitKey::User`). The flow service only learns the
//! user from the stored flow state, which handlers cannot read, so the password step hands the
//! page a `factor_token`: the user id sealed with the KEK (purpose [`FACTOR_TOKEN_PURPOSE`]) and
//! bound to the tenant and flow as AAD. It names the limiter key before the code is checked; it grants
//! nothing by itself (the flow service still decides from the flow state). A missing or
//! tampered token restarts the sign-in. A lock answers 429 with `Retry-After`.

use anvil_core::flow::engine::FlowInput;
use anvil_core::flow::form::FormDescription;
use anvil_core::model::{FlowId, TenantId, UserId};
use anvil_core::service::flow::AuthAttempt;
use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;

use super::flow_driver::{self, DriveOutcome, FlowBinding, Throttle};
use super::login::{
    Extras, UiForm, UiQuery, csrf_page, drive_response, locked_page, rejected_form,
    restart_login_in,
};
use super::nav::{NavContext, UiPage};
use crate::i18n::{Locale, RequestLocale};
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// KEK purpose of the second-factor binding token.
pub const FACTOR_TOKEN_PURPOSE: &str = "anvilid/second-factor-user/v1";

const PAGE: &str = "/ui/login/second-factor";

/// The routes of this module (tenant-relative paths).
pub fn routes() -> Router<AppState> {
    Router::new().route(PAGE, get(show).post(submit))
}

fn token_aad(tenant: TenantId, flow: FlowId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(flow.0.as_bytes());
    aad
}

/// Seals `user` for the second-factor form of `flow` in `tenant` (base64url).
pub(super) fn seal_factor_token(
    kek: &Kek,
    tenant: TenantId,
    flow: FlowId,
    user: UserId,
) -> Result<String, anvil_jose::JoseError> {
    kek.seal(
        FACTOR_TOKEN_PURPOSE,
        &token_aad(tenant, flow),
        user.0.as_bytes(),
    )
    .map(|sealed| b64url(&sealed))
}

/// The user a second-factor token names, if it opens for this tenant and flow.
pub(super) fn open_factor_token(
    kek: &Kek,
    tenant: TenantId,
    flow: FlowId,
    token: &str,
) -> Option<UserId> {
    let sealed = b64url_decode(token).ok()?;
    let plain = kek
        .open(FACTOR_TOKEN_PURPOSE, &token_aad(tenant, flow), &sealed)
        .ok()?;
    uuid::Uuid::from_slice(&plain).ok().map(UserId)
}

/// `GET`: the page is only ever the answer to a POST (its CSRF token cannot be shown again), so
/// a direct visit goes back to the sign-in page. A reload in the browser holding the flow cookie
/// keeps the flow's authorization request.
async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    RequestLocale(loc, _): RequestLocale,
    jar: CookieJar,
    Query(q): Query<UiQuery>,
) -> Response {
    let has_cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .is_some();
    let nav = match q.flow_id() {
        Some(flow) if has_cookie => NavContext::from_flow(&state, &tenant, flow).await,
        _ => NavContext::none(),
    };
    let location = nav.url(&tenant, &loc, UiPage::Login);
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

/// `POST /ui/login/second-factor?flow=`: a TOTP code or a recovery code.
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
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), form.csrf_token.as_deref()) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let tenant_id = tenant.tenant.id;
    let nav = NavContext::from_flow(&state, &tenant, flow_id).await;
    let Some(user) = form
        .factor_token
        .as_deref()
        .and_then(|t| open_factor_token(state.kek(), tenant_id, flow_id, t))
    else {
        return restart_login_in(&state, &tenant, &loc, &nav).await;
    };
    let present = |v: &Option<String>| v.clone().filter(|s| !s.trim().is_empty());
    let input = match present(&form.recovery_code) {
        Some(code) => FlowInput::RecoveryCode { code },
        None => FlowInput::Totp {
            code: form.code.clone().unwrap_or_default(),
        },
    };
    let binding = FlowBinding::Cookie { jar: &jar, csrf };
    let throttle = Throttle::SecondFactor { user };
    match flow_driver::submit(&state, &tenant, &ctx, flow_id, binding, throttle, input).await {
        // A lock after a failed code keeps the token of the user the flow counted.
        DriveOutcome::Locked {
            form,
            retry_after,
            attempt: Some(AuthAttempt::SecondFactorFailed { user }),
        } => locked_second_factor(
            &state,
            &tenant,
            &loc,
            &nav,
            form,
            flow_id,
            user,
            retry_after,
        ),
        outcome => {
            let token = seal_factor_token(state.kek(), tenant_id, flow_id, user).ok();
            let extras = Extras {
                factor_token: token.clone(),
                ..Extras::default()
            };
            drive_response(&state, &tenant, &loc, &nav, outcome, &extras, token)
        }
    }
}

/// The second-factor form answering a lock (429, `Retry-After`), still carrying its token.
#[expect(
    clippy::too_many_arguments,
    reason = "threads the request's locale, links and binding"
)]
fn locked_second_factor(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    nav: &NavContext,
    form: FormDescription,
    flow: FlowId,
    user: UserId,
    retry_after: std::time::Duration,
) -> Response {
    let token = seal_factor_token(state.kek(), tenant.tenant.id, flow, user).ok();
    locked_page(state, tenant, loc, nav, form, retry_after, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_token_round_trips_only_for_its_tenant_and_flow() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let flow = FlowId::new_v7();
        let user = UserId::new_v7();
        let token = seal_factor_token(&kek, tenant, flow, user).expect("seal");
        assert_eq!(open_factor_token(&kek, tenant, flow, &token), Some(user));
        assert_eq!(
            open_factor_token(&kek, tenant, FlowId::new_v7(), &token),
            None
        );
        assert_eq!(
            open_factor_token(&kek, TenantId::new_v7(), flow, &token),
            None
        );
        assert_eq!(
            open_factor_token(&Kek::generate(), tenant, flow, &token),
            None
        );
        assert_eq!(open_factor_token(&kek, tenant, flow, "garbage"), None);
        let mut tampered = token.clone();
        tampered.replace_range(0..1, if token.starts_with('A') { "B" } else { "A" });
        assert_eq!(open_factor_token(&kek, tenant, flow, &tampered), None);
    }
}
