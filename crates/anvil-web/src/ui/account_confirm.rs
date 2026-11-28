//! The confirmation step of destructive account actions (07.1-21, U-M12): removing a passkey or
//! the authenticator app, new recovery codes, removing an app's access, disconnecting a linked
//! account and signing out the other devices.
//!
//! It needs no JavaScript. The page's form posts to the action as before; a POST without
//! `confirm=yes` changes nothing and answers `200` with `account_confirm.html`: a second form
//! (`#form-confirm`) posting to the same action URL (same flow binding) with the same CSRF token
//! and `confirm=yes`, and a link back to the page. Only that second POST, with a valid binding,
//! performs the action. The handlers check the binding (and, where the action needs it, the recent
//! sign-in and its target: the credential, the link, the app's grant) before showing this step,
//! so a forged, stale or pointless first POST is refused like the action itself (403 / the page's
//! refusal).

use anvil_core::error::CoreError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::account_attributes::attributes_nav_or_page;
use super::account_security::AccountHeader;
use super::consent::no_store;
use crate::errors::core_error_page_in;
use crate::i18n::Locale;
use crate::render::PageContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// The value of the `confirm` form field that performs the action.
const CONFIRMED: &str = "yes";

/// Whether a submission carries the confirmation (`confirm=yes`). Anything else, including an
/// empty or repeated-but-different value, asks for it.
pub(crate) fn confirmed(confirm: Option<&str>) -> bool {
    confirm == Some(CONFIRMED)
}

/// A destructive action to confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Destructive {
    RemovePasskey,
    RemoveTotp,
    RegenerateRecoveryCodes,
    RevokeApp,
    Unlink,
    SignOutOthers,
}

impl Destructive {
    /// The catalog key prefix of the action's texts (`{prefix}_question`, `_explain`, `_submit`).
    fn prefix(self) -> &'static str {
        match self {
            Self::RemovePasskey => "account_confirm.remove_passkey",
            Self::RemoveTotp => "account_confirm.remove_totp",
            Self::RegenerateRecoveryCodes => "account_confirm.regenerate_codes",
            Self::RevokeApp => "account_confirm.revoke_app",
            Self::Unlink => "account_confirm.unlink",
            Self::SignOutOthers => "account_confirm.sign_out_others",
        }
    }

    /// The `data-action` value of the confirmation form (stable selector for tests and themes).
    fn id(self) -> &'static str {
        match self {
            Self::RemovePasskey => "remove-passkey",
            Self::RemoveTotp => "remove-totp",
            Self::RegenerateRecoveryCodes => "regenerate-recovery-codes",
            Self::RevokeApp => "revoke-app",
            Self::Unlink => "unlink",
            Self::SignOutOthers => "sign-out-others",
        }
    }
}

/// What the confirmation page shows.
pub(crate) struct Confirmation<'a> {
    pub(crate) action: Destructive,
    /// The thing the action applies to (a passkey label, an app or provider name), shown in the
    /// question; "" when there is none. Escaped by the template engine.
    pub(crate) subject: String,
    /// The account section (`account_nav`) and its page title key.
    pub(crate) section: &'static str,
    pub(crate) title_key: &'static str,
    /// The action URL the confirmed form posts to (the original form's action, with its flow).
    pub(crate) post_url: String,
    /// The page's CSRF token (the same binding as the first POST).
    pub(crate) csrf: &'a str,
    /// The page to go back to without doing anything.
    pub(crate) cancel_url: String,
    pub(crate) header: &'a AccountHeader,
}

/// Renders the confirmation step (`200`, `no-store`).
pub(crate) async fn confirm_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    c: Confirmation<'_>,
) -> Response {
    let attributes_nav = match attributes_nav_or_page(state, tenant, loc).await {
        Ok(f) => f,
        Err(page) => return *page,
    };
    let prefix = c.action.prefix();
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, c.title_key).into_value(),
        account_base => tenant.base_path(),
        account_nav => c.section,
        account_attributes_nav => attributes_nav,
        account_header => c.header.value(),
        csrf_token => c.csrf,
        action_id => c.action.id(),
        question_key => format!("{prefix}_question"),
        explain_key => format!("{prefix}_explain"),
        submit_key => format!("{prefix}_submit"),
        subject => c.subject,
        post_url => c.post_url,
        cancel_url => c.cancel_url,
    };
    match state.renderer().page("account_confirm.html", ctx) {
        Ok(html) => no_store((StatusCode::OK, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the confirmation page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_yes_confirms() {
        assert!(confirmed(Some("yes")));
        for v in [
            None,
            Some(""),
            Some("no"),
            Some("YES"),
            Some("yes "),
            Some("1"),
        ] {
            assert!(!confirmed(v), "{v:?}");
        }
    }

    #[test]
    fn every_action_has_english_and_german_texts() {
        let catalogs = crate::i18n::Catalogs::load(None).expect("catalogs");
        let all = [
            Destructive::RemovePasskey,
            Destructive::RemoveTotp,
            Destructive::RegenerateRecoveryCodes,
            Destructive::RevokeApp,
            Destructive::Unlink,
            Destructive::SignOutOthers,
        ];
        for loc in [Locale::fallback(), Locale::new("de")] {
            for a in all {
                for suffix in ["question", "explain", "submit"] {
                    let key = format!("{}_{suffix}", a.prefix());
                    assert_ne!(
                        catalogs.text(&loc, &key, &[("subject", "x".into())]),
                        key,
                        "{key}"
                    );
                }
            }
            assert_ne!(
                catalogs.text(&loc, "account_confirm.cancel", &[]),
                "account_confirm.cancel"
            );
        }
    }
}
