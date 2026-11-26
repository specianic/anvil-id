//! Browser-facing self-service pages. Every route here is behind the Fetch-Metadata CSRF layer,
//! except the upstream sign-in callback ([`upstream::callback_routes`]): a provider may return with
//! a cross-site `form_post`; that callback is protected by state, binding cookie and nonce. The
//! SAML assertion consumer service ([`saml::callback_routes`]) is exempt for the same reason (the
//! HTTP-POST binding is a cross-site form post).

mod account_apps;
// Phase 5 (pre-declared by plan 05-02; the owning plan adds its routes)
mod account_attributes;
mod account_linked;
mod account_profile;
mod account_security;
mod account_sessions;
mod consent;
mod email_code;
mod format;
mod login;
mod logout;
mod mfa;
mod preview;
mod recovery;
mod registration;
mod select_account;
mod setup;
mod upstream;
mod verification;
// Phase 6 (pre-declared by plan 06-04; the owning plans add their routes)
mod invitation;
mod saml;
mod select_organization;

use axum::Router;

use crate::layers::csrf::fetch_metadata_layer;
use crate::state::AppState;

/// The shared body-limit rejection check, also used by the admin API's JSON extractor.
pub(crate) use login::rejection_is_too_large;

/// All UI routes (tenant-relative paths), behind the Fetch-Metadata CSRF layer; the upstream
/// callback and the SAML ACS are merged after the layer and are not covered by it.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(login::routes())
        .merge(registration::routes())
        .merge(verification::routes())
        .merge(recovery::routes())
        .merge(setup::routes())
        .merge(mfa::routes())
        .merge(consent::routes())
        .merge(account_security::routes())
        .merge(account_sessions::routes())
        .merge(account_apps::routes())
        .merge(account_profile::routes())
        .merge(account_linked::routes())
        .merge(account_attributes::routes())
        .merge(select_account::routes())
        .merge(email_code::routes())
        .merge(logout::routes())
        .merge(preview::routes())
        .merge(upstream::routes())
        .merge(select_organization::routes())
        .merge(invitation::routes())
        .merge(saml::routes())
        .layer(fetch_metadata_layer())
        // After the layer: exempt from the Fetch-Metadata check (cross-site `form_post`).
        .merge(upstream::callback_routes())
        // After the layer: the SAML HTTP-POST binding to the ACS is cross-site.
        .merge(saml::callback_routes())
}

#[cfg(test)]
mod tests {
    use crate::render::Renderer;

    #[test]
    fn account_base_marks_the_current_section() {
        let r = Renderer::new(None).expect("renderer");
        let html = r
            .page(
                "account_base.html",
                minijinja::context! {
                    page => minijinja::context! { title => "Sessions", asset_base => "/assets" },
                    account_base => "/t/acme",
                    account_nav => "sessions",
                },
            )
            .expect("renders")
            .0
            .replace("&#x2f;", "/");
        assert!(html.contains(r#"aria-label="Account""#), "{html}");
        assert!(
            html.contains(r#"href="/t/acme/ui/account/sessions" aria-current="page""#),
            "{html}"
        );
        assert_eq!(html.matches("aria-current").count(), 1, "{html}");
        assert!(html.contains(r#"href="/t/acme/ui/account/security""#));
        assert!(html.contains(r#"href="/t/acme/ui/account/apps""#));
    }
}
