//! Browser-facing self-service pages. Every route here is behind the Fetch-Metadata CSRF layer.

mod account_apps;
mod account_security;
mod account_sessions;
mod consent;
mod format;
mod login;
mod mfa;
mod recovery;
mod registration;
mod setup;
mod verification;

use axum::Router;

use crate::layers::csrf::fetch_metadata_layer;
use crate::state::AppState;

/// All UI routes (tenant-relative paths), behind the Fetch-Metadata CSRF layer.
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
        .layer(fetch_metadata_layer())
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
