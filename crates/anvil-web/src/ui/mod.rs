//! Browser-facing self-service pages. Every route here is behind the Fetch-Metadata CSRF layer.

mod login;
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
        .layer(fetch_metadata_layer())
}
