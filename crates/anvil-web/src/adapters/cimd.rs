//! Client ID Metadata Document fetcher on the SSRF-guarded outbound client
//! (`ports::ClientMetadataFetcher`).
//!
//! Pre-declared by plan 05-02; owner: plan 05-15 (adds the adapter and replaces the body of
//! [`AppState::cimd_fetcher`] in this file).

use std::sync::Arc;

use anvil_core::ports::ClientMetadataFetcher;

use crate::state::AppState;

impl AppState {
    /// The metadata document fetcher handed to the authorize, token and client-authentication
    /// services. `None` until plan 05-15 provides the adapter: URL client ids are then not
    /// resolved at all (no fetch).
    pub(crate) fn cimd_fetcher(&self) -> Option<Arc<dyn ClientMetadataFetcher>> {
        None // TRANSITIONAL(05-15)
    }
}
