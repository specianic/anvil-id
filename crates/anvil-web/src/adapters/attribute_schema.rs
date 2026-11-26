//! Offline JSON Schema check for custom user attributes (`ports::AttributeSchemaCheck`).
//!
//! Pre-declared by plan 05-02; owner: plan 05-10 (adds the `jsonschema` adapter and replaces the
//! body of [`AppState::attribute_check`] in this file).

use std::sync::Arc;

use anvil_core::ports::AttributeSchemaCheck;

use crate::state::AppState;

impl AppState {
    /// The attribute schema check handed to the token and UserInfo services. `None` until plan
    /// 05-10 provides the adapter; the services do not read the field before then.
    pub(crate) fn attribute_check(&self) -> Option<Arc<dyn AttributeSchemaCheck>> {
        None // TRANSITIONAL(05-10)
    }
}
