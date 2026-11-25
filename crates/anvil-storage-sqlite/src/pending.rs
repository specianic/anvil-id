//! TRANSITIONAL(04-04): Phase 4 storage the sqlite backend does not implement yet. Every method
//! here returns `StorageError::Unsupported`, never a success, and the write guards refuse
//! Phase 4 values that have no column yet instead of silently dropping them. Plan 04-04 adds
//! the 0.3 migration and real implementations and deletes this module.

use anvil_core::model::{ClientUpdate, NewClient};
use anvil_core::ports::StorageError;

/// TRANSITIONAL(04-04): refuses Phase 4 client fields that have no column yet.
pub(crate) fn refuse_phase4_client(c: &NewClient) -> Result<(), StorageError> {
    if !c.post_logout_redirect_uris.is_empty()
        || c.backchannel_logout_uri.is_some()
        || c.backchannel_logout_session_required
        || !c.allowed_resources.is_empty()
        || c.mfa_policy.is_some()
    {
        return Err(StorageError::Unsupported(
            "phase 4 client fields are not stored by this backend yet",
        ));
    }
    Ok(())
}

/// TRANSITIONAL(04-04): refuses Phase 4 client updates that have no column yet.
pub(crate) fn refuse_phase4_client_update(u: &ClientUpdate) -> Result<(), StorageError> {
    if u.post_logout_redirect_uris.is_some()
        || u.backchannel_logout_uri.is_some()
        || u.backchannel_logout_session_required.is_some()
        || u.allowed_resources.is_some()
        || u.mfa_policy.is_some()
    {
        return Err(StorageError::Unsupported(
            "phase 4 client fields are not stored by this backend yet",
        ));
    }
    Ok(())
}

/// TRANSITIONAL(04-04): refuses RFC 8707 resources on codes, families and access tokens.
pub(crate) fn refuse_resource(resource: &[String]) -> Result<(), StorageError> {
    if resource.is_empty() {
        Ok(())
    } else {
        Err(StorageError::Unsupported(
            "resource indicators are not stored by this backend yet",
        ))
    }
}
