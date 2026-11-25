//! Conversions between Postgres column values and the domain model.
//!
//! uuid and timestamptz map natively through sqlx; only bytea hashes and errors need code.

use anvil_core::model::CodeHash;
use anvil_core::ports::StorageError;

/// bytea → code hash. Anything other than 32 bytes is corrupt data.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "transitional: used again by plan 02-06")
)]
pub(crate) fn bytea_to_code_hash(bytes: &[u8]) -> Result<CodeHash, StorageError> {
    CodeHash::from_slice(bytes).map_err(|e| StorageError::Corrupt(format!("code_hash: {e}")))
}

/// Maps a driver error: unique/primary-key violations (SQLSTATE 23505) become `Conflict`,
/// everything else `Backend`.
pub(crate) fn map_err(err: sqlx::Error) -> StorageError {
    if let sqlx::Error::Database(db) = &err
        && db.is_unique_violation()
    {
        return StorageError::Conflict(db.message().to_owned());
    }
    StorageError::Backend(Box::new(err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_length_code_hash_is_corrupt() {
        for len in [0usize, 31, 33] {
            assert!(matches!(
                bytea_to_code_hash(&vec![0u8; len]),
                Err(StorageError::Corrupt(_))
            ));
        }
        assert!(bytea_to_code_hash(&[0u8; 32]).is_ok());
    }

    #[test]
    fn non_database_errors_are_backend() {
        assert!(matches!(
            map_err(sqlx::Error::PoolTimedOut),
            StorageError::Backend(_)
        ));
    }
}
