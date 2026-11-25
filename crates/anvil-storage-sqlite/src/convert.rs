//! Conversions between SQLite column values and the domain model.

use anvil_core::model::CodeHash;
use anvil_core::ports::StorageError;
use time::OffsetDateTime;

/// Timestamp → unix milliseconds (the SQLite storage format).
///
/// Every `OffsetDateTime` (years ±9999) fits in an `i64` of milliseconds, so the cast is lossless
/// apart from the documented sub-millisecond truncation.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "transitional: used again by plan 02-05")
)]
pub(crate) fn odt_to_ms(t: OffsetDateTime) -> i64 {
    (t.unix_timestamp_nanos() / 1_000_000) as i64
}

/// Unix milliseconds → timestamp. Out-of-range values are corrupt data.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "transitional: used again by plan 02-05")
)]
pub(crate) fn ms_to_odt(ms: i64) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|e| StorageError::Corrupt(format!("timestamp {ms} ms out of range: {e}")))
}

/// BLOB → code hash. Anything other than 32 bytes is corrupt data.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "transitional: used again by plan 02-05")
)]
pub(crate) fn blob_to_code_hash(bytes: &[u8]) -> Result<CodeHash, StorageError> {
    CodeHash::from_slice(bytes).map_err(|e| StorageError::Corrupt(format!("code_hash: {e}")))
}

/// Maps a driver error: unique/primary-key violations become `Conflict`, everything else
/// `Backend`.
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
    use time::macros::datetime;

    #[test]
    fn ms_round_trip() {
        let t = datetime!(2026-11-25 12:00:00.123 UTC);
        assert_eq!(odt_to_ms(t), 1_795_608_000_123);
        assert_eq!(ms_to_odt(odt_to_ms(t)).unwrap(), t);
    }

    #[test]
    fn ms_out_of_range_is_corrupt() {
        assert!(matches!(ms_to_odt(i64::MAX), Err(StorageError::Corrupt(_))));
    }

    #[test]
    fn wrong_length_code_hash_is_corrupt() {
        assert!(matches!(
            blob_to_code_hash(&[0u8; 31]),
            Err(StorageError::Corrupt(_))
        ));
        assert!(blob_to_code_hash(&[0u8; 32]).is_ok());
    }
}
