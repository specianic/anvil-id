//! Conversions between SQLite column values and the domain model.
//!
//! Storage formats: timestamps are INTEGER unix milliseconds, ids are 16-byte UUID BLOBs, secret
//! hashes are 32-byte BLOBs, enums are their snake_case `as_str()` names and structured values
//! are JSON TEXT. Anything that does not decode is reported as [`StorageError::Corrupt`].

use anvil_core::model::SecretHash;
use anvil_core::ports::StorageError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use time::OffsetDateTime;

/// Timestamp → unix milliseconds (the SQLite storage format).
///
/// Every `OffsetDateTime` (years ±9999) fits in an `i64` of milliseconds, so the cast is lossless
/// apart from the documented sub-millisecond truncation.
pub(crate) fn odt_to_ms(t: OffsetDateTime) -> i64 {
    (t.unix_timestamp_nanos() / 1_000_000) as i64
}

/// Optional timestamp → optional unix milliseconds.
pub(crate) fn opt_odt_to_ms(t: Option<OffsetDateTime>) -> Option<i64> {
    t.map(odt_to_ms)
}

/// Unix milliseconds → timestamp. Out-of-range values are corrupt data.
pub(crate) fn ms_to_odt(ms: i64) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .map_err(|e| StorageError::Corrupt(format!("timestamp {ms} ms out of range: {e}")))
}

/// Optional unix milliseconds → optional timestamp.
pub(crate) fn opt_ms_to_odt(ms: Option<i64>) -> Result<Option<OffsetDateTime>, StorageError> {
    ms.map(ms_to_odt).transpose()
}

/// The current time at millisecond precision, for the few port methods that take no `now`
/// (`UserRepo::delete`, `ClientRepo::delete` stamp the family revocation with it).
pub(crate) fn now_ms() -> OffsetDateTime {
    anvil_core::model::truncate_to_ms(OffsetDateTime::now_utc())
}

/// BLOB → secret hash. Anything other than 32 bytes is corrupt data.
pub(crate) fn blob_to_hash(bytes: &[u8], what: &str) -> Result<SecretHash, StorageError> {
    SecretHash::from_slice(bytes).map_err(|e| StorageError::Corrupt(format!("{what}: {e}")))
}

/// Optional BLOB → optional secret hash.
pub(crate) fn opt_blob_to_hash(
    bytes: Option<&[u8]>,
    what: &str,
) -> Result<Option<SecretHash>, StorageError> {
    bytes.map(|b| blob_to_hash(b, what)).transpose()
}

/// Value → JSON TEXT.
pub(crate) fn to_json<T: Serialize + ?Sized>(
    value: &T,
    what: &str,
) -> Result<String, StorageError> {
    serde_json::to_string(value)
        .map_err(|e| StorageError::Backend(format!("encoding {what} as JSON: {e}").into()))
}

/// JSON TEXT → value. Undecodable JSON is corrupt data.
pub(crate) fn from_json<T: DeserializeOwned>(text: &str, what: &str) -> Result<T, StorageError> {
    serde_json::from_str(text).map_err(|e| StorageError::Corrupt(format!("{what}: {e}")))
}

/// Optional JSON TEXT → optional value.
pub(crate) fn opt_from_json<T: DeserializeOwned>(
    text: Option<&str>,
    what: &str,
) -> Result<Option<T>, StorageError> {
    text.map(|t| from_json(t, what)).transpose()
}

/// Stored enum name → enum, through the model's `parse` function. Unknown names are corrupt.
pub(crate) fn parse_enum<T>(
    text: &str,
    parse: fn(&str) -> Option<T>,
    what: &str,
) -> Result<T, StorageError> {
    parse(text).ok_or_else(|| StorageError::Corrupt(format!("unknown {what} {text:?}")))
}

/// Stored non-negative INTEGER → u32. Out-of-range values are corrupt data.
pub(crate) fn i64_to_u32(value: i64, what: &str) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::Corrupt(format!("{what} {value} out of range")))
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Bytes → unpadded base64url (RFC 4648 §5), the TEXT format of sealed values in TEXT columns.
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let idx = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(B64URL[idx as usize]));
        }
    }
    out
}

/// Unpadded base64url → bytes. Anything that is not canonical base64url is corrupt data.
pub(crate) fn b64url_decode(text: &str, what: &str) -> Result<Vec<u8>, StorageError> {
    let corrupt = || StorageError::Corrupt(format!("{what}: not base64url"));
    let value = |c: u8| -> Option<u32> { B64URL.iter().position(|&x| x == c).map(|p| p as u32) };
    let input = text.as_bytes();
    if input.len() % 4 == 1 {
        return Err(corrupt());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 2);
    for chunk in input.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c).ok_or_else(corrupt)? << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = chunk.len() - 1;
        // Non-canonical trailing bits would make two texts decode to the same bytes.
        if bytes[keep..].iter().any(|&b| b != 0) && chunk.len() < 4 {
            return Err(corrupt());
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Ok(out)
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

/// Builds a page from up to `limit + 1` rows fetched in id order: `next_cursor` is the id of the
/// last returned item iff an extra row was fetched.
pub(crate) fn into_page<T>(
    mut items: Vec<T>,
    limit: u32,
    id_of: impl Fn(&T) -> uuid::Uuid,
) -> anvil_core::model::Page<T> {
    let limit = limit as usize;
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = if more { items.last().map(id_of) } else { None };
    anvil_core::model::Page { items, next_cursor }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::UserStatus;
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
    fn wrong_length_hash_is_corrupt() {
        assert!(matches!(
            blob_to_hash(&[0u8; 31], "h"),
            Err(StorageError::Corrupt(_))
        ));
        assert!(blob_to_hash(&[0u8; 32], "h").is_ok());
    }

    #[test]
    fn bad_json_and_unknown_enum_are_corrupt() {
        assert!(matches!(
            from_json::<Vec<String>>("{", "x"),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            parse_enum("nope", UserStatus::parse, "status"),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            i64_to_u32(-1, "attempts"),
            Err(StorageError::Corrupt(_))
        ));
    }

    #[test]
    fn b64url_round_trip_and_rejects_garbage() {
        for len in 0..10usize {
            let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37) ^ 0xA5).collect();
            let text = b64url_encode(&bytes);
            assert!(!text.contains('='));
            assert_eq!(b64url_decode(&text, "x").unwrap(), bytes, "len {len}");
        }
        assert_eq!(b64url_encode(b"\xfb\xff"), "-_8");
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        assert!(matches!(
            b64url_decode("Zm9v+mFy", "x"),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            b64url_decode("Zm9vY", "x"),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            b64url_decode("Zh", "x"),
            Err(StorageError::Corrupt(_))
        ));
    }

    #[test]
    fn page_cursor_only_when_more_rows_follow() {
        let ids: Vec<uuid::Uuid> = (0..3).map(|_| uuid::Uuid::now_v7()).collect();
        let page = into_page(ids.clone(), 2, |u| *u);
        assert_eq!(page.items, ids[..2]);
        assert_eq!(page.next_cursor, Some(ids[1]));
        let last = into_page(ids[2..].to_vec(), 2, |u| *u);
        assert_eq!(last.next_cursor, None);
    }
}
