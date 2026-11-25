//! Conversions between Postgres column values and the domain model.
//!
//! uuid, timestamptz, text[] and bool map natively through sqlx. Hashes (bytea), enums (text),
//! JSON documents (jsonb), counters and errors need the helpers here. Anything that does not
//! decode is reported as [`StorageError::Corrupt`], never silently defaulted.

use anvil_core::model::SecretHash;
use anvil_core::ports::StorageError;
use serde::Serialize;
use serde::de::DeserializeOwned;

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

/// bytea → 32-byte hash. Anything else is corrupt data.
pub(crate) fn hash(column: &str, bytes: &[u8]) -> Result<SecretHash, StorageError> {
    SecretHash::from_slice(bytes).map_err(|e| StorageError::Corrupt(format!("{column}: {e}")))
}

/// Nullable bytea → optional 32-byte hash.
pub(crate) fn opt_hash(
    column: &str,
    bytes: Option<&[u8]>,
) -> Result<Option<SecretHash>, StorageError> {
    bytes.map(|b| hash(column, b)).transpose()
}

/// text → enum via the model's `parse`.
pub(crate) fn enum_from<T>(
    column: &str,
    value: &str,
    parse: fn(&str) -> Option<T>,
) -> Result<T, StorageError> {
    parse(value).ok_or_else(|| StorageError::Corrupt(format!("{column}: unknown value {value:?}")))
}

/// text[] → enums.
pub(crate) fn enums_from<T>(
    column: &str,
    values: &[String],
    parse: fn(&str) -> Option<T>,
) -> Result<Vec<T>, StorageError> {
    values.iter().map(|v| enum_from(column, v, parse)).collect()
}

/// Value → jsonb.
pub(crate) fn to_json<T: Serialize>(
    column: &str,
    value: &T,
) -> Result<serde_json::Value, StorageError> {
    serde_json::to_value(value)
        .map_err(|e| StorageError::Backend(format!("encoding {column}: {e}").into()))
}

/// jsonb → value.
pub(crate) fn from_json<T: DeserializeOwned>(
    column: &str,
    value: serde_json::Value,
) -> Result<T, StorageError> {
    serde_json::from_value(value).map_err(|e| StorageError::Corrupt(format!("{column}: {e}")))
}

/// Nullable jsonb → optional value.
pub(crate) fn opt_from_json<T: DeserializeOwned>(
    column: &str,
    value: Option<serde_json::Value>,
) -> Result<Option<T>, StorageError> {
    value.map(|v| from_json(column, v)).transpose()
}

/// Non-negative integer column → u32.
pub(crate) fn to_u32(column: &str, value: i32) -> Result<u32, StorageError> {
    u32::try_from(value).map_err(|_| StorageError::Corrupt(format!("{column}: negative {value}")))
}

/// Bytes → lowercase hex (sealed TOTP seeds in `credential.data`, a text column shared with PHC
/// strings and passkey JSON).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Hex → bytes. Anything else is corrupt data.
pub(crate) fn from_hex(column: &str, text: &str) -> Result<Vec<u8>, StorageError> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(StorageError::Corrupt(format!("{column}: odd-length hex")));
    }
    pairs
        .iter()
        .map(|pair| match (nibble(pair[0]), nibble(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err(StorageError::Corrupt(format!("{column}: invalid hex"))),
        })
        .collect()
}

/// Non-negative bigint column → u32 (passkey signature counters).
pub(crate) fn bigint_to_u32(column: &str, value: i64) -> Result<u32, StorageError> {
    u32::try_from(value)
        .map_err(|_| StorageError::Corrupt(format!("{column}: out of range {value}")))
}

/// Non-negative bigint column → u64 (TOTP steps).
pub(crate) fn bigint_to_u64(column: &str, value: i64) -> Result<u64, StorageError> {
    u64::try_from(value).map_err(|_| StorageError::Corrupt(format!("{column}: negative {value}")))
}

/// Enum slice → text[] values.
pub(crate) fn enum_names<T>(values: &[T], name: fn(&T) -> &'static str) -> Vec<String> {
    values.iter().map(|v| name(v).to_owned()).collect()
}

/// Page size for keyset pagination: `limit + 1` rows are fetched to know whether more follow.
pub(crate) fn fetch_limit(limit: u32) -> i64 {
    i64::from(limit) + 1
}

/// Splits `limit + 1` fetched rows into a page (`next_cursor` iff more rows follow).
pub(crate) fn into_page<T>(
    mut items: Vec<T>,
    limit: u32,
    id: impl Fn(&T) -> uuid::Uuid,
) -> anvil_core::model::Page<T> {
    let limit = limit as usize;
    let more = items.len() > limit;
    items.truncate(limit);
    let next_cursor = if more { items.last().map(&id) } else { None };
    anvil_core::model::Page { items, next_cursor }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_core::model::ClientType;

    #[test]
    fn wrong_length_hash_is_corrupt() {
        for len in [0usize, 31, 33] {
            assert!(matches!(
                hash("h", &vec![0u8; len]),
                Err(StorageError::Corrupt(_))
            ));
        }
        assert!(hash("h", &[0u8; 32]).is_ok());
        assert!(matches!(opt_hash("h", None), Ok(None)));
    }

    #[test]
    fn unknown_enum_is_corrupt() {
        assert!(matches!(
            enum_from("t", "nope", ClientType::parse),
            Err(StorageError::Corrupt(_))
        ));
        assert_eq!(
            enum_from("t", "public", ClientType::parse).ok(),
            Some(ClientType::Public)
        );
    }

    #[test]
    fn negative_counter_is_corrupt() {
        assert!(matches!(to_u32("a", -1), Err(StorageError::Corrupt(_))));
        assert_eq!(to_u32("a", 3).ok(), Some(3));
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(to_hex(&bytes), "0001abff");
        assert_eq!(from_hex("c", "0001abff").ok(), Some(bytes.to_vec()));
        assert_eq!(from_hex("c", "0001ABFF").ok(), Some(bytes.to_vec()));
        for bad in ["0", "zz", "0g"] {
            assert!(matches!(from_hex("c", bad), Err(StorageError::Corrupt(_))));
        }
        assert!(matches!(
            bigint_to_u32("c", -1),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            bigint_to_u32("c", 1 << 33),
            Err(StorageError::Corrupt(_))
        ));
        assert!(matches!(
            bigint_to_u64("c", -1),
            Err(StorageError::Corrupt(_))
        ));
    }

    #[test]
    fn page_cursor_only_when_more_follow() {
        let ids: Vec<uuid::Uuid> = (0..3).map(|_| uuid::Uuid::now_v7()).collect();
        let p = into_page(ids.clone(), 2, |u| *u);
        assert_eq!(p.items, ids[..2]);
        assert_eq!(p.next_cursor, Some(ids[1]));
        let p = into_page(ids.clone(), 3, |u| *u);
        assert_eq!(p.next_cursor, None);
    }

    #[test]
    fn non_database_errors_are_backend() {
        assert!(matches!(
            map_err(sqlx::Error::PoolTimedOut),
            StorageError::Backend(_)
        ));
    }
}
