//! Transactional email outbox.

use std::collections::BTreeMap;

use anvil_jose::Kek;
use time::OffsetDateTime;

use super::ids::{OutboxId, TenantId};
use crate::error::CoreError;

/// An email to be enqueued (in the same transaction as the change that triggers it).
/// `payload` holds the template variables, sealed with [`seal_payload`] (a single `sealed` entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEmail {
    pub id: OutboxId,
    pub to: String,
    pub template: String,
    pub payload: BTreeMap<String, String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

/// A stored outbox email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEmail {
    pub id: OutboxId,
    pub tenant_id: TenantId,
    pub to: String,
    pub template: String,
    pub payload: BTreeMap<String, String>,
    pub attempts: u32,
    pub next_attempt_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub sent_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
}

/// KEK purpose for sealed outbox payloads.
pub const OUTBOX_PAYLOAD_PURPOSE: &str = "anvilid/outbox-payload/v1";

/// The single key of a sealed payload map.
pub const SEALED_PAYLOAD_KEY: &str = "sealed";

/// Seals template variables for storage (they can carry single-use links). Returns
/// `{"sealed": base64url(Kek::seal(OUTBOX_PAYLOAD_PURPOSE, tenant id bytes, json))}`.
pub fn seal_payload(
    _kek: &Kek,
    _tenant: TenantId,
    _payload: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CoreError> {
    Err(CoreError::Internal("not implemented".into()))
}

/// Opens a payload sealed with [`seal_payload`]. Anything but exactly one `sealed` entry is
/// rejected (there is no plaintext fallback). Errors are generic and never contain the value.
pub fn open_payload(
    _kek: &Kek,
    _tenant: TenantId,
    _stored: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, CoreError> {
    Err(CoreError::Internal("not implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("tenant_name".to_owned(), "Acme Corp".to_owned()),
            ("email".to_owned(), "alice@example.com".to_owned()),
            (
                "link".to_owned(),
                "https://id.example.test/ui/recovery?token=MARKER-TOKEN-1234".to_owned(),
            ),
        ])
    }

    #[test]
    fn round_trip() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let sealed = seal_payload(&kek, tenant, &payload()).unwrap();
        assert_eq!(sealed.len(), 1);
        assert!(sealed.contains_key(SEALED_PAYLOAD_KEY));
        assert_eq!(open_payload(&kek, tenant, &sealed).unwrap(), payload());
        let empty = seal_payload(&kek, tenant, &BTreeMap::new()).unwrap();
        assert!(open_payload(&kek, tenant, &empty).unwrap().is_empty());
    }

    #[test]
    fn wrong_tenant_or_kek_fails() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let sealed = seal_payload(&kek, tenant, &payload()).unwrap();
        assert!(open_payload(&kek, TenantId::new_v7(), &sealed).is_err());
        assert!(open_payload(&Kek::generate(), tenant, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let sealed = seal_payload(&kek, tenant, &payload()).unwrap();
        let raw = anvil_jose::encoding::b64url_decode(&sealed[SEALED_PAYLOAD_KEY]).unwrap();
        for i in [0, raw.len() / 2, raw.len() - 1] {
            let mut flipped = raw.clone();
            flipped[i] ^= 0x01;
            let tampered = BTreeMap::from([(
                SEALED_PAYLOAD_KEY.to_owned(),
                anvil_jose::encoding::b64url(&flipped),
            )]);
            assert!(open_payload(&kek, tenant, &tampered).is_err(), "flip {i}");
        }
        let garbage = BTreeMap::from([(SEALED_PAYLOAD_KEY.to_owned(), "!!not base64!!".into())]);
        assert!(open_payload(&kek, tenant, &garbage).is_err());
        let short = BTreeMap::from([(SEALED_PAYLOAD_KEY.to_owned(), "AAAA".into())]);
        assert!(open_payload(&kek, tenant, &short).is_err());
    }

    #[test]
    fn unsealed_maps_are_rejected() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        assert!(open_payload(&kek, tenant, &payload()).is_err());
        assert!(open_payload(&kek, tenant, &BTreeMap::new()).is_err());
        // A sealed entry next to plaintext entries is not accepted either.
        let mut mixed = seal_payload(&kek, tenant, &payload()).unwrap();
        mixed.insert("link".into(), "https://evil.example/".into());
        assert!(open_payload(&kek, tenant, &mixed).is_err());
    }

    #[test]
    fn sealed_map_leaks_no_input_value() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let sealed = seal_payload(&kek, tenant, &payload()).unwrap();
        let stored: String = sealed.iter().map(|(k, v)| format!("{k}={v}")).collect();
        for (k, v) in payload() {
            assert!(!stored.contains(&v), "value of {k} leaked");
            assert!(!stored.contains(&k), "key {k} leaked");
        }
        assert!(!stored.contains("MARKER-TOKEN-1234"));
    }

    #[test]
    fn open_error_does_not_echo_the_value() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let err = open_payload(&kek, tenant, &payload()).unwrap_err().to_string();
        assert!(!err.contains("MARKER-TOKEN-1234") && !err.contains("alice"));
    }
}
