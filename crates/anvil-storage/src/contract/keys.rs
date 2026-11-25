//! KeyRepo contract.

use anvil_core::model::{KeyState, NewSigningKey, SigningKey, TenantId};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn expected_key(tenant: TenantId, k: &NewSigningKey) -> SigningKey {
    SigningKey {
        id: k.id,
        tenant_id: tenant,
        kid: k.kid.clone(),
        alg: k.alg.clone(),
        state: k.state,
        private_key_enc: k.private_key_enc.clone(),
        public_jwk: k.public_jwk.clone(),
        created_at: k.created_at,
        activated_at: k.activated_at,
        retired_at: k.retired_at,
        expires_at: k.expires_at,
    }
}

pub async fn key_insert_and_active(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let key = new_signing_key("RS256", KeyState::Active, None);
    s.storage.keys().insert(tenant, &key).await.expect("insert");
    assert_eq!(
        s.storage
            .keys()
            .active(tenant, "RS256")
            .await
            .expect("active"),
        Some(expected_key(tenant, &key)),
        "active must return every field of the active key"
    );
    assert_eq!(
        s.storage
            .keys()
            .active(tenant, "ES256")
            .await
            .expect("active"),
        None
    );
    assert_eq!(
        s.storage
            .keys()
            .active(other, "RS256")
            .await
            .expect("active"),
        None,
        "keys must be tenant-scoped"
    );
}

pub async fn key_second_active_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let keys = s.storage.keys();
    let first = new_signing_key("RS256", KeyState::Active, None);
    keys.insert(tenant, &first).await.expect("insert");

    match keys
        .insert(tenant, &new_signing_key("RS256", KeyState::Active, None))
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("a second active key for the same alg must conflict, got {r:?}"),
    }
    keys.insert(tenant, &new_signing_key("RS256", KeyState::Next, None))
        .await
        .expect("a Next key next to the active one must be allowed");
    keys.insert(tenant, &new_signing_key("ES256", KeyState::Active, None))
        .await
        .expect("an active key for another alg must be allowed");
    keys.insert(other, &new_signing_key("RS256", KeyState::Active, None))
        .await
        .expect("an active key in another tenant must be allowed");
    assert_eq!(
        keys.active(tenant, "RS256")
            .await
            .expect("active")
            .map(|k| k.id),
        Some(first.id)
    );
}

pub async fn key_published_excludes_expired(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let keys = s.storage.keys();
    let next = new_signing_key("RS256", KeyState::Next, None);
    let active = new_signing_key("RS256", KeyState::Active, None);
    let retired = new_signing_key("RS256", KeyState::Retired, Some(Duration::days(1)));
    let expired = new_signing_key("RS256", KeyState::Retired, Some(Duration::seconds(-1)));
    for k in [&next, &active, &retired, &expired] {
        keys.insert(tenant, k).await.expect("insert");
    }
    let published = keys.published(tenant, now_ms()).await.expect("published");
    assert_eq!(
        published,
        vec![
            expected_key(tenant, &next),
            expected_key(tenant, &active),
            expected_key(tenant, &retired),
        ],
        "published must return unexpired keys of any state in id order"
    );
    assert!(
        keys.published(seed_tenant(s).await, now_ms())
            .await
            .expect("published")
            .is_empty()
    );
}
