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

async fn insert_key(s: &TestStorage, tenant: TenantId, key: &NewSigningKey) {
    s.storage.keys().insert(tenant, key).await.expect("insert");
}

pub async fn key_list_returns_every_state(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let keys = [
        new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(-1))),
        new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(1))),
        new_signing_key("RS256", KeyState::Active, None),
        new_signing_key("RS256", KeyState::Next, None),
        new_signing_key("ES256", KeyState::Active, None),
    ];
    for k in &keys {
        insert_key(s, tenant, k).await;
    }
    assert_eq!(
        s.storage.keys().list(tenant).await.expect("list"),
        keys.iter()
            .map(|k| expected_key(tenant, k))
            .collect::<Vec<_>>(),
        "every key in id order, expired retired keys included"
    );
    assert!(s.storage.keys().list(other).await.expect("list").is_empty());
}

pub async fn key_promote_retires_then_activates(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.keys();
    let active = new_signing_key("RS256", KeyState::Active, None);
    let next = new_signing_key("RS256", KeyState::Next, None);
    insert_key(s, tenant, &active).await;
    insert_key(s, tenant, &next).await;

    let now = now_ms() + Duration::seconds(1);
    let expires_at = now + Duration::hours(2);
    assert!(
        repo.promote(tenant, Some((active.id, expires_at)), next.id, now)
            .await
            .expect("promote")
    );
    let promoted = repo
        .active(tenant, "RS256")
        .await
        .expect("active")
        .expect("active key");
    assert_eq!(promoted.id, next.id);
    assert_eq!(promoted.activated_at, Some(now));
    let all = repo.list(tenant).await.expect("list");
    let retired = all.iter().find(|k| k.id == active.id).expect("old key");
    assert_eq!(retired.state, KeyState::Retired);
    assert_eq!(retired.retired_at, Some(now));
    assert_eq!(retired.expires_at, Some(expires_at));
    assert_eq!(
        all.iter().filter(|k| k.state == KeyState::Active).count(),
        1,
        "exactly one active key per alg afterwards"
    );

    // Activating without retiring while a key is active violates the one-active rule.
    let third = new_signing_key("RS256", KeyState::Next, None);
    insert_key(s, tenant, &third).await;
    let err = repo
        .promote(tenant, None, third.id, now_ms())
        .await
        .expect_err("a second active key must conflict");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");
    let after = repo.list(tenant).await.expect("list");
    assert_eq!(
        after.iter().find(|k| k.id == third.id).map(|k| k.state),
        Some(KeyState::Next),
        "a failed promote changes nothing"
    );
    assert_eq!(
        repo.active(tenant, "RS256")
            .await
            .expect("active")
            .map(|k| k.id),
        Some(next.id)
    );

    // A first key for an alg can be activated without retiring anything.
    let es = new_signing_key("ES256", KeyState::Next, None);
    insert_key(s, tenant, &es).await;
    assert!(
        repo.promote(tenant, None, es.id, now_ms())
            .await
            .expect("promote")
    );
    assert_eq!(
        repo.active(tenant, "ES256")
            .await
            .expect("active")
            .map(|k| k.id),
        Some(es.id)
    );
}

pub async fn key_promote_stale_ids_change_nothing(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.keys();
    let active = new_signing_key("RS256", KeyState::Active, None);
    let retired = new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(1)));
    let next = new_signing_key("RS256", KeyState::Next, None);
    for k in [&active, &retired, &next] {
        insert_key(s, tenant, k).await;
    }
    let before = repo.list(tenant).await.expect("list");
    let exp = now_ms() + Duration::hours(1);
    for (why, retire, activate, t) in [
        (
            "retire a key that is not active",
            Some((retired.id, exp)),
            next.id,
            tenant,
        ),
        (
            "activate an unknown key",
            Some((active.id, exp)),
            anvil_core::model::SigningKeyId::new_v7(),
            tenant,
        ),
        (
            "activate a key that is not next",
            Some((active.id, exp)),
            retired.id,
            tenant,
        ),
        ("another tenant", Some((active.id, exp)), next.id, other),
    ] {
        assert!(
            !repo
                .promote(t, retire, activate, now_ms())
                .await
                .expect("promote"),
            "{why}: must report false"
        );
        assert_eq!(
            repo.list(tenant).await.expect("list"),
            before,
            "{why}: nothing changed"
        );
    }
}

pub async fn key_delete_expired_removes_only_expired_retired(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let expired = new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(-1)));
    let live = new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(1)));
    let active = new_signing_key("RS256", KeyState::Active, Some(Duration::hours(-1)));
    let next = new_signing_key("RS256", KeyState::Next, None);
    let other_expired = new_signing_key("RS256", KeyState::Retired, Some(Duration::hours(-1)));
    for k in [&expired, &live, &active, &next] {
        insert_key(s, tenant, k).await;
    }
    insert_key(s, other, &other_expired).await;

    assert_eq!(
        s.storage
            .keys()
            .delete_expired(tenant, now_ms())
            .await
            .expect("delete_expired"),
        1
    );
    let left: Vec<_> = s
        .storage
        .keys()
        .list(tenant)
        .await
        .expect("list")
        .into_iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(left, vec![live.id, active.id, next.id]);
    assert_eq!(
        s.storage.keys().list(other).await.expect("list").len(),
        1,
        "other tenants are untouched"
    );
}
