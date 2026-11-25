//! Storage contract suite (feature `contract`).
//!
//! Every backend instantiates [`storage_contract_tests!`](crate::storage_contract_tests) with a
//! factory returning a fresh [`TestStorage`]. The list of contract tests lives in one place (the
//! macro), so a backend cannot silently skip one.
//!
//! All timestamps are truncated to whole milliseconds: the storage contract is millisecond
//! precision (see `anvil_core::model::truncate_to_ms`).

use std::any::Any;
use std::sync::Arc;

use anvil_core::model::{
    AuthorizationCode, CodeHash, NewAuthorizationCode, NewTenant, TenantId, TokenFamilyId,
    truncate_to_ms,
};
use anvil_core::ports::{ConsumeOutcome, Storage, StorageError};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// A storage backend under test.
pub struct TestStorage {
    pub storage: Arc<dyn Storage>,
    /// Keeps backend resources (temp dir, test database handle, ...) alive for the test.
    pub _guard: Box<dyn Any + Send + Sync>,
}

/// The current time, truncated to milliseconds.
pub fn now_ms() -> OffsetDateTime {
    truncate_to_ms(OffsetDateTime::now_utc())
}

/// A tenant with a unique slug.
pub fn new_tenant() -> NewTenant {
    let id = TenantId::new_v7();
    NewTenant {
        id,
        slug: format!("t-{}", Uuid::now_v7().simple()),
        display_name: format!("Tenant {}", id.0),
        created_at: now_ms(),
    }
}

/// A unique code hash built from two UUIDv7 values.
pub fn unique_code_hash() -> CodeHash {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::now_v7().as_bytes());
    bytes[16..].copy_from_slice(Uuid::now_v7().as_bytes());
    CodeHash(bytes)
}

/// A code expiring `expires_in` from now. Every nullable field is populated so round-trips
/// exercise the nullable columns.
pub fn new_code(expires_in: Duration) -> NewAuthorizationCode {
    let now = now_ms();
    NewAuthorizationCode {
        code_hash: unique_code_hash(),
        client_id: "client-a".to_owned(),
        redirect_uri: "https://app.example.test/callback".to_owned(),
        scope: "openid profile".to_owned(),
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        nonce: Some(format!("n-{}", Uuid::now_v7().simple())),
        token_family_id: Some(TokenFamilyId::new_v7()),
        expires_at: now + expires_in,
        created_at: now,
    }
}

/// The record `consume_code` must return for `code` stored under `tenant`.
pub fn expected_code(tenant: TenantId, code: &NewAuthorizationCode) -> AuthorizationCode {
    AuthorizationCode {
        tenant_id: tenant,
        code_hash: code.code_hash,
        client_id: code.client_id.clone(),
        redirect_uri: code.redirect_uri.clone(),
        scope: code.scope.clone(),
        code_challenge: code.code_challenge.clone(),
        nonce: code.nonce.clone(),
        token_family_id: code.token_family_id,
        expires_at: code.expires_at,
        created_at: code.created_at,
    }
}

/// Creates a tenant.
pub async fn seed_tenant(s: &TestStorage) -> TenantId {
    let t = new_tenant();
    s.storage
        .tenants()
        .create(&t)
        .await
        .expect("creating a seed tenant must succeed");
    t.id
}

/// Creates a tenant and a code valid for five minutes.
pub async fn seed_tenant_and_code(s: &TestStorage) -> (TenantId, NewAuthorizationCode) {
    let tenant = seed_tenant(s).await;
    let code = new_code(Duration::minutes(5));
    s.storage
        .grants()
        .create_code(tenant, &code)
        .await
        .expect("creating a seed code must succeed");
    (tenant, code)
}

pub async fn tenant_create_and_get(s: &TestStorage) {
    let repo = s.storage.tenants();
    let new = new_tenant();
    let created = repo.create(&new).await.expect("create must succeed");
    assert_eq!(created.id, new.id, "create must return the inserted id");
    assert_eq!(created.slug, new.slug);
    assert_eq!(created.display_name, new.display_name);
    assert_eq!(created.created_at, new.created_at);

    let by_id = repo.get(new.id).await.expect("get must succeed");
    assert_eq!(by_id.as_ref(), Some(&created), "get(id) must return the created tenant");

    let by_slug = repo
        .get_by_slug(&new.slug)
        .await
        .expect("get_by_slug must succeed");
    assert_eq!(by_slug.as_ref(), Some(&created), "get_by_slug must return the created tenant");

    assert_eq!(
        repo.get(TenantId::new_v7()).await.expect("get must succeed"),
        None,
        "unknown id must return None"
    );
    assert_eq!(
        repo.get_by_slug("no-such-tenant")
            .await
            .expect("get_by_slug must succeed"),
        None,
        "unknown slug must return None"
    );
}

pub async fn tenant_slug_conflict(s: &TestStorage) {
    let repo = s.storage.tenants();
    let first = new_tenant();
    repo.create(&first).await.expect("first create must succeed");

    let mut dup = new_tenant();
    dup.slug = first.slug.clone();
    match repo.create(&dup).await {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate slug must be rejected with Conflict, got {other:?}"),
    }
    assert_eq!(
        repo.get(dup.id).await.expect("get must succeed"),
        None,
        "the conflicting tenant must not have been stored"
    );
}

pub async fn consume_code_once(s: &TestStorage) {
    let (tenant, code) = seed_tenant_and_code(s).await;
    let grants = s.storage.grants();

    let first = grants
        .consume_code(tenant, &code.code_hash, now_ms())
        .await
        .expect("first consume must not error");
    assert_eq!(
        first,
        ConsumeOutcome::Consumed(expected_code(tenant, &code)),
        "first consume must return the stored code"
    );

    let second = grants
        .consume_code(tenant, &code.code_hash, now_ms())
        .await
        .expect("second consume must not error");
    assert_eq!(
        second,
        ConsumeOutcome::AlreadyConsumed {
            family_id: code.token_family_id
        },
        "second consume must report AlreadyConsumed with the code's token family"
    );
}

pub async fn consume_code_expired(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let grants = s.storage.grants();

    let expired = new_code(Duration::seconds(-1));
    grants
        .create_code(tenant, &expired)
        .await
        .expect("create_code must succeed");
    assert_eq!(
        grants
            .consume_code(tenant, &expired.code_hash, now_ms())
            .await
            .expect("consume must not error"),
        ConsumeOutcome::NotFound,
        "an expired code must not be consumable"
    );

    // Expiry is strict: a code whose expires_at equals `now` is already expired.
    let edge = new_code(Duration::minutes(5));
    grants
        .create_code(tenant, &edge)
        .await
        .expect("create_code must succeed");
    assert_eq!(
        grants
            .consume_code(tenant, &edge.code_hash, edge.expires_at)
            .await
            .expect("consume must not error"),
        ConsumeOutcome::NotFound,
        "a code must not be consumable at exactly expires_at"
    );
}

pub async fn consume_code_unknown(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    assert_eq!(
        s.storage
            .grants()
            .consume_code(tenant, &unique_code_hash(), now_ms())
            .await
            .expect("consume must not error"),
        ConsumeOutcome::NotFound,
        "an unknown code must return NotFound"
    );
}

pub async fn consume_code_wrong_tenant(s: &TestStorage) {
    let (owner, code) = seed_tenant_and_code(s).await;
    let other = seed_tenant(s).await;
    let grants = s.storage.grants();

    assert_eq!(
        grants
            .consume_code(other, &code.code_hash, now_ms())
            .await
            .expect("consume must not error"),
        ConsumeOutcome::NotFound,
        "another tenant must not be able to consume (or even see) the code"
    );
    assert_eq!(
        grants
            .consume_code(owner, &code.code_hash, now_ms())
            .await
            .expect("consume must not error"),
        ConsumeOutcome::Consumed(expected_code(owner, &code)),
        "the owning tenant must still be able to consume the code"
    );
}

pub async fn create_code_duplicate_conflict(s: &TestStorage) {
    let (tenant, code) = seed_tenant_and_code(s).await;
    match s.storage.grants().create_code(tenant, &code).await {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate code_hash must be rejected with Conflict, got {other:?}"),
    }
}

pub async fn consume_code_concurrent_single_winner(s: &TestStorage) {
    const N: usize = 32;
    const ROUNDS: usize = 10;
    for round in 0..ROUNDS {
        let (tenant, code) = seed_tenant_and_code(s).await;
        let hash = code.code_hash;
        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..N {
            let storage = Arc::clone(&s.storage);
            let barrier = Arc::clone(&barrier);
            set.spawn(async move {
                barrier.wait().await;
                storage.grants().consume_code(tenant, &hash, now_ms()).await
            });
        }
        let (mut won, mut lost) = (0usize, 0usize);
        while let Some(joined) = set.join_next().await {
            match joined.expect("consume task panicked") {
                Ok(ConsumeOutcome::Consumed(_)) => won += 1,
                Ok(ConsumeOutcome::AlreadyConsumed { .. }) => lost += 1,
                Ok(ConsumeOutcome::NotFound) => {
                    panic!("round {round}: a valid code must never be NotFound")
                }
                Err(e) => panic!("round {round}: no storage errors allowed, got {e:?}"),
            }
        }
        assert_eq!(
            (won, lost),
            (1, N - 1),
            "round {round}: exactly one concurrent consume must win"
        );
    }
}

/// Expands one `#[tokio::test]` per contract test, each calling `$factory().await` for a fresh
/// [`TestStorage`](crate::contract::TestStorage).
///
/// The callers need `tokio` (with `macros` and `rt-multi-thread`) as a dev-dependency.
#[macro_export]
macro_rules! storage_contract_tests {
    ($factory:path) => {
        $crate::storage_contract_tests!(@each $factory;
            tenant_create_and_get,
            tenant_slug_conflict,
            consume_code_once,
            consume_code_expired,
            consume_code_unknown,
            consume_code_wrong_tenant,
            create_code_duplicate_conflict,
            consume_code_concurrent_single_winner,
        );
    };
    (@each $factory:path; $($name:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn $name() {
                let s = $factory().await;
                $crate::contract::$name(&s).await;
            }
        )+
    };
}
