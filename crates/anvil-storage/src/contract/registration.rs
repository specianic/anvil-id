//! RegistrationRepo contract: initial access tokens (stored by hash, single conditional consume,
//! revocation, expiry) and the per-source client count behind the DCR `max_clients` cap.

use anvil_core::model::{ClientSource, InitialAccessTokenId};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn iat_create_list_revoke(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.registration();
    assert!(repo.list_iats(tenant).await.expect("list").is_empty());
    let limited = new_iat(Some(5), Some(Duration::days(1)));
    let unlimited = new_iat(None, None);
    assert_eq!(
        repo.create_iat(tenant, &limited).await.expect("create"),
        expected_iat(tenant, &limited)
    );
    assert_eq!(
        repo.create_iat(tenant, &unlimited).await.expect("create"),
        expected_iat(tenant, &unlimited)
    );
    assert_eq!(
        repo.list_iats(tenant).await.expect("list"),
        vec![
            expected_iat(tenant, &limited),
            expected_iat(tenant, &unlimited)
        ],
        "id order"
    );

    let mut dup = new_iat(Some(1), None);
    dup.token_hash = limited.token_hash;
    assert!(matches!(
        repo.create_iat(tenant, &dup).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(repo.list_iats(tenant).await.expect("list").len(), 2);

    let at = now_ms() + Duration::seconds(1);
    assert!(
        repo.revoke_iat(tenant, limited.id, at)
            .await
            .expect("revoke")
    );
    assert!(
        !repo
            .revoke_iat(tenant, limited.id, at)
            .await
            .expect("revoke"),
        "already revoked"
    );
    assert!(
        !repo
            .revoke_iat(tenant, InitialAccessTokenId::new_v7(), at)
            .await
            .expect("revoke")
    );
    let listed = repo.list_iats(tenant).await.expect("list");
    assert_eq!(listed[0].revoked_at, Some(at), "revoked tokens stay listed");
    assert_eq!(listed[1].revoked_at, None);
}

pub async fn iat_consume_decrements_and_stops_at_zero(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.registration();
    let token = new_iat(Some(2), Some(Duration::hours(1)));
    repo.create_iat(tenant, &token).await.expect("create");
    let now = now_ms();

    let first = repo
        .consume_iat(tenant, &token.token_hash, now)
        .await
        .expect("consume")
        .expect("first use");
    assert_eq!(first.id, token.id);
    assert_eq!(first.uses_remaining, Some(1));
    let second = repo
        .consume_iat(tenant, &token.token_hash, now)
        .await
        .expect("consume")
        .expect("second use");
    assert_eq!(second.uses_remaining, Some(0));
    assert_eq!(
        repo.consume_iat(tenant, &token.token_hash, now)
            .await
            .expect("consume"),
        None,
        "no uses left"
    );

    // Unlimited tokens never run out and keep `uses_remaining = None`.
    let unlimited = new_iat(None, None);
    repo.create_iat(tenant, &unlimited).await.expect("create");
    for _ in 0..3 {
        let t = repo
            .consume_iat(tenant, &unlimited.token_hash, now)
            .await
            .expect("consume")
            .expect("unlimited");
        assert_eq!(t.uses_remaining, None);
    }
    assert_eq!(
        repo.consume_iat(tenant, &unique_hash(), now)
            .await
            .expect("consume"),
        None,
        "unknown hash"
    );
}

pub async fn iat_expired_or_revoked_not_consumed(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.registration();
    let expiring = new_iat(Some(3), Some(Duration::minutes(5)));
    repo.create_iat(tenant, &expiring).await.expect("create");
    let expires_at = expiring.expires_at.expect("expiry set");
    assert_eq!(
        repo.consume_iat(tenant, &expiring.token_hash, expires_at)
            .await
            .expect("consume"),
        None,
        "not valid at exactly expires_at"
    );
    assert_eq!(
        repo.list_iats(tenant).await.expect("list")[0].uses_remaining,
        Some(3),
        "a refused consume changes nothing"
    );

    let revoked = new_iat(None, None);
    repo.create_iat(tenant, &revoked).await.expect("create");
    let now = now_ms();
    assert!(
        repo.revoke_iat(tenant, revoked.id, now)
            .await
            .expect("revoke")
    );
    assert_eq!(
        repo.consume_iat(tenant, &revoked.token_hash, now)
            .await
            .expect("consume"),
        None
    );

    // Another tenant's token is unknown here.
    let other = seed_tenant(s).await;
    let theirs = new_iat(Some(1), None);
    repo.create_iat(other, &theirs).await.expect("create");
    assert_eq!(
        repo.consume_iat(tenant, &theirs.token_hash, now)
            .await
            .expect("consume"),
        None
    );
    assert!(
        !repo
            .revoke_iat(tenant, theirs.id, now)
            .await
            .expect("revoke"),
        "cannot revoke another tenant's token"
    );
    assert!(repo.list_iats(tenant).await.expect("list").len() == 2);
    assert_eq!(
        repo.consume_iat(other, &theirs.token_hash, now)
            .await
            .expect("consume")
            .map(|t| t.uses_remaining),
        Some(Some(0)),
        "still usable in its own tenant"
    );
}

pub async fn iat_single_use_concurrent_single_winner(s: &TestStorage) {
    const CONSUMERS: usize = 8;
    let tenant = seed_tenant(s).await;
    let token = new_iat(Some(1), Some(Duration::hours(1)));
    s.storage
        .registration()
        .create_iat(tenant, &token)
        .await
        .expect("create");
    let now = now_ms();
    let storage = s.storage.clone();
    let hash = token.token_hash;
    let results = race(CONSUMERS, move |_| {
        let storage = storage.clone();
        async move { storage.registration().consume_iat(tenant, &hash, now).await }
    })
    .await;
    let winners = results
        .into_iter()
        .map(|r| r.expect("no storage errors allowed"))
        .filter(Option::is_some)
        .count();
    assert_eq!(winners, 1, "a single-use token is consumed exactly once");
    assert_eq!(
        s.storage
            .registration()
            .list_iats(tenant)
            .await
            .expect("list")[0]
            .uses_remaining,
        Some(0)
    );
}

pub async fn count_clients_by_source(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.registration();
    for source in [
        ClientSource::Static,
        ClientSource::Dynamic,
        ClientSource::Cimd,
    ] {
        assert_eq!(
            repo.count_clients_by_source(tenant, source)
                .await
                .expect("count"),
            0
        );
    }
    seed_client(s, tenant).await;
    seed_client(s, tenant).await;
    seed_client(s, other).await;
    let mut dynamic = new_client();
    dynamic.registration_source = ClientSource::Dynamic;
    dynamic.registration_access_token_hash = Some(unique_hash());
    s.storage
        .clients()
        .create(tenant, &dynamic)
        .await
        .expect("create dynamic client");
    let now = now_ms();
    s.storage
        .clients()
        .upsert_cimd(tenant, &new_cimd_client(), now + Duration::hours(1), now)
        .await
        .expect("upsert_cimd");

    assert_eq!(
        repo.count_clients_by_source(tenant, ClientSource::Static)
            .await
            .expect("count"),
        2
    );
    assert_eq!(
        repo.count_clients_by_source(tenant, ClientSource::Dynamic)
            .await
            .expect("count"),
        1
    );
    assert_eq!(
        repo.count_clients_by_source(tenant, ClientSource::Cimd)
            .await
            .expect("count"),
        1
    );
    assert_eq!(
        repo.count_clients_by_source(other, ClientSource::Dynamic)
            .await
            .expect("count"),
        0
    );
}
