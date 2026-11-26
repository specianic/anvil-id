//! GrantRepo contract, pushed authorization requests (RFC 9126): create, single-use consume
//! (including under concurrency), expiry, tenant isolation, purge and the client cascade.

use std::sync::Arc;

use anvil_core::model::{NewPushedRequest, PushedRequest};
use anvil_core::ports::StorageError;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::TestStorage;
use super::fixtures::*;

/// A pushed request of `client_id` created now, expiring after `expires_in`.
fn new_pushed(client_id: &str, expires_in: Duration) -> NewPushedRequest {
    let now = now_ms();
    NewPushedRequest {
        request_uri_hash: unique_hash(),
        client_id: client_id.to_owned(),
        params: json!({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://app.example.test/cb",
            "scope": "openid profile",
            "state": "s-1",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "nested": {"claims": {"id_token": {"email": null}}},
        }),
        created_at: now,
        expires_at: now + expires_in,
    }
}

async fn push(s: &TestStorage, tenant: anvil_core::model::TenantId, req: &NewPushedRequest) {
    s.storage
        .grants()
        .create_pushed_request(tenant, req)
        .await
        .expect("create_pushed_request must succeed");
}

async fn consume(
    s: &TestStorage,
    tenant: anvil_core::model::TenantId,
    req: &NewPushedRequest,
    now: OffsetDateTime,
) -> Option<PushedRequest> {
    s.storage
        .grants()
        .consume_pushed_request(tenant, &req.request_uri_hash, now)
        .await
        .expect("consume_pushed_request must not error")
}

pub async fn par_create_and_consume_round_trip(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let req = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    push(s, ctx.tenant, &req).await;
    let now = now_ms();
    let got = consume(s, ctx.tenant, &req, now)
        .await
        .expect("a fresh pushed request must be consumable");
    assert_eq!(
        got,
        PushedRequest {
            client_id: req.client_id.clone(),
            params: req.params.clone(),
            expires_at: req.expires_at,
            consumed_at: Some(now),
        },
        "consume must return every stored field with consumed_at = now"
    );
}

pub async fn par_create_duplicate_hash_conflict(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let req = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    push(s, ctx.tenant, &req).await;
    let mut dup = new_pushed(&ctx.client.client_id, Duration::seconds(90));
    dup.request_uri_hash = req.request_uri_hash;
    match s
        .storage
        .grants()
        .create_pushed_request(ctx.tenant, &dup)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("a duplicate request_uri hash must be Conflict, got {other:?}"),
    }
    // The original is untouched.
    let got = consume(s, ctx.tenant, &req, now_ms())
        .await
        .expect("the original stays usable");
    assert_eq!(got.expires_at, req.expires_at);
}

pub async fn par_consume_twice_is_none(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let req = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    push(s, ctx.tenant, &req).await;
    let now = now_ms();
    assert!(consume(s, ctx.tenant, &req, now).await.is_some());
    assert_eq!(
        consume(s, ctx.tenant, &req, now).await,
        None,
        "a consumed pushed request must never be returned again"
    );
    assert_eq!(
        consume(s, ctx.tenant, &req, now + Duration::seconds(1)).await,
        None
    );
}

pub async fn par_consume_expired_is_none(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    // Already expired when stored.
    let past = new_pushed(&ctx.client.client_id, Duration::seconds(-1));
    push(s, ctx.tenant, &past).await;
    assert_eq!(consume(s, ctx.tenant, &past, now_ms()).await, None);

    // Expiry boundary: `expires_at <= now` is expired.
    let req = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    push(s, ctx.tenant, &req).await;
    assert_eq!(
        consume(s, ctx.tenant, &req, req.expires_at).await,
        None,
        "expires_at == now is expired"
    );
    // A failed (expired) consume does not mark it consumed: still usable before expiry.
    assert!(
        consume(
            s,
            ctx.tenant,
            &req,
            req.expires_at - Duration::milliseconds(1)
        )
        .await
        .is_some()
    );

    // Unknown hash.
    let unknown = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    assert_eq!(consume(s, ctx.tenant, &unknown, now_ms()).await, None);
}

pub async fn par_consume_single_winner_under_concurrency(s: &TestStorage) {
    const N: usize = 8;
    const ROUNDS: usize = 10;
    let ctx = seed_grant_ctx(s).await;
    for round in 0..ROUNDS {
        let req = new_pushed(&ctx.client.client_id, Duration::minutes(1));
        push(s, ctx.tenant, &req).await;
        let tenant = ctx.tenant;
        let hash = req.request_uri_hash;
        let storage = Arc::clone(&s.storage);
        let results = race(N, move |_| {
            let storage = Arc::clone(&storage);
            async move {
                storage
                    .grants()
                    .consume_pushed_request(tenant, &hash, now_ms())
                    .await
            }
        })
        .await;
        let mut won = 0usize;
        for r in results {
            match r {
                Ok(Some(p)) => {
                    assert_eq!(p.client_id, req.client_id);
                    won += 1;
                }
                Ok(None) => {}
                Err(e) => panic!("round {round}: no storage errors allowed, got {e:?}"),
            }
        }
        assert_eq!(won, 1, "round {round}: exactly one of {N} consumers wins");
    }
}

pub async fn par_tenant_isolation(s: &TestStorage) {
    let a = seed_grant_ctx(s).await;
    let b = seed_grant_ctx(s).await;
    let req = new_pushed(&a.client.client_id, Duration::seconds(60));
    push(s, a.tenant, &req).await;
    let now = now_ms();
    assert_eq!(
        consume(s, b.tenant, &req, now).await,
        None,
        "another tenant's pushed request behaves like a missing one"
    );
    // The same hash may exist independently in the other tenant.
    let mut in_b = new_pushed(&b.client.client_id, Duration::seconds(60));
    in_b.request_uri_hash = req.request_uri_hash;
    push(s, b.tenant, &in_b).await;
    let got_b = consume(s, b.tenant, &in_b, now).await.expect("b's own");
    assert_eq!(got_b.client_id, b.client.client_id);
    let got_a = consume(s, a.tenant, &req, now)
        .await
        .expect("the foreign attempt and b's consume must not consume a's request");
    assert_eq!(got_a.client_id, a.client.client_id);
}

pub async fn par_purged_after_expiry(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let expired = new_pushed(&ctx.client.client_id, Duration::seconds(-1));
    push(s, ctx.tenant, &expired).await;
    let consumed_expired = new_pushed(&ctx.client.client_id, Duration::seconds(-1));
    push(s, ctx.tenant, &consumed_expired).await;
    let live = new_pushed(&ctx.client.client_id, Duration::minutes(10));
    push(s, ctx.tenant, &live).await;
    let consumed_live = new_pushed(&ctx.client.client_id, Duration::minutes(10));
    push(s, ctx.tenant, &consumed_live).await;
    assert!(
        consume(s, ctx.tenant, &consumed_live, now_ms())
            .await
            .is_some()
    );

    let purged = s
        .storage
        .purge_expired(now_ms())
        .await
        .expect("purge_expired");
    assert!(
        purged >= 2,
        "both expired pushed requests are purged: {purged}"
    );

    // A purged row's hash can be stored again; a kept row's hash still conflicts.
    let reinsert = |orig: &NewPushedRequest| {
        let mut r = new_pushed(&ctx.client.client_id, Duration::minutes(1));
        r.request_uri_hash = orig.request_uri_hash;
        r
    };
    for gone in [&expired, &consumed_expired] {
        s.storage
            .grants()
            .create_pushed_request(ctx.tenant, &reinsert(gone))
            .await
            .expect("an expired pushed request must be deleted by purge_expired");
    }
    for kept in [&live, &consumed_live] {
        match s
            .storage
            .grants()
            .create_pushed_request(ctx.tenant, &reinsert(kept))
            .await
        {
            Err(StorageError::Conflict(_)) => {}
            other => panic!("an unexpired pushed request must survive the purge, got {other:?}"),
        }
    }
    assert!(
        consume(s, ctx.tenant, &live, now_ms()).await.is_some(),
        "the unexpired, unconsumed request stays usable"
    );
}

pub async fn par_deleted_with_client(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let req = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    push(s, ctx.tenant, &req).await;
    assert!(
        s.storage
            .clients()
            .delete(ctx.tenant, &ctx.client.client_id)
            .await
            .expect("delete client")
    );
    assert_eq!(
        consume(s, ctx.tenant, &req, now_ms()).await,
        None,
        "deleting the client deletes its pushed requests"
    );
    // A pushed request for a client that is not in the tenant is refused.
    let orphan = new_pushed(&ctx.client.client_id, Duration::seconds(60));
    assert!(
        s.storage
            .grants()
            .create_pushed_request(ctx.tenant, &orphan)
            .await
            .is_err(),
        "a pushed request must reference a client of the tenant"
    );
}
