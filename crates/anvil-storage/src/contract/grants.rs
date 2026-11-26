//! GrantRepo contract: authorization requests, codes, token families, refresh tokens, replay
//! guards; plus `Storage::purge_expired`.

use std::sync::Arc;

use anvil_core::model::{
    AuthorizationRequest, NewAuthorizationRequest, ReplayKind, RevokeReason, SelfServiceKind,
    TenantId, TokenFamilyId,
};
use anvil_core::ports::{ConsumeOutcome, JtiOutcome, RotateOutcome, StorageError};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn expected_request(tenant: TenantId, r: &NewAuthorizationRequest) -> AuthorizationRequest {
    AuthorizationRequest {
        id: r.id,
        tenant_id: tenant,
        client_id: r.client_id.clone(),
        params: r.params.clone(),
        created_at: r.created_at,
        expires_at: r.expires_at,
    }
}

// ---------------------------------------------------------------------------------------------
// Authorization requests

pub async fn auth_request_round_trip_with_claims_request(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other = seed_tenant(s).await;
    let grants = s.storage.grants();
    let req = new_auth_request(&ctx.client.client_id, Duration::minutes(10));
    assert!(req.params.claims.is_some());
    grants
        .create_authorization_request(ctx.tenant, &req)
        .await
        .expect("create_authorization_request");
    assert_eq!(
        grants
            .get_authorization_request(ctx.tenant, req.id, now_ms())
            .await
            .expect("get"),
        Some(expected_request(ctx.tenant, &req)),
        "every parameter, including the claims request, must round-trip"
    );
    assert_eq!(
        grants
            .get_authorization_request(other, req.id, now_ms())
            .await
            .expect("get"),
        None,
        "authorization requests must be tenant-scoped"
    );
    assert!(
        !grants
            .delete_authorization_request(other, req.id)
            .await
            .expect("delete")
    );
    assert!(
        grants
            .delete_authorization_request(ctx.tenant, req.id)
            .await
            .expect("delete")
    );
    assert_eq!(
        grants
            .get_authorization_request(ctx.tenant, req.id, now_ms())
            .await
            .expect("get"),
        None
    );
    assert!(
        !grants
            .delete_authorization_request(ctx.tenant, req.id)
            .await
            .expect("delete")
    );
}

pub async fn auth_request_expired_none(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let req = new_auth_request(&ctx.client.client_id, Duration::seconds(-1));
    grants
        .create_authorization_request(ctx.tenant, &req)
        .await
        .expect("create");
    assert_eq!(
        grants
            .get_authorization_request(ctx.tenant, req.id, now_ms())
            .await
            .expect("get"),
        None,
        "an expired authorization request must not be returned"
    );
}

// ---------------------------------------------------------------------------------------------
// Codes and families

pub async fn create_code_creates_family(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let (code, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    assert_eq!(
        grants
            .get_family(ctx.tenant, family.id)
            .await
            .expect("get_family"),
        Some(expected_family(ctx.tenant, &family)),
        "create_code must store the family with its full authentication context"
    );
    assert_eq!(code.token_family_id, family.id);

    // A code pointing at a different family id is rejected and nothing is stored.
    let family2 = new_family(&ctx, Duration::days(30));
    let mut mismatched = new_code(&ctx, &family2, Duration::minutes(5));
    mismatched.token_family_id = TokenFamilyId::new_v7();
    match grants.create_code(ctx.tenant, &mismatched, &family2).await {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("a code/family id mismatch must be rejected with Conflict, got {r:?}"),
    }
    assert_eq!(
        grants
            .get_family(ctx.tenant, family2.id)
            .await
            .expect("get_family"),
        None
    );
    assert_eq!(
        grants
            .consume_code(ctx.tenant, &mismatched.code_hash, now_ms())
            .await
            .expect("consume"),
        ConsumeOutcome::NotFound
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
            family_id: Some(code.token_family_id)
        },
        "second consume must report AlreadyConsumed with the code's token family"
    );
}

pub async fn consume_code_expired(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();

    let (expired, _) = seed_code(s, &ctx, Duration::seconds(-1)).await;
    assert_eq!(
        grants
            .consume_code(ctx.tenant, &expired.code_hash, now_ms())
            .await
            .expect("consume must not error"),
        ConsumeOutcome::NotFound,
        "an expired code must not be consumable"
    );

    // Expiry is strict: a code whose expires_at equals `now` is already expired.
    let (edge, _) = seed_code(s, &ctx, Duration::minutes(5)).await;
    assert_eq!(
        grants
            .consume_code(ctx.tenant, &edge.code_hash, edge.expires_at)
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
    let ctx = seed_grant_ctx(s).await;
    let (code, _) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let family = new_family(&ctx, Duration::days(30));
    let dup = anvil_core::model::NewAuthorizationCode {
        token_family_id: family.id,
        ..code
    };
    match s
        .storage
        .grants()
        .create_code(ctx.tenant, &dup, &family)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate code_hash must be rejected with Conflict, got {other:?}"),
    }
    assert_eq!(
        s.storage
            .grants()
            .get_family(ctx.tenant, family.id)
            .await
            .expect("get_family"),
        None,
        "the family of a conflicting code must not be stored"
    );
}

pub async fn consume_code_concurrent_single_winner(s: &TestStorage) {
    const N: usize = 32;
    const ROUNDS: usize = 10;
    let ctx = seed_grant_ctx(s).await;
    for round in 0..ROUNDS {
        let (code, _) = seed_code(s, &ctx, Duration::minutes(5)).await;
        let tenant = ctx.tenant;
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

pub async fn code_reuse_reports_family_id(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (code, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let grants = s.storage.grants();
    grants
        .consume_code(ctx.tenant, &code.code_hash, now_ms())
        .await
        .expect("consume");
    assert_eq!(
        grants
            .consume_code(ctx.tenant, &code.code_hash, now_ms())
            .await
            .expect("consume"),
        ConsumeOutcome::AlreadyConsumed {
            family_id: Some(family.id)
        },
        "a replayed code must report the family created with it"
    );
}

pub async fn revoke_family_idempotent_keeps_first_reason(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other = seed_tenant(s).await;
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let grants = s.storage.grants();
    let t1 = now_ms();
    let t2 = t1 + Duration::seconds(5);

    assert!(
        !grants
            .revoke_family(other, family.id, RevokeReason::Admin, t1)
            .await
            .expect("revoke"),
        "another tenant must not revoke the family"
    );
    assert!(
        grants
            .revoke_family(ctx.tenant, family.id, RevokeReason::CodeReuse, t1)
            .await
            .expect("revoke")
    );
    assert!(
        grants
            .revoke_family(ctx.tenant, family.id, RevokeReason::Admin, t2)
            .await
            .expect("revoke"),
        "revoking an already revoked family is idempotent"
    );
    let f = grants
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert_eq!(f.revoked_at, Some(t1), "the first revocation time is kept");
    assert_eq!(
        f.revoked_reason,
        Some(RevokeReason::CodeReuse),
        "the first reason is kept"
    );
    assert!(
        !grants
            .revoke_family(ctx.tenant, TokenFamilyId::new_v7(), RevokeReason::Admin, t1)
            .await
            .expect("revoke"),
        "revoking an unknown family must return false"
    );
}

// ---------------------------------------------------------------------------------------------
// Refresh tokens

pub async fn refresh_create_find(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other = seed_tenant(s).await;
    let (family, token) = seed_refresh(s, &ctx).await;
    let grants = s.storage.grants();
    assert_eq!(
        grants
            .find_refresh_token(ctx.tenant, &token.token_hash)
            .await
            .expect("find"),
        Some((
            expected_refresh(ctx.tenant, &token),
            expected_family(ctx.tenant, &family)
        ))
    );
    assert_eq!(
        grants
            .find_refresh_token(ctx.tenant, &unique_hash())
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        grants
            .find_refresh_token(other, &token.token_hash)
            .await
            .expect("find"),
        None,
        "refresh tokens must be tenant-scoped"
    );
    match grants.create_refresh_token(ctx.tenant, &token).await {
        Err(StorageError::Conflict(_)) => {}
        r => panic!("a duplicate refresh token hash must conflict, got {r:?}"),
    }
}

pub async fn rotate_refresh_success_inserts_child(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (family, token) = seed_refresh(s, &ctx).await;
    let grants = s.storage.grants();
    let child = new_refresh(family.id, Some(token.token_hash), Duration::days(1));
    let now = now_ms();
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &token.token_hash, &child, now)
            .await
            .expect("rotate"),
        RotateOutcome::Rotated(expected_family(ctx.tenant, &family))
    );
    let (presented, _) = grants
        .find_refresh_token(ctx.tenant, &token.token_hash)
        .await
        .expect("find")
        .expect("the presented token stays readable");
    assert_eq!(
        presented.consumed_at,
        Some(now),
        "rotation must consume the presented token"
    );
    let (stored_child, _) = grants
        .find_refresh_token(ctx.tenant, &child.token_hash)
        .await
        .expect("find")
        .expect("rotation must insert the child");
    assert_eq!(stored_child, expected_refresh(ctx.tenant, &child));

    // The child rotates in turn.
    let grandchild = new_refresh(family.id, Some(child.token_hash), Duration::days(1));
    assert!(matches!(
        grants
            .rotate_refresh(ctx.tenant, &child.token_hash, &grandchild, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::Rotated(_)
    ));

    // Another tenant cannot rotate.
    let other = seed_tenant(s).await;
    let stray = new_refresh(family.id, Some(grandchild.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(other, &grandchild.token_hash, &stray, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound
    );
}

pub async fn rotate_refresh_reuse_revokes_family(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (family, token) = seed_refresh(s, &ctx).await;
    let grants = s.storage.grants();
    let child = new_refresh(family.id, Some(token.token_hash), Duration::days(1));
    grants
        .rotate_refresh(ctx.tenant, &token.token_hash, &child, now_ms())
        .await
        .expect("rotate");

    let child2 = new_refresh(family.id, Some(token.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &token.token_hash, &child2, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::ReuseDetected {
            family_id: family.id
        },
        "presenting a consumed token must be detected as reuse"
    );
    let f = grants
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert!(f.revoked_at.is_some(), "reuse must revoke the family");
    assert_eq!(f.revoked_reason, Some(RevokeReason::RefreshReuse));
    assert_eq!(
        grants
            .find_refresh_token(ctx.tenant, &child2.token_hash)
            .await
            .expect("find"),
        None,
        "no child may be inserted on reuse"
    );
    let grandchild = new_refresh(family.id, Some(child.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &child.token_hash, &grandchild, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound,
        "after reuse the legitimate child must no longer rotate"
    );
}

pub async fn rotate_refresh_expired_not_found(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let grants = s.storage.grants();
    let expired = new_refresh(family.id, None, Duration::seconds(-1));
    grants
        .create_refresh_token(ctx.tenant, &expired)
        .await
        .expect("create");
    let child = new_refresh(family.id, Some(expired.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &expired.token_hash, &child, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound,
        "an expired refresh token must not rotate"
    );
    assert_eq!(
        grants
            .get_family(ctx.tenant, family.id)
            .await
            .expect("get_family")
            .expect("family")
            .revoked_at,
        None,
        "an expired token is not reuse"
    );
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &unique_hash(), &child, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound
    );
}

pub async fn rotate_refresh_absolute_expiry(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();

    // Family past its absolute lifetime.
    let family = new_family(&ctx, Duration::seconds(-1));
    let code = new_code(&ctx, &family, Duration::minutes(5));
    grants
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("create_code");
    let token = new_refresh(family.id, None, Duration::days(1));
    grants
        .create_refresh_token(ctx.tenant, &token)
        .await
        .expect("create");
    let child = new_refresh(family.id, Some(token.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &token.token_hash, &child, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound,
        "a family past absolute_expires_at must not rotate"
    );

    // Revoked family.
    let (revoked, token) = seed_refresh(s, &ctx).await;
    grants
        .revoke_family(ctx.tenant, revoked.id, RevokeReason::Admin, now_ms())
        .await
        .expect("revoke");
    let child = new_refresh(revoked.id, Some(token.token_hash), Duration::days(1));
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &token.token_hash, &child, now_ms())
            .await
            .expect("rotate"),
        RotateOutcome::NotFound,
        "a token of a revoked family must not rotate"
    );
}

pub async fn rotate_refresh_concurrent(s: &TestStorage) {
    const N: usize = 16;
    const ROUNDS: usize = 5;
    let ctx = seed_grant_ctx(s).await;
    for round in 0..ROUNDS {
        let (family, token) = seed_refresh(s, &ctx).await;
        let tenant = ctx.tenant;
        let presented = token.token_hash;
        let barrier = Arc::new(tokio::sync::Barrier::new(N));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..N {
            let storage = Arc::clone(&s.storage);
            let barrier = Arc::clone(&barrier);
            let child = new_refresh(family.id, Some(presented), Duration::days(1));
            set.spawn(async move {
                barrier.wait().await;
                storage
                    .grants()
                    .rotate_refresh(tenant, &presented, &child, now_ms())
                    .await
            });
        }
        let (mut rotated, mut other) = (0usize, 0usize);
        while let Some(joined) = set.join_next().await {
            match joined.expect("rotate task panicked") {
                Ok(RotateOutcome::Rotated(_)) => rotated += 1,
                Ok(RotateOutcome::ReuseDetected { family_id }) => {
                    assert_eq!(family_id, family.id);
                    other += 1;
                }
                Ok(RotateOutcome::NotFound) => other += 1,
                Err(e) => panic!("round {round}: no storage errors allowed, got {e:?}"),
            }
        }
        assert_eq!(
            (rotated, other),
            (1, N - 1),
            "round {round}: exactly one concurrent rotation must win"
        );
        let f = s
            .storage
            .grants()
            .get_family(tenant, family.id)
            .await
            .expect("get_family")
            .expect("family");
        assert!(
            f.revoked_at.is_some(),
            "round {round}: concurrent reuse must leave the family revoked"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Replay guards

pub async fn record_jti_once_then_replayed(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let grants = s.storage.grants();
    let hash = unique_hash();
    let now = now_ms();
    let exp = now + Duration::minutes(5);
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, now)
            .await
            .expect("record_jti"),
        JtiOutcome::Recorded
    );
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, now_ms())
            .await
            .expect("record_jti"),
        JtiOutcome::Replayed,
        "a second use must be detected"
    );
    assert_eq!(
        grants
            .record_jti(other, ReplayKind::ClientAssertionJti, &hash, exp, now_ms())
            .await
            .expect("record_jti"),
        JtiOutcome::Recorded,
        "replay guards are tenant-scoped"
    );
}

pub async fn record_jti_expired_can_be_reused(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let grants = s.storage.grants();
    let hash = unique_hash();
    let now = now_ms();
    let exp = now + Duration::seconds(1);
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, now)
            .await
            .expect("record_jti"),
        JtiOutcome::Recorded
    );
    assert_eq!(
        grants
            .record_jti(
                tenant,
                ReplayKind::ClientAssertionJti,
                &hash,
                exp + Duration::minutes(5),
                exp
            )
            .await
            .expect("record_jti"),
        JtiOutcome::Recorded,
        "an expired entry may be replaced"
    );
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, exp)
            .await
            .expect("record_jti"),
        JtiOutcome::Replayed,
        "the replacement entry is enforced"
    );
}

pub async fn record_jti_concurrent_single_winner(s: &TestStorage) {
    const N: usize = 16;
    let tenant = seed_tenant(s).await;
    let hash = unique_hash();
    let exp = now_ms() + Duration::minutes(5);
    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..N {
        let storage = Arc::clone(&s.storage);
        let barrier = Arc::clone(&barrier);
        set.spawn(async move {
            barrier.wait().await;
            storage
                .grants()
                .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, now_ms())
                .await
        });
    }
    let (mut recorded, mut replayed) = (0usize, 0usize);
    while let Some(joined) = set.join_next().await {
        match joined.expect("record task panicked") {
            Ok(JtiOutcome::Recorded) => recorded += 1,
            Ok(JtiOutcome::Replayed) => replayed += 1,
            Err(e) => panic!("no storage errors allowed, got {e:?}"),
        }
    }
    assert_eq!(
        (recorded, replayed),
        (1, N - 1),
        "exactly one concurrent record must win"
    );
}

// ---------------------------------------------------------------------------------------------
// Purge

pub async fn purge_expired_removes_only_expired_rows(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let users = s.storage.users();

    // Expired rows of every purgeable kind.
    let mut expected_min = 0u64;
    seed_code(s, &ctx, Duration::seconds(-1)).await;
    expected_min += 1;
    let req = new_auth_request(&ctx.client.client_id, Duration::seconds(-1));
    grants
        .create_authorization_request(ctx.tenant, &req)
        .await
        .expect("create");
    expected_min += 1;
    s.storage
        .flows()
        .create(ctx.tenant, &new_flow(None, Duration::seconds(-1)))
        .await
        .expect("create flow");
    expected_min += 1;
    s.storage
        .sessions()
        .create(
            ctx.tenant,
            &new_session(ctx.user.id, Duration::seconds(-1), Duration::seconds(-1)),
        )
        .await
        .expect("create session");
    expected_min += 1;
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let expired_rt = new_refresh(family.id, None, Duration::seconds(-1));
    grants
        .create_refresh_token(ctx.tenant, &expired_rt)
        .await
        .expect("create");
    expected_min += 1;
    let now = now_ms();
    grants
        .record_jti(
            ctx.tenant,
            ReplayKind::ClientAssertionJti,
            &unique_hash(),
            now - Duration::seconds(1),
            now - Duration::seconds(2),
        )
        .await
        .expect("record_jti");
    expected_min += 1;
    let expired_sst = new_self_service_token(
        SelfServiceKind::Verification,
        ctx.user.id,
        &ctx.user.email,
        Duration::seconds(-1),
    );
    users
        .issue_self_service_token(ctx.tenant, &expired_sst, None)
        .await
        .expect("issue");
    expected_min += 1;
    s.storage
        .setup()
        .create_setup_token(&new_setup_token(Duration::seconds(-1)))
        .await
        .expect("create_setup_token");
    expected_min += 1;
    let mut stale_email = new_email(&ctx.user.email);
    stale_email.expires_at = now - Duration::seconds(1);
    s.storage
        .outbox()
        .enqueue(ctx.tenant, &stale_email)
        .await
        .expect("enqueue");
    expected_min += 1;

    // Live rows that must survive.
    let (live_code, _) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let live_req = new_auth_request(&ctx.client.client_id, Duration::minutes(10));
    grants
        .create_authorization_request(ctx.tenant, &live_req)
        .await
        .expect("create");
    let live_flow = new_flow(None, Duration::minutes(10));
    s.storage
        .flows()
        .create(ctx.tenant, &live_flow)
        .await
        .expect("create");
    let live_rt = new_refresh(family.id, None, Duration::days(1));
    grants
        .create_refresh_token(ctx.tenant, &live_rt)
        .await
        .expect("create");
    // A consumed but unexpired refresh token is kept so reuse detection keeps working.
    let (consumed_family, consumed_rt) = seed_refresh(s, &ctx).await;
    let consumed_child = new_refresh(
        consumed_family.id,
        Some(consumed_rt.token_hash),
        Duration::days(1),
    );
    grants
        .rotate_refresh(
            ctx.tenant,
            &consumed_rt.token_hash,
            &consumed_child,
            now_ms(),
        )
        .await
        .expect("rotate");
    let live_jti = unique_hash();
    grants
        .record_jti(
            ctx.tenant,
            ReplayKind::ClientAssertionJti,
            &live_jti,
            now_ms() + Duration::minutes(5),
            now_ms(),
        )
        .await
        .expect("record_jti");
    let live_sst = new_self_service_token(
        SelfServiceKind::Verification,
        ctx.user.id,
        &ctx.user.email,
        Duration::hours(1),
    );
    users
        .issue_self_service_token(ctx.tenant, &live_sst, None)
        .await
        .expect("issue");
    let live_setup = new_setup_token(Duration::hours(1));
    s.storage
        .setup()
        .create_setup_token(&live_setup)
        .await
        .expect("create_setup_token");
    let live_email = new_email(&ctx.user.email);
    s.storage
        .outbox()
        .enqueue(ctx.tenant, &live_email)
        .await
        .expect("enqueue");

    let purged = s
        .storage
        .purge_expired(now_ms())
        .await
        .expect("purge_expired");
    assert!(
        purged >= expected_min,
        "purge_expired must delete every expired row ({purged} < {expected_min})"
    );
    assert_eq!(
        grants
            .find_refresh_token(ctx.tenant, &expired_rt.token_hash)
            .await
            .expect("find"),
        None,
        "expired refresh tokens must be purged"
    );

    // Survivors still work.
    let now = now_ms();
    assert!(matches!(
        grants
            .consume_code(ctx.tenant, &live_code.code_hash, now)
            .await
            .expect("consume"),
        ConsumeOutcome::Consumed(_)
    ));
    assert!(
        grants
            .get_authorization_request(ctx.tenant, live_req.id, now)
            .await
            .expect("get")
            .is_some()
    );
    assert!(
        s.storage
            .flows()
            .get(ctx.tenant, live_flow.id, now)
            .await
            .expect("get")
            .is_some()
    );
    assert!(
        s.storage
            .sessions()
            .get_active(ctx.tenant, &ctx.session.token_hash, now)
            .await
            .expect("get_active")
            .is_some()
    );
    assert!(
        grants
            .find_refresh_token(ctx.tenant, &live_rt.token_hash)
            .await
            .expect("find")
            .is_some()
    );
    let reuse_child = new_refresh(
        consumed_family.id,
        Some(consumed_rt.token_hash),
        Duration::days(1),
    );
    assert_eq!(
        grants
            .rotate_refresh(ctx.tenant, &consumed_rt.token_hash, &reuse_child, now)
            .await
            .expect("rotate"),
        RotateOutcome::ReuseDetected {
            family_id: consumed_family.id
        },
        "purge must keep consumed, unexpired refresh tokens for reuse detection"
    );
    assert_eq!(
        grants
            .record_jti(
                ctx.tenant,
                ReplayKind::ClientAssertionJti,
                &live_jti,
                now + Duration::minutes(5),
                now
            )
            .await
            .expect("record_jti"),
        JtiOutcome::Replayed
    );
    assert!(
        s.storage
            .setup()
            .peek_setup_token(&live_setup.token_hash, now)
            .await
            .expect("peek")
    );
    assert!(
        users
            .complete_verification(ctx.tenant, &live_sst.token_hash, now)
            .await
            .expect("complete_verification")
            .is_some()
    );
    let claimed = s
        .storage
        .outbox()
        .claim_due(now, 100, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(
        claimed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![live_email.id]
    );
}

pub async fn purge_expired_removes_expired_token_families(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let create = |absolute_in: Duration, code_in: Duration| {
        let family = new_family(&ctx, absolute_in);
        let code = new_code(&ctx, &family, code_in);
        (code, family)
    };

    // Past its absolute expiry, its only code expired: purged with its refresh tokens.
    let (code, dead) = create(Duration::seconds(-1), Duration::seconds(-1));
    grants
        .create_code(ctx.tenant, &code, &dead)
        .await
        .expect("create_code");
    let dead_rt = new_refresh(dead.id, None, Duration::days(1));
    grants
        .create_refresh_token(ctx.tenant, &dead_rt)
        .await
        .expect("create_refresh_token");
    // Past its absolute expiry but with a still-valid code: kept (the code still points at it).
    let (live_code, with_code) = create(Duration::seconds(-1), Duration::minutes(5));
    grants
        .create_code(ctx.tenant, &live_code, &with_code)
        .await
        .expect("create_code");
    // Not yet at its absolute expiry: kept even though its code expired.
    let (old_code, unexpired) = create(Duration::days(30), Duration::seconds(-1));
    grants
        .create_code(ctx.tenant, &old_code, &unexpired)
        .await
        .expect("create_code");
    let live_rt = new_refresh(unexpired.id, None, Duration::days(1));
    grants
        .create_refresh_token(ctx.tenant, &live_rt)
        .await
        .expect("create_refresh_token");

    s.storage
        .purge_expired(now_ms())
        .await
        .expect("purge_expired");

    assert_eq!(
        grants.get_family(ctx.tenant, dead.id).await.expect("get"),
        None,
        "a family past its absolute expiry with no live code is purged"
    );
    assert_eq!(
        grants
            .find_refresh_token(ctx.tenant, &dead_rt.token_hash)
            .await
            .expect("find"),
        None,
        "its refresh tokens go with it"
    );
    assert!(
        grants
            .get_family(ctx.tenant, with_code.id)
            .await
            .expect("get")
            .is_some(),
        "a family with an unexpired code is kept"
    );
    assert!(
        grants
            .get_family(ctx.tenant, unexpired.id)
            .await
            .expect("get")
            .is_some(),
        "an unexpired family is kept"
    );
    assert!(
        grants
            .find_refresh_token(ctx.tenant, &live_rt.token_hash)
            .await
            .expect("find")
            .is_some()
    );
}

// ---- Phase 4 (plan 04-01); backends implement it in 04-04 / 04-05 ----

pub async fn code_and_family_resource_round_trip(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let resource = vec!["https://api.example.test/".to_owned()];
    let family = anvil_core::model::NewTokenFamily {
        resource: resource.clone(),
        ..new_family(&ctx, Duration::days(30))
    };
    let code = anvil_core::model::NewAuthorizationCode {
        resource: resource.clone(),
        ..new_code(&ctx, &family, Duration::minutes(5))
    };
    grants
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("create_code");
    assert_eq!(
        grants
            .get_family(ctx.tenant, family.id)
            .await
            .expect("get_family"),
        Some(expected_family(ctx.tenant, &family))
    );
    match grants
        .consume_code(ctx.tenant, &code.code_hash, now_ms())
        .await
        .expect("consume")
    {
        ConsumeOutcome::Consumed(c) => {
            assert_eq!(c, expected_code(ctx.tenant, &code));
            assert_eq!(c.resource, resource);
        }
        other => panic!("expected Consumed, got {other:?}"),
    }

    // The stored authorization request keeps its resource indicators.
    let req = NewAuthorizationRequest {
        params: anvil_core::model::AuthorizationParams {
            resource: resource.clone(),
            ..full_params()
        },
        ..new_auth_request(&ctx.client.client_id, Duration::minutes(10))
    };
    grants
        .create_authorization_request(ctx.tenant, &req)
        .await
        .expect("create_authorization_request");
    assert_eq!(
        grants
            .get_authorization_request(ctx.tenant, req.id, now_ms())
            .await
            .expect("get")
            .expect("request")
            .params
            .resource,
        resource
    );
}

// ---- Phase 6 (plan 06-04): org-bound grants and SAML assertion replay ----

pub async fn code_and_family_org_round_trip(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let org = seed_org(s, ctx.tenant).await;
    let family = new_org_family(&ctx, Some(org.id));
    let code = anvil_core::model::NewAuthorizationCode {
        org_id: Some(org.id),
        ..new_code(&ctx, &family, Duration::minutes(5))
    };
    grants
        .create_code(ctx.tenant, &code, &family)
        .await
        .expect("create_code");
    let stored = grants
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert_eq!(stored, expected_family(ctx.tenant, &family));
    assert_eq!(stored.org_id, Some(org.id));
    match grants
        .consume_code(ctx.tenant, &code.code_hash, now_ms())
        .await
        .expect("consume")
    {
        ConsumeOutcome::Consumed(c) => {
            assert_eq!(c, expected_code(ctx.tenant, &code));
            assert_eq!(c.org_id, Some(org.id));
        }
        other => panic!("expected Consumed, got {other:?}"),
    }
    // A family without a code keeps its org too.
    let service = new_org_family(&ctx, Some(org.id));
    grants
        .create_family(ctx.tenant, &service)
        .await
        .expect("create_family");
    assert_eq!(
        grants
            .get_family(ctx.tenant, service.id)
            .await
            .expect("get_family")
            .expect("family")
            .org_id,
        Some(org.id)
    );
}

pub async fn record_jti_saml_assertion_id_replay(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let grants = s.storage.grants();
    let hash = unique_hash();
    let now = now_ms();
    let exp = now + Duration::hours(1);
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::SamlAssertionId, &hash, exp, now)
            .await
            .expect("record"),
        JtiOutcome::Recorded
    );
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::SamlAssertionId, &hash, exp, now_ms())
            .await
            .expect("record again"),
        JtiOutcome::Replayed,
        "a replayed assertion id is detected"
    );
    // Kinds are separate namespaces.
    assert_eq!(
        grants
            .record_jti(tenant, ReplayKind::ClientAssertionJti, &hash, exp, now_ms())
            .await
            .expect("record other kind"),
        JtiOutcome::Recorded
    );
}

// ---- Phase 7 (plan 07-08): export read ----

pub async fn families_for_user_every_state_oldest_first(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let mut first = new_family(&ctx, Duration::days(30));
    first.created_at = now_ms() - Duration::seconds(30);
    let mut expired = new_family(&ctx, Duration::days(30));
    expired.created_at = first.created_at + Duration::seconds(1);
    expired.absolute_expires_at = expired.created_at + Duration::seconds(2);
    let mut revoked = new_family(&ctx, Duration::days(30));
    revoked.created_at = first.created_at + Duration::seconds(2);
    for f in [&revoked, &first, &expired] {
        grants.create_family(ctx.tenant, f).await.expect("create");
    }
    let at = now_ms();
    assert!(
        grants
            .revoke_family(ctx.tenant, revoked.id, RevokeReason::Admin, at)
            .await
            .expect("revoke")
    );
    // Not the user's: a service family, another user's family, another tenant's family.
    grants
        .create_family(
            ctx.tenant,
            &new_service_family(&ctx.client.client_id, Duration::days(1)),
        )
        .await
        .expect("create");
    let someone_else = seed_user(s, ctx.tenant).await;
    seed_family_for(s, ctx.tenant, &someone_else, None).await;
    let other = seed_grant_ctx(s).await;
    grants
        .create_family(other.tenant, &new_family(&other, Duration::days(1)))
        .await
        .expect("create");

    let mut revoked_expected = expected_family(ctx.tenant, &revoked);
    revoked_expected.revoked_at = Some(at);
    revoked_expected.revoked_reason = Some(RevokeReason::Admin);
    assert_eq!(
        grants
            .families_for_user(ctx.tenant, ctx.user.id)
            .await
            .expect("families_for_user"),
        vec![
            expected_family(ctx.tenant, &first),
            expected_family(ctx.tenant, &expired),
            revoked_expected,
        ],
        "every family of the user in any state, oldest first"
    );
    assert!(
        grants
            .families_for_user(other.tenant, ctx.user.id)
            .await
            .expect("families_for_user")
            .is_empty(),
        "tenant isolation"
    );
}
