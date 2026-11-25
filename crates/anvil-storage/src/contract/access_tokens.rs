//! GrantRepo opaque access-token contract (and families created without a code).

use anvil_core::model::RevokeReason;
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn access_token_create_find_with_and_without_family(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;

    let user_token = new_access_token(
        Some(family.id),
        &ctx.client.client_id,
        Some(ctx.user.id),
        Duration::hours(1),
    );
    grants
        .create_access_token(ctx.tenant, &user_token)
        .await
        .expect("create_access_token");
    assert_eq!(
        grants
            .find_access_token(ctx.tenant, &user_token.token_hash)
            .await
            .expect("find"),
        Some((
            expected_access_token(ctx.tenant, &user_token),
            Some(expected_family(ctx.tenant, &family))
        ))
    );

    let service_token = new_access_token(None, &ctx.client.client_id, None, Duration::hours(1));
    grants
        .create_access_token(ctx.tenant, &service_token)
        .await
        .expect("create_access_token");
    assert_eq!(
        grants
            .find_access_token(ctx.tenant, &service_token.token_hash)
            .await
            .expect("find"),
        Some((expected_access_token(ctx.tenant, &service_token), None))
    );

    let err = grants
        .create_access_token(ctx.tenant, &service_token)
        .await
        .expect_err("a duplicate hash must conflict");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");
    assert_eq!(
        grants
            .find_access_token(ctx.tenant, &unique_hash())
            .await
            .expect("find"),
        None
    );
}

pub async fn access_token_found_in_any_state(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let expired = new_access_token(
        Some(family.id),
        &ctx.client.client_id,
        Some(ctx.user.id),
        Duration::seconds(-1),
    );
    grants
        .create_access_token(ctx.tenant, &expired)
        .await
        .expect("create");
    assert!(
        grants
            .find_access_token(ctx.tenant, &expired.token_hash)
            .await
            .expect("find")
            .is_some(),
        "expired tokens are still found (callers decide validity)"
    );

    grants
        .revoke_family(ctx.tenant, family.id, RevokeReason::Admin, now_ms())
        .await
        .expect("revoke_family");
    let (_, fam) = grants
        .find_access_token(ctx.tenant, &expired.token_hash)
        .await
        .expect("find")
        .expect("token");
    let fam = fam.expect("family");
    assert!(fam.revoked_at.is_some(), "the revoked family is reported");
    assert_eq!(fam.revoked_reason, Some(RevokeReason::Admin));
}

pub async fn access_token_revoke(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other = seed_tenant(s).await;
    let grants = s.storage.grants();
    let token = new_access_token(None, &ctx.client.client_id, None, Duration::hours(1));
    grants
        .create_access_token(ctx.tenant, &token)
        .await
        .expect("create");

    assert!(
        !grants
            .revoke_access_token(other, &token.token_hash, now_ms())
            .await
            .expect("revoke"),
        "another tenant cannot revoke it"
    );
    assert_eq!(
        grants
            .find_access_token(other, &token.token_hash)
            .await
            .expect("find"),
        None
    );
    let now = now_ms();
    assert!(
        grants
            .revoke_access_token(ctx.tenant, &token.token_hash, now)
            .await
            .expect("revoke")
    );
    assert!(
        !grants
            .revoke_access_token(ctx.tenant, &token.token_hash, now_ms())
            .await
            .expect("revoke"),
        "already revoked"
    );
    let (record, _) = grants
        .find_access_token(ctx.tenant, &token.token_hash)
        .await
        .expect("find")
        .expect("token");
    assert_eq!(record.revoked_at, Some(now));
    assert!(
        !grants
            .revoke_access_token(ctx.tenant, &unique_hash(), now_ms())
            .await
            .expect("revoke")
    );
}

pub async fn create_family_without_code(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let family = new_service_family(&ctx.client.client_id, Duration::days(1));
    grants
        .create_family(ctx.tenant, &family)
        .await
        .expect("create_family");
    assert_eq!(
        grants
            .get_family(ctx.tenant, family.id)
            .await
            .expect("get_family"),
        Some(expected_family(ctx.tenant, &family)),
        "a user-less family round-trips"
    );
    let err = grants
        .create_family(ctx.tenant, &family)
        .await
        .expect_err("a duplicate family id must conflict");
    assert!(matches!(err, StorageError::Conflict(_)), "{err:?}");

    let with_user = new_family(&ctx, Duration::days(1));
    grants
        .create_family(ctx.tenant, &with_user)
        .await
        .expect("create_family");
    assert_eq!(
        grants
            .get_family(ctx.tenant, with_user.id)
            .await
            .expect("get_family"),
        Some(expected_family(ctx.tenant, &with_user))
    );
}
