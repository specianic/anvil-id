//! GrantRepo consent contract.

use anvil_core::model::{ConsentGrant, RevokeReason};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn scopes(g: &ConsentGrant) -> Vec<&str> {
    g.scopes.iter().map(String::as_str).collect()
}

pub async fn consent_upsert_unions_scopes(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let client_id = ctx.client.client_id.as_str();
    assert_eq!(
        grants
            .consent(ctx.tenant, ctx.user.id, client_id)
            .await
            .expect("consent"),
        None
    );

    let first = new_consent(ctx.user.id, client_id, &["openid", "profile"]);
    let t1 = now_ms();
    let created = grants
        .upsert_consent(ctx.tenant, &first, t1)
        .await
        .expect("upsert");
    assert_eq!(created.id, first.id);
    assert_eq!(created.user_id, ctx.user.id);
    assert_eq!(created.client_id, client_id);
    assert_eq!(scopes(&created), vec!["openid", "profile"]);
    assert_eq!(created.created_at, first.created_at);
    assert_eq!(created.revoked_at, None);

    let t2 = t1 + Duration::seconds(5);
    let second = new_consent(ctx.user.id, client_id, &["email", "openid"]);
    let merged = grants
        .upsert_consent(ctx.tenant, &second, t2)
        .await
        .expect("upsert");
    assert_eq!(
        merged.id, first.id,
        "an existing grant is updated, not replaced"
    );
    assert_eq!(
        scopes(&merged),
        vec!["email", "openid", "profile"],
        "union, sorted"
    );
    assert_eq!(merged.created_at, first.created_at);
    assert_eq!(merged.updated_at, t2);
    assert_eq!(
        grants
            .consent(ctx.tenant, ctx.user.id, client_id)
            .await
            .expect("consent"),
        Some(merged.clone())
    );
    assert_eq!(
        grants
            .list_consents(ctx.tenant, ctx.user.id)
            .await
            .expect("list"),
        vec![merged]
    );
}

pub async fn consent_revoked_is_ignored_and_reactivated(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let grants = s.storage.grants();
    let client_id = ctx.client.client_id.as_str();
    grants
        .upsert_consent(
            ctx.tenant,
            &new_consent(ctx.user.id, client_id, &["openid", "profile"]),
            now_ms(),
        )
        .await
        .expect("upsert");
    assert!(
        grants
            .revoke_consent(ctx.tenant, ctx.user.id, client_id, now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(
        grants
            .consent(ctx.tenant, ctx.user.id, client_id)
            .await
            .expect("consent"),
        None,
        "a revoked consent is not active"
    );
    assert!(
        grants
            .list_consents(ctx.tenant, ctx.user.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        !grants
            .revoke_consent(ctx.tenant, ctx.user.id, client_id, now_ms())
            .await
            .expect("revoke"),
        "revoking twice reports false"
    );

    let again = grants
        .upsert_consent(
            ctx.tenant,
            &new_consent(ctx.user.id, client_id, &["openid"]),
            now_ms(),
        )
        .await
        .expect("upsert");
    assert_eq!(again.revoked_at, None);
    assert_eq!(
        scopes(&again),
        vec!["openid"],
        "re-activation grants exactly the new scopes"
    );
}

pub async fn consent_revoke_revokes_only_that_clients_families(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other_client = seed_client(s, ctx.tenant).await;
    let grants = s.storage.grants();
    let (_, family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let other_ctx = GrantCtx {
        tenant: ctx.tenant,
        user: ctx.user.clone(),
        client: other_client.clone(),
        session: ctx.session.clone(),
    };
    let (_, other_family) = seed_code(s, &other_ctx, Duration::minutes(5)).await;
    for c in [&ctx.client.client_id, &other_client.client_id] {
        grants
            .upsert_consent(
                ctx.tenant,
                &new_consent(ctx.user.id, c, &["openid"]),
                now_ms(),
            )
            .await
            .expect("upsert");
    }

    assert!(
        grants
            .revoke_consent(ctx.tenant, ctx.user.id, &ctx.client.client_id, now_ms())
            .await
            .expect("revoke")
    );
    let revoked = grants
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.revoked_reason, Some(RevokeReason::ConsentRevoked));
    let untouched = grants
        .get_family(ctx.tenant, other_family.id)
        .await
        .expect("get_family")
        .expect("family");
    assert_eq!(
        untouched.revoked_at, None,
        "another client's family stays valid"
    );
    assert!(
        grants
            .consent(ctx.tenant, ctx.user.id, &other_client.client_id)
            .await
            .expect("consent")
            .is_some()
    );

    assert!(
        !grants
            .revoke_consent(ctx.tenant, ctx.user.id, "no-such-client", now_ms())
            .await
            .expect("revoke"),
        "no consent: false"
    );
}

pub async fn consent_isolated_by_tenant(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let other = seed_tenant(s).await;
    let grants = s.storage.grants();
    let client_id = ctx.client.client_id.as_str();
    grants
        .upsert_consent(
            ctx.tenant,
            &new_consent(ctx.user.id, client_id, &["openid"]),
            now_ms(),
        )
        .await
        .expect("upsert");
    assert_eq!(
        grants
            .consent(other, ctx.user.id, client_id)
            .await
            .expect("consent"),
        None
    );
    assert!(
        grants
            .list_consents(other, ctx.user.id)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        !grants
            .revoke_consent(other, ctx.user.id, client_id, now_ms())
            .await
            .expect("revoke")
    );
    assert!(
        grants
            .consent(ctx.tenant, ctx.user.id, client_id)
            .await
            .expect("consent")
            .is_some()
    );
}
