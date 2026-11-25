//! ClientRepo contract.

use anvil_core::model::{
    ClientUpdate, ConsentMode, GrantType, NewClient, PageRequest, RevokeReason, TokenFormat,
};
use anvil_core::ports::{RotateOutcome, StorageError};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn client_create_get_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let new = new_client();
    assert!(new.jwks.is_some() && new.secret_hash.is_some());
    let created = s
        .storage
        .clients()
        .create(tenant, &new)
        .await
        .expect("create must succeed");
    assert_eq!(
        created,
        expected_client(tenant, &new),
        "create must return every field"
    );
    assert_eq!(
        s.storage
            .clients()
            .get(tenant, &new.client_id)
            .await
            .expect("get"),
        Some(created),
        "get must return every field"
    );
    assert_eq!(
        s.storage
            .clients()
            .get(tenant, "unknown")
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        s.storage
            .clients()
            .get(other, &new.client_id)
            .await
            .expect("get"),
        None,
        "clients must be tenant-scoped"
    );
}

pub async fn client_id_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let first = seed_client(s, tenant).await;
    let mut dup = new_client();
    dup.client_id = first.client_id.clone();
    match s.storage.clients().create(tenant, &dup).await {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate client_id must be rejected with Conflict, got {other:?}"),
    }
    let other = seed_tenant(s).await;
    s.storage
        .clients()
        .create(other, &dup)
        .await
        .expect("the same client_id must be allowed in another tenant");
}

pub async fn client_update(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let client = seed_client(s, tenant).await;
    let later = now_ms() + Duration::seconds(10);
    let updated = s
        .storage
        .clients()
        .update(
            tenant,
            &client.client_id,
            &ClientUpdate {
                name: Some("Renamed".into()),
                redirect_uris: Some(vec!["https://new.example.test/cb".into()]),
                grant_types: Some(vec![GrantType::ClientCredentials]),
                scopes: Some(vec!["api".into()]),
                require_pkce: Some(false),
                jwks: Some(None),
                ..ClientUpdate::default()
            },
            later,
        )
        .await
        .expect("update")
        .expect("updating an existing client must return it");
    assert_eq!(updated.name, "Renamed");
    assert_eq!(
        updated.redirect_uris,
        vec!["https://new.example.test/cb".to_owned()]
    );
    assert_eq!(updated.grant_types, vec![GrantType::ClientCredentials]);
    assert_eq!(updated.scopes, vec!["api".to_owned()]);
    assert!(!updated.require_pkce);
    assert_eq!(updated.jwks, None, "jwks Some(None) must clear the JWKS");
    assert_eq!(updated.updated_at, later);
    assert_eq!(updated.created_at, client.created_at);
    assert_eq!(
        updated.secret_hash, client.secret_hash,
        "update never touches the secret"
    );
    assert_eq!(
        s.storage
            .clients()
            .get(tenant, &client.client_id)
            .await
            .expect("get"),
        Some(updated)
    );
    assert_eq!(
        s.storage
            .clients()
            .update(tenant, "unknown", &ClientUpdate::default(), later)
            .await
            .expect("update"),
        None
    );
}

pub async fn client_set_secret_hash(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let client = seed_client(s, tenant).await;
    let later = now_ms() + Duration::seconds(10);
    let new_hash = unique_hash();
    assert!(
        s.storage
            .clients()
            .set_secret_hash(tenant, &client.client_id, Some(new_hash), later)
            .await
            .expect("set_secret_hash")
    );
    let got = s
        .storage
        .clients()
        .get(tenant, &client.client_id)
        .await
        .expect("get")
        .expect("client");
    assert_eq!(got.secret_hash, Some(new_hash));
    assert_eq!(got.updated_at, later);
    assert!(
        s.storage
            .clients()
            .set_secret_hash(tenant, &client.client_id, None, later)
            .await
            .expect("set_secret_hash")
    );
    assert_eq!(
        s.storage
            .clients()
            .get(tenant, &client.client_id)
            .await
            .expect("get")
            .expect("client")
            .secret_hash,
        None
    );
    assert!(
        !s.storage
            .clients()
            .set_secret_hash(tenant, "unknown", Some(new_hash), later)
            .await
            .expect("set_secret_hash")
    );
}

pub async fn client_delete_revokes_families(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (family, refresh) = seed_refresh(s, &ctx).await;
    assert!(
        s.storage
            .clients()
            .delete(ctx.tenant, &ctx.client.client_id)
            .await
            .expect("delete")
    );
    assert_eq!(
        s.storage
            .clients()
            .get(ctx.tenant, &ctx.client.client_id)
            .await
            .expect("get"),
        None
    );
    if let Some(f) = s
        .storage
        .grants()
        .get_family(ctx.tenant, family.id)
        .await
        .expect("get_family")
    {
        assert!(
            f.revoked_at.is_some(),
            "the client's families must be revoked"
        );
        assert_eq!(f.revoked_reason, Some(RevokeReason::ClientDeleted));
    }
    let child = new_refresh(family.id, Some(refresh.token_hash), Duration::days(1));
    assert_eq!(
        s.storage
            .grants()
            .rotate_refresh(ctx.tenant, &refresh.token_hash, &child, now_ms())
            .await
            .expect("rotate_refresh"),
        RotateOutcome::NotFound,
        "refresh tokens of a deleted client must not rotate"
    );
    assert!(
        !s.storage
            .clients()
            .delete(ctx.tenant, &ctx.client.client_id)
            .await
            .expect("delete")
    );
}

pub async fn client_list_pagination(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    seed_client(s, other).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(seed_client(s, tenant).await.id);
    }
    let first = s
        .storage
        .clients()
        .list(
            tenant,
            PageRequest {
                after: None,
                limit: 2,
            },
        )
        .await
        .expect("list");
    assert_eq!(
        first.items.iter().map(|c| c.id).collect::<Vec<_>>(),
        ids[..2]
    );
    assert_eq!(first.next_cursor, Some(ids[1].0));
    let second = s
        .storage
        .clients()
        .list(
            tenant,
            PageRequest {
                after: first.next_cursor,
                limit: 2,
            },
        )
        .await
        .expect("list");
    assert_eq!(
        second.items.iter().map(|c| c.id).collect::<Vec<_>>(),
        ids[2..]
    );
    assert_eq!(second.next_cursor, None);
}

pub async fn client_phase3_fields_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let new = NewClient {
        token_format: TokenFormat::Opaque,
        consent_mode: ConsentMode::SkipFirstParty,
        id_token_signed_response_alg: Some("ES256".into()),
        can_introspect: true,
        ..new_client()
    };
    let created = s
        .storage
        .clients()
        .create(tenant, &new)
        .await
        .expect("create");
    assert_eq!(created, expected_client(tenant, &new));
    assert_eq!(
        s.storage
            .clients()
            .get(tenant, &new.client_id)
            .await
            .expect("get"),
        Some(expected_client(tenant, &new))
    );

    let updated = s
        .storage
        .clients()
        .update(
            tenant,
            &new.client_id,
            &ClientUpdate {
                token_format: Some(TokenFormat::Jwt),
                consent_mode: Some(ConsentMode::Required),
                id_token_signed_response_alg: Some(None),
                can_introspect: Some(false),
                ..ClientUpdate::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("client");
    assert_eq!(updated.token_format, TokenFormat::Jwt);
    assert_eq!(updated.consent_mode, ConsentMode::Required);
    assert_eq!(updated.id_token_signed_response_alg, None);
    assert!(!updated.can_introspect);
}
