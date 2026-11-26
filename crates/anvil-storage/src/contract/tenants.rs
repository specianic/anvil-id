//! TenantRepo contract.

use anvil_core::model::{
    CaptchaProvider, CaptchaSettings, PageRequest, RegistrationMode, TenantId, TenantSettings,
    TenantUpdate,
};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn tenant_create_and_get(s: &TestStorage) {
    let repo = s.storage.tenants();
    let new = new_tenant();
    let created = repo.create(&new).await.expect("create must succeed");
    assert_eq!(created.id, new.id, "create must return the inserted id");
    assert_eq!(created.slug, new.slug);
    assert_eq!(created.display_name, new.display_name);
    assert_eq!(created.host, new.host);
    assert_eq!(created.settings, new.settings);
    assert_eq!(created.created_at, new.created_at);

    let by_id = repo.get(new.id).await.expect("get must succeed");
    assert_eq!(
        by_id.as_ref(),
        Some(&created),
        "get(id) must return the created tenant"
    );

    let by_slug = repo
        .get_by_slug(&new.slug)
        .await
        .expect("get_by_slug must succeed");
    assert_eq!(
        by_slug.as_ref(),
        Some(&created),
        "get_by_slug must return the created tenant"
    );

    assert_eq!(
        repo.get(TenantId::new_v7())
            .await
            .expect("get must succeed"),
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
    repo.create(&first)
        .await
        .expect("first create must succeed");

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

pub async fn tenant_get_by_host(s: &TestStorage) {
    let repo = s.storage.tenants();
    let new = new_tenant();
    let created = repo.create(&new).await.expect("create must succeed");
    let host = new.host.clone().expect("fixture has a host");
    assert_eq!(
        repo.get_by_host(&host)
            .await
            .expect("get_by_host must succeed"),
        Some(created),
        "get_by_host must return the tenant"
    );
    assert_eq!(
        repo.get_by_host("unknown.example.test")
            .await
            .expect("get_by_host must succeed"),
        None,
        "unknown host must return None"
    );
}

pub async fn tenant_host_conflict(s: &TestStorage) {
    let repo = s.storage.tenants();
    let first = new_tenant();
    repo.create(&first)
        .await
        .expect("first create must succeed");

    let mut dup = new_tenant();
    dup.host = first.host.clone();
    match repo.create(&dup).await {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("duplicate host must be rejected with Conflict, got {other:?}"),
    }
    assert_eq!(repo.get(dup.id).await.expect("get must succeed"), None);

    // Tenants without a host do not conflict with each other.
    for _ in 0..2 {
        let mut t = new_tenant();
        t.host = None;
        repo.create(&t)
            .await
            .expect("several tenants without a host must be allowed");
    }
}

pub async fn tenant_list_pagination(s: &TestStorage) {
    let repo = s.storage.tenants();
    let mut ids = Vec::new();
    for _ in 0..3 {
        let t = new_tenant();
        repo.create(&t).await.expect("create must succeed");
        ids.push(t.id);
    }

    let first = repo
        .list(PageRequest {
            after: None,
            limit: 2,
        })
        .await
        .expect("list must succeed");
    assert_eq!(
        first.items.iter().map(|t| t.id).collect::<Vec<_>>(),
        ids[..2],
        "first page must hold the two oldest tenants in id order"
    );
    assert_eq!(
        first.next_cursor,
        Some(ids[1].0),
        "a non-final page must return the last id as cursor"
    );

    let second = repo
        .list(PageRequest {
            after: first.next_cursor,
            limit: 2,
        })
        .await
        .expect("list must succeed");
    assert_eq!(
        second.items.iter().map(|t| t.id).collect::<Vec<_>>(),
        ids[2..],
        "second page must hold the remaining tenant"
    );
    assert_eq!(
        second.next_cursor, None,
        "the last page must not return a cursor"
    );
}

pub async fn tenant_update_settings_round_trip(s: &TestStorage) {
    let repo = s.storage.tenants();
    let new = new_tenant();
    let created = repo.create(&new).await.expect("create must succeed");

    let settings = TenantSettings {
        registration: RegistrationMode::Disabled,
        require_verified_email: false,
        signing_algs: vec!["RS256".into(), "ES256".into()],
        captcha: Some(CaptchaSettings {
            provider: CaptchaProvider::Hcaptcha,
            site_key: "site-key".into(),
            secret_sealed: "c2VhbGVkLXNlY3JldA".into(),
        }),
        mfa_policy: anvil_core::model::MfaPolicy::Optional,
        email_otp: false,
        magic_link: false,
        auto_link: true,
        upstream_registration: None,
        default_locale: "en".to_owned(),
        // Phase 5 sections live in the settings JSON: non-default values must round-trip.
        dcr: anvil_core::model::DcrSettings {
            policy: anvil_core::model::DcrPolicy::AllowListed,
            allowed_redirect_hosts: vec!["app.example".to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            allowed_resources: vec!["https://api.example".to_owned()],
            allow_client_credentials: true,
            max_clients: 10,
        },
        cimd: anvil_core::model::CimdSettings {
            policy: anvil_core::model::CimdPolicy::AllowListed,
            allowed_hosts: vec!["mcp.example".to_owned()],
            min_cache_secs: 60,
            max_cache_secs: 600,
        },
        claims: anvil_core::model::ClaimMappingSettings {
            roles: None,
            permissions: Some(anvil_core::model::ClaimRule {
                claim: "perms".to_owned(),
                tokens: vec![anvil_core::model::TokenTarget::IdToken],
                scope: Some("perms".to_owned()),
            }),
        },
    };
    let updated = repo
        .update(
            new.id,
            &TenantUpdate {
                display_name: Some("Renamed".into()),
                host: Some(None),
                settings: Some(settings.clone()),
            },
        )
        .await
        .expect("update must succeed")
        .expect("update of an existing tenant must return it");
    assert_eq!(updated.display_name, "Renamed");
    assert_eq!(updated.host, None, "host Some(None) must clear the host");
    assert_eq!(updated.settings, settings);
    assert_eq!(updated.slug, created.slug, "unchanged fields must stay");
    assert_eq!(updated.created_at, created.created_at);
    assert_eq!(
        repo.get(new.id).await.expect("get must succeed"),
        Some(updated.clone()),
        "update must persist"
    );

    // Empty update changes nothing.
    assert_eq!(
        repo.update(new.id, &TenantUpdate::default())
            .await
            .expect("update must succeed"),
        Some(updated),
    );

    // Taking another tenant's host conflicts.
    let other = new_tenant();
    repo.create(&other).await.expect("create must succeed");
    match repo
        .update(
            new.id,
            &TenantUpdate {
                host: Some(other.host.clone()),
                ..TenantUpdate::default()
            },
        )
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("updating to a taken host must conflict, got {other:?}"),
    }

    assert_eq!(
        repo.update(TenantId::new_v7(), &TenantUpdate::default())
            .await
            .expect("update must succeed"),
        None,
        "updating an unknown tenant must return None"
    );
}

pub async fn tenant_delete_cascades(s: &TestStorage) {
    let ctx = seed_grant_ctx(s).await;
    let (code, _family) = seed_code(s, &ctx, Duration::minutes(5)).await;
    let keep = seed_grant_ctx(s).await;

    assert!(
        s.storage
            .tenants()
            .delete(ctx.tenant)
            .await
            .expect("delete must succeed"),
        "deleting an existing tenant must return true"
    );
    assert_eq!(
        s.storage.tenants().get(ctx.tenant).await.expect("get"),
        None
    );
    assert_eq!(
        s.storage
            .users()
            .get(ctx.tenant, ctx.user.id)
            .await
            .expect("get"),
        None,
        "users must be deleted with the tenant"
    );
    assert_eq!(
        s.storage
            .clients()
            .get(ctx.tenant, &ctx.client.client_id)
            .await
            .expect("get"),
        None,
        "clients must be deleted with the tenant"
    );
    assert_eq!(
        s.storage
            .sessions()
            .get_active(ctx.tenant, &ctx.session.token_hash, now_ms())
            .await
            .expect("get_active"),
        None,
        "sessions must be deleted with the tenant"
    );
    assert_eq!(
        s.storage
            .grants()
            .consume_code(ctx.tenant, &code.code_hash, now_ms())
            .await
            .expect("consume"),
        anvil_core::ports::ConsumeOutcome::NotFound,
        "codes must be deleted with the tenant"
    );
    assert!(
        !s.storage
            .tenants()
            .delete(ctx.tenant)
            .await
            .expect("delete"),
        "deleting a missing tenant must return false"
    );

    // Other tenants are untouched.
    assert!(
        s.storage
            .tenants()
            .get(keep.tenant)
            .await
            .expect("get")
            .is_some()
    );
    assert!(
        s.storage
            .users()
            .get(keep.tenant, keep.user.id)
            .await
            .expect("get")
            .is_some()
    );
}
