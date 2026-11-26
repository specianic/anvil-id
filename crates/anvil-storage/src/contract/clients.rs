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

// ---- Phase 4 (plan 04-01); backends implement it in 04-04 / 04-05 ----

pub async fn client_phase4_fields_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    // Defaults first: empty, false, None.
    let plain = seed_client(s, tenant).await;
    assert!(plain.post_logout_redirect_uris.is_empty());
    assert_eq!(plain.backchannel_logout_uri, None);
    assert!(!plain.backchannel_logout_session_required);
    assert!(plain.allowed_resources.is_empty());
    assert_eq!(plain.mfa_policy, None);

    let new = NewClient {
        post_logout_redirect_uris: vec![
            "https://app.example.test/bye".into(),
            "https://app.example.test/bye2".into(),
        ],
        backchannel_logout_uri: Some("https://app.example.test/bc".into()),
        backchannel_logout_session_required: true,
        allowed_resources: vec!["https://api.example.test/".into()],
        mfa_policy: Some(anvil_core::model::MfaPolicy::Required),
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
                post_logout_redirect_uris: Some(vec!["https://app.example.test/other".into()]),
                backchannel_logout_uri: Some(None),
                backchannel_logout_session_required: Some(false),
                allowed_resources: Some(vec![]),
                mfa_policy: Some(Some(anvil_core::model::MfaPolicy::Off)),
                ..ClientUpdate::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("client");
    assert_eq!(
        updated.post_logout_redirect_uris,
        vec!["https://app.example.test/other".to_owned()]
    );
    assert_eq!(updated.backchannel_logout_uri, None);
    assert!(!updated.backchannel_logout_session_required);
    assert!(updated.allowed_resources.is_empty());
    assert_eq!(updated.mfa_policy, Some(anvil_core::model::MfaPolicy::Off));

    let reset = s
        .storage
        .clients()
        .update(
            tenant,
            &new.client_id,
            &ClientUpdate {
                mfa_policy: Some(None),
                ..ClientUpdate::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("client");
    assert_eq!(reset.mfa_policy, None, "Some(None) resets to inherit");
    assert_eq!(
        reset.post_logout_redirect_uris, updated.post_logout_redirect_uris,
        "absent fields are unchanged"
    );
}

/// Phase 5 fields (client registration source and RFC 7592 token hash, CIMD expiry, consent
/// resources, audit webhook fan-out) are either persisted faithfully or refused with
/// `StorageError::Unsupported`; a backend never accepts and silently drops them.
pub async fn client_phase5_fields_never_dropped(s: &TestStorage) {
    use anvil_core::model::{
        AuditAction, AuditOutcome, ClientSource, WebhookEvent, WebhookEventType,
    };

    let tenant = seed_tenant(s).await;
    let clients = s.storage.clients();

    // Create with non-default registration fields.
    let mut new = new_client();
    new.registration_source = ClientSource::Dynamic;
    new.registration_access_token_hash = Some(unique_hash());
    new.metadata_expires_at = Some(now_ms() + Duration::hours(1));
    match clients.create(tenant, &new).await {
        Ok(created) => {
            assert_eq!(created, expected_client(tenant, &new));
            assert_eq!(
                clients.get(tenant, &new.client_id).await.expect("get"),
                Some(created)
            );
        }
        Err(StorageError::Unsupported(_)) => {
            assert_eq!(
                clients.get(tenant, &new.client_id).await.expect("get"),
                None,
                "a refused create must not store anything"
            );
        }
        Err(e) => panic!("create: unexpected error {e:?}"),
    }

    // Update with non-default registration fields.
    let existing = seed_client(s, tenant).await;
    let expires = now_ms() + Duration::hours(2);
    let hash = unique_hash();
    let update = ClientUpdate {
        metadata_expires_at: Some(Some(expires)),
        registration_access_token_hash: Some(Some(hash)),
        ..ClientUpdate::default()
    };
    match clients
        .update(tenant, &existing.client_id, &update, now_ms())
        .await
    {
        Ok(Some(updated)) => {
            assert_eq!(updated.metadata_expires_at, Some(expires));
            assert_eq!(updated.registration_access_token_hash, Some(hash));
        }
        Ok(None) => panic!("update of an existing client must return it"),
        Err(StorageError::Unsupported(_)) => {
            assert_eq!(
                clients.get(tenant, &existing.client_id).await.expect("get"),
                Some(existing.clone()),
                "a refused update must not change anything"
            );
        }
        Err(e) => panic!("update: unexpected error {e:?}"),
    }

    // Consent covering resources.
    let ctx = seed_grant_ctx(s).await;
    let mut consent = new_consent(ctx.user.id, &ctx.client.client_id, &["openid"]);
    consent.resources = vec![
        "https://b.example".to_owned(),
        "https://a.example".to_owned(),
    ];
    match s
        .storage
        .grants()
        .upsert_consent(ctx.tenant, &consent, now_ms())
        .await
    {
        Ok(grant) => assert_eq!(
            grant.resources,
            vec![
                "https://a.example".to_owned(),
                "https://b.example".to_owned()
            ],
            "resources must be stored sorted"
        ),
        Err(StorageError::Unsupported(_)) => assert_eq!(
            s.storage
                .grants()
                .consent(ctx.tenant, ctx.user.id, &ctx.client.client_id)
                .await
                .expect("consent"),
            None,
            "a refused consent must not be stored"
        ),
        Err(e) => panic!("upsert_consent: unexpected error {e:?}"),
    }

    // Audit event with a webhook fan-out.
    let mut event = new_audit_event(
        AuditAction::UserCreated,
        AuditOutcome::Success,
        "admin-1",
        "user-1",
        now_ms(),
    );
    event.webhook = Some(WebhookEvent {
        event_type: WebhookEventType::UserCreated,
        payload_json: "{}".to_owned(),
    });
    match s.storage.audit().append(tenant, &event).await {
        Ok(()) | Err(StorageError::Unsupported(_)) => {}
        Err(e) => panic!("audit append: unexpected error {e:?}"),
    }
}

pub async fn client_upsert_cimd_inserts_then_replaces(s: &TestStorage) {
    use anvil_core::model::ClientSource;

    let tenant = seed_tenant(s).await;
    let clients = s.storage.clients();
    let t1 = now_ms();
    let expires1 = t1 + Duration::hours(1);
    // Whatever the input says, the stored row is a CIMD client with the given expiry.
    let mut new = new_cimd_client();
    new.registration_source = ClientSource::Static;
    new.metadata_expires_at = None;
    let inserted = clients
        .upsert_cimd(tenant, &new, expires1, t1)
        .await
        .expect("upsert_cimd");
    let mut expected = expected_client(tenant, &new);
    expected.registration_source = ClientSource::Cimd;
    expected.metadata_expires_at = Some(expires1);
    expected.created_at = t1;
    expected.updated_at = t1;
    assert_eq!(inserted, expected);
    assert_eq!(
        clients.get(tenant, &new.client_id).await.expect("get"),
        Some(inserted.clone())
    );

    // A refreshed document replaces the metadata and keeps the row identity.
    let t2 = t1 + Duration::minutes(10);
    let expires2 = t2 + Duration::hours(2);
    let mut refreshed = new_cimd_client();
    refreshed.client_id = new.client_id.clone();
    refreshed.name = "Renamed MCP client".to_owned();
    refreshed.redirect_uris = vec!["http://127.0.0.1:33418/callback".to_owned()];
    refreshed.scopes = vec!["openid".to_owned()];
    let replaced = clients
        .upsert_cimd(tenant, &refreshed, expires2, t2)
        .await
        .expect("upsert_cimd");
    assert_eq!(replaced.id, inserted.id, "the row id is kept");
    assert_eq!(replaced.created_at, inserted.created_at);
    assert_eq!(replaced.updated_at, t2);
    assert_eq!(replaced.name, refreshed.name);
    assert_eq!(replaced.redirect_uris, refreshed.redirect_uris);
    assert_eq!(replaced.scopes, refreshed.scopes);
    assert_eq!(replaced.registration_source, ClientSource::Cimd);
    assert_eq!(replaced.metadata_expires_at, Some(expires2));
    assert_eq!(
        clients.get(tenant, &new.client_id).await.expect("get"),
        Some(replaced)
    );
    let other = seed_tenant(s).await;
    assert_eq!(
        clients.get(other, &new.client_id).await.expect("get"),
        None,
        "CIMD clients are per tenant"
    );
}

pub async fn client_upsert_cimd_never_overwrites_registered_clients(s: &TestStorage) {
    use anvil_core::model::ClientSource;

    let tenant = seed_tenant(s).await;
    let clients = s.storage.clients();
    let now = now_ms();
    let mut static_client = new_client();
    static_client.client_id = format!("https://static-{}.example.test/c", static_client.id.0);
    let existing = clients
        .create(tenant, &static_client)
        .await
        .expect("create static client");
    let mut doc = new_cimd_client();
    doc.client_id = static_client.client_id.clone();
    let refused = clients
        .upsert_cimd(tenant, &doc, now + Duration::hours(1), now)
        .await;
    assert!(
        matches!(refused, Err(StorageError::Conflict(_))),
        "a metadata document must not replace a static client: {refused:?}"
    );
    assert_eq!(
        clients
            .get(tenant, &static_client.client_id)
            .await
            .expect("get"),
        Some(existing)
    );

    let mut dynamic = new_client();
    dynamic.registration_source = ClientSource::Dynamic;
    dynamic.registration_access_token_hash = Some(unique_hash());
    let registered = clients
        .create(tenant, &dynamic)
        .await
        .expect("create dynamic client");
    let mut doc = new_cimd_client();
    doc.client_id = dynamic.client_id.clone();
    let refused = clients
        .upsert_cimd(tenant, &doc, now + Duration::hours(1), now)
        .await;
    assert!(
        matches!(refused, Err(StorageError::Conflict(_))),
        "a metadata document must not replace a dynamic client: {refused:?}"
    );
    assert_eq!(
        clients.get(tenant, &dynamic.client_id).await.expect("get"),
        Some(registered)
    );
}

pub async fn client_registration_token_lookup_and_rotation(s: &TestStorage) {
    use anvil_core::model::ClientSource;

    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let clients = s.storage.clients();
    let token = unique_hash();
    let mut dynamic = new_client();
    dynamic.registration_source = ClientSource::Dynamic;
    dynamic.registration_access_token_hash = Some(token);
    let created = clients
        .create(tenant, &dynamic)
        .await
        .expect("create dynamic client");
    assert_eq!(
        clients
            .get_by_registration_token(tenant, &dynamic.client_id, &token)
            .await
            .expect("lookup"),
        Some(created.clone())
    );
    assert_eq!(
        clients
            .get_by_registration_token(tenant, &dynamic.client_id, &unique_hash())
            .await
            .expect("lookup"),
        None,
        "wrong token"
    );
    assert_eq!(
        clients
            .get_by_registration_token(other, &dynamic.client_id, &token)
            .await
            .expect("lookup"),
        None,
        "other tenant"
    );
    assert_eq!(
        clients
            .get_by_registration_token(tenant, "no-such-client", &token)
            .await
            .expect("lookup"),
        None
    );

    // Rotation: the old token stops working, the new one works.
    let rotated = unique_hash();
    let later = now_ms() + Duration::seconds(5);
    assert!(
        clients
            .set_registration_token(tenant, &dynamic.client_id, Some(&rotated), later)
            .await
            .expect("set")
    );
    assert_eq!(
        clients
            .get_by_registration_token(tenant, &dynamic.client_id, &token)
            .await
            .expect("lookup"),
        None
    );
    let found = clients
        .get_by_registration_token(tenant, &dynamic.client_id, &rotated)
        .await
        .expect("lookup")
        .expect("rotated token works");
    assert_eq!(found.registration_access_token_hash, Some(rotated));
    assert_eq!(found.updated_at, later);

    // Clearing: no token matches any more.
    assert!(
        clients
            .set_registration_token(tenant, &dynamic.client_id, None, later)
            .await
            .expect("set")
    );
    assert_eq!(
        clients
            .get_by_registration_token(tenant, &dynamic.client_id, &rotated)
            .await
            .expect("lookup"),
        None
    );
    assert!(
        !clients
            .set_registration_token(tenant, "no-such-client", Some(&rotated), later)
            .await
            .expect("set")
    );
    assert!(
        !clients
            .set_registration_token(other, &dynamic.client_id, Some(&rotated), later)
            .await
            .expect("set"),
        "another tenant's client behaves like a missing one"
    );

    // A static client never matches, even with a stored hash.
    let static_client = seed_client(s, tenant).await;
    let hash = unique_hash();
    assert!(
        clients
            .set_registration_token(tenant, &static_client.client_id, Some(&hash), later)
            .await
            .expect("set")
    );
    assert_eq!(
        clients
            .get_by_registration_token(tenant, &static_client.client_id, &hash)
            .await
            .expect("lookup"),
        None,
        "only dynamic clients have a configuration endpoint"
    );
}

// ---- Phase 6 (plan 06-04): client organization policy; the backends refuse values other than
// `off` with StorageError::Unsupported until 06-07 / 06-08 ----

pub async fn client_organization_policy_round_trip(s: &TestStorage) {
    use anvil_core::model::OrgClientPolicy;

    let tenant = seed_tenant(s).await;
    let clients = s.storage.clients();
    let mut new = new_client();
    new.organization = OrgClientPolicy::Required;
    let created = clients.create(tenant, &new).await.expect("create");
    assert_eq!(created, expected_client(tenant, &new));
    assert_eq!(created.organization, OrgClientPolicy::Required);
    let updated = clients
        .update(
            tenant,
            &new.client_id,
            &ClientUpdate {
                organization: Some(OrgClientPolicy::Optional),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("exists");
    assert_eq!(updated.organization, OrgClientPolicy::Optional);
    assert_eq!(
        clients
            .get(tenant, &new.client_id)
            .await
            .expect("get")
            .expect("exists")
            .organization,
        OrgClientPolicy::Optional
    );
}
