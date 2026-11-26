//! ConnectionRepo contract: upstream connections and identity links.

use std::sync::Arc;

use anvil_core::model::{
    ConnectionId, ConnectionUpdate, IdentityLinkId, NewConnection, NewIdentityLink, NewUser,
    SelfServiceKind, TenantId, User, UserId,
};
use anvil_core::ports::{DeleteLinkOutcome, StorageError};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn connection_create_get_list_update(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.connections();
    let oidc = new_connection();
    let social = new_social_connection();
    assert_eq!(
        repo.create(tenant, &oidc).await.expect("create"),
        expected_connection(tenant, &oidc),
        "create must return every field"
    );
    assert_eq!(
        repo.create(tenant, &social).await.expect("create"),
        expected_connection(tenant, &social)
    );
    assert_eq!(
        repo.get(tenant, oidc.id).await.expect("get"),
        Some(expected_connection(tenant, &oidc))
    );
    assert_eq!(
        repo.get_by_slug(tenant, &social.slug)
            .await
            .expect("get_by_slug"),
        Some(expected_connection(tenant, &social))
    );
    assert_eq!(
        repo.get_by_slug(tenant, "missing").await.expect("get"),
        None
    );
    assert_eq!(
        repo.get(tenant, ConnectionId::new_v7()).await.expect("get"),
        None
    );

    let listed = repo.list(tenant).await.expect("list");
    let mut slugs = vec![oidc.slug.clone(), social.slug.clone()];
    slugs.sort();
    assert_eq!(
        listed.iter().map(|c| c.slug.clone()).collect::<Vec<_>>(),
        slugs,
        "list is in slug order"
    );

    let later = now_ms() + Duration::seconds(5);
    let updated = repo
        .update(
            tenant,
            oidc.id,
            &ConnectionUpdate {
                display_name: Some("Renamed".into()),
                enabled: Some(false),
                config: Some(social.config.clone()),
                trust_email_verified: Some(true),
            },
            later,
        )
        .await
        .expect("update")
        .expect("connection");
    assert_eq!(updated.display_name, "Renamed");
    assert!(!updated.enabled);
    assert_eq!(updated.config, social.config);
    assert!(updated.trust_email_verified);
    assert_eq!(updated.updated_at, later);
    assert_eq!(updated.created_at, oidc.created_at);
    assert_eq!(
        updated.secret_enc, oidc.secret_enc,
        "update keeps the secret"
    );
    assert_eq!(
        repo.get(tenant, oidc.id).await.expect("get"),
        Some(updated.clone())
    );

    let untouched = repo
        .update(tenant, oidc.id, &ConnectionUpdate::default(), later)
        .await
        .expect("update")
        .expect("connection");
    assert_eq!(
        untouched.display_name, "Renamed",
        "None leaves fields alone"
    );
    assert_eq!(
        repo.update(
            tenant,
            ConnectionId::new_v7(),
            &ConnectionUpdate::default(),
            later
        )
        .await
        .expect("update"),
        None
    );
}

pub async fn connection_slug_conflict_per_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.connections();
    let first = seed_connection(s, tenant).await;
    let dup = NewConnection {
        slug: first.slug.clone(),
        ..new_connection()
    };
    assert!(
        matches!(
            repo.create(tenant, &dup).await,
            Err(StorageError::Conflict(_))
        ),
        "a duplicate slug in one tenant must conflict"
    );
    assert_eq!(repo.get(tenant, dup.id).await.expect("get"), None);
    repo.create(other, &dup)
        .await
        .expect("the same slug in another tenant is fine");
}

pub async fn connection_set_secret_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let sealed = vec![0x5A_u8; 77];
    let later = now_ms() + Duration::seconds(3);
    assert!(
        repo.set_secret(tenant, c.id, Some(&sealed), later)
            .await
            .expect("set_secret")
    );
    let got = repo.get(tenant, c.id).await.expect("get").expect("conn");
    assert_eq!(got.secret_enc.as_deref(), Some(sealed.as_slice()));
    assert_eq!(got.updated_at, later);
    assert!(
        repo.set_secret(tenant, c.id, None, later)
            .await
            .expect("set_secret")
    );
    assert_eq!(
        repo.get(tenant, c.id)
            .await
            .expect("get")
            .expect("conn")
            .secret_enc,
        None
    );
    assert!(
        !repo
            .set_secret(other, c.id, Some(&sealed), later)
            .await
            .expect("set_secret"),
        "another tenant's connection is missing"
    );
    assert!(
        !repo
            .set_secret(tenant, ConnectionId::new_v7(), None, later)
            .await
            .expect("set_secret")
    );
}

pub async fn connection_delete_cascades_links(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let keep = seed_connection(s, tenant).await;
    let link = new_identity_link(user.id, c.id, "sub-1");
    let kept = new_identity_link(user.id, keep.id, "sub-1");
    repo.create_link(tenant, &link).await.expect("create_link");
    repo.create_link(tenant, &kept).await.expect("create_link");

    assert!(repo.delete(tenant, c.id).await.expect("delete"));
    assert_eq!(repo.get(tenant, c.id).await.expect("get"), None);
    assert_eq!(
        repo.find_link(tenant, c.id, "sub-1").await.expect("find"),
        None,
        "deleting a connection deletes its links"
    );
    assert_eq!(
        repo.links_for_user(tenant, user.id).await.expect("links"),
        vec![expected_link(tenant, &kept)]
    );
    assert!(
        !repo.delete(tenant, c.id).await.expect("delete"),
        "second delete"
    );
}

pub async fn identity_link_create_find_and_conflict(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let other_user = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let c2 = seed_connection(s, tenant).await;

    let link = new_identity_link(user.id, c.id, "upstream-42");
    assert_eq!(
        repo.create_link(tenant, &link).await.expect("create_link"),
        expected_link(tenant, &link)
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "upstream-42")
            .await
            .expect("find"),
        Some(expected_link(tenant, &link))
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "upstream-4")
            .await
            .expect("find"),
        None,
        "subjects match exactly"
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "UPSTREAM-42")
            .await
            .expect("find"),
        None,
        "subjects are case-sensitive"
    );
    assert_eq!(
        repo.find_link(tenant, c2.id, "upstream-42")
            .await
            .expect("find"),
        None,
        "links are per connection"
    );

    for dup_user in [user.id, other_user.id] {
        let dup = new_identity_link(dup_user, c.id, "upstream-42");
        assert!(
            matches!(
                repo.create_link(tenant, &dup).await,
                Err(StorageError::Conflict(_))
            ),
            "(connection, subject) is linked at most once"
        );
    }
    // The same subject at another connection is a different identity.
    let at_c2 = new_identity_link(other_user.id, c2.id, "upstream-42");
    repo.create_link(tenant, &at_c2).await.expect("create_link");

    let second = new_identity_link(user.id, c2.id, "upstream-43");
    repo.create_link(tenant, &second)
        .await
        .expect("create_link");
    let links = repo.links_for_user(tenant, user.id).await.expect("links");
    assert_eq!(
        links,
        vec![expected_link(tenant, &link), expected_link(tenant, &second)],
        "links_for_user returns only the user's links, oldest first"
    );

    let used = now_ms() + Duration::seconds(9);
    assert!(repo.touch_link(tenant, link.id, used).await.expect("touch"));
    assert_eq!(
        repo.find_link(tenant, c.id, "upstream-42")
            .await
            .expect("find")
            .expect("link")
            .last_used_at,
        Some(used)
    );
    assert!(
        !repo
            .touch_link(tenant, IdentityLinkId::new_v7(), used)
            .await
            .expect("touch")
    );
}

pub async fn identity_link_delete_only_own(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    // seed_user has a password, so the link is not the last sign-in method.
    let user = seed_user(s, tenant).await;
    let attacker = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let link = new_identity_link(user.id, c.id, "victim");
    repo.create_link(tenant, &link).await.expect("create_link");

    assert_eq!(
        repo.delete_link(tenant, attacker.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::NotFound,
        "another user's link is never deleted"
    );
    assert!(
        repo.find_link(tenant, c.id, "victim")
            .await
            .expect("find")
            .is_some()
    );
    assert_eq!(
        repo.delete_link(tenant, user.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::Deleted
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "victim").await.expect("find"),
        None
    );
    assert_eq!(
        repo.delete_link(tenant, user.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::NotFound
    );
}

/// Creates a user without any credential (`verified` sets `email_verified`).
async fn seed_bare_user(s: &TestStorage, tenant: TenantId, verified: bool) -> User {
    let user = NewUser {
        email_verified: verified,
        ..new_user()
    };
    s.storage
        .users()
        .create(tenant, &user, None, None, None)
        .await
        .expect("create user")
}

/// Links `user` to a fresh connection and returns the link.
async fn seed_link(s: &TestStorage, tenant: TenantId, user: UserId) -> NewIdentityLink {
    let c = seed_connection(s, tenant).await;
    let link = new_identity_link(user, c.id, "subject");
    s.storage
        .connections()
        .create_link(tenant, &link)
        .await
        .expect("create_link");
    link
}

async fn link_exists(s: &TestStorage, tenant: TenantId, user: UserId, id: IdentityLinkId) -> bool {
    s.storage
        .connections()
        .links_for_user(tenant, user)
        .await
        .expect("links")
        .iter()
        .any(|l| l.id == id)
}

pub async fn delete_link_keeps_a_sign_in_method(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other_tenant = seed_tenant(s).await;
    let repo = s.storage.connections();
    let users = s.storage.users();

    // The only method is one link: refused with or without email sign-in while unverified.
    let only = seed_bare_user(s, tenant, false).await;
    let link = seed_link(s, tenant, only.id).await;
    for email_sign_in in [false, true] {
        assert_eq!(
            repo.delete_link(tenant, only.id, link.id, email_sign_in)
                .await
                .expect("delete_link"),
            DeleteLinkOutcome::LastSignInMethod,
            "an unverified email never counts (email_sign_in = {email_sign_in})"
        );
        assert!(link_exists(s, tenant, only.id, link.id).await);
    }
    // TOTP is a second factor, not a sign-in method.
    users
        .create_totp(tenant, only.id, &new_totp(), &recovery_codes(2), now_ms())
        .await
        .expect("create_totp");
    assert_eq!(
        repo.delete_link(tenant, only.id, link.id, true)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::LastSignInMethod,
        "TOTP is not a sign-in method"
    );

    // Verified email: allowed only when the tenant offers email sign-in.
    let verified = seed_bare_user(s, tenant, true).await;
    let link = seed_link(s, tenant, verified.id).await;
    assert_eq!(
        repo.delete_link(tenant, verified.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::LastSignInMethod
    );
    assert_eq!(
        repo.delete_link(tenant, verified.id, link.id, true)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::Deleted,
        "a verified email with tenant email sign-in is a remaining method"
    );
    assert!(!link_exists(s, tenant, verified.id, link.id).await);

    // A password.
    let with_password = seed_user(s, tenant).await;
    let link = seed_link(s, tenant, with_password.id).await;
    assert_eq!(
        repo.delete_link(tenant, with_password.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::Deleted
    );

    // A passkey.
    let with_passkey = seed_bare_user(s, tenant, false).await;
    users
        .create_passkey(tenant, with_passkey.id, &new_passkey())
        .await
        .expect("create_passkey");
    let link = seed_link(s, tenant, with_passkey.id).await;
    assert_eq!(
        repo.delete_link(tenant, with_passkey.id, link.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::Deleted
    );

    // A second link: the first goes, then the second is the last method.
    let two = seed_bare_user(s, tenant, false).await;
    let first = seed_link(s, tenant, two.id).await;
    let second = seed_link(s, tenant, two.id).await;
    assert_eq!(
        repo.delete_link(tenant, two.id, first.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::Deleted
    );
    assert_eq!(
        repo.delete_link(tenant, two.id, second.id, false)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::LastSignInMethod
    );
    assert!(link_exists(s, tenant, two.id, second.id).await);

    // Another user's link, an unknown id, another tenant: NotFound, nothing deleted.
    let victim = seed_user(s, tenant).await;
    let victim_link = seed_link(s, tenant, victim.id).await;
    for (t, u, id) in [
        (tenant, with_password.id, victim_link.id),
        (tenant, victim.id, IdentityLinkId::new_v7()),
        (other_tenant, victim.id, victim_link.id),
        (tenant, UserId::new_v7(), victim_link.id),
    ] {
        assert_eq!(
            repo.delete_link(t, u, id, true).await.expect("delete_link"),
            DeleteLinkOutcome::NotFound
        );
    }
    assert!(link_exists(s, tenant, victim.id, victim_link.id).await);
}

pub async fn delete_link_concurrent_never_removes_the_last_method(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    for round in 0..10 {
        let user = seed_bare_user(s, tenant, false).await;
        let a = seed_link(s, tenant, user.id).await;
        let b = seed_link(s, tenant, user.id).await;
        let ids = [a.id, b.id];
        let storage = Arc::clone(&s.storage);
        let outcomes = race(2, move |i| {
            let storage = Arc::clone(&storage);
            let id = ids[i];
            async move {
                storage
                    .connections()
                    .delete_link(tenant, user.id, id, true)
                    .await
            }
        })
        .await;
        let outcomes: Vec<DeleteLinkOutcome> = outcomes
            .into_iter()
            .map(|r| r.expect("no storage error under contention"))
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == DeleteLinkOutcome::Deleted)
                .count(),
            1,
            "round {round}: exactly one unlink wins ({outcomes:?})"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == DeleteLinkOutcome::LastSignInMethod)
                .count(),
            1,
            "round {round}: the other is refused ({outcomes:?})"
        );
        assert_eq!(
            s.storage
                .connections()
                .links_for_user(tenant, user.id)
                .await
                .expect("links")
                .len(),
            1,
            "round {round}: exactly one link is left"
        );
    }
}

pub async fn create_user_with_link_is_atomic(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let existing = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;

    let new = new_user();
    let link = new_identity_link(new.id, c.id, "fresh");
    let user = repo
        .create_user_with_link(tenant, &new, &link, None, None, None)
        .await
        .expect("create_user_with_link");
    assert_eq!(user, expected_user(tenant, &new));
    assert_eq!(
        repo.find_link(tenant, c.id, "fresh").await.expect("find"),
        Some(expected_link(tenant, &link))
    );
    assert_eq!(
        s.storage
            .users()
            .password(tenant, new.id)
            .await
            .expect("password"),
        None,
        "upstream sign-up creates no password"
    );

    // Email conflict: no user, no link.
    let dup_email = anvil_core::model::NewUser {
        email: existing.email.clone(),
        username: None,
        ..new_user()
    };
    let orphan = new_identity_link(dup_email.id, c.id, "orphan");
    assert!(matches!(
        repo.create_user_with_link(tenant, &dup_email, &orphan, None, None, None)
            .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        s.storage
            .users()
            .get(tenant, dup_email.id)
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "orphan").await.expect("find"),
        None,
        "an email conflict stores no link"
    );

    // Link conflict: no user.
    let taken = new_user();
    let dup_link = new_identity_link(taken.id, c.id, "fresh");
    assert!(matches!(
        repo.create_user_with_link(tenant, &taken, &dup_link, None, None, None)
            .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        s.storage.users().get(tenant, taken.id).await.expect("get"),
        None,
        "a link conflict stores no user"
    );
    assert_eq!(
        s.storage
            .users()
            .get_by_email(tenant, &taken.email)
            .await
            .expect("get_by_email"),
        None
    );
}

pub async fn create_user_with_link_stores_verification_atomically(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let existing = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let users = s.storage.users();
    let c = seed_connection(s, tenant).await;

    let new = new_user();
    let link = new_identity_link(new.id, c.id, "unverified");
    let token = new_self_service_token(
        SelfServiceKind::Verification,
        new.id,
        &new.email,
        Duration::hours(1),
    );
    let email = new_email(&new.email);
    repo.create_user_with_link(tenant, &new, &link, Some(&token), Some(&email), None)
        .await
        .expect("create_user_with_link");
    let now = now_ms();
    let verified = users
        .complete_verification(tenant, &token.token_hash, now)
        .await
        .expect("complete_verification")
        .expect("the token was stored with the user");
    assert!(verified.email_verified);
    let claimed = s
        .storage
        .outbox()
        .claim_due(now, 100, LEASE)
        .await
        .expect("claim_due");
    assert_eq!(
        claimed.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![email.id],
        "the email is in the outbox"
    );

    // Email conflict: no user, link, token or email.
    let dup = NewUser {
        email: existing.email.clone(),
        username: None,
        ..new_user()
    };
    let orphan = new_identity_link(dup.id, c.id, "orphan");
    let orphan_token = new_self_service_token(
        SelfServiceKind::Verification,
        dup.id,
        &dup.email,
        Duration::hours(1),
    );
    let orphan_email = new_email(&dup.email);
    assert!(matches!(
        repo.create_user_with_link(
            tenant,
            &dup,
            &orphan,
            Some(&orphan_token),
            Some(&orphan_email),
            None
        )
        .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(users.get(tenant, dup.id).await.expect("get"), None);
    assert_eq!(
        repo.find_link(tenant, c.id, "orphan").await.expect("find"),
        None
    );
    assert_eq!(
        users
            .complete_verification(tenant, &orphan_token.token_hash, now_ms())
            .await
            .expect("complete_verification"),
        None,
        "a conflict stores no token"
    );
    let later = now_ms() + LEASE + Duration::seconds(1);
    assert!(
        s.storage
            .outbox()
            .claim_due(later, 100, LEASE)
            .await
            .expect("claim_due")
            .iter()
            .all(|e| e.id != orphan_email.id),
        "a conflict stores no email"
    );
}

pub async fn connections_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let link = new_identity_link(user.id, c.id, "iso");
    repo.create_link(tenant, &link).await.expect("create_link");

    assert_eq!(repo.get(other, c.id).await.expect("get"), None);
    assert_eq!(
        repo.get_by_slug(other, &c.slug).await.expect("get_by_slug"),
        None
    );
    assert!(repo.list(other).await.expect("list").is_empty());
    assert_eq!(
        repo.update(other, c.id, &ConnectionUpdate::default(), now_ms())
            .await
            .expect("update"),
        None
    );
    assert!(!repo.delete(other, c.id).await.expect("delete"));
    assert_eq!(
        repo.find_link(other, c.id, "iso").await.expect("find"),
        None
    );
    assert!(
        repo.links_for_user(other, user.id)
            .await
            .expect("links")
            .is_empty()
    );
    assert!(
        !repo
            .touch_link(other, link.id, now_ms())
            .await
            .expect("touch")
    );
    assert_eq!(
        repo.delete_link(other, user.id, link.id, true)
            .await
            .expect("delete_link"),
        DeleteLinkOutcome::NotFound
    );
    // A link in another tenant cannot point at this tenant's connection or user.
    let foreign = new_identity_link(user.id, c.id, "foreign");
    assert!(
        repo.create_link(other, &foreign).await.is_err(),
        "a link must reference a user and connection of its own tenant"
    );
    assert!(repo.get(tenant, c.id).await.expect("get").is_some());
}

// ---- Phase 6 (plan 06-04): organization connections, SAML configs, has_links and JIT
// membership; the backends refuse them with StorageError::Unsupported until 06-07 / 06-08 ----

pub async fn connection_org_and_saml_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.connections();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let tenant_conn = seed_connection(s, tenant).await;

    let oidc = new_org_connection(org.id);
    let created = repo.create(tenant, &oidc).await.expect("org oidc");
    assert_eq!(created, expected_connection(tenant, &oidc));
    assert_eq!(created.org_id, Some(org.id));
    let saml = new_saml_connection(org.id);
    let created_saml = repo.create(tenant, &saml).await.expect("org saml");
    assert_eq!(created_saml, expected_connection(tenant, &saml));
    assert_eq!(created_saml.kind().as_str(), "saml");
    assert_eq!(
        repo.get(tenant, saml.id).await.expect("get"),
        Some(created_saml.clone())
    );
    assert_eq!(
        repo.get_by_slug(tenant, &saml.slug).await.expect("by slug"),
        Some(created_saml.clone())
    );
    let other = seed_org_connection(s, tenant, other_org.id).await;

    // `list` returns tenant and org connections; `list_for_org` only that org's.
    let all: Vec<ConnectionId> = repo
        .list(tenant)
        .await
        .expect("list")
        .into_iter()
        .map(|c| c.id)
        .collect();
    for id in [tenant_conn.id, oidc.id, saml.id, other.id] {
        assert!(all.contains(&id), "list includes every connection");
    }
    let mut want = vec![created.clone(), created_saml.clone()];
    want.sort_by(|a, b| a.slug.cmp(&b.slug));
    assert_eq!(
        repo.list_for_org(tenant, org.id).await.expect("for org"),
        want,
        "slug order, this org only"
    );
    assert!(
        repo.list_for_org(seed_tenant(s).await, org.id)
            .await
            .expect("for org from another tenant")
            .is_empty()
    );

    // A SAML config update round-trips too.
    let mut changed = match created_saml.config.clone() {
        anvil_core::model::ConnectionConfig::Saml(c) => c,
        other => panic!("expected saml, got {other:?}"),
    };
    changed.signing_certs.push(changed.signing_certs[0].clone());
    let updated = repo
        .update(
            tenant,
            saml.id,
            &ConnectionUpdate {
                config: Some(anvil_core::model::ConnectionConfig::Saml(changed.clone())),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("update")
        .expect("exists");
    assert_eq!(
        updated.config,
        anvil_core::model::ConnectionConfig::Saml(changed)
    );
    assert_eq!(updated.org_id, Some(org.id), "updates keep the org");
}

pub async fn connection_has_links(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.connections();
    let org = seed_org(s, tenant).await;
    let conn = seed_org_connection(s, tenant, org.id).await;
    let user = seed_user(s, tenant).await;
    assert!(!repo.has_links(tenant, conn.id).await.expect("has_links"));
    let link = new_identity_link(user.id, conn.id, "sub-has-links");
    repo.create_link(tenant, &link).await.expect("link");
    assert!(repo.has_links(tenant, conn.id).await.expect("has_links"));
    assert!(
        !repo
            .has_links(seed_tenant(s).await, conn.id)
            .await
            .expect("has_links from another tenant")
    );
    assert!(
        !repo
            .has_links(tenant, ConnectionId::new_v7())
            .await
            .expect("has_links unknown")
    );
    // Keep a password so the link is not the user's last sign-in method.
    assert_eq!(
        repo.delete_link(tenant, user.id, link.id, false)
            .await
            .expect("delete link"),
        DeleteLinkOutcome::Deleted
    );
    assert!(!repo.has_links(tenant, conn.id).await.expect("has_links"));
}

pub async fn create_user_with_link_with_membership(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.connections();
    let orgs = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let role = seed_org_role(s, tenant, org.id, &["docs:read"]).await;
    let conn = seed_org_connection(s, tenant, org.id).await;

    // With a membership: user, link, membership and its role assignment in one transaction.
    let new = new_user();
    let link = new_identity_link(new.id, conn.id, "jit-member");
    let membership = new_membership(org.id, new.id, &[role.id]);
    repo.create_user_with_link(tenant, &new, &link, None, None, Some(&membership))
        .await
        .expect("create with membership");
    assert!(
        orgs.is_member(tenant, org.id, new.id)
            .await
            .expect("is_member")
    );
    assert_eq!(
        s.storage
            .roles()
            .roles_for_user_in_org(tenant, new.id, org.id)
            .await
            .expect("roles")
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        vec![role.id]
    );

    // Without one: no membership.
    let plain = new_user();
    let plain_link = new_identity_link(plain.id, conn.id, "jit-plain");
    repo.create_user_with_link(tenant, &plain, &plain_link, None, None, None)
        .await
        .expect("create without membership");
    assert!(
        !orgs
            .is_member(tenant, org.id, plain.id)
            .await
            .expect("is_member")
    );

    // A membership that cannot be stored (role of another org) rolls everything back.
    let other_org = seed_org(s, tenant).await;
    let foreign_role = seed_org_role(s, tenant, other_org.id, &[]).await;
    let doomed = new_user();
    let doomed_link = new_identity_link(doomed.id, conn.id, "jit-doomed");
    let bad = new_membership(org.id, doomed.id, &[foreign_role.id]);
    assert!(
        repo.create_user_with_link(tenant, &doomed, &doomed_link, None, None, Some(&bad))
            .await
            .is_err()
    );
    assert_eq!(
        s.storage.users().get(tenant, doomed.id).await.expect("get"),
        None
    );
    assert_eq!(
        repo.find_link(tenant, conn.id, "jit-doomed")
            .await
            .expect("find"),
        None
    );
}
