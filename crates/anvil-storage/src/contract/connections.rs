//! ConnectionRepo contract: upstream connections and identity links.

use anvil_core::model::{ConnectionId, ConnectionUpdate, IdentityLinkId, NewConnection};
use anvil_core::ports::StorageError;
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
    let user = seed_user(s, tenant).await;
    let attacker = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;
    let link = new_identity_link(user.id, c.id, "victim");
    repo.create_link(tenant, &link).await.expect("create_link");

    assert!(
        !repo
            .delete_link(tenant, attacker.id, link.id)
            .await
            .expect("delete_link"),
        "another user's link is never deleted"
    );
    assert!(
        repo.find_link(tenant, c.id, "victim")
            .await
            .expect("find")
            .is_some()
    );
    assert!(
        repo.delete_link(tenant, user.id, link.id)
            .await
            .expect("delete_link")
    );
    assert_eq!(
        repo.find_link(tenant, c.id, "victim").await.expect("find"),
        None
    );
    assert!(
        !repo
            .delete_link(tenant, user.id, link.id)
            .await
            .expect("delete_link")
    );
}

pub async fn create_user_with_link_is_atomic(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let existing = seed_user(s, tenant).await;
    let repo = s.storage.connections();
    let c = seed_connection(s, tenant).await;

    let new = new_user();
    let link = new_identity_link(new.id, c.id, "fresh");
    let user = repo
        .create_user_with_link(tenant, &new, &link)
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
        repo.create_user_with_link(tenant, &dup_email, &orphan)
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
        repo.create_user_with_link(tenant, &taken, &dup_link).await,
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
    assert!(
        !repo
            .delete_link(other, user.id, link.id)
            .await
            .expect("delete_link")
    );
    // A link in another tenant cannot point at this tenant's connection or user.
    let foreign = new_identity_link(user.id, c.id, "foreign");
    assert!(
        repo.create_link(other, &foreign).await.is_err(),
        "a link must reference a user and connection of its own tenant"
    );
    assert!(repo.get(tenant, c.id).await.expect("get").is_some());
}
