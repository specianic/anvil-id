//! OrgRepo contract, invitations: listing and revocation, single-use acceptance (also under
//! concurrency), the email binding checked inside the intent, closed tokens, existing members,
//! and acceptance by registering a new user in one transaction.
//!
//! The SQLite and Postgres backends refuse these methods with `StorageError::Unsupported` until
//! 06-07 / 06-08 implement them.

use std::sync::Arc;

use anvil_core::model::{InvitationAccept, NewUser, OrgInvitationId, RoleId, UserId};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn invitation_create_list_revoke(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let role = seed_role(s, tenant, &["docs:read"]).await;

    let first = new_invitation(org.id, "a@example.test", &[role.id], Duration::days(7));
    let created = repo
        .create_invitation(tenant, &first)
        .await
        .expect("create");
    assert_eq!(created, expected_invitation(tenant, &first));
    let second = anvil_core::model::NewOrgInvitation {
        created_at: first.created_at + Duration::seconds(1),
        ..new_invitation(org.id, "b@example.test", &[], Duration::days(7))
    };
    repo.create_invitation(tenant, &second)
        .await
        .expect("create");
    repo.create_invitation(
        tenant,
        &new_invitation(other_org.id, "c@example.test", &[], Duration::days(7)),
    )
    .await
    .expect("create in another org");

    let open = repo
        .list_invitations(tenant, org.id, false)
        .await
        .expect("list");
    assert_eq!(
        open.iter().map(|i| i.id).collect::<Vec<_>>(),
        vec![second.id, first.id],
        "newest first, only this org"
    );

    let later = now_ms();
    assert!(
        repo.revoke_invitation(tenant, org.id, first.id, later)
            .await
            .expect("revoke")
    );
    assert!(
        !repo
            .revoke_invitation(tenant, org.id, first.id, later)
            .await
            .expect("revoke twice"),
        "only open invitations can be revoked"
    );
    assert!(
        !repo
            .revoke_invitation(tenant, other_org.id, second.id, later)
            .await
            .expect("revoke via another org"),
        "an invitation is revoked only through its own org"
    );
    assert!(
        !repo
            .revoke_invitation(tenant, org.id, OrgInvitationId::new_v7(), later)
            .await
            .expect("revoke unknown")
    );
    assert_eq!(
        repo.list_invitations(tenant, org.id, false)
            .await
            .expect("list open")
            .iter()
            .map(|i| i.id)
            .collect::<Vec<_>>(),
        vec![second.id]
    );
    let all = repo
        .list_invitations(tenant, org.id, true)
        .await
        .expect("list all");
    assert_eq!(all.len(), 2);
    let revoked = all.iter().find(|i| i.id == first.id).expect("revoked kept");
    assert_eq!(revoked.revoked_at, Some(later));
}

pub async fn invitation_by_hash_and_unique_hash(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let inv = new_invitation(org.id, "a@example.test", &[], Duration::days(7));
    repo.create_invitation(tenant, &inv).await.expect("create");
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv))
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &unique_hash())
            .await
            .expect("by hash"),
        None
    );
    let dup = anvil_core::model::NewOrgInvitation {
        token_hash: inv.token_hash,
        ..new_invitation(org.id, "b@example.test", &[], Duration::days(7))
    };
    assert!(matches!(
        repo.create_invitation(tenant, &dup).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        repo.list_invitations(tenant, org.id, true)
            .await
            .expect("list")
            .len(),
        1,
        "a conflicting invitation stores nothing"
    );
}

pub async fn invitation_accept_adds_membership_and_roles(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["docs:read"]).await;
    let org_role = seed_org_role(s, tenant, org.id, &["org:admin"]).await;
    let user = seed_user(s, tenant).await;
    let inv = new_invitation(
        org.id,
        &user.email,
        &[tenant_role.id, org_role.id],
        Duration::days(7),
    );
    repo.create_invitation(tenant, &inv).await.expect("create");

    let now = now_ms();
    match repo
        .accept_invitation(tenant, &inv.token_hash, user.id, &user.email, now)
        .await
        .expect("accept")
    {
        InvitationAccept::Accepted(m) => {
            assert_eq!(m.org_id, org.id);
            assert_eq!(m.user_id, user.id);
            assert_eq!(m.tenant_id, tenant);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
    assert!(
        repo.is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );
    let mut held: Vec<RoleId> = s
        .storage
        .roles()
        .roles_for_user_in_org(tenant, user.id, org.id)
        .await
        .expect("roles")
        .into_iter()
        .map(|r| r.id)
        .collect();
    held.sort_by_key(|id| id.0);
    let mut want = vec![tenant_role.id, org_role.id];
    want.sort_by_key(|id| id.0);
    assert_eq!(held, want);
    let stored = repo
        .invitation_by_hash(tenant, &inv.token_hash)
        .await
        .expect("by hash")
        .expect("kept");
    assert_eq!(stored.accepted_at, Some(now));
    assert_eq!(stored.accepted_user_id, Some(user.id));
}

pub async fn invitation_accept_wrong_email_writes_nothing(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let user = seed_user(s, tenant).await;
    let inv = new_invitation(org.id, "invited@example.test", &[], Duration::days(7));
    repo.create_invitation(tenant, &inv).await.expect("create");

    assert_eq!(
        repo.accept_invitation(
            tenant,
            &inv.token_hash,
            user.id,
            "someone-else@example.test",
            now_ms()
        )
        .await
        .expect("accept"),
        InvitationAccept::EmailMismatch
    );
    assert!(
        !repo
            .is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv)),
        "the token stays open"
    );
}

pub async fn invitation_accept_concurrent_single_winner(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let org = seed_org(s, tenant).await;
    let inv = new_invitation(org.id, "race@example.test", &[], Duration::days(7));
    s.storage
        .organizations()
        .create_invitation(tenant, &inv)
        .await
        .expect("create");
    let mut users = Vec::new();
    for _ in 0..8 {
        users.push(seed_user(s, tenant).await.id);
    }
    let users = Arc::new(users);
    let storage = Arc::clone(&s.storage);
    let hash = inv.token_hash;
    let results = race(8, |i| {
        let storage = Arc::clone(&storage);
        let users = Arc::clone(&users);
        async move {
            storage
                .organizations()
                .accept_invitation(tenant, &hash, users[i], "race@example.test", now_ms())
                .await
                .expect("accept")
        }
    })
    .await;
    let winners = results
        .iter()
        .filter(|r| matches!(r, InvitationAccept::Accepted(_)))
        .count();
    assert_eq!(winners, 1, "exactly one accept wins: {results:?}");
    assert!(
        results
            .iter()
            .all(|r| matches!(r, InvitationAccept::Accepted(_) | InvitationAccept::Invalid)),
        "the losers see a closed token: {results:?}"
    );
    let members = s
        .storage
        .organizations()
        .list_members(
            tenant,
            org.id,
            anvil_core::model::PageRequest {
                after: None,
                limit: 20,
            },
        )
        .await
        .expect("members");
    assert_eq!(members.items.len(), 1);
}

pub async fn invitation_closed_tokens_are_invalid(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let user = seed_user(s, tenant).await;

    // Expired: `expires_at <= now`.
    let expired = new_invitation(org.id, &user.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &expired)
        .await
        .expect("create");
    assert_eq!(
        repo.accept_invitation(
            tenant,
            &expired.token_hash,
            user.id,
            &user.email,
            expired.expires_at
        )
        .await
        .expect("accept"),
        InvitationAccept::Invalid
    );

    // Revoked.
    let revoked = new_invitation(org.id, &user.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &revoked)
        .await
        .expect("create");
    assert!(
        repo.revoke_invitation(tenant, org.id, revoked.id, now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(
        repo.accept_invitation(tenant, &revoked.token_hash, user.id, &user.email, now_ms())
            .await
            .expect("accept"),
        InvitationAccept::Invalid
    );

    // Unknown.
    assert_eq!(
        repo.accept_invitation(tenant, &unique_hash(), user.id, &user.email, now_ms())
            .await
            .expect("accept"),
        InvitationAccept::Invalid
    );
    assert!(
        !repo
            .is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );

    // Accepted once, then closed for everyone (even after leaving the org).
    let once = new_invitation(org.id, &user.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &once).await.expect("create");
    assert!(matches!(
        repo.accept_invitation(tenant, &once.token_hash, user.id, &user.email, now_ms())
            .await
            .expect("accept"),
        InvitationAccept::Accepted(_)
    ));
    assert!(
        repo.remove_member(tenant, org.id, user.id, now_ms())
            .await
            .expect("remove")
    );
    assert_eq!(
        repo.accept_invitation(tenant, &once.token_hash, user.id, &user.email, now_ms())
            .await
            .expect("accept"),
        InvitationAccept::Invalid
    );

    // An unknown user is Invalid and the token stays open.
    let open = new_invitation(org.id, &user.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &open).await.expect("create");
    assert_eq!(
        repo.accept_invitation(
            tenant,
            &open.token_hash,
            UserId::new_v7(),
            &user.email,
            now_ms()
        )
        .await
        .expect("accept"),
        InvitationAccept::Invalid
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &open.token_hash)
            .await
            .expect("by hash")
            .expect("kept")
            .accepted_at,
        None
    );
}

pub async fn invitation_existing_member_keeps_token(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let user = seed_member(s, tenant, org.id, &[]).await;
    let inv = new_invitation(org.id, &user.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &inv).await.expect("create");
    assert_eq!(
        repo.accept_invitation(tenant, &inv.token_hash, user.id, &user.email, now_ms())
            .await
            .expect("accept"),
        InvitationAccept::AlreadyMember
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv)),
        "the token stays open"
    );
}

pub async fn invitation_accept_with_new_user_is_atomic(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let users = s.storage.users();
    let org = seed_org(s, tenant).await;
    let role = seed_role(s, tenant, &["docs:read"]).await;

    // Success: verified user, password, membership with the invitation's roles.
    let new = NewUser {
        email_verified: true,
        ..new_user()
    };
    let inv = new_invitation(org.id, &new.email, &[role.id], Duration::days(7));
    repo.create_invitation(tenant, &inv).await.expect("create");
    let password = new_password();
    match repo
        .accept_invitation_with_new_user(tenant, &inv.token_hash, &new, &password, now_ms())
        .await
        .expect("accept")
    {
        InvitationAccept::Accepted(m) => {
            assert_eq!(m.user_id, new.id);
            assert_eq!(m.org_id, org.id);
        }
        other => panic!("expected Accepted, got {other:?}"),
    }
    let stored = users
        .get(tenant, new.id)
        .await
        .expect("get")
        .expect("user created");
    assert!(stored.email_verified);
    assert_eq!(
        users
            .password(tenant, new.id)
            .await
            .expect("password")
            .expect("password stored")
            .phc,
        password.phc
    );
    assert!(
        repo.is_member(tenant, org.id, new.id)
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
    // The token is now closed.
    let again = NewUser {
        email_verified: true,
        email: new.email.clone(),
        ..new_user()
    };
    assert_eq!(
        repo.accept_invitation_with_new_user(
            tenant,
            &inv.token_hash,
            &again,
            &new_password(),
            now_ms()
        )
        .await
        .expect("accept"),
        InvitationAccept::Invalid
    );
    assert_eq!(users.get(tenant, again.id).await.expect("get"), None);

    // An existing email: Conflict, nothing written, the token stays open.
    let taken = seed_user(s, tenant).await;
    let inv2 = new_invitation(org.id, &taken.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &inv2).await.expect("create");
    let clash = NewUser {
        email_verified: true,
        email: taken.email.clone(),
        ..new_user()
    };
    assert!(matches!(
        repo.accept_invitation_with_new_user(
            tenant,
            &inv2.token_hash,
            &clash,
            &new_password(),
            now_ms()
        )
        .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(users.get(tenant, clash.id).await.expect("get"), None);
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv2.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv2))
    );

    // A different email than invited: EmailMismatch, nothing written.
    let inv3 = new_invitation(org.id, "invited3@example.test", &[], Duration::days(7));
    repo.create_invitation(tenant, &inv3).await.expect("create");
    let stranger = NewUser {
        email_verified: true,
        ..new_user()
    };
    assert_eq!(
        repo.accept_invitation_with_new_user(
            tenant,
            &inv3.token_hash,
            &stranger,
            &new_password(),
            now_ms()
        )
        .await
        .expect("accept"),
        InvitationAccept::EmailMismatch
    );
    assert_eq!(users.get(tenant, stranger.id).await.expect("get"), None);
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv3.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv3))
    );
}

pub async fn invitations_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let outsider = seed_user(s, other).await;
    let inv = new_invitation(org.id, &outsider.email, &[], Duration::days(7));
    repo.create_invitation(tenant, &inv).await.expect("create");

    assert_eq!(
        repo.invitation_by_hash(other, &inv.token_hash)
            .await
            .expect("by hash"),
        None
    );
    assert!(
        repo.list_invitations(other, org.id, true)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(
        !repo
            .revoke_invitation(other, org.id, inv.id, now_ms())
            .await
            .expect("revoke")
    );
    assert_eq!(
        repo.accept_invitation(
            other,
            &inv.token_hash,
            outsider.id,
            &outsider.email,
            now_ms()
        )
        .await
        .expect("accept"),
        InvitationAccept::Invalid
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &inv.token_hash)
            .await
            .expect("by hash"),
        Some(expected_invitation(tenant, &inv))
    );
}
