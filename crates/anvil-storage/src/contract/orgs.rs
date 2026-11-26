//! OrgRepo contract, organizations and members: per-tenant unique slugs, isolation, idempotent
//! membership with in-org role assignments, membership removal revoking only that org's token
//! families, and org deletion cascading to everything the org owns.
//!
//! The SQLite and Postgres backends refuse these methods with `StorageError::Unsupported` until
//! 06-07 / 06-08 implement them.

use anvil_core::model::{OrgId, OrganizationUpdate, PageRequest, RevokeReason, RoleId, UserId};
use anvil_core::ports::AddMemberOutcome;
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn page(after: Option<uuid::Uuid>, limit: u32) -> PageRequest {
    PageRequest { after, limit }
}

pub async fn org_create_get_update_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let new = new_org();
    let created = repo.create(tenant, &new).await.expect("create");
    assert_eq!(created, expected_org(tenant, &new));
    assert_eq!(
        repo.get(tenant, new.id).await.expect("get"),
        Some(created.clone())
    );
    assert_eq!(
        repo.get_by_slug(tenant, &new.slug).await.expect("by slug"),
        Some(created.clone())
    );
    assert_eq!(
        repo.get_by_slug(tenant, "no-such-org")
            .await
            .expect("by slug"),
        None
    );

    let later = new.created_at + Duration::seconds(5);
    let updated = repo
        .update(
            tenant,
            new.id,
            &OrganizationUpdate {
                slug: Some(format!("{}-x", new.slug)),
                display_name: Some("Renamed".to_owned()),
                mfa_policy: Some(None),
                settings: Some(anvil_core::model::OrgSettings {
                    default_role_ids: vec![RoleId::new_v7()],
                }),
                metadata: Some(serde_json::json!({"plan": "free"})),
            },
            later,
        )
        .await
        .expect("update")
        .expect("org exists");
    assert_eq!(updated.slug, format!("{}-x", new.slug));
    assert_eq!(updated.display_name, "Renamed");
    assert_eq!(updated.mfa_policy, None);
    assert_eq!(updated.settings.default_role_ids.len(), 1);
    assert_eq!(updated.metadata, serde_json::json!({"plan": "free"}));
    assert_eq!(updated.created_at, new.created_at);
    assert_eq!(updated.updated_at, later);
    assert_eq!(
        repo.get(tenant, new.id).await.expect("get"),
        Some(updated.clone())
    );
    // An empty update keeps every field.
    let same = repo
        .update(tenant, new.id, &OrganizationUpdate::default(), later)
        .await
        .expect("update")
        .expect("org exists");
    assert_eq!(same, updated);
    assert_eq!(
        repo.update(
            tenant,
            OrgId::new_v7(),
            &OrganizationUpdate::default(),
            later
        )
        .await
        .expect("update"),
        None
    );

    assert!(repo.delete(tenant, new.id, later).await.expect("delete"));
    assert!(!repo.delete(tenant, new.id, later).await.expect("delete"));
    assert_eq!(repo.get(tenant, new.id).await.expect("get"), None);
}

pub async fn org_slug_conflict_per_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let first = new_org();
    repo.create(tenant, &first).await.expect("create");

    let dup = anvil_core::model::NewOrganization {
        slug: first.slug.clone(),
        ..new_org()
    };
    assert!(matches!(
        repo.create(tenant, &dup).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(repo.get(tenant, dup.id).await.expect("get"), None);
    // The same slug in another tenant is fine.
    repo.create(other, &dup).await.expect("other tenant");

    // Renaming onto a taken slug conflicts and changes nothing.
    let second = repo.create(tenant, &new_org()).await.expect("create");
    assert!(matches!(
        repo.update(
            tenant,
            second.id,
            &OrganizationUpdate {
                slug: Some(first.slug.clone()),
                ..Default::default()
            },
            now_ms(),
        )
        .await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(
        repo.get(tenant, second.id).await.expect("get"),
        Some(second)
    );
}

pub async fn org_list_pagination(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(seed_org(s, tenant).await.id);
    }
    ids.sort_by_key(|id| id.0);
    let first = repo.list(tenant, page(None, 2)).await.expect("list");
    assert_eq!(
        first.items.iter().map(|o| o.id).collect::<Vec<_>>(),
        ids[..2].to_vec()
    );
    let cursor = first.next_cursor.expect("more pages");
    let second = repo
        .list(tenant, page(Some(cursor), 10))
        .await
        .expect("list");
    assert_eq!(
        second.items.iter().map(|o| o.id).collect::<Vec<_>>(),
        ids[2..].to_vec()
    );
    assert_eq!(second.next_cursor, None);
}

pub async fn orgs_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let member = seed_member(s, tenant, org.id, &[]).await;

    assert_eq!(repo.get(other, org.id).await.expect("get"), None);
    assert_eq!(
        repo.get_by_slug(other, &org.slug).await.expect("by slug"),
        None
    );
    assert!(
        repo.list(other, page(None, 10))
            .await
            .expect("list")
            .items
            .is_empty()
    );
    assert_eq!(
        repo.update(other, org.id, &OrganizationUpdate::default(), now_ms())
            .await
            .expect("update"),
        None
    );
    assert!(!repo.delete(other, org.id, now_ms()).await.expect("delete"));
    assert!(
        !repo
            .is_member(other, org.id, member.id)
            .await
            .expect("is_member")
    );
    assert!(
        repo.list_members(other, org.id, page(None, 10))
            .await
            .expect("members")
            .items
            .is_empty()
    );
    assert!(
        !repo
            .remove_member(other, org.id, member.id, now_ms())
            .await
            .expect("remove")
    );
    assert!(
        repo.memberships_of_user(other, member.id)
            .await
            .expect("memberships")
            .is_empty()
    );
    // Everything is still there for the owning tenant.
    assert_eq!(
        repo.get(tenant, org.id).await.expect("get"),
        Some(org.clone())
    );
    assert!(
        repo.is_member(tenant, org.id, member.id)
            .await
            .expect("is_member")
    );
}

pub async fn org_add_member_idempotent_with_roles(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let roles = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["docs:read"]).await;
    let org_role = seed_org_role(s, tenant, org.id, &["org:admin"]).await;
    let user = seed_user(s, tenant).await;

    let membership = new_membership(org.id, user.id, &[tenant_role.id, org_role.id]);
    assert_eq!(
        repo.add_member(tenant, &membership).await.expect("add"),
        AddMemberOutcome::Added
    );
    assert!(
        repo.is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );
    let mut held: Vec<RoleId> = roles
        .roles_for_user_in_org(tenant, user.id, org.id)
        .await
        .expect("roles in org")
        .into_iter()
        .map(|r| r.id)
        .collect();
    held.sort_by_key(|id| id.0);
    let mut want = vec![tenant_role.id, org_role.id];
    want.sort_by_key(|id| id.0);
    assert_eq!(held, want, "the membership's roles are assigned in the org");
    assert!(
        roles
            .roles_for_user(tenant, user.id)
            .await
            .expect("tenant roles")
            .is_empty(),
        "in-org assignments are not tenant-wide"
    );

    // Adding again keeps the membership and does not touch its assignments.
    let again = new_membership(org.id, user.id, &[]);
    assert_eq!(
        repo.add_member(tenant, &again).await.expect("add again"),
        AddMemberOutcome::AlreadyMember
    );
    assert_eq!(
        roles
            .roles_for_user_in_org(tenant, user.id, org.id)
            .await
            .expect("roles in org")
            .len(),
        2
    );
    let members = repo
        .list_members(tenant, org.id, page(None, 10))
        .await
        .expect("members");
    assert_eq!(members.items.len(), 1);
    assert_eq!(members.items[0].user_id, user.id);
    assert_eq!(members.items[0].org_id, org.id);
    assert_eq!(members.items[0].tenant_id, tenant);
    assert_eq!(members.items[0].created_at, membership.created_at);
}

pub async fn org_add_member_refuses_unknown_or_foreign(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let foreign_user = seed_user(s, other).await;
    let user = seed_user(s, tenant).await;

    // A user of another tenant.
    assert_eq!(
        repo.add_member(tenant, &new_membership(org.id, foreign_user.id, &[]))
            .await
            .expect("add"),
        AddMemberOutcome::NotFound
    );
    // An unknown user, an unknown org.
    assert_eq!(
        repo.add_member(tenant, &new_membership(org.id, UserId::new_v7(), &[]))
            .await
            .expect("add"),
        AddMemberOutcome::NotFound
    );
    assert_eq!(
        repo.add_member(tenant, &new_membership(OrgId::new_v7(), user.id, &[]))
            .await
            .expect("add"),
        AddMemberOutcome::NotFound
    );
    // An org of this tenant seen from another tenant.
    assert_eq!(
        repo.add_member(other, &new_membership(org.id, foreign_user.id, &[]))
            .await
            .expect("add"),
        AddMemberOutcome::NotFound
    );
    // A role owned by another org, an unknown role, a role of another tenant: nothing stored.
    let foreign_org_role = seed_org_role(s, tenant, other_org.id, &["x"]).await;
    let other_tenant_role = seed_role(s, other, &["x"]).await;
    for bad in [foreign_org_role.id, RoleId::new_v7(), other_tenant_role.id] {
        assert_eq!(
            repo.add_member(tenant, &new_membership(org.id, user.id, &[bad]))
                .await
                .expect("add"),
            AddMemberOutcome::NotFound
        );
        assert!(
            !repo
                .is_member(tenant, org.id, user.id)
                .await
                .expect("is_member"),
            "a refused membership stores nothing"
        );
    }
}

pub async fn org_remove_member_revokes_only_that_orgs_families(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let roles = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let org_b = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["docs:read"]).await;
    let user = seed_member(s, tenant, org.id, &[tenant_role.id]).await;
    let other_member = seed_member(s, tenant, org.id, &[]).await;
    assert_eq!(
        repo.add_member(
            tenant,
            &new_membership(org_b.id, user.id, &[tenant_role.id])
        )
        .await
        .expect("add to b"),
        AddMemberOutcome::Added
    );
    assert!(
        roles
            .assign(tenant, tenant_role.id, user.id, now_ms())
            .await
            .expect("tenant-wide assign")
    );

    let in_org = seed_family_for(s, tenant, &user, Some(org.id)).await;
    let in_org_b = seed_family_for(s, tenant, &user, Some(org_b.id)).await;
    let no_org = seed_family_for(s, tenant, &user, None).await;
    let other_members = seed_family_for(s, tenant, &other_member, Some(org.id)).await;

    assert!(
        repo.remove_member(tenant, org.id, user.id, now_ms())
            .await
            .expect("remove")
    );
    assert!(
        !repo
            .is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );
    assert!(
        roles
            .roles_for_user_in_org(tenant, user.id, org.id)
            .await
            .expect("roles in org")
            .is_empty(),
        "the user's assignments in the org are gone"
    );
    assert!(
        roles
            .org_assignments(tenant, org.id, user.id)
            .await
            .expect("assignments")
            .is_empty()
    );
    assert_eq!(
        family_revocation(s, tenant, in_org).await,
        Some(RevokeReason::Admin)
    );
    assert_eq!(family_revocation(s, tenant, in_org_b).await, None);
    assert_eq!(family_revocation(s, tenant, no_org).await, None);
    assert_eq!(family_revocation(s, tenant, other_members).await, None);
    // Other memberships and tenant-wide assignments stay.
    assert!(
        repo.is_member(tenant, org_b.id, user.id)
            .await
            .expect("is_member")
    );
    assert_eq!(
        roles
            .roles_for_user_in_org(tenant, user.id, org_b.id)
            .await
            .expect("roles in b")
            .len(),
        1
    );
    assert_eq!(
        roles
            .roles_for_user(tenant, user.id)
            .await
            .expect("tenant roles")
            .len(),
        1
    );
    // Removing again is a no-op.
    assert!(
        !repo
            .remove_member(tenant, org.id, user.id, now_ms())
            .await
            .expect("remove again")
    );
}

pub async fn org_delete_cascades_and_revokes_families(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let roles = s.storage.roles();
    let connections = s.storage.connections();
    let org = seed_org(s, tenant).await;
    let survivor = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["docs:read"]).await;
    let org_role = seed_org_role(s, tenant, org.id, &["org:admin"]).await;
    let user = seed_member(s, tenant, org.id, &[tenant_role.id, org_role.id]).await;
    assert_eq!(
        repo.add_member(
            tenant,
            &new_membership(survivor.id, user.id, &[tenant_role.id])
        )
        .await
        .expect("add to survivor"),
        AddMemberOutcome::Added
    );
    assert!(
        roles
            .assign(tenant, tenant_role.id, user.id, now_ms())
            .await
            .expect("tenant-wide assign")
    );
    let conn = seed_org_connection(s, tenant, org.id).await;
    let link = new_identity_link(user.id, conn.id, "sub-delete");
    connections.create_link(tenant, &link).await.expect("link");
    let domain = new_org_domain(org.id, &unique_domain(), Some(conn.id));
    repo.create_domain(tenant, &domain).await.expect("domain");
    let invitation = new_invitation(org.id, "inv@example.test", &[], Duration::days(7));
    repo.create_invitation(tenant, &invitation)
        .await
        .expect("invitation");
    let family = seed_family_for(s, tenant, &user, Some(org.id)).await;
    let survivor_family = seed_family_for(s, tenant, &user, Some(survivor.id)).await;

    assert!(repo.delete(tenant, org.id, now_ms()).await.expect("delete"));

    assert_eq!(repo.get(tenant, org.id).await.expect("get"), None);
    assert!(
        !repo
            .is_member(tenant, org.id, user.id)
            .await
            .expect("is_member")
    );
    assert_eq!(roles.get(tenant, org_role.id).await.expect("get"), None);
    assert!(
        roles
            .org_assignments(tenant, org.id, user.id)
            .await
            .expect("assignments")
            .is_empty()
    );
    assert_eq!(connections.get(tenant, conn.id).await.expect("get"), None);
    assert_eq!(
        connections
            .find_link(tenant, conn.id, "sub-delete")
            .await
            .expect("find"),
        None
    );
    assert_eq!(
        repo.get_domain(tenant, domain.id).await.expect("domain"),
        None
    );
    assert_eq!(
        repo.invitation_by_hash(tenant, &invitation.token_hash)
            .await
            .expect("invitation"),
        None
    );
    assert_eq!(
        family_revocation(s, tenant, family).await,
        Some(RevokeReason::Admin)
    );

    // The user, tenant roles, tenant-wide assignments and other orgs are untouched.
    assert!(
        s.storage
            .users()
            .get(tenant, user.id)
            .await
            .expect("user")
            .is_some()
    );
    assert!(
        roles
            .get(tenant, tenant_role.id)
            .await
            .expect("get")
            .is_some()
    );
    assert_eq!(
        roles
            .roles_for_user(tenant, user.id)
            .await
            .expect("tenant roles")
            .len(),
        1
    );
    assert!(
        repo.is_member(tenant, survivor.id, user.id)
            .await
            .expect("is_member")
    );
    assert_eq!(family_revocation(s, tenant, survivor_family).await, None);
}

pub async fn org_memberships_of_user(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let _unrelated = seed_org(s, tenant).await;
    let user = seed_member(s, tenant, a.id, &[]).await;
    assert_eq!(
        repo.add_member(tenant, &new_membership(b.id, user.id, &[]))
            .await
            .expect("add"),
        AddMemberOutcome::Added
    );
    let mut want = vec![a.clone(), b.clone()];
    want.sort_by(|x, y| x.slug.cmp(&y.slug));
    assert_eq!(
        repo.memberships_of_user(tenant, user.id)
            .await
            .expect("memberships"),
        want,
        "slug order"
    );
    let loner = seed_user(s, tenant).await;
    assert!(
        repo.memberships_of_user(tenant, loner.id)
            .await
            .expect("memberships")
            .is_empty()
    );
}

pub async fn org_list_members_paginates(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.organizations();
    let org = seed_org(s, tenant).await;
    let mut ids = Vec::new();
    for _ in 0..5 {
        ids.push(seed_member(s, tenant, org.id, &[]).await.id);
    }
    // A member of another org never shows up.
    let other_org = seed_org(s, tenant).await;
    seed_member(s, tenant, other_org.id, &[]).await;
    ids.sort_by_key(|id| id.0);
    let first = repo
        .list_members(tenant, org.id, page(None, 3))
        .await
        .expect("members");
    assert_eq!(
        first.items.iter().map(|m| m.user_id).collect::<Vec<_>>(),
        ids[..3].to_vec()
    );
    let cursor = first.next_cursor.expect("more pages");
    let second = repo
        .list_members(tenant, org.id, page(Some(cursor), 10))
        .await
        .expect("members");
    assert_eq!(
        second.items.iter().map(|m| m.user_id).collect::<Vec<_>>(),
        ids[3..].to_vec()
    );
    assert_eq!(second.next_cursor, None);
}
