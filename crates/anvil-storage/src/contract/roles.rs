//! RoleRepo contract: tenant-scoped roles, per-tenant unique names, idempotent assignments that
//! never cross tenants, cascades, and the active-holder count behind the last-admin guard.

use anvil_core::model::{PageRequest, RoleId, RoleUpdate, UserId, UserStatus, UserUpdate};
use anvil_core::ports::StorageError;
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn page(after: Option<uuid::Uuid>, limit: u32) -> PageRequest {
    PageRequest { after, limit }
}

pub async fn role_create_get_update_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let new = new_role(&["docs:read", "docs:write"]);
    let created = repo.create(tenant, &new).await.expect("create");
    assert_eq!(created, expected_role(tenant, &new));
    assert_eq!(
        repo.get(tenant, new.id).await.expect("get"),
        Some(created.clone())
    );
    assert_eq!(
        repo.get_by_name(tenant, &new.name)
            .await
            .expect("get_by_name"),
        Some(created.clone())
    );
    assert_eq!(
        repo.get_by_name(tenant, "no-such-role")
            .await
            .expect("get_by_name"),
        None
    );

    let later = new.created_at + Duration::seconds(5);
    let updated = repo
        .update(
            tenant,
            new.id,
            &RoleUpdate {
                name: Some(format!("{}-renamed", new.name)),
                description: Some("Renamed".to_owned()),
                permissions: Some(vec!["docs:read".to_owned()]),
            },
            later,
        )
        .await
        .expect("update")
        .expect("role exists");
    assert_eq!(updated.name, format!("{}-renamed", new.name));
    assert_eq!(updated.description, "Renamed");
    assert_eq!(updated.permissions, vec!["docs:read".to_owned()]);
    assert_eq!(updated.created_at, new.created_at);
    assert_eq!(updated.updated_at, later);
    assert_eq!(
        repo.get(tenant, new.id).await.expect("get"),
        Some(updated.clone())
    );
    // An empty update keeps every field.
    let same = repo
        .update(tenant, new.id, &RoleUpdate::default(), later)
        .await
        .expect("update")
        .expect("role exists");
    assert_eq!(same.permissions, updated.permissions);
    assert_eq!(
        repo.update(tenant, RoleId::new_v7(), &RoleUpdate::default(), later)
            .await
            .expect("update"),
        None
    );

    assert!(repo.delete(tenant, new.id).await.expect("delete"));
    assert!(!repo.delete(tenant, new.id).await.expect("delete"));
    assert_eq!(repo.get(tenant, new.id).await.expect("get"), None);
}

pub async fn role_list_in_name_order(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    for name in ["zeta", "alpha", "mid"] {
        let mut r = new_role(&["p"]);
        r.name = name.to_owned();
        repo.create(tenant, &r).await.expect("create");
    }
    let names: Vec<String> = repo
        .list(tenant)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, vec!["alpha", "mid", "zeta"]);
}

pub async fn role_name_conflict_per_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.roles();
    let first = new_role(&["a"]);
    repo.create(tenant, &first).await.expect("create");

    let mut dup = new_role(&["b"]);
    dup.name = first.name.clone();
    assert!(
        matches!(
            repo.create(tenant, &dup).await,
            Err(StorageError::Conflict(_))
        ),
        "duplicate role name in one tenant must conflict"
    );
    assert_eq!(repo.get(tenant, dup.id).await.expect("get"), None);
    assert_eq!(repo.list(tenant).await.expect("list").len(), 1);

    // The same name in another tenant is fine.
    repo.create(other, &dup)
        .await
        .expect("same name in another tenant");

    // Renaming onto an existing name conflicts and changes nothing.
    let second = seed_role(s, tenant, &["c"]).await;
    assert!(matches!(
        repo.update(
            tenant,
            second.id,
            &RoleUpdate {
                name: Some(first.name.clone()),
                ..RoleUpdate::default()
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

pub async fn role_assign_idempotent_and_unassign(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.roles();
    let a = seed_role(s, tenant, &["a"]).await;
    let b = seed_role(s, tenant, &["b"]).await;
    let now = now_ms();

    assert!(
        repo.assign(tenant, a.id, user.id, now)
            .await
            .expect("assign")
    );
    assert!(
        repo.assign(tenant, a.id, user.id, now)
            .await
            .expect("assign"),
        "assigning twice is idempotent"
    );
    assert!(
        repo.assign(tenant, b.id, user.id, now)
            .await
            .expect("assign")
    );
    let mut expected = vec![a.clone(), b.clone()];
    expected.sort_by(|x, y| x.name.cmp(&y.name));
    assert_eq!(
        repo.roles_for_user(tenant, user.id).await.expect("roles"),
        expected
    );

    assert!(
        repo.unassign(tenant, a.id, user.id)
            .await
            .expect("unassign")
    );
    assert!(
        !repo
            .unassign(tenant, a.id, user.id)
            .await
            .expect("unassign"),
        "nothing left to remove"
    );
    assert_eq!(
        repo.roles_for_user(tenant, user.id).await.expect("roles"),
        vec![b]
    );
    assert_eq!(
        repo.roles_for_user(tenant, UserId::new_v7())
            .await
            .expect("roles"),
        vec![]
    );
    // Unknown role or user: nothing stored.
    assert!(
        !repo
            .assign(tenant, RoleId::new_v7(), user.id, now)
            .await
            .expect("assign")
    );
    assert!(
        !repo
            .assign(tenant, a.id, UserId::new_v7(), now)
            .await
            .expect("assign")
    );
}

pub async fn role_assign_refuses_foreign_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let foreign_user = seed_user(s, other).await;
    let role = seed_role(s, tenant, &["a"]).await;
    let foreign_role = seed_role(s, other, &["a"]).await;
    let repo = s.storage.roles();
    let now = now_ms();

    assert!(
        !repo
            .assign(tenant, role.id, foreign_user.id, now)
            .await
            .expect("assign"),
        "a user of another tenant must not get this tenant's role"
    );
    assert!(
        !repo
            .assign(tenant, foreign_role.id, user.id, now)
            .await
            .expect("assign"),
        "a role of another tenant must not be assigned"
    );
    assert!(
        !repo
            .assign(other, role.id, foreign_user.id, now)
            .await
            .expect("assign"),
        "the role is invisible from the other tenant"
    );
    assert_eq!(
        repo.roles_for_user(tenant, user.id).await.expect("roles"),
        vec![]
    );
    assert_eq!(
        repo.roles_for_user(other, foreign_user.id)
            .await
            .expect("roles"),
        vec![]
    );
    assert_eq!(
        repo.users_with_role(tenant, role.id, page(None, 10))
            .await
            .expect("users_with_role")
            .items,
        vec![]
    );
}

pub async fn role_delete_cascades_assignments(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.roles();
    let role = seed_role(s, tenant, &["a"]).await;
    let keep = seed_role(s, tenant, &["b"]).await;
    let now = now_ms();
    assert!(
        repo.assign(tenant, role.id, user.id, now)
            .await
            .expect("assign")
    );
    assert!(
        repo.assign(tenant, keep.id, user.id, now)
            .await
            .expect("assign")
    );

    assert!(repo.delete(tenant, role.id).await.expect("delete"));
    assert_eq!(
        repo.roles_for_user(tenant, user.id).await.expect("roles"),
        vec![keep.clone()]
    );
    assert_eq!(
        repo.holders_of_permission(tenant, "a")
            .await
            .expect("holders"),
        0
    );
    // Deleting the user removes its assignments too.
    assert!(
        s.storage
            .users()
            .delete(tenant, user.id)
            .await
            .expect("delete user")
    );
    assert_eq!(
        repo.users_with_role(tenant, keep.id, page(None, 10))
            .await
            .expect("users_with_role")
            .items,
        vec![]
    );
}

pub async fn role_users_with_role_paginates(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let role = seed_role(s, tenant, &["a"]).await;
    let mut users = Vec::new();
    for _ in 0..5 {
        let u = seed_user(s, tenant).await;
        assert!(
            repo.assign(tenant, role.id, u.id, now_ms())
                .await
                .expect("assign")
        );
        users.push(u);
    }
    // An unassigned user is never listed.
    seed_user(s, tenant).await;
    users.sort_by_key(|u| u.id.0);

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let p = repo
            .users_with_role(tenant, role.id, page(after, 2))
            .await
            .expect("users_with_role");
        assert!(p.items.len() <= 2);
        seen.extend(p.items.iter().cloned());
        match p.next_cursor {
            Some(c) => after = Some(c),
            None => break,
        }
    }
    assert_eq!(seen, users, "every holder exactly once, in id order");
}

pub async fn role_holders_of_permission_counts_active_users(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.roles();
    let admin = seed_role(s, tenant, &["admin:write", "x"]).await;
    let also = seed_role(s, tenant, &["admin:write"]).await;
    let unrelated = seed_role(s, tenant, &["admin:read"]).await;
    let now = now_ms();

    let a = seed_user(s, tenant).await;
    let b = seed_user(s, tenant).await;
    let blocked = seed_user(s, tenant).await;
    let deleted = seed_user(s, tenant).await;
    let reader = seed_user(s, tenant).await;
    // `a` holds the permission through two roles: counted once.
    for (role, user) in [
        (admin.id, a.id),
        (also.id, a.id),
        (admin.id, b.id),
        (admin.id, blocked.id),
        (also.id, deleted.id),
        (unrelated.id, reader.id),
    ] {
        assert!(repo.assign(tenant, role, user, now).await.expect("assign"));
    }
    assert_eq!(
        repo.holders_of_permission(tenant, "admin:write")
            .await
            .expect("holders"),
        4
    );

    s.storage
        .users()
        .update(
            tenant,
            blocked.id,
            &UserUpdate {
                status: Some(UserStatus::Blocked),
                ..UserUpdate::default()
            },
            now,
        )
        .await
        .expect("block")
        .expect("user exists");
    assert!(
        s.storage
            .users()
            .delete(tenant, deleted.id)
            .await
            .expect("delete")
    );
    assert_eq!(
        repo.holders_of_permission(tenant, "admin:write")
            .await
            .expect("holders"),
        2,
        "blocked and deleted users are not counted"
    );
    assert_eq!(
        repo.holders_of_permission(tenant, "admin")
            .await
            .expect("holders"),
        0,
        "exact permission match only"
    );
    assert_eq!(
        repo.holders_of_permission(other, "admin:write")
            .await
            .expect("holders"),
        0,
        "other tenants see nothing"
    );
}

pub async fn roles_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.roles();
    let role = seed_role(s, tenant, &["a"]).await;

    assert_eq!(repo.get(other, role.id).await.expect("get"), None);
    assert_eq!(
        repo.get_by_name(other, &role.name)
            .await
            .expect("get_by_name"),
        None
    );
    assert_eq!(repo.list(other).await.expect("list"), vec![]);
    assert_eq!(
        repo.update(
            other,
            role.id,
            &RoleUpdate {
                description: Some("hijacked".to_owned()),
                ..RoleUpdate::default()
            },
            now_ms(),
        )
        .await
        .expect("update"),
        None
    );
    assert!(!repo.delete(other, role.id).await.expect("delete"));
    assert_eq!(repo.get(tenant, role.id).await.expect("get"), Some(role));
}

// ---- Phase 6 (plan 06-04): organization-level roles and assignments ----

fn ids(roles: &[anvil_core::model::Role]) -> Vec<RoleId> {
    let mut v: Vec<RoleId> = roles.iter().map(|r| r.id).collect();
    v.sort_by_key(|id| id.0);
    v
}

pub async fn role_org_owned_name_unique_per_org(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["docs:read"]).await;

    // An org-owned role may share a tenant role's name.
    let same_as_tenant = anvil_core::model::NewRole {
        name: tenant_role.name.clone(),
        ..new_org_role(org.id, &["docs:read"])
    };
    let created = repo
        .create(tenant, &same_as_tenant)
        .await
        .expect("org role with a tenant role's name");
    assert_eq!(created, expected_role(tenant, &same_as_tenant));
    assert_eq!(created.org_id, Some(org.id));
    // The same name twice in one org conflicts; in another org it is fine.
    let dup = anvil_core::model::NewRole {
        name: tenant_role.name.clone(),
        ..new_org_role(org.id, &[])
    };
    assert!(matches!(
        repo.create(tenant, &dup).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(repo.get(tenant, dup.id).await.expect("get"), None);
    let in_other = anvil_core::model::NewRole {
        name: tenant_role.name.clone(),
        ..new_org_role(other_org.id, &[])
    };
    repo.create(tenant, &in_other).await.expect("another org");
    // The tenant-level lookup by name still finds the tenant role only.
    assert_eq!(
        repo.get_by_name(tenant, &tenant_role.name)
            .await
            .expect("by name"),
        Some(tenant_role.clone())
    );
    // An org of another tenant (or an unknown org) cannot own a role here.
    let stranger = seed_tenant(s).await;
    let foreign_org = seed_org(s, stranger).await;
    let foreign = new_org_role(foreign_org.id, &[]);
    assert!(matches!(
        repo.create(tenant, &foreign).await,
        Err(StorageError::Conflict(_))
    ));
    assert_eq!(repo.get(tenant, foreign.id).await.expect("get"), None);
}

pub async fn role_list_excludes_org_roles(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &[]).await;
    let org_a = seed_org_role(s, tenant, org.id, &[]).await;
    let org_b = seed_org_role(s, tenant, org.id, &[]).await;
    seed_org_role(s, tenant, other_org.id, &[]).await;

    assert_eq!(
        repo.list(tenant).await.expect("list"),
        vec![tenant_role],
        "tenant roles only"
    );
    let mut want = vec![org_a, org_b];
    want.sort_by(|x, y| x.name.cmp(&y.name));
    assert_eq!(
        repo.list_org_roles(tenant, org.id)
            .await
            .expect("org roles"),
        want,
        "this org's roles in name order"
    );
    assert!(
        repo.list_org_roles(seed_tenant(s).await, org.id)
            .await
            .expect("org roles of a foreign org")
            .is_empty()
    );
}

pub async fn role_assign_in_org_requires_membership(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let role = seed_role(s, tenant, &["docs:read"]).await;
    let outsider = seed_user(s, tenant).await;
    assert!(
        !repo
            .assign_in_org(tenant, role.id, outsider.id, org.id, now_ms())
            .await
            .expect("assign"),
        "a non-member cannot hold roles in the org"
    );
    assert!(
        repo.org_assignments(tenant, org.id, outsider.id)
            .await
            .expect("assignments")
            .is_empty()
    );
    let member = seed_member(s, tenant, org.id, &[]).await;
    assert!(
        repo.assign_in_org(tenant, role.id, member.id, org.id, now_ms())
            .await
            .expect("assign")
    );
    // Idempotent.
    assert!(
        repo.assign_in_org(tenant, role.id, member.id, org.id, now_ms())
            .await
            .expect("assign again")
    );
    assert_eq!(
        repo.org_assignments(tenant, org.id, member.id)
            .await
            .expect("assignments"),
        vec![anvil_core::model::RoleAssignment {
            role_id: role.id,
            user_id: member.id,
            org_id: Some(org.id),
        }]
    );
    // Unknown role, unknown org.
    assert!(
        !repo
            .assign_in_org(tenant, RoleId::new_v7(), member.id, org.id, now_ms())
            .await
            .expect("assign unknown role")
    );
    assert!(
        !repo
            .assign_in_org(
                tenant,
                role.id,
                member.id,
                anvil_core::model::OrgId::new_v7(),
                now_ms()
            )
            .await
            .expect("assign in unknown org")
    );
}

pub async fn role_org_owned_role_only_in_its_org(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let a = seed_org(s, tenant).await;
    let b = seed_org(s, tenant).await;
    let role_a = seed_org_role(s, tenant, a.id, &["org:admin"]).await;
    let member = seed_member(s, tenant, a.id, &[]).await;
    assert_eq!(
        s.storage
            .organizations()
            .add_member(tenant, &new_membership(b.id, member.id, &[]))
            .await
            .expect("add to b"),
        anvil_core::ports::AddMemberOutcome::Added
    );

    assert!(
        !repo
            .assign_in_org(tenant, role_a.id, member.id, b.id, now_ms())
            .await
            .expect("assign in b"),
        "org A's role cannot be assigned in org B"
    );
    assert!(
        !repo
            .assign(tenant, role_a.id, member.id, now_ms())
            .await
            .expect("tenant-wide assign"),
        "an org-owned role is never assigned tenant-wide"
    );
    assert!(
        repo.roles_for_user(tenant, member.id)
            .await
            .expect("tenant roles")
            .is_empty()
    );
    assert!(
        repo.roles_for_user_in_org(tenant, member.id, b.id)
            .await
            .expect("roles in b")
            .is_empty()
    );
    assert!(
        repo.assign_in_org(tenant, role_a.id, member.id, a.id, now_ms())
            .await
            .expect("assign in a")
    );
    assert_eq!(
        ids(&repo
            .roles_for_user_in_org(tenant, member.id, a.id)
            .await
            .expect("roles in a")),
        vec![role_a.id]
    );
}

pub async fn role_tenant_role_in_org_scoped_to_that_org(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let x = seed_org(s, tenant).await;
    let y = seed_org(s, tenant).await;
    let role = seed_role(s, tenant, &["docs:write"]).await;
    let user = seed_member(s, tenant, x.id, &[]).await;
    assert_eq!(
        s.storage
            .organizations()
            .add_member(tenant, &new_membership(y.id, user.id, &[]))
            .await
            .expect("add to y"),
        anvil_core::ports::AddMemberOutcome::Added
    );
    assert!(
        repo.assign_in_org(tenant, role.id, user.id, x.id, now_ms())
            .await
            .expect("assign in x")
    );

    assert_eq!(
        ids(&repo
            .roles_for_user_in_org(tenant, user.id, x.id)
            .await
            .expect("roles in x")),
        vec![role.id]
    );
    assert!(
        repo.roles_for_user_in_org(tenant, user.id, y.id)
            .await
            .expect("roles in y")
            .is_empty(),
        "an assignment in X never holds in Y"
    );
    assert!(
        repo.roles_for_user(tenant, user.id)
            .await
            .expect("tenant roles")
            .is_empty(),
        "an assignment in X is not tenant-wide"
    );
    assert!(
        repo.users_with_role(tenant, role.id, page(None, 10))
            .await
            .expect("holders")
            .items
            .is_empty(),
        "users_with_role lists tenant-wide holders only"
    );

    // A tenant-wide assignment of the same role is separate and does not show in the org view.
    assert!(
        repo.assign(tenant, role.id, user.id, now_ms())
            .await
            .expect("tenant-wide")
    );
    assert!(
        repo.roles_for_user_in_org(tenant, user.id, y.id)
            .await
            .expect("roles in y")
            .is_empty()
    );
    // Unassigning in the org keeps the tenant-wide assignment, and vice versa.
    assert!(
        repo.unassign_in_org(tenant, role.id, user.id, x.id)
            .await
            .expect("unassign in x")
    );
    assert!(
        !repo
            .unassign_in_org(tenant, role.id, user.id, x.id)
            .await
            .expect("unassign in x again")
    );
    assert_eq!(
        ids(&repo
            .roles_for_user(tenant, user.id)
            .await
            .expect("tenant roles")),
        vec![role.id]
    );
    assert!(
        repo.assign_in_org(tenant, role.id, user.id, x.id, now_ms())
            .await
            .expect("assign in x")
    );
    assert!(
        repo.unassign(tenant, role.id, user.id)
            .await
            .expect("unassign tenant-wide")
    );
    assert_eq!(
        ids(&repo
            .roles_for_user_in_org(tenant, user.id, x.id)
            .await
            .expect("roles in x")),
        vec![role.id]
    );
}

pub async fn role_holders_of_permission_ignores_org_assignments(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let role = seed_role(s, tenant, &["admin:write"]).await;
    let org_role = seed_org_role(s, tenant, org.id, &["admin:write"]).await;
    let member = seed_member(s, tenant, org.id, &[role.id, org_role.id]).await;
    assert_eq!(
        repo.holders_of_permission(tenant, "admin:write")
            .await
            .expect("holders"),
        0,
        "org assignments never count for the tenant-level guard"
    );
    assert!(
        repo.assign(tenant, role.id, member.id, now_ms())
            .await
            .expect("tenant-wide")
    );
    assert_eq!(
        repo.holders_of_permission(tenant, "admin:write")
            .await
            .expect("holders"),
        1
    );
}

pub async fn role_org_holders_of_permission_counts_in_org_members(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.roles();
    let org = seed_org(s, tenant).await;
    let other_org = seed_org(s, tenant).await;
    let tenant_role = seed_role(s, tenant, &["org:admin"]).await;
    let org_role = seed_org_role(s, tenant, org.id, &["org:admin", "docs:read"]).await;
    let reader = seed_org_role(s, tenant, org.id, &["docs:read"]).await;

    // Through a tenant role assigned in the org, and through an org-owned role.
    let a = seed_member(s, tenant, org.id, &[tenant_role.id]).await;
    let b = seed_member(s, tenant, org.id, &[org_role.id, tenant_role.id]).await;
    // Not counted: a reader, a member of another org, a tenant-wide holder, a blocked member.
    seed_member(s, tenant, org.id, &[reader.id]).await;
    seed_member(s, tenant, other_org.id, &[tenant_role.id]).await;
    let tenant_wide = seed_member(s, tenant, org.id, &[]).await;
    assert!(
        repo.assign(tenant, tenant_role.id, tenant_wide.id, now_ms())
            .await
            .expect("tenant-wide")
    );
    let blocked = seed_member(s, tenant, org.id, &[org_role.id]).await;
    s.storage
        .users()
        .update(
            tenant,
            blocked.id,
            &UserUpdate {
                status: Some(UserStatus::Blocked),
                ..Default::default()
            },
            now_ms(),
        )
        .await
        .expect("block");

    assert_eq!(
        repo.org_holders_of_permission(tenant, org.id, "org:admin")
            .await
            .expect("org holders"),
        2,
        "a (tenant role in org) and b (both, counted once)"
    );
    assert_eq!(
        repo.org_holders_of_permission(tenant, other_org.id, "org:admin")
            .await
            .expect("org holders"),
        1
    );
    assert!(
        s.storage
            .organizations()
            .remove_member(tenant, org.id, a.id, now_ms())
            .await
            .expect("remove a")
    );
    assert!(
        repo.unassign_in_org(tenant, tenant_role.id, b.id, org.id)
            .await
            .expect("unassign")
    );
    assert_eq!(
        repo.org_holders_of_permission(tenant, org.id, "org:admin")
            .await
            .expect("org holders"),
        1,
        "b still holds it through the org-owned role"
    );
}
