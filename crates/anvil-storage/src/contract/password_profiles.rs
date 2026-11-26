//! PasswordProfileRepo contract: per-tenant legacy password hash profiles (create, get, list,
//! delete, name uniqueness, tenant isolation, reference counting through PHC strings).

use anvil_core::model::{
    NewPasswordCredential, NewPasswordHashProfile, PasswordHashProfile, ProfileKind, TenantId,
};
use anvil_core::ports::StorageError;
use uuid::Uuid;

use super::TestStorage;
use super::fixtures::*;

/// A Firebase scrypt profile with a unique name and a (fake) sealed signer key.
fn new_profile() -> NewPasswordHashProfile {
    let id = Uuid::now_v7();
    NewPasswordHashProfile {
        id,
        name: format!("firebase-{}", id.simple()),
        kind: ProfileKind::FirebaseScrypt,
        salt_separator: vec![0x42, 0x00, 0xff],
        rounds: 8,
        mem_cost: 14,
        signer_key_sealed: vec![0xA5; 61],
        created_at: now_ms(),
    }
}

fn expected_profile(tenant: TenantId, p: &NewPasswordHashProfile) -> PasswordHashProfile {
    PasswordHashProfile {
        id: p.id,
        tenant_id: tenant,
        name: p.name.clone(),
        kind: p.kind,
        salt_separator: p.salt_separator.clone(),
        rounds: p.rounds,
        mem_cost: p.mem_cost,
        signer_key_sealed: p.signer_key_sealed.clone(),
        created_at: p.created_at,
    }
}

async fn create(s: &TestStorage, tenant: TenantId, p: &NewPasswordHashProfile) {
    s.storage
        .password_profiles()
        .create(tenant, p)
        .await
        .expect("creating a profile must succeed");
}

/// Creates a user whose password credential is `phc`.
async fn user_with_phc(s: &TestStorage, tenant: TenantId, phc: String) {
    s.storage
        .users()
        .create(
            tenant,
            &new_user(),
            Some(&NewPasswordCredential {
                phc,
                created_at: now_ms(),
            }),
            None,
            None,
        )
        .await
        .expect("create user");
}

fn firebase_phc(profile: Uuid) -> String {
    format!(
        "$anvil-firebase-scrypt$profile={}$salt=c2FsdA$hash=aGFzaA",
        profile.hyphenated()
    )
}

pub async fn password_profile_create_get_list_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.password_profiles();
    let mut first = new_profile();
    first.name = "b-profile".into();
    let mut second = new_profile();
    second.name = "a-profile".into();
    second.salt_separator = Vec::new();
    second.rounds = 1;
    second.mem_cost = 1;

    let created = repo.create(tenant, &first).await.expect("create");
    assert_eq!(
        created,
        expected_profile(tenant, &first),
        "create returns every field"
    );
    create(s, tenant, &second).await;
    assert_eq!(
        repo.get(tenant, first.id).await.expect("get"),
        Some(expected_profile(tenant, &first)),
        "get returns every field"
    );
    assert_eq!(
        repo.list(tenant).await.expect("list"),
        vec![
            expected_profile(tenant, &second),
            expected_profile(tenant, &first)
        ],
        "list is in name order"
    );
    assert_eq!(repo.get(tenant, Uuid::now_v7()).await.expect("get"), None);

    assert!(repo.delete(tenant, first.id).await.expect("delete"));
    assert!(
        !repo.delete(tenant, first.id).await.expect("delete again"),
        "deleting an unknown profile is false"
    );
    assert_eq!(repo.get(tenant, first.id).await.expect("get"), None);
    assert_eq!(
        repo.list(tenant).await.expect("list"),
        vec![expected_profile(tenant, &second)]
    );

    // Duplicate id: Conflict.
    let mut dup_id = new_profile();
    dup_id.id = second.id;
    assert!(matches!(
        repo.create(tenant, &dup_id).await,
        Err(StorageError::Conflict(_))
    ));
}

pub async fn password_profile_name_unique_per_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.password_profiles();
    let p = new_profile();
    create(s, tenant, &p).await;

    let mut same_name = new_profile();
    same_name.name = p.name.clone();
    match repo.create(tenant, &same_name).await {
        Err(StorageError::Conflict(_)) => {}
        other => panic!("a duplicate name in the tenant must be Conflict, got {other:?}"),
    }
    assert_eq!(
        repo.get(tenant, same_name.id).await.expect("get"),
        None,
        "a refused create stores nothing"
    );
    assert_eq!(repo.list(tenant).await.expect("list").len(), 1);

    // The same name in another tenant is fine.
    create(s, other, &same_name).await;
    assert_eq!(
        repo.get(other, same_name.id).await.expect("get"),
        Some(expected_profile(other, &same_name))
    );
}

pub async fn password_profile_tenant_isolation(s: &TestStorage) {
    let a = seed_tenant(s).await;
    let b = seed_tenant(s).await;
    let repo = s.storage.password_profiles();
    let p = new_profile();
    create(s, a, &p).await;
    user_with_phc(s, a, firebase_phc(p.id)).await;

    assert_eq!(repo.get(b, p.id).await.expect("get"), None);
    assert!(repo.list(b).await.expect("list").is_empty());
    assert!(
        !repo.delete(b, p.id).await.expect("delete"),
        "another tenant cannot delete the profile"
    );
    assert_eq!(
        repo.count_references(b, p.id).await.expect("count"),
        0,
        "references are counted per tenant"
    );
    assert_eq!(
        repo.get(a, p.id).await.expect("get"),
        Some(expected_profile(a, &p)),
        "the profile survives the foreign delete"
    );
    assert_eq!(repo.count_references(a, p.id).await.expect("count"), 1);

    // Deleting the tenant deletes its profiles.
    assert!(s.storage.tenants().delete(a).await.expect("delete tenant"));
    assert_eq!(repo.get(a, p.id).await.expect("get"), None);
}

pub async fn password_profile_count_references(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.password_profiles();
    let p = new_profile();
    let q = new_profile();
    create(s, tenant, &p).await;
    create(s, tenant, &q).await;
    assert_eq!(repo.count_references(tenant, p.id).await.expect("count"), 0);

    user_with_phc(s, tenant, firebase_phc(p.id)).await;
    user_with_phc(s, tenant, firebase_phc(p.id)).await;
    user_with_phc(s, tenant, firebase_phc(q.id)).await;
    // Not references: another scheme, the id without the exact prefix, another tenant.
    seed_user(s, tenant).await;
    user_with_phc(
        s,
        tenant,
        format!(
            "$anvil-firebase-scrypt$profile={}x$salt=AA$hash=AA",
            p.id.hyphenated()
        ),
    )
    .await;
    user_with_phc(s, tenant, format!("$bcrypt$profile={}$", p.id.hyphenated())).await;
    user_with_phc(s, other, firebase_phc(p.id)).await;

    assert_eq!(repo.count_references(tenant, p.id).await.expect("count"), 2);
    assert_eq!(repo.count_references(tenant, q.id).await.expect("count"), 1);
    assert_eq!(
        repo.count_references(tenant, Uuid::now_v7())
            .await
            .expect("count"),
        0
    );
}
