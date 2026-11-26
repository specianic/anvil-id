//! AttributeRepo contract: per-tenant attribute definitions (upsert by name, position order) and
//! per-user value objects that survive definition deletes and never cross tenants.

use anvil_core::model::UserId;
use serde_json::{Map, Value, json};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn values(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        other => panic!("not an object: {other}"),
    }
}

pub async fn attribute_upsert_list_get_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.attributes();
    assert_eq!(repo.list(tenant).await.expect("list"), vec![]);

    let dept = new_attribute("department", 2);
    let cost = new_attribute("cost_center", 1);
    let mut badge = new_attribute("badge", 2);
    badge.claim = None;
    badge.required = false;
    badge.user_editable = false;
    for d in [&dept, &cost, &badge] {
        assert_eq!(&repo.upsert(tenant, d, now_ms()).await.expect("upsert"), d);
    }
    assert_eq!(
        repo.list(tenant).await.expect("list"),
        vec![cost.clone(), badge.clone(), dept.clone()],
        "position order, then name"
    );
    assert_eq!(
        repo.get(tenant, "department").await.expect("get"),
        Some(dept.clone())
    );
    assert_eq!(repo.get(tenant, "missing").await.expect("get"), None);

    // Upsert with the same name replaces the definition.
    let mut changed = dept.clone();
    changed.schema = json!({"type": "integer"});
    changed.required = false;
    changed.position = 0;
    assert_eq!(
        repo.upsert(tenant, &changed, now_ms() + Duration::seconds(1))
            .await
            .expect("upsert"),
        changed
    );
    assert_eq!(
        repo.get(tenant, "department").await.expect("get"),
        Some(changed.clone())
    );
    assert_eq!(repo.list(tenant).await.expect("list").len(), 3);
    assert_eq!(repo.list(tenant).await.expect("list")[0], changed);

    assert!(repo.delete(tenant, "department").await.expect("delete"));
    assert!(!repo.delete(tenant, "department").await.expect("delete"));
    assert_eq!(repo.get(tenant, "department").await.expect("get"), None);
    assert_eq!(repo.list(tenant).await.expect("list").len(), 2);
}

pub async fn attribute_user_values_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.attributes();
    assert_eq!(
        repo.user_values(tenant, user.id)
            .await
            .expect("user_values"),
        Some(Map::new()),
        "a user starts with an empty object"
    );

    let v = values(json!({
        "department": "R&D",
        "level": 3,
        "tags": ["a", "b"],
        "nested": {"ok": true, "none": null}
    }));
    let later = now_ms() + Duration::seconds(3);
    assert!(
        repo.set_user_values(tenant, user.id, &v, later)
            .await
            .expect("set")
    );
    assert_eq!(
        repo.user_values(tenant, user.id)
            .await
            .expect("user_values"),
        Some(v)
    );
    let stored = s
        .storage
        .users()
        .get(tenant, user.id)
        .await
        .expect("get")
        .expect("user exists");
    assert_eq!(stored.updated_at, later, "setting values touches the user");

    // The whole object is replaced, not merged.
    let replaced = values(json!({"level": 4}));
    assert!(
        repo.set_user_values(tenant, user.id, &replaced, later)
            .await
            .expect("set")
    );
    assert_eq!(
        repo.user_values(tenant, user.id)
            .await
            .expect("user_values"),
        Some(replaced)
    );

    assert_eq!(
        repo.user_values(tenant, UserId::new_v7())
            .await
            .expect("user_values"),
        None
    );
    assert!(
        !repo
            .set_user_values(tenant, UserId::new_v7(), &Map::new(), later)
            .await
            .expect("set")
    );
}

pub async fn attribute_delete_keeps_user_values(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.attributes();
    repo.upsert(tenant, &new_attribute("department", 0), now_ms())
        .await
        .expect("upsert");
    let v = values(json!({"department": "Ops"}));
    assert!(
        repo.set_user_values(tenant, user.id, &v, now_ms())
            .await
            .expect("set")
    );
    assert!(repo.delete(tenant, "department").await.expect("delete"));
    assert_eq!(
        repo.user_values(tenant, user.id)
            .await
            .expect("user_values"),
        Some(v),
        "deleting a definition leaves stored values untouched"
    );
}

pub async fn attributes_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let user = seed_user(s, tenant).await;
    let repo = s.storage.attributes();
    let def = new_attribute("department", 0);
    repo.upsert(tenant, &def, now_ms()).await.expect("upsert");
    let v = values(json!({"department": "Sales"}));
    assert!(
        repo.set_user_values(tenant, user.id, &v, now_ms())
            .await
            .expect("set")
    );

    assert_eq!(repo.list(other).await.expect("list"), vec![]);
    assert_eq!(repo.get(other, "department").await.expect("get"), None);
    assert!(!repo.delete(other, "department").await.expect("delete"));
    assert_eq!(
        repo.user_values(other, user.id).await.expect("user_values"),
        None,
        "another tenant's user behaves like a missing user"
    );
    assert!(
        !repo
            .set_user_values(other, user.id, &Map::new(), now_ms())
            .await
            .expect("set")
    );
    // The same name in the other tenant is an independent definition.
    let mut theirs = new_attribute("department", 5);
    theirs.required = false;
    repo.upsert(other, &theirs, now_ms()).await.expect("upsert");
    assert_eq!(
        repo.get(tenant, "department").await.expect("get"),
        Some(def)
    );
    assert_eq!(
        repo.user_values(tenant, user.id)
            .await
            .expect("user_values"),
        Some(v)
    );
}
