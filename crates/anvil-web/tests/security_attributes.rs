//! Custom user attributes (AUTH-14) on the selected backend (`ANVILID_TEST_DB`): attribute
//! schemas are offline, size/depth capped and meta-validated, patterns run in linear time, every
//! value write is validated, schema changes and deletions never rewrite stored values, and
//! values never cross tenants. Driven through `AttributeService` with the production
//! `JsonSchemaCheck` (the admin routes come in 05-23).

mod support;
mod ui_helpers;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_core::clock::SystemClock;
use anvil_core::error::CoreError;
use anvil_core::model::{
    AttributeDefinition, AuditAction, AuditActor, AuditQuery, MAX_SCHEMA_BYTES, RequestContext,
    TenantId, UserId,
};
use anvil_core::service::attribute::{AttributeError, AttributeService, WriteMode};
use anvil_web::adapters::attribute_schema::{JsonSchemaCheck, MAX_SCHEMA_DEPTH};
use serde_json::{Map, Value, json};
use support::TestApp;
use ui_helpers::*;

const PASSWORD: &str = "correct horse battery";

fn service(app: &TestApp) -> AttributeService {
    AttributeService {
        storage: app.storage_arc(),
        clock: Arc::new(SystemClock),
        check: Arc::new(JsonSchemaCheck::new()),
    }
}

fn admin() -> AuditActor {
    AuditActor::admin("test-admin")
}

fn ctx() -> RequestContext {
    RequestContext::system()
}

fn def(name: &str, schema: Value, required: bool, editable: bool) -> AttributeDefinition {
    AttributeDefinition {
        name: name.to_owned(),
        schema,
        required,
        user_editable: editable,
        claim: None,
        position: 0,
    }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().expect("object").clone()
}

async fn user(app: &TestApp, base: &str, tenant: TenantId, email: &str) -> UserId {
    register(app, base, email, PASSWORD).await;
    app.storage()
        .users()
        .get_by_email(tenant, email)
        .await
        .expect("lookup")
        .expect("registered")
        .id
}

async fn count(app: &TestApp, tenant: TenantId, action: AuditAction) -> usize {
    app.storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 500,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .into_iter()
        .filter(|e| e.action == action)
        .count()
}

fn assert_schema_refused(result: Result<AttributeDefinition, CoreError>) {
    assert!(
        matches!(
            result,
            Err(CoreError::Validation {
                field: "schema",
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn attribute_schema_remote_ref_refused() {
    let app = TestApp::new().await;
    let t = default_tenant(&app).id;
    let svc = service(&app);
    for schema in [
        json!({"$ref": "https://attacker.example/schema.json"}),
        json!({"$ref": "http://169.254.169.254/latest/meta-data"}),
        json!({"$ref": "file:///etc/passwd"}),
        json!({"type": "object", "properties": {"a": {"$ref": "https://attacker.example/x#/a"}}}),
        json!({"$id": "https://attacker.example/base/", "$ref": "other.json"}),
    ] {
        let start = Instant::now();
        assert_schema_refused(
            svc.define(
                t,
                admin(),
                &def("department", schema.clone(), false, true),
                &ctx(),
            )
            .await,
        );
        // Refused without waiting on any network.
        assert!(start.elapsed() < Duration::from_secs(2), "{schema}");
    }
    assert!(svc.list(t).await.unwrap().is_empty());
    assert_eq!(count(&app, t, AuditAction::AttributeDefined).await, 0);

    // A reference inside the schema is fine.
    let local = json!({
        "$defs": {"code": {"type": "string", "maxLength": 4}},
        "$ref": "#/$defs/code",
    });
    svc.define(t, admin(), &def("code", local, false, true), &ctx())
        .await
        .expect("local $ref accepted");
    let u = user(&app, "", t, "alice@example.com").await;
    let err = svc
        .set_user_values(
            t,
            admin(),
            u,
            &obj(json!({"code": "toolong"})),
            WriteMode::Replace,
            &ctx(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/code"]));
    svc.set_user_values(
        t,
        admin(),
        u,
        &obj(json!({"code": "ab"})),
        WriteMode::Replace,
        &ctx(),
    )
    .await
    .expect("valid against the local reference");
}

#[tokio::test]
async fn attribute_schema_size_capped() {
    let app = TestApp::new().await;
    let t = default_tenant(&app).id;
    let svc = service(&app);

    let big = json!({"type": "string", "description": "x".repeat(MAX_SCHEMA_BYTES)});
    assert_schema_refused(
        svc.define(t, admin(), &def("big", big, false, true), &ctx())
            .await,
    );

    let mut deep = json!({"type": "string"});
    for _ in 0..MAX_SCHEMA_DEPTH {
        deep = json!({"items": deep});
    }
    assert_schema_refused(
        svc.define(t, admin(), &def("deep", deep, false, true), &ctx())
            .await,
    );

    for meta_invalid in [
        json!({"type": "strng"}),
        json!({"minLength": -1}),
        json!({"pattern": "("}),
        json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
        json!("string"),
    ] {
        assert_schema_refused(
            svc.define(t, admin(), &def("bad", meta_invalid, false, true), &ctx())
                .await,
        );
    }

    // Names: syntax and the standard / protocol claims.
    for name in ["sub", "email", "name", "email_verified", "Dept", "1x", ""] {
        let result = svc
            .define(
                t,
                admin(),
                &def(name, json!({"type": "string"}), false, true),
                &ctx(),
            )
            .await;
        assert!(
            matches!(result, Err(CoreError::Validation { field: "name", .. })),
            "{name}: {result:?}"
        );
    }
    assert!(svc.list(t).await.unwrap().is_empty());
    assert_eq!(count(&app, t, AuditAction::AttributeDefined).await, 0);
}

#[tokio::test]
async fn attribute_pattern_is_linear_time() {
    let app = TestApp::new().await;
    let t = default_tenant(&app).id;
    let svc = service(&app);
    svc.define(
        t,
        admin(),
        &def(
            "code",
            json!({"type": "string", "pattern": "^(a+)+$"}),
            false,
            true,
        ),
        &ctx(),
    )
    .await
    .expect("pattern accepted");
    // Backtracking-only constructs do not compile on the linear-time engine.
    assert_schema_refused(
        svc.define(
            t,
            admin(),
            &def(
                "look",
                json!({"type": "string", "pattern": "(?=a)a"}),
                false,
                true,
            ),
            &ctx(),
        )
        .await,
    );

    let u = user(&app, "", t, "alice@example.com").await;
    let mut evil = "a".repeat(50 * 1024);
    evil.push('!');
    let start = Instant::now();
    let err = svc
        .set_user_values(
            t,
            admin(),
            u,
            &obj(json!({"code": evil})),
            WriteMode::Replace,
            &ctx(),
        )
        .await
        .unwrap_err();
    let elapsed = start.elapsed();
    assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/code"]));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[tokio::test]
async fn attribute_values_validated_on_write() {
    let app = TestApp::new().await;
    let t = default_tenant(&app).id;
    let svc = service(&app);
    let dept = def(
        "department",
        json!({"type": "string", "enum": ["eng", "ops"]}),
        false,
        true,
    );
    svc.define(t, admin(), &dept, &ctx())
        .await
        .expect("defined");
    svc.define(
        t,
        admin(),
        &def("cost_center", json!({"type": "integer"}), true, false),
        &ctx(),
    )
    .await
    .expect("defined");
    assert_eq!(count(&app, t, AuditAction::AttributeDefined).await, 2);
    let u = user(&app, "", t, "alice@example.com").await;

    // Valid write, audited.
    svc.set_user_values(
        t,
        admin(),
        u,
        &obj(json!({"department": "eng", "cost_center": 7})),
        WriteMode::Replace,
        &ctx(),
    )
    .await
    .expect("valid");
    assert_eq!(count(&app, t, AuditAction::UserAttributesUpdated).await, 1);

    let refusals: [(Value, WriteMode, Vec<&str>); 4] = [
        (
            json!({"department": "sales", "cost_center": 7}),
            WriteMode::Replace,
            vec!["/department"],
        ),
        (
            json!({"cost_center": 7, "shoe_size": 42}),
            WriteMode::Replace,
            vec!["/shoe_size"],
        ),
        (
            json!({"department": "ops"}),
            WriteMode::Replace,
            vec!["/cost_center"],
        ),
        (
            json!({"cost_center": "seven"}),
            WriteMode::Replace,
            vec!["/cost_center"],
        ),
    ];
    for (values, mode, pointers) in refusals {
        let err = svc
            .set_user_values(t, admin(), u, &obj(values.clone()), mode, &ctx())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AttributeError::Invalid(p) if *p == pointers),
            "{values}: {err:?}"
        );
    }
    // Self-service may not write a non-editable attribute.
    let err = svc
        .set_user_values(
            t,
            AuditActor::user(u),
            u,
            &obj(json!({"cost_center": 8})),
            WriteMode::SelfService,
            &ctx(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AttributeError::NotEditable(n) if n == vec!["cost_center"]));
    // Nothing of the refused writes was stored or audited.
    let stored = svc.user_values(t, u).await.unwrap();
    assert_eq!(stored, obj(json!({"department": "eng", "cost_center": 7})));
    assert_eq!(count(&app, t, AuditAction::UserAttributesUpdated).await, 1);

    // A schema change keeps the stored value even though it no longer validates.
    let mut narrowed = dept.clone();
    narrowed.schema = json!({"type": "string", "enum": ["ops"]});
    svc.define(t, admin(), &narrowed, &ctx())
        .await
        .expect("redefined");
    assert_eq!(svc.user_values(t, u).await.unwrap()["department"], "eng");

    // Deleting a definition keeps the value; later writes leave it alone.
    svc.delete(t, admin(), "department", &ctx())
        .await
        .expect("deleted");
    assert_eq!(count(&app, t, AuditAction::AttributeDeleted).await, 1);
    assert!(matches!(
        svc.delete(t, admin(), "department", &ctx()).await,
        Err(CoreError::NotFound)
    ));
    svc.set_user_values(
        t,
        admin(),
        u,
        &obj(json!({"cost_center": 9})),
        WriteMode::Replace,
        &ctx(),
    )
    .await
    .expect("valid");
    assert_eq!(
        svc.user_values(t, u).await.unwrap(),
        obj(json!({"department": "eng", "cost_center": 9}))
    );
    // Writing the orphaned key is refused like any unknown attribute.
    let err = svc
        .set_user_values(
            t,
            admin(),
            u,
            &obj(json!({"cost_center": 9, "department": "ops"})),
            WriteMode::Replace,
            &ctx(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/department"]));

    // The effective schema is a valid, compilable document of the current definitions.
    let effective = svc.effective_schema(t).await.unwrap();
    assert_eq!(effective["additionalProperties"], false);
    assert_eq!(effective["required"], json!(["cost_center"]));
    use anvil_core::ports::AttributeSchemaCheck as _;
    JsonSchemaCheck::new()
        .check_definition(&effective)
        .expect("effective schema compiles");
}

#[tokio::test]
async fn attribute_other_tenant_user_refused() {
    let app = TestApp::new().await;
    let home = default_tenant(&app).id;
    let acme = create_tenant(&app, "acme").await.id;
    let svc = service(&app);
    let dept = def("department", json!({"type": "string"}), false, true);
    svc.define(home, admin(), &dept, &ctx())
        .await
        .expect("defined");
    svc.define(acme, admin(), &dept, &ctx())
        .await
        .expect("defined");

    let alice = user(&app, "", home, "alice@example.com").await;
    let mallory = user(&app, "/t/acme", acme, "mallory@example.com").await;

    // Through the other tenant, the user does not exist: nothing is read or written.
    let err = svc
        .set_user_values(
            acme,
            admin(),
            alice,
            &obj(json!({"department": "x"})),
            WriteMode::Replace,
            &ctx(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, AttributeError::Core(CoreError::NotFound)),
        "{err:?}"
    );
    assert!(matches!(
        svc.user_values(acme, alice).await,
        Err(CoreError::NotFound)
    ));
    assert!(svc.user_values(home, alice).await.unwrap().is_empty());
    assert_eq!(
        count(&app, acme, AuditAction::UserAttributesUpdated).await,
        0
    );

    // Definitions are per tenant: deleting acme's leaves the home tenant's in place.
    svc.delete(acme, admin(), "department", &ctx())
        .await
        .unwrap();
    assert_eq!(svc.list(home).await.unwrap().len(), 1);
    assert!(svc.list(acme).await.unwrap().is_empty());
    // And mallory's tenant has no attribute to write any more.
    let err = svc
        .set_user_values(
            acme,
            admin(),
            mallory,
            &obj(json!({"department": "x"})),
            WriteMode::Replace,
            &ctx(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/department"]));
}
