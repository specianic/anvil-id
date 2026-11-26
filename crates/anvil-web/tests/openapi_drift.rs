//! The committed OpenAPI document (`docs/openapi/admin-v1.json`) must match the one generated
//! from the handlers. Refresh it with `just openapi-update` (`UPDATE_OPENAPI=1`).

mod support;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anvil_core::service::admin_scope::ALL_ADMIN_SCOPES;
use serde_json::Value;
use support::{TestApp, json};

fn committed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi/admin-v1.json")
}

fn generated() -> String {
    let mut spec = anvil_web::admin::openapi()
        .to_pretty_json()
        .expect("the OpenAPI document serialises");
    spec.push('\n');
    spec
}

#[test]
fn committed_spec_matches_generated() {
    let spec = generated();
    let path = committed_path();
    if std::env::var("UPDATE_OPENAPI").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("docs/openapi")).expect("create docs/openapi");
        std::fs::write(&path, &spec).expect("write docs/openapi/admin-v1.json");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == spec,
        "docs/openapi/admin-v1.json is out of date with the management API; \
         run `just openapi-update` and commit the result"
    );
}

#[test]
fn spec_is_openapi_3_1_with_oauth2_admin_scopes() {
    let doc: Value = serde_json::from_str(&generated()).expect("JSON");
    assert!(doc["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(doc["info"]["title"], "AnvilID Management API");
    assert_eq!(doc["info"]["version"], "v1");

    let scheme = &doc["components"]["securitySchemes"]["oauth2"];
    assert_eq!(scheme["type"], "oauth2");
    let flow = &scheme["flows"]["clientCredentials"];
    assert_eq!(flow["tokenUrl"], "/t/system/token");
    let scopes: BTreeSet<&str> = flow["scopes"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = ALL_ADMIN_SCOPES.iter().copied().collect();
    assert_eq!(scopes, expected);

    // Every operation requires the oauth2 scheme with admin scopes only.
    let paths = doc["paths"].as_object().unwrap();
    assert!(paths.keys().any(|p| p.contains("/clients")));
    let mut operations = 0;
    for (path, item) in paths {
        assert!(path.starts_with("/api/admin/v1/"), "{path}");
        for (method, op) in item.as_object().unwrap() {
            operations += 1;
            let security = op["security"]
                .as_array()
                .unwrap_or_else(|| panic!("{method} {path} has no security"));
            assert!(!security.is_empty(), "{method} {path}");
            for req in security {
                let granted = req["oauth2"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{method} {path}: {req}"));
                assert!(!granted.is_empty());
                for s in granted {
                    assert!(
                        expected.contains(s.as_str().unwrap()),
                        "{method} {path}: {s}"
                    );
                }
            }
            assert!(op["responses"]["401"].is_object(), "{method} {path}");
            assert!(op["responses"]["403"].is_object(), "{method} {path}");
        }
    }
    assert_eq!(operations, 102);
}

#[tokio::test]
async fn served_spec_is_public_and_matches() {
    let app = TestApp::new().await;
    let resp = app.get("/api/admin/v1/openapi.json").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("content-type"), Some("application/json"));
    let served = json(&resp);
    let generated: Value = serde_json::from_str(&generated()).unwrap();
    assert_eq!(served, generated);
    // Deterministic: no deployment URL leaks into the document.
    assert!(!resp.text().contains("op.test"));
}
