//! The committed OpenAPI document of the headless flow API (`docs/openapi/flows-v1.json`) must
//! match the one generated from the handlers. Refresh it with `just openapi-update`
//! (`UPDATE_OPENAPI=1`).

use std::path::PathBuf;

use serde_json::Value;

fn committed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/openapi/flows-v1.json")
}

fn generated() -> String {
    let mut spec = anvil_web::api_flows::openapi()
        .to_pretty_json()
        .expect("the OpenAPI document serialises");
    spec.push('\n');
    spec
}

#[test]
fn committed_flows_spec_matches_generated() {
    let spec = generated();
    let path = committed_path();
    if std::env::var("UPDATE_OPENAPI").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("docs/openapi")).expect("create docs/openapi");
        std::fs::write(&path, &spec).expect("write docs/openapi/flows-v1.json");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == spec,
        "docs/openapi/flows-v1.json is out of date with the headless flow API; \
         run `just openapi-update` and commit the result"
    );
}

#[test]
fn flows_spec_is_openapi_3_1_v1_with_every_route() {
    let doc: Value = serde_json::from_str(&generated()).expect("JSON");
    assert!(doc["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(doc["info"]["title"], "AnvilID headless flow API");
    assert_eq!(doc["info"]["version"], "v1");
    let paths = doc["paths"].as_object().expect("paths");
    for p in [
        "/api/flows/v1/{kind}",
        "/api/flows/v1/{kind}/{flow_id}",
        "/api/flows/v1/login/{flow_id}/passkey/options",
        "/api/flows/v1/login/{flow_id}/passkey",
        "/api/flows/v1/login/{flow_id}/enroll/passkey/start",
        "/api/flows/v1/login/{flow_id}/enroll/passkey/finish",
        "/api/flows/v1/login/{flow_id}/second-factor/passkey/start",
        "/api/flows/v1/login/{flow_id}/second-factor/passkey/finish",
    ] {
        assert!(paths.contains_key(p), "{p} missing");
    }
    for (path, item) in paths {
        assert!(path.starts_with("/api/flows/v1/"), "{path}");
        for (method, op) in item.as_object().expect("operations") {
            // Every request about an existing flow needs the CSRF header.
            if path.contains("{flow_id}") {
                assert!(op["security"].is_array(), "{method} {path} has no security");
            }
            assert!(op["responses"]["403"].is_object(), "{method} {path}");
        }
    }
    // The internal form description is not part of the contract.
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    assert!(schemas.contains_key("FlowResponse"));
    assert!(!schemas.contains_key("FormDescription"));
    let form = &schemas["FormDto"]["properties"];
    for k in ["action", "method", "csrf_token"] {
        assert!(form.get(k).is_none(), "FormDto.{k}");
    }
}
