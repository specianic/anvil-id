//! Breaking-change check for the versioned HTTP APIs (QUAL-03, docs/COMPATIBILITY.md).
//!
//! The documents generated from the handlers (`/api/admin/v1`, `/api/flows/v1`) are compared
//! with the committed 1.0 baselines (`docs/openapi/*.baseline-1.0.json`). Within 1.x only
//! additive changes are allowed. The comparator reduces each document to two sets of facts:
//!
//! - facts that must survive (`kept`): operations, response fields and enum values, accepted
//!   request fields, parameters, enum values and types, security alternatives, declared scopes.
//!   A baseline fact missing from the current document is a breaking removal or narrowing.
//! - facts that must not grow (`limited`): required request fields and parameters. A current
//!   fact absent from the baseline is breaking (a new required input).
//! - the types a response field may take (`response_types`): a field present in the baseline
//!   that may now be `null` or another type is breaking. New fields carry no constraint.
//!
//! The generated documents are used rather than the committed `admin-v1.json`/`flows-v1.json`,
//! so the check holds even before the drift tests are refreshed.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Value, json};

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn baseline(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../docs/openapi/{name}.baseline-1.0.json"));
    let text = std::fs::read_to_string(&path).expect("baseline-1.0.json is committed");
    serde_json::from_str(&text).expect("baseline is JSON")
}

fn generated(spec: utoipa::openapi::OpenApi) -> Value {
    serde_json::from_str(&spec.to_pretty_json().expect("serialises")).expect("JSON")
}

#[derive(Default)]
struct Facts {
    kept: BTreeSet<String>,
    limited: BTreeSet<String>,
    response_types: BTreeSet<String>,
}

#[derive(Default)]
struct Walked {
    fields: BTreeSet<String>,
    enums: BTreeSet<String>,
    types: BTreeSet<String>,
    required: BTreeSet<String>,
}

fn resolve<'a>(doc: &'a Value, reference: &str) -> &'a Value {
    let pointer = reference
        .strip_prefix('#')
        .unwrap_or_else(|| panic!("external $ref {reference}"));
    doc.pointer(pointer)
        .unwrap_or_else(|| panic!("dangling $ref {reference}"))
}

/// Collects field paths, enum values, types and (when every parent is required) required
/// fields below `schema`. `$ref` cycles stop at the first repetition.
fn walk(
    doc: &Value,
    schema: &Value,
    at: &str,
    required_chain: bool,
    stack: &mut Vec<String>,
    w: &mut Walked,
) {
    if let Some(r) = schema.get("$ref").and_then(Value::as_str)
        && !stack.iter().any(|s| s == r)
    {
        stack.push(r.to_owned());
        walk(doc, resolve(doc, r), at, required_chain, stack, w);
        stack.pop();
    }
    match schema.get("type") {
        Some(Value::String(t)) => {
            w.types.insert(format!("{at}: {t}"));
        }
        Some(Value::Array(ts)) => {
            for t in ts.iter().filter_map(Value::as_str) {
                w.types.insert(format!("{at}: {t}"));
            }
        }
        _ => {}
    }
    for v in schema
        .get("enum")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        w.enums.insert(format!("{at}={v}"));
    }
    if let Some(v) = schema.get("const") {
        w.enums.insert(format!("{at}={v}"));
    }
    for s in schema
        .get("allOf")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(doc, s, at, required_chain, stack, w);
    }
    // A variant's required fields only apply when that variant is chosen.
    for key in ["oneOf", "anyOf"] {
        for s in schema
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(doc, s, at, false, stack, w);
        }
    }
    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        let required: BTreeSet<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for (name, sub) in props {
            let path = format!("{at}.{name}");
            let is_required = required_chain && required.contains(name.as_str());
            w.fields.insert(path.clone());
            if is_required {
                w.required.insert(path.clone());
            }
            walk(doc, sub, &path, is_required, stack, w);
        }
    }
    if let Some(items) = schema.get("items").filter(|i| i.is_object()) {
        walk(doc, items, &format!("{at}[]"), false, stack, w);
    }
    if let Some(extra) = schema.get("additionalProperties").filter(|a| a.is_object()) {
        walk(doc, extra, &format!("{at}{{}}"), false, stack, w);
    }
}

fn walked(doc: &Value, schema: &Value, at: &str, required: bool) -> Walked {
    let mut w = Walked::default();
    walk(doc, schema, at, required, &mut Vec::new(), &mut w);
    w
}

fn security_alternative(req: &Value) -> String {
    let parts: Vec<String> = req
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(scheme, scopes)| {
                    let mut s: Vec<&str> = scopes
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect();
                    s.sort_unstable();
                    format!("{scheme}[{}]", s.join(" "))
                })
                .collect()
        })
        .unwrap_or_default();
    if parts.is_empty() {
        "(none)".to_owned()
    } else {
        parts.join(" & ")
    }
}

fn facts(doc: &Value) -> Facts {
    let mut f = Facts::default();
    let schemes = doc
        .pointer("/components/securitySchemes")
        .and_then(Value::as_object);
    for (name, scheme) in schemes.into_iter().flatten() {
        f.kept.insert(format!("security scheme {name}"));
        for flow in scheme
            .get("flows")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            for scope in flow
                .1
                .get("scopes")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                f.kept.insert(format!("declared scope {name}:{}", scope.0));
            }
        }
    }
    let paths = doc.get("paths").and_then(Value::as_object);
    for (path, item) in paths.into_iter().flatten() {
        let shared = item.get("parameters").and_then(Value::as_array);
        for method in METHODS {
            let Some(op_doc) = item.get(method) else {
                continue;
            };
            let op = format!("{} {path}", method.to_uppercase());
            f.kept.insert(format!("operation {op}"));

            let own = op_doc.get("parameters").and_then(Value::as_array);
            for p in shared
                .into_iter()
                .flatten()
                .chain(own.into_iter().flatten())
            {
                let p = match p.get("$ref").and_then(Value::as_str) {
                    Some(r) => resolve(doc, r),
                    None => p,
                };
                let at = format!(
                    "{op} param {}:{}",
                    p["in"].as_str().unwrap_or("?"),
                    p["name"]
                );
                f.kept.insert(format!("request {at}"));
                if p.get("required").and_then(Value::as_bool) == Some(true) {
                    f.limited.insert(format!("required request {at}"));
                }
                let w = walked(doc, p.get("schema").unwrap_or(&Value::Null), &at, false);
                f.kept
                    .extend(w.enums.into_iter().map(|e| format!("request enum {e}")));
                f.kept
                    .extend(w.types.into_iter().map(|t| format!("request type {t}")));
            }

            if let Some(body) = op_doc.get("requestBody") {
                let body_required = body.get("required").and_then(Value::as_bool) == Some(true);
                if body_required {
                    f.limited.insert(format!("required request {op} body"));
                }
                for (ct, media) in body
                    .get("content")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                {
                    let at = format!("{op} body({ct})");
                    f.kept.insert(format!("request content {at}"));
                    let schema = media.get("schema").unwrap_or(&Value::Null);
                    let w = walked(doc, schema, &at, body_required);
                    f.kept
                        .extend(w.fields.into_iter().map(|x| format!("request field {x}")));
                    f.kept
                        .extend(w.enums.into_iter().map(|e| format!("request enum {e}")));
                    f.kept
                        .extend(w.types.into_iter().map(|t| format!("request type {t}")));
                    f.limited.extend(
                        w.required
                            .into_iter()
                            .map(|r| format!("required request {r}")),
                    );
                }
            }

            let responses = op_doc.get("responses").and_then(Value::as_object);
            for (status, resp) in responses.into_iter().flatten() {
                f.kept.insert(format!("response {op} {status}"));
                for (ct, media) in resp
                    .get("content")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                {
                    let at = format!("{op} {status} {ct} $");
                    f.kept
                        .insert(format!("response content {op} {status} {ct}"));
                    let w = walked(doc, media.get("schema").unwrap_or(&Value::Null), &at, false);
                    f.kept
                        .extend(w.fields.into_iter().map(|x| format!("response field {x}")));
                    f.kept
                        .extend(w.enums.into_iter().map(|e| format!("response enum {e}")));
                    f.response_types.extend(w.types);
                }
            }

            match op_doc.get("security").and_then(Value::as_array) {
                Some(alts) if !alts.is_empty() => {
                    for alt in alts {
                        f.kept
                            .insert(format!("security {op}: {}", security_alternative(alt)));
                    }
                }
                _ => {
                    f.kept.insert(format!("security {op}: (none)"));
                }
            }
        }
    }
    f
}

/// Every breaking difference of `current` relative to `base`, one message each.
fn breaking_changes(base: &Value, current: &Value) -> Vec<String> {
    let (b, c) = (facts(base), facts(current));
    let removed = b
        .kept
        .difference(&c.kept)
        .map(|x| format!("removed or narrowed: {x}"));
    let added = c
        .limited
        .difference(&b.limited)
        .map(|x| format!("new constraint: {x}"));
    let typed: BTreeSet<&str> = b
        .response_types
        .iter()
        .filter_map(|t| t.rsplit_once(": ").map(|(field, _)| field))
        .collect();
    let widened = c
        .response_types
        .difference(&b.response_types)
        .filter(|t| {
            t.rsplit_once(": ")
                .is_some_and(|(field, _)| typed.contains(field))
        })
        .map(|t| format!("new constraint: response type {t}"));
    removed.chain(added).chain(widened).collect()
}

fn assert_compatible(name: &str, current: &Value) {
    let breaks = breaking_changes(&baseline(name), current);
    assert!(
        breaks.is_empty(),
        "{name}: breaking changes against docs/openapi/{name}.baseline-1.0.json \
         (see docs/COMPATIBILITY.md; a breaking change needs a new major version):\n{}",
        breaks.join("\n")
    );
}

fn assert_detected(base: &Value, mutated: &Value, needle: &str) {
    let breaks = breaking_changes(base, mutated);
    assert!(
        breaks.iter().any(|b| b.contains(needle)),
        "expected a breaking change mentioning {needle:?}, got {breaks:#?}"
    );
}

#[test]
fn api_compat_admin_has_no_breaking_change() {
    assert_compatible("admin-v1", &generated(anvil_web::admin::openapi()));
}

#[test]
fn api_compat_flows_has_no_breaking_change() {
    assert_compatible("flows-v1", &generated(anvil_web::api_flows::openapi()));
}

#[test]
fn api_compat_baseline_is_compatible_with_itself_and_has_facts() {
    for name in ["admin-v1", "flows-v1"] {
        let base = baseline(name);
        assert!(breaking_changes(&base, &base).is_empty());
        let f = facts(&base);
        assert!(f.kept.iter().any(|k| k.starts_with("operation ")), "{name}");
        assert!(
            f.kept.iter().any(|k| k.starts_with("response field ")),
            "{name}"
        );
        assert!(
            f.limited.iter().any(|k| k.starts_with("required request ")),
            "{name}"
        );
    }
}

#[test]
fn api_compat_detects_removed_operation() {
    for name in ["admin-v1", "flows-v1"] {
        let base = baseline(name);
        let mut mutated = base.clone();
        let paths = mutated["paths"].as_object_mut().unwrap();
        let (path, item) = paths.iter_mut().next().unwrap();
        let path = path.clone();
        let item = item.as_object_mut().unwrap();
        let method = METHODS.iter().find(|m| item.contains_key(**m)).unwrap();
        item.remove(*method);
        assert_detected(
            &base,
            &mutated,
            &format!("operation {} {path}", method.to_uppercase()),
        );
    }
}

#[test]
fn api_compat_detects_removed_response_field() {
    let base = baseline("admin-v1");
    let mut mutated = base.clone();
    let tenant = &mut mutated["components"]["schemas"]["TenantView"]["properties"];
    tenant
        .as_object_mut()
        .unwrap()
        .remove("issuer")
        .expect("TenantView.issuer");
    assert_detected(
        &base,
        &mutated,
        "response field GET /api/admin/v1/tenants 200 application/json $.items[].issuer",
    );

    // A removed enum value is a removal too.
    let mut mutated = base.clone();
    mutated["components"]["schemas"]["UserStatus"]["enum"] = json!(["active"]);
    assert_detected(&base, &mutated, "response enum");
    assert_detected(&base, &mutated, "=\"blocked\"");

    // A response field that may now be null (or change type) breaks readers.
    let mut mutated = base.clone();
    mutated["components"]["schemas"]["TenantView"]["properties"]["issuer"]["type"] =
        json!(["string", "null"]);
    assert_detected(
        &base,
        &mutated,
        "response type GET /api/admin/v1/tenants/{slug} 200 application/json $.issuer: null",
    );
}

#[test]
fn api_compat_detects_new_required_request_field() {
    let base = baseline("admin-v1");
    let mut mutated = base.clone();
    let create = &mut mutated["components"]["schemas"]["CreateTenant"];
    create["properties"]["region"] = json!({"type": "string"});
    create["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("region"));
    assert_detected(
        &base,
        &mutated,
        "required request POST /api/admin/v1/tenants body(application/json).region",
    );

    // An optional field becoming required, and a type narrowing, are caught as well.
    let mut mutated = base.clone();
    let create = &mut mutated["components"]["schemas"]["CreateTenant"];
    create["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("host"));
    create["properties"]["host"] = json!({"type": "string"});
    assert_detected(&base, &mutated, "body(application/json).host");
    assert_detected(
        &base,
        &mutated,
        "request type POST /api/admin/v1/tenants body(application/json).host: null",
    );
}

#[test]
fn api_compat_detects_removed_scope() {
    let base = baseline("admin-v1");
    let mut mutated = base.clone();
    let security = mutated["paths"]["/api/admin/v1/tenants"]["get"]["security"]
        .as_array_mut()
        .unwrap();
    security.retain(|alt| alt != &json!({"oauth2": ["admin:read"]}));
    assert_detected(
        &base,
        &mutated,
        "security GET /api/admin/v1/tenants: oauth2[admin:read]",
    );

    let mut mutated = base.clone();
    mutated["components"]["securitySchemes"]["oauth2"]["flows"]["clientCredentials"]["scopes"]
        .as_object_mut()
        .unwrap()
        .remove("admin:users:export")
        .expect("admin:users:export declared");
    assert_detected(&base, &mutated, "declared scope oauth2:admin:users:export");
}

#[test]
fn api_compat_allows_added_optional_field() {
    let base = baseline("admin-v1");
    let mut mutated = base.clone();
    let schemas = &mut mutated["components"]["schemas"];
    schemas["CreateTenant"]["properties"]["region"] = json!({"type": ["string", "null"]});
    schemas["TenantView"]["properties"]["region"] = json!({"type": "string"});
    schemas["UserStatus"]["enum"]
        .as_array_mut()
        .unwrap()
        .push(json!("suspended"));
    schemas["CreateTenant"]["properties"]["display_name"] = json!({"type": ["string", "null"]});
    // A new operation, a widened request type and an extra security alternative are additive.
    mutated["paths"]["/api/admin/v1/regions"] = json!({"get": {
        "responses": {"200": {"description": "ok"}},
        "security": [{"oauth2": ["admin:read"]}]
    }});
    mutated["paths"]["/api/admin/v1/tenants"]["get"]["security"]
        .as_array_mut()
        .unwrap()
        .push(json!({"oauth2": ["admin:tenants:list"]}));
    let breaks = breaking_changes(&base, &mutated);
    assert!(breaks.is_empty(), "{breaks:#?}");
}
