//! Offline JSON Schema check for custom user attributes (`ports::AttributeSchemaCheck`).
//!
//! Built on `jsonschema` with default features off (no HTTP or file resolver is compiled in):
//!
//! - Draft 2020-12 only; a `$schema` naming anything else is refused.
//! - Every external reference is refused by [`RefuseExternal`]; only references inside the
//!   schema (`#/$defs/...`) resolve. No network or file access can happen.
//! - `pattern` / `patternProperties` use the `regex` engine (linear time, no backtracking, so
//!   no ReDoS); constructs it cannot compile (look-around, back-references) are refused.
//! - Formats (`email`, `date`, `uri`, ...) are validated, not just annotated.
//! - Admin schemas are meta-validated, then compiled. Size ([`MAX_SCHEMA_BYTES`]) and nesting
//!   depth ([`MAX_SCHEMA_DEPTH`]) are capped before either step.
//!
//! Validation errors report JSON pointers into the instance only, never the values.

use std::io::Write;
use std::sync::Arc;

use anvil_core::model::MAX_SCHEMA_BYTES;
use anvil_core::ports::{AttributeSchemaCheck, SchemaIssue};
use jsonschema::{Draft, PatternOptions, Retrieve, Uri, Validator};
use serde_json::Value;

use crate::state::AppState;

/// Deepest accepted nesting of objects and arrays in a schema (the root object is depth 1).
pub const MAX_SCHEMA_DEPTH: usize = 32;

/// The only accepted `$schema` value (absent is accepted too).
const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

/// Refuses every external resource, so schema compilation never performs I/O.
struct RefuseExternal;

impl Retrieve for RefuseExternal {
    fn retrieve(
        &self,
        _uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("external schema references are not allowed".into())
    }
}

/// The `jsonschema` adapter behind `AttributeSchemaCheck`.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonSchemaCheck;

impl JsonSchemaCheck {
    pub fn new() -> Self {
        Self
    }
}

fn issue(message: impl Into<String>) -> SchemaIssue {
    SchemaIssue {
        message: message.into(),
    }
}

/// A writer that only counts, and fails once the limit is passed (stops serializing early).
struct CappedCounter {
    len: usize,
}

impl Write for CappedCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.len += buf.len();
        if self.len > MAX_SCHEMA_BYTES {
            return Err(std::io::Error::other("too large"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn within_size(schema: &Value) -> bool {
    serde_json::to_writer(&mut CappedCounter { len: 0 }, schema).is_ok()
}

/// Whether the nesting depth is at most `MAX_SCHEMA_DEPTH` (explicit stack, early exit).
fn within_depth(schema: &Value) -> bool {
    let mut stack: Vec<(&Value, usize)> = vec![(schema, 1)];
    while let Some((v, depth)) = stack.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match v {
            Value::Object(m) => Box::new(m.values()),
            Value::Array(a) => Box::new(a.iter()),
            _ => continue,
        };
        if depth > MAX_SCHEMA_DEPTH {
            return false;
        }
        stack.extend(children.map(|c| (c, depth + 1)));
    }
    true
}

/// Shape, size, depth and `$schema` checks that run before any parsing by `jsonschema`.
fn precheck(schema: &Value) -> Result<(), SchemaIssue> {
    let Some(obj) = schema.as_object() else {
        return Err(issue("the schema must be a JSON object"));
    };
    if !within_size(schema) {
        return Err(issue(format!(
            "the schema must be at most {MAX_SCHEMA_BYTES} bytes"
        )));
    }
    if !within_depth(schema) {
        return Err(issue(format!(
            "the schema must be nested at most {MAX_SCHEMA_DEPTH} levels deep"
        )));
    }
    match obj.get("$schema") {
        None => Ok(()),
        Some(Value::String(s)) if s.trim_end_matches('#') == DRAFT_2020_12 => Ok(()),
        Some(_) => Err(issue(format!(
            "only JSON Schema draft 2020-12 is supported ($schema: {DRAFT_2020_12})"
        ))),
    }
}

fn compile(schema: &Value) -> Result<Validator, SchemaIssue> {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_pattern_options(PatternOptions::regex())
        .with_retriever(RefuseExternal)
        .build(schema)
        .map_err(|e| issue(format!("the schema does not compile: {e}")))
}

impl AttributeSchemaCheck for JsonSchemaCheck {
    fn check_definition(&self, schema: &Value) -> Result<(), SchemaIssue> {
        precheck(schema)?;
        jsonschema::draft202012::meta::validate(schema).map_err(|e| {
            issue(format!(
                "the schema is not valid JSON Schema at {}: {}",
                pointer_or_root(&e.instance_path().to_string()),
                short_message(&e)
            ))
        })?;
        compile(schema).map(|_| ())
    }

    fn validate(&self, schema: &Value, instance: &Value) -> Result<(), Vec<String>> {
        // A schema that no longer passes the checks validates nothing (fail closed).
        let validator = precheck(schema)
            .and_then(|()| compile(schema))
            .map_err(|_| vec![String::new()])?;
        let mut pointers: Vec<String> = validator
            .iter_errors(instance)
            .map(|e| e.instance_path().to_string())
            .collect();
        if pointers.is_empty() {
            return Ok(());
        }
        pointers.sort();
        pointers.dedup();
        Err(pointers)
    }
}

fn pointer_or_root(p: &str) -> &str {
    if p.is_empty() { "the root" } else { p }
}

/// A meta-validation message bounded to 200 characters (it may quote parts of the schema).
fn short_message(e: &jsonschema::ValidationError<'_>) -> String {
    let full = e.to_string();
    let mut short: String = full.chars().take(200).collect();
    if short.len() < full.len() {
        short.push_str("...");
    }
    short
}

impl AppState {
    /// The attribute schema check handed to the token and UserInfo services.
    pub(crate) fn attribute_check(&self) -> Option<Arc<dyn AttributeSchemaCheck>> {
        Some(Arc::new(JsonSchemaCheck::new()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;

    fn check() -> JsonSchemaCheck {
        JsonSchemaCheck::new()
    }

    #[test]
    fn valid_schema_is_accepted_and_validates() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "cost_center": {"type": "integer", "minimum": 1},
                "code": {"$ref": "#/$defs/code"},
            },
            "required": ["cost_center"],
            "$defs": {"code": {"type": "string", "maxLength": 4}},
        });
        check().check_definition(&schema).unwrap();
        check()
            .validate(&schema, &json!({"cost_center": 3, "code": "ab"}))
            .unwrap();
        let err = check()
            .validate(&schema, &json!({"cost_center": 0, "code": "abcdef"}))
            .unwrap_err();
        assert_eq!(err, vec!["/code".to_owned(), "/cost_center".to_owned()]);
        assert_eq!(
            check().validate(&schema, &json!({})).unwrap_err(),
            vec![String::new()]
        );
    }

    #[test]
    fn remote_ref_is_refused_without_network() {
        for schema in [
            json!({"$ref": "https://evil/x"}),
            json!({"$ref": "http://169.254.169.254/latest/meta-data"}),
            json!({"$ref": "file:///etc/passwd"}),
            json!({"$id": "https://evil/base/", "$ref": "other.json"}),
            json!({"properties": {"a": {"$ref": "https://evil/x#/a"}}}),
        ] {
            let start = Instant::now();
            assert!(check().check_definition(&schema).is_err(), "{schema}");
            // A refused reference never validates anything either.
            assert!(check().validate(&schema, &json!("x")).is_err(), "{schema}");
            assert!(start.elapsed() < Duration::from_secs(1));
        }
    }

    #[test]
    fn retriever_refuses_everything() {
        let uri = jsonschema::uri::from_str("https://evil/x").unwrap();
        assert!(RefuseExternal.retrieve(&uri).is_err());
    }

    #[test]
    fn redos_pattern_runs_in_linear_time() {
        let schema = json!({"type": "string", "pattern": "(a+)+$"});
        check().check_definition(&schema).unwrap();
        let mut evil = "a".repeat(50 * 1024);
        evil.push('b');
        let start = Instant::now();
        let result = check().validate(&schema, &Value::String(evil));
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
    }

    #[test]
    fn backtracking_only_patterns_are_refused() {
        for pattern in ["(?=a)a", "(a)\\1", "(?<!x)y"] {
            let schema = json!({"type": "string", "pattern": pattern});
            assert!(check().check_definition(&schema).is_err(), "{pattern}");
        }
    }

    #[test]
    fn oversized_schema_is_refused() {
        let schema = json!({"type": "string", "description": "x".repeat(MAX_SCHEMA_BYTES)});
        let err = check().check_definition(&schema).unwrap_err();
        assert!(err.message.contains("bytes"), "{err:?}");
        assert!(check().validate(&schema, &json!("x")).is_err());
    }

    #[test]
    fn deeply_nested_schema_is_refused() {
        let mut nested = json!({"type": "string"});
        for _ in 0..MAX_SCHEMA_DEPTH {
            nested = json!({"items": nested});
        }
        let err = check().check_definition(&nested).unwrap_err();
        assert!(err.message.contains("levels"), "{err:?}");

        let mut ok = json!({"type": "string"});
        for _ in 0..(MAX_SCHEMA_DEPTH - 1) {
            ok = json!({"items": ok});
        }
        assert!(within_depth(&ok));
        check().check_definition(&ok).unwrap();
    }

    #[test]
    fn email_format_is_validated() {
        let schema = json!({"type": "string", "format": "email"});
        check().check_definition(&schema).unwrap();
        assert!(
            check()
                .validate(&schema, &json!("alice@example.test"))
                .is_ok()
        );
        assert_eq!(
            check()
                .validate(&schema, &json!("not-an-email"))
                .unwrap_err(),
            vec![String::new()]
        );
    }

    #[test]
    fn non_object_and_meta_invalid_schemas_are_refused() {
        for schema in [
            json!(true),
            json!(false),
            json!("string"),
            json!(["type"]),
            json!(null),
            json!({"type": "strng"}),
            json!({"minLength": -1}),
            json!({"required": "name"}),
            json!({"properties": []}),
            json!({"pattern": "("}),
            json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
            json!({"$schema": 7}),
        ] {
            assert!(check().check_definition(&schema).is_err(), "{schema}");
        }
        assert!(
            check()
                .check_definition(
                    &json!({"$schema": "https://json-schema.org/draft/2020-12/schema#"})
                )
                .is_ok()
        );
    }

    #[test]
    fn errors_never_echo_instance_values() {
        let schema = json!({"type": "object", "properties": {"pin": {"type": "integer"}}});
        let err = check()
            .validate(&schema, &json!({"pin": "SECRET-VALUE"}))
            .unwrap_err();
        assert_eq!(err, vec!["/pin".to_owned()]);
    }
}
