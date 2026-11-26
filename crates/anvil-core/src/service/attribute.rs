//! Custom user attribute definitions and values (ADM-06, AUTH-14).
//!
//! # Definitions
//!
//! A tenant defines attributes ([`AttributeDefinition`]): a name, a JSON Schema fragment for the
//! value, `required`, `user_editable` and an optional claim rule. [`AttributeService::define`]
//! creates or replaces one (the name is the natural key) after these checks, in order:
//!
//! 1. the name syntax ([`validate_attribute_name`]) and no collision with a reserved protocol or
//!    standard claim ([`is_reserved_claim`]: `sub`, `email`, `name`, ...);
//! 2. the schema size ([`check_schema_size`], 16 KiB), then [`AttributeSchemaCheck::check_definition`]:
//!    meta-validated against draft 2020-12, depth-capped, compiled offline (every remote `$ref`
//!    is refused, patterns run on a linear-time engine);
//! 3. the tenant's whole claim mapping with this definition in place ([`validate_mapping`]: no
//!    reserved claim, no two rules producing the same claim).
//!
//! Every successful change records one audit event (`attribute_defined` / `attribute_deleted`,
//! target and details = the attribute name). Failed calls record nothing.
//!
//! # Values
//!
//! A user's values are one JSON object keyed by attribute name. Every write goes through
//! [`AttributeService::set_user_values`] and is validated against the tenant's definitions as one
//! object, equivalent to [`effective_schema`] (`type: object`, `additionalProperties: false`,
//! `required`, each property = its fragment):
//!
//! - a key without a definition is refused (`/name`);
//! - a missing required attribute is refused (`/name`);
//! - each value is validated against its own fragment; errors are JSON pointers into the object
//!   (`/name`, `/name/0`, ...), never the values.
//!
//! Each fragment is validated on its own (not through the assembled document) so that the size
//! and depth caps apply per definition and `#/$defs/...` references inside a fragment resolve
//! against that fragment.
//!
//! [`WriteMode::Replace`] (administrator) replaces every defined value with the submitted object;
//! [`WriteMode::SelfService`] (account page) patches the submitted keys only, refuses keys whose
//! definition is not `user_editable` ([`AttributeError::NotEditable`]), and treats `null` as
//! "remove this value". In both modes stored keys that have no definition any more are kept
//! unchanged: deleting a definition or changing its schema never rewrites stored data (claims
//! filter invalid values at issue time, `policy::claims_mapping`). A stored value that no longer
//! validates blocks further writes until it is corrected or removed.
//!
//! A write that changes nothing is not stored or audited; otherwise one `user_attributes_updated`
//! event is recorded (target = user id, details = the number of changed attributes).

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::flow::settings::SettingsState;
use crate::model::{
    AttributeDefinition, AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession,
    FlowKind, RequestContext, TenantId, UserId, check_schema_size, validate_attribute_name,
};
use crate::policy::claims_mapping::{is_reserved_claim, validate_mapping};
use crate::ports::{AttributeSchemaCheck, Storage};
use crate::service::account::SettingsBinding;
use crate::service::audit::AuditService;
use crate::service::flow::{BindingError, check_binding};

/// `$id` prefix given to each fragment inside [`effective_schema`], so references inside a
/// fragment resolve against the fragment.
pub const FRAGMENT_ID_PREFIX: &str = "urn:anvilid:attribute:";

/// Why a value write was refused.
#[derive(Debug)]
pub enum AttributeError {
    /// The values do not validate. JSON pointers into the submitted object (`/department`,
    /// `/tags/0`; `""` = the object as a whole), sorted and unique. Never the values.
    Invalid(Vec<String>),
    /// A self-service write named attributes the user may not edit (their names, sorted).
    NotEditable(Vec<String>),
    /// The account page's settings flow expired; show the page again with a fresh flow.
    FlowExpired,
    /// Anything else: `Forbidden` for a broken settings binding, `NotFound` for a user outside
    /// the tenant, storage errors.
    Core(CoreError),
}

impl From<CoreError> for AttributeError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

impl From<crate::ports::StorageError> for AttributeError {
    fn from(e: crate::ports::StorageError) -> Self {
        Self::Core(e.into())
    }
}

/// How submitted values combine with the stored ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Administrator: the submitted object replaces every defined value.
    Replace,
    /// Account page: only the submitted keys change, each must be `user_editable`; `null`
    /// removes the value.
    SelfService,
}

/// The result of combining a submission with the stored values.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedValues {
    /// The complete object to store (including stored keys without a definition).
    pub values: Map<String, Value>,
    /// Names of the defined attributes whose value changes, sorted.
    pub changed: Vec<String>,
}

/// The tenant's definitions assembled into one JSON Schema for the user's attribute object:
/// `additionalProperties: false`, `required` = the required names, each property = the
/// definition's fragment (given an `$id` under [`FRAGMENT_ID_PREFIX`] when it has none).
pub fn effective_schema(definitions: &[AttributeDefinition]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for def in definitions {
        let mut fragment = def.schema.clone();
        if let Value::Object(obj) = &mut fragment
            && !obj.contains_key("$id")
        {
            obj.insert(
                "$id".into(),
                Value::from(format!("{FRAGMENT_ID_PREFIX}{}", def.name)),
            );
        }
        properties.insert(def.name.clone(), fragment);
        if def.required {
            required.push(Value::from(def.name.clone()));
        }
    }
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    })
}

fn invalid(field: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// Checks a definition: name, reserved claims, schema (size, meta, offline compile) and the
/// claim rule against the rest of the tenant's mapping (`others` = the other definitions).
pub fn check_definition(
    definition: &AttributeDefinition,
    others: &[AttributeDefinition],
    claims: &crate::model::ClaimMappingSettings,
    check: &dyn AttributeSchemaCheck,
) -> Result<(), CoreError> {
    validate_attribute_name(&definition.name)?;
    if is_reserved_claim(&definition.name) {
        return Err(invalid(
            "name",
            format!(
                "{:?} is a reserved protocol or standard claim name",
                definition.name
            ),
        ));
    }
    check_schema_size(&definition.schema)?;
    check
        .check_definition(&definition.schema)
        .map_err(|issue| invalid("schema", issue.message))?;
    let mut all: Vec<AttributeDefinition> = others
        .iter()
        .filter(|d| d.name != definition.name)
        .cloned()
        .collect();
    all.push(definition.clone());
    validate_mapping(claims, &all)
}

/// `/name` as a JSON pointer (RFC 6901 escaping; attribute names never need it, unknown keys
/// may).
fn pointer(name: &str) -> String {
    format!("/{}", name.replace('~', "~0").replace('/', "~1"))
}

/// Combines a submission with the stored values and validates the result (see the module docs).
pub fn plan_values(
    definitions: &[AttributeDefinition],
    stored: &Map<String, Value>,
    submitted: &Map<String, Value>,
    mode: WriteMode,
    check: &dyn AttributeSchemaCheck,
) -> Result<PlannedValues, AttributeError> {
    let def_of = |name: &str| definitions.iter().find(|d| d.name == name);

    let unknown: Vec<String> = submitted
        .keys()
        .filter(|k| def_of(k).is_none())
        .map(|k| pointer(k))
        .collect();
    if !unknown.is_empty() {
        return Err(AttributeError::Invalid(sorted(unknown)));
    }

    let mut values = stored.clone();
    match mode {
        WriteMode::Replace => {
            for def in definitions {
                values.remove(&def.name);
            }
            for (k, v) in submitted {
                values.insert(k.clone(), v.clone());
            }
        }
        WriteMode::SelfService => {
            let locked: Vec<String> = submitted
                .keys()
                .filter(|k| def_of(k).is_some_and(|d| !d.user_editable))
                .cloned()
                .collect();
            if !locked.is_empty() {
                return Err(AttributeError::NotEditable(sorted(locked)));
            }
            for (k, v) in submitted {
                if v.is_null() {
                    values.remove(k);
                } else {
                    values.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let mut errors = Vec::new();
    for def in definitions {
        match values.get(&def.name) {
            None if def.required => errors.push(pointer(&def.name)),
            None => {}
            Some(value) => {
                if let Err(pointers) = check.validate(&def.schema, value) {
                    let base = pointer(&def.name);
                    errors.extend(pointers.into_iter().map(|p| format!("{base}{p}")));
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(AttributeError::Invalid(sorted(errors)));
    }

    let changed = definitions
        .iter()
        .filter(|d| stored.get(&d.name) != values.get(&d.name))
        .map(|d| d.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(PlannedValues { values, changed })
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

/// Attribute definitions and validated value writes.
pub struct AttributeService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub check: Arc<dyn AttributeSchemaCheck>,
}

impl AttributeService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    /// Every definition of the tenant, by position then name.
    pub async fn list(&self, tenant: TenantId) -> Result<Vec<AttributeDefinition>, CoreError> {
        Ok(self.storage.attributes().list(tenant).await?)
    }

    /// One definition (`NotFound` if it does not exist).
    pub async fn get(
        &self,
        tenant: TenantId,
        name: &str,
    ) -> Result<AttributeDefinition, CoreError> {
        self.storage
            .attributes()
            .get(tenant, name)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// The tenant's [`effective_schema`].
    pub async fn effective_schema(&self, tenant: TenantId) -> Result<Value, CoreError> {
        Ok(effective_schema(&self.list(tenant).await?))
    }

    /// Creates or replaces a definition after [`check_definition`]; audited `attribute_defined`.
    /// Stored user values are never touched.
    pub async fn define(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        definition: &AttributeDefinition,
        ctx: &RequestContext,
    ) -> Result<AttributeDefinition, CoreError> {
        let settings = self
            .storage
            .tenants()
            .get(tenant)
            .await?
            .ok_or(CoreError::NotFound)?
            .settings;
        let others = self.list(tenant).await?;
        check_definition(definition, &others, &settings.claims, self.check.as_ref())?;
        let stored = self
            .storage
            .attributes()
            .upsert(tenant, definition, self.clock.now())
            .await?;
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::AttributeDefined,
                Some(stored.name.clone()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::attribute(&stored.name),
            )
            .await?;
        Ok(stored)
    }

    /// Deletes a definition (`NotFound` if it does not exist); audited `attribute_deleted`.
    /// Stored user values are kept (a re-created definition sees them again).
    pub async fn delete(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        name: &str,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if !self.storage.attributes().delete(tenant, name).await? {
            return Err(CoreError::NotFound);
        }
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::AttributeDeleted,
                Some(name.to_owned()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::attribute(name),
            )
            .await
    }

    /// The user's stored values (`NotFound` for a user outside the tenant).
    pub async fn user_values(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Map<String, Value>, CoreError> {
        self.storage
            .attributes()
            .user_values(tenant, user)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Validates and stores a user's values ([`plan_values`]); audited `user_attributes_updated`
    /// when something changed. Returns the stored object.
    pub async fn set_user_values(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        user: UserId,
        submitted: &Map<String, Value>,
        mode: WriteMode,
        ctx: &RequestContext,
    ) -> Result<Map<String, Value>, AttributeError> {
        let stored = self.user_values(tenant, user).await?;
        let definitions = self.list(tenant).await?;
        let planned = plan_values(&definitions, &stored, submitted, mode, self.check.as_ref())?;
        if planned.changed.is_empty() {
            return Ok(stored);
        }
        if !self
            .storage
            .attributes()
            .set_user_values(tenant, user, &planned.values, self.clock.now())
            .await?
        {
            return Err(CoreError::NotFound.into());
        }
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::UserAttributesUpdated,
                Some(user.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::count("attributes", planned.changed.len() as u64),
            )
            .await?;
        Ok(planned.values)
    }

    /// Checks an account-page submission's settings-flow binding: flow cookie, CSRF token, a
    /// settings flow owned by the session's user. No recent sign-in is needed (like profile
    /// edits). Changes nothing.
    pub async fn check_own_binding(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
    ) -> Result<(), AttributeError> {
        let now = self.clock.now();
        let Some(flow) = self
            .storage
            .flows()
            .get(tenant, binding.flow_id, now)
            .await?
        else {
            return Err(AttributeError::FlowExpired);
        };
        if flow.kind != FlowKind::Settings || session.tenant_id != tenant {
            return Err(CoreError::Forbidden.into());
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return Err(AttributeError::FlowExpired),
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden.into()),
        }
        let state = SettingsState::from_json(&flow.state)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        if state.user != session.user_id {
            return Err(CoreError::Forbidden.into());
        }
        Ok(())
    }

    /// The account page's write: [`Self::check_own_binding`], then [`Self::set_user_values`] in
    /// [`WriteMode::SelfService`] as the user.
    pub async fn update_own(
        &self,
        tenant: TenantId,
        session: &BrowserSession,
        binding: &SettingsBinding<'_>,
        submitted: &Map<String, Value>,
        ctx: &RequestContext,
    ) -> Result<Map<String, Value>, AttributeError> {
        self.check_own_binding(tenant, session, binding).await?;
        self.set_user_values(
            tenant,
            AuditActor::user(session.user_id),
            session.user_id,
            submitted,
            WriteMode::SelfService,
            ctx,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::{ClaimMappingSettings, ClaimRule, TokenTarget};
    use crate::ports::SchemaIssue;

    /// A schema check for unit tests: `type` and `enum` only; `{"$ref": ..}` and
    /// `{"bad": true}` are refused as definitions.
    struct TypeCheck;

    impl AttributeSchemaCheck for TypeCheck {
        fn check_definition(&self, schema: &Value) -> Result<(), SchemaIssue> {
            if schema.get("$ref").is_some() || schema.get("bad").is_some() {
                return Err(SchemaIssue {
                    message: "refused".into(),
                });
            }
            Ok(())
        }

        fn validate(&self, schema: &Value, instance: &Value) -> Result<(), Vec<String>> {
            let type_ok = match schema.get("type").and_then(Value::as_str) {
                Some("string") => instance.is_string(),
                Some("integer") => instance.is_i64(),
                Some("boolean") => instance.is_boolean(),
                Some("array") => instance.is_array(),
                _ => true,
            };
            let enum_ok = schema
                .get("enum")
                .and_then(Value::as_array)
                .is_none_or(|e| e.contains(instance));
            if type_ok && enum_ok {
                Ok(())
            } else {
                Err(vec![String::new()])
            }
        }
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

    fn defs() -> Vec<AttributeDefinition> {
        vec![
            def(
                "department",
                json!({"type": "string", "enum": ["eng", "ops"]}),
                false,
                true,
            ),
            def("cost_center", json!({"type": "integer"}), true, false),
        ]
    }

    #[test]
    fn valid_definition_is_accepted() {
        let d = def("department", json!({"type": "string"}), false, true);
        check_definition(&d, &[], &ClaimMappingSettings::default(), &TypeCheck).unwrap();
    }

    #[test]
    fn bad_names_and_reserved_claim_names_are_refused() {
        for name in [
            "", "Dept", "1a", "sub", "email", "name", "locale", "iss", "nonce",
        ] {
            let d = def(name, json!({"type": "string"}), false, true);
            let err = check_definition(&d, &[], &ClaimMappingSettings::default(), &TypeCheck)
                .unwrap_err();
            assert!(
                matches!(err, CoreError::Validation { field: "name", .. }),
                "{name}: {err:?}"
            );
        }
    }

    #[test]
    fn schema_issues_and_oversized_schemas_are_refused() {
        for schema in [
            json!({"$ref": "https://evil/x"}),
            json!({"bad": true}),
            json!({"description": "x".repeat(crate::model::MAX_SCHEMA_BYTES)}),
        ] {
            let d = def("department", schema, false, true);
            let err = check_definition(&d, &[], &ClaimMappingSettings::default(), &TypeCheck)
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    CoreError::Validation {
                        field: "schema",
                        ..
                    }
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn claim_rule_collisions_are_refused() {
        let rule = |claim: &str| ClaimRule {
            claim: claim.into(),
            tokens: vec![TokenTarget::IdToken],
            scope: None,
        };
        let mut other = def("team", json!({"type": "string"}), false, false);
        other.claim = Some(rule("org_unit"));
        let mut d = def("department", json!({"type": "string"}), false, true);
        d.claim = Some(rule("org_unit"));
        let settings = ClaimMappingSettings::default();
        assert!(matches!(
            check_definition(&d, std::slice::from_ref(&other), &settings, &TypeCheck),
            Err(CoreError::Validation { field: "claim", .. })
        ));
        // Replacing the same definition does not collide with its stored self.
        let mut same = other.clone();
        same.schema = json!({"type": "integer"});
        check_definition(&same, &[other], &settings, &TypeCheck).unwrap();
        d.claim = Some(rule("sub"));
        assert!(check_definition(&d, &[], &settings, &TypeCheck).is_err());
    }

    #[test]
    fn values_are_validated_with_field_pointers() {
        let stored = obj(json!({"cost_center": 7}));
        let ok = plan_values(
            &defs(),
            &stored,
            &obj(json!({"department": "eng"})),
            WriteMode::SelfService,
            &TypeCheck,
        )
        .unwrap();
        assert_eq!(
            ok.values,
            obj(json!({"cost_center": 7, "department": "eng"}))
        );
        assert_eq!(ok.changed, vec!["department".to_owned()]);

        let err = plan_values(
            &defs(),
            &stored,
            &obj(json!({"department": "sales"})),
            WriteMode::SelfService,
            &TypeCheck,
        )
        .unwrap_err();
        assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/department"]));
    }

    #[test]
    fn unknown_keys_are_refused() {
        for mode in [WriteMode::Replace, WriteMode::SelfService] {
            let err = plan_values(
                &defs(),
                &obj(json!({"cost_center": 1})),
                &obj(json!({"shoe/size": 42, "department": "eng"})),
                mode,
                &TypeCheck,
            )
            .unwrap_err();
            assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/shoe~1size"]));
        }
    }

    #[test]
    fn missing_required_is_refused() {
        let err = plan_values(
            &defs(),
            &Map::new(),
            &obj(json!({"department": "ops"})),
            WriteMode::Replace,
            &TypeCheck,
        )
        .unwrap_err();
        assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/cost_center"]));
    }

    #[test]
    fn self_service_refuses_non_editable_and_null_removes() {
        let stored = obj(json!({"cost_center": 1, "department": "eng"}));
        let err = plan_values(
            &defs(),
            &stored,
            &obj(json!({"cost_center": 2})),
            WriteMode::SelfService,
            &TypeCheck,
        )
        .unwrap_err();
        assert!(matches!(err, AttributeError::NotEditable(n) if n == vec!["cost_center"]));

        let ok = plan_values(
            &defs(),
            &stored,
            &obj(json!({"department": null})),
            WriteMode::SelfService,
            &TypeCheck,
        )
        .unwrap();
        assert_eq!(ok.values, obj(json!({"cost_center": 1})));
        // The administrator may set non-editable attributes.
        let ok = plan_values(
            &defs(),
            &stored,
            &obj(json!({"cost_center": 2})),
            WriteMode::Replace,
            &TypeCheck,
        )
        .unwrap();
        assert_eq!(ok.values, obj(json!({"cost_center": 2})));
    }

    #[test]
    fn stored_values_without_a_definition_are_kept() {
        let stored = obj(json!({"cost_center": 1, "legacy": [1, 2]}));
        for mode in [WriteMode::Replace, WriteMode::SelfService] {
            let submitted = match mode {
                WriteMode::Replace => obj(json!({"cost_center": 1, "department": "ops"})),
                WriteMode::SelfService => obj(json!({"department": "ops"})),
            };
            let ok = plan_values(&defs(), &stored, &submitted, mode, &TypeCheck).unwrap();
            assert_eq!(ok.values["legacy"], json!([1, 2]));
            assert_eq!(ok.changed, vec!["department".to_owned()]);
        }
    }

    #[test]
    fn nested_errors_are_prefixed_and_no_change_is_detected() {
        let d = vec![def("tags", json!({"type": "array"}), false, true)];
        let err = plan_values(
            &d,
            &Map::new(),
            &obj(json!({"tags": "x"})),
            WriteMode::Replace,
            &TypeCheck,
        )
        .unwrap_err();
        assert!(matches!(err, AttributeError::Invalid(p) if p == vec!["/tags"]));
        let same = plan_values(
            &d,
            &obj(json!({"tags": [1]})),
            &obj(json!({"tags": [1]})),
            WriteMode::Replace,
            &TypeCheck,
        )
        .unwrap();
        assert!(same.changed.is_empty());
    }

    #[test]
    fn effective_schema_assembles_the_definitions() {
        let schema = effective_schema(&defs());
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"], json!(["cost_center"]));
        assert_eq!(
            schema["properties"]["department"]["$id"],
            "urn:anvilid:attribute:department"
        );
        assert_eq!(
            schema["properties"]["department"]["enum"],
            json!(["eng", "ops"])
        );
    }
}
