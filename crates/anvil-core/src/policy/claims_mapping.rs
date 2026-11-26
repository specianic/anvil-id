//! Explicit claim mapping of attributes, roles and permissions into tokens (ADM-06/ADM-05).
//!
//! Pure functions: no I/O, no clock. The token and UserInfo services pass the user's roles,
//! permissions and attribute values, the tenant's [`ClaimMappingSettings`] and attribute
//! definitions, the granted scope and the token being built; [`mapped_claims`] returns the extra
//! claims for that token. There is no expression language: a [`ClaimRule`] names a claim, the
//! tokens it goes into and the scope that gates it.
//!
//! Rules:
//! - A rule emits only into its listed [`TokenTarget`]s, and only when its scope (if any) was
//!   granted.
//! - Role and permission arrays are de-duplicated and sorted; an empty set omits the claim
//!   (never `[]`).
//! - An attribute value is emitted only when it passes the caller's validity predicate (the
//!   wiring passes the `AttributeSchemaCheck` adapter), so a value stored under an older schema
//!   never leaks into a token after the schema tightened.
//! - Claim names may not shadow protocol or standard claims ([`RESERVED_CLAIMS`]) or each other
//!   ([`validate_mapping`]). [`mapped_claims`] also skips such rules defensively, so stored
//!   configuration that predates a check can never override `sub`, `iss`, `aud`, ...

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::model::{AttributeDefinition, ClaimMappingSettings, ClaimRule, Scope, TokenTarget};

/// Claims a mapping rule can never produce, compared case-insensitively: JWT/OIDC/RFC 9068
/// protocol claims, OIDC standard claims (OIDC Core §5.1) and claims AnvilID sets itself.
pub const RESERVED_CLAIMS: &[&str] = &[
    // JWT (RFC 7519 §4.1)
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    // OIDC Core §2 and §3.3.2.11
    "azp",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "at_hash",
    "c_hash",
    "s_hash",
    "_claim_names",
    "_claim_sources",
    // RFC 9068 / RFC 8693 / RFC 7800 / back-channel logout
    "client_id",
    "scope",
    "cnf",
    "act",
    "may_act",
    "events",
    "typ",
    // AnvilID token family
    "fid",
    // AnvilID organizations (the active org of the grant; only the org mapping rules produce
    // `org_roles` / `org_permissions`, see [`validate_mapping`])
    "org_id",
    "org_slug",
    "org_roles",
    "org_permissions",
    // OIDC standard claims (OIDC Core §5.1)
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
];

/// Longest accepted claim name, in bytes.
pub const MAX_CLAIM_NAME_LEN: usize = 256;

/// The user data a mapping draws from.
#[derive(Debug, Clone, Copy)]
pub struct ClaimInputs<'a> {
    /// Role names assigned to the user (any order, duplicates allowed).
    pub roles: &'a [String],
    /// Effective permissions of those roles (any order, duplicates allowed).
    pub permissions: &'a [String],
    /// The user's stored attribute values, keyed by attribute name.
    pub attribute_values: &'a Map<String, Value>,
    /// The tenant's attribute definitions.
    pub attributes: &'a [AttributeDefinition],
}

/// Whether `claim` is a reserved protocol or standard claim (case-insensitive).
pub fn is_reserved_claim(claim: &str) -> bool {
    RESERVED_CLAIMS
        .iter()
        .any(|r| r.eq_ignore_ascii_case(claim))
}

fn rule_applies(rule: &ClaimRule, granted: &Scope, target: TokenTarget) -> bool {
    rule.tokens.contains(&target) && rule.scope.as_deref().is_none_or(|s| granted.contains(s))
}

fn sorted_unique(values: &[String]) -> Option<Value> {
    let set: BTreeSet<&str> = values.iter().map(String::as_str).collect();
    if set.is_empty() {
        return None;
    }
    Some(Value::Array(set.into_iter().map(Value::from).collect()))
}

/// Inserts unless the name is reserved or already taken by an earlier rule (case-insensitive).
fn insert_claim(out: &mut Map<String, Value>, taken: &mut BTreeSet<String>, claim: &str, v: Value) {
    if claim.is_empty() || is_reserved_claim(claim) {
        return;
    }
    if taken.insert(claim.to_ascii_lowercase()) {
        out.insert(claim.to_owned(), v);
    }
}

/// The mapped claims for one token: roles, then permissions, then attributes in definition order.
///
/// `is_valid` decides whether a stored attribute value still validates against the attribute's
/// current schema; values that fail it (and `null` values) are not emitted.
pub fn mapped_claims(
    inputs: &ClaimInputs<'_>,
    settings: &ClaimMappingSettings,
    granted: &Scope,
    target: TokenTarget,
    is_valid: &dyn Fn(&AttributeDefinition, &Value) -> bool,
) -> Map<String, Value> {
    let mut out = Map::new();
    let mut taken = BTreeSet::new();

    for (rule, values) in [
        (settings.roles.as_ref(), inputs.roles),
        (settings.permissions.as_ref(), inputs.permissions),
    ] {
        if let Some(rule) = rule.filter(|r| rule_applies(r, granted, target))
            && let Some(v) = sorted_unique(values)
        {
            insert_claim(&mut out, &mut taken, &rule.claim, v);
        }
    }

    for def in inputs.attributes {
        let Some(rule) = def
            .claim
            .as_ref()
            .filter(|r| rule_applies(r, granted, target))
        else {
            continue;
        };
        let Some(value) = inputs.attribute_values.get(&def.name) else {
            continue;
        };
        if value.is_null() || !is_valid(def, value) {
            continue;
        }
        insert_claim(&mut out, &mut taken, &rule.claim, value.clone());
    }
    out
}

fn invalid(message: String) -> CoreError {
    CoreError::Validation {
        field: "claim",
        message,
    }
}

/// `own_name`: the one reserved name this rule may carry (the org mapping rules produce
/// `org_roles` / `org_permissions`); `None` for every other rule.
fn check_rule_syntax(rule: &ClaimRule, own_name: Option<&str>) -> Result<(), CoreError> {
    let c = rule.claim.as_str();
    if c.is_empty()
        || c.len() > MAX_CLAIM_NAME_LEN
        || !c
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        return Err(invalid(format!(
            "claim names are 1-{MAX_CLAIM_NAME_LEN} printable ASCII characters without spaces, quotes or backslashes"
        )));
    }
    if is_reserved_claim(c) && own_name != Some(c) {
        return Err(invalid(format!(
            "claim {c:?} is a protocol or standard claim and cannot be mapped"
        )));
    }
    if let Some(scope) = &rule.scope
        && Scope::parse(scope).map(|s| s.len() != 1).unwrap_or(true)
    {
        return Err(invalid(format!(
            "the scope gating claim {c:?} must be a single scope name"
        )));
    }
    Ok(())
}

/// Validates a tenant's mapping: every claim name is well formed, none is reserved, and no two
/// rules (roles, permissions, org roles, org permissions, attributes) produce the same claim
/// (case-insensitive). The org rules may keep their own reserved names (`org_roles`,
/// `org_permissions`); no other rule may use a reserved name.
pub fn validate_mapping(
    settings: &ClaimMappingSettings,
    attributes: &[AttributeDefinition],
) -> Result<(), CoreError> {
    let rules = settings
        .roles
        .iter()
        .map(|r| (r, None))
        .chain(settings.permissions.iter().map(|r| (r, None)))
        .chain(settings.org_roles.iter().map(|r| (r, Some("org_roles"))))
        .chain(
            settings
                .org_permissions
                .iter()
                .map(|r| (r, Some("org_permissions"))),
        )
        .chain(
            attributes
                .iter()
                .filter_map(|a| a.claim.as_ref())
                .map(|r| (r, None)),
        );
    let mut seen = BTreeSet::new();
    for (rule, own_name) in rules {
        check_rule_syntax(rule, own_name)?;
        if !seen.insert(rule.claim.to_ascii_lowercase()) {
            return Err(invalid(format!(
                "claim {:?} is produced by more than one mapping",
                rule.claim
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    fn rule(claim: &str, tokens: &[TokenTarget], scope: Option<&str>) -> ClaimRule {
        ClaimRule {
            claim: claim.to_owned(),
            tokens: tokens.to_vec(),
            scope: scope.map(str::to_owned),
        }
    }

    fn attr(name: &str, claim: Option<ClaimRule>) -> AttributeDefinition {
        AttributeDefinition {
            name: name.to_owned(),
            schema: json!({"type": "string"}),
            required: false,
            user_editable: false,
            claim,
            position: 0,
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    fn all_valid(_: &AttributeDefinition, _: &Value) -> bool {
        true
    }

    fn map_for(
        roles: &[String],
        perms: &[String],
        values: &Map<String, Value>,
        attrs: &[AttributeDefinition],
        settings: &ClaimMappingSettings,
        granted: &str,
        target: TokenTarget,
    ) -> Map<String, Value> {
        let inputs = ClaimInputs {
            roles,
            permissions: perms,
            attribute_values: values,
            attributes: attrs,
        };
        mapped_claims(&inputs, settings, &scope(granted), target, &all_valid)
    }

    #[test]
    fn roles_are_gated_by_their_scope() {
        let settings = ClaimMappingSettings::default();
        let roles = strings(&["admin"]);
        let none = Map::new();
        for t in TokenTarget::ALL {
            let m = map_for(&roles, &[], &none, &[], &settings, "openid", *t);
            assert!(!m.contains_key("roles"), "{t:?}");
            let m = map_for(&roles, &[], &none, &[], &settings, "openid roles", *t);
            assert_eq!(m.get("roles"), Some(&json!(["admin"])), "{t:?}");
        }
    }

    #[test]
    fn ungated_permissions_go_to_the_access_token_only() {
        let settings = ClaimMappingSettings::default();
        let perms = strings(&["orders:read"]);
        let none = Map::new();
        let at = map_for(
            &[],
            &perms,
            &none,
            &[],
            &settings,
            "openid",
            TokenTarget::AccessToken,
        );
        assert_eq!(at.get("permissions"), Some(&json!(["orders:read"])));
        for t in [TokenTarget::IdToken, TokenTarget::Userinfo] {
            let m = map_for(&[], &perms, &none, &[], &settings, "openid roles", t);
            assert!(!m.contains_key("permissions"), "{t:?}");
        }
    }

    #[test]
    fn rule_targets_are_respected() {
        let settings = ClaimMappingSettings {
            roles: Some(rule("roles", &[TokenTarget::IdToken], None)),
            permissions: None,
            org_roles: None,
            org_permissions: None,
        };
        let roles = strings(&["a"]);
        let none = Map::new();
        let id = map_for(
            &roles,
            &[],
            &none,
            &[],
            &settings,
            "openid",
            TokenTarget::IdToken,
        );
        assert!(id.contains_key("roles"));
        for t in [TokenTarget::AccessToken, TokenTarget::Userinfo] {
            assert!(map_for(&roles, &[], &none, &[], &settings, "openid", t).is_empty());
        }
    }

    #[test]
    fn arrays_are_deduplicated_sorted_and_omitted_when_empty() {
        let settings = ClaimMappingSettings::default();
        let none = Map::new();
        let m = map_for(
            &strings(&["b", "a", "b", "c", "a"]),
            &strings(&["y", "x", "y"]),
            &none,
            &[],
            &settings,
            "openid roles",
            TokenTarget::AccessToken,
        );
        assert_eq!(m.get("roles"), Some(&json!(["a", "b", "c"])));
        assert_eq!(m.get("permissions"), Some(&json!(["x", "y"])));

        let empty = map_for(
            &[],
            &[],
            &none,
            &[],
            &settings,
            "openid roles",
            TokenTarget::AccessToken,
        );
        assert!(!empty.contains_key("roles"));
        assert!(!empty.contains_key("permissions"));
    }

    #[test]
    fn disabled_rules_emit_nothing() {
        let settings = ClaimMappingSettings {
            roles: None,
            permissions: None,
            org_roles: None,
            org_permissions: None,
        };
        let m = map_for(
            &strings(&["a"]),
            &strings(&["p"]),
            &Map::new(),
            &[],
            &settings,
            "openid roles",
            TokenTarget::AccessToken,
        );
        assert!(m.is_empty());
    }

    #[test]
    fn attribute_values_respect_validity_scope_and_target() {
        let attrs = vec![
            attr(
                "department",
                Some(rule(
                    "dept",
                    &[TokenTarget::IdToken, TokenTarget::Userinfo],
                    Some("profile"),
                )),
            ),
            attr(
                "cost_center",
                Some(rule("cost_center", &[TokenTarget::AccessToken], None)),
            ),
            attr("hidden", None),
        ];
        let mut values = Map::new();
        values.insert("department".into(), json!("eng"));
        values.insert("cost_center".into(), json!(42));
        values.insert("hidden".into(), json!("x"));
        let settings = ClaimMappingSettings {
            roles: None,
            permissions: None,
            org_roles: None,
            org_permissions: None,
        };
        let inputs = ClaimInputs {
            roles: &[],
            permissions: &[],
            attribute_values: &values,
            attributes: &attrs,
        };

        let id = mapped_claims(
            &inputs,
            &settings,
            &scope("openid profile"),
            TokenTarget::IdToken,
            &all_valid,
        );
        assert_eq!(id.get("dept"), Some(&json!("eng")));
        assert!(!id.contains_key("cost_center"));
        assert!(!id.contains_key("hidden") && !id.contains_key("department"));

        let ungranted = mapped_claims(
            &inputs,
            &settings,
            &scope("openid"),
            TokenTarget::IdToken,
            &all_valid,
        );
        assert!(ungranted.is_empty());

        // The predicate rejects the department value (e.g. it no longer matches the schema).
        let only_numbers = |_: &AttributeDefinition, v: &Value| v.is_number();
        let at = mapped_claims(
            &inputs,
            &settings,
            &scope("openid profile"),
            TokenTarget::AccessToken,
            &only_numbers,
        );
        assert_eq!(at.get("cost_center"), Some(&json!(42)));
        let id = mapped_claims(
            &inputs,
            &settings,
            &scope("openid profile"),
            TokenTarget::IdToken,
            &only_numbers,
        );
        assert!(!id.contains_key("dept"));
    }

    #[test]
    fn missing_and_null_attribute_values_are_not_emitted() {
        let attrs = vec![
            attr("a", Some(rule("a", &[TokenTarget::IdToken], None))),
            attr("b", Some(rule("b", &[TokenTarget::IdToken], None))),
        ];
        let mut values = Map::new();
        values.insert("b".into(), Value::Null);
        let settings = ClaimMappingSettings {
            roles: None,
            permissions: None,
            org_roles: None,
            org_permissions: None,
        };
        let m = map_for(
            &[],
            &[],
            &values,
            &attrs,
            &settings,
            "openid",
            TokenTarget::IdToken,
        );
        assert!(m.is_empty());
    }

    #[test]
    fn validate_mapping_accepts_defaults_and_distinct_attributes() {
        let attrs = vec![
            attr(
                "department",
                Some(rule("dept", &[TokenTarget::IdToken], None)),
            ),
            attr("x", None),
            attr(
                "groups",
                Some(rule(
                    "https://example.test/groups",
                    &[TokenTarget::AccessToken],
                    Some("groups"),
                )),
            ),
        ];
        validate_mapping(&ClaimMappingSettings::default(), &attrs).unwrap();
    }

    #[test]
    fn validate_mapping_rejects_reserved_claims() {
        for name in [
            "sub",
            "iss",
            "aud",
            "exp",
            "email",
            "SUB",
            "client_id",
            "scope",
        ] {
            let attrs = vec![attr("a", Some(rule(name, &[TokenTarget::IdToken], None)))];
            let err = validate_mapping(&ClaimMappingSettings::default(), &attrs);
            assert!(
                matches!(err, Err(CoreError::Validation { field: "claim", .. })),
                "{name}: {err:?}"
            );
            let settings = ClaimMappingSettings {
                roles: Some(rule(name, &[TokenTarget::AccessToken], None)),
                permissions: None,
                org_roles: None,
                org_permissions: None,
            };
            assert!(validate_mapping(&settings, &[]).is_err(), "roles as {name}");
        }
    }

    #[test]
    fn org_claim_names_are_reserved_for_attribute_and_role_rules() {
        for name in [
            "org_id",
            "org_slug",
            "ORG_SLUG",
            "Org_Slug",
            "org_roles",
            "org_permissions",
        ] {
            let attrs = vec![attr("a", Some(rule(name, &[TokenTarget::IdToken], None)))];
            let err = validate_mapping(&ClaimMappingSettings::default(), &attrs);
            assert!(
                matches!(err, Err(CoreError::Validation { field: "claim", .. })),
                "attribute as {name}: {err:?}"
            );
            let settings = ClaimMappingSettings {
                roles: Some(rule(name, &[TokenTarget::AccessToken], None)),
                ..ClaimMappingSettings::default()
            };
            assert!(validate_mapping(&settings, &[]).is_err(), "roles as {name}");
        }
        // The org rules keep their own names but cannot take the other reserved ones.
        validate_mapping(&ClaimMappingSettings::default(), &[]).unwrap();
        let swapped = ClaimMappingSettings {
            org_roles: Some(rule("org_permissions", &[TokenTarget::AccessToken], None)),
            org_permissions: None,
            ..ClaimMappingSettings::default()
        };
        assert!(validate_mapping(&swapped, &[]).is_err());
        let slug = ClaimMappingSettings {
            org_permissions: Some(rule("org_slug", &[TokenTarget::AccessToken], None)),
            ..ClaimMappingSettings::default()
        };
        assert!(validate_mapping(&slug, &[]).is_err());
        let sub = ClaimMappingSettings {
            org_roles: Some(rule("sub", &[TokenTarget::AccessToken], None)),
            ..ClaimMappingSettings::default()
        };
        assert!(validate_mapping(&sub, &[]).is_err());
        // An org rule renamed to a free name collides like any other rule.
        let clash = ClaimMappingSettings {
            org_roles: Some(rule("roles", &[TokenTarget::AccessToken], None)),
            ..ClaimMappingSettings::default()
        };
        assert!(validate_mapping(&clash, &[]).is_err());
    }

    #[test]
    fn org_slug_attribute_is_never_emitted_at_runtime() {
        let attrs = vec![
            attr(
                "a",
                Some(rule("org_slug", &[TokenTarget::AccessToken], None)),
            ),
            attr("b", Some(rule("Org_Id", &[TokenTarget::AccessToken], None))),
        ];
        let mut values = Map::new();
        values.insert("a".into(), json!("evil"));
        values.insert("b".into(), json!("evil"));
        let m = map_for(
            &[],
            &[],
            &values,
            &attrs,
            &ClaimMappingSettings::default(),
            "openid",
            TokenTarget::AccessToken,
        );
        assert!(m.is_empty(), "{m:?}");
    }

    #[test]
    fn validate_mapping_rejects_role_attribute_collision() {
        let attrs = vec![attr(
            "r",
            Some(rule("roles", &[TokenTarget::IdToken], None)),
        )];
        assert!(validate_mapping(&ClaimMappingSettings::default(), &attrs).is_err());
        let attrs = vec![attr(
            "p",
            Some(rule("Permissions", &[TokenTarget::IdToken], None)),
        )];
        assert!(validate_mapping(&ClaimMappingSettings::default(), &attrs).is_err());
        let settings = ClaimMappingSettings {
            roles: Some(rule("authz", &[TokenTarget::AccessToken], None)),
            permissions: Some(rule("authz", &[TokenTarget::AccessToken], None)),
            org_roles: None,
            org_permissions: None,
        };
        assert!(validate_mapping(&settings, &[]).is_err());
    }

    #[test]
    fn validate_mapping_rejects_two_attributes_with_the_same_claim() {
        let attrs = vec![
            attr("a", Some(rule("org", &[TokenTarget::IdToken], None))),
            attr("b", Some(rule("org", &[TokenTarget::AccessToken], None))),
        ];
        assert!(validate_mapping(&ClaimMappingSettings::default(), &attrs).is_err());
    }

    #[test]
    fn validate_mapping_rejects_malformed_names_and_scopes() {
        for bad in [
            "",
            "has space",
            "quo\"te",
            "back\\slash",
            "tab\t",
            &"x".repeat(257),
        ] {
            let attrs = vec![attr("a", Some(rule(bad, &[TokenTarget::IdToken], None)))];
            assert!(
                validate_mapping(&ClaimMappingSettings::default(), &attrs).is_err(),
                "{bad:?}"
            );
        }
        for bad_scope in ["", "two scopes", "bad\"scope"] {
            let attrs = vec![attr(
                "a",
                Some(rule("dept", &[TokenTarget::IdToken], Some(bad_scope))),
            )];
            assert!(
                validate_mapping(&ClaimMappingSettings::default(), &attrs).is_err(),
                "{bad_scope:?}"
            );
        }
    }

    #[test]
    fn mapping_never_overrides_reserved_or_earlier_claims_at_runtime() {
        // Stored configuration that bypassed validate_mapping.
        let settings = ClaimMappingSettings {
            roles: Some(rule("sub", &[TokenTarget::AccessToken], None)),
            permissions: Some(rule("perms", &[TokenTarget::AccessToken], None)),
            org_roles: None,
            org_permissions: None,
        };
        let attrs = vec![
            attr("a", Some(rule("PERMS", &[TokenTarget::AccessToken], None))),
            attr("b", Some(rule("iss", &[TokenTarget::AccessToken], None))),
        ];
        let mut values = Map::new();
        values.insert("a".into(), json!("x"));
        values.insert("b".into(), json!("y"));
        let m = map_for(
            &strings(&["admin"]),
            &strings(&["p"]),
            &values,
            &attrs,
            &settings,
            "openid",
            TokenTarget::AccessToken,
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("perms"), Some(&json!(["p"])));
    }

    fn claim_name() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(RESERVED_CLAIMS).prop_map(str::to_owned),
            prop::sample::select(RESERVED_CLAIMS).prop_map(|s| s.to_ascii_uppercase()),
            "[a-z_]{1,8}",
        ]
    }

    fn target() -> impl Strategy<Value = TokenTarget> {
        prop::sample::select(TokenTarget::ALL)
    }

    proptest! {
        #[test]
        fn output_never_contains_protocol_claims(
            roles_claim in claim_name(),
            perms_claim in claim_name(),
            attr_claims in prop::collection::vec(claim_name(), 0..6),
            t in target(),
        ) {
            let settings = ClaimMappingSettings {
                roles: Some(rule(&roles_claim, TokenTarget::ALL, None)),
                permissions: Some(rule(&perms_claim, TokenTarget::ALL, None)),
                org_roles: None,
                org_permissions: None,
            };
            let attrs: Vec<AttributeDefinition> = attr_claims
                .iter()
                .enumerate()
                .map(|(i, c)| attr(&format!("a{i}"), Some(rule(c, TokenTarget::ALL, None))))
                .collect();
            let values: Map<String, Value> =
                (0..attrs.len()).map(|i| (format!("a{i}"), json!("v"))).collect();
            let m = map_for(
                &strings(&["r"]),
                &strings(&["p"]),
                &values,
                &attrs,
                &settings,
                "openid",
                t,
            );
            for k in m.keys() {
                prop_assert!(!is_reserved_claim(k), "{k}");
            }
            let lower: BTreeSet<String> = m.keys().map(|k| k.to_ascii_lowercase()).collect();
            prop_assert_eq!(lower.len(), m.len());
        }
    }
}
