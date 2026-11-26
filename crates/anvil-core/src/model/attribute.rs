//! Custom user attributes (ADM-06) and the explicit claim mapping that puts attributes, roles and
//! permissions into tokens. No expression language in 0.4: a rule names a claim, the tokens it
//! goes into and the scope that gates it.

use serde::{Deserialize, Serialize};

use super::ids::str_enum;
use crate::error::CoreError;

/// Largest accepted attribute JSON Schema, in bytes (serialized).
pub const MAX_SCHEMA_BYTES: usize = 16 * 1024;

/// Longest attribute name, in bytes.
pub const MAX_ATTRIBUTE_NAME_LEN: usize = 64;

/// Where a mapped claim is emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenTarget {
    AccessToken,
    IdToken,
    Userinfo,
}

str_enum!(TokenTarget {
    AccessToken => "access_token",
    IdToken => "id_token",
    Userinfo => "userinfo",
});

/// One claim mapping rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRule {
    /// The claim name in the token / userinfo response.
    pub claim: String,
    /// Where the claim is emitted.
    pub tokens: Vec<TokenTarget>,
    /// Scope that must be granted for the claim to appear; `None` = always.
    #[serde(default)]
    pub scope: Option<String>,
}

/// A tenant's definition of one custom user attribute. Values are validated against `schema`
/// (JSON Schema, offline, at most [`MAX_SCHEMA_BYTES`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeDefinition {
    /// Unique per tenant; see [`validate_attribute_name`].
    pub name: String,
    pub schema: serde_json::Value,
    #[serde(default)]
    pub required: bool,
    /// The user may edit the value on the account page.
    #[serde(default)]
    pub user_editable: bool,
    /// How the attribute is mapped into tokens; `None` = not emitted.
    #[serde(default)]
    pub claim: Option<ClaimRule>,
    /// Display order (ascending).
    #[serde(default)]
    pub position: u32,
}

/// Validates an attribute name: `^[a-z][a-z0-9_]{0,63}$`.
pub fn validate_attribute_name(name: &str) -> Result<(), CoreError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(first) => {
            first.is_ascii_lowercase()
                && name.len() <= MAX_ATTRIBUTE_NAME_LEN
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
        None => false,
    };
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation {
            field: "name",
            message:
                "attribute names are 1-64 characters of a-z, 0-9 or '_', starting with a letter"
                    .to_owned(),
        })
    }
}

/// Rejects a schema larger than [`MAX_SCHEMA_BYTES`] once serialized.
pub fn check_schema_size(schema: &serde_json::Value) -> Result<(), CoreError> {
    let len = serde_json::to_vec(schema)
        .map_err(|e| CoreError::Internal(format!("serializing an attribute schema: {e}")))?
        .len();
    if len > MAX_SCHEMA_BYTES {
        return Err(CoreError::Validation {
            field: "schema",
            message: format!("the schema must be at most {MAX_SCHEMA_BYTES} bytes"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_names_accept_and_reject() {
        for good in ["department", "a", "cost_center_2", &"a".repeat(64)] {
            assert!(validate_attribute_name(good).is_ok(), "{good:?}");
        }
        for bad in [
            "",
            "1abc",
            "_x",
            "Dept",
            "a-b",
            "a.b",
            "a b",
            &"a".repeat(65),
        ] {
            assert!(validate_attribute_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn schema_size_is_capped() {
        assert!(check_schema_size(&serde_json::json!({"type": "string"})).is_ok());
        let big = serde_json::json!({ "description": "x".repeat(MAX_SCHEMA_BYTES) });
        assert!(check_schema_size(&big).is_err());
    }

    #[test]
    fn token_targets_round_trip() {
        for t in TokenTarget::ALL {
            assert_eq!(TokenTarget::parse(t.as_str()), Some(*t));
        }
        let rule: ClaimRule =
            serde_json::from_str(r#"{"claim":"dept","tokens":["id_token","userinfo"]}"#).unwrap();
        assert_eq!(rule.scope, None);
        assert_eq!(
            rule.tokens,
            vec![TokenTarget::IdToken, TokenTarget::Userinfo]
        );
    }
}
