//! The OIDC Core §5.5 `claims` request parameter (minimal 0.1 support).
//!
//! Supported: the `userinfo` and `id_token` members, and per claim `null` or an object with
//! `essential`, `value` and `values`. Unknown top-level members and unknown per-claim members are
//! ignored. The input is capped at [`MAX_CLAIMS_LEN`] bytes.

use serde_json::{Map, Value};

use crate::error::CoreError;
use crate::model::{ClaimsRequest, RequestedClaim};

/// Largest accepted `claims` parameter, in bytes.
pub const MAX_CLAIMS_LEN: usize = 4096;

fn bad(message: &str) -> CoreError {
    CoreError::InvalidRequest(format!("invalid claims parameter: {message}"))
}

/// Parses the `claims` parameter. Any malformed input yields `invalid_request`.
pub fn parse_claims(json: &str) -> Result<ClaimsRequest, CoreError> {
    if json.len() > MAX_CLAIMS_LEN {
        return Err(bad("too large"));
    }
    let v: Value = serde_json::from_str(json).map_err(|_| bad("not JSON"))?;
    let obj = v.as_object().ok_or_else(|| bad("not a JSON object"))?;
    Ok(ClaimsRequest {
        userinfo: member(obj, "userinfo")?,
        id_token: member(obj, "id_token")?,
    })
}

fn member(obj: &Map<String, Value>, name: &str) -> Result<Vec<RequestedClaim>, CoreError> {
    let Some(v) = obj.get(name) else {
        return Ok(Vec::new());
    };
    if v.is_null() {
        return Ok(Vec::new());
    }
    let claims = v
        .as_object()
        .ok_or_else(|| bad("userinfo and id_token must be objects"))?;
    claims
        .iter()
        .map(|(claim, spec)| requested(claim, spec))
        .collect()
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn requested(name: &str, spec: &Value) -> Result<RequestedClaim, CoreError> {
    let mut out = RequestedClaim {
        name: name.to_owned(),
        essential: false,
        values: Vec::new(),
    };
    match spec {
        Value::Null => {}
        Value::Object(o) => {
            if let Some(e) = o.get("essential") {
                out.essential = e
                    .as_bool()
                    .ok_or_else(|| bad("essential must be a boolean"))?;
            }
            if let Some(v) = o.get("value") {
                out.values.push(value_text(v));
            }
            if let Some(vs) = o.get("values") {
                let arr = vs
                    .as_array()
                    .ok_or_else(|| bad("values must be an array"))?;
                out.values.extend(arr.iter().map(value_text));
            }
        }
        _ => return Err(bad("a claim request must be null or an object")),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_userinfo_essential() {
        let c = parse_claims(r#"{"userinfo":{"name":{"essential":true}}}"#).unwrap();
        assert_eq!(c.userinfo.len(), 1);
        assert_eq!(c.userinfo[0].name, "name");
        assert!(c.userinfo[0].essential);
        assert!(c.id_token.is_empty());
    }

    #[test]
    fn parses_values_null_and_ignores_unknown() {
        let c = parse_claims(
            r#"{"id_token":{"acr":{"values":["a","b"]},"email":null,"sub":{"value":"u1","x":1}},
                "userinfo":null,"unknown":{"x":1}}"#,
        )
        .unwrap();
        assert_eq!(c.id_token.len(), 3);
        let acr = c.id_token.iter().find(|r| r.name == "acr").unwrap();
        assert_eq!(acr.values, vec!["a", "b"]);
        let sub = c.id_token.iter().find(|r| r.name == "sub").unwrap();
        assert_eq!(sub.values, vec!["u1"]);
        assert!(c.userinfo.is_empty());
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "not json",
            "[]",
            r#"{"userinfo":[]}"#,
            r#"{"userinfo":{"name":1}}"#,
            r#"{"userinfo":{"name":{"essential":"yes"}}}"#,
            r#"{"userinfo":{"name":{"values":"a"}}}"#,
        ] {
            assert!(
                matches!(parse_claims(bad), Err(CoreError::InvalidRequest(_))),
                "{bad}"
            );
        }
        let big = format!(r#"{{"userinfo":{{"x":"{}"}}}}"#, "a".repeat(MAX_CLAIMS_LEN));
        assert!(matches!(
            parse_claims(&big),
            Err(CoreError::InvalidRequest(_))
        ));
    }
}
