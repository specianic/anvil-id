//! RFC 8707 resource indicators: parsing, validation against the client's allowed resources,
//! downscoping at the token endpoint and the resulting access-token audience (OIDC-16).
//!
//! Matching is exact string comparison, like redirect URIs: values are never normalised through
//! [`url::Url`] before comparing.
//!
//! Specs: RFC 8707 §2 (resource parameter), §2.1 (authorization request), §2.2 (access token
//! request, downscoping), §3 (security: multiple audiences); RFC 9068 §3 (`aud`); RFC 7519 §4.1.3
//! (`aud` as string or array).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Longest accepted resource indicator.
pub const MAX_RESOURCE_LEN: usize = 2048;

/// Parses the (possibly repeated) `resource` parameter values (RFC 8707 §2): each must be an
/// absolute URI without fragment, without query, without whitespace and at most
/// [`MAX_RESOURCE_LEN`] characters. Duplicates are removed preserving the first occurrence.
/// The values are returned verbatim. Anything else is `invalid_target`.
pub fn parse_resources(values: &[String]) -> Result<Vec<String>, CoreError> {
    let _ = values;
    Ok(Vec::new())
}

/// Every requested resource must be exactly one of the client's allowed resources
/// (RFC 8707 §2: the AS decides which resources a client may ask for).
pub fn validate_resources(requested: &[String], allowed: &[String]) -> Result<(), CoreError> {
    let _ = (requested, allowed);
    Ok(())
}

/// Resources for an access token issued from a grant (RFC 8707 §2.2): no `resource` in the token
/// request means every granted resource; otherwise the request must be a subset of the grant.
pub fn downscope(granted: &[String], requested: &[String]) -> Result<Vec<String>, CoreError> {
    let _ = requested;
    Ok(granted.to_vec())
}

/// An access-token `aud` value: one string, or an array for several (RFC 7519 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    /// The audience values as a list.
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::One(v) => vec![v.clone()],
            Self::Many(v) => v.clone(),
        }
    }

    /// Whether `value` is one of the audiences.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(v) => v == value,
            Self::Many(v) => v.iter().any(|a| a == value),
        }
    }
}

/// The access-token audience: the resources (one value as a string, several as an array), or
/// `client_id` when none was requested (0.2 behaviour).
pub fn audience(resources: &[String], client_id: &str) -> Audience {
    let _ = resources;
    Audience::One(client_id.to_owned())
}

/// The UserInfo audience rule: an access token is accepted at `/userinfo` only if its `aud`
/// contains the requesting client's `client_id` or `{issuer}/userinfo`, so a token minted for an
/// API cannot be replayed to UserInfo by that API.
pub fn userinfo_audience_ok(aud: &[String], client_id: &str, issuer: &str) -> bool {
    let _ = (aud, client_id, issuer);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    const API: &str = "https://api.example.test";
    const MCP: &str = "https://mcp.example.test/mcp";

    #[test]
    fn parses_absolute_uris_verbatim() {
        let v = s(&[
            API,
            MCP,
            "urn:example:resource",
            "https://API.example.test:443/x/../y",
        ]);
        assert_eq!(parse_resources(&v).unwrap(), v);
    }

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(parse_resources(&[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn deduplicates_preserving_order() {
        let v = s(&[MCP, API, MCP, API]);
        assert_eq!(parse_resources(&v).unwrap(), s(&[MCP, API]));
    }

    #[test]
    fn rejects_invalid_values() {
        let long = format!("https://a.example.test/{}", "x".repeat(MAX_RESOURCE_LEN));
        for bad in [
            "",
            "api",
            "/relative",
            "//host/path",
            "https://api.example.test/#frag",
            "https://api.example.test/#",
            "https://api.example.test/?q=1",
            "https://api.example.test/?",
            " https://api.example.test",
            "https://api.example.test ",
            "https://api.example .test",
            "https://api.example.test/\n",
            "http://[::1",
            long.as_str(),
        ] {
            let err = parse_resources(&[API.to_owned(), bad.to_owned()]).unwrap_err();
            assert!(matches!(err, CoreError::InvalidTarget(_)), "{bad:?}");
        }
    }

    #[test]
    fn accepts_maximum_length() {
        let prefix = "https://a.example.test/";
        let ok = format!("{prefix}{}", "x".repeat(MAX_RESOURCE_LEN - prefix.len()));
        assert_eq!(ok.len(), MAX_RESOURCE_LEN);
        assert_eq!(parse_resources(&[ok.clone()]).unwrap(), vec![ok]);
    }

    #[test]
    fn validate_requires_exact_match() {
        let allowed = s(&[API, MCP]);
        assert!(validate_resources(&s(&[API]), &allowed).is_ok());
        assert!(validate_resources(&s(&[MCP, API]), &allowed).is_ok());
        assert!(validate_resources(&[], &allowed).is_ok());
        for bad in [
            "https://api.example.test/",
            "https://API.example.test",
            "https://api.example.test:443",
            "https://evil.example.test",
            "https://mcp.example.test/mcp/",
        ] {
            let err = validate_resources(&s(&[API, bad]), &allowed).unwrap_err();
            assert!(matches!(err, CoreError::InvalidTarget(_)), "{bad}");
        }
    }

    #[test]
    fn validate_rejects_everything_when_nothing_allowed() {
        let err = validate_resources(&s(&[API]), &[]).unwrap_err();
        assert!(matches!(err, CoreError::InvalidTarget(_)));
    }

    #[test]
    fn downscope_empty_request_keeps_grant() {
        assert_eq!(downscope(&s(&[API, MCP]), &[]).unwrap(), s(&[API, MCP]));
        assert_eq!(downscope(&[], &[]).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn downscope_to_subset() {
        assert_eq!(downscope(&s(&[API, MCP]), &s(&[MCP])).unwrap(), s(&[MCP]));
        assert_eq!(
            downscope(&s(&[API, MCP]), &s(&[MCP, API])).unwrap(),
            s(&[MCP, API])
        );
    }

    #[test]
    fn downscope_rejects_widening() {
        for (granted, requested) in [
            (s(&[API]), s(&[MCP])),
            (s(&[API]), s(&[API, MCP])),
            (vec![], s(&[API])),
            (s(&[API]), s(&["https://api.example.test/"])),
        ] {
            let err = downscope(&granted, &requested).unwrap_err();
            assert!(matches!(err, CoreError::InvalidTarget(_)));
        }
    }

    #[test]
    fn audience_shapes() {
        assert_eq!(audience(&[], "rp"), Audience::One("rp".to_owned()));
        assert_eq!(audience(&s(&[API]), "rp"), Audience::One(API.to_owned()));
        assert_eq!(
            audience(&s(&[API, MCP]), "rp"),
            Audience::Many(s(&[API, MCP]))
        );
    }

    #[test]
    fn audience_serialises_one_as_string_and_many_as_array() {
        assert_eq!(
            serde_json::to_value(audience(&s(&[API]), "rp")).unwrap(),
            serde_json::json!(API)
        );
        assert_eq!(
            serde_json::to_value(audience(&[], "rp")).unwrap(),
            serde_json::json!("rp")
        );
        assert_eq!(
            serde_json::to_value(audience(&s(&[API, MCP]), "rp")).unwrap(),
            serde_json::json!([API, MCP])
        );
        let back: Audience = serde_json::from_value(serde_json::json!([API, MCP])).unwrap();
        assert_eq!(back, Audience::Many(s(&[API, MCP])));
        let back: Audience = serde_json::from_value(serde_json::json!("rp")).unwrap();
        assert_eq!(back, Audience::One("rp".to_owned()));
    }

    #[test]
    fn audience_helpers() {
        let a = Audience::Many(s(&[API, MCP]));
        assert!(a.contains(MCP));
        assert!(!a.contains("rp"));
        assert_eq!(a.values(), s(&[API, MCP]));
        let one = Audience::One("rp".to_owned());
        assert!(one.contains("rp"));
        assert_eq!(one.values(), s(&["rp"]));
    }

    #[test]
    fn userinfo_audience_rule() {
        let iss = "https://id.example.test/t";
        assert!(userinfo_audience_ok(&s(&["rp"]), "rp", iss));
        assert!(userinfo_audience_ok(&s(&[API, "rp"]), "rp", iss));
        assert!(userinfo_audience_ok(
            &s(&[API, "https://id.example.test/t/userinfo"]),
            "rp",
            iss
        ));
        assert!(!userinfo_audience_ok(&s(&[API]), "rp", iss));
        assert!(!userinfo_audience_ok(&s(&[API, MCP]), "rp", iss));
        assert!(!userinfo_audience_ok(&[], "rp", iss));
        assert!(!userinfo_audience_ok(&s(&["other"]), "rp", iss));
        assert!(!userinfo_audience_ok(
            &s(&["https://id.example.test/other/userinfo"]),
            "rp",
            iss
        ));
    }

    proptest! {
        #[test]
        fn parsed_values_have_no_query_or_fragment(v in proptest::collection::vec(".{0,40}", 0..5)) {
            if let Ok(out) = parse_resources(&v) {
                for r in &out {
                    prop_assert!(!r.contains('#') && !r.contains('?'));
                    prop_assert!(v.contains(r));
                    prop_assert!(url::Url::parse(r).is_ok());
                }
                let mut dedup = out.clone();
                dedup.dedup();
                prop_assert_eq!(dedup.len(), out.len());
            }
        }

        #[test]
        fn downscope_result_is_subset_of_grant(
            granted in proptest::collection::vec("[a-c]", 0..4),
            requested in proptest::collection::vec("[a-d]", 0..4),
        ) {
            match downscope(&granted, &requested) {
                Ok(out) => {
                    for r in &out {
                        prop_assert!(granted.contains(r));
                    }
                }
                Err(e) => {
                    prop_assert!(matches!(e, CoreError::InvalidTarget(_)));
                    prop_assert!(requested.iter().any(|r| !granted.contains(r)));
                }
            }
        }

        #[test]
        fn validated_resources_are_allowed(
            allowed in proptest::collection::vec("[a-c]", 0..4),
            requested in proptest::collection::vec("[a-d]", 0..4),
        ) {
            let ok = validate_resources(&requested, &allowed).is_ok();
            prop_assert_eq!(ok, requested.iter().all(|r| allowed.contains(r)));
        }
    }
}
