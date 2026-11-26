//! Where a sign-in may return to when it is not bound to an authorization request (ORG-02).
//!
//! Pure, no I/O. The login page accepts a `return_to` parameter, and the only page that sends
//! one is the invitation page: a signed-out user who already has an account signs in and comes
//! back to the invitation to accept it. [`parse_return_target`] is therefore an exact allowlist,
//! not a general same-origin rule: the value must be the tenant-relative path `/ui/invitation`
//! with exactly one `token` parameter of 1 to [`MAX_TOKEN_LEN`] base64url characters, and nothing
//! else. A general "any relative path" rule is an open-redirect surface (scheme-relative `//host`,
//! backslashes, encoded slashes and dots, parser differences between servers and browsers) for no
//! benefit while there is a single consumer.
//!
//! Anything that does not match is ignored: the sign-in then ends on the normal signed-in page.
//! The web layer prefixes the tenant's own UI origin (`{issuer}` + the path); a host or scheme is
//! never taken from the request.
//!
//! The value carries the invitation token, a bearer value: the flow stores it only sealed with
//! the KEK (`service::flow`), and [`ReturnTarget`]'s `Debug` output redacts it.

use std::fmt;

pub use crate::service::org_invitation::MAX_TOKEN_LEN;

/// The one path a sign-in may return to.
const INVITATION_PREFIX: &str = "/ui/invitation?token=";

/// A validated return target: `/ui/invitation?token=<1..=MAX_TOKEN_LEN base64url characters>`.
#[derive(Clone, PartialEq, Eq)]
pub struct ReturnTarget(String);

impl ReturnTarget {
    /// The tenant-relative path with its query (`/ui/invitation?token=…`).
    pub fn as_path(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReturnTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token is a bearer value.
        f.write_str("ReturnTarget(/ui/invitation?token=[redacted])")
    }
}

/// The return target `raw` names, if it is exactly an allowlisted one (module docs).
pub fn parse_return_target(raw: &str) -> Option<ReturnTarget> {
    let token = raw.strip_prefix(INVITATION_PREFIX)?;
    let ok = !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then(|| ReturnTarget(raw.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_invitation_paths_with_a_base64url_token() {
        let token43 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";
        assert_eq!(token43.len(), 43);
        for token in [
            token43.to_owned(),
            "a".to_owned(),
            "Z".repeat(MAX_TOKEN_LEN),
            "-_-_09".to_owned(),
        ] {
            let raw = format!("/ui/invitation?token={token}");
            let t = parse_return_target(&raw).expect("allowed");
            assert_eq!(t.as_path(), raw);
        }
    }

    #[test]
    fn rejects_everything_else() {
        let long = format!("/ui/invitation?token={}", "a".repeat(MAX_TOKEN_LEN + 1));
        let rejected = [
            "",
            "https://evil.example/ui/invitation?token=a",
            "//evil.example/ui/invitation?token=a",
            "/\\evil.example",
            "\\\\evil.example/ui/invitation?token=a",
            "/ui/invitation",
            "/ui/invitation?",
            "/ui/invitation?token=",
            "/ui/invitation?token=a&x=1",
            "/ui/invitation?x=1&token=a",
            "/ui/invitation?token=a&token=b",
            "/ui/invitation?token=a#f",
            "/ui/invitation?token=a%2F",
            "/ui/invitation?token=%61",
            "/ui/../ui/invitation?token=a",
            "/ui/./invitation?token=a",
            "/ui/invitation/?token=a",
            "/ui/account",
            "/ui/invitation/register?token=a",
            "/UI/invitation?token=a",
            "/ui/Invitation?token=a",
            " /ui/invitation?token=a",
            "/ui/invitation?token=a ",
            "/ui/invitation?token=a+b",
            "/ui/invitation?token=a/b",
            "/ui/invitation?token=a=",
            "/ui/invitation?token=a b",
            "/ui/invitation?token=a\r\nLocation: https://evil.example",
            "/ui/invitation?token=a\n",
            "/ui/invitation?token=a\t",
            "/ui/invitation?token=a\0",
            "/ui/invitation?token=aé",
            "/ui/invitation?token=a.b",
            "/ui/invitation?token=..",
            "/ui/invitation;token=a",
            "javascript:alert(1)",
            long.as_str(),
        ];
        for raw in rejected {
            assert_eq!(parse_return_target(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn debug_redacts_the_token() {
        let t = parse_return_target("/ui/invitation?token=secret-token-value").unwrap();
        let shown = format!("{t:?}");
        assert!(!shown.contains("secret-token-value"), "{shown}");
        assert!(shown.contains("redacted"));
    }
}
