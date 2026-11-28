//! Where a sign-in may return to when it is not bound to an authorization request (ORG-02).
//!
//! Pure, no I/O. The login page accepts a `return_to` parameter, sent by two kinds of page:
//!
//! * the invitation page: a signed-out user who already has an account signs in and comes back to
//!   the invitation to accept it (ORG-02);
//! * the account pages (07.1, U-H3): a signed-out visit to `/ui/account/security` signs in and
//!   lands on that page, not on the generic signed-in page.
//!
//! [`parse_return_target`] is therefore an exact allowlist, not a general same-origin rule. The
//! value must be either
//!
//! * the tenant-relative path `/ui/invitation` with exactly one `token` parameter of 1 to
//!   [`MAX_TOKEN_LEN`] base64url characters, and nothing else; or
//! * exactly one of [`ACCOUNT_PATHS`] (one per account page route), compared byte for byte after
//!   checking there is no query and no fragment: no trailing slash, no case folding, no
//!   percent-decoding, no dot segments.
//!
//! A general "any relative path" rule is an open-redirect surface (scheme-relative `//host`,
//! backslashes, encoded slashes and dots, parser differences between servers and browsers) for no
//! benefit while the consumers are this short list.
//!
//! Anything that does not match is ignored: the sign-in then ends on the normal signed-in page.
//! The web layer prefixes the tenant's own UI origin (`{issuer}` + the path); a host or scheme is
//! never taken from the request.
//!
//! An invitation target carries the invitation token, a bearer value: the flow stores every
//! target only sealed with the KEK (`service::flow`), and [`ReturnTarget`]'s `Debug` output
//! redacts the token (an account path carries no secret and is shown as is).

use std::fmt;

pub use crate::service::org_invitation::MAX_TOKEN_LEN;

/// The invitation page a sign-in may return to (with its token).
const INVITATION_PREFIX: &str = "/ui/invitation?token=";

/// The account pages a sign-in may return to: exactly one per account page route
/// (`anvil-web` `ui::account_*`), without query or fragment. A test in `anvil-web` keeps this list
/// and the account navigation in step.
pub const ACCOUNT_PATHS: [&str; 8] = [
    "/ui/account/profile",
    "/ui/account/email",
    "/ui/account/password",
    "/ui/account/security",
    "/ui/account/sessions",
    "/ui/account/apps",
    "/ui/account/linked",
    "/ui/account/attributes",
];

/// A validated return target: `/ui/invitation?token=<1..=MAX_TOKEN_LEN base64url characters>`
/// or one of [`ACCOUNT_PATHS`].
#[derive(Clone, PartialEq, Eq)]
pub struct ReturnTarget(String);

impl ReturnTarget {
    /// The tenant-relative path with its query (`/ui/invitation?token=…`, `/ui/account/…`).
    pub fn as_path(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReturnTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.starts_with(INVITATION_PREFIX) {
            // The token is a bearer value.
            f.write_str("ReturnTarget(/ui/invitation?token=[redacted])")
        } else {
            // An allowlisted account path: no secret.
            write!(f, "ReturnTarget({})", self.0)
        }
    }
}

/// The return target `raw` names, if it is exactly an allowlisted one (module docs).
pub fn parse_return_target(raw: &str) -> Option<ReturnTarget> {
    if !raw.contains(['?', '#']) && ACCOUNT_PATHS.contains(&raw) {
        return Some(ReturnTarget(raw.to_owned()));
    }
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
    fn accepts_exactly_the_account_paths() {
        for path in ACCOUNT_PATHS {
            let t = parse_return_target(path).expect(path);
            assert_eq!(t.as_path(), path);
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
            // Account pages: exact paths only.
            "/ui/account/",
            "/ui/account/../x",
            "/ui/account/../account/security",
            "/ui/account/./security",
            "/ui/account//security",
            "/ui/account/securityx",
            "/ui/account/security/",
            "/ui/account/security/totp",
            "/ui/account/security/passkey/options",
            "/ui/account/email/confirm",
            "/ui/account/sessions/revoke-others",
            "/ui/account/settings",
            "/ui/account%2Fsecurity",
            "/ui%2Faccount%2Fsecurity",
            "%2Fui%2Faccount%2Fsecurity",
            "/ui/account/%2e%2e/security",
            "/ui/account/%2E%2E/x",
            "/ui/account/securit%79",
            "//evil.example/ui/account/security",
            "//evil.example",
            "/\\evil.example/ui/account/security",
            "\\ui\\account\\security",
            "https://evil.example/ui/account/security",
            "http://localhost/ui/account/security",
            "https:/ui/account/security",
            "/t/other/ui/account/security",
            "/t/acme/ui/account/profile",
            "ui/account/security",
            "/UI/account/security",
            "/ui/Account/security",
            "/ui/account/Security",
            "/ui/account/SECURITY",
            " /ui/account/security",
            "/ui/account/security ",
            "/ui/account/security\r\nLocation: https://evil.example",
            "/ui/account/security\r",
            "/ui/account/security\n",
            "/ui/account/security\t",
            "/ui/account/security\0",
            "/ui/account/security#frag",
            "/ui/account/security#",
            "/ui/account/security?",
            "/ui/account/security?x=1",
            "/ui/account/security?client_id=app",
            "/ui/account/security;x=1",
            "/ui/account/securité",
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
        let account = parse_return_target("/ui/account/security").unwrap();
        assert_eq!(format!("{account:?}"), "ReturnTarget(/ui/account/security)");
    }
}
