//! Redirect URI matching (authorization time) and validation (registration time).
//!
//! Matching is an exact string comparison (RFC 9700 §2.1, §4.1.3). The only exception is the
//! RFC 8252 §7.3 loopback rule for native clients: a registered `http://127.0.0.1/...` or
//! `http://[::1]/...` URI matches the same URI with any port. `localhost` gets no port
//! flexibility. Strings are never normalised through [`url::Url`] before comparing, because
//! normalisation (trailing slash, case, dot segments, percent-encoding) would turn a mismatch into
//! a match.

use crate::error::CoreError;
use crate::model::ApplicationType;

/// Longest redirect URI accepted at registration.
pub const MAX_REDIRECT_URI_LEN: usize = 2048;

/// Whether `requested` is acceptable for a client with the `registered` redirect URIs.
pub fn redirect_matches(registered: &[String], requested: &str, app: ApplicationType) -> bool {
    if registered.iter().any(|r| r == requested) {
        return true;
    }
    if app != ApplicationType::Native {
        return false;
    }
    let Some(req) = LoopbackUri::split(requested) else {
        return false;
    };
    registered
        .iter()
        .filter_map(|r| LoopbackUri::split(r))
        .any(|reg| reg.host == req.host && reg.rest == req.rest)
}

/// An `http://<loopback IP literal>[:port]<rest>` URI split into host text and the rest
/// (path, query). The rest is kept as raw text.
struct LoopbackUri<'a> {
    host: &'a str,
    rest: &'a str,
}

impl<'a> LoopbackUri<'a> {
    fn split(uri: &'a str) -> Option<Self> {
        let after = uri.strip_prefix("http://")?;
        if after.contains('#') {
            return None;
        }
        let end = after.find(['/', '?']).unwrap_or(after.len());
        let (authority, rest) = after.split_at(end);
        if authority.contains('@') {
            return None;
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let close = v6.find(']')?;
            let host = &authority[..close + 2];
            (host, &v6[close + 1..])
        } else {
            match authority.find(':') {
                Some(i) => (&authority[..i], &authority[i..]),
                None => (authority, ""),
            }
        };
        if !port.is_empty() {
            let digits = port.strip_prefix(':')?;
            if digits.is_empty()
                || digits.len() > 5
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || digits.parse::<u32>().ok()? > 65535
            {
                return None;
            }
        }
        if !is_loopback_ip_literal(host) {
            return None;
        }
        Some(Self { host, rest })
    }
}

/// `127.0.0.1`-style IPv4 or `[::1]`-style IPv6 literal that is a loopback address. Host names
/// (including `localhost`) are not IP literals.
fn is_loopback_ip_literal(host: &str) -> bool {
    match url::Host::parse(host) {
        Ok(url::Host::Ipv4(ip)) => ip.is_loopback() && ip.to_string() == host,
        Ok(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// The message for a URI that is a host (or `host:port`) without a scheme, such as
/// `localhost:5173/cb` (which parses with the scheme `localhost`).
pub const MISSING_SCHEME_MESSAGE: &str =
    "redirect URI is missing its scheme: add http:// (localhost only) or https://";

/// Whether `uri` looks like a host or `host:port` written without a scheme: what precedes the
/// first `:` is `localhost` or an IP address, or what follows it starts with a port number
/// (`app.example:8080/cb`). Only used to choose the message of a URI that is refused anyway.
fn looks_like_missing_scheme(uri: &str) -> bool {
    let authority = uri.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() {
        return false;
    }
    let hostish = host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.starts_with('[');
    let numeric_port = port.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    // A bare `app.example/cb` (no colon) is a host too; `name:/x` is a custom scheme.
    let dotted_host_without_scheme = port.is_none()
        && host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    hostish || numeric_port || dotted_host_without_scheme
}

fn invalid(message: &str) -> CoreError {
    CoreError::Validation {
        field: "redirect_uris",
        message: message.to_owned(),
    }
}

/// Registration-time validation of a redirect URI.
///
/// - absolute, at most [`MAX_REDIRECT_URI_LEN`] bytes, no fragment, no `*` wildcard, no userinfo;
/// - `https` for every client;
/// - `http` only for a loopback IP literal (`127.0.0.1`, `[::1]`) or `localhost`; `localhost`
///   is accepted for local development, both for web and native clients;
/// - native clients may also use a private-use (custom) scheme (RFC 8252 §7.1), except schemes
///   that execute or read content (`javascript`, `data`, `file`, `vbscript`, `blob`, `about`).
///
/// A refused URI that looks like a host without a scheme (`localhost:5173/cb`,
/// `127.0.0.1:8080/cb`, `app.example/cb`) gets [`MISSING_SCHEME_MESSAGE`]; the accept/refuse
/// decision does not depend on it.
pub fn validate_redirect_uri(uri: &str, app: ApplicationType) -> Result<(), CoreError> {
    if uri.is_empty() || uri.len() > MAX_REDIRECT_URI_LEN {
        return Err(invalid("redirect URI is empty or too long"));
    }
    if uri.contains('#') {
        return Err(invalid("redirect URI must not contain a fragment"));
    }
    if uri.contains('*') {
        return Err(invalid("redirect URI must not contain a wildcard"));
    }
    if uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("redirect URI contains whitespace"));
    }
    let parsed = url::Url::parse(uri).map_err(|_| {
        if looks_like_missing_scheme(uri) {
            invalid(MISSING_SCHEME_MESSAGE)
        } else {
            invalid("redirect URI must be absolute")
        }
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("redirect URI must not contain userinfo"));
    }
    match parsed.scheme() {
        "https" => {
            if parsed.host_str().is_none_or(str::is_empty) {
                return Err(invalid("redirect URI must have a host"));
            }
            Ok(())
        }
        "http" => {
            let local = match parsed.host() {
                Some(url::Host::Domain(d)) => d == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            if local {
                Ok(())
            } else {
                Err(invalid(
                    "http redirect URIs are only allowed for loopback addresses and localhost; \
                     use https",
                ))
            }
        }
        "javascript" | "data" | "file" | "vbscript" | "blob" | "about" | "ws" | "wss" | "ftp" => {
            Err(invalid("redirect URI scheme is not allowed"))
        }
        _ if app == ApplicationType::Native => Ok(()),
        // `localhost:5173/cb` parses with the scheme `localhost`: say what is really wrong.
        _ if looks_like_missing_scheme(uri) => Err(invalid(MISSING_SCHEME_MESSAGE)),
        _ => Err(invalid("web clients must use https redirect URIs")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reg(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn web_is_exact_only() {
        let r = reg(&["https://rp.example.test/cb"]);
        assert!(redirect_matches(
            &r,
            "https://rp.example.test/cb",
            ApplicationType::Web
        ));
        for bad in [
            "https://rp.example.test/cb/extra",
            "https://rp.example.test/cb?x=1",
            "https://RP.example.test/cb",
            "https://rp.example.test/CB",
            "https://rp.example.test:8443/cb",
            "https://rp.example.test/cb/",
            "https://rp.example.test/cb#frag",
            "http://rp.example.test/cb",
            "",
        ] {
            assert!(
                !redirect_matches(&r, bad, ApplicationType::Web),
                "{bad} must not match"
            );
        }
    }

    #[test]
    fn web_gets_no_loopback_flexibility() {
        let r = reg(&["http://127.0.0.1/cb"]);
        assert!(!redirect_matches(
            &r,
            "http://127.0.0.1:51234/cb",
            ApplicationType::Web
        ));
    }

    #[test]
    fn native_loopback_any_port() {
        let r = reg(&["http://127.0.0.1/cb"]);
        let n = ApplicationType::Native;
        assert!(redirect_matches(&r, "http://127.0.0.1:51234/cb", n));
        assert!(redirect_matches(&r, "http://127.0.0.1/cb", n));
        for bad in [
            "http://127.0.0.1:5/other",
            "http://localhost:5/cb",
            "https://127.0.0.1:5/cb",
            "http://127.0.0.1:5/cb?x=1",
            "http://127.0.0.1:5/cb#f",
            "http://127.0.0.2:5/cb",
            "http://127.0.0.1:/cb",
            "http://127.0.0.1:99999/cb",
            "http://127.0.0.1:5x/cb",
            "http://user@127.0.0.1:5/cb",
        ] {
            assert!(!redirect_matches(&r, bad, n), "{bad} must not match");
        }
        let v6 = reg(&["http://[::1]/cb"]);
        assert!(redirect_matches(&v6, "http://[::1]:9/cb", n));
        assert!(!redirect_matches(&v6, "http://127.0.0.1:9/cb", n));
        // Registered with a port: any port still matches.
        let with_port = reg(&["http://127.0.0.1:8080/cb"]);
        assert!(redirect_matches(&with_port, "http://127.0.0.1:9/cb", n));
    }

    #[test]
    fn native_localhost_is_exact() {
        let r = reg(&["http://localhost/cb"]);
        let n = ApplicationType::Native;
        assert!(redirect_matches(&r, "http://localhost/cb", n));
        assert!(!redirect_matches(&r, "http://localhost:5/cb", n));
    }

    #[test]
    fn validate_accepts_good_uris() {
        let w = ApplicationType::Web;
        let n = ApplicationType::Native;
        for ok in [
            "https://rp.example.test/cb",
            "https://rp.example.test/cb?x=1",
            "http://localhost:3000/cb",
            "http://127.0.0.1/cb",
        ] {
            assert!(validate_redirect_uri(ok, w).is_ok(), "{ok}");
        }
        for ok in [
            "http://[::1]/cb",
            "com.example.app:/oauth2redirect",
            "https://a.test/",
        ] {
            assert!(validate_redirect_uri(ok, n).is_ok(), "{ok}");
        }
    }

    #[test]
    fn validate_rejects_bad_uris() {
        let w = ApplicationType::Web;
        let n = ApplicationType::Native;
        for bad in [
            "",
            "/relative/cb",
            "https://rp.example.test/cb#frag",
            "https://*.example.test/cb",
            "http://rp.example.test/cb",
            "https://user:pw@rp.example.test/cb",
            "com.example.app:/cb",
            "javascript:alert(1)",
            "https://rp.example.test/c b",
        ] {
            assert!(validate_redirect_uri(bad, w).is_err(), "{bad}");
        }
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
        ] {
            assert!(validate_redirect_uri(bad, n).is_err(), "{bad}");
        }
        let long = format!(
            "https://rp.example.test/{}",
            "a".repeat(MAX_REDIRECT_URI_LEN)
        );
        assert!(validate_redirect_uri(&long, w).is_err());
    }

    fn message(r: Result<(), CoreError>) -> String {
        match r {
            Err(CoreError::Validation { message, .. }) => message,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn missing_scheme_is_named() {
        let w = ApplicationType::Web;
        for bad in [
            "localhost:5173/cb",
            "LOCALHOST:5173/cb",
            "localhost/cb",
            "127.0.0.1:8080/cb",
            "127.0.0.1/cb",
            "app.example:8443/cb",
            "app.example/cb",
        ] {
            assert_eq!(
                message(validate_redirect_uri(bad, w)),
                MISSING_SCHEME_MESSAGE,
                "{bad}"
            );
        }
        // The DCR and native refusals of the same shape use the same text.
        assert_eq!(
            message(validate_redirect_uri(
                "localhost/cb",
                ApplicationType::Native
            )),
            MISSING_SCHEME_MESSAGE
        );
    }

    #[test]
    fn other_refusals_keep_their_message() {
        let w = ApplicationType::Web;
        assert!(
            message(validate_redirect_uri("http://app.example/cb", w))
                .contains("only allowed for loopback addresses and localhost")
        );
        assert_eq!(
            message(validate_redirect_uri("com.example.app:/cb", w)),
            "web clients must use https redirect URIs"
        );
        assert_eq!(
            message(validate_redirect_uri("/relative/cb", w)),
            "redirect URI must be absolute"
        );
        assert_eq!(
            message(validate_redirect_uri("javascript:alert(1)", w)),
            "redirect URI scheme is not allowed"
        );
    }

    #[test]
    fn messages_do_not_change_decisions() {
        // Native custom schemes that look like host:port stay accepted (decision unchanged).
        let n = ApplicationType::Native;
        for ok in ["com.example.app:/cb", "localhost:5173/cb", "myapp:1234/cb"] {
            assert!(validate_redirect_uri(ok, n).is_ok(), "{ok}");
        }
        let w = ApplicationType::Web;
        for ok in ["http://localhost:5173/cb", "https://app.example/cb"] {
            assert!(validate_redirect_uri(ok, w).is_ok(), "{ok}");
        }
    }

    proptest! {
        #[test]
        fn web_matching_is_set_membership(
            registered in proptest::collection::vec("[ -~]{0,40}", 0..5),
            requested in "[ -~]{0,40}",
            pick in any::<bool>(),
        ) {
            let requested = if pick && !registered.is_empty() {
                registered[0].clone()
            } else {
                requested
            };
            prop_assert_eq!(
                redirect_matches(&registered, &requested, ApplicationType::Web),
                registered.contains(&requested)
            );
        }

        #[test]
        fn missing_scheme_detection_never_panics(uri in "\\PC{0,60}") {
            let _ = looks_like_missing_scheme(&uri);
            let _ = validate_redirect_uri(&uri, ApplicationType::Web);
        }
    }
}
