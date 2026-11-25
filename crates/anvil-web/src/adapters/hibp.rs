//! Breached-password check through the Have I Been Pwned k-anonymity range API (AUTH-01).
//!
//! Only the first five hex characters of the password's SHA-1 leave the server
//! (`GET {base_url}/range/{prefix}` with `Add-Padding: true`); the suffix is matched locally.
//! Padding entries have a count of 0 and never match.
//!
//! **Fail-open:** a network error, a timeout (2 s by default) or a non-success status logs a
//! warning and reports "not breached", so an unreachable API never blocks registration or password
//! changes. Operators of air-gapped installations configure [`BreachCheckMode::Off`].
//!
//! Requests go through the single SSRF-guarded [`OutboundClient`]; the response body is capped.

use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::ports::BreachChecker;

use crate::adapters::outbound::{OutboundClient, OutboundPolicy};

/// Public HIBP Pwned Passwords API base URL.
pub const HIBP_BASE_URL: &str = "https://api.pwnedpasswords.com";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest range response read. A padded range response is about 40 KiB.
const MAX_BODY: usize = 256 * 1024;

/// How breached passwords are detected (configuration `password.breach_check`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreachCheckMode {
    /// No breach check (air-gapped installations). Every password is reported as not breached.
    Off,
    /// The HIBP range API at `base_url` (normally [`HIBP_BASE_URL`]).
    Hibp { base_url: String },
}

/// The breach checker for the configured mode, sending through `outbound` (the binary passes
/// the client built from the operator's outbound policy).
pub fn breach_checker_with(
    mode: BreachCheckMode,
    outbound: Arc<OutboundClient>,
) -> Arc<dyn BreachChecker> {
    match mode {
        BreachCheckMode::Off => Arc::new(Disabled),
        BreachCheckMode::Hibp { base_url } => {
            Arc::new(HibpChecker::new(outbound, &base_url, DEFAULT_TIMEOUT))
        }
    }
}

/// The breach checker for the configured mode with the production outbound policy (public
/// https destinations only, built-in roots). If that client cannot be built the check fails
/// open, as documented for an unreachable API.
pub fn breach_checker(mode: BreachCheckMode) -> Arc<dyn BreachChecker> {
    if mode == BreachCheckMode::Off {
        return Arc::new(Disabled);
    }
    match OutboundClient::new(&OutboundPolicy::default()) {
        Ok(client) => breach_checker_with(mode, Arc::new(client)),
        Err(e) => {
            tracing::error!(error = %e, "building the outbound client failed; breach check unavailable (fail-open)");
            Arc::new(Unavailable)
        }
    }
}

/// The outbound client could not be built: every check fails open with a warning.
#[derive(Debug, Clone, Copy)]
struct Unavailable;

#[async_trait::async_trait]
impl BreachChecker for Unavailable {
    async fn is_breached(&self, _password: &str) -> Result<bool, CoreError> {
        tracing::warn!("breached-password check unavailable; allowing the password (fail-open)");
        Ok(false)
    }
}

/// Breach checking switched off by configuration (documented, air-gapped deployments).
#[derive(Debug, Clone, Copy)]
struct Disabled;

#[async_trait::async_trait]
impl BreachChecker for Disabled {
    async fn is_breached(&self, _password: &str) -> Result<bool, CoreError> {
        Ok(false)
    }
}

/// HIBP range API client.
#[derive(Debug, Clone)]
pub struct HibpChecker {
    outbound: Arc<OutboundClient>,
    base_url: String,
    timeout: Duration,
}

fn sha1_upper_hex(password: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        password.as_bytes(),
    );
    let mut out = String::with_capacity(40);
    for &b in digest.as_ref() {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// `true` if the response body lists `suffix` with a count above zero.
fn suffix_listed(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        let Some((s, count)) = line.trim().split_once(':') else {
            return false;
        };
        s.eq_ignore_ascii_case(suffix) && count.trim().parse::<u64>().is_ok_and(|c| c > 0)
    })
}

impl HibpChecker {
    /// A client for the range API at `base_url` with the given request timeout, sending
    /// through `outbound`.
    pub fn new(outbound: Arc<OutboundClient>, base_url: &str, timeout: Duration) -> Self {
        Self {
            outbound,
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
        }
    }

    async fn lookup(&self, prefix: &str, suffix: &str) -> Result<bool, String> {
        let url = format!("{}/range/{prefix}", self.base_url);
        let body = self
            .outbound
            .get(&url)
            .map_err(|e| e.to_string())?
            .header(
                reqwest::header::HeaderName::from_static("add-padding"),
                reqwest::header::HeaderValue::from_static("true"),
            )
            .timeout(self.timeout)
            .fetch(MAX_BODY)
            .await
            .map_err(|e| e.to_string())?;
        let body = String::from_utf8(body).map_err(|_| "response is not UTF-8".to_owned())?;
        Ok(suffix_listed(&body, suffix))
    }
}

#[async_trait::async_trait]
impl BreachChecker for HibpChecker {
    async fn is_breached(&self, password: &str) -> Result<bool, CoreError> {
        let hash = sha1_upper_hex(password);
        let (prefix, suffix) = hash.split_at(5);
        match self.lookup(prefix, suffix).await {
            Ok(found) => Ok(found),
            Err(e) => {
                tracing::warn!(error = %e, "breached-password check unavailable; allowing the password (fail-open)");
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const PREFIX: &str = "5BAA6";
    const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_is_upper_hex() {
        assert_eq!(sha1_upper_hex("password"), format!("{PREFIX}{SUFFIX}"));
    }

    fn local() -> Arc<OutboundClient> {
        Arc::new(OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("client"))
    }

    async fn server_with(body: &str, status: u16) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/range/{PREFIX}")))
            .and(header("Add-Padding", "true"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body.to_owned()))
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn listed_suffix_is_breached() {
        let body = format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{SUFFIX}:3861493\r\n");
        let server = server_with(&body, 200).await;
        let c = HibpChecker::new(local(), &server.uri(), DEFAULT_TIMEOUT);
        assert!(c.is_breached("password").await.expect("check"));
    }

    #[tokio::test]
    async fn padding_entry_with_count_zero_is_not_breached() {
        let body = format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{SUFFIX}:0\r\n");
        let server = server_with(&body, 200).await;
        let c = HibpChecker::new(local(), &server.uri(), DEFAULT_TIMEOUT);
        assert!(!c.is_breached("password").await.expect("check"));
    }

    #[tokio::test]
    async fn absent_suffix_is_not_breached() {
        let server = server_with("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", 200).await;
        let c = HibpChecker::new(local(), &server.uri(), DEFAULT_TIMEOUT);
        assert!(!c.is_breached("password").await.expect("check"));
    }

    #[tokio::test]
    async fn server_error_fails_open() {
        let server = server_with("", 500).await;
        let c = HibpChecker::new(local(), &server.uri(), DEFAULT_TIMEOUT);
        assert!(!c.is_breached("password").await.expect("fail-open"));
    }

    #[tokio::test]
    async fn timeout_fails_open() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("{SUFFIX}:5"))
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;
        let c = HibpChecker::new(local(), &server.uri(), Duration::from_millis(100));
        assert!(!c.is_breached("password").await.expect("fail-open"));
    }

    #[tokio::test]
    async fn blocked_destination_fails_open_without_a_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!("{SUFFIX}:5")))
            .expect(0)
            .mount(&server)
            .await;
        // The production policy does not reach a loopback mock.
        let prod = Arc::new(OutboundClient::new(&OutboundPolicy::default()).expect("client"));
        let c = HibpChecker::new(prod, &server.uri(), DEFAULT_TIMEOUT);
        assert!(!c.is_breached("password").await.expect("fail-open"));
    }

    #[tokio::test]
    async fn off_mode_reports_not_breached() {
        let c = breach_checker(BreachCheckMode::Off);
        assert!(!c.is_breached("password").await.expect("off"));
    }
}
