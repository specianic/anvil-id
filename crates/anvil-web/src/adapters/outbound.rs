//! The single outbound HTTP client (ARCHITECTURE §11, SSRF row).
//!
//! Every server-side fetch AnvilID makes goes through [`OutboundClient`]: CAPTCHA siteverify, the
//! HIBP range API and, from 0.3 on, upstream OIDC discovery / JWKS / token / userinfo and
//! back-channel logout delivery. Some of those URLs come from administrators or clients, so the
//! client is built to refuse server-side request forgery:
//!
//! - **Destination policy.** Private, loopback, link-local, shared, documentation, benchmarking,
//!   multicast and reserved ranges are blocked ([`OutboundPolicy::allows`]), including IPv4
//!   embedded in IPv6 (IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`).
//!   IP-literal hosts are checked before sending (reqwest does not call the resolver for them);
//!   host names are checked on every DNS answer by [`GuardedResolver`], so the address connected
//!   to is the address checked (no DNS-rebinding window). Operators open specific ranges with
//!   `outbound_allow_cidrs`; an allow-listed address is allowed even if it is in a blocked range.
//! - **No redirects** (a 3xx is returned as [`OutboundError::Status`]), **no proxies** (the
//!   `*_PROXY` environment is ignored), **no userinfo** in URLs.
//! - **https only.** Plain http only when the policy allows it (development mode) *and* the
//!   destination is explicitly allow-listed.
//! - **Bounded.** Connect timeout 5 s, total timeout 10 s (per request overridable), response
//!   bodies read through [`read_capped`].
//! - **Quiet errors.** [`OutboundError`] never echoes the URL, a resolved address or a body.
//!
//! Development-mode defaults (see [`crate::config::AppConfig::new`]) follow the trusted-proxies
//! precedent: a public URL on a loopback host allows loopback destinations (`127.0.0.0/8`,
//! `::1/128`) and plain http to them, so local mocks and a local upstream work out of the box.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};

use crate::errors::WebError;

/// Body limit for documents (discovery, JWKS, userinfo, siteverify).
pub const LIMIT_DOCUMENT: usize = 1024 * 1024;
/// Body limit for token-endpoint responses.
pub const LIMIT_TOKEN: usize = 64 * 1024;
/// Connect timeout of every outbound request.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default total timeout of an outbound request (overridable per request).
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an outbound request was refused or failed. The text never contains the URL, an address
/// or a response body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboundError {
    #[error("destination not allowed")]
    Blocked,
    #[error("outbound request failed")]
    Network,
    #[error("outbound request timed out")]
    Timeout,
    #[error("outbound request answered with status {0}")]
    Status(u16),
    #[error("outbound response too large")]
    TooLarge,
    #[error("invalid outbound URL")]
    InvalidUrl,
}

/// Which destinations the outbound client may reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// Destinations allowed even inside a blocked range (`outbound_allow_cidrs`). Plain http is
    /// only ever sent to these.
    pub allow_cidrs: Vec<IpNet>,
    /// Extra trusted root certificates (PEM bundle, `outbound_ca_file`), merged with the
    /// built-in roots.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// Plain http may be used towards allow-listed destinations (development mode).
    pub allow_http: bool,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), len)
}

const fn v6(s: [u16; 8], len: u8) -> Ipv6Net {
    Ipv6Net::new_assert(
        Ipv6Addr::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
        len,
    )
}

/// Blocked IPv4 ranges (IANA special-purpose registry: not globally reachable or reserved).
pub const BLOCKED_V4: &[Ipv4Net] = &[
    v4(0, 0, 0, 0, 8),          // "this network"
    v4(10, 0, 0, 0, 8),         // private
    v4(100, 64, 0, 0, 10),      // shared address space (CGNAT)
    v4(127, 0, 0, 0, 8),        // loopback
    v4(169, 254, 0, 0, 16),     // link-local (cloud metadata)
    v4(172, 16, 0, 0, 12),      // private
    v4(192, 0, 0, 0, 24),       // IETF protocol assignments
    v4(192, 0, 2, 0, 24),       // documentation
    v4(192, 88, 99, 0, 24),     // deprecated 6to4 relay anycast
    v4(192, 168, 0, 0, 16),     // private
    v4(198, 18, 0, 0, 15),      // benchmarking
    v4(198, 51, 100, 0, 24),    // documentation
    v4(203, 0, 113, 0, 24),     // documentation
    v4(224, 0, 0, 0, 4),        // multicast
    v4(240, 0, 0, 0, 4),        // reserved
    v4(255, 255, 255, 255, 32), // broadcast
];

/// Blocked IPv6 ranges. IPv4 embedded in IPv6 is checked separately ([`embedded_v4`]).
pub const BLOCKED_V6: &[Ipv6Net] = &[
    v6([0, 0, 0, 0, 0, 0, 0, 0], 128),         // unspecified
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128),         // loopback
    v6([0, 0, 0, 0, 0, 0, 0, 0], 96),          // deprecated IPv4-compatible
    v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),  // local-use NAT64
    v6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),      // discard-only
    v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 32),     // Teredo (obfuscated IPv4)
    v6([0x2001, 2, 0, 0, 0, 0, 0, 0], 48),     // benchmarking
    v6([0x2001, 0x10, 0, 0, 0, 0, 0, 0], 28),  // deprecated ORCHID
    v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation
    v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),     // documentation
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),      // unique local
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),     // link-local
    v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),     // deprecated site-local
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),      // multicast
];

/// The IPv4 address embedded in an IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`) or
/// 6to4 (`2002::/16`) address.
pub fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return Some(mapped);
    }
    let s = ip.segments();
    let o = ip.octets();
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// `true` if `ip` is in a blocked range, directly or through an embedded IPv4 address.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => BLOCKED_V4.iter().any(|n| n.contains(&a)),
        IpAddr::V6(a) => {
            BLOCKED_V6.iter().any(|n| n.contains(&a))
                || embedded_v4(a).is_some_and(|e| is_blocked(IpAddr::V4(e)))
        }
    }
}

impl OutboundPolicy {
    /// The development-mode policy: loopback allowed, plain http to it allowed.
    pub fn loopback_dev() -> Self {
        Self {
            allow_cidrs: vec![
                IpNet::V4(v4(127, 0, 0, 0, 8)),
                IpNet::V6(v6([0, 0, 0, 0, 0, 0, 0, 1], 128)),
            ],
            extra_ca_pem: None,
            allow_http: true,
        }
    }

    /// `true` if `ip` (or the IPv4 address an IPv4-mapped `ip` connects to) is allow-listed.
    pub fn allow_listed(&self, ip: IpAddr) -> bool {
        let mapped = match ip {
            IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        [Some(ip), mapped]
            .into_iter()
            .flatten()
            .any(|c| self.allow_cidrs.iter().any(|n| n.contains(&c)))
    }

    /// `true` if an https request may connect to `ip`: allow-listed, or not in a blocked range.
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.allow_listed(ip) || !is_blocked(ip)
    }
}

/// The resolver error when every answer was filtered out. Carries no name or address.
#[derive(Debug, thiserror::Error)]
#[error("destination not allowed")]
struct DestinationBlocked;

/// The resolver error when the name did not resolve. Carries no name.
#[derive(Debug, thiserror::Error)]
#[error("name resolution failed")]
struct ResolveFailed;

#[derive(Debug, Clone, Copy)]
enum ResolveMode {
    /// https: any allowed address ([`OutboundPolicy::allows`]).
    Public,
    /// plain http: allow-listed addresses only.
    AllowListed,
}

/// DNS resolver that drops every answer the policy does not allow and fails with "destination
/// not allowed" when none remains.
#[derive(Debug, Clone)]
pub struct GuardedResolver {
    policy: Arc<OutboundPolicy>,
    mode: ResolveMode,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = Arc::clone(&self.policy);
        let mode = self.mode;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            type BoxError = Box<dyn std::error::Error + Send + Sync>;
            let answers = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| Box::new(ResolveFailed) as BoxError)?;
            let kept: Vec<SocketAddr> = answers
                .filter(|a| match mode {
                    ResolveMode::Public => policy.allows(a.ip()),
                    ResolveMode::AllowListed => policy.allow_listed(a.ip()),
                })
                .collect();
            if kept.is_empty() {
                return Err(Box::new(DestinationBlocked) as BoxError);
            }
            Ok(Box::new(kept.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The guarded outbound HTTP client. Cheap to clone.
#[derive(Clone)]
pub struct OutboundClient {
    policy: Arc<OutboundPolicy>,
    https: reqwest::Client,
    /// Only built when the policy allows plain http.
    http: Option<reqwest::Client>,
}

impl std::fmt::Debug for OutboundClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundClient")
            .field("allow_cidrs", &self.policy.allow_cidrs.len())
            .field("allow_http", &self.policy.allow_http)
            .finish_non_exhaustive()
    }
}

/// Validates a PEM bundle of extra root certificates: at least one certificate, every one
/// usable as a trust anchor. Errors never contain the bundle.
pub fn validate_ca_pem(pem: &[u8]) -> Result<(), WebError> {
    OutboundClient::new(&OutboundPolicy {
        extra_ca_pem: Some(pem.to_vec()),
        ..OutboundPolicy::default()
    })
    .map(|_| ())
}

impl OutboundClient {
    /// Builds the client for `policy`. Fails if the extra CA bundle holds no usable certificate
    /// or the TLS stack cannot be initialised.
    pub fn new(policy: &OutboundPolicy) -> Result<Self, WebError> {
        let policy = Arc::new(policy.clone());
        let certs = match &policy.extra_ca_pem {
            Some(pem) => {
                let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|_| {
                    WebError::Config("outbound CA bundle is not valid PEM".to_owned())
                })?;
                if certs.is_empty() {
                    return Err(WebError::Config(
                        "outbound CA bundle contains no certificate".to_owned(),
                    ));
                }
                certs
            }
            None => Vec::new(),
        };
        let build = |mode: ResolveMode, https_only: bool| {
            reqwest::Client::builder()
                .dns_resolver(GuardedResolver {
                    policy: Arc::clone(&policy),
                    mode,
                })
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .https_only(https_only)
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(TOTAL_TIMEOUT)
                .user_agent("anvilid")
                .tls_certs_merge(certs.clone())
                .build()
                .map_err(|_| {
                    WebError::Config(
                        "building the outbound HTTP client failed (check the outbound CA bundle)"
                            .to_owned(),
                    )
                })
        };
        let https = build(ResolveMode::Public, true)?;
        let http = if policy.allow_http {
            Some(build(ResolveMode::AllowListed, false)?)
        } else {
            None
        };
        Ok(Self {
            policy,
            https,
            http,
        })
    }

    /// The policy this client enforces.
    pub fn policy(&self) -> &OutboundPolicy {
        &self.policy
    }

    /// Checks everything about `url` that can be checked before connecting: scheme (https, or
    /// http when the policy allows it), no userinfo, a host, and an IP-literal host against the
    /// policy (plain http only to an allow-listed literal). Host names are checked by the
    /// resolver on every connection.
    pub fn check_url(&self, url: &url::Url) -> Result<(), OutboundError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OutboundError::InvalidUrl);
        }
        let https = match url.scheme() {
            "https" => true,
            "http" if self.policy.allow_http => false,
            _ => return Err(OutboundError::InvalidUrl),
        };
        let ip = match url.host() {
            Some(url::Host::Ipv4(a)) => IpAddr::V4(a),
            Some(url::Host::Ipv6(a)) => IpAddr::V6(a),
            Some(url::Host::Domain(d)) if !d.is_empty() => return Ok(()),
            _ => return Err(OutboundError::InvalidUrl),
        };
        let allowed = if https {
            self.policy.allows(ip)
        } else {
            self.policy.allow_listed(ip)
        };
        if allowed {
            Ok(())
        } else {
            Err(OutboundError::Blocked)
        }
    }

    /// A request to `url` after [`Self::check_url`].
    pub fn request(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> Result<OutboundRequest, OutboundError> {
        let url = url::Url::parse(url).map_err(|_| OutboundError::InvalidUrl)?;
        self.check_url(&url)?;
        let client = match url.scheme() {
            "https" => &self.https,
            _ => self.http.as_ref().ok_or(OutboundError::InvalidUrl)?,
        };
        Ok(OutboundRequest {
            inner: client.request(method, url),
        })
    }

    /// A GET request to `url`.
    pub fn get(&self, url: &str) -> Result<OutboundRequest, OutboundError> {
        self.request(reqwest::Method::GET, url)
    }

    /// A POST request to `url`.
    pub fn post(&self, url: &str) -> Result<OutboundRequest, OutboundError> {
        self.request(reqwest::Method::POST, url)
    }
}

/// A checked request of an [`OutboundClient`].
#[derive(Debug)]
pub struct OutboundRequest {
    inner: reqwest::RequestBuilder,
}

impl OutboundRequest {
    pub fn header(self, name: HeaderName, value: HeaderValue) -> Self {
        Self {
            inner: self.inner.header(name, value),
        }
    }

    /// A form-encoded body (`application/x-www-form-urlencoded`); `body` is already encoded.
    pub fn form_body(self, body: String) -> Self {
        Self {
            inner: self
                .inner
                .header(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                )
                .body(body),
        }
    }

    /// A JSON body.
    pub fn json<T: serde::Serialize + ?Sized>(self, body: &T) -> Self {
        Self {
            inner: self.inner.json(body),
        }
    }

    pub fn basic_auth(self, user: &str, password: &str) -> Self {
        Self {
            inner: self.inner.basic_auth(user, Some(password)),
        }
    }

    pub fn bearer_auth(self, token: &str) -> Self {
        Self {
            inner: self.inner.bearer_auth(token),
        }
    }

    /// Overrides the total timeout ([`TOTAL_TIMEOUT`]) of this request.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
        }
    }

    /// Sends the request and returns the response whatever its status (redirects are never
    /// followed). For callers that read error bodies (OAuth token endpoints).
    pub async fn send_any_status(self) -> Result<reqwest::Response, OutboundError> {
        self.inner.send().await.map_err(map_error)
    }

    /// Sends the request; any non-2xx status (including a 3xx redirect) is
    /// [`OutboundError::Status`].
    pub async fn send(self) -> Result<reqwest::Response, OutboundError> {
        let resp = self.send_any_status().await?;
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(OutboundError::Status(resp.status().as_u16()))
        }
    }

    /// [`Self::send`], then [`read_capped`] with `limit`.
    pub async fn fetch(self, limit: usize) -> Result<Vec<u8>, OutboundError> {
        let resp = self.send().await?;
        read_capped(resp, limit).await
    }
}

/// Reads the response body, failing with [`OutboundError::TooLarge`] as soon as it exceeds
/// `limit` bytes (streaming; never buffers more than `limit` plus one chunk).
pub async fn read_capped(
    mut resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, OutboundError> {
    if resp
        .content_length()
        .is_some_and(|len| len > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        return Err(OutboundError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(map_error)? {
        if body.len() + chunk.len() > limit {
            return Err(OutboundError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn map_error(err: reqwest::Error) -> OutboundError {
    if err.is_timeout() {
        return OutboundError::Timeout;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&err);
    while let Some(e) = source {
        if e.is::<DestinationBlocked>() {
            return OutboundError::Blocked;
        }
        source = e.source();
    }
    OutboundError::Network
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn blocked_table() {
        let p = OutboundPolicy::default();
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:db8::1",
            "3fff::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            // Embedded IPv4.
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "2002:c0a8:101::",
        ] {
            assert!(!p.allows(ip(s)), "{s} must be blocked");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        let p = OutboundPolicy::default();
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(p.allows(ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn allow_list_overrides_and_dev_default() {
        let p = OutboundPolicy {
            allow_cidrs: vec!["127.0.0.1/32".parse().expect("net")],
            ..OutboundPolicy::default()
        };
        assert!(p.allows(ip("127.0.0.1")));
        assert!(p.allows(ip("::ffff:127.0.0.1")), "mapped connects to v4");
        assert!(!p.allows(ip("127.0.0.2")));
        assert!(!p.allows(ip("::1")));
        assert!(
            !p.allow_listed(ip("8.8.8.8")),
            "public but not allow-listed"
        );
        let dev = OutboundPolicy::loopback_dev();
        assert!(dev.allow_http);
        assert!(dev.allows(ip("127.0.0.53")) && dev.allows(ip("::1")));
        assert!(!dev.allows(ip("10.0.0.1")) && !dev.allows(ip("169.254.169.254")));
    }

    #[test]
    fn check_url_rules() {
        let prod = OutboundClient::new(&OutboundPolicy::default()).expect("client");
        let check = |c: &OutboundClient, u: &str| c.check_url(&url::Url::parse(u).expect("url"));
        assert_eq!(check(&prod, "https://idp.example.com/x"), Ok(()));
        assert_eq!(check(&prod, "https://8.8.8.8/x"), Ok(()));
        assert_eq!(
            check(&prod, "http://idp.example.com/x"),
            Err(OutboundError::InvalidUrl)
        );
        assert_eq!(
            check(&prod, "https://user:pw@idp.example.com/"),
            Err(OutboundError::InvalidUrl)
        );
        assert_eq!(
            check(&prod, "https://user@idp.example.com/"),
            Err(OutboundError::InvalidUrl)
        );
        assert_eq!(
            check(&prod, "file:///etc/passwd"),
            Err(OutboundError::InvalidUrl)
        );
        assert_eq!(
            check(&prod, "ftp://8.8.8.8/"),
            Err(OutboundError::InvalidUrl)
        );
        // Alternative IPv4 notations normalise to the literal and are blocked.
        for u in [
            "https://2130706433/",
            "https://0x7f.1/",
            "https://0177.0.0.1/",
            "https://127.1/",
            "https://[::ffff:7f00:1]/",
        ] {
            assert_eq!(check(&prod, u), Err(OutboundError::Blocked), "{u}");
        }
        let dev = OutboundClient::new(&OutboundPolicy::loopback_dev()).expect("client");
        assert_eq!(check(&dev, "http://127.0.0.1:9/x"), Ok(()));
        assert_eq!(
            check(&dev, "http://8.8.8.8/x"),
            Err(OutboundError::Blocked),
            "http only to allow-listed destinations"
        );
        assert_eq!(check(&dev, "https://8.8.8.8/x"), Ok(()));
    }

    #[test]
    fn errors_never_echo_details() {
        for e in [
            OutboundError::Blocked,
            OutboundError::Network,
            OutboundError::Timeout,
            OutboundError::Status(302),
            OutboundError::TooLarge,
            OutboundError::InvalidUrl,
        ] {
            let s = e.to_string();
            assert!(
                !s.contains('.') && !s.contains(':') && !s.contains('/'),
                "{s}"
            );
        }
    }

    #[test]
    fn bad_ca_bundle_is_rejected_without_echoing_it() {
        let err = validate_ca_pem(b"not a pem bundle secret-ish").expect_err("no certs");
        assert!(!err.to_string().contains("secret-ish"));
        let garbage = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".as_slice();
        assert!(
            validate_ca_pem(garbage).is_err(),
            "unusable DER is rejected"
        );
    }

    fn in_v4(net: Ipv4Net, bits: u32) -> Ipv4Addr {
        let host_mask = u32::MAX
            .checked_shr(u32::from(net.prefix_len()))
            .unwrap_or(0);
        Ipv4Addr::from((u32::from(net.network()) & !host_mask) | (bits & host_mask))
    }

    fn in_v6(net: Ipv6Net, bits: u128) -> Ipv6Addr {
        let host_mask = u128::MAX
            .checked_shr(u32::from(net.prefix_len()))
            .unwrap_or(0);
        Ipv6Addr::from((u128::from(net.network()) & !host_mask) | (bits & host_mask))
    }

    proptest! {
        #[test]
        fn any_address_in_a_blocked_v4_net_is_blocked(i in 0..BLOCKED_V4.len(), bits: u32) {
            let a = in_v4(BLOCKED_V4[i], bits);
            let p = OutboundPolicy::default();
            prop_assert!(!p.allows(IpAddr::V4(a)), "{a}");
            prop_assert!(!p.allows(IpAddr::V6(a.to_ipv6_mapped())), "mapped {a}");
            let o = a.octets();
            let nat64 = Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0,
                u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]));
            prop_assert!(!p.allows(IpAddr::V6(nat64)), "nat64 {nat64}");
            let six_to_four = Ipv6Addr::new(0x2002,
                u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]), 0, 0, 0, 0, 1);
            prop_assert!(!p.allows(IpAddr::V6(six_to_four)), "6to4 {six_to_four}");
        }

        #[test]
        fn any_address_in_a_blocked_v6_net_is_blocked(i in 0..BLOCKED_V6.len(), bits: u128) {
            let a = in_v6(BLOCKED_V6[i], bits);
            prop_assert!(!OutboundPolicy::default().allows(IpAddr::V6(a)), "{a}");
        }
    }
}
