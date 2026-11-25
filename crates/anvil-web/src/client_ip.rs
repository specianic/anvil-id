//! The client IP address of a request (OPS-06). This is the only client-IP implementation.
//!
//! The TCP peer address is the client unless the peer lies inside an operator-configured trusted
//! proxy CIDR. Then the configured forwarding header (`X-Forwarded-For` by default, or RFC 7239
//! `Forwarded`) is walked from right to left, skipping trusted hops; the first untrusted address is
//! the client. An unparsable entry (`unknown`, an obfuscated `_identifier`, garbage) stops the walk
//! and the last trusted hop is used. If every entry is trusted, the leftmost one is used.
//!
//! Only the one configured header is read, so a client cannot mix sources. Scheme and host are never
//! taken from forwarding headers: issuers, cookie attributes and HSTS derive from the configured
//! public URL only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use ipnet::IpNet;

use crate::state::AppState;

/// At most this many forwarding entries are examined (from the right). Longer chains stop at the
/// last trusted hop examined.
pub const MAX_HOPS: usize = 32;

/// Which forwarding header trusted proxies set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ForwardedHeader {
    /// `X-Forwarded-For: client, proxy1, proxy2`.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded: for=client, for=proxy1`.
    Forwarded,
}

impl ForwardedHeader {
    fn name(self) -> HeaderName {
        match self {
            Self::XForwardedFor => HeaderName::from_static("x-forwarded-for"),
            Self::Forwarded => HeaderName::from_static("forwarded"),
        }
    }
}

/// Trusted reverse proxies. The default trusts nobody: forwarding headers are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    pub cidrs: Vec<IpNet>,
    pub header: ForwardedHeader,
}

impl TrustedProxies {
    /// Loopback only (`127.0.0.0/8`, `::1/128`): the development-mode default.
    pub fn loopback() -> Self {
        Self {
            cidrs: vec![
                IpNet::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).expect("valid prefix"),
                IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).expect("valid prefix"),
            ],
            header: ForwardedHeader::XForwardedFor,
        }
    }

    /// `true` if `ip` (normalised) lies in a trusted CIDR.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.cidrs.iter().any(|net| net.contains(&ip))
    }
}

/// The client IP of a request whose TCP peer is `peer`. IPv4-mapped IPv6 addresses are returned
/// as IPv4.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, cfg: &TrustedProxies) -> IpAddr {
    let peer = peer.to_canonical();
    if !cfg.is_trusted(peer) {
        return peer;
    }
    let entries = entries(headers, cfg.header);
    let mut last_trusted = peer;
    for entry in entries.iter().rev().take(MAX_HOPS) {
        let Some(ip) = entry.as_deref().and_then(parse_node) else {
            return last_trusted;
        };
        let ip = ip.to_canonical();
        if !cfg.is_trusted(ip) {
            return ip;
        }
        last_trusted = ip;
    }
    last_trusted
}

/// The node values of the configured header, all header lines joined in order. `None` marks an
/// element that has no usable node (for example a `Forwarded` element without `for=`).
fn entries(headers: &HeaderMap, which: ForwardedHeader) -> Vec<Option<String>> {
    let mut out = Vec::new();
    for value in headers.get_all(which.name()) {
        let Ok(value) = value.to_str() else {
            // A non-visible-ASCII line cannot be walked reliably: treat it as one bad entry.
            out.push(None);
            continue;
        };
        for element in split_unquoted(value, ',') {
            match which {
                ForwardedHeader::XForwardedFor => out.push(Some(element.trim().to_owned())),
                ForwardedHeader::Forwarded => out.push(forwarded_for(element)),
            }
        }
    }
    out
}

/// The `for` parameter of one `Forwarded` element (keys are case-insensitive), unquoted.
fn forwarded_for(element: &str) -> Option<String> {
    split_unquoted(element, ';').into_iter().find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("for") {
            return None;
        }
        Some(unquote(value.trim()))
    })
}

/// Splits on `sep` outside double-quoted strings (backslash escapes honoured inside quotes).
fn split_unquoted(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if in_quotes && c == '\\' {
            escaped = true;
        } else if c == '"' {
            in_quotes = !in_quotes;
        } else if c == sep && !in_quotes {
            parts.push(&s[start..i]);
            start = i + c.len_utf8();
        }
    }
    parts.push(&s[start..]);
    parts
}

fn unquote(v: &str) -> String {
    match v.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => {
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                } else {
                    out.push(c);
                }
            }
            out
        }
        None => v.to_owned(),
    }
}

/// Parses a node: `1.2.3.4`, `1.2.3.4:port`, `2001:db8::1`, `[2001:db8::1]` or
/// `[2001:db8::1]:port`. `unknown`, obfuscated identifiers and anything else give `None`.
fn parse_node(node: &str) -> Option<IpAddr> {
    let node = node.trim();
    if let Some(rest) = node.strip_prefix('[') {
        let (addr, after) = rest.split_once(']')?;
        if !(after.is_empty() || valid_port(after.strip_prefix(':')?)) {
            return None;
        }
        return addr.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    if let Ok(ip) = node.parse::<IpAddr>() {
        return Some(ip);
    }
    let (addr, port) = node.rsplit_once(':')?;
    if !valid_port(port) {
        return None;
    }
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// A decimal port or an RFC 7239 obfuscated port (`_abc`).
fn valid_port(p: &str) -> bool {
    if let Some(obf) = p.strip_prefix('_') {
        return !obf.is_empty()
            && obf
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    }
    !p.is_empty() && p.len() <= 5 && p.parse::<u16>().is_ok()
}

/// The client IP of the request, from the peer address (`ConnectInfo<SocketAddr>`) and the
/// configured trusted proxies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Rejection of [`ClientIp`]: the request carries no peer address. This is a server wiring error,
/// answered with a generic 500 (never a made-up address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingPeerAddress;

impl IntoResponse for MissingPeerAddress {
    fn into_response(self) -> Response {
        tracing::error!("request without peer address (ConnectInfo missing)");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}

impl ClientIp {
    /// Resolves the client IP from request parts (`ConnectInfo<SocketAddr>` extension).
    pub fn from_parts(parts: &Parts, cfg: &TrustedProxies) -> Result<Self, MissingPeerAddress> {
        let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
            return Err(MissingPeerAddress);
        };
        Ok(Self(client_ip(peer.ip(), &parts.headers, cfg)))
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = MissingPeerAddress;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, MissingPeerAddress> {
        Self::from_parts(parts, &state.config().trusted_proxies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Request};

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    fn trusted(cidrs: &[&str], header: ForwardedHeader) -> TrustedProxies {
        TrustedProxies {
            cidrs: cidrs.iter().map(|c| c.parse().expect("cidr")).collect(),
            header,
        }
    }

    #[test]
    fn client_ip_parses_nodes() {
        assert_eq!(parse_node("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_node(" 1.2.3.4:8080 "), Some(ip("1.2.3.4")));
        assert_eq!(parse_node("2001:db8::1"), Some(ip("2001:db8::1")));
        assert_eq!(parse_node("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_node("[2001:db8::1]:4711"), Some(ip("2001:db8::1")));
        assert_eq!(parse_node("[2001:db8::1]:_x1"), Some(ip("2001:db8::1")));
        for bad in [
            "unknown",
            "_hidden",
            "",
            "1.2.3",
            "1.2.3.4:99999",
            "1.2.3.4:",
            "[1.2.3.4]",
            "[2001:db8::1]x",
            "2001:db8::1:_x",
            "evil.test",
        ] {
            assert_eq!(parse_node(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn client_ip_splits_forwarded_respecting_quotes() {
        assert_eq!(
            split_unquoted(r#"for="a,b";proto=https, for=c"#, ','),
            vec![r#"for="a,b";proto=https"#, " for=c"]
        );
        assert_eq!(
            forwarded_for(r#"Proto=https;FOR="[2001:db8::1]:4711""#).as_deref(),
            Some("[2001:db8::1]:4711")
        );
        assert_eq!(forwarded_for("proto=https;by=1.2.3.4"), None);
        assert_eq!(unquote(r#""a\"b""#), "a\"b");
    }

    #[test]
    fn client_ip_loopback_default_and_mapped_peer() {
        let lo = TrustedProxies::loopback();
        assert!(lo.is_trusted(ip("127.0.0.1")));
        assert!(lo.is_trusted(ip("::1")));
        assert!(lo.is_trusted(ip("::ffff:127.0.0.1")));
        assert!(!lo.is_trusted(ip("10.0.0.1")));
        assert!(!TrustedProxies::default().is_trusted(ip("127.0.0.1")));
    }

    #[test]
    fn client_ip_caps_the_walk() {
        let cfg = trusted(&["10.0.0.0/8"], ForwardedHeader::XForwardedFor);
        let mut chain = vec!["198.51.100.7".to_owned()];
        chain.extend((0..MAX_HOPS + 5).map(|i| format!("10.0.{}.{}", i / 250, i % 250 + 1)));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&chain.join(", ")).expect("header"),
        );
        let got = client_ip(ip("10.9.9.9"), &headers, &cfg);
        assert!(cfg.is_trusted(got), "stops at a trusted hop: {got}");
        assert_ne!(got, ip("198.51.100.7"));
    }

    #[test]
    fn client_ip_extractor_requires_connect_info() {
        let cfg = TrustedProxies::default();
        let (parts, ()) = Request::get("/").body(()).expect("req").into_parts();
        let err = ClientIp::from_parts(&parts, &cfg).expect_err("no peer, no address");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        let mut req = Request::get("/")
            .header("x-forwarded-for", "1.2.3.4")
            .body(())
            .expect("req");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 1234))));
        let (parts, ()) = req.into_parts();
        assert_eq!(
            ClientIp::from_parts(&parts, &cfg).expect("peer").0,
            ip("203.0.113.9")
        );
    }
}
