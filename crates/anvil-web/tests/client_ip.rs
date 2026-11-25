//! Client IP behind trusted proxies (OPS-06): spoofing, chains, `Forwarded`, IPv4-mapped peers,
//! and proof that scheme/host never come from forwarding headers. Selected backend via
//! `ANVILID_TEST_DB` for the harness tests.

mod support;

use std::net::IpAddr;

use anvil_web::client_ip::{ForwardedHeader, TrustedProxies, client_ip};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, header};
use proptest::prelude::*;
use support::{TestApp, json};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

fn cfg(cidrs: &[&str], header: ForwardedHeader) -> TrustedProxies {
    TrustedProxies {
        cidrs: cidrs.iter().map(|c| c.parse().expect("cidr")).collect(),
        header,
    }
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_str(v).expect("header value"));
    }
    h
}

const XFF: ForwardedHeader = ForwardedHeader::XForwardedFor;
const FWD: ForwardedHeader = ForwardedHeader::Forwarded;

#[test]
fn client_ip_untrusted_peer_ignores_spoofed_xff() {
    let c = cfg(&["10.0.0.0/8"], XFF);
    let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
    assert_eq!(client_ip(ip("203.0.113.9"), &h, &c), ip("203.0.113.9"));
}

#[test]
fn client_ip_no_trusted_proxies_ignores_headers() {
    let h = headers(&[("x-forwarded-for", "1.2.3.4"), ("forwarded", "for=1.2.3.4")]);
    assert_eq!(
        client_ip(ip("127.0.0.1"), &h, &TrustedProxies::default()),
        ip("127.0.0.1")
    );
    assert_eq!(
        client_ip(ip("10.0.0.2"), &h, &TrustedProxies::default()),
        ip("10.0.0.2")
    );
}

#[test]
fn client_ip_dev_loopback_is_trusted() {
    let h = headers(&[("x-forwarded-for", "198.51.100.7")]);
    let lo = TrustedProxies::loopback();
    assert_eq!(client_ip(ip("127.0.0.1"), &h, &lo), ip("198.51.100.7"));
    assert_eq!(client_ip(ip("::1"), &h, &lo), ip("198.51.100.7"));
}

#[test]
fn client_ip_walks_right_to_left_never_leftmost() {
    let c = cfg(&["10.0.0.0/8"], XFF);
    let h = headers(&[("x-forwarded-for", "6.6.6.6, 198.51.100.7, 10.0.0.5")]);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("198.51.100.7"));
}

#[test]
fn client_ip_joins_multiple_header_lines_in_order() {
    let c = cfg(&["10.0.0.0/8"], XFF);
    let h = headers(&[
        ("x-forwarded-for", "6.6.6.6, 198.51.100.7"),
        ("x-forwarded-for", "10.0.0.7, 10.0.0.5"),
    ]);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("198.51.100.7"));

    let all_trusted = headers(&[
        ("x-forwarded-for", "10.1.1.1, 10.2.2.2"),
        ("x-forwarded-for", "10.3.3.3"),
    ]);
    assert_eq!(client_ip(ip("10.0.0.2"), &all_trusted, &c), ip("10.1.1.1"));
}

#[test]
fn client_ip_forwarded_header_parses_quoted_ipv6_and_ipv4() {
    let c = cfg(&["10.0.0.0/8"], FWD);
    let h = headers(&[(
        "forwarded",
        r#"for="[2001:db8::1]:4711";proto=https, For=198.51.100.7"#,
    )]);
    // 198.51.100.7 is the first untrusted hop from the right.
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("198.51.100.7"));

    let c = cfg(&["10.0.0.0/8", "198.51.100.0/24"], FWD);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("2001:db8::1"));

    let h = headers(&[("forwarded", r#"Proto=https;FOR="[2001:db8::2]""#)]);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("2001:db8::2"));
}

#[test]
fn client_ip_unparsable_entry_stops_the_walk() {
    let c = cfg(&["10.0.0.0/8"], XFF);
    for bad in ["unknown", "_obf", "garbage", "evil.test", ""] {
        let h = headers(&[("x-forwarded-for", &format!("198.51.100.7, {bad}, 10.0.0.5"))]);
        assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("10.0.0.5"), "{bad:?}");
    }
    let c = cfg(&["10.0.0.0/8"], FWD);
    for bad in ["for=unknown", "for=_hidden", "proto=https", "for=\"[::1\""] {
        let h = headers(&[("forwarded", &format!("for=198.51.100.7, {bad}"))]);
        assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("10.0.0.2"), "{bad:?}");
    }
}

#[test]
fn client_ip_ipv4_mapped_ipv6_is_normalised() {
    let c = cfg(&["10.0.0.0/8"], XFF);
    let h = headers(&[("x-forwarded-for", "::ffff:198.51.100.7")]);
    assert_eq!(client_ip(ip("::ffff:10.0.0.2"), &h, &c), ip("198.51.100.7"));
    // An untrusted mapped peer comes back as IPv4.
    assert_eq!(
        client_ip(ip("::ffff:203.0.113.9"), &HeaderMap::new(), &c),
        ip("203.0.113.9")
    );
    // A mapped hop inside the trusted range is skipped.
    let h = headers(&[("x-forwarded-for", "198.51.100.7, ::ffff:10.0.0.9")]);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &c), ip("198.51.100.7"));
}

#[test]
fn client_ip_header_modes_do_not_mix() {
    let h = headers(&[
        ("x-forwarded-for", "198.51.100.7"),
        ("forwarded", "for=192.0.2.44"),
    ]);
    let x = cfg(&["10.0.0.0/8"], XFF);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &x), ip("198.51.100.7"));
    let f = cfg(&["10.0.0.0/8"], FWD);
    assert_eq!(client_ip(ip("10.0.0.2"), &h, &f), ip("192.0.2.44"));

    // Only the other header present: nothing to walk, the trusted peer is the answer.
    let only_fwd = headers(&[("forwarded", "for=192.0.2.44")]);
    assert_eq!(client_ip(ip("10.0.0.2"), &only_fwd, &x), ip("10.0.0.2"));
    let only_xff = headers(&[("x-forwarded-for", "198.51.100.7")]);
    assert_eq!(client_ip(ip("10.0.0.2"), &only_xff, &f), ip("10.0.0.2"));
}

/// Proxy headers must not change the issuer, cookie attributes or HSTS: they derive from the
/// configured public URL only.
#[tokio::test]
async fn client_ip_forwarded_proto_and_host_do_not_change_issuer_or_cookies() {
    let app = TestApp::with(|c| {
        c.trusted_proxies = TrustedProxies {
            cidrs: vec![
                "0.0.0.0/0".parse().expect("cidr"),
                "::/0".parse().expect("cidr"),
            ],
            header: XFF,
        };
    })
    .await;
    let spoof = |path: &str| {
        Request::get(path)
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-host", "evil.test")
            .header("forwarded", "proto=http;host=evil.test")
            .body(Body::empty())
            .expect("request")
    };

    let disc = app.send(spoof("/.well-known/openid-configuration")).await;
    assert_eq!(disc.status, 200, "{}", disc.text());
    let doc = json(&disc);
    assert_eq!(doc["issuer"], app.issuer(None));
    assert!(!disc.text().contains("evil.test"));
    assert!(
        disc.header("strict-transport-security").is_some(),
        "HSTS stays on for an https public URL"
    );

    let login = app.send(spoof("/ui/login")).await;
    assert_eq!(login.status, 200, "{}", login.text());
    let flow_cookie = login
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.contains("anvil_flow_"))
        .expect("flow cookie")
        .to_owned();
    assert!(flow_cookie.starts_with("__Host-"), "{flow_cookie}");
    assert!(
        flow_cookie.to_ascii_lowercase().contains("; secure"),
        "{flow_cookie}"
    );
    assert!(!login.html().contains("evil.test"));
}

fn honest_ip() -> impl Strategy<Value = IpAddr> {
    // Client addresses outside the trusted 10.0.0.0/8 range.
    (11u8..=223, any::<u8>(), any::<u8>(), 1u8..=254)
        .prop_map(|(a, b, c, d)| IpAddr::from([a, b, c, d]))
}

fn trusted_hop() -> impl Strategy<Value = IpAddr> {
    (any::<u8>(), any::<u8>(), 1u8..=254).prop_map(|(b, c, d)| IpAddr::from([10, b, c, d]))
}

fn spoofed_entry() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| IpAddr::from(o).to_string()),
        any::<[u16; 8]>().prop_map(|s| IpAddr::from(s).to_string()),
        "[a-z_]{1,10}",
        Just("unknown".to_owned()),
    ]
}

proptest! {
    /// An attacker controls everything left of the honest client entry the first trusted proxy
    /// appended. Whatever they send, the result is the honest client.
    #[test]
    fn client_ip_never_comes_from_spoofed_prefix(
        spoofed in prop::collection::vec(spoofed_entry(), 0..6),
        client in honest_ip(),
        hops in prop::collection::vec(trusted_hop(), 0..5),
        peer in trusted_hop(),
    ) {
        let c = cfg(&["10.0.0.0/8"], XFF);
        let mut chain = spoofed.clone();
        chain.push(client.to_string());
        chain.extend(hops.iter().map(ToString::to_string));
        let h = headers(&[("x-forwarded-for", &chain.join(", "))]);
        prop_assert_eq!(client_ip(peer, &h, &c), client);
    }

    /// The same for `Forwarded`, split across header lines.
    #[test]
    fn client_ip_never_comes_from_spoofed_forwarded_prefix(
        spoofed in prop::collection::vec(spoofed_entry(), 0..6),
        client in honest_ip(),
        hops in prop::collection::vec(trusted_hop(), 0..5),
        peer in trusted_hop(),
    ) {
        let c = cfg(&["10.0.0.0/8"], FWD);
        let attacker = spoofed
            .iter()
            .map(|s| format!("for=\"{s}\""))
            .collect::<Vec<_>>();
        let mut honest = vec![format!("for={client}")];
        honest.extend(hops.iter().map(|h| format!("for={h}")));
        let mut h = HeaderMap::new();
        if !attacker.is_empty() {
            h.append("forwarded", HeaderValue::from_str(&attacker.join(", ")).expect("hv"));
        }
        h.append("forwarded", HeaderValue::from_str(&honest.join(", ")).expect("hv"));
        prop_assert_eq!(client_ip(peer, &h, &c), client);
    }
}
