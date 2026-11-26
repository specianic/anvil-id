//! `anvilid healthcheck`: a readiness probe for images without a shell or curl (distroless).
//!
//! Sends `GET /health/ready` over plain HTTP/1.1 to a loopback address and exits 0 when the answer
//! is `200`, 1 when the server is not ready or unreachable, and 2 on a usage error. Targets other
//! than `127.0.0.1`, `::1` and `localhost` are refused before any connection is made, so the
//! command cannot be turned into a network probe. Operator infrastructure: it does not go through
//! the outbound HTTP client (05-CONTEXT Q5).

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::config::CliOverrides;

/// Connect, write and read timeout of the probe.
pub const TIMEOUT: Duration = Duration::from_secs(2);

/// The default probe path.
pub const READY_PATH: &str = "/health/ready";

/// Exit codes.
pub const EXIT_READY: i32 = 0;
pub const EXIT_NOT_READY: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

/// Most response bytes read (only the status line matters).
const MAX_RESPONSE: u64 = 8 * 1024;

/// `healthcheck` arguments.
#[derive(Debug, clap::Args)]
pub struct HealthcheckArgs {
    /// URL to probe; loopback only (127.0.0.1, ::1, localhost), plain http
    /// [default: http://127.0.0.1:{port of `listen`}/health/ready].
    #[arg(long, value_name = "URL")]
    pub url: Option<String>,

    #[command(flatten)]
    pub config: CliOverrides,
}

/// A validated probe target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    /// `Host` header value.
    pub host: String,
    pub path: String,
}

/// Parses and validates `--url`.
pub fn target_from_url(raw: &str) -> Result<Target, String> {
    let url = url::Url::parse(raw).map_err(|_| "--url is not a valid URL".to_owned())?;
    if url.scheme() != "http" {
        return Err("--url must use plain http (the probe speaks HTTP/1.1 without TLS)".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("--url must not contain credentials".into());
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) if ip == Ipv4Addr::LOCALHOST => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) if ip == Ipv6Addr::LOCALHOST => IpAddr::V6(ip),
        // Never resolved: localhost always means the IPv4 loopback address here.
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        _ => {
            return Err(
                "--url must point to this host (127.0.0.1, [::1] or localhost); the healthcheck \
                 never probes other hosts"
                    .into(),
            );
        }
    };
    let port = url.port().unwrap_or(80);
    let path = match url.path() {
        "" | "/" => READY_PATH.to_owned(),
        p => p.to_owned(),
    };
    let host = match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().unwrap_or("127.0.0.1")),
        None => url.host_str().unwrap_or("127.0.0.1").to_owned(),
    };
    Ok(Target {
        addr: SocketAddr::new(ip, port),
        host,
        path,
    })
}

/// The default target for the server's `listen` address: a wildcard address is probed on the
/// loopback address of its family; a specific address must be the loopback address itself.
pub fn target_from_listen(listen: SocketAddr) -> Result<Target, String> {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() || ip == Ipv4Addr::LOCALHOST => {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        IpAddr::V6(ip) if ip.is_unspecified() || ip == Ipv6Addr::LOCALHOST => {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        }
        other => {
            return Err(format!(
                "listen address {other} is not reachable on loopback; pass --url"
            ));
        }
    };
    let addr = SocketAddr::new(ip, listen.port());
    Ok(Target {
        addr,
        host: addr.to_string(),
        path: READY_PATH.to_owned(),
    })
}

/// Probes `target`: `Ok(())` iff the status line is `200`.
pub fn probe(target: &Target) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&target.addr, TIMEOUT)
        .map_err(|e| format!("cannot connect to {}: {e}", target.addr))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| format!("socket error: {e}"))?;
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: anvilid-healthcheck\r\nConnection: close\r\n\r\n",
        target.path, target.host
    )
    .map_err(|e| format!("request failed: {e}"))?;
    let mut raw = Vec::new();
    // A timeout or reset after the status line still leaves a usable answer.
    let read = stream.take(MAX_RESPONSE).read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.split(' ');
    match (parts.next(), parts.next()) {
        (Some(v), Some("200")) if v.starts_with("HTTP/1.") => Ok(()),
        (Some(v), Some(code)) if v.starts_with("HTTP/1.") => Err(format!("status {code}")),
        _ => Err(match read {
            Err(e) => format!("no response: {e}"),
            Ok(_) => "no HTTP response".to_owned(),
        }),
    }
}

/// Runs the probe against `target` and returns the exit code.
pub fn run(target: Result<Target, String>) -> i32 {
    let target = match target {
        Ok(t) => t,
        Err(e) => {
            eprintln!("healthcheck: {e}");
            return EXIT_USAGE;
        }
    };
    match probe(&target) {
        Ok(()) => {
            println!("ready");
            EXIT_READY
        }
        Err(e) => {
            eprintln!("not ready: {e}");
            EXIT_NOT_READY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_urls_are_accepted() {
        let t = target_from_url("http://127.0.0.1:8080/health/ready").expect("v4");
        assert_eq!(t.addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(t.path, "/health/ready");
        assert_eq!(t.host, "127.0.0.1:8080");
        let t = target_from_url("http://[::1]:9000").expect("v6");
        assert_eq!(t.addr, "[::1]:9000".parse().unwrap());
        assert_eq!(t.path, READY_PATH);
        let t = target_from_url("http://localhost:8080/readyz").expect("localhost");
        assert_eq!(t.addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(t.path, "/readyz");
        assert_eq!(t.host, "localhost:8080");
        assert_eq!(
            target_from_url("http://LOCALHOST")
                .expect("default port")
                .addr,
            "127.0.0.1:80".parse().unwrap()
        );
    }

    #[test]
    fn other_hosts_schemes_and_credentials_are_refused() {
        for bad in [
            "http://example.com/",
            "http://192.0.2.1:8080/health/ready",
            "http://10.0.0.1/",
            "http://127.0.0.2/",
            "http://0.0.0.0:8080/",
            "http://[::]:8080/",
            "http://localhost.example.com/",
            "http://127.0.0.1.nip.io/",
            "https://127.0.0.1:8443/",
            "ftp://127.0.0.1/",
            "http://user:pw@127.0.0.1:8080/",
            "not a url",
        ] {
            assert!(target_from_url(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn listen_addresses_map_to_loopback() {
        assert_eq!(
            target_from_listen("0.0.0.0:8080".parse().unwrap())
                .expect("v4 any")
                .addr,
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            target_from_listen("[::]:8080".parse().unwrap())
                .expect("v6 any")
                .addr,
            "[::1]:8080".parse().unwrap()
        );
        assert_eq!(
            target_from_listen("127.0.0.1:9".parse().unwrap())
                .expect("loopback")
                .path,
            READY_PATH
        );
        assert!(target_from_listen("10.1.2.3:8080".parse().unwrap()).is_err());
    }
}
