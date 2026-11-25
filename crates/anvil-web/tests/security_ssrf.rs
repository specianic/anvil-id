//! SSRF guard of the single outbound HTTP client (ARCHITECTURE §11): every bypass class is
//! refused. The clients are production [`OutboundClient`]s built from a policy; destinations are
//! local listeners and IP literals only (no external network access).

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anvil_web::adapters::outbound::{
    LIMIT_TOKEN, OutboundClient, OutboundError, OutboundPolicy, read_capped,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(policy: OutboundPolicy) -> OutboundClient {
    OutboundClient::new(&policy).expect("client")
}

fn allow(cidrs: &[&str], allow_http: bool) -> OutboundPolicy {
    OutboundPolicy {
        allow_cidrs: cidrs.iter().map(|c| c.parse().expect("cidr")).collect(),
        extra_ca_pem: None,
        allow_http,
    }
}

/// A TCP listener that records whether anything connected.
struct Witness {
    listener: TcpListener,
}

impl Witness {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        Self { listener }
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().expect("addr").port()
    }

    fn connected(&self) -> bool {
        self.listener.accept().is_ok()
    }
}

#[tokio::test]
async fn blocked_ip_literals_are_refused_without_connecting() {
    let witness = Witness::new();
    let port = witness.port();
    let prod = client(OutboundPolicy::default());
    for url in [
        format!("https://127.0.0.1:{port}/"),
        format!("https://[::1]:{port}/"),
        format!("https://[::ffff:127.0.0.1]:{port}/"),
        format!("https://[64:ff9b::7f00:1]:{port}/"),
        format!("https://[2002:7f00:1::1]:{port}/"),
        "https://169.254.169.254/latest/meta-data/".to_owned(),
        "https://10.0.0.1/".to_owned(),
        "https://192.168.0.1/".to_owned(),
        "https://100.64.0.1/".to_owned(),
        "https://[fd00::1]/".to_owned(),
        "https://[fe80::1]/".to_owned(),
        format!("https://2130706433:{port}/"),
        format!("https://0x7f.1:{port}/"),
    ] {
        let err = prod
            .get(&url)
            .expect_err("blocked before a request is built");
        assert_eq!(err, OutboundError::Blocked, "{url}");
    }
    // Plain http to loopback is refused too (http is off in production).
    let err = prod
        .get(&format!("http://127.0.0.1:{port}/"))
        .expect_err("http refused");
    assert_eq!(err, OutboundError::InvalidUrl);
    assert!(!witness.connected(), "no connection may be attempted");
}

#[tokio::test]
async fn host_name_resolving_to_loopback_is_blocked_unless_allow_listed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/doc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let port = server.address().port();
    let url = format!("http://localhost:{port}/doc");

    // https towards a name that resolves only to loopback: the resolver drops every answer.
    let prod = client(OutboundPolicy::default());
    let err = prod
        .get(&format!("https://localhost:{port}/doc"))
        .expect("name passes the pre-check")
        .send()
        .await
        .expect_err("resolver blocks loopback");
    assert_eq!(err, OutboundError::Blocked);

    // http allowed by the policy, but loopback is not allow-listed.
    let http_no_list = client(allow(&[], true));
    let err = http_no_list
        .get(&url)
        .expect("name passes the pre-check")
        .send()
        .await
        .expect_err("not allow-listed");
    assert_eq!(err, OutboundError::Blocked);

    // A public-looking allow-list entry does not open loopback either.
    let other_list = client(allow(&["10.0.0.0/8"], true));
    let err = other_list
        .get(&url)
        .expect("pre-check")
        .send()
        .await
        .expect_err("still blocked");
    assert_eq!(err, OutboundError::Blocked);

    // Explicitly allow-listed (127.0.0.1/32 and ::1, whichever `localhost` resolves to first).
    let listed = client(allow(&["127.0.0.1/32", "::1/128"], true));
    let body = listed
        .get(&url)
        .expect("pre-check")
        .fetch(1024)
        .await
        .expect("allowed");
    assert_eq!(body, b"ok");
    assert!(
        !server
            .received_requests()
            .await
            .expect("recorded")
            .is_empty()
    );
}

#[tokio::test]
async fn redirects_are_never_followed() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("followed"))
        .expect(0)
        .mount(&target)
        .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/x", target.uri())),
        )
        .mount(&server)
        .await;
    let c = client(allow(&["127.0.0.1/32"], true));
    let err = c
        .get(&format!("{}/start", server.uri()))
        .expect("pre-check")
        .send()
        .await
        .expect_err("302 is not success");
    assert_eq!(err, OutboundError::Status(302));
    let resp = c
        .get(&format!("{}/start", server.uri()))
        .expect("pre-check")
        .send_any_status()
        .await
        .expect("response");
    assert_eq!(resp.status().as_u16(), 302, "returned, not followed");
    // `expect(0)` on the target is verified on drop.
}

#[tokio::test]
async fn userinfo_and_non_https_schemes_are_rejected() {
    let prod = client(OutboundPolicy::default());
    for url in [
        "https://user:pass@idp.example.com/",
        "https://user@idp.example.com/",
        "http://idp.example.com/",
        "ftp://idp.example.com/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "not a url",
    ] {
        assert_eq!(
            prod.get(url).expect_err(url),
            OutboundError::InvalidUrl,
            "{url}"
        );
    }
    // Dev policy: http only to an allow-listed destination.
    let dev = client(OutboundPolicy::loopback_dev());
    assert!(dev.get("http://127.0.0.1:9/").is_ok());
    assert_eq!(
        dev.get("http://8.8.8.8/").expect_err("not listed"),
        OutboundError::Blocked
    );
    assert_eq!(
        dev.get("http://user:pw@127.0.0.1:9/")
            .expect_err("userinfo"),
        OutboundError::InvalidUrl
    );
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; LIMIT_TOKEN + 1]))
        .mount(&server)
        .await;
    let c = client(allow(&["127.0.0.1/32"], true));
    let err = c
        .get(&server.uri())
        .expect("pre-check")
        .fetch(LIMIT_TOKEN)
        .await
        .expect_err("cap");
    assert_eq!(err, OutboundError::TooLarge);
    let resp = c
        .get(&server.uri())
        .expect("pre-check")
        .send()
        .await
        .expect("send");
    assert_eq!(read_capped(resp, 1000).await, Err(OutboundError::TooLarge));
    let ok = c
        .get(&server.uri())
        .expect("pre-check")
        .fetch(LIMIT_TOKEN + 1)
        .await
        .expect("within the cap");
    assert_eq!(ok.len(), LIMIT_TOKEN + 1);
}

#[tokio::test]
async fn slow_server_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("late")
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let c = client(allow(&["127.0.0.1/32"], true));
    let started = Instant::now();
    let err = c
        .get(&server.uri())
        .expect("pre-check")
        .timeout(Duration::from_millis(200))
        .send()
        .await
        .expect_err("timeout");
    assert_eq!(err, OutboundError::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn errors_do_not_echo_the_destination() {
    let prod = client(OutboundPolicy::default());
    let err = prod
        .get("https://169.254.169.254/latest/meta-data/")
        .expect_err("blocked");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("169.254"), "{text}");
    let witness = Witness::new();
    let err = client(OutboundPolicy::default())
        .get(&format!("https://localhost:{}/secret-path", witness.port()))
        .expect("pre-check")
        .send()
        .await
        .expect_err("blocked by the resolver");
    let text = format!("{err} {err:?}");
    assert!(
        !text.contains("127.0.0.1") && !text.contains("localhost") && !text.contains("secret"),
        "{text}"
    );
    assert!(!witness.connected());
}

// --- proxies -----------------------------------------------------------------------------------

const CHILD_TARGET: &str = "ANVIL_SSRF_TEST_TARGET";

/// Runs only as the child process of [`proxy_environment_is_ignored`], which sets the proxy
/// environment for the whole process (setting it in this process would race other tests).
#[tokio::test]
#[ignore = "child process of proxy_environment_is_ignored"]
async fn proxy_child() {
    let Ok(target) = std::env::var(CHILD_TARGET) else {
        return;
    };
    let url = format!("{target}/where");
    // Control: a default reqwest client (test code) honours the proxy environment.
    let control = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("control client");
    let via = control
        .get(&url)
        .send()
        .await
        .expect("control")
        .text()
        .await
        .expect("body");
    assert_eq!(via, "proxy", "control client must go through the proxy");
    // The guarded client ignores it and connects directly.
    let guarded = client(allow(&["127.0.0.1/32"], true));
    let body = guarded
        .get(&url)
        .expect("pre-check")
        .fetch(1024)
        .await
        .expect("direct");
    assert_eq!(body, b"direct");
}

#[tokio::test]
async fn proxy_environment_is_ignored() {
    let direct = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/where"))
        .respond_with(ResponseTemplate::new(200).set_body_string("direct"))
        .mount(&direct)
        .await;
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("proxy"))
        .mount(&proxy)
        .await;
    let exe = std::env::current_exe().expect("test binary");
    let out = tokio::process::Command::new(exe)
        .args(["--exact", "proxy_child", "--ignored", "--nocapture"])
        .env(CHILD_TARGET, direct.uri())
        .env("HTTP_PROXY", proxy.uri())
        .env("http_proxy", proxy.uri())
        .env("HTTPS_PROXY", proxy.uri())
        .env("https_proxy", proxy.uri())
        .env("ALL_PROXY", proxy.uri())
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .await
        .expect("run child");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "child test must run: {text}");
    assert_eq!(direct.received_requests().await.expect("recorded").len(), 1);
}

// --- extra CA ----------------------------------------------------------------------------------

fn openssl(args: &[&str], dir: &Path) -> bool {
    match Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => true,
        Ok(s) => panic!("openssl {args:?} failed: {s}"),
        Err(e) => {
            eprintln!("SKIPPED: openssl is not on PATH ({e}); extra-CA test not run");
            false
        }
    }
}

/// A throwaway test CA and a leaf certificate for 127.0.0.1 signed by it, generated per run
/// (no key material is committed). `None` when openssl is unavailable.
fn test_pki(dir: &Path) -> Option<()> {
    let ec = [
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
    ];
    let mut ca = vec!["req", "-x509"];
    ca.extend(ec);
    ca.extend([
        "-days",
        "1",
        "-subj",
        "/CN=anvilid-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
    ]);
    if !openssl(&ca, dir) {
        return None;
    }
    let mut csr = vec!["req"];
    csr.extend(ec);
    csr.extend([
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        "leaf.key",
        "-out",
        "leaf.csr",
    ]);
    openssl(&csr, dir);
    std::fs::write(
        dir.join("leaf.ext"),
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n",
    )
    .expect("ext file");
    openssl(
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            "leaf.ext",
            "-out",
            "leaf.pem",
        ],
        dir,
    );
    Some(())
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

#[tokio::test]
async fn extra_ca_is_trusted_only_when_configured() {
    let dir = tempfile::tempdir().expect("tempdir");
    if test_pki(dir.path()).is_none() {
        return;
    }
    let port = free_port();
    let server = Command::new("openssl")
        .args(["s_server", "-quiet", "-www", "-accept"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["-cert", "leaf.pem", "-key", "leaf.key"])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("openssl s_server");
    let _server = KillOnDrop(server);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "TLS test server did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let url = format!("https://127.0.0.1:{port}/");
    let ca = std::fs::read(dir.path().join("ca.pem")).expect("ca");

    let without = client(allow(&["127.0.0.1/32"], false));
    let err = without
        .get(&url)
        .expect("pre-check")
        .send()
        .await
        .expect_err("unknown issuer");
    assert_eq!(err, OutboundError::Network);

    let with = client(OutboundPolicy {
        extra_ca_pem: Some(ca),
        ..allow(&["127.0.0.1/32"], false)
    });
    let body = with
        .get(&url)
        .expect("pre-check")
        .fetch(64 * 1024)
        .await
        .expect("trusted through the extra CA");
    assert!(!body.is_empty());
}
