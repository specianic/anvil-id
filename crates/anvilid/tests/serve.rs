//! End-to-end tests for `anvilid serve`: storage selection, migrations on start, the discovery
//! document of the full router, the TLS listener and graceful shutdown.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Picks a free local port (bind to :0, read it, release it).
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Kills the child on drop so a failing assertion never leaks a server process.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Sends SIGTERM without waiting.
    fn send_term(&self) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
    }

    /// Sends SIGTERM and waits for the exit status.
    fn terminate(&mut self) -> ExitStatus {
        self.send_term();
        self.wait_exit()
    }

    /// Waits (at most 20 s) for the process to exit.
    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            assert!(Instant::now() < deadline, "anvilid did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stderr(&mut self) -> String {
        let mut err = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            let _ = stderr.read_to_string(&mut err);
        }
        err
    }
}

/// `anvilid serve` on `port` with a loopback public URL, the data dir `data_dir`, an optional
/// database URL and extra arguments. Only PATH is inherited from the environment.
fn spawn(data_dir: &Path, database_url: Option<&str>, port: u16, extra: &[&str]) -> Child {
    let mut cmd = Command::new(BIN);
    cmd.arg("serve")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--public-url")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--breach-check")
        .arg("off")
        .args(extra)
        .current_dir(data_dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    if let Some(url) = database_url {
        cmd.arg("--database-url").arg(url);
    }
    cmd.spawn().expect("spawn anvilid")
}

/// Minimal HTTP/1.1 GET returning (status line, body).
fn http_get(port: u16, path: &str) -> std::io::Result<(String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let status = raw.lines().next().unwrap_or_default().to_owned();
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Waits until `ready` returns true; panics (with stderr) if the server exits first.
fn wait_ready(server: &mut Server, mut ready: impl FnMut(u16) -> bool) {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            let err = server.stderr();
            panic!("anvilid exited early with {status}: {err}");
        }
        if ready(server.port) {
            return;
        }
        assert!(Instant::now() < deadline, "anvilid did not become ready");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn healthy(port: u16) -> bool {
    http_get(port, "/healthz").is_ok_and(|(status, _)| status.contains(" 200 "))
}

/// Starts the server and waits until /healthz answers 200.
fn start(data_dir: &Path, database_url: Option<&str>) -> Server {
    let port = free_port();
    let mut server = Server {
        child: spawn(data_dir, database_url, port, &[]),
        port,
    };
    wait_ready(&mut server, healthy);
    server
}

fn assert_discovery(port: u16) {
    let (status, body) = http_get(port, "/.well-known/openid-configuration").expect("discovery");
    assert!(status.contains(" 200 "), "discovery status: {status}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("discovery JSON");
    assert_eq!(doc["issuer"], format!("http://127.0.0.1:{port}"), "{body}");
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        serde_json::json!(["RS256"]),
        "{body}"
    );
    assert_eq!(
        doc["userinfo_endpoint"],
        format!("http://127.0.0.1:{port}/userinfo"),
        "{body}"
    );
    let (status, body) = http_get(port, "/jwks").expect("jwks");
    assert!(status.contains(" 200 "), "jwks status: {status}");
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("jwks JSON");
    assert!(
        jwks["keys"].as_array().is_some_and(|k| !k.is_empty()),
        "{body}"
    );
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn defaults_to_data_dir_sqlite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start(dir.path(), None);
    assert_discovery(server.port);
    let db = dir.path().join("anvilid.db");
    assert!(db.exists(), "default database file was not created");
    assert!(dir.path().join("kek").exists(), "KEK file was not created");
}

#[test]
fn sqlite_file_is_created_migrated_and_restart_is_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("anvil.db");
    let url = format!("sqlite://{}?mode=rwc", db.display());

    let first = start(dir.path(), Some(&url));
    assert_discovery(first.port);
    assert!(db.exists(), "database file was not created");
    assert!(file_len(&db) > 0, "database file is empty (no migrations?)");
    drop(first);

    // Same file again: migrations already applied must not break startup.
    let second = start(dir.path(), Some(&url));
    assert_discovery(second.port);
}

#[test]
fn sqlite_memory_serves_discovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let server = start(dir.path(), Some("sqlite::memory:"));
    assert_discovery(server.port);
}

#[test]
fn rejects_unsupported_scheme() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Command::new(BIN)
        .args([
            "serve",
            "--database-url",
            "mysql://user:pw-secret@localhost/anvil",
        ])
        .current_dir(dir.path())
        .env_clear()
        .output()
        .expect("run anvilid");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported database URL scheme"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("pw-secret"), "stderr: {stderr}");
}

#[test]
fn sigterm_shuts_down_gracefully_with_exit_code_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut server = start(dir.path(), None);
    let status = server.terminate();
    let stderr = server.stderr();
    assert!(status.success(), "exit status {status}: {stderr}");
    assert!(stderr.contains("shut down cleanly"), "{stderr}");
}

#[test]
fn sigterm_turns_readiness_503_serves_during_the_drain_then_exits_zero() {
    const DRAIN: Duration = Duration::from_secs(2);
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let mut server = Server {
        child: spawn(dir.path(), None, port, &["--shutdown-drain", "2s"]),
        port,
    };
    wait_ready(&mut server, healthy);
    for path in ["/readyz", "/health/ready"] {
        let (status, _) = http_get(port, path).expect("ready");
        assert!(status.contains(" 200 "), "{path}: {status}");
    }

    let signalled = Instant::now();
    server.send_term();
    // Readiness flips at once (well within the drain delay).
    loop {
        let (status, body) = http_get(port, "/readyz").expect("readyz during drain");
        if status.contains(" 503 ") {
            assert_eq!(body, "draining");
            break;
        }
        assert!(
            signalled.elapsed() < DRAIN / 2,
            "readiness did not turn 503 promptly: {status}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let (status, _) = http_get(port, "/health/ready").expect("health/ready during drain");
    assert!(status.contains(" 503 "), "{status}");
    // New connections are still served while draining: liveness and real endpoints.
    let (status, _) = http_get(port, "/healthz").expect("healthz during drain");
    assert!(status.contains(" 200 "), "{status}");
    assert_discovery(port);
    assert!(
        signalled.elapsed() < DRAIN,
        "the checks above ran past the drain"
    );

    let status = server.wait_exit();
    let elapsed = signalled.elapsed();
    let stderr = server.stderr();
    assert!(status.success(), "exit status {status}: {stderr}");
    assert!(
        elapsed >= DRAIN,
        "exited after {elapsed:?}, before the drain"
    );
    assert!(stderr.contains("draining before shutdown"), "{stderr}");
    assert!(stderr.contains("shut down cleanly"), "{stderr}");
}

#[test]
fn metrics_listen_serves_only_metrics_and_the_main_port_has_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let metrics_port = free_port();
    let mut server = Server {
        child: spawn(
            dir.path(),
            None,
            port,
            &["--metrics-listen", &format!("127.0.0.1:{metrics_port}")],
        ),
        port,
    };
    wait_ready(&mut server, healthy);
    assert_discovery(port);
    let (status, body) = http_get(metrics_port, "/metrics").expect("metrics");
    assert!(status.contains(" 200 "), "{status}");
    assert!(
        body.contains("anvil_http_requests_total{route_class=\"default\",status_class=\"2xx\"}"),
        "{body}"
    );
    assert!(
        body.contains("anvil_http_request_duration_seconds_bucket{route_class="),
        "{body}"
    );
    assert!(
        !body.contains("127.0.0.1"),
        "an address leaked into metrics: {body}"
    );
    let (status, _) = http_get(metrics_port, "/healthz").expect("metrics listener");
    assert!(status.contains(" 404 "), "only /metrics there: {status}");
    let (status, _) = http_get(port, "/metrics").expect("main listener");
    assert!(
        status.contains(" 404 "),
        "no /metrics on the main port: {status}"
    );
}

#[test]
fn metrics_on_main_port_serves_metrics_there() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let mut server = Server {
        child: spawn(dir.path(), None, port, &["--metrics-on-main-port"]),
        port,
    };
    wait_ready(&mut server, healthy);
    let (status, body) = http_get(port, "/metrics").expect("metrics");
    assert!(status.contains(" 200 "), "{status}");
    assert!(
        body.contains("anvil_http_requests_total{route_class=\"health\",status_class=\"2xx\"}"),
        "{body}"
    );
}

/// Generates a self-signed P-256 certificate for localhost with openssl, or returns `None` (and
/// says why) when openssl is not available.
fn self_signed_cert(dir: &Path) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
        ])
        .args(["-nodes", "-days", "1", "-subj", "/CN=localhost"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Some((cert, key)),
        Ok(s) => panic!("openssl failed to create a test certificate: {s}"),
        Err(e) => {
            eprintln!("SKIPPED: openssl is not on PATH ({e}); TLS listener test not run");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_listener_serves_discovery_over_https() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((cert, key)) = self_signed_cert(dir.path()) else {
        return;
    };
    let port = free_port();
    let child = spawn(
        dir.path(),
        None,
        port,
        &[
            "--tls-cert",
            cert.to_str().expect("utf-8 path"),
            "--tls-key",
            key.to_str().expect("utf-8 path"),
        ],
    );
    let mut server = Server { child, port };
    let client = reqwest::Client::builder()
        // The certificate is self-signed: this test proves the listener speaks TLS, not PKI.
        .tls_danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let url = format!("https://127.0.0.1:{port}/.well-known/openid-configuration");
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let body = loop {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            let err = server.stderr();
            panic!("anvilid exited early with {status}: {err}");
        }
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            break resp.text().await.expect("body");
        }
        assert!(Instant::now() < deadline, "TLS listener did not answer");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let doc: serde_json::Value = serde_json::from_str(&body).expect("discovery JSON");
    assert_eq!(doc["issuer"], format!("http://127.0.0.1:{port}"));

    // Plain http on the TLS port must not be served.
    assert!(
        http_get(port, "/healthz").map_or(true, |(status, _)| !status.contains(" 200 ")),
        "plain http answered on the TLS listener"
    );
    let status = server.terminate();
    assert!(status.success(), "exit status {status}");
}
