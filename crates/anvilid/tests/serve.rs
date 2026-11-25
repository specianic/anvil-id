//! End-to-end tests for `anvilid serve`: storage selection by URL scheme and migrations on start.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

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

fn spawn(database_url: Option<&str>, port: u16) -> Child {
    let mut cmd = Command::new(BIN);
    cmd.arg("serve")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--issuer")
        .arg(format!("http://127.0.0.1:{port}"))
        .env_remove("ANVILID_DATABASE_URL")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
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

/// Starts the server and waits until /healthz answers 200; panics (with stderr) if it exits.
fn start(database_url: &str) -> Server {
    let port = free_port();
    let mut server = Server {
        child: spawn(Some(database_url), port),
        port,
    };
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            let mut err = String::new();
            if let Some(mut stderr) = server.child.stderr.take() {
                let _ = stderr.read_to_string(&mut err);
            }
            panic!("anvilid exited early with {status}: {err}");
        }
        if let Ok((status, _)) = http_get(port, "/healthz")
            && status.contains(" 200 ")
        {
            return server;
        }
        assert!(Instant::now() < deadline, "anvilid did not become healthy");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs the binary expecting it to fail fast; returns stderr.
fn expect_failure(database_url: Option<&str>) -> String {
    let mut server = Server {
        child: spawn(database_url, free_port()),
        port: 0,
    };
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let status = loop {
        if let Some(status) = server.child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "anvilid kept running for {database_url:?}; expected it to exit with an error"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !status.success(),
        "anvilid unexpectedly succeeded for {database_url:?}"
    );
    let mut err = String::new();
    if let Some(mut stderr) = server.child.stderr.take() {
        stderr.read_to_string(&mut err).expect("read stderr");
    }
    err
}

fn assert_discovery(port: u16) {
    let (status, body) = http_get(port, "/.well-known/openid-configuration").expect("discovery");
    assert!(status.contains(" 200 "), "discovery status: {status}");
    assert!(
        body.contains(&format!("\"issuer\":\"http://127.0.0.1:{port}\"")),
        "discovery body: {body}"
    );
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[test]
fn sqlite_file_is_created_migrated_and_restart_is_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("anvil.db");
    let url = format!("sqlite://{}?mode=rwc", db.display());

    let first = start(&url);
    assert_discovery(first.port);
    assert!(db.exists(), "database file was not created");
    assert!(file_len(&db) > 0, "database file is empty (no migrations?)");
    drop(first);

    // Same file again: migrations already applied must not break startup.
    let second = start(&url);
    assert_discovery(second.port);
}

#[test]
fn sqlite_memory_serves_discovery() {
    let server = start("sqlite::memory:");
    assert_discovery(server.port);
}

#[test]
fn rejects_unsupported_scheme() {
    let stderr = expect_failure(Some("mysql://user@localhost/anvil"));
    assert!(
        stderr.contains("unsupported database URL scheme"),
        "stderr: {stderr}"
    );
}

#[test]
fn requires_database_url() {
    let stderr = expect_failure(None);
    assert!(stderr.contains("--database-url"), "stderr: {stderr}");
}
