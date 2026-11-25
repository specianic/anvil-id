//! `anvilid keys rotate` on a SQLite data directory: prepublish (the next key is served in the
//! JWKS afterwards), `--immediate` (active kid changes, the old key expires now), unknown tenant
//! and the `key_rotation_requested` audit row.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anvil_core::model::{AuditAction, AuditQuery, DEFAULT_TENANT_SLUG, KeyState, SigningKey};
use anvil_core::ports::Storage as _;
use anvil_storage_sqlite::SqliteStorage;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn command(cwd: &Path, args: &[&str], port: u16) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("ANVILID_LISTEN", format!("127.0.0.1:{port}"))
        .env("ANVILID_PUBLIC_URL", format!("http://127.0.0.1:{port}"))
        .env("ANVILID_BREACH_CHECK", "off")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

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

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve(cwd: &Path, port: u16) -> Server {
    let child = command(cwd, &["serve"], port)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn anvilid");
    let mut server = Server(child);
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            panic!("anvilid exited early with {status}");
        }
        if http_get(port, "/healthz").is_ok_and(|(s, _)| s.contains(" 200 ")) {
            return server;
        }
        assert!(Instant::now() < deadline, "anvilid did not become healthy");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The kids in the default tenant's JWKS (path taken from the discovery document).
fn jwks_kids(port: u16) -> Vec<String> {
    let (status, body) = http_get(port, "/.well-known/openid-configuration").expect("discovery");
    assert!(status.contains(" 200 "), "discovery: {status}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("discovery JSON");
    let uri = doc["jwks_uri"].as_str().expect("jwks_uri").to_owned();
    let path = uri
        .strip_prefix(&format!("http://127.0.0.1:{port}"))
        .expect("jwks_uri on the public URL");
    let (status, body) = http_get(port, path).expect("jwks");
    assert!(status.contains(" 200 "), "jwks: {status}");
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("jwks JSON");
    jwks["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| k["kid"].as_str().expect("kid").to_owned())
        .collect()
}

async fn open(cwd: &Path) -> SqliteStorage {
    let db = cwd.join("anvilid-data").join("anvilid.db");
    SqliteStorage::connect(&format!("sqlite://{}", db.display()))
        .await
        .expect("open db")
}

async fn rs256_keys(cwd: &Path) -> (anvil_core::model::TenantId, Vec<SigningKey>) {
    let storage = open(cwd).await;
    let tenant = storage
        .tenants()
        .get_by_slug(DEFAULT_TENANT_SLUG)
        .await
        .expect("tenant")
        .expect("default tenant");
    let keys = storage
        .keys()
        .list(tenant.id)
        .await
        .expect("keys")
        .into_iter()
        .filter(|k| k.alg == "RS256")
        .collect();
    (tenant.id, keys)
}

fn of_state(keys: &[SigningKey], state: KeyState) -> Vec<&SigningKey> {
    keys.iter().filter(|k| k.state == state).collect()
}

#[test]
fn keys_rotate_prepublishes_and_rotates_immediately() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // Before installation there is nothing to rotate.
    let out = command(cwd.path(), &["keys", "rotate"], free_port())
        .output()
        .expect("run");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("does not exist"), "{}", text(&out));

    // Install (first start), then stop.
    drop(serve(cwd.path(), free_port()));
    let (_, keys) = rt.block_on(rs256_keys(cwd.path()));
    let active = of_state(&keys, KeyState::Active);
    assert_eq!(active.len(), 1, "{keys:?}");
    let original_kid = active[0].kid.clone();

    // Prepublish.
    let out = command(
        cwd.path(),
        &["keys", "rotate", "--tenant", "default"],
        free_port(),
    )
    .output()
    .expect("run");
    assert!(out.status.success(), "{}", text(&out));
    let (tenant, keys) = rt.block_on(rs256_keys(cwd.path()));
    let next = of_state(&keys, KeyState::Next);
    assert_eq!(next.len(), 1, "{keys:?}");
    let next_kid = next[0].kid.clone();
    assert!(String::from_utf8_lossy(&out.stdout).contains(&next_kid));
    assert_eq!(of_state(&keys, KeyState::Active)[0].kid, original_kid);

    // The audit row exists (and was mirrored to stdout as JSON).
    let requested = rt.block_on(async {
        open(cwd.path())
            .await
            .audit()
            .query(
                tenant,
                &AuditQuery {
                    action: Some(AuditAction::KeyRotationRequested),
                    limit: 50,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit")
            .items
    });
    assert_eq!(requested.len(), 1, "{requested:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("\"action\":\"key_rotation_requested\""),
        "{}",
        text(&out)
    );

    // The next key is published in the JWKS of a server started afterwards.
    let port = free_port();
    let server = serve(cwd.path(), port);
    let kids = jwks_kids(port);
    assert!(kids.contains(&next_kid), "{kids:?}");
    assert!(kids.contains(&original_kid), "{kids:?}");
    drop(server);

    // Immediate rotation: the active kid changes and the old key expires now.
    let before = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let out = command(
        cwd.path(),
        &["keys", "rotate", "--alg", "RS256", "--immediate"],
        free_port(),
    )
    .output()
    .expect("run");
    assert!(out.status.success(), "{}", text(&out));
    let after = time::OffsetDateTime::now_utc() + time::Duration::seconds(1);
    let (_, keys) = rt.block_on(rs256_keys(cwd.path()));
    let active = of_state(&keys, KeyState::Active);
    assert_eq!(active.len(), 1, "{keys:?}");
    assert_ne!(active[0].kid, original_kid);
    let old = keys
        .iter()
        .find(|k| k.kid == original_kid)
        .expect("old key kept until purged");
    assert_eq!(old.state, KeyState::Retired);
    let expires = old.expires_at.expect("expires_at");
    assert!(
        before <= expires && expires <= after,
        "expires_at {expires}"
    );
}

#[test]
fn keys_rotate_rejects_unknown_tenant_and_alg() {
    let cwd = tempfile::tempdir().expect("tempdir");
    drop(serve(cwd.path(), free_port()));

    let out = command(
        cwd.path(),
        &["keys", "rotate", "--tenant", "nope"],
        free_port(),
    )
    .output()
    .expect("run");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("tenant `nope` does not exist"),
        "{}",
        text(&out)
    );

    let out = command(
        cwd.path(),
        &["keys", "rotate", "--alg", "HS256"],
        free_port(),
    )
    .output()
    .expect("run");
    assert!(!out.status.success(), "{}", text(&out));

    // ES256 is not enabled for the default tenant.
    let out = command(
        cwd.path(),
        &["keys", "rotate", "--alg", "ES256"],
        free_port(),
    )
    .output()
    .expect("run");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("not enabled"), "{}", text(&out));
}
