//! Phase 3 configuration and startup reconciliation of the spawned binary: trusted proxies, rate
//! limits, rotation and retention keys (`config show|validate`), and `serve` on a fresh data
//! directory (console client, signing keys, audit JSON on stdout with `RUST_LOG=warn`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anvil_core::model::{DEFAULT_TENANT_SLUG, PageRequest, SYSTEM_TENANT_SLUG};
use anvil_core::ports::Storage as _;
use anvil_core::service::bootstrap::CONSOLE_CLIENT_ID;
use anvil_storage_sqlite::SqliteStorage;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// A known, valid KEK (32 bytes of 0x2a) used to prove errors never print it.
const KNOWN_KEK: &str = "KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=";

fn command(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd
}

fn run(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    command(cwd, args, envs).output().expect("run anvilid")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn invalid_trusted_proxy_fails_validate_naming_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "validate"],
        &[
            ("ANVILID_KEK", KNOWN_KEK),
            ("ANVILID_TRUSTED_PROXIES", "10.0.0.0/8, 300.1.2.3/8"),
        ],
    );
    assert!(!out.status.success(), "{}", text(&out));
    let all = text(&out);
    assert!(all.contains("trusted_proxies"), "{all}");
    assert!(!all.contains(KNOWN_KEK), "KEK leaked: {all}");
}

#[test]
fn valid_phase3_keys_pass_validate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "validate", "--key-rotation-days", "30"],
        &[
            ("ANVILID_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16"),
            ("ANVILID_TRUSTED_PROXY_HEADER", "forwarded"),
            ("ANVILID_RATE_LIMIT_ENABLED", "false"),
            ("ANVILID_RATE_LIMIT_AUTH_PER_MINUTE", "20"),
            ("ANVILID_AUDIT_RETENTION_DAYS", "0"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rate_limit_enabled is false"),
        "{}",
        text(&out)
    );
}

#[test]
fn out_of_range_days_fail_validate() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (var, key) in [
        ("ANVILID_KEY_ROTATION_DAYS", "key_rotation_days"),
        (
            "ANVILID_RATE_LIMIT_TOKEN_PER_SECOND",
            "rate_limit_token_per_second",
        ),
    ] {
        let out = run(dir.path(), &["config", "validate"], &[(var, "0")]);
        assert!(!out.status.success(), "{var}: {}", text(&out));
        assert!(text(&out).contains(key), "{}", text(&out));
    }
}

#[test]
fn config_show_lists_phase3_keys_with_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        &["config", "show", "--audit-retention-days", "30"],
        &[
            ("ANVILID_PUBLIC_URL", "https://id.example.test"),
            ("ANVILID_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.0/16"),
            ("ANVILID_RATE_LIMIT_AUTH_PER_MINUTE", "20"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in [
        "trusted_proxies = 10.0.0.0/8, 192.168.0.0/16 (env ANVILID_TRUSTED_PROXIES)",
        "trusted_proxy_header = x-forwarded-for (default)",
        "rate_limit_enabled = true (default)",
        "rate_limit_auth_per_minute = 20 (env ANVILID_RATE_LIMIT_AUTH_PER_MINUTE)",
        "rate_limit_token_per_second = 50 (default)",
        "rate_limit_token_client_per_second = 100 (default)",
        "rate_limit_admin_per_second = 20 (default)",
        "rate_limit_default_per_second = 50 (default)",
        "key_rotation_days = 90 (default)",
        "audit_retention_days = 30 (cli --audit-retention-days)",
    ] {
        assert!(stdout.contains(line), "missing `{line}`:\n{stdout}");
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn collect(stream: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            let mut out = sink.lock().expect("output lock");
            out.push_str(&line);
            out.push('\n');
        }
    });
}

fn healthy(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    if write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    raw.lines().next().is_some_and(|l| l.contains(" 200 "))
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn serve_reconciles_console_client_and_keys_and_streams_audit_json() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = command(
        cwd.path(),
        &["serve", "--breach-check", "off"],
        &[("ANVILID_LISTEN", listen.as_str()), ("RUST_LOG", "warn")],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("spawn anvilid");
    let stdout = Arc::new(Mutex::new(String::new()));
    let stderr = Arc::new(Mutex::new(String::new()));
    collect(child.stdout.take().expect("stdout"), Arc::clone(&stdout));
    collect(child.stderr.take().expect("stderr"), Arc::clone(&stderr));
    let mut server = Killed(child);

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while !healthy(port) {
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            std::thread::sleep(Duration::from_millis(200));
            panic!(
                "anvilid exited early with {status}: {}",
                stderr.lock().expect("lock")
            );
        }
        assert!(Instant::now() < deadline, "anvilid did not become healthy");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    drop(server);

    // Audit JSON lines on stdout even though RUST_LOG=warn; none on stderr.
    let out = stdout.lock().expect("lock").clone();
    let events: Vec<serde_json::Value> = out
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "client_created" && e["target"] == CONSOLE_CLIENT_ID),
        "no client_created audit line on stdout: {out}"
    );
    for e in &events {
        for key in ["id", "tenant_id", "at", "actor", "action", "outcome"] {
            assert!(e.get(key).is_some(), "{key} missing in {e}");
        }
    }
    let err = stderr.lock().expect("lock").clone();
    assert!(
        !err.contains("client_created"),
        "audit leaked to stderr: {err}"
    );
    assert!(!err.contains(" INFO "), "RUST_LOG=warn not honoured: {err}");

    // The database now holds the console client and an active RS256 key for every tenant.
    let db = cwd.path().join("anvilid-data").join("anvilid.db");
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let storage = SqliteStorage::connect(&format!("sqlite://{}", db.display()))
            .await
            .expect("open db");
        let system = storage
            .tenants()
            .get_by_slug(SYSTEM_TENANT_SLUG)
            .await
            .expect("system tenant")
            .expect("system tenant exists");
        assert!(
            storage
                .clients()
                .get(system.id, CONSOLE_CLIENT_ID)
                .await
                .expect("get client")
                .is_some(),
            "console client missing"
        );
        let tenants = storage
            .tenants()
            .list(PageRequest {
                after: None,
                limit: 100,
            })
            .await
            .expect("list tenants")
            .items;
        assert!(tenants.iter().any(|t| t.slug == DEFAULT_TENANT_SLUG));
        for t in &tenants {
            assert!(
                storage
                    .keys()
                    .active(t.id, "RS256")
                    .await
                    .expect("active key")
                    .is_some(),
                "tenant {} has no active RS256 key",
                t.slug
            );
        }
    });
}
