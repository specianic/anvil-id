//! `anvilid backup create|restore` on a SQLite data directory: an online backup while the server
//! runs and the database is being written, the restore guards (running server, corrupt file,
//! existing database without --yes, wrong KEK) and a full restore round trip.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditEventId, AuditOutcome, AuditQuery,
    DEFAULT_TENANT_SLUG, NewAuditEvent, RequestContext,
};
use anvil_core::ports::Storage as _;
use anvil_storage_sqlite::SqliteStorage;
use anvil_storage_sqlite::backup::{inspect, latest_migration_version};

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

fn run(cwd: &Path, args: &[&str], port: u16) -> Output {
    command(cwd, args, port).output().expect("run anvilid")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn healthy(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    if write!(
        stream,
        "GET /health/ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return false;
    }
    let mut raw = String::new();
    let _ = stream.read_to_string(&mut raw);
    raw.starts_with("HTTP/1.1 200")
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
        if healthy(port) {
            return server;
        }
        assert!(Instant::now() < deadline, "anvilid did not become healthy");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn db_path(cwd: &Path) -> PathBuf {
    cwd.join("anvilid-data").join("anvilid.db")
}

async fn open(path: &Path) -> SqliteStorage {
    SqliteStorage::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("open db")
}

async fn key_count(path: &Path) -> usize {
    let storage = open(path).await;
    let tenant = storage
        .tenants()
        .get_by_slug(DEFAULT_TENANT_SLUG)
        .await
        .expect("tenant")
        .expect("default tenant");
    let n = storage.keys().list(tenant.id).await.expect("keys").len();
    storage.close().await;
    n
}

/// Installs (first serve) and stops the server again.
fn install(cwd: &Path) {
    drop(serve(cwd, free_port()));
}

#[test]
fn backup_create_while_serving_and_writing_is_consistent_and_warns_about_the_kek() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let server = serve(cwd.path(), port);
    let rt = tokio::runtime::Runtime::new().expect("runtime");

    // A second process keeps writing (audit events) while the backup runs.
    let storage = rt.block_on(open(&db_path(cwd.path())));
    let tenant = rt
        .block_on(storage.tenants().get_by_slug(DEFAULT_TENANT_SLUG))
        .expect("tenant")
        .expect("default tenant");
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = stop.clone();
        let storage = storage.clone();
        rt.spawn(async move {
            let mut written = 0_u64;
            while !stop.load(Ordering::Relaxed) {
                let event = NewAuditEvent {
                    id: AuditEventId::new_v7(),
                    at: anvil_core::model::truncate_to_ms(time::OffsetDateTime::now_utc()),
                    actor: AuditActor::system(),
                    action: AuditAction::KeyRotationRequested,
                    target: None,
                    outcome: AuditOutcome::Success,
                    ctx: RequestContext::system(),
                    details: AuditDetails::empty(),
                    webhook: None,
                };
                storage
                    .audit()
                    .append(tenant.id, &event)
                    .await
                    .expect("append");
                written += 1;
            }
            written
        })
    };
    std::thread::sleep(Duration::from_millis(100));

    let output = cwd.path().join("backups").join("anvil.db");
    std::fs::create_dir(cwd.path().join("backups")).expect("mkdir");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            output.to_str().expect("utf8"),
        ],
        port,
    );
    stop.store(true, Ordering::Relaxed);
    let written = rt.block_on(writer).expect("writer task");
    assert!(written > 0, "the writer never ran");
    assert!(out.status.success(), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("KEK is not included"), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("backup written to"),
        "{}",
        text(&out)
    );
    assert!(healthy(port), "the server kept running");

    // Only the backup is left in the directory (the temporary file was renamed).
    let names: Vec<_> = std::fs::read_dir(cwd.path().join("backups"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("anvil.db")]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&output)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "backups are owner-only");
    }

    let manifest = rt.block_on(inspect(&output)).expect("integrity ok");
    assert_eq!(manifest.migration_version, latest_migration_version());
    assert_eq!(manifest.tenants, 2);
    // The copy is a complete database with a point-in-time subset of the events.
    let copy = rt.block_on(open(&output));
    let in_copy = rt
        .block_on(copy.audit().query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::KeyRotationRequested),
                limit: 10,
                ..AuditQuery::default()
            },
        ))
        .expect("query copy")
        .items
        .len();
    assert!(in_copy > 0, "the copy holds the events written before it");
    rt.block_on(copy.close());

    // An existing output is never overwritten.
    let again = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            output.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(!again.status.success(), "{}", text(&again));
    assert!(text(&again).contains("already exists"), "{}", text(&again));
    rt.block_on(storage.close());
    drop(server);
}

#[test]
fn backup_restore_refuses_while_the_server_runs() {
    let cwd = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let server = serve(cwd.path(), port);
    let backup = cwd.path().join("b.db");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            backup.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(out.status.success(), "{}", text(&out));

    let out = run(
        cwd.path(),
        &[
            "backup",
            "restore",
            "--input",
            backup.to_str().expect("utf8"),
            "--yes",
        ],
        port,
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("server is running"), "{}", text(&out));
    assert!(healthy(port), "the running server is untouched");
    drop(server);
}

#[test]
fn backup_restore_refuses_corrupt_and_foreign_files() {
    let cwd = tempfile::tempdir().expect("tempdir");
    install(cwd.path());
    let port = free_port();
    let backup = cwd.path().join("b.db");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            backup.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(out.status.success(), "{}", text(&out));
    let before = std::fs::read(db_path(cwd.path())).expect("read db");

    let bytes = std::fs::read(&backup).expect("read backup");
    let truncated = cwd.path().join("truncated.db");
    std::fs::write(&truncated, &bytes[..bytes.len() / 3]).expect("write");
    let garbage = cwd.path().join("garbage.db");
    std::fs::write(&garbage, b"not a database at all").expect("write");
    for bad in [&truncated, &garbage, &cwd.path().join("missing.db")] {
        let out = run(
            cwd.path(),
            &[
                "backup",
                "restore",
                "--input",
                bad.to_str().expect("utf8"),
                "--yes",
            ],
            port,
        );
        assert!(!out.status.success(), "{}: {}", bad.display(), text(&out));
        assert!(text(&out).contains("refusing to restore"), "{}", text(&out));
    }
    assert_eq!(
        std::fs::read(db_path(cwd.path())).expect("read db"),
        before,
        "a refused restore leaves the database alone"
    );
}

#[test]
fn backup_restore_refuses_a_wrong_kek_and_an_existing_database_without_yes() {
    let cwd = tempfile::tempdir().expect("tempdir");
    install(cwd.path());
    let port = free_port();
    let backup = cwd.path().join("b.db");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            backup.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(out.status.success(), "{}", text(&out));

    let out = run(
        cwd.path(),
        &[
            "backup",
            "restore",
            "--input",
            backup.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("--yes"), "{}", text(&out));

    // Another installation's KEK cannot open the backup's signing keys.
    let other = anvil_jose::Kek::generate();
    let out = command(
        cwd.path(),
        &[
            "backup",
            "restore",
            "--input",
            backup.to_str().expect("utf8"),
            "--yes",
        ],
        port,
    )
    .env(
        "ANVILID_KEK",
        secrecy::ExposeSecret::expose_secret(&other.to_base64()),
    )
    .output()
    .expect("run");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("cannot decrypt"), "{}", text(&out));
    let leftovers: Vec<_> = std::fs::read_dir(cwd.path().join("anvilid-data"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".restore-"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

    // Without a KEK at all the restore is refused before anything is touched.
    std::fs::remove_file(cwd.path().join("anvilid-data").join("kek")).expect("rm kek");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "restore",
            "--input",
            backup.to_str().expect("utf8"),
            "--yes",
        ],
        port,
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("KEK"), "{}", text(&out));
}

#[test]
fn backup_restore_round_trip_replaces_the_database_and_serve_starts() {
    let cwd = tempfile::tempdir().expect("tempdir");
    install(cwd.path());
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let db = db_path(cwd.path());
    let keys_at_backup = rt.block_on(key_count(&db));
    let port = free_port();
    let backup = cwd.path().join("b.db");
    let out = run(
        cwd.path(),
        &[
            "backup",
            "create",
            "--output",
            backup.to_str().expect("utf8"),
        ],
        port,
    );
    assert!(out.status.success(), "{}", text(&out));

    // A change after the backup: a prepublished signing key.
    let out = run(cwd.path(), &["keys", "rotate"], port);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(rt.block_on(key_count(&db)), keys_at_backup + 1);
    // A stale WAL beside the database must not survive the restore.
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let shm = PathBuf::from(format!("{}-shm", db.display()));
    std::fs::write(&wal, b"stale").expect("stale wal");
    std::fs::write(&shm, b"stale").expect("stale shm");

    let out = run(
        cwd.path(),
        &[
            "backup",
            "restore",
            "--input",
            backup.to_str().expect("utf8"),
            "--yes",
        ],
        port,
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("restored"), "{}", text(&out));
    assert!(!text(&out).contains("could not verify"), "{}", text(&out));
    assert!(!wal.exists(), "-wal removed");
    assert!(!shm.exists(), "-shm removed");
    let leftovers: Vec<_> = std::fs::read_dir(cwd.path().join("anvilid-data"))
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

    // The server starts on the restored database, which is the backed-up state.
    let server = serve(cwd.path(), port);
    assert!(healthy(port));
    drop(server);
    assert_eq!(rt.block_on(key_count(&db)), keys_at_backup);
}
