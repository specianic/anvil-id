//! `anvilid users import <file>` (ADM-08) on a SQLite installation, through the binary:
//!
//! - a mixed file creates the valid users and lists rejected lines with reason codes (exit 1);
//! - a re-run reports only `unchanged`; `--dry-run` writes nothing;
//! - a conflict without `--update` leaves the user unchanged, with `--update` it is updated;
//! - a 2,500-line file runs in three batches (three `users_imported` events);
//! - stdout and stderr never carry hash material;
//! - the `--help` output lists every flag.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{AuditAction, AuditQuery, PageRequest, PublicUrl, Tenant};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::Storage as _;
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use anvil_web::adapters::Argon2Pool;
use secrecy::ExposeSecret;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
const PBKDF2_HASH_HEX: &str = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
const PBKDF2_SALT_HEX: &str =
    "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74";

/// An installed data directory (in-process install, KEK file written).
struct Instance {
    dir: tempfile::TempDir,
    storage: Arc<SqliteStorage>,
}

impl Instance {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("anvilid-data");
        std::fs::create_dir(&data).expect("data dir");
        let kek = Kek::generate();
        std::fs::write(data.join("kek"), kek.to_base64().expose_secret()).expect("kek file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(data.join("kek"), std::fs::Permissions::from_mode(0o600))
                .expect("chmod kek");
        }
        let storage = SqliteStorage::connect(&format!(
            "sqlite://{}?mode=rwc",
            data.join("anvilid.db").display()
        ))
        .await
        .expect("connect");
        storage.migrate().await.expect("migrate");
        let storage = Arc::new(storage);
        let bootstrap = BootstrapService {
            storage: storage.clone(),
            clock: Arc::new(SystemClock),
            kek: Arc::new(kek),
            hasher: Arc::new(Argon2Pool::new(Argon2Pool::owasp_params(), 1).expect("argon2")),
            policy: PasswordPolicy::default(),
            public_url: PublicUrl::parse("https://id.example.test").expect("public url"),
        };
        assert!(matches!(
            bootstrap.ensure_installed().await.expect("install"),
            InstallResult::Installed { .. }
        ));
        Self { dir, storage }
    }

    fn write(&self, name: &str, lines: &[String]) -> PathBuf {
        let path = self.dir.path().join(name);
        std::fs::write(&path, lines.join("\n") + "\n").expect("write file");
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        run_in(self.dir.path(), args)
    }

    async fn tenant(&self) -> Tenant {
        self.storage
            .tenants()
            .get_by_slug("default")
            .await
            .expect("lookup")
            .expect("tenant")
    }

    async fn users(&self) -> usize {
        let tenant = self.tenant().await;
        let mut n = 0;
        let mut after = None;
        loop {
            let page = self
                .storage
                .users()
                .list(tenant.id, PageRequest { after, limit: 200 })
                .await
                .expect("list");
            n += page.items.len();
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => return n,
            }
        }
    }

    async fn audit_count(&self, action: AuditAction) -> usize {
        let tenant = self.tenant().await;
        self.storage
            .audit()
            .query(
                tenant.id,
                &AuditQuery {
                    action: Some(action),
                    limit: 200,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit")
            .items
            .len()
    }
}

/// Runs the binary in `cwd` with a clean environment (only PATH kept).
fn run_in(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .env("ANVILID_PUBLIC_URL", "https://id.example.test")
        .env("ANVILID_BREACH_CHECK", "off")
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    cmd.output().expect("run anvilid")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_no_hash_material(out: &Output) {
    let all = format!("{}{}", stdout(out), stderr(out));
    for needle in [
        BCRYPT_HASH,
        &BCRYPT_HASH[7..29],
        &PBKDF2_HASH_HEX[..20],
        &PBKDF2_SALT_HEX[..20],
        "$anvil-",
        "$2a$",
        "$2b$",
        "$2x$",
        "$argon2",
    ] {
        assert!(!all.contains(needle), "{needle:?} in output:\n{all}");
    }
}

fn user(email: &str) -> String {
    json!({"email": email, "email_verified": true}).to_string()
}

fn mixed() -> Vec<String> {
    vec![
        json!({"email": "bcrypt@example.com", "email_verified": true,
            "password": {"scheme": "bcrypt", "hash": BCRYPT_HASH}})
        .to_string(),
        json!({"email": "pbkdf2@example.com",
            "password": {"scheme": "pbkdf2", "prf": "sha1", "iterations": 4096,
                "salt": {"hex": PBKDF2_SALT_HEX}, "hash": {"hex": PBKDF2_HASH_HEX}}})
        .to_string(),
        String::new(),
        user("plain@example.com"),
        "{not json".to_owned(),
        json!({"email": "x@example.com",
            "password": {"scheme": "bcrypt",
                "hash": "$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"}})
        .to_string(),
        user("not-an-email"),
    ]
}

#[test]
fn users_import_help_lists_every_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run_in(dir.path(), &["users", "import", "--help"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let help = stdout(&out);
    for flag in ["<FILE>", "--tenant", "--dry-run", "--update", "--source"] {
        assert!(help.contains(flag), "{flag} missing from:\n{help}");
    }
}

#[test]
fn users_import_without_an_installation_fails_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("u.ndjson"), user("a@example.com")).unwrap();
    let out = run_in(dir.path(), &["users", "import", "u.ndjson"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not exist"), "{}", stderr(&out));
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_file_rerun_and_dry_run() {
    let inst = Instance::new().await;
    let file = inst.write("users.ndjson", &mixed());
    let file = file.to_str().unwrap();
    let before = inst.users().await;

    // Dry run: the report, nothing written, still non-zero because of the rejected lines.
    let dry = inst.run(&["users", "import", file, "--dry-run", "--source", "legacy"]);
    assert!(!dry.status.success());
    assert!(stdout(&dry).contains("dry run"), "{}", stdout(&dry));
    assert!(stdout(&dry).contains("created:   3"), "{}", stdout(&dry));
    assert_eq!(inst.users().await, before, "dry run writes nothing");
    assert_no_hash_material(&dry);

    let out = inst.run(&["users", "import", file, "--source", "legacy"]);
    assert!(!out.status.success(), "rejections exit non-zero");
    let text = stdout(&out);
    assert!(text.contains("created:   3"), "{text}");
    assert!(text.contains("rejected:  3"), "{text}");
    assert!(text.contains("weak hashes accepted: 2"), "{text}");
    assert!(text.contains("line 5: invalid_record"), "{text}");
    assert!(text.contains("line 6: refused_variant"), "{text}");
    assert!(text.contains("line 7: invalid_email"), "{text}");
    assert!(
        stderr(&out).contains("3 record(s) rejected"),
        "{}",
        stderr(&out)
    );
    assert_no_hash_material(&out);
    assert_eq!(inst.users().await, before + 3);

    // Re-run: only unchanged.
    let again = inst.run(&["users", "import", file]);
    let text = stdout(&again);
    assert!(text.contains("unchanged: 3"), "{text}");
    assert!(text.contains("created:   0"), "{text}");
    assert_no_hash_material(&again);

    // A file of valid records only exits zero.
    let good = inst.write("good.ndjson", &mixed()[..4]);
    let ok = inst.run(&["users", "import", good.to_str().unwrap()]);
    assert!(ok.status.success(), "{}{}", stdout(&ok), stderr(&ok));
}

#[tokio::test(flavor = "multi_thread")]
async fn conflict_needs_update() {
    let inst = Instance::new().await;
    let first = inst.write("a.ndjson", &[user("c@example.com")]);
    assert!(
        inst.run(&["users", "import", first.to_str().unwrap()])
            .status
            .success()
    );
    let changed = inst.write(
        "b.ndjson",
        &[json!({"email": "c@example.com", "email_verified": true,
            "claims": {"name": "Cee"}})
        .to_string()],
    );
    let changed = changed.to_str().unwrap();
    let tenant = inst.tenant().await;
    let get = || async {
        inst.storage
            .users()
            .get_by_email(tenant.id, "c@example.com")
            .await
            .unwrap()
            .unwrap()
    };

    let out = inst.run(&["users", "import", changed]);
    assert!(out.status.success(), "a conflict alone does not fail");
    assert!(stdout(&out).contains("conflict:  1"), "{}", stdout(&out));
    assert!(stdout(&out).contains("line 1"), "{}", stdout(&out));
    assert_eq!(get().await.claims.name, None, "not overwritten");

    let out = inst.run(&["users", "import", changed, "--update"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("updated:   1"), "{}", stdout(&out));
    assert_eq!(get().await.claims.name.as_deref(), Some("Cee"));
}

#[tokio::test(flavor = "multi_thread")]
async fn large_file_runs_in_batches() {
    let inst = Instance::new().await;
    let lines: Vec<String> = (0..2500)
        .map(|i| user(&format!("u{i}@example.com")))
        .collect();
    let file = inst.write("big.ndjson", &lines);
    let before = inst.users().await;
    let imported_before = inst.audit_count(AuditAction::UsersImported).await;
    let out = inst.run(&["users", "import", file.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("batches:   3"), "{text}");
    assert!(text.contains("created:   2500"), "{text}");
    assert_eq!(inst.users().await, before + 2500);
    assert_eq!(
        inst.audit_count(AuditAction::UsersImported).await,
        imported_before + 3
    );
}
