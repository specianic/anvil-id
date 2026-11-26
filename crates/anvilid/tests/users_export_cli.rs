//! `anvilid users export` (ADM-09) on a SQLite installation: bulk NDJSON over more than one page,
//! single-user JSON, the GDPR bundle, password hashes absent by default and present (and audited)
//! only with `--include-password-hashes`, the flag refused with `--gdpr` and `--user`, and the
//! output file created with mode 0600.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{
    ActorKind, AuditAction, AuditQuery, NewPasswordCredential, NewUser, PublicUrl, StandardClaims,
    TenantId, UserId, UserStatus,
};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::Storage as _;
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use anvil_web::adapters::Argon2Pool;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
/// More than one bulk page (`BULK_PAGE_SIZE` = 100).
const USERS: usize = 130;
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$Y2xpc2FsdA$Y2xpaGFzaA";

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// An installed data directory with `USERS` users in the default tenant.
struct Instance {
    dir: tempfile::TempDir,
    storage: Arc<SqliteStorage>,
    tenant: TenantId,
    users: Vec<UserId>,
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
        let tenant = storage
            .tenants()
            .get_by_slug("default")
            .await
            .expect("lookup")
            .expect("default tenant")
            .id;
        let now = anvil_core::model::truncate_to_ms(time::OffsetDateTime::now_utc());
        let mut users = Vec::new();
        for i in 0..USERS {
            let u = NewUser {
                id: UserId::new_v7(),
                email: format!("user-{i:03}@example.test"),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: now,
            };
            // Every other user has a password.
            let pw = (i % 2 == 0).then(|| NewPasswordCredential {
                phc: PHC.to_owned(),
                created_at: now,
            });
            storage
                .users()
                .create(tenant, &u, pw.as_ref(), None, None)
                .await
                .expect("user");
            users.push(u.id);
        }
        users.sort();
        Self {
            dir,
            storage,
            tenant,
            users,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(self.dir.path())
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

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    /// `user_exported` events, newest first, as (actor id, target, details).
    async fn exports(&self) -> Vec<(Option<String>, Option<String>, Value)> {
        let page = self
            .storage
            .audit()
            .query(
                self.tenant,
                &AuditQuery {
                    from: None,
                    to: None,
                    actor_id: None,
                    action: Some(AuditAction::UserExported),
                    outcome: None,
                    target: None,
                    before: None,
                    limit: 50,
                },
            )
            .await
            .expect("audit");
        page.items
            .into_iter()
            .map(|e| {
                assert_eq!(e.actor.kind, ActorKind::System);
                (
                    e.actor.id,
                    e.target,
                    Value::Object(e.details.as_map().clone()),
                )
            })
            .collect()
    }
}

fn ndjson(text: &str) -> Vec<Value> {
    text.lines()
        .map(|l| serde_json::from_str(l).expect("one JSON object per line"))
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn users_export_help_lists_every_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Command::new(BIN)
        .args(["users", "export", "--help"])
        .current_dir(dir.path())
        .env_clear()
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", stderr(&out));
    let help = stdout(&out);
    for flag in [
        "--tenant",
        "--user",
        "--gdpr",
        "--include-password-hashes",
        "--out",
    ] {
        assert!(help.contains(flag), "{flag} missing from:\n{help}");
    }
    assert!(
        help.contains("never part of the GDPR export (decision Q4)"),
        "{help}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_export_streams_every_user_without_hashes() {
    let i = Instance::new().await;
    let out = i.run(&["users", "export"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let records = ndjson(&stdout(&out));
    let ids: Vec<String> = records
        .iter()
        .map(|r| r["id"].as_str().expect("id").to_owned())
        .collect();
    let expected: Vec<String> = i.users.iter().map(ToString::to_string).collect();
    assert_eq!(
        ids, expected,
        "every user once, over two pages, in id order"
    );
    let text = stdout(&out);
    assert!(!text.contains("password_hash"), "no hashes by default");
    assert!(!text.contains("$argon2"), "no hashes by default");
    assert!(stderr(&out).contains(&format!("exported {USERS} users")));

    assert_eq!(
        i.exports().await,
        [(
            Some("cli".to_owned()),
            None,
            json!({"mode": "bulk", "count": USERS, "include_password_hashes": false})
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_export_with_hashes_is_opt_in_and_audited() {
    let i = Instance::new().await;
    let file = i.path("users.ndjson");
    let out = i.run(&[
        "users",
        "export",
        "--include-password-hashes",
        "--out",
        file.to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    // With --out, stdout carries only the audit mirror line (never exported data).
    let mirror = ndjson(&stdout(&out));
    assert_eq!(mirror.len(), 1, "{}", stdout(&out));
    assert_eq!(mirror[0]["action"], "user_exported");
    assert_eq!(mirror[0]["details"]["include_password_hashes"], true);
    assert!(!stdout(&out).contains("$argon2"));
    assert!(stderr(&out).contains("password hashes"), "{}", stderr(&out));
    let records = ndjson(&std::fs::read_to_string(&file).expect("read"));
    assert_eq!(records.len(), USERS);
    let with_hash = records
        .iter()
        .filter(|r| r.get("password_hash") == Some(&Value::from(PHC)))
        .count();
    assert_eq!(
        with_hash,
        USERS.div_ceil(2),
        "exactly the users with a password"
    );
    assert!(
        records
            .iter()
            .all(|r| r.get("password_hash").is_none() || r["password_hash"] == PHC)
    );
    #[cfg(unix)]
    assert_eq!(mode(&file), 0o600);

    assert_eq!(
        i.exports().await,
        [(
            Some("cli".to_owned()),
            None,
            json!({"mode": "bulk", "count": USERS, "include_password_hashes": true})
        )]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn single_and_gdpr_exports() {
    let i = Instance::new().await;
    let id = i.users[0].to_string();

    let out = i.run(&["users", "export", "--user", &id]);
    assert!(out.status.success(), "{}", stderr(&out));
    let record: Value = serde_json::from_str(&stdout(&out)).expect("one JSON document");
    assert_eq!(record["id"], id);
    assert!(record.get("password_hash").is_none());

    let file = i.path("gdpr.json");
    std::fs::write(&file, "old contents").expect("pre-existing file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    let out = i.run(&[
        "users",
        "export",
        "--user",
        &id,
        "--gdpr",
        "--out",
        file.to_str().expect("utf-8 path"),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let bundle: Value =
        serde_json::from_str(&std::fs::read_to_string(&file).expect("read")).expect("json");
    assert_eq!(bundle["export_format_version"], 1);
    assert_eq!(bundle["subject"]["id"], id);
    assert_eq!(bundle["operator_statement"], Value::Null);
    // The single export of a moment ago is an audit event about the subject.
    assert_eq!(bundle["audit_events"][0]["action"], "user_exported");
    assert_eq!(bundle["audit_events"][0]["actor"], "system");
    assert!(!bundle.to_string().contains("$argon2"));
    #[cfg(unix)]
    assert_eq!(mode(&file), 0o600, "an existing file is tightened to 0600");

    assert_eq!(
        i.exports().await,
        [
            (
                Some("cli".to_owned()),
                Some(id.clone()),
                json!({"mode": "gdpr", "count": 1, "include_password_hashes": false})
            ),
            (
                Some("cli".to_owned()),
                Some(id.clone()),
                json!({"mode": "single", "count": 1, "include_password_hashes": false})
            ),
        ]
    );

    // An unknown user is an error and writes no audit event.
    let unknown = UserId::new_v7().to_string();
    let out = i.run(&["users", "export", "--user", &unknown]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not exist"), "{}", stderr(&out));
    assert_eq!(i.exports().await.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_hash_flag_refused_with_gdpr() {
    let i = Instance::new().await;
    let id = i.users[0].to_string();
    for args in [
        vec![
            "users",
            "export",
            "--user",
            id.as_str(),
            "--gdpr",
            "--include-password-hashes",
        ],
        vec![
            "users",
            "export",
            "--user",
            id.as_str(),
            "--include-password-hashes",
        ],
    ] {
        let out = i.run(&args);
        assert!(!out.status.success(), "{args:?} must be refused");
        assert!(stdout(&out).is_empty(), "nothing exported for {args:?}");
        assert!(!stdout(&out).contains("$argon2"));
    }
    // --gdpr without --user is refused by the parser.
    let out = i.run(&["users", "export", "--gdpr"]);
    assert!(!out.status.success());
    assert!(i.exports().await.is_empty(), "refused runs export nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_tenant_is_an_error() {
    let i = Instance::new().await;
    let out = i.run(&["users", "export", "--tenant", "nope"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("tenant `nope` does not exist"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn missing_database_is_refused_without_creating_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = Command::new(BIN)
        .args(["users", "export"])
        .current_dir(dir.path())
        .env_clear()
        .env("ANVILID_PUBLIC_URL", "https://id.example.test")
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert!(!out.status.success());
    assert!(stdout(&out).is_empty());
}
