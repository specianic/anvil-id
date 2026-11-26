//! `anvilid admin recover` (ADM-07) on a SQLite installation:
//!
//! - `--email` prints one recovery URL that opens the system reset page and sets a password once;
//!   the token expires after one hour; unknown and other-tenant emails are refused;
//! - the administrator role is (re)assigned; `--reset-mfa` removes TOTP and passkeys, without it
//!   they stay; every issue is audited as `admin_recovery_issued` by the system actor;
//! - without `--email`: a new-administrator setup URL only when nobody holds `admin:write`;
//! - no HTTP route reaches the recovery service.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_core::clock::SystemClock;
use anvil_core::error::CoreError;
use anvil_core::model::{
    ActorKind, AuditAction, AuditEvent, AuditQuery, CredentialId, CredentialKind,
    DEFAULT_TENANT_SLUG, NewPasskey, NewTotp, NewUser, PublicUrl, RequestContext,
    SYSTEM_ADMIN_ROLE, SYSTEM_TENANT_SLUG, SecretHash, Tenant, User, UserId, UserStatus,
    truncate_to_ms,
};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::{Clock, PasswordHasher as _, Storage as _};
use anvil_core::service::admin_recovery::AdminRecoveryService;
use anvil_core::service::admin_scope::ADMIN_WRITE;
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_jose::Kek;
use anvil_jose::encoding::secret_hash;
use anvil_storage_sqlite::SqliteStorage;
use anvil_web::adapters::Argon2Pool;
use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const ADMIN_EMAIL: &str = "admin@example.test";
const PASSWORD: &str = "correct horse battery staple 42";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The test clock: a fixed instant.
struct At(OffsetDateTime);

impl Clock for At {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// An installed data directory (in-process install, KEK file written) with one administrator.
struct Install {
    dir: tempfile::TempDir,
    port: u16,
    storage: Arc<SqliteStorage>,
    kek: Arc<Kek>,
    system: Tenant,
    admin: User,
}

impl Install {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let port = free_port();
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
        let kek = Arc::new(kek);
        let mut install = Self {
            port,
            system: placeholder_tenant(),
            admin: placeholder_user(),
            storage,
            kek,
            dir,
        };
        let InstallResult::Installed { setup_url } = install
            .bootstrap()
            .ensure_installed()
            .await
            .expect("install")
        else {
            panic!("fresh database must install");
        };
        install.admin = install
            .complete_setup(&setup_url, ADMIN_EMAIL)
            .await
            .expect("first setup");
        install.system = install
            .storage
            .tenants()
            .get_by_slug(SYSTEM_TENANT_SLUG)
            .await
            .expect("tenant")
            .expect("system tenant");
        install
    }

    fn public_url(&self) -> PublicUrl {
        PublicUrl::parse(&format!("http://127.0.0.1:{}", self.port)).expect("public url")
    }

    fn bootstrap(&self) -> BootstrapService {
        BootstrapService {
            storage: self.storage.clone(),
            clock: Arc::new(SystemClock),
            kek: self.kek.clone(),
            hasher: Arc::new(Argon2Pool::new(Argon2Pool::owasp_params(), 1).expect("argon2")),
            policy: PasswordPolicy::default(),
            public_url: self.public_url(),
        }
    }

    /// Completes setup with the token of `setup_url`.
    async fn complete_setup(
        &self,
        setup_url: &SecretString,
        email: &str,
    ) -> Result<User, CoreError> {
        let token = setup_url
            .expose_secret()
            .split_once("token=")
            .expect("setup URL has a token")
            .1
            .to_owned();
        self.bootstrap()
            .complete_setup(
                &token,
                email,
                &SecretString::from(PASSWORD),
                &RequestContext::default(),
            )
            .await
            .map(|r| r.admin)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(self.dir.path())
            .env_clear()
            .env("ANVILID_LISTEN", format!("127.0.0.1:{}", self.port))
            .env(
                "ANVILID_PUBLIC_URL",
                format!("http://127.0.0.1:{}", self.port),
            )
            .env("ANVILID_BREACH_CHECK", "off")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd
    }

    fn recover(&self, args: &[&str]) -> Output {
        let mut all = vec!["admin", "recover"];
        all.extend_from_slice(args);
        self.command(&all).output().expect("run anvilid")
    }

    async fn recovery_events(&self) -> Vec<AuditEvent> {
        self.storage
            .audit()
            .query(
                self.system.id,
                &AuditQuery {
                    action: Some(AuditAction::AdminRecoveryIssued),
                    limit: 50,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit query")
            .items
    }

    async fn holds_admin(&self, user: UserId) -> bool {
        self.storage
            .roles()
            .roles_for_user(self.system.id, user)
            .await
            .expect("roles")
            .iter()
            .any(|r| r.name == SYSTEM_ADMIN_ROLE && r.permissions.iter().any(|p| p == ADMIN_WRITE))
    }

    async fn unassign_admin(&self, user: UserId) {
        let role = self
            .storage
            .roles()
            .get_by_name(self.system.id, SYSTEM_ADMIN_ROLE)
            .await
            .expect("role")
            .expect("administrator role");
        assert!(
            self.storage
                .roles()
                .unassign(self.system.id, role.id, user)
                .await
                .expect("unassign")
        );
    }

    async fn holders(&self) -> u64 {
        self.storage
            .roles()
            .holders_of_permission(self.system.id, ADMIN_WRITE)
            .await
            .expect("holders")
    }

    /// Consumes a recovery token with a new password, as the reset page's POST does.
    async fn complete_recovery(&self, token: &str, at: OffsetDateTime) -> Option<User> {
        let hasher = Argon2Pool::new(Argon2Pool::owasp_params(), 1).expect("argon2");
        let phc = hasher
            .hash("a brand new passphrase 99")
            .await
            .expect("hash");
        self.storage
            .users()
            .complete_recovery(
                self.system.id,
                &SecretHash(secret_hash(token)),
                &phc,
                at,
                None,
            )
            .await
            .expect("complete_recovery")
    }
}

fn placeholder_tenant() -> Tenant {
    Tenant {
        id: anvil_core::model::TenantId::new_v7(),
        slug: String::new(),
        display_name: String::new(),
        host: None,
        settings: Default::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn placeholder_user() -> User {
    User {
        id: UserId::new_v7(),
        tenant_id: anvil_core::model::TenantId::new_v7(),
        email: String::new(),
        email_verified: false,
        username: None,
        claims: Default::default(),
        status: UserStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        last_login_at: None,
    }
}

/// The single `{prefix} URL` line of `out`.
fn url_line(out: &Output, prefix: &str) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<_> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix(prefix))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one URL line: {stdout}");
    lines[0].trim().to_owned()
}

fn token_of(url: &str) -> String {
    url.split_once("?token=").expect("token").1.to_owned()
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

#[test]
fn admin_recover_issues_a_one_time_recovery_url_for_a_system_admin() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());

    // The address is normalised like every other email input.
    let out = install.recover(&["--email", "Admin@Example.TEST"]);
    assert!(out.status.success(), "{}", text(&out));
    let url = url_line(&out, "Recovery URL:");
    let prefix = format!(
        "http://127.0.0.1:{}/t/system/ui/recovery?token=",
        install.port
    );
    assert!(url.starts_with(&prefix), "{url}");
    assert!(
        !text(&out).contains("Assigned the administrator role"),
        "the administrator already holds the role: {}",
        text(&out)
    );
    let token = token_of(&url);

    // The URL opens the existing reset page of the system tenant.
    {
        let child = install
            .command(&["serve"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut server = Server(child);
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let path = url
            .strip_prefix(&format!("http://127.0.0.1:{}", install.port))
            .expect("path");
        let (status, body) = loop {
            if let Some(status) = server.0.try_wait().expect("try_wait") {
                panic!("anvilid exited early with {status}");
            }
            if let Ok(resp) = http_get(install.port, path) {
                break resp;
            }
            assert!(Instant::now() < deadline, "server did not start");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.contains(" 200 "), "{status}");
        assert!(
            body.contains("name=\"token\""),
            "reset form expected: {body}"
        );
        assert!(
            body.contains("type=\"password\""),
            "reset form expected: {body}"
        );
    }

    // One use: the first reset succeeds for the administrator, the second fails.
    let now = truncate_to_ms(OffsetDateTime::now_utc());
    let user = rt
        .block_on(install.complete_recovery(&token, now))
        .expect("first use sets the password");
    assert_eq!(user.id, install.admin.id);
    assert!(
        rt.block_on(install.complete_recovery(&token, now))
            .is_none(),
        "second use must fail"
    );

    let events = rt.block_on(install.recovery_events());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].actor.kind, ActorKind::System);
    assert_eq!(
        events[0].target.as_deref(),
        Some(install.admin.id.to_string().as_str())
    );
    assert!(
        !format!("{:?}", events[0].details).contains(&token),
        "the token is never audited"
    );
}

#[test]
fn admin_recover_token_expires_after_one_hour() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    let t0 = truncate_to_ms(OffsetDateTime::now_utc());
    let service = AdminRecoveryService {
        storage: install.storage.clone(),
        clock: Arc::new(At(t0)),
        public_url: install.public_url(),
    };

    let expired = rt
        .block_on(service.issue(ADMIN_EMAIL, false))
        .expect("issue");
    assert_eq!(expired.expires_at, t0 + time::Duration::hours(1));
    assert!(
        rt.block_on(install.complete_recovery(
            &token_of(expired.url.expose_secret()),
            t0 + time::Duration::hours(1)
        ))
        .is_none(),
        "expired after one hour"
    );

    let fresh = rt
        .block_on(service.issue(ADMIN_EMAIL, false))
        .expect("issue");
    assert!(
        rt.block_on(install.complete_recovery(
            &token_of(fresh.url.expose_secret()),
            t0 + time::Duration::minutes(59)
        ))
        .is_some(),
        "valid within the hour"
    );
}

#[test]
fn admin_recover_refuses_unknown_and_other_tenant_emails() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    let default = rt
        .block_on(install.storage.tenants().get_by_slug(DEFAULT_TENANT_SLUG))
        .expect("tenant")
        .expect("default tenant");
    let now = truncate_to_ms(OffsetDateTime::now_utc());
    let other = rt
        .block_on(install.storage.users().create(
            default.id,
            &NewUser {
                id: UserId::new_v7(),
                email: "someone@example.test".to_owned(),
                email_verified: true,
                username: None,
                claims: Default::default(),
                status: UserStatus::Active,
                created_at: now,
            },
            None,
            None,
            None,
        ))
        .expect("default-tenant user");

    for email in ["someone@example.test", "nobody@example.test"] {
        let out = install.recover(&["--email", email]);
        assert!(!out.status.success(), "{email}: {}", text(&out));
        assert!(text(&out).contains("system-tenant"), "{}", text(&out));
        assert!(!text(&out).contains("Recovery URL"), "{}", text(&out));
    }
    let out = install.recover(&["--email", "not-an-email"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("Recovery URL"), "{}", text(&out));

    // Nothing was created, assigned or audited.
    assert!(rt.block_on(install.recovery_events()).is_empty());
    assert!(
        rt.block_on(install.storage.roles().roles_for_user(default.id, other.id))
            .expect("roles")
            .is_empty()
    );
    assert_eq!(rt.block_on(install.holders()), 1);
}

#[test]
fn admin_recover_reset_mfa_removes_totp_and_passkeys_only_when_asked() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    let now = truncate_to_ms(OffsetDateTime::now_utc());
    let users = install.storage.users();
    rt.block_on(users.create_totp(
        install.system.id,
        install.admin.id,
        &NewTotp {
            id: CredentialId::new_v7(),
            secret_enc: vec![1; 48],
            created_at: now,
        },
        &[],
        now,
    ))
    .expect("totp");
    rt.block_on(users.create_passkey(
        install.system.id,
        install.admin.id,
        &NewPasskey {
            id: CredentialId::new_v7(),
            credential_id: vec![7; 16],
            passkey_json: "{}".to_owned(),
            counter: 0,
            backup_eligible: false,
            label: "security key".to_owned(),
            created_at: now,
        },
    ))
    .expect("passkey");
    let kinds = |rt: &tokio::runtime::Runtime| {
        let mut k: Vec<_> = rt
            .block_on(users.list_credentials(install.system.id, install.admin.id))
            .expect("credentials")
            .into_iter()
            .map(|c| c.kind)
            .collect();
        k.sort_by_key(|k| k.as_str());
        k
    };
    let all = vec![
        CredentialKind::Password,
        CredentialKind::Totp,
        CredentialKind::Webauthn,
    ];
    assert_eq!(kinds(&rt), all);

    let out = install.recover(&["--email", ADMIN_EMAIL]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        kinds(&rt),
        all,
        "without --reset-mfa the second factors stay"
    );

    // --reset-mfa needs --email.
    let out = install.recover(&["--reset-mfa"]);
    assert!(!out.status.success(), "{}", text(&out));

    let out = install.recover(&["--email", ADMIN_EMAIL, "--reset-mfa"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Removed 2"), "{}", text(&out));
    assert_eq!(kinds(&rt), vec![CredentialKind::Password]);

    let events = rt.block_on(install.recovery_events());
    assert_eq!(events.len(), 2);
    // Newest first: the --reset-mfa issue records it, the first one does not.
    let fields = |e: &AuditEvent| e.details.as_map()["fields"].to_string();
    assert!(
        fields(&events[0]).contains("\"mfa\""),
        "{}",
        fields(&events[0])
    );
    assert!(
        !fields(&events[1]).contains("\"mfa\""),
        "{}",
        fields(&events[1])
    );
    // Each removed factor is audited like an administrator's removal, by the system actor.
    for action in [AuditAction::TotpRemoved, AuditAction::PasskeyRemoved] {
        let removed = rt
            .block_on(install.storage.audit().query(
                install.system.id,
                &AuditQuery {
                    action: Some(action),
                    limit: 10,
                    ..AuditQuery::default()
                },
            ))
            .expect("audit")
            .items;
        assert_eq!(removed.len(), 1, "{action:?}");
        assert_eq!(removed[0].actor.kind, ActorKind::System);
    }
}

#[test]
fn admin_recover_assigns_the_administrator_role() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    rt.block_on(install.unassign_admin(install.admin.id));
    assert!(!rt.block_on(install.holds_admin(install.admin.id)));

    let out = install.recover(&["--email", ADMIN_EMAIL]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Assigned the administrator role"),
        "{}",
        text(&out)
    );
    assert!(rt.block_on(install.holds_admin(install.admin.id)));
    let events = rt.block_on(install.recovery_events());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor.kind, ActorKind::System);
    assert!(
        events[0].details.as_map()["fields"]
            .to_string()
            .contains("administrator_role"),
        "{:?}",
        events[0].details
    );
}

#[test]
fn admin_recover_refuses_blocked_accounts() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    rt.block_on(install.storage.users().update(
        install.system.id,
        install.admin.id,
        &anvil_core::model::UserUpdate {
            status: Some(UserStatus::Blocked),
            ..Default::default()
        },
        truncate_to_ms(OffsetDateTime::now_utc()),
    ))
    .expect("update")
    .expect("user");
    let out = install.recover(&["--email", ADMIN_EMAIL]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("without --email"), "{}", text(&out));
    assert!(rt.block_on(install.recovery_events()).is_empty());
}

#[test]
fn admin_recover_creates_fresh_admin_when_locked_out() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    rt.block_on(install.unassign_admin(install.admin.id));
    assert_eq!(rt.block_on(install.holders()), 0, "locked out");

    let out = install.recover(&[]);
    assert!(out.status.success(), "{}", text(&out));
    let url = url_line(&out, "Setup URL:");
    assert!(
        url.starts_with(&format!("http://127.0.0.1:{}/setup?token=", install.port)),
        "{url}"
    );

    // Completing setup creates a new system user holding administrator (admin:write).
    let url = SecretString::from(url);
    let fresh = rt
        .block_on(install.complete_setup(&url, "new-admin@example.test"))
        .expect("setup with the recovery URL");
    assert_ne!(fresh.id, install.admin.id);
    assert_eq!(fresh.tenant_id, install.system.id);
    assert!(rt.block_on(install.holds_admin(fresh.id)));
    assert_eq!(rt.block_on(install.holders()), 1);
    // One use.
    assert!(matches!(
        rt.block_on(install.complete_setup(&url, "third@example.test")),
        Err(CoreError::Forbidden)
    ));

    let events = rt.block_on(install.recovery_events());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor.kind, ActorKind::System);
    assert_eq!(events[0].target, None);
}

#[test]
fn admin_recover_without_email_refused_when_admin_exists() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let install = rt.block_on(Install::new());
    assert_eq!(rt.block_on(install.holders()), 1);

    let out = install.recover(&[]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("--email"), "{}", text(&out));
    assert!(!text(&out).contains("Setup URL"), "{}", text(&out));
    assert!(rt.block_on(install.recovery_events()).is_empty());
    assert_eq!(rt.block_on(install.holders()), 1);
}

/// The recovery service is reachable from the CLI only: no web module refers to it.
#[test]
fn admin_recovery_has_no_http_route() {
    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates.join("anvil-web").join("src"), &mut files);
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(!files.is_empty());
    for file in files {
        let src = std::fs::read_to_string(&file).expect("read");
        let uses = src.contains("AdminRecoveryService") || src.contains("admin_recovery");
        let allowed = file.ends_with("anvilid/src/recover.rs");
        assert!(
            !uses || allowed,
            "{} refers to the admin recovery service",
            file.display()
        );
    }
}

#[test]
fn admin_recover_needs_an_installation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(BIN);
    cmd.args(["admin", "recover", "--email", ADMIN_EMAIL])
        .current_dir(dir.path())
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    let out = cmd.output().expect("run");
    assert!(!out.status.success());
    assert!(text(&out).contains("anvilid serve"), "{}", text(&out));
    assert!(!dir.path().join("anvilid-data").exists());
}
