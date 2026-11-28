//! The running version through `anvilid serve`: `GET /api/admin/v1/system/info` answers a
//! system-tenant admin token with this binary's own version (`CARGO_PKG_VERSION` of `anvilid`),
//! and no public endpoint (discovery, JWKS, health, pages, the console shell, 404 and error
//! bodies) or response header carries it.

use std::fs::File;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anvil_core::model::{
    ApplicationType, ClientAuthMethod, ClientId, ClientKind, ClientSource, ClientType, ConsentMode,
    GrantType, NewClient, OrgClientPolicy, SYSTEM_TENANT_SLUG, SecretHash, TokenFormat,
};
use anvil_core::ports::Storage as _;
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_storage_sqlite::SqliteStorage;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Kills the server on drop so a failing assertion never leaks a process.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(data_dir: &Path, port: u16) -> Server {
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
        .current_dir(data_dir)
        .env_clear()
        .env("ANVILID_RATE_LIMIT_ENABLED", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(data_dir.join("stderr.log")).expect("stderr log"));
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    Server(cmd.spawn().expect("spawn anvilid"))
}

async fn wait_ready(server: &mut Server, http: &reqwest::Client, base: &str, data_dir: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = server.0.try_wait().expect("try_wait") {
            let err = std::fs::read_to_string(data_dir.join("stderr.log")).unwrap_or_default();
            panic!("anvilid exited early with {status}: {err}");
        }
        if let Ok(resp) = http.get(format!("{base}/health/ready")).send().await
            && resp.status().is_success()
        {
            return;
        }
        assert!(Instant::now() < deadline, "anvilid did not become ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Registers a client_credentials client with `admin:read` in the system tenant through the
/// storage port (no setup flow needed) and returns its id and secret.
async fn seed_admin_client(data_dir: &Path) -> (String, String) {
    let storage = SqliteStorage::connect(&format!(
        "sqlite://{}",
        data_dir.join("anvilid.db").display()
    ))
    .await
    .expect("connect");
    let system = storage
        .tenants()
        .get_by_slug(SYSTEM_TENANT_SLUG)
        .await
        .expect("tenant lookup")
        .expect("system tenant");
    let client_id = format!("adm-{}", &random_token()[..12]);
    let secret = random_token();
    storage
        .clients()
        .create(
            system.id,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: client_id.clone(),
                name: "system info test client".to_owned(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(SecretHash(secret_hash(&secret))),
                jwks: None,
                redirect_uris: Vec::new(),
                grant_types: vec![GrantType::ClientCredentials],
                scopes: vec!["admin:read".to_owned()],
                require_pkce: true,
                created_at: time::OffsetDateTime::now_utc(),
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: vec![],
                mfa_policy: None,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: ClientSource::Static,
                organization: OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: ClientKind::Application,
                headless_native: false,
                client_uri: None,
                initiate_login_uri: None,
            },
        )
        .await
        .expect("create the admin client");
    storage.close().await;
    (client_id, secret)
}

async fn assert_no_version(what: &str, resp: reqwest::Response) {
    for (name, value) in resp.headers() {
        assert!(
            !value.to_str().unwrap_or_default().contains(VERSION),
            "{what} discloses the version in header {name}"
        );
    }
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains(VERSION),
        "{what} discloses the version in its body"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn system_info_reports_the_binary_version_to_admins_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let mut server = spawn(dir.path(), port);
    wait_ready(&mut server, &http, &base, dir.path()).await;
    let info = format!("{base}/api/admin/v1/system/info");

    // Unauthenticated: 401, no version.
    let resp = http.get(&info).send().await.expect("info");
    assert_eq!(resp.status(), 401);
    assert_no_version("unauthenticated system/info", resp).await;

    // A system-tenant admin token: 200 with this binary's version.
    let (client_id, secret) = seed_admin_client(dir.path()).await;
    let resp = http
        .post(format!("{base}/t/system/token"))
        .basic_auth(&client_id, Some(&secret))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&scope=admin%3Aread")
        .send()
        .await
        .expect("token");
    assert_eq!(resp.status(), 200);
    let token: serde_json::Value = resp.json().await.expect("token JSON");
    let token = token["access_token"].as_str().expect("access token");
    let resp = http
        .get(&info)
        .bearer_auth(token)
        .send()
        .await
        .expect("info");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("info JSON");
    // No ANVILID_SMTP_URL in this environment: smtp_configured is false (07.1-06).
    assert_eq!(
        body,
        serde_json::json!({ "version": VERSION, "smtp_configured": false })
    );

    // Nothing public carries it.
    for path in [
        "/.well-known/openid-configuration",
        "/t/system/.well-known/openid-configuration",
        "/jwks",
        "/health/live",
        "/health/ready",
        "/healthz",
        "/readyz",
        "/ui/login",
        "/console/",
        "/api/admin/v1/openapi.json",
        "/does-not-exist",
        "/api/admin/v1/does-not-exist",
    ] {
        let resp = http.get(format!("{base}{path}")).send().await.expect(path);
        assert_no_version(path, resp).await;
    }
    let resp = http
        .post(format!("{base}/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("grant_type=nonsense")
        .send()
        .await
        .expect("token error");
    assert_no_version("/token error", resp).await;
}
