//! The binary runs the back-channel logout worker (OIDC-12) and logouts wake it: `anvilid serve`
//! on SQLite in development mode; the test seeds a client with a back-channel logout URI (a local
//! RP on 127.0.0.1), a user, a browser session and an authorization code through the storage
//! ports on the same database file, gets a real ID token from `/token`, and logs out through
//! `GET /logout?id_token_hint=…` with the session cookie. The RP must receive the logout token
//! well before the worker's 10 s poll interval, three times in a row (one coincidence with a
//! poll tick is possible, three are not plausible), which proves the in-process wake.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anvil_core::model::{
    ACR_PWD, AMR_PWD, ApplicationType, AuthorizationParams, ClientAuthMethod, ClientId, ClientType,
    ConsentMode, DEFAULT_TENANT_SLUG, GrantType, NewBrowserSession, NewClient, NewUser, SecretHash,
    SessionId, StandardClaims, Tenant, TokenFormat, UserId, UserStatus,
};
use anvil_core::ports::Storage;
use anvil_core::service::authorize::build_code;
use anvil_core::service::client::{new_client_id, new_client_secret};
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_storage_sqlite::SqliteStorage;
use anvil_web::cookies::CookiePolicy;
use secrecy::ExposeSecret as _;
use time::OffsetDateTime;

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const REDIRECT: &str = "https://rp.test/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// Well below the worker's 10 s poll interval.
const WAKE_DEADLINE: Duration = Duration::from_millis(2500);

struct Server(Child);

impl Drop for Server {
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

fn spawn(data_dir: &Path, db: &str, port: u16) -> Server {
    let mut cmd = Command::new(BIN);
    cmd.arg("serve")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--public-url")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--database-url")
        .arg(db)
        .arg("--breach-check")
        .arg("off")
        .current_dir(data_dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    Server(cmd.spawn().expect("spawn anvilid"))
}

/// A local RP: answers every request with 204 and reports each request body with its arrival
/// time.
fn rp() -> (u16, mpsc::Receiver<(Instant, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind RP");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if let Some(v) = lower.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; len];
            let _ = reader.read_exact(&mut body);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            let _ = tx.send((Instant::now(), String::from_utf8_lossy(&body).into_owned()));
        }
    });
    (port, rx)
}

async fn wait_healthy(base: &str, http: &reqwest::Client) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(r) = http.get(format!("{base}/healthz")).send().await
            && r.status() == 200
        {
            return;
        }
        assert!(Instant::now() < deadline, "anvilid did not become ready");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Seeds a session signed in to the client (code issued by `issuer`); returns the session cookie
/// value and the code.
async fn signed_in(
    storage: &dyn Storage,
    tenant: &Tenant,
    client: &anvil_core::model::Client,
    issuer: &str,
    n: usize,
) -> (String, String) {
    let now = OffsetDateTime::now_utc();
    let user = storage
        .users()
        .create(
            tenant.id,
            &NewUser {
                id: UserId::new_v7(),
                email: format!("user{n}@example.test"),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: now,
            },
            None,
            None,
            None,
        )
        .await
        .expect("user");
    let token = random_token();
    let new = NewBrowserSession {
        id: SessionId::new_v7(),
        user_id: user.id,
        token_hash: SecretHash(secret_hash(&token)),
        auth_time: now,
        acr: ACR_PWD.into(),
        amr: vec![AMR_PWD.into()],
        created_at: now,
        expires_at: now + time::Duration::hours(12),
        idle_expires_at: now + time::Duration::hours(1),
        ip: None,
        user_agent: None,
    };
    storage
        .sessions()
        .create(tenant.id, &new)
        .await
        .expect("session");
    let session = storage
        .sessions()
        .get_active(tenant.id, &new.token_hash, now)
        .await
        .expect("lookup")
        .expect("active");
    let params = AuthorizationParams {
        redirect_uri: REDIRECT.into(),
        scope: "openid".into(),
        state: None,
        nonce: None,
        code_challenge: Some(CHALLENGE.into()),
        prompt: vec![],
        max_age: None,
        login_hint: None,
        acr_values: vec![],
        ui_locales: None,
        claims: None,
        response_mode: Default::default(),
        resource: vec![],
        organization: None,
    };
    let (plain, code, family) = build_code(client, &params, &session, issuer, now);
    storage
        .grants()
        .create_code(tenant.id, &code, &family)
        .await
        .expect("code (records the RP session)");
    (token, plain.expose_secret().to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_wakes_the_worker_and_the_rp_gets_the_token_without_waiting_for_the_poll() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = format!("sqlite://{}", dir.path().join("anvil.db").display());
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let _server = spawn(dir.path(), &db, port);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    wait_healthy(&base, &http).await;

    let storage = SqliteStorage::connect(&db)
        .await
        .expect("open the server's db");
    let tenant = storage
        .tenants()
        .get_by_slug(DEFAULT_TENANT_SLUG)
        .await
        .expect("tenant lookup")
        .expect("installed");
    let (rp_port, deliveries) = rp();
    let (secret, hash) = new_client_secret();
    let client = storage
        .clients()
        .create(
            tenant.id,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: new_client_id(),
                name: "Back-channel RP".into(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(hash),
                jwks: None,
                redirect_uris: vec![REDIRECT.into()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".into()],
                require_pkce: true,
                created_at: OffsetDateTime::now_utc(),
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: Some(format!("http://127.0.0.1:{rp_port}/bc")),
                backchannel_logout_session_required: true,
                allowed_resources: vec![],
                mfa_policy: None,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                registration_source: anvil_core::model::ClientSource::Static,
                organization: anvil_core::model::OrgClientPolicy::Off,
            },
        )
        .await
        .expect("client");
    let cookie_name = CookiePolicy::new(false).session_name(&tenant);

    for n in 0..3 {
        let (session_token, code) = signed_in(&storage, &tenant, &client, &base, n).await;
        let resp = http
            .post(format!("{base}/token"))
            .basic_auth(&client.client_id, Some(secret.expose_secret()))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("grant_type", "authorization_code"),
                        ("code", code.as_str()),
                        ("redirect_uri", REDIRECT),
                        ("code_verifier", VERIFIER),
                    ])
                    .finish(),
            )
            .send()
            .await
            .expect("token request");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.expect("token json");
        let id_token = body["id_token"].as_str().expect("id_token").to_owned();

        let logout = http
            .get(format!(
                "{base}/logout?{}",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("id_token_hint", &id_token)
                    .finish()
            ))
            .header("cookie", format!("{cookie_name}={session_token}"))
            .send()
            .await
            .expect("logout");
        let logged_out = Instant::now();
        assert!(
            logout.status().is_success(),
            "logout status {}",
            logout.status()
        );
        let (at, body) = deliveries
            .recv_timeout(WAKE_DEADLINE)
            .unwrap_or_else(|_| panic!("logout {n}: no delivery within {WAKE_DEADLINE:?}"));
        assert!(at >= logged_out - Duration::from_millis(500));
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(pairs.len(), 1, "{pairs:?}");
        assert_eq!(pairs[0].0, "logout_token");
        assert_eq!(pairs[0].1.split('.').count(), 3, "a JWS");
    }
}
