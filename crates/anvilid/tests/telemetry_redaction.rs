//! OPS-08: no personal data, secrets or client IPs in telemetry.
//!
//! One real `anvilid serve` process (SQLite, development-mode loopback public URL) is driven
//! through the 0.4 flows with known sentinel values, and every telemetry channel the operator
//! receives is searched for them:
//!
//! - the operational log on stderr (JSON, our crates at `debug`),
//! - the spans exported over OTLP/HTTP to a local collector (raw protobuf bytes; strings are
//!   length-prefixed UTF-8, so a sentinel would appear verbatim),
//! - the Prometheus text from `/metrics` (on the main port).
//!
//! The audit stream on stdout keeps the client IP by design (ARCHITECTURE: audit records carry
//! the request context); it is checked for every other sentinel and must contain the IP, which
//! proves the trusted-proxy header reached the server and the IP checks are not vacuous.
//!
//! Flows: setup (admin email and password), admin API token, webhook endpoint create (secret
//! returned once) and a delivery to a loopback sink, user create, a failed and a successful
//! form login reached through `/authorize?login_hint=…`, consent, code exchange, refresh,
//! userinfo, dynamic client registration, and a CIMD fetch through `/authorize`. Every request
//! carries `X-Forwarded-For: 203.0.113.77` from a trusted proxy (127.0.0.1).

use std::collections::BTreeMap;
use std::fs::File;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anvil_jose::encoding::{b64url, sha256};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");

const CLIENT_IP: &str = "203.0.113.77";
const USER_EMAIL: &str = "sentinel-user@example.test";
const USER_PASSWORD: &str = "Sentinel-Pass-7f3a9c2e1b";
const WRONG_PASSWORD: &str = "Sentinel-Wrong-5d81e0aa";
const ADMIN_EMAIL: &str = "sentinel-admin@example.test";
const ADMIN_PASSWORD: &str = "Sentinel-Admin-Pass-c4e2b7";
const STATE: &str = "sentinelstate4b1c";
const CIMD_STATE: &str = "sentinelcimdstate9e2f";
const NONCE: &str = "sentinelnonce6d0a";
const CODE_VERIFIER: &str = "sentinel-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// The server process; killed on drop if a test step panics.
struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// SIGTERM, then wait (bounded) for the exit status: the OTLP batch is flushed at shutdown.
    fn terminate(&mut self) -> ExitStatus {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "anvilid did not exit after SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A tiny cookie jar, a fixed `X-Forwarded-For` and no automatic redirects.
struct Browser {
    http: reqwest::Client,
    base: String,
    cookies: BTreeMap<String, String>,
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_else(|| panic!("no Location ({}): {}", self.status, self.body))
            .to_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}, {}): {}", self.status, self.body))
    }
}

impl Browser {
    fn new(base: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(CLIENT_IP));
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .default_headers(headers)
                .timeout(Duration::from_secs(20))
                .build()
                .expect("client"),
            base: base.to_owned(),
            cookies: BTreeMap::new(),
        }
    }

    fn url(&self, target: &str) -> String {
        if target.starts_with("http://") || target.starts_with("https://") {
            target.to_owned()
        } else {
            format!("{}{target}", self.base)
        }
    }

    async fn send(&mut self, req: reqwest::RequestBuilder) -> Resp {
        let req = if self.cookies.is_empty() {
            req
        } else {
            let cookie = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            req.header("cookie", cookie)
        };
        let resp = req
            .send()
            .await
            .unwrap_or_else(|e| panic!("request: {e:?}"));
        for value in resp.headers().get_all("set-cookie") {
            let raw = value.to_str().expect("ascii cookie");
            let pair = raw.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                let expired = value.is_empty() || raw.to_ascii_lowercase().contains("max-age=0");
                if expired {
                    self.cookies.remove(name.trim());
                } else {
                    self.cookies
                        .insert(name.trim().to_owned(), value.to_owned());
                }
            }
        }
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn get(&mut self, target: &str) -> Resp {
        let req = self.http.get(self.url(target));
        self.send(req).await
    }

    async fn post_form(&mut self, target: &str, fields: &[(String, String)]) -> Resp {
        let req = self
            .http
            .post(self.url(target))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encode(fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))));
        self.send(req).await
    }

    async fn json(&mut self, method: Method, target: &str, bearer: &str, body: Value) -> Resp {
        let req = self
            .http
            .request(method, self.url(target))
            .bearer_auth(bearer)
            .json(&body);
        self.send(req).await
    }

    async fn token(
        &mut self,
        target: &str,
        id: &str,
        secret: &str,
        fields: &[(&str, &str)],
    ) -> Resp {
        let req = self
            .http
            .post(self.url(target))
            .basic_auth(id, Some(secret))
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encode(fields.iter().copied()));
        self.send(req).await
    }
}

/// An `application/x-www-form-urlencoded` body.
fn encode<'a>(fields: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in fields {
        out.append_pair(k, v);
    }
    out.finish()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';') else { break };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "quot" => Some('"'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse::<u32>))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The value of attribute `name` in one tag's text.
fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(unescape(&tag[start..end]))
}

/// The action and hidden inputs of the form with `id` in `html`.
fn form(html: &str, id: &str) -> (String, Vec<(String, String)>) {
    let marker = format!("<form id=\"{id}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no form #{id} in: {html}"));
    let end = html[start..]
        .find("</form>")
        .map_or(html.len(), |e| e + start);
    let body = &html[start..end];
    let open = &body[..body.find('>').expect("form tag")];
    let action = attr(open, "action").expect("form action");
    let mut hidden = Vec::new();
    for chunk in body.split("<input").skip(1) {
        let tag = &chunk[..chunk.find('>').unwrap_or(chunk.len())];
        if attr(tag, "type").as_deref() == Some("hidden")
            && let Some(name) = attr(tag, "name")
        {
            hidden.push((name, attr(tag, "value").unwrap_or_default()));
        }
    }
    (action, hidden)
}

/// The text content of the element with `id`.
fn text_of(html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\">");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no #{id} in: {html}"))
        + marker.len();
    let end = html[start..].find('<').expect("closing tag") + start;
    unescape(html[start..end].trim())
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let parsed = url::Url::parse(url).expect("absolute url");
    parsed
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn authorize_path(client_id: &str, redirect_uri: &str, state: &str, scope: &str) -> String {
    let challenge = b64url(&sha256(CODE_VERIFIER.as_bytes()));
    let mut url = url::Url::parse("http://x/authorize").expect("url");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("nonce", NONCE)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("login_hint", USER_EMAIL);
    format!("/authorize?{}", url.query().expect("query"))
}

/// Follows redirects until a page (200) or a redirect to `stop_prefix`.
async fn follow(b: &mut Browser, mut resp: Resp, stop_prefix: &str) -> (Resp, Option<String>) {
    for _ in 0..10 {
        if !resp.status.is_redirection() {
            return (resp, None);
        }
        let next = resp.location();
        if next.starts_with(stop_prefix) {
            return (resp, Some(next));
        }
        resp = b.get(&next).await;
    }
    panic!("too many redirects");
}

/// Waits for the one-time setup URL in the log.
fn setup_url(log: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = read(log);
        if let Some(i) = text.find("Setup URL: ") {
            let rest = &text[i + "Setup URL: ".len()..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\\')
                .unwrap_or(rest.len());
            return rest[..end].to_owned();
        }
        assert!(Instant::now() < deadline, "no setup URL logged: {text}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn wait_ready(b: &mut Browser, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(r) = b.http.get(b.url("/health/ready")).send().await
            && r.status() == StatusCode::OK
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "anvilid not ready: {}",
            read(log)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn telemetry_carries_no_personal_data_secrets_or_client_ips() {
    // Local collaborators: OTLP collector, webhook sink, CIMD document server.
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/traces"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&collector)
        .await;
    let sink = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&sink)
        .await;
    let docs = MockServer::start().await;
    let rp = "http://127.0.0.1:9/cb";
    let cimd_id = format!("{}/client.json", docs.uri());
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(
                    json!({
                        "client_id": cimd_id,
                        "client_name": "Sentinel Agent",
                        "redirect_uris": [rp],
                        "grant_types": ["authorization_code"],
                        "response_types": ["code"],
                        "token_endpoint_auth_method": "none",
                        "scope": "openid"
                    })
                    .to_string(),
                ),
        )
        .mount(&docs)
        .await;

    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let err_log = dir.path().join("stderr.log");
    let out_log = dir.path().join("stdout.log");
    let data = dir.path().join("data");
    std::fs::create_dir(&data).expect("data dir");

    let mut cmd = Command::new(BIN);
    cmd.arg("serve")
        .current_dir(dir.path())
        .env_clear()
        .env("ANVILID_LISTEN", format!("127.0.0.1:{port}"))
        .env("ANVILID_PUBLIC_URL", &base)
        .env("ANVILID_DATA_DIR", &data)
        .env("ANVILID_BREACH_CHECK", "off")
        .env("ANVILID_LOG_FORMAT", "json")
        // Our crates at debug: an emitting site below the default level must not leak either.
        .env(
            "RUST_LOG",
            "info,anvilid=debug,anvil_web=debug,anvil_core=debug,anvil_cache=debug,\
             anvil_jose=debug,anvil_mail=debug,anvil_storage_sqlite=debug",
        )
        .env("ANVILID_TRUSTED_PROXIES", "127.0.0.1/32")
        .env("ANVILID_METRICS_ON_MAIN_PORT", "true")
        .env("ANVILID_OTEL_ENDPOINT", collector.uri())
        // Functional flow, not a limiter test (several auth requests from one IP).
        .env("ANVILID_RATE_LIMIT_ENABLED", "false")
        .stdin(Stdio::null())
        .stdout(File::create(&out_log).expect("stdout log"))
        .stderr(File::create(&err_log).expect("stderr log"));
    if let Some(p) = std::env::var_os("PATH") {
        cmd.env("PATH", p);
    }
    let mut server = Server {
        child: cmd.spawn().expect("spawn anvilid"),
    };

    let mut b = Browser::new(&base);
    let setup = setup_url(&err_log);
    wait_ready(&mut b, &err_log).await;

    // Sentinels collected from responses (secrets the server generated).
    let mut secrets: Vec<(String, String)> = Vec::new();

    // --- Setup: admin email and password, management credential.
    let setup_query = setup.split_once('?').expect("setup query").1;
    let page = b.get(&format!("/setup?{setup_query}")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let (action, mut fields) = form(&page.body, "setup");
    fields.push(("email".into(), ADMIN_EMAIL.into()));
    fields.push(("password".into(), ADMIN_PASSWORD.into()));
    let done = b.post_form(&action, &fields).await;
    assert_eq!(done.status, 200, "{}", done.body);
    let mgmt_id = text_of(&done.body, "mgmt-client-id");
    let mgmt_secret = text_of(&done.body, "mgmt-client-secret");
    secrets.push(("management client secret".into(), mgmt_secret.clone()));
    b.cookies.clear();

    let resp = b
        .token(
            "/t/system/token",
            &mgmt_id,
            &mgmt_secret,
            &[
                ("grant_type", "client_credentials"),
                ("scope", "admin:read admin:write"),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let admin = resp.json()["access_token"]
        .as_str()
        .expect("admin token")
        .to_owned();
    secrets.push(("admin access token".into(), admin.clone()));
    let api = "/api/admin/v1/tenants/default";

    // --- Webhook endpoint (secret shown once) on the loopback sink.
    let resp = b
        .json(
            Method::POST,
            &format!("{api}/webhooks"),
            &admin,
            json!({"name": "sentinel-sink", "url": format!("{}/hook", sink.uri()),
                   "events": ["user.created"]}),
        )
        .await;
    assert_eq!(resp.status, 201, "{}", resp.body);
    let webhook_secret = resp.json()["secret"]
        .as_str()
        .expect("webhook secret")
        .to_owned();
    secrets.push(("webhook secret".into(), webhook_secret));

    // --- User (triggers a user.created delivery) and a confidential web client.
    let resp = b
        .json(
            Method::POST,
            &format!("{api}/users"),
            &admin,
            json!({"email": USER_EMAIL, "password": USER_PASSWORD, "email_verified": true}),
        )
        .await;
    assert_eq!(resp.status, 201, "{}", resp.body);

    let resp = b
        .json(
            Method::POST,
            &format!("{api}/clients"),
            &admin,
            json!({
                "name": "sentinel rp",
                "client_type": "confidential",
                "auth_method": "client_secret_basic",
                "redirect_uris": [rp],
                "grant_types": ["authorization_code", "refresh_token"],
                "scopes": ["openid", "email", "offline_access"]
            }),
        )
        .await;
    assert_eq!(resp.status, 201, "{}", resp.body);
    let client = resp.json();
    let client_id = client["client_id"].as_str().expect("client id").to_owned();
    let client_secret = client["client_secret"]
        .as_str()
        .expect("client secret")
        .to_owned();
    secrets.push(("client secret".into(), client_secret.clone()));

    // --- /authorize with login_hint -> login page; a wrong password, then the right one.
    let start = b
        .get(&authorize_path(
            &client_id,
            rp,
            STATE,
            "openid email offline_access",
        ))
        .await;
    let (page, done) = follow(&mut b, start, rp).await;
    assert!(done.is_none(), "expected the login page");
    assert_eq!(page.status, 200, "{}", page.body);
    let (action, hidden) = form(&page.body, "login");
    let mut wrong = hidden.clone();
    wrong.push(("identifier".into(), USER_EMAIL.into()));
    wrong.push(("password".into(), WRONG_PASSWORD.into()));
    let resp = b.post_form(&action, &wrong).await;
    // Post/Redirect/Get (rc.4): the failed post redirects to the sign-in page, which shows the
    // error once.
    assert_eq!(resp.status, 303, "wrong password: {}", resp.body);
    let (resp, done) = follow(&mut b, resp, rp).await;
    assert!(done.is_none(), "a wrong password stays on the sign-in page");
    let (action, mut fields) = form(&resp.body, "login");
    fields.push(("identifier".into(), USER_EMAIL.into()));
    fields.push(("password".into(), USER_PASSWORD.into()));
    let resp = b.post_form(&action, &fields).await;
    assert_eq!(resp.status, 303, "login: {}", resp.body);
    let (page, mut done) = follow(&mut b, resp, rp).await;
    if done.is_none() {
        // Consent page.
        let (action, mut fields) = form(&page.body, "consent-form");
        fields.push(("decision".into(), "allow".into()));
        let resp = b.post_form(&action, &fields).await;
        done = follow(&mut b, resp, rp).await.1;
    }
    let callback = done.expect("redirect to the client");
    assert_eq!(query_param(&callback, "state").as_deref(), Some(STATE));
    let code = query_param(&callback, "code").expect("authorization code");
    secrets.push(("authorization code".into(), code.clone()));

    // --- Code exchange, refresh, userinfo.
    let resp = b
        .token(
            "/token",
            &client_id,
            &client_secret,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", rp),
                ("code_verifier", CODE_VERIFIER),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "code exchange: {}", resp.body);
    let tokens = resp.json();
    let access = tokens["access_token"].as_str().expect("access").to_owned();
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh")
        .to_owned();
    secrets.push(("access token".into(), access.clone()));
    secrets.push(("refresh token".into(), refresh.clone()));
    secrets.push((
        "id token".into(),
        tokens["id_token"].as_str().expect("id token").to_owned(),
    ));

    let resp = b
        .token(
            "/token",
            &client_id,
            &client_secret,
            &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
        )
        .await;
    assert_eq!(resp.status, 200, "refresh: {}", resp.body);
    let refreshed = resp.json();
    secrets.push((
        "refreshed access token".into(),
        refreshed["access_token"]
            .as_str()
            .expect("access")
            .to_owned(),
    ));
    secrets.push((
        "rotated refresh token".into(),
        refreshed["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_owned(),
    ));

    let req = b.http.get(b.url("/userinfo")).bearer_auth(&access);
    let resp = b.send(req).await;
    assert_eq!(resp.status, 200, "userinfo: {}", resp.body);

    // --- Dynamic client registration (open policy) and CIMD (loopback document host).
    let resp = b
        .json(
            Method::PATCH,
            api,
            &admin,
            json!({"settings": {
                "dcr": {"policy": "open"},
                "cimd": {"policy": "allow_listed", "allowed_hosts": ["127.0.0.1"]}
            }}),
        )
        .await;
    assert_eq!(resp.status, 200, "tenant settings: {}", resp.body);
    let req = b
        .http
        .post(b.url("/register"))
        .json(&json!({"redirect_uris": ["https://rp.example/cb"], "client_name": "Sentinel DCR"}));
    let resp = b.send(req).await;
    assert_eq!(resp.status, 201, "registration: {}", resp.body);
    let registered = resp.json();
    for key in ["client_secret", "registration_access_token"] {
        if let Some(v) = registered[key].as_str() {
            secrets.push((format!("registration {key}"), v.to_owned()));
        }
    }

    b.cookies.clear();
    let start = b
        .get(&authorize_path(&cimd_id, rp, CIMD_STATE, "openid"))
        .await;
    let (page, _) = follow(&mut b, start, rp).await;
    assert_eq!(page.status, 200, "CIMD authorize: {}", page.body);
    assert!(
        page.body.contains("<form id=\"login\""),
        "CIMD client resolved to the login page: {}",
        page.body
    );
    let fetched = docs.received_requests().await.expect("recording on");
    assert!(!fetched.is_empty(), "the CIMD document was fetched");

    // --- The webhook delivery reaches the sink.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let got = sink.received_requests().await.expect("recording on");
        if !got.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no webhook delivery: {}",
            read(&err_log)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // --- Metrics, then shutdown (flushes the span batch).
    let metrics = b.get("/metrics").await;
    assert_eq!(metrics.status, 200);
    let metrics = metrics.body;
    let status = server.terminate();
    let stderr = read(&err_log);
    let stdout = read(&out_log);
    assert!(status.success(), "exit {status}: {stderr}");

    let traces: Vec<u8> = collector
        .received_requests()
        .await
        .expect("recording on")
        .iter()
        .filter(|r| r.url.path() == "/v1/traces")
        .flat_map(|r| r.body.clone())
        .collect();

    // Non-vacuity: each channel carries what it should.
    let has = |hay: &[u8], needle: &str| hay.windows(needle.len()).any(|w| w == needle.as_bytes());
    assert!(has(&traces, "http.request"), "no request spans exported");
    assert!(has(&traces, "/token"), "no /token span exported");
    assert!(
        stderr.contains("anvil_web::access"),
        "no access log lines: {stderr}"
    );
    assert!(
        metrics.contains("anvil_http_requests_total")
            && metrics.contains("anvil_tokens_issued_total"),
        "{metrics}"
    );
    assert!(
        stdout.contains(CLIENT_IP),
        "audit records the client IP from the trusted proxy header: {stdout}"
    );

    let mut personal: Vec<(String, String)> = vec![
        ("user email".into(), USER_EMAIL.into()),
        (
            "user email (urlencoded)".into(),
            USER_EMAIL.replace('@', "%40"),
        ),
        ("user password".into(), USER_PASSWORD.into()),
        ("wrong password".into(), WRONG_PASSWORD.into()),
        ("admin email".into(), ADMIN_EMAIL.into()),
        ("admin password".into(), ADMIN_PASSWORD.into()),
        ("state".into(), STATE.into()),
        ("CIMD authorize state".into(), CIMD_STATE.into()),
        ("nonce".into(), NONCE.into()),
        ("PKCE verifier".into(), CODE_VERIFIER.into()),
        ("login_hint parameter".into(), "login_hint=".into()),
    ];
    personal.append(&mut secrets);

    let mut leaks = Vec::new();
    for (what, value) in &personal {
        if stderr.contains(value.as_str()) {
            leaks.push(format!("{what} in the log"));
        }
        if has(&traces, value) {
            leaks.push(format!("{what} in an exported span"));
        }
        if metrics.contains(value.as_str()) {
            leaks.push(format!("{what} in /metrics"));
        }
        if stdout.contains(value.as_str()) {
            leaks.push(format!("{what} in the audit stream"));
        }
    }
    if stderr.contains(CLIENT_IP) {
        leaks.push("client IP in the log".into());
    }
    if has(&traces, CLIENT_IP) {
        leaks.push("client IP in an exported span".into());
    }
    if metrics.contains(CLIENT_IP) {
        leaks.push("client IP in /metrics".into());
    }
    assert!(
        leaks.is_empty(),
        "telemetry leaks: {leaks:#?}\n--- stderr ---\n{stderr}\n--- stdout ---\n{stdout}"
    );
}
