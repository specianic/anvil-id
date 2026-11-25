//! Consent screen (OIDC-13) end to end over HTTP on the selected backend (`ANVILID_TEST_DB`):
//! when /authorize asks for consent, Allow (query and form_post), Deny (`access_denied` with
//! `state` and `iss`), remembered grants, a new scope asking again, `prompt=consent` and
//! `prompt=none`, `skip_first_party` clients, the CSRF/flow binding rejections, double
//! submission, expired flows, and the page's markup. Also the `id_token_hint` algorithms (the
//! hint is verified with every algorithm the tenant enables).

mod authz;
mod support;

use std::sync::Arc;

use anvil_core::model::{
    AuditAction, AuditQuery, Client, ClientUpdate, ConsentMode, FlowId, Tenant, TenantSettings,
    TenantUpdate, UserId,
};
use anvil_core::ports::Clock;
use anvil_core::service::key::KeyService;
use anvil_core::service::key_rotation::{KeyRotationService, RotationPolicy};
use anvil_jose::keys::Alg;
use authz::*;
use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse, csrf_from, location};
use time::OffsetDateTime;

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// A signed-in user and a confidential web client whose consent mode is `mode`.
struct Fixture {
    app: TestApp,
    tenant: Tenant,
    client: Client,
    user: UserId,
    /// `Cookie` value of the user's session.
    session: String,
    iss: String,
}

async fn fixture(mode: ConsentMode) -> Fixture {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let client = web_client(&app, &tenant).await;
    let client = app
        .storage()
        .clients()
        .update(
            tenant.id,
            &client.client_id,
            &ClientUpdate {
                consent_mode: Some(mode),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    assert_eq!(client.consent_mode, mode);
    let user = user(&app, &tenant, "alice@example.com").await;
    let session = session(&app, &tenant, user).await;
    let iss = app.issuer(None);
    Fixture {
        app,
        tenant,
        client,
        user,
        session,
        iss,
    }
}

impl Fixture {
    /// The session cookie plus the jar's cookies (the flow cookie set by the consent page).
    fn cookies(&self) -> String {
        let mut parts = vec![self.session.clone()];
        parts.extend(self.app.cookies().iter().map(|(k, v)| format!("{k}={v}")));
        parts.join("; ")
    }

    fn params<'a>(
        &'a self,
        scope: &'a str,
        extra: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut p: Vec<(&str, &str)> = pkce_params(&self.client.client_id)
            .into_iter()
            .map(|(k, v)| if k == "scope" { (k, scope) } else { (k, v) })
            .collect();
        p.extend_from_slice(extra);
        p
    }

    /// GET /authorize with the session.
    async fn authorize(&self, scope: &str, extra: &[(&str, &str)]) -> TestResponse {
        get(
            &self.app,
            &authorize_path("", &self.params(scope, extra)),
            Some(&self.cookies()),
        )
        .await
    }

    /// GET a path with the session and the jar's cookies.
    async fn get(&self, path: &str) -> TestResponse {
        get(&self.app, path, Some(&self.cookies())).await
    }

    /// A same-origin form POST with the session and the jar's cookies.
    async fn post(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        self.post_with(path, pairs, Some(&self.cookies()), "same-origin")
            .await
    }

    async fn post_with(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: Option<&str>,
        fetch_site: &str,
    ) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", fetch_site)
            .header(header::CONTENT_LENGTH, body.len());
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.app
            .send(req.body(Body::from(body)).expect("request"))
            .await
    }

    /// Asserts a 303 to the consent screen and returns its path.
    fn consent_path(&self, resp: &TestResponse) -> String {
        assert_eq!(resp.status, 303, "{}", resp.text());
        let loc = location(resp);
        let prefix = format!("{}/ui/consent?request=", self.iss);
        assert!(loc.starts_with(&prefix), "{loc}");
        to_path(&self.app, &loc)
    }

    /// Opens the consent screen: (page HTML, form action path, CSRF token).
    async fn open(&self, consent_path: &str) -> (String, String, String) {
        let resp = self.get(consent_path).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        let html = resp.html();
        let action = action_of(&self.app, &html, "consent-form");
        let csrf = csrf_from(&html);
        (html, action, csrf)
    }

    /// /authorize → consent screen → `decision`; returns the decision's response.
    async fn decide(&self, scope: &str, extra: &[(&str, &str)], decision: &str) -> TestResponse {
        let resp = self.authorize(scope, extra).await;
        let path = self.consent_path(&resp);
        let (_, action, csrf) = self.open(&path).await;
        self.post(&action, &[("csrf_token", &csrf), ("decision", decision)])
            .await
    }

    async fn granted_scopes(&self) -> Option<Vec<String>> {
        self.app
            .storage()
            .grants()
            .consent(self.tenant.id, self.user, &self.client.client_id)
            .await
            .expect("consent lookup")
            .map(|g| g.scopes)
    }

    async fn audit_actions(&self) -> Vec<(AuditAction, Option<String>)> {
        self.app
            .storage()
            .audit()
            .query(
                self.tenant.id,
                &AuditQuery {
                    limit: 100,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit query")
            .items
            .into_iter()
            .map(|e| (e.action, e.target))
            .collect()
    }
}

fn to_path(app: &TestApp, url: &str) -> String {
    let origin = format!(
        "{}://{}",
        app.config.public_url.scheme(),
        app.config.public_url.host_port()
    );
    url.strip_prefix(&origin).unwrap_or(url).to_owned()
}

/// The `action` of the form with `id`, as a path.
fn action_of(app: &TestApp, html: &str, form_id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{form_id}\""))
        .unwrap_or_else(|| panic!("form #{form_id} in {html}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    let decoded = html[a..b]
        .replace("&amp;", "&")
        .replace("&#x2f;", "/")
        .replace("&#x3d;", "=");
    to_path(app, &decoded)
}

fn flow_of(path: &str) -> FlowId {
    let id = path
        .split("flow=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .expect("flow parameter");
    FlowId(uuid::Uuid::parse_str(id).expect("flow id"))
}

fn assert_code(resp: &TestResponse, iss: &str) -> String {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(resp).starts_with(&format!("{RP}?")),
        "{}",
        location(resp)
    );
    assert_eq!(param(resp, "state").as_deref(), Some("st-1"));
    assert_eq!(param(resp, "iss").as_deref(), Some(iss));
    assert!(param(resp, "error").is_none(), "{}", location(resp));
    param(resp, "code").expect("code")
}

/// The hidden `[name, value]` inputs of the form_post page.
fn form_post_fields(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("<input type=\"hidden\" name=\"") {
        rest = &rest[i + "<input type=\"hidden\" name=\"".len()..];
        let name_end = rest.find('"').expect("name");
        let name = rest[..name_end].to_owned();
        let v = rest.find("value=\"").expect("value") + "value=\"".len();
        let v_end = rest[v..].find('"').expect("value end") + v;
        out.push((
            name,
            rest[v..v_end].replace("&#x2f;", "/").replace("&#x3d;", "="),
        ));
        rest = &rest[v_end..];
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Decision, Allow, remembered grants
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn first_authorization_asks_allow_issues_the_code_and_the_grant_is_remembered() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid profile", &[]).await;
    let path = f.consent_path(&resp);
    let (html, action, csrf) = f.open(&path).await;

    // The page names the client and lists the scopes in plain language.
    assert!(
        html.contains("<strong id=\"consent-client\">Test RP</strong>"),
        "{html}"
    );
    assert!(
        html.contains("data-scope=\"openid\">Sign you in</li>"),
        "{html}"
    );
    assert!(html.contains("data-scope=\"profile\""), "{html}");
    assert!(html.contains("<fieldset"), "{html}");
    assert!(html.contains("<legend>"), "{html}");
    assert!(html.contains("id=\"consent-allow\" name=\"decision\" value=\"allow\""));
    assert!(html.contains("id=\"consent-deny\" name=\"decision\" value=\"deny\""));
    assert!(
        !html.contains("<script"),
        "the consent page needs no JavaScript"
    );
    assert!(
        f.granted_scopes().await.is_none(),
        "nothing granted before Allow"
    );

    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &f.iss);
    assert_eq!(
        f.granted_scopes().await.expect("grant stored"),
        ["openid", "profile"]
    );
    assert!(
        f.audit_actions().await.contains(&(
            AuditAction::ConsentGranted,
            Some(f.client.client_id.clone())
        )),
        "consent_granted audited"
    );

    // Remembered: the same (or fewer) scopes go straight to the code.
    assert_code(&f.authorize("openid profile", &[]).await, &f.iss);
    assert_code(&f.authorize("openid", &[]).await, &f.iss);

    // A new scope asks again; Allow merges the scopes.
    let resp = f.decide("openid email", &[], "allow").await;
    assert_code(&resp, &f.iss);
    assert_eq!(
        f.granted_scopes().await.expect("grant"),
        ["email", "openid", "profile"]
    );
    assert_code(&f.authorize("openid profile email", &[]).await, &f.iss);
}

#[tokio::test]
async fn allow_with_form_post_delivers_the_code_in_the_form() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f
        .decide("openid", &[("response_mode", "form_post")], "allow")
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(html.contains("id=\"form-post\""), "{html}");
    let fields = form_post_fields(&html);
    let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["code", "state", "iss"], "{html}");
    assert_eq!(fields[1].1, "st-1");
    assert!(
        resp.header("content-security-policy")
            .is_some_and(|c| c.contains("form-action https://rp.example")),
        "{:?}",
        resp.header("content-security-policy")
    );
}

#[tokio::test]
async fn prompt_consent_forces_the_screen_even_with_a_grant() {
    let f = fixture(ConsentMode::Required).await;
    assert_code(&f.decide("openid", &[], "allow").await, &f.iss);
    assert_code(&f.authorize("openid", &[]).await, &f.iss);
    let resp = f.authorize("openid", &[("prompt", "consent")]).await;
    let path = f.consent_path(&resp);
    let (_, action, csrf) = f.open(&path).await;
    // Allow after prompt=consent issues the code (no second screen).
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &f.iss);
}

#[tokio::test]
async fn prompt_none_when_consent_is_needed_is_consent_required() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[("prompt", "none")]).await;
    assert_error_redirect(&resp, RP, "consent_required", &f.iss);
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));

    // Via form_post too.
    let resp = f
        .authorize(
            "openid",
            &[("prompt", "none"), ("response_mode", "form_post")],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let fields = form_post_fields(&resp.html());
    assert!(
        fields.contains(&("error".to_owned(), "consent_required".to_owned())),
        "{fields:?}"
    );

    // Once granted, prompt=none issues the code.
    assert_code(&f.decide("openid", &[], "allow").await, &f.iss);
    assert_code(&f.authorize("openid", &[("prompt", "none")]).await, &f.iss);
}

#[tokio::test]
async fn skip_first_party_clients_never_see_the_screen() {
    let f = fixture(ConsentMode::SkipFirstParty).await;
    assert_code(&f.authorize("openid profile email", &[]).await, &f.iss);
    assert_code(
        &f.authorize("openid", &[("prompt", "consent")]).await,
        &f.iss,
    );
    assert_code(&f.authorize("openid", &[("prompt", "none")]).await, &f.iss);
    assert!(f.granted_scopes().await.is_none());
}

// ---------------------------------------------------------------------------------------------
// Deny
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn deny_returns_access_denied_with_state_and_iss() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.decide("openid profile", &[], "deny").await;
    assert_error_redirect(&resp, RP, "access_denied", &f.iss);
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
    assert!(param(&resp, "code").is_none());
    assert!(f.granted_scopes().await.is_none(), "Deny stores nothing");

    // Via form_post.
    let resp = f
        .decide("openid", &[("response_mode", "form_post")], "deny")
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let fields = form_post_fields(&resp.html());
    assert_eq!(fields[0], ("error".to_owned(), "access_denied".to_owned()));
    assert!(fields.contains(&("state".to_owned(), "st-1".to_owned())));
    assert!(fields.contains(&("iss".to_owned(), f.iss.clone())));
}

// ---------------------------------------------------------------------------------------------
// Binding and single use
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn submissions_without_a_valid_binding_are_rejected() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (_, action, csrf) = f.open(&path).await;

    // No CSRF token.
    let resp = f.post(&action, &[("decision", "allow")]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // Wrong CSRF token.
    let resp = f
        .post(&action, &[("csrf_token", "forged"), ("decision", "allow")])
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // No flow cookie (session only).
    let resp = f
        .post_with(
            &action,
            &[("csrf_token", &csrf), ("decision", "allow")],
            Some(&f.session),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // Cross-site.
    let resp = f
        .post_with(
            &action,
            &[("csrf_token", &csrf), ("decision", "allow")],
            Some(&f.cookies()),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // Another user's session with this flow: forbidden.
    let bob = user(&f.app, &f.tenant, "bob@example.com").await;
    let bob_session = session(&f.app, &f.tenant, bob).await;
    let flow_cookie: Vec<String> = f
        .app
        .cookies()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let resp = f
        .post_with(
            &action,
            &[("csrf_token", &csrf), ("decision", "allow")],
            Some(&format!("{bob_session}; {}", flow_cookie.join("; "))),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // An unknown decision value is a bad request.
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "maybe")])
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(
        f.granted_scopes().await.is_none(),
        "no rejected submission granted"
    );

    // The real submission still works.
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &f.iss);
}

#[tokio::test]
async fn a_double_submission_issues_one_code() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (_, action, csrf) = f.open(&path).await;
    let pairs = [("csrf_token", csrf.as_str()), ("decision", "allow")];
    assert_code(&f.post(&action, &pairs).await, &f.iss);
    let again = f.post(&action, &pairs).await;
    assert_error_page(&again, "flow_expired");
    // Deny after Allow cannot turn into a second answer either.
    let deny = f
        .post(
            &action,
            &[("csrf_token", csrf.as_str()), ("decision", "deny")],
        )
        .await;
    assert_error_page(&deny, "flow_expired");
}

#[tokio::test]
async fn an_expired_flow_shows_the_screen_again() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (_, action, csrf) = f.open(&path).await;
    // The flow is gone (expired and purged) while the request is still valid.
    assert!(
        f.app
            .storage()
            .flows()
            .delete(f.tenant.id, flow_of(&action))
            .await
            .expect("delete flow")
    );
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert!(
        html.contains("data-message-key=\"consent.expired\""),
        "{html}"
    );
    assert!(f.granted_scopes().await.is_none());
    // The restarted screen works.
    let action = action_of(&f.app, &html, "consent-form");
    let csrf = csrf_from(&html);
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &f.iss);

    // Once the request itself expired, the page is the flow_expired error.
    let resp = f.authorize("openid email", &[]).await;
    let path = f.consent_path(&resp);
    f.app
        .clock()
        .advance(std::time::Duration::from_secs(16 * 60));
    let resp = f.get(&path).await;
    assert_error_page(&resp, "flow_expired");
}

#[tokio::test]
async fn the_consent_page_needs_a_session() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let resp = get(&f.app, &path, None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let request = path.split("request=").nth(1).expect("request id");
    assert_eq!(
        location(&resp),
        format!("{}/ui/login?request={request}", f.iss)
    );
    // A malformed request id is a bad request.
    let resp = f.get("/ui/consent?request=not-a-uuid").await;
    assert_eq!(resp.status, 400, "{}", resp.text());
}

#[tokio::test]
async fn login_then_consent_resumes_through_the_screen() {
    let f = fixture(ConsentMode::Required).await;
    // No session: /authorize stores the request and sends the user to sign in.
    let p = f.params("openid", &[]);
    let resp = get(&f.app, &authorize_path("", &p), None).await;
    let request = assert_login_redirect(&resp, &f.iss);
    // After sign-in, /authorize/continue sends the user to the consent screen.
    let resp = f
        .get(&format!("/authorize/continue?request={request}"))
        .await;
    let path = f.consent_path(&resp);
    assert!(path.ends_with(&request), "{path}");
    let (_, action, csrf) = f.open(&path).await;
    let resp = f
        .post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &f.iss);
}

// ---------------------------------------------------------------------------------------------
// id_token_hint algorithms
// ---------------------------------------------------------------------------------------------

struct Frozen(OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

#[tokio::test]
async fn an_es256_id_token_hint_is_accepted_when_the_tenant_enables_es256() {
    let f = fixture(ConsentMode::SkipFirstParty).await;
    let tenant = f
        .app
        .storage()
        .tenants()
        .update(
            f.tenant.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: vec!["RS256".into(), "ES256".into()],
                    ..f.tenant.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");
    let now = f.app.clock().now();
    KeyRotationService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: Arc::new(Frozen(now)),
        policy: RotationPolicy::default(),
    }
    .ensure_tenant(&tenant)
    .await
    .expect("ensure keys");
    let signer = KeyService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: Arc::new(Frozen(now)),
    }
    .signer_for(tenant.id, Alg::ES256)
    .await
    .expect("active ES256 key");
    let hint = |sub: String| {
        signer
            .sign_jwt(
                Some("JWT"),
                &serde_json::json!({
                    "iss": f.iss,
                    "sub": sub,
                    "aud": f.client.client_id,
                    "iat": now.unix_timestamp(),
                    "exp": now.unix_timestamp() + 300,
                }),
            )
            .expect("sign hint")
    };
    let mine = hint(f.user.to_string());
    let header = mine.split('.').next().expect("header");
    let header: serde_json::Value =
        serde_json::from_slice(&anvil_jose::encoding::b64url_decode(header).expect("b64url"))
            .expect("json");
    assert_eq!(header["alg"], "ES256");

    // The matching ES256 hint verifies (with prompt=none, an invalid hint is invalid_request).
    let resp = f
        .authorize("openid", &[("prompt", "none"), ("id_token_hint", &mine)])
        .await;
    assert_code(&resp, &f.iss);
    // An ES256 hint for another subject is login_required, not invalid_request.
    let other = hint(UserId::new_v7().to_string());
    let resp = f
        .authorize("openid", &[("prompt", "none"), ("id_token_hint", &other)])
        .await;
    assert_error_redirect(&resp, RP, "login_required", &f.iss);
}

#[tokio::test]
async fn an_es256_hint_is_rejected_when_the_tenant_does_not_enable_es256() {
    let f = fixture(ConsentMode::SkipFirstParty).await;
    // ES256 key exists (enabled, keys generated) ...
    let enabled = f
        .app
        .storage()
        .tenants()
        .update(
            f.tenant.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: vec!["RS256".into(), "ES256".into()],
                    ..f.tenant.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");
    let now = f.app.clock().now();
    KeyRotationService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: Arc::new(Frozen(now)),
        policy: RotationPolicy::default(),
    }
    .ensure_tenant(&enabled)
    .await
    .expect("ensure keys");
    let signer = KeyService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: Arc::new(Frozen(now)),
    }
    .signer_for(enabled.id, Alg::ES256)
    .await
    .expect("active ES256 key");
    let hint = signer
        .sign_jwt(
            Some("JWT"),
            &serde_json::json!({
                "iss": f.iss,
                "sub": f.user.to_string(),
                "aud": f.client.client_id,
                "iat": now.unix_timestamp(),
                "exp": now.unix_timestamp() + 300,
            }),
        )
        .expect("sign hint");
    // ... then the tenant goes back to RS256 only: ES256 hints are no longer accepted.
    f.app
        .storage()
        .tenants()
        .update(
            f.tenant.id,
            &TenantUpdate {
                settings: Some(TenantSettings {
                    signing_algs: vec!["RS256".into()],
                    ..f.tenant.settings.clone()
                }),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");
    let resp = f
        .authorize("openid", &[("prompt", "none"), ("id_token_hint", &hint)])
        .await;
    assert_error_redirect(&resp, RP, "invalid_request", &f.iss);
}
