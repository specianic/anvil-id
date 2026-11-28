//! Agent identification and incremental scope step-up on the consent screen (AGT-03, plan
//! 07-16), end to end over HTTP on the selected backend (`ANVILID_TEST_DB`): the "AI agent /
//! automated client" badge (`#consent-agent`), the provenance note (`#consent-provenance`) for
//! static, dynamic and CIMD clients, and step-up: with a stored grant only the new scopes and
//! resources are listed as new (`#consent-new-scopes`, `#consent-resources`), the already
//! allowed ones sit in the collapsed `#consent-granted-scopes` block, Allow stores the union and
//! Deny leaves the stored grant exactly as it was.

mod admin_support;
mod authz;
mod support;

use admin_support::{API, admin_token, assert_field_error, call};
use anvil_core::model::{
    ApplicationType, AuthRequestId, AuthorizationParams, Client, ClientAuthMethod, ClientId,
    ClientKind, ClientSource, ClientType, ClientUpdate, ConsentGrant, ConsentMode, GrantType,
    NewAuthorizationRequest, NewClient, OrgClientPolicy, Tenant, TokenFormat, UserId,
};
use anvil_core::ports::Clock;
use authz::*;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from, location};

const MCP: &str = "https://mcp.example/";
const OTHER: &str = "https://other.example/";
const CIMD_ID: &str = "https://agent.example.com:8443/oauth/client.json";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

struct Fixture {
    app: TestApp,
    tenant: Tenant,
    user: UserId,
    session: String,
    iss: String,
}

async fn fixture() -> Fixture {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let user = user(&app, &tenant, "alice@example.com").await;
    let session = session(&app, &tenant, user).await;
    let iss = app.issuer(None);
    Fixture {
        app,
        tenant,
        user,
        session,
        iss,
    }
}

impl Fixture {
    fn cookies(&self) -> String {
        let mut parts = vec![self.session.clone()];
        parts.extend(self.app.cookies().iter().map(|(k, v)| format!("{k}={v}")));
        parts.join("; ")
    }

    /// A consent-required client of `source` and `kind` with a self-asserted `name`, stored
    /// directly (CIMD clients through `upsert_cimd`, as the CIMD resolver materialises them).
    async fn client(
        &self,
        source: ClientSource,
        kind: ClientKind,
        client_id: &str,
        name: &str,
    ) -> Client {
        let now = self.app.clock().now();
        let new = NewClient {
            id: ClientId::new_v7(),
            client_id: client_id.into(),
            name: name.into(),
            client_type: ClientType::Public,
            application_type: ApplicationType::Web,
            auth_method: ClientAuthMethod::None,
            secret_hash: None,
            jwks: None,
            redirect_uris: vec![RP.into()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            require_pkce: true,
            created_at: now,
            token_format: TokenFormat::Jwt,
            consent_mode: ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![MCP.into(), OTHER.into()],
            mfa_policy: None,
            metadata_expires_at: (source == ClientSource::Cimd)
                .then(|| now + time::Duration::hours(1)),
            registration_access_token_hash: None,
            registration_source: source,
            organization: OrgClientPolicy::Off,
            require_pushed_authorization_requests: false,
            client_kind: kind,
            headless_native: false,
            client_uri: None,
            initiate_login_uri: None,
        };
        let clients = self.app.storage().clients();
        let client = match source {
            ClientSource::Cimd => clients
                .upsert_cimd(self.tenant.id, &new, now + time::Duration::hours(1), now)
                .await
                .expect("cimd client"),
            ClientSource::Static | ClientSource::Dynamic => {
                clients.create(self.tenant.id, &new).await.expect("client")
            }
        };
        assert_eq!(client.registration_source, source);
        assert_eq!(client.client_kind, kind);
        client
    }

    /// A stored authorization request of `client_id` for `scope` and `resources`.
    async fn request(&self, client_id: &str, scope: &str, resources: &[&str]) -> AuthRequestId {
        let now = self.app.clock().now();
        let id = AuthRequestId::new_v7();
        self.app
            .storage()
            .grants()
            .create_authorization_request(
                self.tenant.id,
                &NewAuthorizationRequest {
                    id,
                    client_id: client_id.into(),
                    params: AuthorizationParams {
                        redirect_uri: RP.into(),
                        scope: scope.into(),
                        state: Some("st-1".into()),
                        nonce: None,
                        code_challenge: Some(CHALLENGE.into()),
                        prompt: vec![],
                        max_age: None,
                        login_hint: None,
                        acr_values: vec![],
                        ui_locales: None,
                        claims: None,
                        response_mode: Default::default(),
                        resource: resources.iter().map(|r| (*r).to_owned()).collect(),
                        organization: None,
                    },
                    created_at: now,
                    expires_at: now + time::Duration::minutes(10),
                },
            )
            .await
            .expect("authorization request");
        id
    }

    /// The consent screen of a stored request: (HTML, form action path, CSRF token).
    async fn open_request(&self, request: AuthRequestId) -> (String, String, String) {
        self.open(&format!("/ui/consent?request={request}")).await
    }

    async fn open(&self, path: &str) -> (String, String, String) {
        let resp = get(&self.app, path, Some(&self.cookies())).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let html = resp.html();
        let action = action_of(&self.app, &html);
        let csrf = csrf_from(&html);
        (html, action, csrf)
    }

    /// GET /authorize for `client` with `scope` and `extra` parameters.
    async fn authorize(
        &self,
        client: &Client,
        scope: &str,
        extra: &[(&str, &str)],
    ) -> TestResponse {
        let mut p: Vec<(&str, &str)> = pkce_params(&client.client_id)
            .into_iter()
            .map(|(k, v)| if k == "scope" { (k, scope) } else { (k, v) })
            .collect();
        p.extend_from_slice(extra);
        get(&self.app, &authorize_path("", &p), Some(&self.cookies())).await
    }

    /// Asserts a 303 to the consent screen and returns its path.
    fn consent_path(&self, resp: &TestResponse) -> String {
        assert_eq!(resp.status, 303, "{}", resp.text());
        let loc = location(resp);
        let prefix = format!("{}/ui/consent?request=", self.iss);
        assert!(loc.starts_with(&prefix), "{loc}");
        to_path(&self.app, &loc)
    }

    async fn post(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::COOKIE, self.cookies())
            .body(Body::from(body))
            .expect("request");
        self.app.send(req).await
    }

    /// /authorize → consent screen → `decision`.
    async fn decide(
        &self,
        client: &Client,
        scope: &str,
        extra: &[(&str, &str)],
        decision: &str,
    ) -> TestResponse {
        let resp = self.authorize(client, scope, extra).await;
        let path = self.consent_path(&resp);
        let (_, action, csrf) = self.open(&path).await;
        self.post(&action, &[("csrf_token", &csrf), ("decision", decision)])
            .await
    }

    async fn grant(&self, client: &Client) -> Option<ConsentGrant> {
        self.app
            .storage()
            .grants()
            .consent(self.tenant.id, self.user, &client.client_id)
            .await
            .expect("consent lookup")
    }

    /// A static consent-required agent client (the step-up tests go through /authorize).
    async fn static_agent(&self) -> Client {
        let base = web_client(&self.app, &self.tenant).await;
        self.app
            .storage()
            .clients()
            .update(
                self.tenant.id,
                &base.client_id,
                &ClientUpdate {
                    consent_mode: Some(ConsentMode::Required),
                    client_kind: Some(ClientKind::Agent),
                    allowed_resources: Some(vec![MCP.into(), OTHER.into()]),
                    ..ClientUpdate::default()
                },
                self.app.clock().now(),
            )
            .await
            .expect("client update")
            .expect("client exists")
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

/// The `action` of `#consent-form`, as a path.
fn action_of(app: &TestApp, html: &str) -> String {
    let start = html
        .find("<form id=\"consent-form\"")
        .unwrap_or_else(|| panic!("consent form in {html}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    let decoded = html[a..b]
        .replace("&amp;", "&")
        .replace("&#x2f;", "/")
        .replace("&#x3d;", "=");
    to_path(app, &decoded)
}

/// The element with `id` (from its opening tag to the first `end` after it), if present.
fn element<'a>(html: &'a str, id: &str, end: &str) -> Option<&'a str> {
    let start = html.find(&format!("id=\"{id}\""))?;
    let len = html[start..].find(end).expect("element end");
    Some(&html[start..start + len])
}

/// The values of `attr="…"` inside `fragment`, in document order (HTML-unescaped for `/`).
fn attr_values(fragment: &str, attr: &str) -> Vec<String> {
    let marker = format!("{attr}=\"");
    let mut out = Vec::new();
    let mut rest = fragment;
    while let Some(i) = rest.find(&marker) {
        rest = &rest[i + marker.len()..];
        let end = rest.find('"').expect("quoted");
        out.push(rest[..end].replace("&#x2f;", "/"));
        rest = &rest[end..];
    }
    out
}

/// The scopes listed as new (`#consent-new-scopes`).
fn new_scopes(html: &str) -> Vec<String> {
    element(html, "consent-new-scopes", "</ul>")
        .map(|e| attr_values(e, "data-scope"))
        .unwrap_or_default()
}

/// The scopes listed as already allowed (`#consent-granted-scopes`).
fn granted_scopes(html: &str) -> Vec<String> {
    element(html, "consent-granted-scopes", "</details>")
        .map(|e| attr_values(e, "data-granted-scope"))
        .unwrap_or_default()
}

/// The resources listed as new (`#consent-resources`).
fn new_resources(html: &str) -> Vec<String> {
    element(html, "consent-resources", "</ul>")
        .map(|e| attr_values(e, "data-resource"))
        .unwrap_or_default()
}

/// The resources listed as already allowed (`#consent-granted-resources`).
fn granted_resources(html: &str) -> Vec<String> {
    element(html, "consent-granted-resources", "</ul>")
        .map(|e| attr_values(e, "data-granted-resource"))
        .unwrap_or_default()
}

/// The `data-provenance` value and the text of `#consent-provenance`.
fn provenance(html: &str) -> (String, String) {
    let e = element(html, "consent-provenance", "</p>").expect("provenance note");
    let value = attr_values(e, "data-provenance").remove(0);
    let text = e[e.find('>').expect("tag end") + 1..].to_owned();
    (value, text)
}

fn assert_code(resp: &TestResponse, iss: &str) {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(resp).starts_with(&format!("{RP}?")),
        "{}",
        location(resp)
    );
    assert_eq!(param(resp, "iss").as_deref(), Some(iss));
    assert!(param(resp, "error").is_none(), "{}", location(resp));
    assert!(param(resp, "code").is_some(), "{}", location(resp));
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|v| (*v).to_owned()).collect()
}

// ---------------------------------------------------------------------------------------------
// Agent identification and provenance
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn consent_shows_agent_badge_for_agent_clients() {
    let f = fixture().await;
    let agent = f
        .client(
            ClientSource::Static,
            ClientKind::Agent,
            "agent-1",
            "Research agent",
        )
        .await;
    let app = f
        .client(
            ClientSource::Static,
            ClientKind::Application,
            "app-1",
            "Mail app",
        )
        .await;

    let (html, _, _) = f
        .open_request(f.request(&agent.client_id, "openid", &[]).await)
        .await;
    assert!(
        html.contains(
            "id=\"consent-agent\" role=\"note\"><strong>AI agent / automated client</strong>"
        ),
        "{html}"
    );
    assert!(
        html.contains("<strong id=\"consent-client\">Research agent</strong>"),
        "{html}"
    );
    // The badge says what an agent is (U-L4).
    assert!(
        html.contains(
            "<span id=\"consent-agent-explain\">It acts on its own, for example as an AI \
             assistant, and can use this access while you are not there.</span>"
        ),
        "{html}"
    );

    let (html, _, _) = f
        .open_request(f.request(&app.client_id, "openid", &[]).await)
        .await;
    assert!(!html.contains("id=\"consent-agent\""), "{html}");

    // German catalog.
    let (html, _, _) = f
        .open(&format!(
            "/ui/consent?request={}&ui_locales=de",
            f.request(&agent.client_id, "openid", &[]).await
        ))
        .await;
    assert!(html.contains("KI-Agent / automatisierter Client"), "{html}");
}

#[tokio::test]
async fn consent_provenance_static_dynamic_cimd() {
    let f = fixture().await;
    let cases = [
        (
            ClientSource::Static,
            "static-1",
            "static",
            "Set up by the administrators of this sign-in service.",
        ),
        (
            ClientSource::Dynamic,
            "dynamic-1",
            "dynamic",
            "Registered itself through dynamic registration. Its details are not verified.",
        ),
        (
            ClientSource::Cimd,
            CIMD_ID,
            "cimd",
            "Identified by its metadata document at agent.example.com:8443. Its name is not verified.",
        ),
    ];
    for (source, client_id, value, text) in cases {
        for kind in [ClientKind::Agent, ClientKind::Application] {
            if kind == ClientKind::Application && source != ClientSource::Static {
                // One application suffices to show provenance is not agent-only.
                continue;
            }
            let client_id = if kind == ClientKind::Application {
                "static-app"
            } else {
                client_id
            };
            let c = f.client(source, kind, client_id, "Helper").await;
            let (html, _, _) = f
                .open_request(f.request(&c.client_id, "openid", &[MCP]).await)
                .await;
            assert_eq!(provenance(&html), (value.into(), text.into()), "{html}");
            // The requested resources stay listed for every provenance.
            assert_eq!(new_resources(&html), [MCP], "{html}");
        }
    }
}

#[tokio::test]
async fn consent_cimd_name_marked_unverified() {
    let f = fixture().await;
    let c = f
        .client(
            ClientSource::Cimd,
            ClientKind::Agent,
            CIMD_ID,
            "Trusted <Bank> Agent",
        )
        .await;
    let (html, _, _) = f
        .open_request(f.request(&c.client_id, "openid", &[]).await)
        .await;
    // Named by the verified host; the self-asserted name is escaped and marked unverified.
    assert!(
        html.contains("<strong id=\"consent-client\"><bdi>agent.example.com:8443</bdi></strong>"),
        "{html}"
    );
    assert!(
        html.contains("<bdi>Trusted &lt;Bank&gt; Agent</bdi> <em class=\"anvil-muted\" id=\"consent-cimd-unverified\">(name not verified)</em>"),
        "{html}"
    );
    assert!(html.contains("Its name is not verified."), "{html}");
    assert!(html.contains("id=\"consent-agent\""), "{html}");
    assert!(!html.contains("Trusted <Bank>"), "{html}");
}

// ---------------------------------------------------------------------------------------------
// Incremental step-up
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn step_up_shows_only_new_scopes() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    assert_code(
        &f.decide(&agent, "openid profile", &[], "allow").await,
        &f.iss,
    );

    let resp = f.authorize(&agent, "openid profile email", &[]).await;
    let (html, _, _) = f.open(&f.consent_path(&resp)).await;
    assert_eq!(new_scopes(&html), ["email"], "{html}");
    assert_eq!(granted_scopes(&html), ["openid", "profile"], "{html}");
    assert!(
        html.contains("<details class=\"anvil-disclosure\" id=\"consent-granted-scopes\">"),
        "granted scopes are collapsed while something is new: {html}"
    );
    assert!(html.contains("New permissions:"), "{html}");

    // First request: everything is new and there is no granted block.
    let other = f
        .client(
            ClientSource::Static,
            ClientKind::Agent,
            "agent-2",
            "Second agent",
        )
        .await;
    let (html, _, _) = f
        .open_request(f.request(&other.client_id, "openid profile", &[]).await)
        .await;
    assert_eq!(new_scopes(&html), ["openid", "profile"], "{html}");
    assert!(!html.contains("id=\"consent-granted-scopes\""), "{html}");

    // prompt=consent with nothing new: the already allowed block is open.
    let resp = f
        .authorize(&agent, "openid", &[("prompt", "consent")])
        .await;
    let (html, _, _) = f.open(&f.consent_path(&resp)).await;
    assert!(new_scopes(&html).is_empty(), "{html}");
    assert!(
        html.contains("id=\"consent-granted-scopes\" open>"),
        "{html}"
    );
}

#[tokio::test]
async fn step_up_shows_only_new_resources() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    assert_code(
        &f.decide(&agent, "openid", &[("resource", MCP)], "allow")
            .await,
        &f.iss,
    );
    let resp = f
        .authorize(&agent, "openid", &[("resource", MCP), ("resource", OTHER)])
        .await;
    let (html, _, _) = f.open(&f.consent_path(&resp)).await;
    assert_eq!(new_resources(&html), [OTHER], "{html}");
    assert_eq!(granted_resources(&html), [MCP], "{html}");
    assert!(new_scopes(&html).is_empty(), "{html}");
    assert_eq!(granted_scopes(&html), ["openid"], "{html}");
}

#[tokio::test]
async fn step_up_allow_stores_union() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    assert_code(
        &f.decide(&agent, "openid profile", &[("resource", MCP)], "allow")
            .await,
        &f.iss,
    );
    assert_code(
        &f.decide(&agent, "openid email", &[("resource", OTHER)], "allow")
            .await,
        &f.iss,
    );
    let g = f.grant(&agent).await.expect("grant");
    assert_eq!(g.scopes, strings(&["email", "openid", "profile"]));
    assert_eq!(g.resources, strings(&[MCP, OTHER]));
    // Every combination is now covered.
    assert_code(
        &f.authorize(
            &agent,
            "openid profile email",
            &[("resource", MCP), ("resource", OTHER)],
        )
        .await,
        &f.iss,
    );
}

#[tokio::test]
async fn step_up_deny_keeps_existing_grant() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    assert_code(
        &f.decide(&agent, "openid profile", &[("resource", MCP)], "allow")
            .await,
        &f.iss,
    );
    let before = f.grant(&agent).await.expect("grant");

    let resp = f
        .decide(
            &agent,
            "openid profile email",
            &[("resource", OTHER)],
            "deny",
        )
        .await;
    assert_error_redirect(&resp, RP, "access_denied", &f.iss);

    // Neither revoked nor shrunk nor extended: the stored grant is identical.
    let after = f.grant(&agent).await.expect("grant kept");
    assert_eq!(after, before);
    // And it still covers what it covered.
    assert_code(
        &f.authorize(&agent, "openid profile", &[("resource", MCP)])
            .await,
        &f.iss,
    );
}

#[tokio::test]
async fn step_up_prompt_none_new_scope_is_consent_required() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    assert_code(&f.decide(&agent, "openid", &[], "allow").await, &f.iss);
    let resp = f
        .authorize(&agent, "openid email", &[("prompt", "none")])
        .await;
    assert_error_redirect(&resp, RP, "consent_required", &f.iss);
    let resp = f
        .authorize(&agent, "openid", &[("resource", MCP), ("prompt", "none")])
        .await;
    assert_error_redirect(&resp, RP, "consent_required", &f.iss);
    // The grant is unchanged by the refused requests.
    assert_eq!(
        f.grant(&agent).await.expect("grant").scopes,
        strings(&["openid"])
    );
}

#[tokio::test]
async fn agent_client_always_sees_consent() {
    let f = fixture().await;
    let agent = f.static_agent().await;
    // No grant: the screen, with the badge.
    let resp = f.authorize(&agent, "openid profile", &[]).await;
    let (html, action, csrf) = f.open(&f.consent_path(&resp)).await;
    assert!(html.contains("id=\"consent-agent\""), "{html}");
    assert_code(
        &f.post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
            .await,
        &f.iss,
    );
    // A full grant and nothing new: the normal rule (no screen), and prompt=consent asks.
    assert_code(&f.authorize(&agent, "openid profile", &[]).await, &f.iss);
    f.consent_path(
        &f.authorize(&agent, "openid", &[("prompt", "consent")])
            .await,
    );

    // An agent can never be skip_first_party: the management API (like every client write
    // path, through validate_client_policy from 07-12) refuses it, and the stored agent stays
    // consent-required.
    let token = admin_token(&f.app, "admin:read admin:write").await;
    let resp = call(
        &f.app,
        Method::PATCH,
        &format!("{API}/tenants/default/clients/{}", agent.client_id),
        Some(&token),
        Some(json!({"consent_mode": "skip_first_party"})),
    )
    .await;
    assert_field_error(&resp, "consent_mode");
    let stored = f
        .app
        .storage()
        .clients()
        .get(f.tenant.id, &agent.client_id)
        .await
        .expect("client lookup")
        .expect("client");
    assert_eq!(stored.client_kind, ClientKind::Agent);
    assert_eq!(stored.consent_mode, ConsentMode::Required);
}
