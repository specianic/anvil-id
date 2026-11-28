//! Consent screen (OIDC-13) end to end over HTTP on the selected backend (`ANVILID_TEST_DB`):
//! when /authorize asks for consent, Allow (query and form_post), Deny (`access_denied` with
//! `state` and `iss`), remembered grants, a new scope asking again, `prompt=consent` and
//! `prompt=none`, `skip_first_party` clients, the CSRF/flow binding rejections, double
//! submission, expired flows, and the page's markup. Also the `id_token_hint` algorithms (the
//! hint is verified with every algorithm the tenant enables), remembered consent covering RFC
//! 8707 resources (plan 05-13), and the screen for CIMD clients (client_id host, unverified
//! name, no remote logo). The signed-in account and "Use another account" (plan 07.1-14):
//! the switch is bound to the consent flow, and the next user is asked for their own consent.

mod authz;
mod support;
mod ui_helpers;

use std::sync::Arc;

use anvil_core::model::{
    ApplicationType, AuditAction, AuditQuery, AuthRequestId, AuthorizationParams, Client,
    ClientAuthMethod, ClientId, ClientSource, ClientType, ClientUpdate, ConsentId, ConsentMode,
    FlowId, GrantType, NewAuthorizationRequest, NewClient, NewConsent, NewTokenFamily, Tenant,
    TenantSettings, TenantUpdate, TokenFamilyId, UserId,
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
// Signed-in account and "Use another account" (07.1-14, U-M15)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn consent_page_shows_the_account_and_use_another_account() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (html, action, _) = f.open(&path).await;
    assert!(
        html.contains("<bdi id=\"consent-account-email\">alice@example.com</bdi>"),
        "{html}"
    );
    assert!(
        html.contains("id=\"consent-other\" name=\"choice\" value=\"other\""),
        "{html}"
    );
    // The switch form posts to the same bound action as the decision form.
    assert_eq!(action_of(&f.app, &html, "consent-switch-form"), action);
}

#[tokio::test]
async fn consent_switch_account_requires_binding() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (_, action, csrf) = f.open(&path).await;
    let other = [("csrf_token", csrf.as_str()), ("choice", "other")];

    // No CSRF token, a forged one, no flow cookie, cross-site, another user's session.
    let resp = f.post(&action, &[("choice", "other")]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post(&action, &[("csrf_token", "forged"), ("choice", "other")])
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post_with(&action, &other, Some(&f.session), "same-origin")
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post_with(&action, &other, Some(&f.cookies()), "cross-site")
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
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
            &other,
            Some(&format!("{bob_session}; {}", flow_cookie.join("; "))),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // A switch and a decision at once is a bad request.
    let resp = f
        .post(
            &action,
            &[
                ("csrf_token", csrf.as_str()),
                ("choice", "other"),
                ("decision", "allow"),
            ],
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());

    // Nothing changed: the session is active, nothing granted, the page still answers.
    let sessions = f
        .app
        .storage()
        .sessions()
        .list_for_user(f.tenant.id, f.user, f.app.clock().now())
        .await
        .expect("sessions");
    assert_eq!(sessions.len(), 1, "Alice's session is untouched");
    assert!(sessions[0].revoked_at.is_none());
    assert!(f.granted_scopes().await.is_none());

    // The bound switch goes to the login page for the request and uses the page up.
    let resp = f.post(&action, &other).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let request = path.split("request=").nth(1).expect("request id");
    assert_eq!(
        location(&resp),
        format!("{}/ui/login?request={request}", f.iss)
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let again = f
        .post(
            &action,
            &[("csrf_token", csrf.as_str()), ("decision", "allow")],
        )
        .await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert!(
        again
            .html()
            .contains("data-message-key=\"consent.expired\""),
        "the used page cannot answer again"
    );
    assert!(
        f.granted_scopes().await.is_none(),
        "the switch grants nothing"
    );
}

#[tokio::test]
async fn use_another_account_on_consent_asks_the_next_user_for_their_own_consent() {
    const PASSWORD: &str = "correct horse battery";
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    ui_helpers::register(&app, "", "alice@example.com", PASSWORD).await;
    ui_helpers::register(&app, "", "bob@example.com", PASSWORD).await;
    let client = web_client(&app, &tenant).await;
    app.storage()
        .clients()
        .update(
            tenant.id,
            &client.client_id,
            &ClientUpdate {
                consent_mode: Some(ConsentMode::Required),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    let iss = app.issuer(None);
    let id_of = |email: &'static str| {
        let app = &app;
        let tenant = tenant.id;
        async move {
            app.storage()
                .users()
                .get_by_email(tenant, email)
                .await
                .expect("lookup")
                .expect("user")
                .id
        }
    };
    let alice = id_of("alice@example.com").await;
    let bob = id_of("bob@example.com").await;
    let grant = |user: UserId| {
        let app = &app;
        let tenant = tenant.id;
        let client_id = client.client_id.clone();
        async move {
            app.storage()
                .grants()
                .consent(tenant, user, &client_id)
                .await
                .expect("consent lookup")
                .map(|g| g.scopes)
        }
    };
    let authorize = |scope: &'static str| {
        let app = &app;
        let client_id = client.client_id.clone();
        async move {
            let p: Vec<(&str, &str)> = pkce_params(&client_id)
                .into_iter()
                .map(|(k, v)| if k == "scope" { (k, scope) } else { (k, v) })
                .collect();
            app.get(&authorize_path("", &p)).await
        }
    };
    let open_consent = |resp: TestResponse| {
        let app = &app;
        async move {
            assert_eq!(resp.status, 303, "{}", resp.text());
            let path = to_path(app, &location(&resp));
            assert!(path.starts_with("/ui/consent?request="), "{path}");
            let page = app.get(&path).await;
            assert_eq!(page.status, 200, "{}", page.text());
            let html = page.html();
            let action = action_of(app, &html, "consent-form");
            let csrf = csrf_from(&html);
            (html, action, csrf)
        }
    };

    // Alice signs in and allows `openid`.
    let resp = ui_helpers::login(&app, "", "alice@example.com", PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let alice_session = ui_helpers::session_cookie(&app).expect("session").1;
    let (_, action, csrf) = open_consent(authorize("openid").await).await;
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &iss);
    assert_eq!(grant(alice).await.expect("Alice's grant"), ["openid"]);

    // A new scope asks Alice again; she uses another account instead.
    let (html, action, csrf) = open_consent(authorize("openid email").await).await;
    assert!(html.contains(">alice@example.com</bdi>"), "{html}");
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("choice", "other")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(&app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");

    // Bob signs in for the request; Alice's session is revoked.
    let resp = ui_helpers::submit_form(
        &app,
        &login,
        &[("identifier", "bob@example.com"), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).contains("/authorize/continue?request="),
        "{}",
        location(&resp)
    );
    let alice_row = app
        .storage()
        .sessions()
        .get_active(
            tenant.id,
            &anvil_core::model::SecretHash(anvil_jose::encoding::secret_hash(&alice_session)),
            app.clock().now(),
        )
        .await
        .expect("session lookup");
    assert!(alice_row.is_none(), "Alice's session is revoked");

    // Bob gets his own consent screen: Alice's grant is not his, so openid is new for him.
    let resp = app.follow(&resp).await;
    let (html, action, csrf) = open_consent(resp).await;
    assert!(html.contains(">bob@example.com</bdi>"), "{html}");
    assert!(html.contains("data-scope=\"openid\""), "{html}");
    assert!(!html.contains("id=\"consent-granted-scopes\""), "{html}");
    assert!(grant(bob).await.is_none(), "nothing granted to Bob yet");
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("decision", "allow")])
        .await;
    assert_code(&resp, &iss);
    assert_eq!(grant(bob).await.expect("Bob's grant"), ["email", "openid"]);
    assert_eq!(
        grant(alice).await.expect("Alice's grant"),
        ["openid"],
        "Alice's grant is unchanged"
    );
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

// ---------------------------------------------------------------------------------------------
// Remembered consent covers resources (plan 05-13)
// ---------------------------------------------------------------------------------------------

const MCP: &str = "https://mcp.example/";
const OTHER: &str = "https://other.example/";

/// [`fixture`] with consent required and a client allowed to request [`MCP`] and [`OTHER`].
async fn resource_fixture() -> Fixture {
    let mut f = fixture(ConsentMode::Required).await;
    f.client = f
        .app
        .storage()
        .clients()
        .update(
            f.tenant.id,
            &f.client.client_id,
            &ClientUpdate {
                allowed_resources: Some(vec![MCP.to_owned(), OTHER.to_owned()]),
                ..ClientUpdate::default()
            },
            f.app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    f
}

impl Fixture {
    async fn granted_resources(&self) -> Option<Vec<String>> {
        self.app
            .storage()
            .grants()
            .consent(self.tenant.id, self.user, &self.client.client_id)
            .await
            .expect("consent lookup")
            .map(|g| g.resources)
    }
}

#[tokio::test]
async fn remembered_consent_covers_resources_and_a_new_resource_asks_again() {
    let f = resource_fixture().await;
    assert_code(
        &f.decide("openid profile", &[("resource", MCP)], "allow")
            .await,
        &f.iss,
    );
    assert_eq!(f.granted_resources().await.expect("grant stored"), [MCP]);
    assert_eq!(
        f.granted_scopes().await.expect("grant stored"),
        ["openid", "profile"]
    );

    // Remembered: the same resource, or none, goes straight to the code.
    assert_code(
        &f.authorize("openid profile", &[("resource", MCP)]).await,
        &f.iss,
    );
    assert_code(&f.authorize("openid", &[]).await, &f.iss);

    // Same scopes, a new resource: the screen again, listing the requested resource.
    let resp = f.authorize("openid profile", &[("resource", OTHER)]).await;
    let path = f.consent_path(&resp);
    let (html, action, csrf) = f.open(&path).await;
    assert!(
        html.contains(&format!(
            "id=\"consent-resource-1\" data-resource=\"{OTHER}\""
        )),
        "{html}"
    );
    assert!(!html.contains("id=\"consent-resource-2\""), "{html}");
    // With prompt=none the same request is consent_required.
    let resp = f
        .authorize("openid profile", &[("resource", OTHER), ("prompt", "none")])
        .await;
    assert_eq!(param(&resp, "error").as_deref(), Some("consent_required"));

    // Allow merges the resources (sorted set) and keeps the scopes.
    assert_code(
        &f.post(&action, &[("csrf_token", &csrf), ("decision", "allow")])
            .await,
        &f.iss,
    );
    assert_eq!(f.granted_resources().await.expect("grant"), [MCP, OTHER]);
    assert_eq!(
        f.granted_scopes().await.expect("grant"),
        ["openid", "profile"]
    );
    assert_code(
        &f.authorize("openid profile", &[("resource", OTHER), ("resource", MCP)])
            .await,
        &f.iss,
    );

    // A new scope with a granted resource still asks (scopes are checked as before).
    let resp = f.authorize("openid email", &[("resource", MCP)]).await;
    f.consent_path(&resp);
}

#[tokio::test]
async fn deny_does_not_add_the_resource() {
    let f = resource_fixture().await;
    assert_code(
        &f.decide("openid", &[("resource", MCP)], "allow").await,
        &f.iss,
    );
    let resp = f.decide("openid", &[("resource", OTHER)], "deny").await;
    assert_eq!(param(&resp, "error").as_deref(), Some("access_denied"));
    assert_eq!(f.granted_resources().await.expect("grant"), [MCP]);
    let resp = f.authorize("openid", &[("resource", OTHER)]).await;
    f.consent_path(&resp);
}

#[tokio::test]
async fn a_grant_without_resources_asks_once_for_a_resource() {
    let f = resource_fixture().await;
    // A grant as stored by 0.3: scopes only.
    let now = f.app.clock().now();
    f.app
        .storage()
        .grants()
        .upsert_consent(
            f.tenant.id,
            &NewConsent {
                id: ConsentId::new_v7(),
                user_id: f.user,
                client_id: f.client.client_id.clone(),
                scopes: vec!["openid".into(), "profile".into()],
                resources: vec![],
                created_at: now,
            },
            now,
        )
        .await
        .expect("grant");
    assert_code(&f.authorize("openid profile", &[]).await, &f.iss);

    // The first request with a resource asks once ...
    assert_code(
        &f.decide("openid profile", &[("resource", MCP)], "allow")
            .await,
        &f.iss,
    );
    assert_eq!(f.granted_resources().await.expect("grant"), [MCP]);
    // ... and is remembered afterwards.
    assert_code(
        &f.authorize("openid profile", &[("resource", MCP)]).await,
        &f.iss,
    );
}

#[tokio::test]
async fn revoking_consent_revokes_families_and_clears_resources() {
    let f = resource_fixture().await;
    assert_code(
        &f.decide("openid", &[("resource", MCP)], "allow").await,
        &f.iss,
    );
    let now = f.app.clock().now();
    let family = TokenFamilyId::new_v7();
    f.app
        .storage()
        .grants()
        .create_family(
            f.tenant.id,
            &NewTokenFamily {
                id: family,
                client_id: f.client.client_id.clone(),
                user_id: Some(f.user),
                scope: "openid".into(),
                resource: vec![MCP.into()],
                auth_time: Some(now),
                acr: None,
                amr: vec![],
                session_id: None,
                claims: None,
                created_at: now,
                absolute_expires_at: now + time::Duration::days(1),
                org_id: None,
            },
        )
        .await
        .expect("family");

    assert!(
        f.app
            .storage()
            .grants()
            .revoke_consent(f.tenant.id, f.user, &f.client.client_id, now)
            .await
            .expect("revoke")
    );
    let family = f
        .app
        .storage()
        .grants()
        .get_family(f.tenant.id, family)
        .await
        .expect("family lookup")
        .expect("family exists");
    assert!(
        family.revoked_at.is_some(),
        "the client's families are revoked"
    );
    assert!(f.granted_resources().await.is_none(), "no active grant");

    // The resource asks again; a new grant holds only what was granted after the revocation.
    assert_code(
        &f.decide("openid", &[("resource", OTHER)], "allow").await,
        &f.iss,
    );
    assert_eq!(f.granted_resources().await.expect("grant"), [OTHER]);
    let resp = f.authorize("openid", &[("resource", MCP)]).await;
    f.consent_path(&resp);
}

// ---------------------------------------------------------------------------------------------
// CIMD clients on the consent screen (plan 05-13)
// ---------------------------------------------------------------------------------------------

const CIMD_ID: &str = "https://app.example.com/oauth/client.json";

/// A CIMD client row (as 05-15 materialises it) with a self-asserted `name`, inserted directly
/// through `ClientRepo::upsert_cimd`, and a stored authorization request for it.
async fn cimd_request(f: &Fixture, name: &str, resources: &[&str]) -> AuthRequestId {
    let now = f.app.clock().now();
    let client = f
        .app
        .storage()
        .clients()
        .upsert_cimd(
            f.tenant.id,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: CIMD_ID.into(),
                name: name.into(),
                client_type: ClientType::Public,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::None,
                secret_hash: None,
                jwks: None,
                redirect_uris: vec![RP.into()],
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: vec!["openid".into()],
                require_pkce: true,
                created_at: now,
                token_format: anvil_core::model::TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: resources.iter().map(|r| (*r).to_owned()).collect(),
                mfa_policy: None,
                metadata_expires_at: Some(now + time::Duration::hours(1)),
                registration_access_token_hash: None,
                registration_source: ClientSource::Cimd,
                organization: anvil_core::model::OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: anvil_core::model::ClientKind::Application,
                headless_native: false,
                client_uri: None,
                initiate_login_uri: None,
            },
            now + time::Duration::hours(1),
            now,
        )
        .await
        .expect("cimd client");
    assert_eq!(client.registration_source, ClientSource::Cimd);
    let id = AuthRequestId::new_v7();
    f.app
        .storage()
        .grants()
        .create_authorization_request(
            f.tenant.id,
            &NewAuthorizationRequest {
                id,
                client_id: CIMD_ID.into(),
                params: AuthorizationParams {
                    redirect_uri: RP.into(),
                    scope: "openid".into(),
                    state: Some("st-1".into()),
                    nonce: None,
                    code_challenge: Some(CHALLENGE.into()),
                    prompt: vec![],
                    max_age: None,
                    login_hint: None,
                    acr_values: vec![],
                    ui_locales: None,
                    claims: None,
                    response_mode: anvil_core::oauth::response_mode::ResponseMode::default(),
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

#[tokio::test]
async fn a_cimd_client_is_named_by_its_host_with_an_unverified_name_and_no_remote_logo() {
    let f = fixture(ConsentMode::Required).await;
    let request = cimd_request(&f, "Acme <Bank>", &[MCP]).await;
    let (html, _, _) = f.open(&format!("/ui/consent?request={request}")).await;

    // The host of the client_id URL is the client's identity on the page.
    assert!(
        html.contains("<strong id=\"consent-client\"><bdi>app.example.com</bdi></strong>"),
        "{html}"
    );
    // The self-asserted name is shown escaped and labelled unverified.
    assert!(
        html.contains("<p id=\"consent-client-name\"><bdi>Acme &lt;Bank&gt;</bdi>"),
        "{html}"
    );
    assert!(!html.contains("<Bank>"), "{html}");
    assert!(
        html.contains("id=\"consent-cimd-unverified\">(name not verified)</em>"),
        "{html}"
    );
    assert!(html.contains("id=\"consent-cimd-note\""), "{html}");
    // Initials, never an image from the client's servers.
    assert!(
        html.contains("id=\"consent-avatar\" aria-hidden=\"true\">AB</span>"),
        "{html}"
    );
    assert!(
        !html.contains("<img"),
        "no image at all on the consent page: {html}"
    );
    // The resources are listed as for any client.
    assert!(
        html.contains(&format!(
            "id=\"consent-resource-1\" data-resource=\"{MCP}\""
        )),
        "{html}"
    );

    // German catalog.
    let resp = f
        .get(&format!("/ui/consent?request={request}&ui_locales=de"))
        .await;
    let html = resp.html();
    assert!(
        html.contains("id=\"consent-cimd-unverified\">(Name nicht überprüft)</em>"),
        "{html}"
    );
}

#[tokio::test]
async fn a_static_client_has_no_cimd_block() {
    let f = fixture(ConsentMode::Required).await;
    let resp = f.authorize("openid", &[]).await;
    let path = f.consent_path(&resp);
    let (html, _, _) = f.open(&path).await;
    assert!(
        html.contains("<strong id=\"consent-client\">Test RP</strong>"),
        "{html}"
    );
    assert!(!html.contains("consent-cimd"), "{html}");
    assert!(!html.contains("consent-avatar"), "{html}");
}
