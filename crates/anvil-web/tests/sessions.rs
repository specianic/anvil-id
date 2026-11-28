//! Session management (AUTH-10, ADM-04) on the selected backend (`ANVILID_TEST_DB`): the account
//! sessions page (list, sign out one, sign out the others, sign out this browser), idle and
//! absolute timeouts, throttled activity writes, token-family revocation, the CSRF and
//! cross-site rejections, and the admin functions of `SessionService` for the management API.
//!
//! Each browser has its own cookie jar ([`Browser`]); sessions are created through the
//! production `SessionService::create` with a request context, like a sign-in.

mod authz;
mod support;
mod token_support;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::model::{
    ActorKind, AuditAction, AuditQuery, PageRequest, RequestContext, SessionId, Tenant, UserId,
};
use anvil_core::ports::Clock;
use anvil_core::service::session::{
    SESSION_ABSOLUTE_LIFETIME, SESSION_IDLE_TIMEOUT, SessionService,
};
use anvil_web::cookies::CookiePolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::ExposeSecret as _;
use support::{TestApp, TestClock, TestResponse, csrf_from, location};

const PAGE: &str = "/ui/account/sessions";
const UA_A: &str = "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0";
const UA_B: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0) Safari/605.1";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// A browser with its own cookie jar on top of the shared app.
struct Browser<'a> {
    app: &'a TestApp,
    jar: RefCell<BTreeMap<String, String>>,
}

impl<'a> Browser<'a> {
    fn new(app: &'a TestApp, cookie_name: &str, token: &str) -> Self {
        let mut jar = BTreeMap::new();
        jar.insert(cookie_name.to_owned(), token.to_owned());
        Self {
            app,
            jar: RefCell::new(jar),
        }
    }

    fn has_session_cookie(&self) -> bool {
        self.jar
            .borrow()
            .keys()
            .any(|k| k.contains("anvil_session_"))
    }

    /// Sends `req` with this jar's cookies (never the app's shared jar) and stores the answer's
    /// `Set-Cookie` headers here.
    async fn send(&self, mut req: Request<Body>) -> TestResponse {
        let cookie = {
            let jar = self.jar.borrow();
            let joined = jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            // A header is always set so the harness never adds its own jar.
            if joined.is_empty() {
                "none=1".to_owned()
            } else {
                joined
            }
        };
        req.headers_mut()
            .insert(header::COOKIE, cookie.parse().expect("cookie header"));
        let resp = self.app.send(req).await;
        let mut jar = self.jar.borrow_mut();
        for v in resp.headers.get_all(header::SET_COOKIE) {
            let Ok(raw) = v.to_str() else { continue };
            let Ok(c) = axum_extra::extract::cookie::Cookie::parse(raw.to_owned()) else {
                continue;
            };
            let expired = c.max_age().is_some_and(|m| m.is_zero() || m.is_negative());
            if expired || c.value().is_empty() {
                jar.remove(c.name());
            } else {
                jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
        resp
    }

    async fn get(&self, path: &str) -> TestResponse {
        self.send(Request::get(path).body(Body::empty()).expect("request"))
            .await
    }

    /// A same-origin form POST (`fetch_site` overrides `Sec-Fetch-Site`).
    async fn post_from(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        fetch_site: &str,
    ) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", fetch_site)
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .expect("request"),
        )
        .await
    }

    async fn post(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        self.post_from(path, pairs, "same-origin").await
    }

    /// Opens the sessions page (asserting 200) and returns its HTML.
    async fn page(&self) -> String {
        let resp = self.get(PAGE).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        resp.html()
    }

    /// Opens the page and submits the form `form_id` with the page's CSRF token.
    async fn submit(&self, form_id: &str) -> TestResponse {
        let html = self.page().await;
        let action = action_of(self.app, &html, form_id);
        let csrf = csrf_from(&html);
        self.post(&action, &[("csrf_token", &csrf)]).await
    }

    /// [`Self::submit`] with the confirmation (`confirm=yes`) of a destructive action.
    async fn submit_confirmed(&self, form_id: &str) -> TestResponse {
        let html = self.page().await;
        let action = action_of(self.app, &html, form_id);
        let csrf = csrf_from(&html);
        self.post(&action, &[("csrf_token", &csrf), ("confirm", "yes")])
            .await
    }
}

/// A session service sharing the app's storage, with a clock started at the app's current time.
fn sessions(app: &TestApp) -> SessionService {
    SessionService {
        storage: app.storage_arc(),
        clock: Arc::new(TestClock::new(app.clock().now())),
    }
}

fn tenant(app: &TestApp) -> Tenant {
    authz::default_tenant(app)
}

fn session_cookie_name(app: &TestApp) -> String {
    CookiePolicy::new(app.config.is_https()).session_name(&tenant(app))
}

/// Signs `user` in (production `SessionService::create`) from `ip` with user agent `ua`.
async fn sign_in<'a>(
    app: &'a TestApp,
    user: UserId,
    ip: &str,
    ua: &str,
) -> (SessionId, Browser<'a>) {
    let ctx = RequestContext::new(Some(ip.parse().expect("ip")), Some(ua), None);
    let created = sessions(app)
        .create(tenant(app).id, user, "", &["pwd".into()], None, &ctx)
        .await
        .expect("session created");
    let browser = Browser::new(
        app,
        &session_cookie_name(app),
        created.token.expose_secret(),
    );
    (created.session.id, browser)
}

async fn user(app: &TestApp, email: &str) -> UserId {
    authz::user(app, &tenant(app), email).await
}

/// The `action` of the form with `id`, as a path.
fn action_of(app: &TestApp, html: &str, form_id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{form_id}\""))
        .unwrap_or_else(|| panic!("form #{form_id} in {html}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    let action = html[a..b].replace("&#x2f;", "/").replace("&amp;", "&");
    let origin = format!(
        "{}://{}",
        app.config.public_url.scheme(),
        app.config.public_url.host_port()
    );
    action.strip_prefix(&origin).unwrap_or(&action).to_owned()
}

/// The settings flow id the page's forms post to.
fn flow_of_page(html: &str) -> String {
    let marker = "?flow=";
    let i = html.find(marker).expect("a form bound to a flow") + marker.len();
    html[i..i + 36].to_owned()
}

fn message_keys(html: &str) -> Vec<String> {
    let marker = "data-message-key=\"";
    html.match_indices(marker)
        .map(|(i, _)| {
            let rest = &html[i + marker.len()..];
            rest[..rest.find('"').expect("quoted")].to_owned()
        })
        .collect()
}

fn error_key(html: &str) -> Option<String> {
    let marker = "data-error-key=\"";
    let i = html.find(marker)? + marker.len();
    Some(html[i..i + html[i..].find('"')?].to_owned())
}

/// Minijinja escapes `/` as `&#x2f;`; compare decoded text.
fn decoded(html: &str) -> String {
    html.replace("&#x2f;", "/")
        .replace("&#x27;", "'")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

async fn is_revoked(app: &TestApp, id: SessionId) -> bool {
    app.storage()
        .sessions()
        .get(tenant(app).id, id)
        .await
        .expect("lookup")
        .expect("session exists")
        .revoked_at
        .is_some()
}

async fn audit_events(app: &TestApp) -> Vec<(AuditAction, ActorKind, Option<String>)> {
    app.storage()
        .audit()
        .query(
            tenant(app).id,
            &AuditQuery {
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .into_iter()
        .filter(|e| {
            matches!(
                e.action,
                AuditAction::SessionRevoked | AuditAction::SessionsRevokedAll
            )
        })
        .map(|e| (e.action, e.actor.kind, e.target))
        .collect()
}

/// A refresh token issued (code exchange) under `session`.
async fn refresh_token_under(app: &TestApp, rp: &token_support::Rp, session: SessionId) -> String {
    let t = tenant(app).id;
    let session = app
        .storage()
        .sessions()
        .get(t, session)
        .await
        .expect("lookup")
        .expect("session");
    let code = token_support::issue_code(
        app,
        t,
        rp,
        &session,
        &token_support::params("openid offline_access", Some(token_support::CHALLENGE)),
    )
    .await;
    let resp = token_support::exchange(app, rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    support::json(&resp)["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned()
}

/// `prompt=none` authorization with `browser`'s cookies: the `error` of the redirect, if any.
async fn prompt_none_error(app: &TestApp, browser: &Browser<'_>) -> Option<String> {
    let client = authz::web_client(app, &tenant(app)).await;
    let mut p = authz::pkce_params(&client.client_id);
    p.push(("prompt", "none"));
    let resp = browser.get(&authz::authorize_path("", &p)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    authz::param(&resp, "error")
}

// ---------------------------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn page_lists_both_sessions_with_ip_and_agent_and_marks_the_current_one() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (a, browser_a) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, _browser_b) = sign_in(&app, alice, "2001:db8::7", UA_B).await;
    let other = user(&app, "bob@example.com").await;
    let (bobs, _) = sign_in(&app, other, "198.51.100.1", "Bob's browser").await;

    let resp = browser_a.get(PAGE).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = decoded(&resp.html());
    assert!(
        html.contains("<caption>"),
        "accessible table with a caption"
    );
    assert!(html.contains(&format!("id=\"session-{a}\" data-current")));
    assert!(html.contains(&format!("id=\"session-{b}\">")));
    assert!(!html.contains(&format!("session-{b}\" data-current")));
    assert_eq!(html.matches("id=\"session-current-marker\"").count(), 1);
    assert!(
        !html.contains(&format!("session-{bobs}")),
        "only own sessions"
    );
    // U-M16: readable devices, never the raw user agent.
    for text in [
        "192.0.2.10",
        "2001:db8::7",
        "<bdi>Firefox on Linux</bdi>",
        "<bdi>Safari on iOS</bdi>",
    ] {
        assert!(html.contains(text), "{text} in {html}");
    }
    for raw in [UA_A, UA_B, "Mozilla/5.0"] {
        assert!(!html.contains(raw), "raw {raw} in {html}");
    }
    assert!(html.contains("aria-label=\"Sign out Safari on iOS\""));
    // Times are machine-readable and labelled UTC (the page runs no script).
    assert!(html.contains("<time datetime=\""), "{html}");
    assert!(html.contains(" UTC</time>"), "{html}");
    assert!(html.contains("id=\"sessions-revoke-others\""));
    assert!(
        html.contains("aria-current=\"page\""),
        "account nav marks Sessions"
    );
}

#[tokio::test]
async fn unknown_or_hostile_user_agents_are_never_shown() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let ua = format!("<script>alert(1)</script>{}", "x".repeat(200));
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", &ua).await;
    sign_in(&app, alice, "192.0.2.11", "").await;
    sign_in(
        &app,
        alice,
        "192.0.2.12",
        "Mozilla/5.0 (Linux; Android 15) Chrome/142.0 Mobile",
    )
    .await;
    let html = browser.page().await;
    assert!(!html.contains("alert(1)"), "the user agent is not shown");
    assert!(
        !html.contains(&"x".repeat(20)),
        "the user agent is not shown"
    );
    assert!(html.contains("<bdi>Unknown browser</bdi>"), "{html}");
    assert!(html.contains("<bdi>Unknown device</bdi>"), "{html}");
    assert!(html.contains("<bdi>Chrome on Android</bdi>"), "{html}");
}

#[tokio::test]
async fn without_a_session_the_page_and_posts_redirect_to_sign_in() {
    let app = TestApp::new().await;
    let anonymous = Browser::new(&app, "unrelated", "1");
    let resp = anonymous.get(PAGE).await;
    assert_eq!(resp.status, 303);
    assert!(
        location(&resp).ends_with("/ui/login?return_to=%2Fui%2Faccount%2Fsessions"),
        "{}",
        location(&resp)
    );
    let resp = anonymous
        .post(
            &format!(
                "/ui/account/sessions/revoke-others?flow={}",
                uuid::Uuid::now_v7()
            ),
            &[("csrf_token", "x")],
        )
        .await;
    assert_eq!(resp.status, 303);
}

// ---------------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn revoking_another_session_signs_it_out_and_revokes_its_tokens() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (a, browser_a) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, browser_b) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let rp = token_support::register(
        &app,
        tenant(&app).id,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let rt_a = refresh_token_under(&app, &rp, a).await;
    let rt_b = refresh_token_under(&app, &rp, b).await;
    assert_ne!(
        prompt_none_error(&app, &browser_b).await.as_deref(),
        Some("login_required")
    );

    let resp = browser_a.submit(&format!("session-revoke-{b}")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["sessions.revoked"]);
    assert!(!resp.html().contains(&format!("session-{b}")));
    assert!(is_revoked(&app, b).await);
    assert!(!is_revoked(&app, a).await);

    // The revoked browser is signed out everywhere.
    assert_eq!(
        prompt_none_error(&app, &browser_b).await.as_deref(),
        Some("login_required")
    );
    let resp = browser_b.get(PAGE).await;
    assert_eq!(resp.status, 303);
    // Refresh tokens issued under it are dead; those of the current session still work.
    let resp = token_support::refresh(&app, &rp, &rt_b, None).await;
    token_support::assert_oauth_error(&resp, 400, "invalid_grant");
    let resp = token_support::refresh(&app, &rp, &rt_a, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_ne!(
        prompt_none_error(&app, &browser_a).await.as_deref(),
        Some("login_required")
    );
    browser_a.page().await;

    assert_eq!(
        audit_events(&app).await,
        vec![(
            AuditAction::SessionRevoked,
            ActorKind::User,
            Some(b.to_string())
        )]
    );
}

#[tokio::test]
async fn revoke_all_others_keeps_only_the_current_session() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (a, browser_a) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, browser_b) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let (c, _) = sign_in(&app, alice, "192.0.2.12", "Third").await;
    let bob = user(&app, "bob@example.com").await;
    let (bobs, _) = sign_in(&app, bob, "198.51.100.1", "Bob").await;

    // The first POST asks for confirmation and signs out nobody.
    let resp = browser_a.submit("sessions-revoke-others").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(resp.html().contains("data-action=\"sign-out-others\""));
    assert!(!is_revoked(&app, b).await && !is_revoked(&app, c).await);

    let resp = browser_a.submit_confirmed("sessions-revoke-others").await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["sessions.revoked_others"]);
    assert!(
        !resp.html().contains("id=\"sessions-revoke-others\""),
        "no other sessions left"
    );
    assert!(is_revoked(&app, b).await && is_revoked(&app, c).await);
    assert!(!is_revoked(&app, a).await);
    assert!(!is_revoked(&app, bobs).await, "other users untouched");
    assert_eq!(browser_b.get(PAGE).await.status, 303);
    browser_a.page().await;
    assert_eq!(
        audit_events(&app).await,
        vec![(
            AuditAction::SessionsRevokedAll,
            ActorKind::User,
            Some(alice.to_string())
        )]
    );
}

#[tokio::test]
async fn revoking_the_current_session_signs_out_and_shows_the_signed_out_page() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (a, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let resp = browser.submit(&format!("session-revoke-{a}")).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let to = location(&resp);
    assert!(to.ends_with("/ui/signed-out"), "{to}");
    assert!(!browser.has_session_cookie(), "session cookie cleared");
    assert!(is_revoked(&app, a).await);

    // U-L8: a signed-out message with a way forward, not a bare sign-in form.
    let resp = browser.get(to.trim_start_matches("https://op.test")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(
        html.contains("data-message-key=\"logout.signed_out\""),
        "{html}"
    );
    assert!(html.contains("id=\"link-login\""), "{html}");
    assert_eq!(browser.get(PAGE).await.status, 303);
}

/// The confirmation step of "Sign out other devices" (07.1-21, U-M12): without `confirm=yes`
/// the POST asks (same action and token, no-store) and signs out nobody; a confirmed POST
/// without a valid binding is refused and signs out nobody.
#[tokio::test]
async fn destructive_post_without_confirm_changes_nothing() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (a, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, _) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let html = browser.page().await;
    let action = action_of(&app, &html, "sessions-revoke-others");
    let csrf = csrf_from(&html);

    for confirm in [None, Some(""), Some("no")] {
        let mut pairs = vec![("csrf_token", csrf.as_str())];
        if let Some(c) = confirm {
            pairs.push(("confirm", c));
        }
        let resp = browser.post(&action, &pairs).await;
        assert_eq!(resp.status, 200, "{confirm:?}: {}", resp.text());
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        let page = resp.html();
        assert!(page.contains("data-action=\"sign-out-others\""), "{page}");
        assert!(page.contains("name=\"confirm\" value=\"yes\""), "{page}");
        assert_eq!(csrf_from(&page), csrf);
        assert_eq!(action_of(&app, &page, "form-confirm"), action);
        assert!(!is_revoked(&app, b).await, "{confirm:?}");
    }
    for pairs in [
        vec![("csrf_token", "wrong"), ("confirm", "yes")],
        vec![("confirm", "yes")],
    ] {
        let resp = browser.post(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{pairs:?}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    let resp = browser
        .post_from(
            &action,
            &[("csrf_token", &csrf), ("confirm", "yes")],
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 403);
    assert!(!is_revoked(&app, b).await);
    assert!(audit_events(&app).await.is_empty());

    let resp = browser
        .post(&action, &[("csrf_token", &csrf), ("confirm", "yes")])
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(is_revoked(&app, b).await && !is_revoked(&app, a).await);
}

#[tokio::test]
async fn another_users_or_unknown_session_cannot_be_revoked() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let bob = user(&app, "bob@example.com").await;
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (bobs, _) = sign_in(&app, bob, "198.51.100.1", "Bob").await;
    let html = browser.page().await;
    let csrf = csrf_from(&html);
    let flow = flow_of_page(&html);
    for id in [
        bobs.to_string(),
        SessionId::new_v7().to_string(),
        "garbage".into(),
    ] {
        let resp = browser
            .post(
                &format!("/ui/account/sessions/{id}/revoke?flow={flow}"),
                &[("csrf_token", &csrf)],
            )
            .await;
        assert_eq!(resp.status, 400, "{id}: {}", resp.text());
        assert_eq!(message_keys(&resp.html()), vec!["sessions.not_found"]);
    }
    assert!(!is_revoked(&app, bobs).await);
    assert!(audit_events(&app).await.is_empty());
}

#[tokio::test]
async fn posts_without_csrf_with_a_wrong_binding_or_cross_site_are_rejected() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, _) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let html = browser.page().await;
    let action = action_of(&app, &html, &format!("session-revoke-{b}"));
    let csrf = csrf_from(&html);

    for pairs in [
        vec![],
        vec![("csrf_token", "wrong")],
        vec![("csrf_token", "")],
    ] {
        let resp = browser.post(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{pairs:?}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    // Missing flow parameter.
    let resp = browser
        .post(
            &format!("/ui/account/sessions/{b}/revoke"),
            &[("csrf_token", &csrf)],
        )
        .await;
    assert_eq!(resp.status, 403);
    // Cross-site submission with the right token: stopped by the Fetch-Metadata layer.
    let resp = browser
        .post_from(&action, &[("csrf_token", &csrf)], "cross-site")
        .await;
    assert_eq!(resp.status, 403);
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));

    // Another user's settings flow (with its cookie and token) does not authorise this session.
    let bob = user(&app, "bob@example.com").await;
    let (_, bob_browser) = sign_in(&app, bob, "198.51.100.1", "Bob").await;
    let bob_html = bob_browser.page().await;
    let bob_flow = flow_of_page(&bob_html);
    let flow_cookie = bob_browser
        .jar
        .borrow()
        .iter()
        .find(|(k, _)| k.contains("anvil_flow_"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .expect("flow cookie");
    browser
        .jar
        .borrow_mut()
        .insert(flow_cookie.0, flow_cookie.1);
    let resp = browser
        .post(
            &format!("/ui/account/sessions/{b}/revoke?flow={bob_flow}"),
            &[("csrf_token", &csrf_from(&bob_html))],
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    assert!(!is_revoked(&app, b).await, "nothing was revoked");
}

#[tokio::test]
async fn an_expired_settings_flow_re_renders_with_a_fresh_one() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (b, _) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let html = browser.page().await;
    let action = action_of(&app, &html, &format!("session-revoke-{b}"));
    let csrf = csrf_from(&html);
    app.clock().advance(Duration::from_secs(2 * 3600));
    let resp = browser.post(&action, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), vec!["account.flow_expired"]);
    assert!(!is_revoked(&app, b).await);
    // The fresh flow works.
    let action = action_of(&app, &resp.html(), &format!("session-revoke-{b}"));
    let resp = browser
        .post(&action, &[("csrf_token", &csrf_from(&resp.html()))])
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(is_revoked(&app, b).await);
}

// ---------------------------------------------------------------------------------------------
// Timeouts and activity
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn idle_timeout_signs_out() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    app.clock().advance(Duration::from_secs(
        SESSION_IDLE_TIMEOUT.whole_seconds() as u64 + 60,
    ));
    assert_eq!(browser.get(PAGE).await.status, 303);
    assert_eq!(
        prompt_none_error(&app, &browser).await.as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn hourly_activity_keeps_the_session_until_the_absolute_limit() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (_, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let hours = SESSION_ABSOLUTE_LIFETIME.whole_hours();
    for h in 1..hours {
        app.clock().advance(Duration::from_secs(3600));
        let resp = browser.get(PAGE).await;
        assert_eq!(resp.status, 200, "hour {h}");
    }
    app.clock().advance(Duration::from_secs(3600));
    assert_eq!(browser.get(PAGE).await.status, 303, "absolute limit");
}

#[tokio::test]
async fn activity_is_written_at_most_once_a_minute() {
    let app = TestApp::new().await;
    let alice = user(&app, "alice@example.com").await;
    let (id, browser) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let t = tenant(&app).id;
    let created = app.clock().now();
    app.clock().advance(Duration::from_secs(61));
    let first = app.clock().now();
    for _ in 0..10 {
        browser.page().await;
        app.clock().advance(Duration::from_secs(5));
    }
    let s = app
        .storage()
        .sessions()
        .get(t, id)
        .await
        .expect("lookup")
        .expect("session");
    assert_eq!(s.last_seen_at, first, "only the first of 10 requests wrote");
    assert_eq!(s.idle_expires_at, first + SESSION_IDLE_TIMEOUT);
    assert!(s.last_seen_at > created);
}

// ---------------------------------------------------------------------------------------------
// Admin functions (management API, 03-23)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn admin_lists_and_revokes_sessions_with_the_admin_actor() {
    let app = TestApp::new().await;
    let t = tenant(&app).id;
    let alice = user(&app, "alice@example.com").await;
    let bob = user(&app, "bob@example.com").await;
    let (a1, browser_a1) = sign_in(&app, alice, "192.0.2.10", UA_A).await;
    let (a2, _) = sign_in(&app, alice, "192.0.2.11", UA_B).await;
    let (b1, browser_b1) = sign_in(&app, bob, "198.51.100.1", "Bob").await;
    let svc = sessions(&app);
    let ctx = RequestContext::default();

    let list = svc.admin_list_user(t, alice).await.expect("list");
    assert_eq!(list.iter().map(|s| s.id).collect::<Vec<_>>(), vec![a2, a1]);
    assert!(list.iter().all(|s| !s.current));
    assert_eq!(list[1].ip.as_deref(), Some("192.0.2.10"));
    assert!(matches!(
        svc.admin_list_user(t, UserId::new_v7()).await,
        Err(CoreError::NotFound)
    ));

    let page = svc
        .admin_list_tenant(
            t,
            PageRequest {
                after: None,
                limit: 2,
            },
        )
        .await
        .expect("page");
    assert_eq!(page.items.len(), 2);
    let rest = svc
        .admin_list_tenant(
            t,
            PageRequest {
                after: page.next_cursor,
                limit: 2,
            },
        )
        .await
        .expect("rest");
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next_cursor.is_none());

    svc.admin_revoke(t, b1, "admin-client", &ctx)
        .await
        .expect("revoke");
    assert_eq!(browser_b1.get(PAGE).await.status, 303);
    assert!(matches!(
        svc.admin_revoke(t, b1, "admin-client", &ctx).await,
        Err(CoreError::NotFound)
    ));

    assert_eq!(
        svc.admin_revoke_all(t, alice, "admin-client", &ctx)
            .await
            .expect("all"),
        2
    );
    assert_eq!(browser_a1.get(PAGE).await.status, 303);
    assert!(matches!(
        svc.admin_revoke_all(t, UserId::new_v7(), "admin-client", &ctx)
            .await,
        Err(CoreError::NotFound)
    ));

    assert_eq!(
        audit_events(&app).await,
        vec![
            (
                AuditAction::SessionsRevokedAll,
                ActorKind::Admin,
                Some(alice.to_string())
            ),
            (
                AuditAction::SessionRevoked,
                ActorKind::Admin,
                Some(b1.to_string())
            ),
        ]
    );
}
