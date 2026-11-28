//! Connected apps (OIDC-13, ADM-04) over HTTP on the selected backend (`ANVILID_TEST_DB`):
//! the page lists the user's grants; revoking one removes the grant, revokes that client's token
//! families (its refresh tokens fail with `invalid_grant`) and leaves other clients alone; the
//! revocation is audited; no session, missing CSRF, foreign flows and cross-site posts change
//! nothing.

mod support;
mod token_support;

use anvil_core::model::{
    ACR_PWD, AMR_PWD, AuditAction, AuditQuery, BrowserSession, ConsentId, NewBrowserSession,
    NewConsent, SecretHash, SessionId, TenantId, User,
};
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_web::cookies::CookiePolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse, csrf_from, json, location};
use token_support::*;

const PAGE: &str = "/ui/account/apps";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// A session for `user` with a known token: (record, `Cookie` value).
async fn browser_session(app: &TestApp, tenant: TenantId, user: &User) -> (BrowserSession, String) {
    let now = app.clock_now();
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
    app.storage()
        .sessions()
        .create(tenant, &new)
        .await
        .expect("session created");
    let session = app
        .storage()
        .sessions()
        .get_active(tenant, &new.token_hash, now)
        .await
        .expect("session lookup")
        .expect("active session");
    let t = &app.default.as_ref().expect("installed").tenant;
    let name = CookiePolicy::new(app.config.is_https()).session_name(t);
    (session, format!("{name}={token}"))
}

/// Grants `scopes` to (user, client) as an Allow on the consent screen does.
async fn grant(app: &TestApp, tenant: TenantId, user: &User, rp: &Rp, scopes: &[&str]) {
    let now = app.clock_now();
    app.storage()
        .grants()
        .upsert_consent(
            tenant,
            &NewConsent {
                id: ConsentId::new_v7(),
                user_id: user.id,
                client_id: rp.id().to_owned(),
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                created_at: now,
                resources: Vec::new(),
            },
            now,
        )
        .await
        .expect("grant stored");
}

/// A code exchange for `rp` with offline_access; returns the refresh token.
async fn refresh_token(
    app: &TestApp,
    tenant: TenantId,
    rp: &Rp,
    session: &BrowserSession,
) -> String {
    let code = issue_code(
        app,
        tenant,
        rp,
        session,
        &params("openid offline_access", Some(CHALLENGE)),
    )
    .await;
    let resp = exchange(app, rp, &code).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    json(&resp)["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned()
}

struct Fixture {
    app: TestApp,
    tenant: TenantId,
    user: User,
    session: BrowserSession,
    cookie: String,
    rp: Rp,
    other: Rp,
}

async fn fixture() -> Fixture {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let mut input = web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic);
    input.name = "Photo <Prints> & Co".into();
    let rp = register(&app, tenant, input).await;
    let mut input = web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic);
    input.name = "Calendar".into();
    let other = register(&app, tenant, input).await;
    let user = seed_user(&app, tenant, "ada@example.test").await;
    let (session, cookie) = browser_session(&app, tenant, &user).await;
    Fixture {
        app,
        tenant,
        user,
        session,
        cookie,
        rp,
        other,
    }
}

impl Fixture {
    fn cookies(&self) -> String {
        let mut parts = vec![self.cookie.clone()];
        parts.extend(self.app.cookies().iter().map(|(k, v)| format!("{k}={v}")));
        parts.join("; ")
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> TestResponse {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.app
            .send(req.body(Body::empty()).expect("request"))
            .await
    }

    async fn page(&self) -> String {
        let resp = self.get(PAGE, Some(&self.cookies())).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        resp.html()
    }

    async fn post(
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

    async fn granted(&self, rp: &Rp) -> bool {
        self.app
            .storage()
            .grants()
            .consent(self.tenant, self.user.id, rp.id())
            .await
            .expect("consent lookup")
            .is_some()
    }
}

/// The revoke form action of the listed app `client_id`, as a path.
fn revoke_action(app: &TestApp, html: &str, client_id: &str) -> String {
    let item = html
        .find(&format!("data-client-id=\"{client_id}\""))
        .unwrap_or_else(|| panic!("app {client_id} listed in {html}"));
    let marker = "action=\"";
    let a = html[item..].find(marker).expect("form action") + item + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    let url = html[a..b]
        .replace("&amp;", "&")
        .replace("&#x2f;", "/")
        .replace("&#x3d;", "=");
    let origin = format!(
        "{}://{}",
        app.config.public_url.scheme(),
        app.config.public_url.host_port()
    );
    url.strip_prefix(&origin).unwrap_or(&url).to_owned()
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_page_lists_grants_with_escaped_names_and_plain_scopes() {
    let f = fixture().await;
    let html = f.page().await;
    assert!(html.contains("id=\"apps-empty\""), "{html}");
    assert!(html.contains("aria-current=\"page\""), "{html}");

    grant(
        &f.app,
        f.tenant,
        &f.user,
        &f.rp,
        &["openid", "email", "api:read"],
    )
    .await;
    let html = f.page().await;
    assert!(!html.contains("id=\"apps-empty\""), "{html}");
    assert!(html.contains("Photo &lt;Prints&gt; &amp; Co"), "{html}");
    assert!(!html.contains("Photo <Prints>"), "client name is escaped");
    assert!(
        html.contains("data-scope=\"openid\">Sign you in</li>"),
        "{html}"
    );
    assert!(
        html.contains("data-scope=\"email\">See your email address</li>"),
        "{html}"
    );
    assert!(html.contains("<code>api:read</code>"), "{html}");
    assert!(html.contains("id=\"app-revoke-1-submit\""), "{html}");
    assert!(
        !html.contains("<script"),
        "the apps page needs no JavaScript"
    );
    assert!(!html.contains("Calendar"), "only granted apps are listed");
}

#[tokio::test]
async fn revoking_removes_the_grant_and_that_clients_tokens_only() {
    let f = fixture().await;
    grant(
        &f.app,
        f.tenant,
        &f.user,
        &f.rp,
        &["openid", "offline_access"],
    )
    .await;
    grant(
        &f.app,
        f.tenant,
        &f.user,
        &f.other,
        &["openid", "offline_access"],
    )
    .await;
    let rt = refresh_token(&f.app, f.tenant, &f.rp, &f.session).await;
    let other_rt = refresh_token(&f.app, f.tenant, &f.other, &f.session).await;

    let html = f.page().await;
    let action = revoke_action(&f.app, &html, f.rp.id());
    let csrf = csrf_from(&html);
    // The first POST asks for confirmation (no JavaScript) and changes nothing.
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(resp.html().contains("id=\"form-confirm\""));
    assert!(f.granted(&f.rp).await);
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf), ("confirm", "yes")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(html.contains("data-message-key=\"apps.revoked\""), "{html}");
    assert!(
        !html.contains(&format!("data-client-id=\"{}\"", f.rp.id())),
        "{html}"
    );
    assert!(
        html.contains(&format!("data-client-id=\"{}\"", f.other.id())),
        "{html}"
    );

    assert!(!f.granted(&f.rp).await);
    assert!(f.granted(&f.other).await);
    assert_oauth_error(
        &refresh(&f.app, &f.rp, &rt, None).await,
        400,
        "invalid_grant",
    );
    let resp = refresh(&f.app, &f.other, &other_rt, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    let events = f
        .app
        .storage()
        .audit()
        .query(
            f.tenant,
            &AuditQuery {
                action: Some(AuditAction::ConsentRevoked),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .items;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].target.as_deref(), Some(f.rp.id()));
    assert_eq!(
        events[0].actor.id.as_deref(),
        Some(f.user.id.to_string().as_str())
    );

    // Revoking again: nothing left to revoke.
    let html = f.page().await;
    let csrf = csrf_from(&html);
    let flow = html
        .split("flow=")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("flow id")
        .to_owned();
    let path = format!("/ui/account/apps/{}/revoke?flow={flow}", f.rp.id());
    let resp = f
        .post(
            &path,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(resp.html().contains("data-message-key=\"apps.not_found\""));
}

#[tokio::test]
async fn revocations_without_a_valid_binding_change_nothing() {
    let f = fixture().await;
    grant(&f.app, f.tenant, &f.user, &f.rp, &["openid"]).await;
    let html = f.page().await;
    let action = revoke_action(&f.app, &html, f.rp.id());
    let csrf = csrf_from(&html);

    // No CSRF token / wrong token / no flow cookie / cross-site.
    let resp = f
        .post(&action, &[], Some(&f.cookies()), "same-origin")
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post(
            &action,
            &[("csrf_token", "forged")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookie),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // Another user's session with this page's flow.
    let bob = seed_user(&f.app, f.tenant, "bob@example.test").await;
    let (_, bob_cookie) = browser_session(&f.app, f.tenant, &bob).await;
    let jar: Vec<String> = f
        .app
        .cookies()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&format!("{bob_cookie}; {}", jar.join("; "))),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // No session at all: sign in first.
    let resp = f
        .post(&action, &[("csrf_token", &csrf)], None, "same-origin")
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).ends_with("/ui/login?return_to=%2Fui%2Faccount%2Fapps"),
        "{}",
        location(&resp)
    );

    assert!(
        f.granted(&f.rp).await,
        "no rejected request revoked the grant"
    );
}

/// The confirmation step of "Remove access" (07.1-21, U-M12): without `confirm=yes` the POST
/// shows the question (escaped app name, same action and CSRF token) and keeps the grant; a
/// confirmed POST without a valid binding is refused and keeps it too.
#[tokio::test]
async fn destructive_post_without_confirm_changes_nothing() {
    let f = fixture().await;
    grant(&f.app, f.tenant, &f.user, &f.rp, &["openid"]).await;
    let html = f.page().await;
    let action = revoke_action(&f.app, &html, f.rp.id());
    let csrf = csrf_from(&html);

    for confirm in [None, Some(""), Some("no"), Some("YES")] {
        let mut pairs = vec![("csrf_token", csrf.as_str())];
        if let Some(c) = confirm {
            pairs.push(("confirm", c));
        }
        let resp = f
            .post(&action, &pairs, Some(&f.cookies()), "same-origin")
            .await;
        assert_eq!(resp.status, 200, "{confirm:?}: {}", resp.text());
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        let page = resp.html();
        assert!(page.contains("id=\"form-confirm\""), "{page}");
        assert!(page.contains("data-action=\"revoke-app\""), "{page}");
        assert!(page.contains("name=\"confirm\" value=\"yes\""), "{page}");
        assert!(page.contains("Photo &lt;Prints&gt; &amp; Co"), "{page}");
        assert!(!page.contains("Photo <Prints>"), "escaped");
        assert!(page.contains("id=\"link-confirm-cancel\""), "{page}");
        assert_eq!(csrf_from(&page), csrf, "same binding");
        let confirm_action = page
            .split("<form id=\"form-confirm\" method=\"post\" action=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("confirm action")
            .replace("&amp;", "&");
        assert!(
            confirm_action.ends_with(&action),
            "{confirm_action} vs {action}"
        );
        assert!(f.granted(&f.rp).await, "{confirm:?}: nothing changed");
    }

    // A first POST without a valid binding is refused before any question.
    let resp = f
        .post(
            &action,
            &[("csrf_token", "forged")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // Confirmed, but with a forged token, without the flow cookie or cross-site: refused.
    for (pairs, cookie, site) in [
        (
            vec![("csrf_token", "forged"), ("confirm", "yes")],
            f.cookies(),
            "same-origin",
        ),
        (vec![("confirm", "yes")], f.cookies(), "same-origin"),
        (
            vec![("csrf_token", csrf.as_str()), ("confirm", "yes")],
            f.cookie.clone(),
            "same-origin",
        ),
        (
            vec![("csrf_token", csrf.as_str()), ("confirm", "yes")],
            f.cookies(),
            "cross-site",
        ),
    ] {
        let resp = f.post(&action, &pairs, Some(&cookie), site).await;
        assert_eq!(resp.status, 403, "{pairs:?} {site}: {}", resp.text());
        assert!(f.granted(&f.rp).await);
    }

    // Confirmed with the page's binding: revoked.
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf), ("confirm", "yes")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(!f.granted(&f.rp).await);
}

#[tokio::test]
async fn the_page_needs_a_session() {
    let f = fixture().await;
    let resp = f.get(PAGE, None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).ends_with("/ui/login?return_to=%2Fui%2Faccount%2Fapps"),
        "{}",
        location(&resp)
    );
}
