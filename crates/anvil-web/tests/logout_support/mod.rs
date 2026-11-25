//! Fixture for the RP-initiated logout tests (tests/logout.rs, tests/security_logout.rs). Test
//! code only.
//!
//! A confidential client with registered post-logout redirect URIs and a back-channel logout URI,
//! a user, a browser session with a known cookie token, and ID tokens: real ones from the token
//! endpoint (code issued through `GrantRepo::create_code`, which records the RP session) and
//! hand-signed ones with the tenant's active key for the edge cases (expired, other `sid`).

#![allow(dead_code)]

use std::sync::Arc;

use anvil_core::model::{
    ACR_PWD, AMR_PWD, AuditAction, AuditEvent, AuditQuery, BrowserSession, ClientUpdate,
    NewBrowserSession, SecretHash, SessionId, Tenant, User,
};
use anvil_core::ports::Clock;
use anvil_core::service::key::KeyService;
use anvil_jose::encoding::{random_token, secret_hash};
use anvil_jose::keys::SigningKey;
use anvil_web::cookies::CookiePolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::Value;
use time::OffsetDateTime;

use crate::support::{TestApp, TestResponse, json};
use crate::token_support::{
    CHALLENGE, REDIRECT, Rp, exchange, issue_code, params, register, seed_user, web_input,
};

/// Registered post-logout redirect URI.
pub const BYE: &str = "https://rp.test/bye";
/// Registered post-logout redirect URI with its own query.
pub const BYE_Q: &str = "https://rp.test/bye?from=op";
/// The client's back-channel logout URI.
pub const BACKCHANNEL: &str = "https://rp.test/backchannel";

pub struct Frozen(pub OffsetDateTime);

impl Clock for Frozen {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

pub struct Fx {
    pub app: TestApp,
    pub tenant: Tenant,
    pub rp: Rp,
    pub user: User,
    pub session: BrowserSession,
    /// `Cookie` pair of the session.
    pub cookie: String,
    pub iss: String,
}

/// An active session for `user` with a known token; returns it and its `Cookie` pair.
pub async fn session_for(app: &TestApp, tenant: &Tenant, user: &User) -> (BrowserSession, String) {
    let now = app.clock().now();
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
        .create(tenant.id, &new)
        .await
        .expect("session created");
    let session = app
        .storage()
        .sessions()
        .get_active(tenant.id, &new.token_hash, now)
        .await
        .expect("session lookup")
        .expect("session active");
    let name = CookiePolicy::new(app.config.is_https()).session_name(tenant);
    (session, format!("{name}={token}"))
}

pub async fn fixture() -> Fx {
    let app = TestApp::new().await;
    let tenant = app.default.as_ref().expect("installed").tenant.clone();
    let rp = register(
        &app,
        tenant.id,
        web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let client = app
        .storage()
        .clients()
        .update(
            tenant.id,
            rp.id(),
            &ClientUpdate {
                post_logout_redirect_uris: Some(vec![BYE.into(), BYE_Q.into()]),
                backchannel_logout_uri: Some(Some(BACKCHANNEL.into())),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    let rp = Rp {
        client,
        secret: rp.secret,
    };
    let user = seed_user(&app, tenant.id, "ada@example.test").await;
    let (session, cookie) = session_for(&app, &tenant, &user).await;
    let iss = app.issuer(None);
    Fx {
        app,
        tenant,
        rp,
        user,
        session,
        cookie,
        iss,
    }
}

impl Fx {
    /// A real ID token (and refresh token, if issued) for the fixture session, from the token
    /// endpoint. Issuing the code records the RP session (back-channel logout).
    pub async fn tokens(&self) -> (String, Option<String>) {
        let code = issue_code(
            &self.app,
            self.tenant.id,
            &self.rp,
            &self.session,
            &params("openid offline_access", Some(CHALLENGE)),
        )
        .await;
        let resp = exchange(&self.app, &self.rp, &code).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        let body = json(&resp);
        (
            body["id_token"].as_str().expect("id_token").to_owned(),
            body["refresh_token"].as_str().map(str::to_owned),
        )
    }

    pub async fn id_token(&self) -> String {
        self.tokens().await.0
    }

    /// The tenant's active RS256 signing key.
    pub async fn signer(&self) -> SigningKey {
        KeyService {
            storage: self.app.storage_arc(),
            kek: self.app.kek_arc(),
            clock: Arc::new(Frozen(self.app.clock().now())),
        }
        .signer(self.tenant.id)
        .await
        .expect("active key")
    }

    /// The claims of an ID token for the fixture session, before any override.
    pub fn claims(&self) -> Value {
        let now = self.app.clock().now().unix_timestamp();
        serde_json::json!({
            "iss": self.iss,
            "sub": self.user.id.to_string(),
            "aud": self.rp.id(),
            "azp": self.rp.id(),
            "sid": self.session.id.to_string(),
            "iat": now,
            "exp": now + 300,
        })
    }

    /// A hint signed by the tenant's active key (`typ: JWT`) with `claims`.
    pub async fn sign(&self, claims: &Value) -> String {
        self.signer()
            .await
            .sign_jwt(Some("JWT"), claims)
            .expect("sign hint")
    }

    /// `/logout?{pairs}`.
    pub fn logout_path(pairs: &[(&str, &str)]) -> String {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        if q.is_empty() {
            "/logout".to_owned()
        } else {
            format!("/logout?{q}")
        }
    }

    /// The session cookie plus the harness jar's cookies (flow cookie).
    pub fn cookies(&self) -> String {
        let mut parts = vec![self.cookie.clone()];
        parts.extend(
            self.app
                .cookies()
                .iter()
                .filter(|(k, _)| !k.contains("anvil_session"))
                .map(|(k, v)| format!("{k}={v}")),
        );
        parts.join("; ")
    }

    /// GET with the session (and jar) cookies.
    pub async fn get(&self, path: &str) -> TestResponse {
        self.get_with(path, Some(&self.cookies())).await
    }

    pub async fn get_with(&self, path: &str, cookie: Option<&str>) -> TestResponse {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.app
            .send(req.body(Body::empty()).expect("request"))
            .await
    }

    /// A form POST with `sec_fetch_site` (`cross-site` for an RP, `same-origin` for our pages).
    pub async fn post(
        &self,
        path: &str,
        pairs: &[(&str, &str)],
        cookie: Option<&str>,
        sec_fetch_site: &str,
    ) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", sec_fetch_site)
            .header(header::CONTENT_LENGTH, body.len());
        if sec_fetch_site == "cross-site" {
            req = req.header(header::ORIGIN, "https://rp.test");
        }
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.app
            .send(req.body(Body::from(body)).expect("request"))
            .await
    }

    /// Whether the fixture session is still active.
    pub async fn session_active(&self) -> bool {
        let s = self
            .app
            .storage()
            .sessions()
            .get(self.tenant.id, self.session.id)
            .await
            .expect("session lookup")
            .expect("session exists");
        s.revoked_at.is_none()
    }

    pub async fn audit(&self, action: AuditAction) -> Vec<AuditEvent> {
        self.app
            .storage()
            .audit()
            .query(
                self.tenant.id,
                &AuditQuery {
                    action: Some(action),
                    limit: 100,
                    ..AuditQuery::default()
                },
            )
            .await
            .expect("audit query")
            .items
    }

    pub async fn deliveries(&self) -> usize {
        self.app
            .storage()
            .logout()
            .deliveries_for_client(self.tenant.id, self.rp.id())
            .await
            .expect("deliveries")
            .len()
    }

    /// `/authorize?prompt=none` with `cookie`.
    pub async fn authorize_prompt_none(&self, cookie: Option<&str>) -> TestResponse {
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", self.rp.id()),
                ("redirect_uri", REDIRECT),
                ("scope", "openid"),
                ("state", "st-1"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("prompt", "none"),
            ])
            .finish();
        self.get_with(&format!("/authorize?{q}"), cookie).await
    }
}

/// The `Location` header (panics without one).
pub fn loc(resp: &TestResponse) -> String {
    resp.header("location")
        .unwrap_or_else(|| panic!("no Location ({}): {}", resp.status, resp.text()))
        .to_owned()
}

/// Asserts a sign-out error page for `key`: 400, no redirect, the key on the message.
pub fn assert_logout_error(resp: &TestResponse, key: &str) {
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(
        resp.header("location").is_none(),
        "an error page never redirects"
    );
    let html = resp.html();
    assert!(
        html.contains(&format!("data-message-key=\"{key}\"")),
        "{key}: {html}"
    );
    assert_eq!(resp.header("cache-control"), Some("no-store"));
}

/// The confirmation page's form action (path) and CSRF token.
pub fn confirm_form(app: &TestApp, resp: &TestResponse) -> (String, String) {
    let html = resp.html().replace("&#x2f;", "/").replace("&amp;", "&");
    assert!(html.contains("id=\"logout-confirm-submit\""), "{html}");
    let start = html.find("action=\"").expect("form action") + 8;
    let action = &html[start..start + html[start..].find('"').expect("end")];
    let origin = app.issuer(None);
    let path = action.strip_prefix(&origin).unwrap_or(action).to_owned();
    (path, crate::support::csrf_from(&resp.html()))
}
