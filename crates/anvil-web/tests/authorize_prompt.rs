//! `prompt` handling of OIDC-14 over HTTP on the selected backend (`ANVILID_TEST_DB`):
//! `select_account` (the account chooser: continue as the session's user, or sign in as someone
//! else, which logs the previous user out), `create` (Initiating User Registration 1.0, only for
//! tenants with open registration), the per-tenant discovery advertisement of `prompt` and `acr`
//! values, the chooser's flow binding, and regressions for `login`, `consent` and `max_age`.

mod support;
mod token_support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    ACR_MFA, ACR_PWD, BrowserSession, ClientUpdate, ConsentMode, RegistrationMode, SecretHash,
    TenantSettings, UserId,
};
use anvil_core::ports::Clock as _;
use support::{TestApp, TestResponse, csrf_from, json, location};
use token_support::{CHALLENGE, REDIRECT, Rp, exchange, jwt_claims, web_input};
use ui_helpers::*;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const CAROL: &str = "carol@example.com";
const PASSWORD: &str = "correct horse battery";

struct Fx {
    app: TestApp,
    rp: Rp,
}

async fn fixture(consent: ConsentMode) -> Fx {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", ALICE, PASSWORD).await;
    register(&app, "", BOB, PASSWORD).await;
    let t = default_tenant(&app);
    let rp = token_support::register(
        &app,
        t.id,
        web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let client = app
        .storage()
        .clients()
        .update(
            t.id,
            rp.id(),
            &ClientUpdate {
                consent_mode: Some(consent),
                ..ClientUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    Fx {
        app,
        rp: Rp {
            client,
            secret: rp.secret,
        },
    }
}

impl Fx {
    /// `GET /authorize` for the RP with `extra` parameters (cookies from the harness jar).
    async fn authorize(&self, extra: &[(&str, &str)]) -> TestResponse {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", self.rp.id()),
            ("redirect_uri", REDIRECT),
            ("scope", "openid"),
            ("state", "st-1"),
            ("nonce", "n-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        pairs.extend_from_slice(extra);
        let q = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.app.get(&format!("/authorize?{q}")).await
    }

    /// The `sub` of the ID token for a code redirect.
    async fn sub(&self, resp: &TestResponse) -> String {
        let code = param(resp, "code").unwrap_or_else(|| panic!("code in {}", location(resp)));
        let token = exchange(&self.app, &self.rp, &code).await;
        assert_eq!(token.status, 200, "{}", token.text());
        let claims = jwt_claims(json(&token)["id_token"].as_str().expect("id_token"));
        claims["sub"].as_str().expect("sub").to_owned()
    }

    /// Follows a 303 inside the app.
    async fn follow(&self, resp: &TestResponse) -> TestResponse {
        assert_eq!(resp.status, 303, "{}", resp.text());
        self.app.get(&to_path(&self.app, &location(resp))).await
    }

    /// Signs `email` in at `/ui/login` (no request) and returns the session.
    async fn sign_in(&self, email: &str) -> BrowserSession {
        let resp = password_login(&self.app, "/ui/login", email).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        current_session(&self.app).await
    }

    /// The chooser page for a fresh `prompt=select_account` request (path, response).
    async fn chooser(&self) -> (String, TestResponse) {
        let resp = self.authorize(&[("prompt", "select_account")]).await;
        assert_eq!(resp.status, 303, "{}", resp.text());
        let path = to_path(&self.app, &location(&resp));
        assert!(path.starts_with("/ui/select-account?request="), "{path}");
        let page = self.app.get(&path).await;
        assert_eq!(page.status, 200, "{}", page.text());
        (path, page)
    }
}

fn param(resp: &TestResponse, name: &str) -> Option<String> {
    let loc = location(resp);
    let (_, q) = loc.split_once('?')?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

async fn user_id(app: &TestApp, email: &str) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
        .expect("user")
        .id
}

async fn password_login(app: &TestApp, path: &str, email: &str) -> TestResponse {
    submit_form(app, path, &[("identifier", email), ("password", PASSWORD)]).await
}

async fn current_session(app: &TestApp) -> BrowserSession {
    let (_, value) = session_cookie(app).expect("session cookie");
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
        .expect("active session")
}

async fn set_registration(app: &TestApp, mode: RegistrationMode) {
    let t = default_tenant(app);
    set_settings(
        app,
        t.id,
        TenantSettings {
            registration: mode,
            ..t.settings.clone()
        },
    )
    .await;
}

/// A same-origin form POST with exactly the cookies in `cookie` (the jar is not sent).
async fn post_with_cookies(
    app: &TestApp,
    path: &str,
    cookie: &str,
    pairs: &[(&str, &str)],
) -> TestResponse {
    use axum::body::Body;
    use axum::http::{Method, Request, header};
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_LENGTH, body.len());
    if !cookie.is_empty() {
        req = req.header(header::COOKIE, cookie);
    }
    app.send(req.body(Body::from(body)).expect("request")).await
}

fn cookie_header(pairs: &[&(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_str().expect("string").to_owned())
        .collect()
}

fn assert_error(resp: &TestResponse, error: &str) {
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(resp).starts_with(REDIRECT), "{}", location(resp));
    assert_eq!(param(resp, "error").as_deref(), Some(error));
    assert_eq!(param(resp, "state").as_deref(), Some("st-1"));
    assert!(param(resp, "code").is_none());
}

// --- select_account ---

#[tokio::test]
async fn select_account_shows_the_chooser_and_continue_issues_the_code_for_the_same_user() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (path, page) = fx.chooser().await;
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert!(flow_cookie(&fx.app).is_some(), "the chooser is flow-bound");
    let html = page.html();
    assert!(html.contains("id=\"select-account-form\""), "{html}");
    assert!(
        html.contains("id=\"select-account-continue\" name=\"choice\" value=\"continue\""),
        "{html}"
    );
    assert!(
        html.contains("id=\"select-account-other\" name=\"choice\" value=\"other\""),
        "{html}"
    );
    assert_eq!(element_text(&html, "select-account-email"), ALICE);
    assert!(!html.contains("<script"), "works without JavaScript");

    let resp = submit_form(&fx.app, &path, &[("choice", "continue")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, ALICE).await.to_string()
    );
}

#[tokio::test]
async fn use_another_account_signs_in_bob_and_logs_alice_out() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let alice = fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (path, _) = fx.chooser().await;
    let resp = submit_form(&fx.app, &path, &[("choice", "other")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    let page = fx.app.get(&login).await;
    assert!(page.html().contains("name=\"password\""), "the login form");

    let resp = password_login(&fx.app, &login, BOB).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).contains("/authorize/continue?request="));
    let resp = fx.follow(&resp).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "no second chooser");
    assert_eq!(fx.sub(&resp).await, user_id(&fx.app, BOB).await.to_string());

    let old = fx
        .app
        .storage()
        .sessions()
        .get(default_tenant(&fx.app).id, alice.id)
        .await
        .expect("lookup")
        .expect("exists");
    assert!(old.revoked_at.is_some(), "Alice's session is revoked");
}

#[tokio::test]
async fn use_another_account_without_signing_in_never_answers_with_the_old_session() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (path, _) = fx.chooser().await;
    let resp = submit_form(&fx.app, &path, &[("choice", "other")]).await;
    let request = location(&resp)
        .split_once("request=")
        .map(|(_, r)| r.to_owned())
        .expect("request id");
    // Going straight back to the continuation shows the chooser again, not a code.
    let resp = fx
        .app
        .get(&format!("/authorize/continue?request={request}"))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        to_path(&fx.app, &location(&resp)).starts_with("/ui/select-account?request="),
        "{}",
        location(&resp)
    );
}

#[tokio::test]
async fn select_account_without_a_session_goes_to_the_login_page() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let resp = fx.authorize(&[("prompt", "select_account")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    let resp = password_login(&fx.app, &login, ALICE).await;
    let resp = fx.follow(&resp).await;
    assert!(
        location(&resp).starts_with(REDIRECT),
        "no chooser after a sign-in"
    );
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, ALICE).await.to_string()
    );

    // The chooser page itself without a session also sends the user to sign in.
    fx.app.clear_cookies();
    let resp = fx.authorize(&[("prompt", "select_account")]).await;
    let request = location(&resp)
        .split_once("request=")
        .map(|(_, r)| r.to_owned())
        .expect("request id");
    let resp = fx
        .app
        .get(&format!("/ui/select-account?request={request}"))
        .await;
    assert_eq!(resp.status, 303);
    assert!(location(&resp).contains("/ui/login?request="));
}

#[tokio::test]
async fn select_account_with_none_is_invalid_request() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    let resp = fx.authorize(&[("prompt", "none select_account")]).await;
    assert_error(&resp, "invalid_request");
}

#[tokio::test]
async fn chooser_submissions_without_a_valid_binding_are_rejected() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (_, page) = fx.chooser().await;
    let html = page.html();
    let action = form_action(&fx.app, &html);
    let csrf = csrf_from(&html);

    // No CSRF token, a wrong one, no flow id: 403 and nothing happens.
    for pairs in [
        vec![("choice", "continue")],
        vec![("csrf_token", "wrong"), ("choice", "continue")],
    ] {
        let resp = fx.app.post_form(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{}", resp.text());
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    let no_flow = action
        .split_once("flow=")
        .map(|(a, rest)| format!("{a}{}", rest.split_once('&').map_or("", |(_, r)| r)))
        .expect("flow in the action");
    let resp = fx
        .app
        .post_form(&no_flow, &[("csrf_token", &csrf), ("choice", "continue")])
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // Without the flow cookie: 403.
    let session = session_cookie(&fx.app).expect("session cookie");
    let resp = post_with_cookies(
        &fx.app,
        &action,
        &cookie_header(&[&session]),
        &[("csrf_token", &csrf), ("choice", "continue")],
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());

    // The intact binding still works (the rejected attempts used nothing up) ...
    let resp = fx
        .app
        .post_form(&action, &[("csrf_token", &csrf), ("choice", "continue")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT));
    // ... once: the request is used up, so a second submission is the flow_expired page.
    let resp = fx
        .app
        .post_form(&action, &[("csrf_token", &csrf), ("choice", "continue")])
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("flow_expired"));
}

#[tokio::test]
async fn a_used_chooser_flow_shows_the_chooser_again() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (_, page) = fx.chooser().await;
    let html = page.html();
    let action = form_action(&fx.app, &html);
    let csrf = csrf_from(&html);
    let resp = fx
        .app
        .post_form(&action, &[("csrf_token", &csrf), ("choice", "other")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    // "Use another account" keeps the request; the same page posted again finds its flow used.
    let resp = fx
        .app
        .post_form(&action, &[("csrf_token", &csrf), ("choice", "continue")])
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"select_account.expired".to_owned()),
        "{}",
        resp.text()
    );
    assert!(is_page(&resp), "no code");
    // The fresh chooser it shows works.
    let html = resp.html();
    let resp = fx
        .app
        .post_form(
            &form_action(&fx.app, &html),
            &[("csrf_token", &csrf_from(&html)), ("choice", "continue")],
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, ALICE).await.to_string()
    );
}

/// A response without a `Location` (a page, not a redirect).
fn is_page(resp: &TestResponse) -> bool {
    resp.header("location").is_none()
}

#[tokio::test]
async fn another_users_chooser_flow_is_refused() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (_, page) = fx.chooser().await;
    let html = page.html();
    let action = form_action(&fx.app, &html);
    let csrf = csrf_from(&html);
    let flow = flow_cookie(&fx.app).expect("flow cookie");
    // Bob signs in in the same browser; Alice's chooser cannot answer for Bob.
    fx.app.clock().advance(std::time::Duration::from_secs(1));
    fx.sign_in(BOB).await;
    let bob = session_cookie(&fx.app).expect("session cookie");
    let resp = post_with_cookies(
        &fx.app,
        &action,
        &cookie_header(&[&bob, &flow]),
        &[("csrf_token", &csrf), ("choice", "continue")],
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
}

#[tokio::test]
async fn continue_still_asks_for_consent_and_never_shows_the_chooser_twice() {
    let fx = fixture(ConsentMode::Required).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let (path, _) = fx.chooser().await;
    let resp = submit_form(&fx.app, &path, &[("choice", "continue")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let consent = to_path(&fx.app, &location(&resp));
    assert!(consent.starts_with("/ui/consent?request="), "{consent}");
    let resp = submit_form(&fx.app, &consent, &[("decision", "allow")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, ALICE).await.to_string()
    );
}

// --- create ---

#[tokio::test]
async fn create_on_an_open_tenant_registers_and_resumes_with_a_code() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let resp = fx.authorize(&[("prompt", "create")]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let registration = to_path(&fx.app, &location(&resp));
    assert!(
        registration.starts_with("/ui/registration?request="),
        "{registration}"
    );
    let resp = submit_form(
        &fx.app,
        &registration,
        &[("email", CAROL), ("password", PASSWORD)],
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).contains("/authorize/continue?request="));
    let resp = fx.follow(&resp).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, CAROL).await.to_string()
    );
}

#[tokio::test]
async fn create_with_a_session_still_shows_the_registration_page() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let resp = fx.authorize(&[("prompt", "create")]).await;
    let registration = to_path(&fx.app, &location(&resp));
    assert!(
        registration.starts_with("/ui/registration?request="),
        "{registration}"
    );
    // Abandoning the registration: Alice's older session does not answer the request.
    let request = registration
        .split_once("request=")
        .map(|(_, r)| r.to_owned())
        .expect("request id");
    let resp = fx
        .app
        .get(&format!("/authorize/continue?request={request}"))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        to_path(&fx.app, &location(&resp)).starts_with("/ui/login?request="),
        "{}",
        location(&resp)
    );
    // Registering answers it for the new account.
    let resp = submit_form(
        &fx.app,
        &registration,
        &[("email", CAROL), ("password", PASSWORD)],
    )
    .await;
    let resp = fx.follow(&resp).await;
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(
        fx.sub(&resp).await,
        user_id(&fx.app, CAROL).await.to_string()
    );
}

#[tokio::test]
async fn create_on_a_closed_tenant_is_invalid_request() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    for mode in [RegistrationMode::InviteOnly, RegistrationMode::Disabled] {
        set_registration(&fx.app, mode).await;
        let resp = fx.authorize(&[("prompt", "create")]).await;
        assert_error(&resp, "invalid_request");
        assert!(
            param(&resp, "error_description")
                .is_some_and(|d| d.contains("unsupported prompt value create")),
            "{}",
            location(&resp)
        );
    }
}

#[tokio::test]
async fn create_combined_with_none_or_select_account_is_invalid_request() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    for prompt in ["create none", "none create", "create select_account"] {
        let resp = fx.authorize(&[("prompt", prompt)]).await;
        assert_error(&resp, "invalid_request");
    }
}

// --- discovery ---

#[tokio::test]
async fn discovery_advertises_prompt_values_per_tenant_registration_mode() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let doc = json(&fx.app.get("/.well-known/openid-configuration").await);
    assert_eq!(
        strings(&doc["prompt_values_supported"]),
        ["none", "login", "consent", "select_account", "create"]
    );
    assert_eq!(strings(&doc["acr_values_supported"]), [ACR_PWD, ACR_MFA]);
    for mode in [RegistrationMode::InviteOnly, RegistrationMode::Disabled] {
        set_registration(&fx.app, mode).await;
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            let doc = json(&fx.app.get(path).await);
            assert_eq!(
                strings(&doc["prompt_values_supported"]),
                ["none", "login", "consent", "select_account"],
                "{mode:?} {path}"
            );
            assert_eq!(strings(&doc["acr_values_supported"]), [ACR_PWD, ACR_MFA]);
        }
    }
}

#[tokio::test]
async fn every_advertised_prompt_value_is_accepted() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let doc = json(&fx.app.get("/.well-known/openid-configuration").await);
    for value in strings(&doc["prompt_values_supported"]) {
        let resp = fx.authorize(&[("prompt", value.as_str())]).await;
        assert_eq!(resp.status, 303, "{value}: {}", resp.text());
        // prompt=none without a session is login_required; nothing is invalid_request.
        assert_ne!(
            param(&resp, "error").as_deref(),
            Some("invalid_request"),
            "{value}"
        );
    }
}

// --- regressions: login, consent, max_age ---

#[tokio::test]
async fn prompt_login_forces_a_new_sign_in() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let before = fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let resp = fx.authorize(&[("prompt", "login")]).await;
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    let resp = password_login(&fx.app, &login, ALICE).await;
    let resp = fx.follow(&resp).await;
    assert!(location(&resp).starts_with(REDIRECT));
    fx.sub(&resp).await;
    assert!(current_session(&fx.app).await.auth_time > before.auth_time);
}

#[tokio::test]
async fn prompt_consent_shows_the_consent_screen() {
    let fx = fixture(ConsentMode::Required).await;
    fx.sign_in(ALICE).await;
    // First authorization grants the scope.
    let resp = fx.authorize(&[]).await;
    let consent = to_path(&fx.app, &location(&resp));
    assert!(consent.starts_with("/ui/consent?request="), "{consent}");
    let resp = submit_form(&fx.app, &consent, &[("decision", "allow")]).await;
    assert!(location(&resp).starts_with(REDIRECT));
    // With the grant, no screen ... unless prompt=consent.
    assert!(location(&fx.authorize(&[]).await).starts_with(REDIRECT));
    let resp = fx.authorize(&[("prompt", "consent")]).await;
    assert!(
        to_path(&fx.app, &location(&resp)).starts_with("/ui/consent?request="),
        "{}",
        location(&resp)
    );
}

#[tokio::test]
async fn max_age_zero_behaves_like_prompt_login() {
    let fx = fixture(ConsentMode::SkipFirstParty).await;
    let before = fx.sign_in(ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(5));
    let resp = fx.authorize(&[("max_age", "0")]).await;
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    let resp = password_login(&fx.app, &login, ALICE).await;
    let resp = fx.follow(&resp).await;
    assert!(location(&resp).starts_with(REDIRECT), "no loop");
    let code = param(&resp, "code").expect("code");
    let token = exchange(&fx.app, &fx.rp, &code).await;
    let claims = jwt_claims(json(&token)["id_token"].as_str().expect("id_token"));
    assert!(claims["auth_time"].as_i64() > Some(before.auth_time.unix_timestamp()));
}
