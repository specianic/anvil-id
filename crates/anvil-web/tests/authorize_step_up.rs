//! `acr_values` step-up and the other sign-in parameters of OIDC-14 (AUTH-08) over HTTP on the
//! selected backend (`ANVILID_TEST_DB`): a single-factor session asked for
//! `urn:anvilid:acr:mfa` is stepped up in place (second factor without the password, same
//! session id, `acr`/`amr`/`auth_time` in the ID token), voluntary and essential requests a user
//! cannot meet, `prompt=none`, `max_age`, the browser switching users (the old session and its
//! RP sessions are logged out), and `login_hint` prefill.

mod support;
mod token_support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    ACR_MFA, ACR_PWD, AMR_MFA, AMR_OTP, AMR_PWD, AuditAction, AuditQuery, BrowserSession,
    ClientUpdate, ConsentMode, CredentialId, MfaPolicy, NewTotp, SecretHash, TOTP_SEED_PURPOSE,
    TenantSettings, UserId, credential_aad,
};
use anvil_core::ports::Clock as _;
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use support::{TestApp, TestResponse, csrf_from, json, location};
use token_support::{CHALLENGE, REDIRECT, Rp, exchange, jwt_claims, web_input};
use ui_helpers::*;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery";
const MFA: &str = "urn:anvilid:acr:mfa";
const ESSENTIAL_MFA: &str =
    r#"{"id_token":{"acr":{"essential":true,"values":["urn:anvilid:acr:mfa"]}}}"#;

struct Fx {
    app: TestApp,
    rp: Rp,
}

async fn fixture(policy: MfaPolicy) -> Fx {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", ALICE, PASSWORD).await;
    register(&app, "", BOB, PASSWORD).await;
    let t = default_tenant(&app);
    set_settings(
        &app,
        t.id,
        TenantSettings {
            mfa_policy: policy,
            ..t.settings.clone()
        },
    )
    .await;
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
                consent_mode: Some(ConsentMode::SkipFirstParty),
                backchannel_logout_uri: Some(Some("https://rp.test/backchannel".into())),
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

    /// The ID token claims for a code redirect.
    async fn id_token(&self, resp: &TestResponse) -> serde_json::Value {
        let code = param(resp, "code").unwrap_or_else(|| panic!("code in {}", location(resp)));
        let token = exchange(&self.app, &self.rp, &code).await;
        assert_eq!(token.status, 200, "{}", token.text());
        jwt_claims(json(&token)["id_token"].as_str().expect("id_token"))
    }

    async fn audit(&self, action: AuditAction) -> Vec<anvil_core::model::AuditEvent> {
        self.app
            .storage()
            .audit()
            .query(
                default_tenant(&self.app).id,
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

/// Enrols an authenticator app for `email`; returns its seed.
async fn enrol_totp(app: &TestApp, email: &str) -> Vec<u8> {
    let tenant = default_tenant(app).id;
    let user = user_id(app, email).await;
    let id = CredentialId::new_v7();
    let seed = TotpSecret::generate();
    let secret_enc = app
        .kek()
        .seal(TOTP_SEED_PURPOSE, &credential_aad(id), seed.as_bytes())
        .expect("seal");
    let (_, hashes) = new_recovery_codes(app.kek()).expect("codes");
    let now = app.clock().now();
    app.storage()
        .users()
        .create_totp(
            tenant,
            user,
            &NewTotp {
                id,
                secret_enc,
                created_at: now,
            },
            &hashes,
            now,
        )
        .await
        .expect("totp");
    seed.as_bytes().to_vec()
}

fn totp_code(seed: &[u8], unix: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter = u64::try_from(unix / 30).expect("positive time");
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    format!("{:06}", bin % 1_000_000)
}

/// Posts the code of a second-factor page.
async fn post_code(app: &TestApp, page: &TestResponse, code: &str) -> TestResponse {
    let html = page.html();
    let token = hidden_inputs(&html)
        .into_iter()
        .find(|(n, _)| n == "factor_token")
        .map(|(_, v)| v)
        .expect("factor_token");
    app.post_form(
        &form_action(app, &html),
        &[
            ("csrf_token", csrf_from(&html).as_str()),
            ("factor_token", token.as_str()),
            ("code", code),
        ],
    )
    .await
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

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_str().expect("string").to_owned())
        .collect()
}

/// Signs `email` in with the password only (policy must not prompt) and returns the session.
async fn single_factor_session(fx: &Fx, email: &str) -> BrowserSession {
    let resp = password_login(&fx.app, "/ui/login", email).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let s = current_session(&fx.app).await;
    assert_eq!(s.acr, ACR_PWD);
    s
}

#[tokio::test]
async fn acr_values_steps_up_the_same_session_without_the_password() {
    let fx = fixture(MfaPolicy::Off).await;
    let seed = enrol_totp(&fx.app, ALICE).await;
    let before = single_factor_session(&fx, ALICE).await;
    let (cookie_name, cookie_value) = session_cookie(&fx.app).expect("cookie");
    fx.app.clock().advance(std::time::Duration::from_secs(120));

    let resp = fx
        .authorize(&[("acr_values", MFA), ("max_age", "3600")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");

    let page = fx.app.get(&login).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("id=\"second-factor\""), "{html}");
    assert!(!html.contains("name=\"password\""), "no password re-entry");

    let code = totp_code(&seed, fx.app.clock().now().unix_timestamp());
    let resp = post_code(&fx.app, &page, &code).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).contains("/authorize/continue?request="));
    // The session cookie is unchanged and the session upgraded in place.
    assert_eq!(
        session_cookie(&fx.app),
        Some((cookie_name, cookie_value)),
        "same cookie"
    );
    let after = current_session(&fx.app).await;
    assert_eq!(after.id, before.id, "same session");
    assert_eq!(after.acr, ACR_MFA);
    assert_eq!(after.amr, vec![AMR_PWD, AMR_OTP, AMR_MFA]);
    assert_eq!(after.auth_time, fx.app.clock().now());
    assert!(after.auth_time > before.auth_time);
    let audited = fx.audit(AuditAction::StepUpCompleted).await;
    assert_eq!(audited.len(), 1);

    let resp = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT));
    let claims = fx.id_token(&resp).await;
    assert_eq!(claims["acr"], ACR_MFA);
    assert!(strings(&claims["amr"]).contains(&AMR_MFA.to_owned()));
    assert_eq!(
        claims["auth_time"].as_i64(),
        Some(after.auth_time.unix_timestamp())
    );
}

#[tokio::test]
async fn step_up_is_refused_once_the_session_is_gone() {
    let fx = fixture(MfaPolicy::Off).await;
    let seed = enrol_totp(&fx.app, ALICE).await;
    let s = single_factor_session(&fx, ALICE).await;
    let resp = fx.authorize(&[("acr_values", MFA)]).await;
    let page = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    assert!(page.html().contains("id=\"second-factor\""));
    fx.app
        .storage()
        .sessions()
        .revoke(default_tenant(&fx.app).id, s.id, fx.app.clock().now())
        .await
        .expect("revoke");
    let code = totp_code(&seed, fx.app.clock().now().unix_timestamp());
    let resp = post_code(&fx.app, &page, &code).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(fx.audit(AuditAction::StepUpCompleted).await.is_empty());
}

#[tokio::test]
async fn voluntary_acr_a_user_cannot_meet_issues_the_lower_acr() {
    let fx = fixture(MfaPolicy::Optional).await;
    single_factor_session(&fx, BOB).await;
    let resp = fx.authorize(&[("acr_values", MFA)]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    let claims = fx.id_token(&resp).await;
    assert_eq!(claims["acr"], ACR_PWD);
    assert_eq!(strings(&claims["amr"]), vec![AMR_PWD.to_owned()]);
}

#[tokio::test]
async fn essential_acr_a_user_cannot_meet_is_unmet_authentication_requirements() {
    let fx = fixture(MfaPolicy::Optional).await;
    // With a session: answered at once.
    single_factor_session(&fx, BOB).await;
    let resp = fx.authorize(&[("claims", ESSENTIAL_MFA)]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT));
    assert_eq!(
        param(&resp, "error").as_deref(),
        Some("unmet_authentication_requirements")
    );
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
    assert!(param(&resp, "code").is_none());

    // Without a session: after the sign-in, through the response mode.
    fx.app.clear_cookies();
    let resp = fx.authorize(&[("claims", ESSENTIAL_MFA)]).await;
    let login = to_path(&fx.app, &location(&resp));
    let resp = password_login(&fx.app, &login, BOB).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let resp = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        param(&resp, "error").as_deref(),
        Some("unmet_authentication_requirements")
    );
}

#[tokio::test]
async fn essential_acr_is_met_by_a_second_factor_at_sign_in() {
    let fx = fixture(MfaPolicy::Off).await;
    let seed = enrol_totp(&fx.app, ALICE).await;
    let resp = fx.authorize(&[("claims", ESSENTIAL_MFA)]).await;
    let login = to_path(&fx.app, &location(&resp));
    let page = password_login(&fx.app, &login, ALICE).await;
    assert!(
        page.html().contains("id=\"second-factor\""),
        "{}",
        page.text()
    );
    let code = totp_code(&seed, fx.app.clock().now().unix_timestamp());
    let resp = post_code(&fx.app, &page, &code).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let resp = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    let claims = fx.id_token(&resp).await;
    assert_eq!(claims["acr"], ACR_MFA);
}

#[tokio::test]
async fn prompt_none_never_shows_a_step_up_page() {
    let fx = fixture(MfaPolicy::Off).await;
    enrol_totp(&fx.app, ALICE).await;
    single_factor_session(&fx, ALICE).await;
    let resp = fx
        .authorize(&[("acr_values", MFA), ("prompt", "none")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT));
    assert_eq!(
        param(&resp, "error").as_deref(),
        Some("interaction_required")
    );
    let resp = fx
        .authorize(&[("claims", ESSENTIAL_MFA), ("prompt", "none")])
        .await;
    assert_eq!(
        param(&resp, "error").as_deref(),
        Some("unmet_authentication_requirements")
    );
}

#[tokio::test]
async fn max_age_exceeded_asks_for_the_full_sign_in_then_the_second_factor() {
    let fx = fixture(MfaPolicy::Off).await;
    let seed = enrol_totp(&fx.app, ALICE).await;
    let before = single_factor_session(&fx, ALICE).await;
    fx.app.clock().advance(std::time::Duration::from_secs(600));
    let resp = fx
        .authorize(&[("acr_values", MFA), ("max_age", "60")])
        .await;
    let login = to_path(&fx.app, &location(&resp));
    let page = fx.app.get(&login).await;
    assert!(page.html().contains("id=\"login\""), "the password form");
    let page = password_login(&fx.app, &login, ALICE).await;
    assert!(
        page.html().contains("id=\"second-factor\""),
        "{}",
        page.text()
    );
    let code = totp_code(&seed, fx.app.clock().now().unix_timestamp());
    let resp = post_code(&fx.app, &page, &code).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let resp = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    let claims = fx.id_token(&resp).await;
    assert_eq!(claims["acr"], ACR_MFA);
    assert_eq!(
        claims["auth_time"].as_i64(),
        Some(fx.app.clock().now().unix_timestamp())
    );
    assert_ne!(
        current_session(&fx.app).await.id,
        before.id,
        "a new sign-in"
    );
}

#[tokio::test]
async fn signing_in_as_another_user_revokes_the_previous_users_session() {
    let fx = fixture(MfaPolicy::Optional).await;
    let alice = single_factor_session(&fx, ALICE).await;
    // Alice's session has an RP session (code issued, tokens exchanged).
    let resp = fx.authorize(&[]).await;
    fx.id_token(&resp).await;
    let tenant = default_tenant(&fx.app).id;
    let deliveries = || async {
        fx.app
            .storage()
            .logout()
            .deliveries_for_client(tenant, fx.rp.id())
            .await
            .expect("deliveries")
            .len()
    };
    assert_eq!(deliveries().await, 0);

    // A new request with prompt=login; Bob signs in in the same browser.
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let resp = fx.authorize(&[("prompt", "login")]).await;
    let login = to_path(&fx.app, &location(&resp));
    let resp = password_login(&fx.app, &login, BOB).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let bob = current_session(&fx.app).await;
    assert_eq!(bob.user_id, user_id(&fx.app, BOB).await);
    let old = fx
        .app
        .storage()
        .sessions()
        .get(tenant, alice.id)
        .await
        .expect("lookup")
        .expect("exists");
    assert!(old.revoked_at.is_some(), "Alice's session is revoked");
    assert!(deliveries().await >= 1, "a back-channel delivery is queued");
    let revoked = fx.audit(AuditAction::SessionRevoked).await;
    assert!(
        revoked
            .iter()
            .any(|e| e.target.as_deref() == Some(alice.id.to_string().as_str())),
        "{revoked:?}"
    );

    // The same user signing in again only rotates the session (no revocation event).
    let n = fx.audit(AuditAction::SessionRevoked).await.len();
    fx.app.clock().advance(std::time::Duration::from_secs(60));
    let resp = fx.authorize(&[("prompt", "login")]).await;
    let login = to_path(&fx.app, &location(&resp));
    password_login(&fx.app, &login, BOB).await;
    assert_eq!(fx.audit(AuditAction::SessionRevoked).await.len(), n);
}

#[tokio::test]
async fn login_hint_prefills_only_an_email_and_is_escaped() {
    let fx = fixture(MfaPolicy::Optional).await;
    let resp = fx.authorize(&[("login_hint", " Alice@Example.com ")]).await;
    let page = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    assert_eq!(page.status, 200);
    assert!(
        page.html().contains("value=\"alice@example.com\""),
        "{}",
        page.html()
    );

    // Not an email: not echoed at all.
    for hint in ["<script>alert(1)</script>", "not an email"] {
        let resp = fx.authorize(&[("login_hint", hint)]).await;
        let page = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
        let html = page.html();
        assert_eq!(page.status, 200);
        assert!(!html.contains("alert(1)"), "hint not echoed: {html}");
        assert!(!html.contains("not an email"));
    }
    // Shaped like an address but full of markup: prefilled, and escaped.
    let resp = fx
        .authorize(&[("login_hint", "\"><script>alert(1)</script>@example.com")])
        .await;
    let page = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    let html = page.html();
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("\"><script"), "{html}");
    assert!(html.contains("&lt;script&gt;alert(1)"), "{html}");
}
