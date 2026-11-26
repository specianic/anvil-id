//! The organization switcher and org-level MFA (ORG-02) over HTTP on the selected backend
//! (`ANVILID_TEST_DB`): a user in several orgs signing in to a client whose organization policy
//! is `required` picks one of their own memberships on `/ui/select-organization`, and the tokens
//! carry that org; switching orgs is a new authorization request with `organization=<other>`
//! (also `prompt=none` with the same session), and an earlier token family keeps its org; an
//! org whose MFA policy is stricter than the session triggers the step-up before the code.
//!
//! Refusals: an org the user is not a member of (403, request unchanged), a bad or missing CSRF
//! token, a replayed choice, another user's flow and a flow bound to another request.

mod support;
mod token_support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    ACR_MFA, ACR_PWD, ClientAuthMethod, ConsentMode, CredentialId, MfaPolicy, NewMembership,
    NewOrganization, NewTotp, OrgClientPolicy, OrgId, OrgSettings, Organization, SecretHash,
    TOTP_SEED_PURPOSE, TenantId, UserId, credential_aad,
};
use anvil_core::ports::{AddMemberOutcome, Clock as _};
use anvil_core::service::account::new_recovery_codes;
use anvil_jose::otp::TotpSecret;
use aws_lc_rs::hmac;
use serde_json::{Value, json};
use support::{TestApp, TestResponse, csrf_from, location};
use token_support::{CHALLENGE, REDIRECT, Rp, exchange, jwt_claims, refresh, web_input};
use ui_helpers::*;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const PASSWORD: &str = "correct horse battery";
const PAGE: &str = "/ui/select-organization?request=";

/// Alice is in `acme` and `beta`; Bob is in `gamma` only.
struct Fx {
    app: TestApp,
    tenant: TenantId,
    rp: Rp,
    acme: Organization,
    beta: Organization,
    gamma: Organization,
}

async fn org(app: &TestApp, tenant: TenantId, slug: &str, mfa: Option<MfaPolicy>) -> Organization {
    app.storage()
        .organizations()
        .create(
            tenant,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: slug.into(),
                display_name: format!("{slug} Inc"),
                mfa_policy: mfa,
                settings: OrgSettings::default(),
                metadata: json!({}),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("org created")
}

async fn join(app: &TestApp, tenant: TenantId, org: &Organization, user: UserId) {
    let outcome = app
        .storage()
        .organizations()
        .add_member(
            tenant,
            &NewMembership {
                org_id: org.id,
                user_id: user,
                role_ids: vec![],
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("add member");
    assert_eq!(outcome, AddMemberOutcome::Added);
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

/// Tenant MFA off; `acme` with `acme_mfa`.
async fn fixture_with(acme_mfa: Option<MfaPolicy>) -> Fx {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    register(&app, "", ALICE, PASSWORD).await;
    register(&app, "", BOB, PASSWORD).await;
    let t = default_tenant(&app);
    set_settings(
        &app,
        t.id,
        anvil_core::model::TenantSettings {
            mfa_policy: MfaPolicy::Off,
            ..t.settings.clone()
        },
    )
    .await;
    let rp = token_support::register_with(
        &app,
        t.id,
        web_input(ClientAuthMethod::ClientSecretBasic),
        |c| {
            c.organization = OrgClientPolicy::Required;
            c.consent_mode = ConsentMode::SkipFirstParty;
        },
    )
    .await;
    let acme = org(&app, t.id, "acme", acme_mfa).await;
    let beta = org(&app, t.id, "beta", None).await;
    let gamma = org(&app, t.id, "gamma", None).await;
    let alice = user_id(&app, ALICE).await;
    let bob = user_id(&app, BOB).await;
    join(&app, t.id, &acme, alice).await;
    join(&app, t.id, &beta, alice).await;
    join(&app, t.id, &gamma, bob).await;
    Fx {
        app,
        tenant: t.id,
        rp,
        acme,
        beta,
        gamma,
    }
}

async fn fixture() -> Fx {
    fixture_with(None).await
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

    /// Signs `email` in at `/ui/login` (no request) with the password only.
    async fn sign_in(&self, email: &str) {
        let resp = submit_form(
            &self.app,
            "/ui/login",
            &[("identifier", email), ("password", PASSWORD)],
        )
        .await;
        assert_eq!(resp.status, 200, "{}", resp.text());
    }

    /// The switcher path for a fresh request without `organization`.
    async fn switcher(&self, extra: &[(&str, &str)]) -> String {
        let resp = self.authorize(extra).await;
        assert_eq!(resp.status, 303, "{}", resp.text());
        let path = to_path(&self.app, &location(&resp));
        assert!(path.starts_with(PAGE), "{path}");
        path
    }

    /// The token response for a code redirect.
    async fn tokens(&self, resp: &TestResponse) -> Value {
        assert_eq!(resp.status, 303, "{}", resp.text());
        let code = param(resp, "code").unwrap_or_else(|| panic!("code in {}", location(resp)));
        let token = exchange(&self.app, &self.rp, &code).await;
        assert_eq!(token.status, 200, "{}", token.text());
        support::json(&token)
    }
}

fn param(resp: &TestResponse, name: &str) -> Option<String> {
    let loc = location(resp);
    let (_, q) = loc.split_once('?')?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn id_claims(body: &Value) -> Value {
    jwt_claims(body["id_token"].as_str().expect("id_token"))
}

/// A response without a `Location` (a page, not a redirect).
fn is_page(resp: &TestResponse) -> bool {
    resp.header("location").is_none()
}

/// The org id of the stored authorization request behind a switcher path.
async fn stored_organization(fx: &Fx, path: &str) -> Option<Option<String>> {
    let id = path.strip_prefix(PAGE).expect("switcher path");
    let id = anvil_core::model::AuthRequestId(uuid::Uuid::parse_str(id).expect("request id"));
    fx.app
        .storage()
        .grants()
        .get_authorization_request(fx.tenant, id, fx.app.clock().now())
        .await
        .expect("lookup")
        .map(|r| r.params.organization)
}

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
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::COOKIE, cookie);
    app.send(req.body(Body::from(body)).expect("request")).await
}

fn cookie_header(pairs: &[&(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
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

async fn session_acr(app: &TestApp) -> String {
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
        .acr
}

// ---------------------------------------------------------------------------------------------
// The switcher
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn switcher_lists_only_own_memberships() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let page = fx.app.get(&path).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(page.header("cache-control"), Some("no-store"));
    assert!(flow_cookie(&fx.app).is_some(), "the switcher is flow-bound");
    let html = page.html();
    for o in [&fx.acme, &fx.beta] {
        assert!(
            html.contains(&format!(
                "id=\"organization-{}\" name=\"organization\" value=\"{}\"",
                o.slug, o.id
            )),
            "{html}"
        );
        assert!(html.contains(&o.display_name), "{html}");
    }
    // Another org of the same tenant is never revealed: no slug, name or id.
    assert!(!html.contains("gamma"), "{html}");
    assert!(!html.contains(&fx.gamma.id.to_string()), "{html}");
    // Nothing was picked silently.
    assert_eq!(stored_organization(&fx, &path).await, Some(None));

    // Without a session the switcher sends the user to sign in.
    fx.app.clear_cookies();
    let resp = fx.app.get(&path).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        to_path(&fx.app, &location(&resp)).starts_with("/ui/login?request="),
        "{}",
        location(&resp)
    );
}

#[tokio::test]
async fn switcher_choice_issues_tokens_for_that_org() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let resp = submit_form(&fx.app, &path, &[("organization", &fx.beta.id.to_string())]).await;
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let body = fx.tokens(&resp).await;
    let claims = id_claims(&body);
    assert_eq!(claims["org_id"], fx.beta.id.to_string());
    assert_eq!(claims["org_slug"], "beta");
    assert_eq!(
        claims["sub"],
        user_id(&fx.app, ALICE).await.to_string(),
        "the session's user"
    );
}

#[tokio::test]
async fn switching_with_new_request_changes_org() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let resp = submit_form(&fx.app, &path, &[("organization", &fx.beta.id.to_string())]).await;
    let first = fx.tokens(&resp).await;
    assert_eq!(id_claims(&first)["org_id"], fx.beta.id.to_string());
    let old_refresh = first["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    // Switching is a new authorization request naming the other org, silently with the same
    // session.
    let resp = fx
        .authorize(&[("organization", "acme"), ("prompt", "none")])
        .await;
    let second = fx.tokens(&resp).await;
    assert_eq!(id_claims(&second)["org_id"], fx.acme.id.to_string());

    // The earlier family keeps the org it was issued for.
    let refreshed = refresh(&fx.app, &fx.rp, &old_refresh, None).await;
    assert_eq!(refreshed.status, 200, "{}", refreshed.text());
    let body = support::json(&refreshed);
    assert_eq!(id_claims(&body)["org_id"], fx.beta.id.to_string());
}

#[tokio::test]
async fn prompt_none_with_organization_for_member_issues_code_without_ui() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    for org in ["beta".to_owned(), fx.beta.id.to_string()] {
        let resp = fx
            .authorize(&[("organization", &org), ("prompt", "none")])
            .await;
        assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
        let body = fx.tokens(&resp).await;
        assert_eq!(id_claims(&body)["org_id"], fx.beta.id.to_string());
    }
    // A non-member org with prompt=none is access_denied, never the switcher.
    let resp = fx
        .authorize(&[("organization", "gamma"), ("prompt", "none")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert_eq!(param(&resp, "error").as_deref(), Some("access_denied"));
    assert!(param(&resp, "code").is_none());
}

// ---------------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn switcher_refuses_foreign_org() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let page = fx.app.get(&path).await;
    let html = page.html();
    let mut action = form_action(&fx.app, &html);
    let mut csrf = csrf_from(&html);
    // Gamma (Bob's org), an unknown id and a malformed value: 403, the switcher again with a
    // message, no code, the request unchanged.
    for org in [
        fx.gamma.id.to_string(),
        OrgId::new_v7().to_string(),
        "gamma".to_owned(),
        String::new(),
    ] {
        let resp = fx
            .app
            .post_form(&action, &[("csrf_token", &csrf), ("organization", &org)])
            .await;
        assert_eq!(resp.status, 403, "{org}: {}", resp.text());
        assert!(is_page(&resp), "no redirect");
        let html = resp.html();
        assert!(
            message_keys(&html).contains(&"select_organization.not_member".to_owned()),
            "{html}"
        );
        assert!(!html.contains("gamma"), "still only Alice's orgs: {html}");
        assert_eq!(stored_organization(&fx, &path).await, Some(None));
        // The page shown again is a fresh switcher (new flow).
        action = form_action(&fx.app, &html);
        csrf = csrf_from(&html);
    }
    // A choice among her own orgs still works.
    let resp = submit_form(&fx.app, &path, &[("organization", &fx.acme.id.to_string())]).await;
    let body = fx.tokens(&resp).await;
    assert_eq!(id_claims(&body)["org_id"], fx.acme.id.to_string());
}

#[tokio::test]
async fn switcher_refuses_bad_csrf() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let page = fx.app.get(&path).await;
    let html = page.html();
    let action = form_action(&fx.app, &html);
    let csrf = csrf_from(&html);
    let beta = fx.beta.id.to_string();

    // No CSRF token, a wrong one: 403 csrf page, nothing changes.
    for pairs in [
        vec![("organization", beta.as_str())],
        vec![("csrf_token", "wrong"), ("organization", beta.as_str())],
    ] {
        let resp = fx.app.post_form(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{}", resp.text());
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    // Without the flow cookie: 403.
    let session = session_cookie(&fx.app).expect("session cookie");
    let resp = post_with_cookies(
        &fx.app,
        &action,
        &cookie_header(&[&session]),
        &[("csrf_token", &csrf), ("organization", &beta)],
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    // Without the flow id in the action: 403.
    let no_flow = format!("/ui/select-organization?request={}", &path[PAGE.len()..]);
    let resp = fx
        .app
        .post_form(&no_flow, &[("csrf_token", &csrf), ("organization", &beta)])
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // A cross-site post is stopped by the Fetch-Metadata layer.
    let resp = {
        use axum::body::Body;
        use axum::http::{Method, Request, header};
        let body = format!("csrf_token={csrf}&organization={beta}");
        let cookies = fx
            .app
            .cookies()
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        fx.app
            .send(
                Request::builder()
                    .method(Method::POST)
                    .uri(&action)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header("sec-fetch-site", "cross-site")
                    .header(header::COOKIE, cookies)
                    .header(header::CONTENT_LENGTH, body.len())
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
    };
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(stored_organization(&fx, &path).await, Some(None));

    // The intact binding still works (the rejected attempts used nothing up).
    let resp = fx
        .app
        .post_form(&action, &[("csrf_token", &csrf), ("organization", &beta)])
        .await;
    let body = fx.tokens(&resp).await;
    assert_eq!(id_claims(&body)["org_id"], beta);
}

#[tokio::test]
async fn switcher_choice_cannot_be_replayed() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let page = fx.app.get(&path).await;
    let html = page.html();
    let action = form_action(&fx.app, &html);
    let csrf = csrf_from(&html);
    let resp = fx
        .app
        .post_form(
            &action,
            &[
                ("csrf_token", &csrf),
                ("organization", &fx.beta.id.to_string()),
            ],
        )
        .await;
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    // The same submission again, also with the other org: the flow and the request are used
    // up, no second code.
    for org in [&fx.beta, &fx.acme] {
        let resp = fx
            .app
            .post_form(
                &action,
                &[("csrf_token", &csrf), ("organization", &org.id.to_string())],
            )
            .await;
        assert_eq!(resp.status, 400, "{}", resp.text());
        assert!(is_page(&resp), "no code");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("flow_expired"));
    }
    // The switcher page itself is gone for that request.
    let resp = fx.app.get(&path).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("flow_expired"));
}

#[tokio::test]
async fn switcher_foreign_flow_refused() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;

    // A flow bound to another request of the same user.
    let first = fx.switcher(&[]).await;
    let page = fx.app.get(&first).await;
    let first_html = page.html();
    let first_action = form_action(&fx.app, &first_html);
    let first_csrf = csrf_from(&first_html);
    let first_flow = flow_cookie(&fx.app).expect("flow cookie");
    let second = fx.switcher(&[("ui_locales", "en")]).await;
    let other_request = &second[PAGE.len()..];
    let crossed = first_action.replace(&first[PAGE.len()..], other_request);
    assert_ne!(crossed, first_action);
    let alice = session_cookie(&fx.app).expect("session cookie");
    let resp = post_with_cookies(
        &fx.app,
        &crossed,
        &cookie_header(&[&alice, &first_flow]),
        &[
            ("csrf_token", &first_csrf),
            ("organization", &fx.beta.id.to_string()),
        ],
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    assert_eq!(stored_organization(&fx, &second).await, Some(None));

    // Alice's flow with Bob's session in the same browser: refused.
    fx.app.clock().advance(std::time::Duration::from_secs(1));
    fx.sign_in(BOB).await;
    let bob = session_cookie(&fx.app).expect("session cookie");
    let resp = post_with_cookies(
        &fx.app,
        &first_action,
        &cookie_header(&[&bob, &first_flow]),
        &[
            ("csrf_token", &first_csrf),
            ("organization", &fx.gamma.id.to_string()),
        ],
    )
    .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    assert_eq!(stored_organization(&fx, &first).await, Some(None));
}

// ---------------------------------------------------------------------------------------------
// Org MFA
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn stricter_org_mfa_triggers_step_up() {
    let fx = fixture_with(Some(MfaPolicy::Required)).await;
    let seed = enrol_totp(&fx.app, ALICE).await;
    fx.sign_in(ALICE).await;
    assert_eq!(session_acr(&fx.app).await, ACR_PWD, "tenant MFA is off");
    fx.app.clock().advance(std::time::Duration::from_secs(60));

    // Beta has no policy of its own: the single-factor session is enough.
    let resp = fx
        .authorize(&[("organization", "beta"), ("prompt", "none")])
        .await;
    let body = fx.tokens(&resp).await;
    assert_eq!(id_claims(&body)["acr"], ACR_PWD);

    // Acme requires MFA: silently it cannot be met ...
    let resp = fx
        .authorize(&[("organization", "acme"), ("prompt", "none")])
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    assert!(param(&resp, "error").is_some(), "{}", location(&resp));
    assert!(param(&resp, "code").is_none());

    // ... and choosing it on the switcher asks for the second factor before any code.
    let path = fx.switcher(&[]).await;
    let resp = submit_form(&fx.app, &path, &[("organization", &fx.acme.id.to_string())]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(&fx.app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    assert!(param(&resp, "code").is_none());
    let page = fx.app.get(&login).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(html.contains("id=\"second-factor\""), "{html}");
    assert!(!html.contains("name=\"password\""), "no password re-entry");

    let code = totp_code(&seed, fx.app.clock().now().unix_timestamp());
    let resp = post_code(&fx.app, &page, &code).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(location(&resp).contains("/authorize/continue?request="));
    let resp = fx.app.get(&to_path(&fx.app, &location(&resp))).await;
    assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
    let claims = id_claims(&fx.tokens(&resp).await);
    assert_eq!(claims["acr"], ACR_MFA);
    assert_eq!(claims["org_id"], fx.acme.id.to_string());
    assert_eq!(session_acr(&fx.app).await, ACR_MFA, "upgraded in place");
}

// ---------------------------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn switcher_page_no_js_and_axe_selectors_present() {
    let fx = fixture().await;
    fx.sign_in(ALICE).await;
    let path = fx.switcher(&[]).await;
    let html = fx.app.get(&path).await.html();
    assert!(!html.contains("<script"), "works without JavaScript");
    assert!(
        html.contains("<form id=\"select-organization-form\" method=\"post\""),
        "{html}"
    );
    assert!(
        html.contains("<button type=\"submit\" id=\"select-organization-form-submit\">"),
        "{html}"
    );
    assert!(html.contains("<fieldset"), "radios are grouped: {html}");
    assert!(html.contains("<legend>"), "the group has a name: {html}");
    assert_eq!(element_text(&html, "select-organization-client"), "Test RP");
    for slug in ["acme", "beta"] {
        assert!(
            html.contains(&format!("<label for=\"organization-{slug}\"")),
            "every radio is labelled: {html}"
        );
        assert!(
            html.contains(&format!("id=\"organization-{slug}\" ")),
            "{html}"
        );
    }
    assert!(html.contains("Choose an organization"), "{html}");

    // German with ui_locales.
    let path = fx.switcher(&[("ui_locales", "de")]).await;
    let html = fx.app.get(&path).await.html();
    assert!(html.contains("lang=\"de\""), "{html}");
    assert!(html.contains("Organisation auswählen"), "{html}");
    assert!(html.contains(">Weiter</button>"), "{html}");
}
