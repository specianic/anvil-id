//! Account security page and AccountService (AUTH-04, AUTH-05, ADM-04) on the selected backend
//! (`ANVILID_TEST_DB`): passkey registration, TOTP enrolment with recovery codes, regeneration,
//! removal, and the rejections (no session, CSRF, cross-site, stale session, garbage ceremonies,
//! replayed challenges, other users' credentials).
//!
//! A positive passkey registration through the page needs a real authenticator (Playwright, plan
//! 03-26); here the ceremony port is replaced by a test double for the service-level tests.

mod support;
mod ui_helpers;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::model::{
    ActorKind, AuditAction, AuditQuery, BrowserSession, CounterOutcome, CredentialKind, FlowId,
    NewPasskey, RecoveryCodeHash, RequestContext, SecretHash, TOTP_SEED_PURPOSE, Tenant, UserId,
    credential_aad,
};
use anvil_core::ports::{
    Challenge, Clock as _, PasskeyCeremonies, PasskeyError, PasskeyUser, RegisteredPasskey,
    RelyingParty,
};
use anvil_core::service::account::{
    AccountError, AccountFailure, AccountService, SettingsBinding, StartedSettings,
};
use anvil_jose::encoding::{b64url, secret_hash};
use anvil_jose::recovery_code::{normalize_recovery_code, recovery_code_hash};
use axum::body::Body;
use axum::http::{Method, Request, header};
use secrecy::ExposeSecret as _;
use support::{TestApp, TestResponse, csrf_from, location};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const PAGE: &str = "/ui/account/security";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// An app with a registered user who is signed in (session cookie in the jar).
async fn signed_in() -> TestApp {
    let app = TestApp::new().await;
    register(&app, "", EMAIL, PASSWORD).await;
    let resp = login(&app, "", EMAIL, PASSWORD).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session_cookie(&app).is_some());
    app
}

async fn user_id(app: &TestApp, email: &str) -> UserId {
    app.storage()
        .users()
        .get_by_email(default_tenant(app).id, email)
        .await
        .expect("lookup")
        .expect("user exists")
        .id
}

/// The session of the jar's session cookie.
async fn current_session(app: &TestApp) -> BrowserSession {
    let (_, token) = session_cookie(app).expect("session cookie");
    app.storage()
        .sessions()
        .get_active(
            default_tenant(app).id,
            &SecretHash(secret_hash(&token)),
            app.clock().now(),
        )
        .await
        .expect("session lookup")
        .expect("active session")
}

/// The `action` of the form with `id`, as a path.
fn action_of(app: &TestApp, html: &str, form_id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{form_id}\""))
        .unwrap_or_else(|| panic!("form #{form_id} in {html}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    to_path(app, &html[a..b].replace("&amp;", "&"))
}

fn flow_of(path: &str) -> FlowId {
    let id = path.split("flow=").nth(1).expect("flow parameter");
    FlowId(uuid::Uuid::parse_str(id).expect("flow id"))
}

async fn flow_state(app: &TestApp, flow: FlowId) -> Option<String> {
    app.storage()
        .flows()
        .get(default_tenant(app).id, flow, app.clock().now())
        .await
        .expect("flow lookup")
        .map(|f| f.state)
}

async fn open_page(app: &TestApp) -> String {
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.html()
}

async fn post(app: &TestApp, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
    app.post_form(path, pairs).await
}

fn element_attr_texts(html: &str, open: &str, close: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(open) {
        rest = &rest[i + open.len()..];
        let end = rest.find(close).expect("element closes");
        out.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    out
}

fn recovery_codes_on(html: &str) -> Vec<String> {
    element_attr_texts(html, "<li><code>", "</code>")
}

/// RFC 4648 base32 (no padding) decoder.
fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let v = ALPHABET.iter().position(|&a| a == c).expect("base32 char") as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) for `step`.
fn totp_code(secret: &[u8], step: u64) -> String {
    use aws_lc_rs::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let offset = usize::from(h[h.len() - 1] & 0x0f);
    let bin = (u32::from(h[offset]) & 0x7f) << 24
        | u32::from(h[offset + 1]) << 16
        | u32::from(h[offset + 2]) << 8
        | u32::from(h[offset + 3]);
    format!("{:06}", bin % 1_000_000)
}

fn current_step(app: &TestApp) -> u64 {
    u64::try_from(app.clock().now().unix_timestamp()).expect("positive") / 30
}

fn hash_of(app: &TestApp, code: &str) -> RecoveryCodeHash {
    let normalized = normalize_recovery_code(code).expect("valid code");
    RecoveryCodeHash(recovery_code_hash(app.kek(), &normalized))
}

async fn consume(app: &TestApp, user: UserId, code: &str) -> bool {
    app.storage()
        .users()
        .consume_recovery_code(
            default_tenant(app).id,
            user,
            &hash_of(app, code),
            app.clock().now(),
            None,
        )
        .await
        .expect("consume")
}

/// Events recorded by signing in (the `signed_in` helpers register and log in users). The account
/// tests assert their own events exactly and ignore only these.
/// Sign-in side effects of the helpers. `SessionRevoked` is one of them: signing a second user
/// in within the same browser revokes the first user's session (session switch, 04-16).
fn is_sign_in_event(action: AuditAction) -> bool {
    matches!(
        action,
        AuditAction::UserRegistered
            | AuditAction::LoginSucceeded
            | AuditAction::LoginFailed
            | AuditAction::SessionRevoked
    )
}

/// The audit log of the default tenant, newest first, without the sign-in events of the helpers.
async fn audit_actions(app: &TestApp) -> Vec<(AuditAction, ActorKind)> {
    app.storage()
        .audit()
        .query(
            default_tenant(app).id,
            &AuditQuery {
                limit: 100,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items
        .into_iter()
        .filter(|e| !is_sign_in_event(e.action))
        .map(|e| (e.action, e.actor.kind))
        .collect()
}

fn assert_no_store(resp: &TestResponse) {
    assert_eq!(resp.header("cache-control"), Some("no-store"));
}

// ---------------------------------------------------------------------------------------------
// HTTP: access, page contract, CSRF, re-authentication
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn without_a_session_every_route_sends_the_user_to_sign_in() {
    let app = TestApp::new().await;
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 303);
    assert_eq!(location(&resp), format!("{}/ui/login", app.issuer(None)));
    for path in [
        "/ui/account/security/totp",
        "/ui/account/security/passkey",
        "/ui/account/security/recovery-codes",
    ] {
        let resp = post(&app, path, &[("csrf_token", "x")]).await;
        assert_eq!(resp.status, 303, "{path}");
    }
    let resp = post(&app, "/ui/account/security/passkey/options", &[]).await;
    assert_eq!(resp.status, 401);
}

#[tokio::test]
async fn page_lists_credentials_and_loads_webauthn_js_without_inline_script() {
    let app = signed_in().await;
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 200);
    assert_no_store(&resp);
    let csp = resp.header("content-security-policy").expect("csp");
    assert!(csp.contains("script-src 'self'") && csp.contains("default-src 'none'"));
    assert!(!csp.contains("unsafe"), "{csp}");
    assert!(flow_cookie(&app).is_some(), "a settings flow is started");
    let html = resp.html();
    for id in [
        "id=\"passkey-register\"",
        "id=\"label\"",
        "id=\"response\"",
        "id=\"passkey-register-submit\"",
        "id=\"totp-begin\"",
        "id=\"totp-begin-submit\"",
        "id=\"passkeys-empty\"",
        "aria-current=\"page\"",
        "data-webauthn=\"register\"",
        "data-webauthn-status",
    ] {
        assert!(html.contains(id), "{id}");
    }
    assert!(
        html.contains(
            "data-options-url=\"https://op.test/ui/account/security/passkey/options?flow="
        )
    );
    // Exactly one script element: the self-hosted webauthn.js, no inline code or handlers.
    let scripts = element_attr_texts(&html, "<script", "</script>");
    assert_eq!(
        scripts,
        vec![" src=\"/assets/webauthn.js\" defer>".to_owned()]
    );
    assert!(!html.contains(" onclick=") && !html.contains(" style="));
    assert!(!html.contains("id=\"account-reauth\""), "fresh session");

    // A stored passkey is listed with its label, creation time and "never used".
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    app.storage()
        .users()
        .create_passkey(
            tenant.id,
            user,
            &fake_passkey(b"listed-cred", "Work laptop"),
        )
        .await
        .expect("store passkey");
    let html = open_page(&app).await;
    assert!(html.contains("Work laptop"));
    assert!(html.contains("2026-11-25 12:00 UTC"));
    assert!(html.contains(">Never<"));
    assert!(!html.contains("id=\"passkeys-empty\""));
}

#[tokio::test]
async fn posts_without_csrf_with_a_wrong_token_or_cross_site_are_rejected() {
    let app = signed_in().await;
    let html = open_page(&app).await;
    let action = action_of(&app, &html, "totp-begin");
    let csrf = csrf_from(&html);
    let flow = flow_of(&action);
    let before = flow_state(&app, flow).await.expect("flow");

    for pairs in [vec![], vec![("csrf_token", "wrong")]] {
        let resp = post(&app, &action, &pairs).await;
        assert_eq!(resp.status, 403, "{pairs:?}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    // Missing flow parameter.
    let resp = post(&app, "/ui/account/security/totp", &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 403);

    // Cross-site browser submission with the right token: stopped by the Fetch-Metadata layer.
    let body = format!("csrf_token={csrf}");
    let resp = app
        .send(
            Request::builder()
                .method(Method::POST)
                .uri(&action)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "cross-site")
                .body(Body::from(body))
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 403);
    assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));

    // Without the flow cookie (another browser) the token alone is not enough.
    let mut jar_without_flow = app.cookies();
    jar_without_flow.retain(|k, _| !k.contains("anvil_flow_"));
    let cookie = jar_without_flow
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ");
    let resp = app
        .send(
            Request::builder()
                .method(Method::POST)
                .uri(&action)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie)
                .body(Body::from(format!("csrf_token={csrf}")))
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 403);

    // The options endpoint checks the token too (form field or header).
    let options = to_path(&app, &attr(&html, "data-options-url"));
    let resp = post(&app, &options, &[("csrf_token", "wrong")]).await;
    assert_eq!(resp.status, 403);

    assert_eq!(
        flow_state(&app, flow).await.as_deref(),
        Some(before.as_str())
    );
    assert!(
        app.storage()
            .users()
            .totp(default_tenant(&app).id, user_id(&app, EMAIL).await)
            .await
            .expect("totp")
            .is_none()
    );
}

fn attr(html: &str, name: &str) -> String {
    let marker = format!("{name}=\"");
    let a = html.find(&marker).expect("attribute") + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    html[a..b].replace("&amp;", "&")
}

#[tokio::test]
async fn a_stale_session_must_sign_in_again_and_changes_nothing() {
    let app = signed_in().await;
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    app.storage()
        .users()
        .create_passkey(tenant.id, user, &fake_passkey(b"stale-cred", "Phone"))
        .await
        .expect("store passkey");
    // Open the page 10 minutes after sign-in (the flow lives 15 minutes from here) …
    app.clock().advance(Duration::from_secs(10 * 60));
    let html = open_page(&app).await;
    let csrf = csrf_from(&html);
    let totp = action_of(&app, &html, "totp-begin");
    let flow = flow_of(&totp);
    let passkey_id = app
        .storage()
        .users()
        .passkeys(tenant.id, user)
        .await
        .expect("passkeys")[0]
        .id;
    let delete = action_of(&app, &html, &format!("credential-delete-{passkey_id}"));
    let options = to_path(&app, &attr(&html, "data-options-url"));
    let before = flow_state(&app, flow).await.expect("flow");

    // … and submit 16 minutes after sign-in.
    app.clock().advance(Duration::from_secs(6 * 60));
    for path in [&totp, &delete] {
        let resp = post(&app, path, &[("csrf_token", &csrf)]).await;
        assert_eq!(resp.status, 400, "{path}: {}", resp.text());
        let html = resp.html();
        assert_eq!(
            message_keys(&html),
            vec!["account.reauth_required".to_owned()]
        );
        assert!(html.contains("id=\"link-reauth\""));
        assert!(html.contains("href=\"https://op.test/ui/login\""));
    }
    let resp = post(&app, &options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 400);
    assert_eq!(json_body(&resp)["error"], "account.reauth_required");

    assert_eq!(
        flow_state(&app, flow).await.as_deref(),
        Some(before.as_str())
    );
    assert_eq!(
        app.storage()
            .users()
            .passkeys(tenant.id, user)
            .await
            .expect("passkeys")
            .len(),
        1
    );
    assert!(
        app.storage()
            .users()
            .totp(tenant.id, user)
            .await
            .expect("totp")
            .is_none()
    );
    assert!(audit_actions(&app).await.is_empty());

    // Signing in again restores access.
    login(&app, "", EMAIL, PASSWORD).await;
    let html = open_page(&app).await;
    assert!(!html.contains("id=\"account-reauth\""));
    let resp = post(
        &app,
        &action_of(&app, &html, "totp-begin"),
        &[("csrf_token", &csrf_from(&html))],
    )
    .await;
    assert_eq!(resp.status, 200);
}

fn json_body(resp: &TestResponse) -> serde_json::Value {
    support::json(resp)
}

#[tokio::test]
async fn an_expired_settings_flow_shows_a_fresh_page() {
    let app = signed_in().await;
    let html = open_page(&app).await;
    let action = action_of(&app, &html, "totp-begin");
    let csrf = csrf_from(&html);
    app.clock().advance(Duration::from_secs(15 * 60));
    let resp = post(&app, &action, &[("csrf_token", &csrf)]).await;
    // Expired flow and stale session coincide here; the flow is checked first.
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.flow_expired".to_owned()]
    );
    assert_ne!(
        action_of(&app, &resp.html(), "totp-begin"),
        action,
        "new flow"
    );
}

// ---------------------------------------------------------------------------------------------
// HTTP: TOTP and recovery codes (no JavaScript)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn totp_enrolment_recovery_codes_regeneration_and_removal() {
    let app = signed_in().await;
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    let html = open_page(&app).await;
    let csrf = csrf_from(&html);
    let begin = action_of(&app, &html, "totp-begin");
    let flow = flow_of(&begin);

    // Begin: QR code (inline SVG) and the key grouped in fours.
    let resp = post(&app, &begin, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_no_store(&resp);
    let html = resp.html();
    assert!(html.contains("<svg") && html.contains("role=\"img\""));
    assert!(html.contains("autocomplete=\"one-time-code\""));
    assert!(html.contains("id=\"totp-confirm-submit\""));
    let grouped = element_text(&html, "totp-secret");
    assert!(grouped.split(' ').all(|g| g.len() <= 4), "{grouped}");
    let base32: String = grouped.split_whitespace().collect();
    let secret = base32_decode(&base32);
    assert_eq!(secret.len(), 20);

    // The flow holds only the sealed secret.
    let state = flow_state(&app, flow).await.expect("flow");
    assert!(state.contains("pending_totp"), "{state}");
    assert!(
        !state.contains(&base32) && !state.contains(&b64url(&secret)),
        "{state}"
    );
    assert!(
        app.storage()
            .users()
            .totp(tenant.id, user)
            .await
            .expect("totp")
            .is_none(),
        "nothing persisted yet"
    );

    // A wrong code keeps the pending secret and shows the same key again.
    let step = current_step(&app);
    let right = totp_code(&secret, step);
    let wrong = format!(
        "{:06}",
        (right.parse::<u32>().expect("digits") + 500_000) % 1_000_000
    );
    let confirm = action_of(&app, &html, "totp-confirm");
    let resp = post(&app, &confirm, &[("csrf_token", &csrf), ("code", &wrong)]).await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["account.totp_invalid_code".to_owned()]
    );
    assert!(html.contains("aria-invalid=\"true\""));
    assert_eq!(element_text(&html, "totp-secret"), grouped);
    assert_eq!(
        flow_state(&app, flow).await.as_deref(),
        Some(state.as_str())
    );

    // The right code enrols and shows 10 recovery codes once.
    let resp = post(&app, &confirm, &[("csrf_token", &csrf), ("code", &right)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_no_store(&resp);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["account.totp_enrolled".to_owned()]
    );
    assert!(html.contains("autocomplete=\"off\""));
    let codes = recovery_codes_on(&html);
    assert_eq!(codes.len(), 10);
    assert!(html.contains(&codes.join("\n")), "copyable block");

    // Stored: seed sealed under the credential AAD, 10 codes, the confirming step used.
    let totp = app
        .storage()
        .users()
        .totp(tenant.id, user)
        .await
        .expect("totp")
        .expect("enrolled");
    let opened = app
        .kek()
        .open(
            TOTP_SEED_PURPOSE,
            &credential_aad(totp.id),
            &totp.secret_enc,
        )
        .expect("seed opens under the credential AAD");
    assert_eq!(opened.as_slice(), secret.as_slice());
    assert_eq!(
        app.storage()
            .users()
            .recovery_codes_remaining(tenant.id, user)
            .await
            .expect("count"),
        10
    );
    let replay = app
        .storage()
        .users()
        .advance_totp_step(tenant.id, user, step, app.clock().now())
        .await
        .expect("advance");
    assert_eq!(
        replay,
        CounterOutcome::Stale,
        "the enrolment code cannot sign in again"
    );
    let state = flow_state(&app, flow).await.expect("flow");
    assert!(!state.contains("pending_totp"), "{state}");

    // Re-submitting (reload) does not show the codes again.
    let resp = post(&app, &confirm, &[("csrf_token", &csrf), ("code", &right)]).await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert_eq!(
        message_keys(&html),
        vec!["account.totp_not_pending".to_owned()]
    );
    assert!(recovery_codes_on(&html).is_empty());
    assert!(codes.iter().all(|c| !html.contains(c.as_str())));

    // The page shows TOTP status and remaining codes, never the codes; a second enrolment is
    // refused.
    let html = open_page(&app).await;
    assert_eq!(element_text(&html, "recovery-codes-count"), "10");
    assert!(codes.iter().all(|c| !html.contains(c.as_str())));
    assert!(!html.contains("id=\"totp-begin\""));
    let csrf = csrf_from(&html);

    assert!(consume(&app, user, &codes[0]).await);

    // Regenerate: new set, old codes stop working.
    let resp = post(
        &app,
        &action_of(&app, &html, "recovery-codes-regenerate"),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.recovery_codes_regenerated".to_owned()]
    );
    let fresh = recovery_codes_on(&resp.html());
    assert_eq!(fresh.len(), 10);
    assert!(fresh.iter().all(|c| !codes.contains(c)));
    assert!(!consume(&app, user, &codes[1]).await, "old set invalidated");
    assert!(consume(&app, user, &fresh[0]).await);

    // Remove TOTP: recovery codes go with it.
    let delete = action_of(&app, &html, &format!("credential-delete-{}", totp.id));
    let resp = post(&app, &delete, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.totp_removed".to_owned()]
    );
    assert!(
        app.storage()
            .users()
            .totp(tenant.id, user)
            .await
            .expect("totp")
            .is_none()
    );
    assert_eq!(
        app.storage()
            .users()
            .recovery_codes_remaining(tenant.id, user)
            .await
            .expect("count"),
        0
    );
    assert!(!consume(&app, user, &fresh[1]).await);

    // Regenerating without TOTP is refused.
    let resp = post(
        &app,
        &action_of(&app, &html, "recovery-codes-regenerate"),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.totp_required".to_owned()]
    );

    let actions: Vec<AuditAction> = audit_actions(&app)
        .await
        .into_iter()
        .map(|(a, k)| {
            assert_eq!(k, ActorKind::User);
            a
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            AuditAction::TotpRemoved,
            AuditAction::RecoveryCodesRegenerated,
            AuditAction::TotpEnrolled
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// HTTP: passkeys
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn passkey_options_require_discoverable_credentials_and_exclude_existing_ones() {
    let app = signed_in().await;
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    app.storage()
        .users()
        .create_passkey(tenant.id, user, &fake_passkey(b"existing-cred", "Old key"))
        .await
        .expect("store passkey");
    let html = open_page(&app).await;
    let csrf = csrf_from(&html);
    let options = to_path(&app, &attr(&html, "data-options-url"));
    let flow = flow_of(&options);

    let resp = post(&app, &options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("content-type"), Some("application/json"));
    assert_no_store(&resp);
    let body = json_body(&resp);
    let pk = &body["publicKey"];
    assert_eq!(pk["authenticatorSelection"]["residentKey"], "required");
    assert_eq!(pk["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(pk["rp"]["id"], "op.test");
    assert_eq!(pk["user"]["name"], EMAIL);
    let excluded: Vec<&str> = pk["excludeCredentials"]
        .as_array()
        .expect("exclude list")
        .iter()
        .map(|c| c["id"].as_str().expect("id"))
        .collect();
    assert_eq!(excluded, vec![b64url(b"existing-cred").as_str()]);
    assert!(
        flow_state(&app, flow)
            .await
            .expect("flow")
            .contains("pending_passkey")
    );

    // The header form of the CSRF token works as well.
    let resp = app
        .send(
            Request::builder()
                .method(Method::POST)
                .uri(&options)
                .header("sec-fetch-site", "same-origin")
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn garbage_or_unrequested_passkey_responses_store_nothing() {
    let app = signed_in().await;
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    let html = open_page(&app).await;
    let csrf = csrf_from(&html);
    let finish = action_of(&app, &html, "passkey-register");
    let options = to_path(&app, &attr(&html, "data-options-url"));
    let flow = flow_of(&finish);

    // No challenge was requested.
    let resp = post(
        &app,
        &finish,
        &[("csrf_token", &csrf), ("response", "{}"), ("label", "x")],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.passkey_failed".to_owned()]
    );

    // A challenge, then garbage: rejected, and the challenge is used up.
    assert_eq!(
        post(&app, &options, &[("csrf_token", &csrf)]).await.status,
        200
    );
    for response in ["garbage", "{\"id\":\"AAAA\",\"type\":\"public-key\"}"] {
        let resp = post(
            &app,
            &finish,
            &[
                ("csrf_token", &csrf),
                ("response", response),
                ("label", "Key"),
            ],
        )
        .await;
        assert_eq!(resp.status, 400, "{}", resp.text());
        assert_eq!(
            message_keys(&resp.html()),
            vec!["account.passkey_failed".to_owned()]
        );
        assert!(
            !flow_state(&app, flow)
                .await
                .expect("flow")
                .contains("pending_passkey")
        );
    }

    // An over-long label is refused before the challenge is touched.
    assert_eq!(
        post(&app, &options, &[("csrf_token", &csrf)]).await.status,
        200
    );
    let long = "x".repeat(65);
    let resp = post(
        &app,
        &finish,
        &[
            ("csrf_token", &csrf),
            ("response", "garbage"),
            ("label", &long),
        ],
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.invalid_label".to_owned()]
    );
    assert!(
        flow_state(&app, flow)
            .await
            .expect("flow")
            .contains("pending_passkey")
    );

    assert!(
        app.storage()
            .users()
            .passkeys(tenant.id, user)
            .await
            .expect("passkeys")
            .is_empty()
    );
    assert!(audit_actions(&app).await.is_empty());
}

#[tokio::test]
async fn removing_a_passkey_works_without_javascript_and_only_for_its_owner() {
    let app = signed_in().await;
    let tenant = default_tenant(&app);
    let user = user_id(&app, EMAIL).await;
    register(&app, "", "bob@example.com", PASSWORD).await;
    login(&app, "", EMAIL, PASSWORD).await;
    let bob = user_id(&app, "bob@example.com").await;
    let mine = fake_passkey(b"alice-cred", "Mine");
    let his = fake_passkey(b"bob-cred", "His");
    app.storage()
        .users()
        .create_passkey(tenant.id, user, &mine)
        .await
        .expect("store");
    app.storage()
        .users()
        .create_passkey(tenant.id, bob, &his)
        .await
        .expect("store");

    let html = open_page(&app).await;
    let csrf = csrf_from(&html);
    let mine_action = action_of(&app, &html, &format!("credential-delete-{}", mine.id));
    assert!(
        !html.contains(&his.id.to_string()),
        "other users' passkeys are not listed"
    );

    // Bob's credential id in Alice's form: not found, nothing deleted.
    let his_action = mine_action.replace(&mine.id.to_string(), &his.id.to_string());
    let resp = post(&app, &his_action, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.credential_not_found".to_owned()]
    );
    let bad = mine_action.replace(&mine.id.to_string(), "not-a-uuid");
    assert_eq!(post(&app, &bad, &[("csrf_token", &csrf)]).await.status, 400);
    assert_eq!(
        app.storage()
            .users()
            .passkeys(tenant.id, bob)
            .await
            .expect("passkeys")
            .len(),
        1
    );

    let resp = post(&app, &mine_action, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["account.passkey_removed".to_owned()]
    );
    assert!(resp.html().contains("id=\"passkeys-empty\""));
    assert!(
        app.storage()
            .users()
            .passkeys(tenant.id, user)
            .await
            .expect("passkeys")
            .is_empty()
    );
    assert_eq!(
        audit_actions(&app).await,
        vec![(AuditAction::PasskeyRemoved, ActorKind::User)]
    );
}

// ---------------------------------------------------------------------------------------------
// AccountService with a test double for the WebAuthn ceremonies
// ---------------------------------------------------------------------------------------------

fn fake_passkey(credential_id: &[u8], label: &str) -> NewPasskey {
    NewPasskey {
        id: anvil_core::model::CredentialId::new_v7(),
        credential_id: credential_id.to_vec(),
        passkey_json: "{}".into(),
        counter: 0,
        backup_eligible: false,
        label: label.into(),
        created_at: support::start_time(),
    }
}

/// Accepts any response whose text is the credential id; records the exclude lists.
#[derive(Default)]
struct FakeCeremonies {
    excluded: Mutex<Vec<Vec<Vec<u8>>>>,
}

impl PasskeyCeremonies for FakeCeremonies {
    fn start_registration(
        &self,
        _rp: &RelyingParty,
        _user: &PasskeyUser,
        exclude: &[Vec<u8>],
    ) -> Result<Challenge, CoreError> {
        self.excluded.lock().expect("lock").push(exclude.to_vec());
        Ok(Challenge {
            options_json: "{\"publicKey\":{}}".into(),
            state_json: format!(
                "{{\"challenge\":\"{}\"}}",
                anvil_jose::encoding::random_token()
            ),
        })
    }

    fn finish_registration(
        &self,
        _rp: &RelyingParty,
        response_json: &str,
        state_json: &str,
    ) -> Result<RegisteredPasskey, PasskeyError> {
        if response_json.is_empty() || !state_json.contains("challenge") {
            return Err(PasskeyError::Invalid);
        }
        Ok(RegisteredPasskey {
            credential_id: response_json.as_bytes().to_vec(),
            passkey_json: "{}".into(),
            counter: 0,
            backup_eligible: true,
        })
    }

    fn start_discoverable(&self, _rp: &RelyingParty) -> Result<Challenge, CoreError> {
        Err(CoreError::Internal("not used".into()))
    }

    fn identify(&self, _: &str) -> Result<anvil_core::ports::AssertionIdentity, PasskeyError> {
        Err(PasskeyError::Invalid)
    }

    fn finish_discoverable(
        &self,
        _: &RelyingParty,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<anvil_core::ports::VerifiedAssertion, PasskeyError> {
        Err(PasskeyError::Invalid)
    }
}

struct Fixture {
    app: TestApp,
    service: AccountService,
    fake: Arc<FakeCeremonies>,
    tenant: Tenant,
    session: BrowserSession,
    rp: RelyingParty,
}

async fn fixture() -> Fixture {
    let app = signed_in().await;
    let fake = Arc::new(FakeCeremonies::default());
    let service = AccountService {
        storage: app.storage_arc(),
        clock: Arc::new(SharedClock(app.clock().now())),
        kek: app.kek_arc(),
        passkeys: fake.clone(),
    };
    let tenant = default_tenant(&app);
    let session = current_session(&app).await;
    let rp = RelyingParty {
        rp_id: "op.test".into(),
        origin: "https://op.test".into(),
        name: "Default".into(),
    };
    Fixture {
        app,
        service,
        fake,
        tenant,
        session,
        rp,
    }
}

/// A fixed clock at the harness time (the service runs inside the sign-in window).
struct SharedClock(time::OffsetDateTime);

impl anvil_core::ports::Clock for SharedClock {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn binding(s: &StartedSettings) -> SettingsBinding<'_> {
    SettingsBinding {
        flow_id: s.flow_id,
        cookie_token: Some(s.cookie_token.expose_secret()),
        csrf_token: s.csrf_token.expose_secret(),
    }
}

fn failure<T: std::fmt::Debug>(r: Result<T, AccountError>) -> AccountFailure {
    match r {
        Err(AccountError::Failure(f)) => f,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn passkey_challenge_is_single_use_even_concurrently_and_duplicates_conflict() {
    let f = fixture().await;
    let ctx = RequestContext::system();
    let started = f
        .service
        .start(f.tenant.id, &f.session)
        .await
        .expect("start");
    let b = binding(&started);

    // Registration with a trimmed label; the challenge cannot be reused.
    f.service
        .begin_passkey(&f.tenant, &f.session, &b, &f.rp)
        .await
        .expect("begin");
    let id = f
        .service
        .finish_passkey(
            &f.tenant,
            &f.session,
            &b,
            &f.rp,
            "cred-1",
            "  Laptop  ",
            &ctx,
        )
        .await
        .expect("finish");
    let stored = f
        .app
        .storage()
        .users()
        .passkeys(f.tenant.id, f.session.user_id)
        .await
        .expect("passkeys");
    assert_eq!(stored.len(), 1);
    assert_eq!((stored[0].id, stored[0].label.as_str()), (id, "Laptop"));
    assert_eq!(stored[0].credential_id, b"cred-1");
    assert_eq!(
        failure(
            f.service
                .finish_passkey(&f.tenant, &f.session, &b, &f.rp, "cred-2", "", &ctx)
                .await
        ),
        AccountFailure::PasskeyFailed
    );

    // The next options exclude the registered credential.
    f.service
        .begin_passkey(&f.tenant, &f.session, &b, &f.rp)
        .await
        .expect("begin");
    assert_eq!(
        f.fake.excluded.lock().expect("lock").last().cloned(),
        Some(vec![b"cred-1".to_vec()])
    );

    // Two concurrent finishes of one challenge: exactly one registers.
    let (r1, r2) = tokio::join!(
        f.service
            .finish_passkey(&f.tenant, &f.session, &b, &f.rp, "cred-a", "", &ctx),
        f.service
            .finish_passkey(&f.tenant, &f.session, &b, &f.rp, "cred-b", "", &ctx),
    );
    assert_eq!(
        usize::from(r1.is_ok()) + usize::from(r2.is_ok()),
        1,
        "{r1:?} {r2:?}"
    );
    let loser = if r1.is_ok() { r2 } else { r1 };
    assert_eq!(failure(loser), AccountFailure::PasskeyFailed);

    // A credential id already registered in the tenant (here: another user's) is rejected.
    let bob = {
        register(&f.app, "", "bob@example.com", PASSWORD).await;
        user_id(&f.app, "bob@example.com").await
    };
    f.app
        .storage()
        .users()
        .create_passkey(f.tenant.id, bob, &fake_passkey(b"bob-cred", "Bob"))
        .await
        .expect("store");
    f.service
        .begin_passkey(&f.tenant, &f.session, &b, &f.rp)
        .await
        .expect("begin");
    assert_eq!(
        failure(
            f.service
                .finish_passkey(&f.tenant, &f.session, &b, &f.rp, "bob-cred", "", &ctx)
                .await
        ),
        AccountFailure::PasskeyExists
    );
    assert_eq!(
        f.app
            .storage()
            .users()
            .passkeys(f.tenant.id, f.session.user_id)
            .await
            .expect("passkeys")
            .len(),
        2
    );
    let registered = audit_actions(&f.app)
        .await
        .into_iter()
        .filter(|(a, _)| *a == AuditAction::PasskeyRegistered)
        .count();
    assert_eq!(registered, 2);
}

#[tokio::test]
async fn binding_owner_and_kind_are_enforced() {
    let f = fixture().await;
    let started = f
        .service
        .start(f.tenant.id, &f.session)
        .await
        .expect("start");
    let ctx = RequestContext::system();

    // Wrong cookie or CSRF token: Forbidden.
    let wrong_csrf = SettingsBinding {
        csrf_token: "nope",
        ..binding(&started)
    };
    let no_cookie = SettingsBinding {
        cookie_token: None,
        ..binding(&started)
    };
    for b in [wrong_csrf, no_cookie] {
        let r = f.service.begin_totp(&f.tenant, &f.session, &b).await;
        assert!(
            matches!(r, Err(AccountError::Core(CoreError::Forbidden))),
            "{r:?}"
        );
    }

    // Another user's session cannot use this flow.
    let mut other = f.session.clone();
    other.user_id = UserId::new_v7();
    let r = f
        .service
        .begin_totp(&f.tenant, &other, &binding(&started))
        .await;
    assert!(
        matches!(r, Err(AccountError::Core(CoreError::Forbidden))),
        "{r:?}"
    );

    // A stale session is refused before anything changes.
    let mut stale = f.session.clone();
    stale.auth_time -= time::Duration::minutes(16);
    assert_eq!(
        failure(
            f.service
                .begin_passkey(&f.tenant, &stale, &binding(&started), &f.rp)
                .await
        ),
        AccountFailure::ReauthRequired
    );
    assert_eq!(
        failure(
            f.service
                .regenerate_recovery_codes(&f.tenant, &stale, &binding(&started), &ctx)
                .await
        ),
        AccountFailure::ReauthRequired
    );

    // Unknown flow: expired.
    let unknown = SettingsBinding {
        flow_id: FlowId::new_v7(),
        ..binding(&started)
    };
    assert_eq!(
        failure(f.service.begin_totp(&f.tenant, &f.session, &unknown).await),
        AccountFailure::FlowExpired
    );

    // A TOTP confirmation without a pending enrolment.
    assert_eq!(
        failure(
            f.service
                .confirm_totp(&f.tenant, &f.session, &binding(&started), "123456", &ctx)
                .await
        ),
        AccountFailure::TotpNotPending
    );

    // With the right binding the enrolment starts and is held sealed in the flow.
    f.service
        .begin_totp(&f.tenant, &f.session, &binding(&started))
        .await
        .expect("begin");
    let state = flow_state(&f.app, started.flow_id).await.expect("flow");
    assert!(state.contains("pending_totp"));
}

#[tokio::test]
async fn admin_list_and_remove_audit_with_an_admin_actor() {
    let f = fixture().await;
    let user = f.session.user_id;
    let ctx = RequestContext::system();
    let pk = fake_passkey(b"admin-cred", "Key");
    f.app
        .storage()
        .users()
        .create_passkey(f.tenant.id, user, &pk)
        .await
        .expect("store");

    let listed = f.service.admin_list(f.tenant.id, user).await.expect("list");
    let kinds: Vec<CredentialKind> = listed.iter().map(|c| c.kind).collect();
    assert!(kinds.contains(&CredentialKind::Password) && kinds.contains(&CredentialKind::Webauthn));
    assert!(matches!(
        f.service.admin_list(f.tenant.id, UserId::new_v7()).await,
        Err(CoreError::NotFound)
    ));

    // Wrong user, unknown id and the password are not removable.
    let password = listed
        .iter()
        .find(|c| c.kind == CredentialKind::Password)
        .expect("password")
        .id;
    for (u, id) in [
        (UserId::new_v7(), pk.id),
        (user, anvil_core::model::CredentialId::new_v7()),
        (user, password),
    ] {
        assert!(matches!(
            f.service
                .admin_remove(f.tenant.id, u, id, "admin-1", &ctx)
                .await,
            Err(CoreError::NotFound)
        ));
    }
    let kind = f
        .service
        .admin_remove(f.tenant.id, user, pk.id, "admin-1", &ctx)
        .await
        .expect("remove");
    assert_eq!(kind, CredentialKind::Webauthn);
    assert!(
        f.app
            .storage()
            .users()
            .passkeys(f.tenant.id, user)
            .await
            .expect("passkeys")
            .is_empty()
    );
    let events = f
        .app
        .storage()
        .audit()
        .query(
            f.tenant.id,
            &AuditQuery {
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .items
        .into_iter()
        .filter(|e| !is_sign_in_event(e.action))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, AuditAction::PasskeyRemoved);
    assert_eq!(events[0].actor.kind, ActorKind::Admin);
    assert_eq!(events[0].actor.id.as_deref(), Some("admin-1"));
    assert_eq!(events[0].target, Some(pk.id.to_string()));
    assert!(password != pk.id);
}
