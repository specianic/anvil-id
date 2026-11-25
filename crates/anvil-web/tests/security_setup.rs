//! First-run setup page (ADM-03): single-use token, no default credentials, the management
//! client secret shown once and usable. Selected backend via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{DEFAULT_TENANT_SLUG, PageRequest, SYSTEM_TENANT_SLUG, TenantBase, issuer};
use anvil_core::ports::Clock as _;
use anvil_core::service::client_auth::ClientAuthInput;
use anvil_core::service::token::{TokenRequest, TokenService};
use base64::Engine as _;
use support::TestApp;
use ui_helpers::*;

const ADMIN: &str = "admin@example.com";
const PASSWORD: &str = "a long admin passphrase";

async fn user_count(app: &OwnApp, slug: &str) -> usize {
    let tenant = app.tenant(slug).await;
    app.storage
        .users()
        .list(
            tenant.id,
            PageRequest {
                after: None,
                limit: 200,
            },
        )
        .await
        .expect("list users")
        .items
        .len()
}

fn setup_path(token: &str) -> String {
    format!("/setup?token={token}")
}

/// Opens the setup form and returns `(action, csrf)`.
async fn open_setup(app: &OwnApp) -> (String, String) {
    open_form(app, &setup_path(&app.setup_token)).await
}

async fn post_setup(app: &OwnApp, action: &str, csrf: &str, token: &str) -> support::TestResponse {
    Client::post_form(
        app,
        action,
        &[
            ("csrf_token", csrf),
            ("token", token),
            ("email", ADMIN),
            ("password", PASSWORD),
        ],
    )
    .await
}

#[tokio::test]
async fn fresh_install_has_no_users_and_no_default_credentials() {
    let app = OwnApp::installed().await;
    assert_eq!(user_count(&app, SYSTEM_TENANT_SLUG).await, 0);
    assert_eq!(user_count(&app, DEFAULT_TENANT_SLUG).await, 0);
    // A typical default credential pair does not sign in anywhere.
    for (base, id) in [("", "admin"), ("/t/system", "admin@localhost")] {
        let resp = login(&app, base, id, "admin").await;
        assert_eq!(resp.status, 400, "{base}");
        app.clear_cookies();
    }
}

#[tokio::test]
async fn valid_token_shows_the_form_invalid_token_is_403_without_a_form() {
    let app = OwnApp::installed().await;
    let resp = Client::get(&app, &setup_path(&app.setup_token)).await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    assert!(html.contains("id=\"setup-submit\""), "{html}");
    assert!(html.contains("id=\"email\"") && html.contains("id=\"password\""));
    assert_eq!(resp.header("cache-control"), Some("no-store"));

    for path in ["/setup", "/setup?token=", "/setup?token=not-a-real-token"] {
        let resp = Client::get(&app, path).await;
        assert_eq!(resp.status, 403, "{path}");
        let html = resp.html();
        assert!(!html.contains("setup-submit"), "{path}: no form");
        assert_eq!(error_key(&html).as_deref(), Some("invalid_request"));
    }
    // Installation-level only: not below a tenant path.
    let resp = Client::get(&app, &format!("/t/system{}", setup_path(&app.setup_token))).await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn setup_creates_the_admin_and_a_working_management_client_once() {
    let app = OwnApp::installed().await;
    let (action, csrf) = open_setup(&app).await;
    assert!(action.starts_with("/setup?flow="), "{action}");
    let resp = post_setup(&app, &action, &csrf, &app.setup_token).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();
    let client_id = element_text(&html, "mgmt-client-id");
    let secret = element_text(&html, "mgmt-client-secret");
    assert!(client_id.starts_with("mgmt-"), "{client_id}");
    assert!(secret.len() >= 32, "secret shown");
    assert_eq!(element_text(&html, "admin-email"), ADMIN);
    assert_eq!(
        element_text(&html, "token-endpoint"),
        "https://op.test/t/system/token"
    );
    assert_eq!(
        element_text(&html, "admin-api-base"),
        "https://op.test/api/admin/v1"
    );
    assert_eq!(user_count(&app, SYSTEM_TENANT_SLUG).await, 1);
    assert_eq!(user_count(&app, DEFAULT_TENANT_SLUG).await, 0);

    // The secret authenticates a client_credentials request for the system tenant.
    let system = app.tenant(SYSTEM_TENANT_SLUG).await;
    let iss = issuer(
        &app.config.public_url,
        &TenantBase::Path(SYSTEM_TENANT_SLUG.to_owned()),
    );
    let tokens = TokenService {
        storage: Arc::clone(&app.storage),
        clock: Arc::clone(&app.clock) as Arc<dyn anvil_core::ports::Clock>,
        kek: Arc::clone(&app.kek),
    };
    let basic = |secret: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
        )
    };
    let request = |secret: &str| TokenRequest {
        grant_type: Some("client_credentials".to_owned()),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        scope: Some("admin:read".to_owned()),
        auth: ClientAuthInput {
            basic: Some(basic(secret)),
            client_id: None,
            client_secret: None,
            client_assertion_type: None,
            client_assertion: None,
        },
    };
    let ok = tokens
        .token(&system, &iss, request(&secret))
        .await
        .expect("the shown secret authenticates");
    assert!(!ok.access_token.is_empty());
    assert!(
        tokens
            .token(&system, &iss, request("wrong-secret"))
            .await
            .is_err(),
        "a wrong secret is rejected"
    );

    // The token is single-use: a second submission (fresh form, same token) is refused.
    let resp = Client::get(&app, &setup_path(&app.setup_token)).await;
    assert_eq!(resp.status, 403);
    let resp = post_setup(&app, &action, &csrf, &app.setup_token).await;
    assert_eq!(resp.status, 403);
    assert!(!resp.html().contains("mgmt-client-secret"));
    assert_eq!(user_count(&app, SYSTEM_TENANT_SLUG).await, 1);
}

#[tokio::test]
async fn expired_token_is_refused() {
    let app = OwnApp::installed().await;
    let (action, csrf) = open_setup(&app).await;
    app.clock.advance(Duration::from_secs(61 * 60));
    assert_eq!(
        Client::get(&app, &setup_path(&app.setup_token))
            .await
            .status,
        403
    );
    let resp = post_setup(&app, &action, &csrf, &app.setup_token).await;
    assert_eq!(resp.status, 403);
    assert_eq!(user_count(&app, SYSTEM_TENANT_SLUG).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_submissions_complete_setup_exactly_once() {
    let app = OwnApp::installed().await;
    let (action, csrf) = open_setup(&app).await;
    let token = app.setup_token.clone();
    let post = || post_setup(&app, &action, &csrf, &token);
    let results = tokio::join!(
        post(),
        post(),
        post(),
        post(),
        post(),
        post(),
        post(),
        post()
    );
    let all = [
        results.0, results.1, results.2, results.3, results.4, results.5, results.6, results.7,
    ];
    let done = all
        .iter()
        .filter(|r| r.status == 200 && r.html().contains("id=\"mgmt-client-secret\""))
        .count();
    assert_eq!(done, 1, "exactly one setup_done");
    // Losers are refused (403); with rate limiting on by default, submissions beyond the auth
    // burst from the same peer are refused earlier with 429. Either way only one setup wins.
    for r in &all {
        assert!(
            r.status == 200 || r.status == 403 || r.status == 429,
            "{}",
            r.status
        );
    }
    assert_eq!(user_count(&app, SYSTEM_TENANT_SLUG).await, 1);
}

#[tokio::test]
async fn setup_token_created_through_the_setup_repo_works_on_the_harness_app() {
    let app = TestApp::new().await;
    let (record, token) = anvil_core::service::bootstrap::build_setup_token(app.clock().now());
    app.storage()
        .setup()
        .create_setup_token(&record)
        .await
        .expect("create setup token");
    use secrecy::ExposeSecret as _;
    let resp = app.get(&setup_path(token.expose_secret())).await;
    assert_eq!(resp.status, 200);
    let resp = app.get("/setup?token=wrong").await;
    assert_eq!(resp.status, 403);
}

#[tokio::test]
async fn uninstalled_setup_answers_403() {
    let app = TestApp::uninstalled().await;
    assert_eq!(app.get("/setup?token=anything").await.status, 403);
}
