//! The account area is reachable and leavable (07.1-12, U-H3, U-H4).
//!
//! A signed-out visit to an account page signs in and lands on that page: the sign-in link
//! carries `return_to`, an exact allowlist (`policy::return_to`) that only ever names the
//! tenant's own account paths, prefixed with the tenant's own UI origin. Anything else ends on the
//! normal signed-in page, and an authorization request always wins (`org_invitations`
//! `return_to_ignored_with_authorization_request`). Selected backend via `ANVILID_TEST_DB`.

mod support;
mod token_support;
mod ui_helpers;

use support::{TestApp, TestResponse, location};
use ui_helpers::{message_keys, to_path};

const ALICE: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery staple";

/// Every account page (one per account route).
const ACCOUNT_PAGES: [&str; 8] = [
    "/ui/account/profile",
    "/ui/account/email",
    "/ui/account/password",
    "/ui/account/security",
    "/ui/account/sessions",
    "/ui/account/apps",
    "/ui/account/linked",
    "/ui/account/attributes",
];

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

fn encoded(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

/// The answer is the normal signed-in page (no redirect anywhere).
fn signed_in_page(resp: &TestResponse, what: &str) {
    assert_eq!(resp.status, 200, "{what}: {}", resp.text());
    assert!(resp.header("location").is_none(), "{what}");
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{what}: {}",
        resp.text()
    );
}

/// Signs in through the sign-in page at `login_path` (a path on the public origin).
async fn sign_in(app: &TestApp, login_path: &str) -> TestResponse {
    ui_helpers::submit_form(
        app,
        login_path,
        &[("identifier", ALICE), ("password", PASSWORD)],
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// return_to (U-H3)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_signed_out_account_page_links_sign_in_returning_to_it() {
    let app = app().await;
    for page in ACCOUNT_PAGES {
        app.clear_cookies();
        let resp = app.get(page).await;
        assert_eq!(resp.status, 303, "{page}: {}", resp.text());
        assert_eq!(
            location(&resp),
            format!("https://op.test/ui/login?return_to={}", encoded(page)),
            "{page}"
        );
    }
}

#[tokio::test]
async fn return_to_account_targets_only_on_own_origin() {
    let app = app().await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;

    // Signed out: the account page sends the browser to sign-in with its own path.
    let resp = app.get("/ui/account/security").await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = location(&resp);
    assert_eq!(
        login,
        "https://op.test/ui/login?return_to=%2Fui%2Faccount%2Fsecurity"
    );

    // Signing in lands on that page, on the tenant's own UI origin.
    let resp = sign_in(&app, &to_path(&app, &login)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(&resp), "https://op.test/ui/account/security");
    let page = app.follow(&resp).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert!(
        page.text().contains("aria-current=\"page\""),
        "{}",
        page.text()
    );

    // Every account page round-trips.
    for target in ACCOUNT_PAGES {
        app.clear_cookies();
        let resp = sign_in(&app, &format!("/ui/login?return_to={}", encoded(target))).await;
        assert_eq!(resp.status, 303, "{target}: {}", resp.text());
        assert_eq!(location(&resp), format!("https://op.test{target}"));
    }

    // Forged values are ignored: the sign-in ends on the normal signed-in page.
    for forged in [
        "https://evil.example",
        "https://evil.example/ui/account/security",
        "//evil.example/ui/account/security",
        "/\\evil.example",
        "/ui/account/",
        "/ui/account/../x",
        "/ui/account/securityx",
        "/ui/account%2Fsecurity",
        "/ui/account/%2e%2e/security",
        "/t/other/ui/account/security",
        "/UI/account/security",
        "/ui/account/Security",
        "/ui/account/security\r\nLocation: https://evil.example",
        "/ui/account/security#frag",
        "/ui/account/security?x=1",
    ] {
        app.clear_cookies();
        let resp = sign_in(&app, &format!("/ui/login?return_to={}", encoded(forged))).await;
        signed_in_page(&resp, forged);
    }
}

#[tokio::test]
async fn return_to_account_path_stays_on_the_own_tenant() {
    let app = app().await;
    let acme = ui_helpers::create_tenant(&app, "acme").await;
    let mut settings = acme.settings.clone();
    settings.registration = anvil_core::model::RegistrationMode::Open;
    ui_helpers::set_settings(&app, acme.id, settings).await;
    ui_helpers::register(&app, "/t/acme", ALICE, PASSWORD).await;

    let resp = app.get("/t/acme/ui/account/sessions").await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = location(&resp);
    assert_eq!(
        login,
        "https://op.test/t/acme/ui/login?return_to=%2Fui%2Faccount%2Fsessions"
    );
    let resp = sign_in(&app, &to_path(&app, &login)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        location(&resp),
        "https://op.test/t/acme/ui/account/sessions"
    );

    // Another tenant's account path (or the default tenant's absolute one) is refused.
    for forged in [
        "/t/other/ui/account/sessions",
        "/t/acme/ui/account/sessions",
        "https://op.test/ui/account/sessions",
    ] {
        app.clear_cookies();
        let resp = sign_in(
            &app,
            &format!("/t/acme/ui/login?return_to={}", encoded(forged)),
        )
        .await;
        signed_in_page(&resp, forged);
    }
}
