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

use anvil_core::model::{ClientAuthMethod, ClientSource, TenantId};
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

// ---------------------------------------------------------------------------------------------
// Account header (U-H4)
// ---------------------------------------------------------------------------------------------

const APP_LOGIN: &str = "https://shop.example/start-login";
const APP_HOME: &str = "https://shop.example/";

/// The `href` of the element with `id`, decoded like a browser would (`None` when absent).
fn href(html: &str, id: &str) -> Option<String> {
    let start = html.find(&format!("id=\"{id}\""))?;
    let tag_end = html[start..].find('>')? + start;
    let tag_start = html[..start].rfind('<')?;
    let tag = &html[tag_start..tag_end];
    let marker = "href=\"";
    let at = tag.find(marker)? + marker.len();
    let end = tag[at..].find('"')? + at;
    Some(tag[at..end].replace("&#x2f;", "/").replace("&amp;", "&"))
}

/// A first-party client named Shop with the given source and home URLs.
async fn shop(
    app: &TestApp,
    tenant: TenantId,
    source: ClientSource,
    initiate_login_uri: Option<&str>,
    client_uri: Option<&str>,
) -> token_support::Rp {
    token_support::register_with(
        app,
        tenant,
        token_support::web_input(ClientAuthMethod::ClientSecretBasic),
        |c| {
            c.name = "Shop".into();
            c.registration_source = source;
            c.initiate_login_uri = initiate_login_uri.map(str::to_owned);
            c.client_uri = client_uri.map(str::to_owned);
        },
    )
    .await
}

/// Registers and signs in Alice on the default tenant.
async fn signed_in() -> TestApp {
    let app = app().await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;
    let resp = ui_helpers::login(&app, "", ALICE, PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    app
}

/// The header every account page shows: who is signed in and the sign-out form (a POST).
fn assert_header(html: &str, what: &str) {
    assert!(
        html.contains(&format!("<strong id=\"account-identity\">{ALICE}</strong>")),
        "{what}: identity\n{html}"
    );
    assert!(
        html.contains("<form id=\"form-sign-out\" method=\"post\" action=\"https:&#x2f;&#x2f;op.test&#x2f;logout\">"),
        "{what}: sign-out form\n{html}"
    );
}

#[tokio::test]
async fn every_account_page_shows_identity_and_sign_out() {
    let app = signed_in().await;
    for page in ACCOUNT_PAGES {
        let resp = app.get(page).await;
        assert_eq!(resp.status, 200, "{page}: {}", resp.text());
        let html = resp.text();
        assert_header(&html, page);
        assert!(!html.contains("id=\"link-back-to-app\""), "{page}");
        // Without a client the navigation links are the plain pages.
        assert_eq!(
            href(&html, "account-nav-security").as_deref(),
            Some("/ui/account/security"),
            "{page}"
        );
    }
}

#[tokio::test]
async fn account_sign_out_is_a_post_that_needs_the_confirmation() {
    let app = signed_in().await;
    // The form posts to the end-session endpoint: without an id_token_hint it only asks.
    let resp = app.post_form("/logout", &[]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(location(&resp), "https://op.test/ui/logout");
    assert_eq!(
        app.get("/ui/account/profile").await.status,
        200,
        "still signed in"
    );
    // A GET of the end-session endpoint signs nothing out either.
    let resp = app.get("/logout").await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(
        app.get("/ui/account/profile").await.status,
        200,
        "still signed in"
    );
    // A confirmation POST without its CSRF token changes nothing.
    let page = app.get("/ui/logout").await;
    assert_eq!(page.status, 200, "{}", page.text());
    let action = ui_helpers::form_action(&app, &page.html());
    let resp = app.post_form(&action, &[]).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(
        app.get("/ui/account/profile").await.status,
        200,
        "still signed in"
    );
    // The confirmation with its token signs out.
    let resp = ui_helpers::submit_form(&app, "/ui/logout", &[]).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    assert_eq!(
        app.get("/ui/account/profile").await.status,
        303,
        "signed out"
    );
}

#[tokio::test]
async fn account_header_links_back_to_a_static_app() {
    let app = signed_in().await;
    let tenant = ui_helpers::default_tenant(&app).id;
    let preferred = shop(
        &app,
        tenant,
        ClientSource::Static,
        Some(APP_LOGIN),
        Some(APP_HOME),
    )
    .await;
    let home_only = shop(&app, tenant, ClientSource::Static, None, Some(APP_HOME)).await;
    for (rp, expected) in [(&preferred, APP_LOGIN), (&home_only, APP_HOME)] {
        for page in ACCOUNT_PAGES {
            let resp = app
                .get(&format!("{page}?client_id={}", encoded(rp.id())))
                .await;
            assert_eq!(resp.status, 200, "{page}: {}", resp.text());
            let html = resp.text();
            assert_header(&html, page);
            assert_eq!(
                href(&html, "link-back-to-app").as_deref(),
                Some(expected),
                "{page}"
            );
            assert!(html.contains("Back to Shop"), "{page}");
            // The links between account pages keep the app.
            assert_eq!(
                href(&html, "account-nav-sessions"),
                Some(format!("/ui/account/sessions?client_id={}", rp.id())),
                "{page}"
            );
        }
    }

    // A static client without a home, an unknown id and another tenant's client: no link,
    // no error, and the value is never echoed.
    let no_home = shop(&app, tenant, ClientSource::Static, None, None).await;
    let other = ui_helpers::create_tenant(&app, "other").await;
    let foreign = shop(&app, other.id, ClientSource::Static, Some(APP_LOGIN), None).await;
    for client_id in [
        no_home.id(),
        "unknown-client",
        foreign.id(),
        "javascript:alert(1)",
        "",
    ] {
        let resp = app
            .get(&format!(
                "/ui/account/profile?client_id={}",
                encoded(client_id)
            ))
            .await;
        assert_eq!(resp.status, 200, "{client_id:?}: {}", resp.text());
        let html = resp.text();
        assert_header(&html, client_id);
        assert!(!html.contains("id=\"link-back-to-app\""), "{client_id:?}");
        assert!(!html.contains("shop.example"), "{client_id:?}");
        assert!(!html.contains("client_id="), "{client_id:?}: not echoed");
    }
}

#[tokio::test]
async fn account_header_never_links_dynamic_or_cimd_client() {
    let app = signed_in().await;
    let tenant = ui_helpers::default_tenant(&app).id;
    for (source, host) in [
        (ClientSource::Dynamic, "dcr-app.example"),
        (ClientSource::Cimd, "cimd-app.example"),
    ] {
        let login = format!("https://{host}/login");
        let home = format!("https://{host}/");
        let rp = shop(&app, tenant, source, Some(&login), Some(&home)).await;
        for page in ACCOUNT_PAGES {
            let resp = app
                .get(&format!("{page}?client_id={}", encoded(rp.id())))
                .await;
            assert_eq!(resp.status, 200, "{source:?} {page}: {}", resp.text());
            let html = resp.text();
            assert_header(&html, page);
            assert!(
                !html.contains("id=\"link-back-to-app\""),
                "{source:?} {page}: {html}"
            );
            assert!(
                !html.contains(host),
                "{source:?} {page}: no link to {host} anywhere"
            );
            assert!(
                !html.contains("client_id="),
                "{source:?} {page}: the id is not carried"
            );
        }
    }
}

/// The `action` of the form with `id`, as a path (`&amp;` decoded).
fn form_action_of(app: &TestApp, html: &str, id: &str) -> String {
    let start = html
        .find(&format!("<form id=\"{id}\""))
        .unwrap_or_else(|| panic!("form #{id}"));
    let marker = "action=\"";
    let a = html[start..].find(marker).expect("action") + start + marker.len();
    let b = html[a..].find('"').expect("quoted") + a;
    to_path(
        app,
        &html[a..b].replace("&amp;", "&").replace("&#x2f;", "/"),
    )
}

/// 07.1-21: an account form opened for a static client carries its `client_id` in the form
/// action, and the Post/Redirect/Get answer of a refused POST keeps it, so "Back to <app>" is
/// still there on the page that shows the refusal.
#[tokio::test]
async fn back_to_app_survives_a_refused_account_form() {
    let app = signed_in().await;
    let tenant = ui_helpers::default_tenant(&app).id;
    let rp = shop(&app, tenant, ClientSource::Static, None, Some(APP_HOME)).await;
    for (page, form, field) in [
        ("/ui/account/password", "password-form", "new_password"),
        ("/ui/account/profile", "profile-form", "locale"),
        ("/ui/account/email", "email-change", "new_email"),
    ] {
        let resp = app
            .get(&format!("{page}?client_id={}", encoded(rp.id())))
            .await;
        let html = resp.text();
        let action = form_action_of(&app, &html, form);
        assert!(
            action.ends_with(&format!("&client_id={}", encoded(rp.id()))),
            "{action}"
        );
        let csrf = support::csrf_from(&html);
        let resp = app
            .post_form(&action, &[("csrf_token", &csrf), (field, "x")])
            .await;
        assert!(support::is_prg(&resp), "{page}: {}", resp.status);
        let to = location(&resp);
        assert!(
            to.ends_with(&format!("&client_id={}", encoded(rp.id()))),
            "{to}"
        );
        let shown = app.follow(&resp).await;
        assert_eq!(shown.status, 400, "{page}");
        assert_eq!(message_keys(&shown.text()).len(), 1, "{page}");
        assert_eq!(
            href(&shown.text(), "link-back-to-app").as_deref(),
            Some(APP_HOME),
            "{page}"
        );
    }
}
