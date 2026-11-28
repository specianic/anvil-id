//! No dead ends (07.1-08): every end-user error page is localized from the request
//! (`Accept-Language`, `ui_locales`), shows a friendly heading and explanation around the
//! unchanged contract sentence, a danger icon with a text label, technical detail only in
//! development mode, and a way forward for every error key. "Back to <app>" uses only a stored
//! static client's `initiate_login_uri` / `client_uri`, never a request value and never a DCR or
//! CIMD client's URL. Selected backend via `ANVILID_TEST_DB`.

mod support;
mod token_support;
mod ui_helpers;

use std::path::Path;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{ClientAuthMethod, ClientSource, ClientUpdate, ConsentMode, TenantId};
use axum::body::Body;
use axum::http::{Method, Request, header};
use support::{TestApp, TestResponse, location};
use token_support::{CHALLENGE, ClockNow as _, REDIRECT, Rp, register_with, web_input};
use ui_helpers::{default_tenant, error_key, to_path};

const ALICE: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";
const APP_LOGIN: &str = "https://shop.example/start-login";
const APP_HOME: &str = "https://shop.example/";
/// Hosts a request tries to smuggle into a link.
const EVIL: &str = "evil.example";

/// Ids of the way forward links an error page can render.
const WAY_FORWARD_IDS: [&str; 6] = [
    "link-back-to-app",
    "link-continue",
    "link-login",
    "link-account",
    "link-console",
    "link-home",
];

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// The message `id` of a shipped catalog file (`themes/default/locales/{tag}/{file}`).
fn catalog(tag: &str, file: &str, id: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../themes/default/locales")
        .join(tag)
        .join(file);
    let text = std::fs::read_to_string(&path).expect("catalog file");
    let prefix = format!("{id} = ");
    text.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("{id} in {}", path.display()))
        .to_owned()
}

/// The text minijinja renders for `s` (HTML escaping of `'` and `/`).
fn escaped(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('\'', "&#x27;")
        .replace('/', "&#x2f;")
}

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

/// The way forward link ids present on the page, in document order.
fn way_forward(html: &str) -> Vec<&'static str> {
    let mut found: Vec<(usize, &'static str)> = WAY_FORWARD_IDS
        .iter()
        .filter_map(|id| html.find(&format!("id=\"{id}\"")).map(|at| (at, *id)))
        .collect();
    found.sort_unstable();
    found.into_iter().map(|(_, id)| id).collect()
}

/// Every error page shows a friendly heading, the danger label, the explanation and a way
/// forward.
fn assert_friendly(resp: &TestResponse, key: &str) {
    let html = resp.text();
    assert_eq!(error_key(&html).as_deref(), Some(key), "{html}");
    assert!(html.contains("id=\"error-label\""), "{key}: danger label");
    assert!(
        html.contains("<svg") && html.contains("aria-hidden=\"true\""),
        "{key}: icon"
    );
    assert!(!html.contains(" style="), "{key}: no inline style (CSP)");
    assert!(html.contains("id=\"error-explanation\""), "{key}");
    assert!(
        !way_forward(&html).is_empty(),
        "{key}: a way forward on every error page:\n{html}"
    );
}

fn get_with(path: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut req = Request::get(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.body(Body::empty()).expect("request")
}

/// The `/authorize` query for `client_id` with `redirect_uri` and extra pairs.
fn authorize_query(client_id: &str, redirect_uri: &str, extra: &[(&str, &str)]) -> String {
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("scope", "openid"),
            ("state", "st-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ])
        .extend_pairs(extra.iter().copied())
        .finish();
    format!("/authorize?{q}")
}

/// A first-party client named Shop with the given source and home URLs.
async fn shop(
    app: &TestApp,
    tenant: TenantId,
    source: ClientSource,
    initiate_login_uri: Option<&str>,
    client_uri: Option<&str>,
) -> Rp {
    register_with(
        app,
        tenant,
        web_input(ClientAuthMethod::ClientSecretBasic),
        |c| {
            c.name = "Shop".into();
            c.consent_mode = ConsentMode::SkipFirstParty;
            c.registration_source = source;
            c.initiate_login_uri = initiate_login_uri.map(str::to_owned);
            c.client_uri = client_uri.map(str::to_owned);
        },
    )
    .await
}

// ---------------------------------------------------------------------------------------------
// Localization
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn not_found_is_localized_from_accept_language_and_ui_locales() {
    let app = TestApp::new().await;
    for req in [
        get_with("/nope", &[("accept-language", "de-DE,de;q=0.9,en;q=0.5")]),
        get_with("/nope?ui_locales=de", &[("accept-language", "en")]),
        get_with("/t/default/nope", &[("accept-language", "de")]),
    ] {
        let resp = app.send(req).await;
        assert_eq!(resp.status, 404);
        let html = resp.text();
        assert!(html.contains("<html lang=\"de\""), "{html}");
        assert!(html.contains(&escaped(&catalog(
            "de",
            "errors_friendly.ftl",
            "errors_friendly-heading-not_found"
        ))));
        assert!(html.contains(&catalog("de", "main.ftl", "error-not_found")));
        assert_friendly(&resp, "not_found");
        assert_eq!(way_forward(&html), ["link-login"]);
    }
    // English stays English.
    let resp = app.get("/nope").await;
    let html = resp.text();
    assert!(html.contains("<html lang=\"en\""));
    assert!(html.contains(&escaped("This page doesn't exist")), "{html}");
    assert!(html.contains("Page not found."));
}

#[tokio::test]
async fn unknown_tenant_page_is_localized_and_links_the_start_page() {
    let app = TestApp::new().await;
    let resp = app
        .send(get_with(
            "/t/no-such-tenant/ui/login",
            &[("accept-language", "de")],
        ))
        .await;
    assert_eq!(resp.status, 404);
    let html = resp.text();
    assert!(html.contains("<html lang=\"de\""), "{html}");
    assert_friendly(&resp, "not_found");
    assert_eq!(way_forward(&html), ["link-home"]);
    assert_eq!(
        href(&html, "link-home").as_deref(),
        Some("https://op.test/")
    );
}

#[tokio::test]
async fn signed_in_not_found_offers_the_account_and_sign_out() {
    let app = TestApp::new().await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;
    let resp = ui_helpers::login(&app, "", ALICE, PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.status);
    let resp = app.get("/nope").await;
    assert_eq!(resp.status, 404);
    let html = resp.text();
    assert_eq!(way_forward(&html), ["link-account"], "{html}");
    assert!(html.contains("id=\"form-sign-out\""));
    assert!(!html.contains("id=\"link-login\""));
}

#[tokio::test]
async fn authorize_errors_honour_ui_locales_and_keep_the_contract_sentence() {
    let app = TestApp::new().await;
    let rp = shop(
        &app,
        default_tenant(&app).id,
        ClientSource::Static,
        None,
        None,
    )
    .await;
    let resp = app
        .get(&authorize_query(
            rp.id(),
            "https://other.test/cb",
            &[("ui_locales", "de")],
        ))
        .await;
    assert_eq!(resp.status, 400);
    let html = resp.text();
    assert!(html.contains("<html lang=\"de\""), "{html}");
    assert!(html.contains(&catalog("de", "main.ftl", "error-redirect_uri_mismatch")));
    assert_friendly(&resp, "redirect_uri_mismatch");

    // The English contract sentences are byte-identical to main.ftl (conformance, e2e).
    let resp = app
        .get(&authorize_query(rp.id(), "https://other.test/cb", &[]))
        .await;
    let html = resp.text();
    let sentence = catalog("en", "main.ftl", "error-redirect_uri_mismatch");
    assert_eq!(
        sentence,
        "The redirect URI in this request is not registered for this client."
    );
    assert!(
        html.contains(&format!("role=\"alert\">{sentence}</p>")),
        "{html}"
    );
    let resp = app
        .get(&authorize_query("no-such-client", REDIRECT, &[]))
        .await;
    let sentence = catalog("en", "main.ftl", "error-unknown_client");
    assert_eq!(sentence, "This application is not registered.");
    assert!(resp.text().contains(&sentence));
    assert_friendly(&resp, "unknown_client");
}

#[tokio::test]
async fn csrf_and_rate_limit_pages_are_localized_with_a_way_forward() {
    let app = TestApp::new().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/ui/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header("accept-language", "de")
        .body(Body::from("identifier=a%40b.test&password=x"))
        .expect("request");
    let resp = app.send(req).await;
    assert_eq!(resp.status, 403);
    let html = resp.text();
    assert!(html.contains("<html lang=\"de\""), "{html}");
    assert!(html.contains(&catalog("de", "main.ftl", "error-csrf")));
    assert_friendly(&resp, "csrf");
    assert_eq!(
        href(&html, "link-login").as_deref(),
        Some("https://op.test/ui/login")
    );

    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(1, 1)).await;
    let post = || {
        Request::builder()
            .method(Method::POST)
            .uri("/ui/login?ui_locales=de")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from("identifier=a%40b.test&password=x"))
            .expect("request")
    };
    let mut limited = None;
    for _ in 0..5 {
        let resp = app.send(post()).await;
        if resp.status == 429 {
            limited = Some(resp);
            break;
        }
    }
    let resp = limited.expect("the auth class limits the second attempt");
    let html = resp.text();
    assert!(html.contains("<html lang=\"de\""), "{html}");
    assert!(html.contains(&catalog("de", "main.ftl", "error-too_many_requests")));
    assert_friendly(&resp, "too_many_requests");
}

// ---------------------------------------------------------------------------------------------
// Detail and way forward
// ---------------------------------------------------------------------------------------------

/// `POST /authorize` with a non-form body: an error page that carries a technical detail.
fn text_authorize() -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/authorize")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("client_id=x"))
        .expect("request")
}

#[tokio::test]
async fn error_detail_hidden_outside_dev_mode() {
    const DETAIL: &str = "application/x-www-form-urlencoded";
    let prod = TestApp::new().await;
    let resp = prod.send(text_authorize()).await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert_eq!(error_key(&html).as_deref(), Some("invalid_request"));
    assert!(!html.contains("id=\"error-detail\""), "{html}");
    assert!(!html.contains(DETAIL), "no technical detail in production");

    let dev = TestApp::dev().await;
    let resp = dev.send(text_authorize()).await;
    assert_eq!(resp.status, 400);
    let html = resp.html();
    assert!(html.contains("id=\"error-detail\""), "{html}");
    assert!(html.contains(DETAIL), "{html}");
}

#[tokio::test]
async fn every_error_key_has_a_way_forward() {
    let app = TestApp::new().await;
    let rp = shop(
        &app,
        default_tenant(&app).id,
        ClientSource::Static,
        None,
        None,
    )
    .await;
    let cases: Vec<(&str, TestResponse)> = vec![
        ("not_found", app.get("/nope").await),
        ("invalid_request", app.send(text_authorize()).await),
        (
            "unknown_client",
            app.get(&authorize_query("no-such-client", REDIRECT, &[]))
                .await,
        ),
        (
            "redirect_uri_mismatch",
            app.get(&authorize_query(rp.id(), "https://other.test/cb", &[]))
                .await,
        ),
        (
            "flow_expired",
            app.get("/authorize/continue?request=not-a-request").await,
        ),
        (
            "flow_expired",
            app.get("/authorize/continue?request=0190a6d4-0000-7000-8000-0000000000aa")
                .await,
        ),
        ("not_found", app.get("/theme/logo/0000").await),
    ];
    for (key, resp) in cases {
        assert_friendly(&resp, key);
    }
}

#[tokio::test]
async fn static_app_home_is_the_primary_way_forward() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app).id;
    let both = shop(
        &app,
        tenant,
        ClientSource::Static,
        Some(APP_LOGIN),
        Some(APP_HOME),
    )
    .await;
    let resp = app
        .get(&authorize_query(both.id(), "https://other.test/cb", &[]))
        .await;
    let html = resp.text();
    assert_eq!(
        way_forward(&html),
        ["link-back-to-app", "link-login"],
        "{html}"
    );
    assert_eq!(href(&html, "link-back-to-app").as_deref(), Some(APP_LOGIN));
    assert!(html.contains("Back to Shop"), "{html}");

    // client_uri when there is no initiate_login_uri.
    let home = shop(&app, tenant, ClientSource::Static, None, Some(APP_HOME)).await;
    let resp = app
        .get(&authorize_query(home.id(), "https://other.test/cb", &[]))
        .await;
    assert_eq!(
        href(&resp.text(), "link-back-to-app").as_deref(),
        Some(APP_HOME)
    );

    // Neither: sign-in only.
    let none = shop(&app, tenant, ClientSource::Static, None, None).await;
    let resp = app
        .get(&authorize_query(none.id(), "https://other.test/cb", &[]))
        .await;
    assert_eq!(way_forward(&resp.text()), ["link-login"]);
}

#[tokio::test]
async fn continuation_error_goes_back_to_the_static_app() {
    let app = TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await;
    let tenant = default_tenant(&app).id;
    let rp = shop(&app, tenant, ClientSource::Static, Some(APP_LOGIN), None).await;
    let resp = app.get(&authorize_query(rp.id(), REDIRECT, &[])).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let path = to_path(&app, &location(&resp));
    let request = path
        .strip_prefix("/ui/login?request=")
        .expect("sign-in with the request")
        .split('&')
        .next()
        .expect("id")
        .to_owned();
    // The client changed while the user was away: the stored redirect URI is gone.
    app.storage()
        .clients()
        .update(
            tenant,
            rp.id(),
            &ClientUpdate {
                redirect_uris: Some(vec!["https://rp.test/other".into()]),
                ..ClientUpdate::default()
            },
            app.clock_now(),
        )
        .await
        .expect("update")
        .expect("client exists");
    let resp = app
        .get(&format!("/authorize/continue?request={request}"))
        .await;
    assert_eq!(resp.status, 400);
    let html = resp.text();
    assert_eq!(error_key(&html).as_deref(), Some("redirect_uri_mismatch"));
    assert_eq!(way_forward(&html)[0], "link-back-to-app", "{html}");
    assert_eq!(href(&html, "link-back-to-app").as_deref(), Some(APP_LOGIN));
    // Never back into the same continuation.
    assert!(!html.contains("authorize&#x2f;continue"), "{html}");
}

#[tokio::test]
async fn app_home_never_from_request() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app).id;
    let rp = shop(&app, tenant, ClientSource::Static, None, None).await;
    let evil = format!("https://{EVIL}/x");
    for client_id in [rp.id(), "no-such-client"] {
        let path = authorize_query(
            client_id,
            &evil,
            &[
                ("client_uri", evil.as_str()),
                ("initiate_login_uri", evil.as_str()),
                ("post_logout_redirect_uri", evil.as_str()),
                ("return_to", evil.as_str()),
            ],
        );
        let resp = app
            .send(get_with(
                &path,
                &[
                    ("x-forwarded-host", EVIL),
                    ("referer", evil.as_str()),
                    ("origin", evil.as_str()),
                ],
            ))
            .await;
        assert_eq!(resp.status, 400);
        let html = resp.text();
        for id in WAY_FORWARD_IDS {
            if let Some(h) = href(&html, id) {
                assert!(!h.contains(EVIL), "#{id} -> {h}");
            }
        }
        assert!(!html.contains(EVIL), "{html}");
    }
}

#[tokio::test]
async fn app_home_never_for_dynamic_or_cimd_clients() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app).id;
    for (source, host) in [
        (ClientSource::Dynamic, "dcr-app.example"),
        (ClientSource::Cimd, "cimd-app.example"),
    ] {
        let login = format!("https://{host}/login");
        let home = format!("https://{host}/");
        let rp = shop(&app, tenant, source, Some(&login), Some(&home)).await;
        let resp = app
            .get(&authorize_query(rp.id(), "https://other.test/cb", &[]))
            .await;
        assert_eq!(resp.status, 400, "{source:?}");
        let html = resp.text();
        assert_eq!(error_key(&html).as_deref(), Some("redirect_uri_mismatch"));
        assert!(
            !html.contains("id=\"link-back-to-app\""),
            "{source:?}: {html}"
        );
        assert!(
            !html.contains(host),
            "{source:?}: no link to {host} anywhere"
        );
        assert_eq!(way_forward(&html), ["link-login"], "{source:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Tenant root pages
// ---------------------------------------------------------------------------------------------

/// Seeds the first administrator, so setup is complete.
async fn set_up(app: &TestApp) {
    let system = ui_helpers::system_tenant(app).id;
    token_support::seed_user(app, system, "admin@example.com").await;
}

#[tokio::test]
async fn root_pages_before_setup_show_setup_guidance() {
    let app = TestApp::new().await;
    for path in ["/", "/ui", "/t/system", "/t/default/ui"] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{path}");
        let html = resp.text();
        assert!(html.contains("Setup is not complete"), "{path}: {html}");
        assert!(
            html.contains("id=\"setup-command\">anvilid admin setup-url<"),
            "{path}"
        );
        assert!(!html.contains("id=\"link-login\""), "{path}");
    }
    let resp = app.send(get_with("/", &[("accept-language", "de")])).await;
    let html = resp.text();
    assert!(html.contains("<html lang=\"de\""));
    assert!(html.contains(&catalog(
        "de",
        "errors_friendly.ftl",
        "errors_friendly-setup_pending_title"
    )));
}

#[tokio::test]
async fn root_pages_signed_out_offer_sign_in_and_administration_on_the_default_tenant() {
    let app = TestApp::new().await;
    set_up(&app).await;
    ui_helpers::create_tenant(&app, "acme").await;
    for (path, admin) in [
        ("/", true),
        ("/ui", true),
        ("/t/default/", true),
        ("/t/system", false),
        ("/t/acme/ui", false),
    ] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 200, "{path}");
        assert_eq!(resp.header("cache-control"), Some("no-store"), "{path}");
        let html = resp.text();
        assert!(href(&html, "link-login").is_some(), "{path}: {html}");
        assert!(!html.contains("id=\"form-sign-out\""), "{path}");
        assert_eq!(
            href(&html, "link-administration").as_deref(),
            admin.then_some("https://op.test/console/"),
            "{path}"
        );
        assert!(!html.contains("setup-command"), "{path}");
    }
    assert_eq!(
        href(&app.get("/t/acme/").await.text(), "link-login").as_deref(),
        Some("https://op.test/t/acme/ui/login")
    );
}

#[tokio::test]
async fn root_page_signed_in_offers_account_and_sign_out() {
    let app = TestApp::new().await;
    set_up(&app).await;
    ui_helpers::register(&app, "", ALICE, PASSWORD).await;
    let resp = ui_helpers::login(&app, "", ALICE, PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.status);
    for path in ["/", "/ui"] {
        let resp = app.get(path).await;
        assert_eq!(resp.status, 200);
        let html = resp.text();
        assert_eq!(
            href(&html, "link-account").as_deref(),
            Some("https://op.test/ui/account/profile"),
            "{html}"
        );
        assert!(
            html.contains("id=\"form-sign-out\" method=\"post\""),
            "{html}"
        );
        assert!(!html.contains("id=\"link-login\""));
        assert!(html.contains("id=\"link-administration\""));
    }
}
