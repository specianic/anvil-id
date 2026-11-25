//! Theme stylesheet and logo routes (UI-03) over HTTP on the selected backend
//! (`ANVILID_TEST_DB`): defaults for an unbranded tenant, the tenant theme with ETag
//! revalidation, the client override resolved server-side from `?flow=`, fallback for flows of
//! another tenant, preview drafts, the logo rule and the logo route's caching headers, and the
//! theme link in every tenant page.

mod authz;
mod support;

use anvil_core::model::{AuditActor, BrandingScope, RequestContext, ThemeColors, ThemeTokens};
use anvil_core::service::branding::{BrandingInput, BrandingService};
use authz::*;
use axum::body::Body;
use axum::http::{Request, header};
use support::{TestApp, TestResponse};

fn service(app: &TestApp) -> BrandingService {
    BrandingService {
        storage: app.storage_arc(),
        clock: std::sync::Arc::new(app_clock(app)),
    }
}

/// The harness clock, shared through a thin wrapper.
struct ClockRef(time::OffsetDateTime);

impl anvil_core::ports::Clock for ClockRef {
    fn now(&self) -> time::OffsetDateTime {
        self.0
    }
}

fn app_clock(app: &TestApp) -> ClockRef {
    use anvil_core::ports::Clock as _;
    ClockRef(app.clock().now())
}

fn primary(hex: &str) -> BrandingInput {
    BrandingInput {
        tokens: ThemeTokens {
            colors: ThemeColors {
                primary: Some(hex.into()),
                ..ThemeColors::default()
            },
            ..ThemeTokens::default()
        },
        custom_css: None,
    }
}

async fn brand(app: &TestApp, scope: BrandingScope, input: BrandingInput) {
    let tenant = default_tenant(app);
    service(app)
        .put(
            tenant.id,
            &scope,
            input,
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .expect("branding stored");
}

/// A 1x1 PNG.
pub const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

fn assert_css(resp: &TestResponse) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("content-type"), Some("text/css; charset=utf-8"));
    assert_eq!(resp.header("cache-control"), Some("no-cache"));
    let etag = resp.header("etag").expect("etag");
    let digest = anvil_jose::encoding::sha256(&resp.body);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(etag, format!("\"{hex}\""));
}

/// The theme link of a rendered page (decoded path).
fn theme_link(html: &str) -> String {
    let marker = "<link rel=\"stylesheet\" href=\"";
    let mut links = html.match_indices(marker).map(|(i, _)| {
        let rest = &html[i + marker.len()..];
        rest[..rest.find('"').expect("quoted")].replace("&amp;", "&")
    });
    links
        .find(|l| l.contains("/theme/theme.css"))
        .unwrap_or_else(|| panic!("page links the theme: {html}"))
}

/// Starts an authorization request of `client_id` without a session and opens the sign-in
/// page; returns the page HTML.
async fn login_page(app: &TestApp, client_id: &str) -> String {
    let resp = get(app, &authorize_path("", &pkce_params(client_id)), None).await;
    let request = assert_login_redirect(&resp, &app.issuer(None));
    let resp = get(app, &format!("/ui/login?request={request}"), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.html()
}

#[tokio::test]
async fn unbranded_tenant_gets_defaults_and_a_hidden_logo() {
    let app = TestApp::new().await;
    let resp = app.get("/theme/theme.css").await;
    assert_css(&resp);
    assert_eq!(resp.text(), ".anvil-logo{display:none}\n");

    let html = app.get("/ui/login").await.html();
    // Linked right after anvil.css; the sign-in page is flow-bound, so the link carries it.
    assert!(
        html.contains("<link rel=\"stylesheet\" href=\"/assets/anvil.css\">\n<link rel=\"stylesheet\" href=\"/theme/theme.css?flow="),
        "theme link after anvil.css: {html}"
    );
    // A flow without an authorization request uses the tenant theme.
    let text = app.get(&theme_link(&html)).await.text();
    assert_eq!(text, ".anvil-logo{display:none}\n");
    assert!(
        html.contains("<span class=\"anvil-logo\" role=\"img\" aria-label=\"Default\"></span>"),
        "{html}"
    );
    // Path tenants link their own theme.
    create_path(&app, "acme").await;
    let html = app.get("/t/acme/ui/login").await.html();
    assert!(
        theme_link(&html).starts_with("/t/acme/theme/theme.css?flow="),
        "{html}"
    );
    // Pages without a flow link the plain tenant theme.
    let html = app.get("/t/acme/ui/no-such-page").await.html();
    assert_eq!(theme_link(&html), "/t/acme/theme/theme.css");
}

async fn create_path(app: &TestApp, slug: &str) -> anvil_core::model::Tenant {
    path_tenant(app, slug).await
}

#[tokio::test]
async fn tenant_theme_variables_and_etag_revalidation() {
    let app = TestApp::new().await;
    brand(&app, BrandingScope::Tenant, primary("#123456")).await;
    let resp = app.get("/theme/theme.css").await;
    assert_css(&resp);
    assert!(
        resp.text().contains("--anvil-primary:#123456"),
        "{}",
        resp.text()
    );
    let etag = resp.header("etag").expect("etag").to_owned();

    let req = Request::get("/theme/theme.css")
        .header(header::IF_NONE_MATCH, &etag)
        .body(Body::empty())
        .unwrap();
    let resp = app.send(req).await;
    assert_eq!(resp.status, 304);
    assert!(resp.body.is_empty());
    assert_eq!(resp.header("etag"), Some(etag.as_str()));

    // A change changes the tag; the old tag no longer matches.
    brand(&app, BrandingScope::Tenant, primary("#223344")).await;
    let req = Request::get("/theme/theme.css")
        .header(header::IF_NONE_MATCH, &etag)
        .body(Body::empty())
        .unwrap();
    let resp = app.send(req).await;
    assert_eq!(resp.status, 200);
    assert!(resp.text().contains("#223344"));
}

#[tokio::test]
async fn client_override_applies_on_that_clients_login_page_only() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let branded = web_client(&app, &tenant).await;
    let plain = web_client(&app, &tenant).await;
    brand(&app, BrandingScope::Tenant, primary("#123456")).await;
    brand(
        &app,
        BrandingScope::Client(branded.client_id.clone()),
        BrandingInput {
            custom_css: Some(".anvil-tenant{font-weight:700}".into()),
            ..primary("#654321")
        },
    )
    .await;

    let link = theme_link(&login_page(&app, &branded.client_id).await);
    assert!(link.starts_with("/theme/theme.css?flow="), "{link}");
    let css = app.get(&link).await;
    assert_css(&css);
    let text = css.text();
    assert!(text.contains("--anvil-primary:#654321"), "{text}");
    assert!(text.ends_with(".anvil-tenant{font-weight:700}\n"), "{text}");

    let link = theme_link(&login_page(&app, &plain.client_id).await);
    let text = app.get(&link).await.text();
    assert!(text.contains("--anvil-primary:#123456"), "{text}");
    assert!(!text.contains("#654321"));

    // Without a flow: the tenant theme.
    let text = app.get("/theme/theme.css").await.text();
    assert!(
        text.contains("#123456") && !text.contains("#654321"),
        "{text}"
    );
}

#[tokio::test]
async fn unknown_or_foreign_flows_fall_back_to_the_tenant_theme() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let client = web_client(&app, &tenant).await;
    brand(
        &app,
        BrandingScope::Client(client.client_id.clone()),
        primary("#654321"),
    )
    .await;
    let link = theme_link(&login_page(&app, &client.client_id).await);
    let flow = link.split("flow=").nth(1).expect("flow id").to_owned();

    // The default tenant's flow under another tenant: that tenant's own (unbranded) theme.
    create_path(&app, "other").await;
    let resp = app
        .get(&format!("/t/other/theme/theme.css?flow={flow}"))
        .await;
    assert_css(&resp);
    assert_eq!(resp.text(), ".anvil-logo{display:none}\n");

    // Malformed and unknown flow ids are not errors.
    for q in ["not-a-uuid", "0190f5b8-6b5e-7cc0-8b1a-1c2d3e4f5a6b", ""] {
        let resp = app.get(&format!("/theme/theme.css?flow={q}")).await;
        assert_css(&resp);
        assert_eq!(resp.text(), ".anvil-logo{display:none}\n", "{q}");
    }
}

#[tokio::test]
async fn preview_token_serves_the_draft() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    brand(&app, BrandingScope::Tenant, primary("#123456")).await;
    let draft = service(&app)
        .put_draft(tenant.id, &BrandingScope::Tenant, primary("#0a0b0c"))
        .await
        .expect("draft");
    let resp = app
        .get(&format!("/theme/theme.css?preview={}", draft.token))
        .await;
    assert_css(&resp);
    assert!(resp.text().contains("#0a0b0c"), "{}", resp.text());
    // The live theme is unchanged.
    assert!(app.get("/theme/theme.css").await.text().contains("#123456"));
    // An unknown token is not found.
    let resp = app
        .get(&format!(
            "/theme/theme.css?preview={}",
            anvil_jose::encoding::random_token()
        ))
        .await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn logo_rule_and_logo_route_headers() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    service(&app)
        .set_logo(
            tenant.id,
            &BrandingScope::Tenant,
            PNG.to_vec(),
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .expect("logo");
    let sha: String = anvil_jose::encoding::sha256(PNG)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let css = app.get("/theme/theme.css").await.text();
    assert!(
        css.contains(&format!("background-image:url(\"logo/{sha}\")")),
        "{css}"
    );
    assert!(css.contains(".anvil-logo{display:block"), "{css}");

    let resp = app.get(&format!("/theme/logo/{sha}")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, PNG);
    assert_eq!(resp.header("content-type"), Some("image/png"));
    assert_eq!(
        resp.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(resp.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        resp.header("content-security-policy"),
        Some("default-src 'none'")
    );
    // Unknown and malformed hashes.
    assert_eq!(
        app.get(&format!("/theme/logo/{}", "0".repeat(64)))
            .await
            .status,
        404
    );
    assert_eq!(app.get("/theme/logo/..%2f..%2fetc").await.status, 404);
}
