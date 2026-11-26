//! Branding management API end to end (UI-03): CRUD for the tenant and client scopes, contrast
//! warnings, validation errors with field and CSS line, logo upload, the preview/publish flow and
//! the `branding_updated` audit rows. Organization branding (06-17): its API (also for the org's own
//! admin), and the sign-in page theme with precedence client > org > tenant when the authorization
//! request names the organization. Selected backend via `ANVILID_TEST_DB`.

mod admin_support;
mod authz;
mod support;
mod token_support;

use admin_support::*;
use anvil_cache::limiter::RateQuota;
use anvil_core::model::{AuditAction, AuditQuery, Tenant};
use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::{Value, json};
use support::{TestApp, TestResponse, json as body_json};

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.admin = RateQuota::per_second(100_000, 100_000)).await
}

async fn full(app: &TestApp) -> String {
    admin_token(app, "admin:read admin:write").await
}

const T: &str = "/api/admin/v1/tenants/default/branding";

async fn req(app: &TestApp, t: &str, m: Method, path: &str, body: Option<Value>) -> TestResponse {
    call(app, m, path, Some(t), body).await
}

/// A 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
    0x42, 0x60, 0x82,
];

async fn default_tenant(app: &TestApp) -> Tenant {
    app.default.as_ref().expect("installed").tenant.clone()
}

async fn new_client(app: &TestApp, t: &str) -> String {
    let resp = req(
        app,
        t,
        Method::POST,
        "/api/admin/v1/tenants/default/clients",
        Some(json!({
            "name": "Branded app",
            "client_type": "confidential",
            "redirect_uris": ["https://rp.example/cb"],
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    body_json(&resp)["client_id"].as_str().unwrap().to_owned()
}

async fn audit_count(app: &TestApp) -> usize {
    let tenant = default_tenant(app).await;
    app.storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::BrandingUpdated),
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit")
        .items
        .len()
}

#[tokio::test]
async fn tenant_branding_crud() {
    let app = app().await;
    let t = full(&app).await;

    let resp = req(&app, &t, Method::GET, T, None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    assert_eq!(v["customized"], false);
    assert_eq!(v["scope"], "tenant");

    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({
            "tokens": {"colors": {"primary": "#1D4ED8"}, "radius_px": 8, "font_family": "Georgia, serif"},
            "custom_css": ".anvil-tenant { font-weight: 700; }",
        })),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let v = body_json(&resp);
    assert_eq!(v["customized"], true);
    assert_eq!(v["tokens"]["colors"]["primary"], "#1D4ED8");
    assert_eq!(v["tokens"]["radius_px"], 8);
    assert_eq!(v["custom_css"], ".anvil-tenant { font-weight: 700; }");
    assert_eq!(v["warnings"], json!([]));
    assert!(v["updated_at"].is_string());

    let v = body_json(&req(&app, &t, Method::GET, T, None).await);
    assert_eq!(v["tokens"]["font_family"], "Georgia, serif");
    let css = app.get("/theme/theme.css").await.text();
    assert!(css.contains("--anvil-primary:#1d4ed8"), "{css}");
    assert!(css.contains(".anvil-tenant { font-weight: 700; }"), "{css}");

    let resp = req(&app, &t, Method::DELETE, T, None).await;
    assert_eq!(resp.status, 204, "{}", resp.text());
    let v = body_json(&req(&app, &t, Method::GET, T, None).await);
    assert_eq!(v["customized"], false);
    assert_problem(&req(&app, &t, Method::DELETE, T, None).await, 404);
    assert_eq!(audit_count(&app).await, 2);
}

#[tokio::test]
async fn contrast_warnings_and_refusals() {
    let app = app().await;
    let t = full(&app).await;
    // #777777 on white is about 4.48:1: accepted with a warning.
    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"colors": {"text": "#777777", "bg": "#ffffff", "surface": "#ffffff"}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    let ws = v["warnings"].as_array().expect("warnings");
    assert!(!ws.is_empty(), "{v}");
    assert_eq!(ws[0]["scheme"], "light");
    let ratio = ws[0]["ratio"].as_f64().unwrap();
    assert!((4.0..4.5).contains(&ratio), "{ratio}");
    // GET reports the stored tokens' warnings too.
    let v = body_json(&req(&app, &t, Method::GET, T, None).await);
    assert!(!v["warnings"].as_array().unwrap().is_empty());

    // Below 3:1 is refused.
    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"colors": {"text": "#bbbbbb", "bg": "#ffffff"}}})),
    )
    .await;
    assert_field_error(&resp, "colors");
}

#[tokio::test]
async fn validation_errors_name_field_and_css_line() {
    let app = app().await;
    let t = full(&app).await;
    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"colors": {"primary": "blue"}}})),
    )
    .await;
    assert_field_error(&resp, "colors.primary");

    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"radius_px": 64}})),
    )
    .await;
    assert_field_error(&resp, "radius_px");

    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"custom_css": ".a { color: red; }\n.b { color: blue; }\n.c { background: url(x) }"})),
    )
    .await;
    assert_field_error(&resp, "custom_css");
    let v = body_json(&resp);
    let msg = v["errors"][0]["message"].as_str().unwrap();
    assert!(msg.starts_with("line 3:"), "{msg}");

    let resp = req(
        &app,
        &t,
        Method::PUT,
        T,
        Some(json!({"tokens": {"nope": 1}})),
    )
    .await;
    assert_problem(&resp, 422);
    assert_eq!(audit_count(&app).await, 0, "failed calls record nothing");
}

#[tokio::test]
async fn client_branding_and_logo() {
    let app = app().await;
    let t = full(&app).await;
    let client_id = new_client(&app, &t).await;
    let base = format!("/api/admin/v1/tenants/default/clients/{client_id}/branding");

    let resp = req(
        &app,
        &t,
        Method::PUT,
        &base,
        Some(json!({"tokens": {"colors": {"primary": "#654321"}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    assert_eq!(v["scope"], "client");
    assert_eq!(v["client_id"], client_id);

    let data = anvil_jose::encoding::b64std(PNG);
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{base}/logo"),
        Some(json!({"data": data})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    let logo_url = v["logo_url"].as_str().expect("logo url").to_owned();
    assert!(logo_url.starts_with("/t/default/theme/logo/"), "{logo_url}");
    assert_eq!(v["tokens"]["colors"]["primary"], "#654321", "tokens kept");
    let resp = app.get(&logo_url).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, PNG);

    let resp = req(&app, &t, Method::DELETE, &format!("{base}/logo"), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(body_json(&resp)["logo_url"].is_null());
    assert_problem(
        &req(&app, &t, Method::DELETE, &format!("{base}/logo"), None).await,
        404,
    );

    // Unknown clients are not found.
    let resp = req(
        &app,
        &t,
        Method::GET,
        "/api/admin/v1/tenants/default/clients/nope/branding",
        None,
    )
    .await;
    assert_problem(&resp, 404);
    assert_eq!(audit_count(&app).await, 3);
}

#[tokio::test]
async fn logo_upload_near_the_limit_passes_the_body_limit() {
    let app = app().await;
    let t = full(&app).await;
    // A PNG signature followed by padding: 200 KiB decoded, about 270 KiB as JSON.
    let mut big = PNG[..8].to_vec();
    big.resize(200 * 1024, 0);
    let body = json!({"data": anvil_jose::encoding::b64std(&big)}).to_string();
    let resp = app
        .send(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("{T}/logo"))
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    // Other routes keep the 64 KiB limit.
    let body = json!({"custom_css": "a{}".repeat(30_000)}).to_string();
    let resp = app
        .send(
            Request::builder()
                .method(Method::PUT)
                .uri(T)
                .header(header::AUTHORIZATION, format!("Bearer {t}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, 413);
}

#[tokio::test]
async fn preview_then_publish() {
    let app = app().await;
    let t = full(&app).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{T}/preview"),
        Some(json!({"tokens": {"colors": {"primary": "#0a0b0c"}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    let token = v["token"].as_str().unwrap().to_owned();
    assert_eq!(
        v["preview_url"],
        format!("/t/default/ui/preview?token={token}")
    );
    assert!(v["expires_at"].is_string());
    // The draft is not live and not audited.
    assert!(!app.get("/theme/theme.css").await.text().contains("#0a0b0c"));
    assert_eq!(audit_count(&app).await, 0);

    // The preview page renders with the draft stylesheet.
    let page = app.get(v["preview_url"].as_str().unwrap()).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let link = format!("/t/default/theme/theme.css?preview={token}");
    assert!(html.contains(&link), "{html}");
    assert!(html.contains("id=\"preview-banner\""));
    assert!(app.get(&link).await.text().contains("#0a0b0c"));

    // Publishing with a token of another scope fails; with the right scope it goes live.
    let client_id = new_client(&app, &t).await;
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("/api/admin/v1/tenants/default/clients/{client_id}/branding/publish"),
        Some(json!({"token": token})),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{T}/publish"),
        Some(json!({"token": token})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["tokens"]["colors"]["primary"], "#0a0b0c");
    assert!(app.get("/theme/theme.css").await.text().contains("#0a0b0c"));
    assert_eq!(audit_count(&app).await, 1);

    // Preview drafts are validated like live input.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{T}/preview"),
        Some(json!({"custom_css": "@import 'x.css';"})),
    )
    .await;
    assert_field_error(&resp, "custom_css");
}

// ---------------------------------------------------------------------------------------------
// Organization branding (06-17)
// ---------------------------------------------------------------------------------------------

const O: &str = "/api/admin/v1/tenants/default/organizations/acme/branding";

#[tokio::test]
async fn org_branding_put_get_delete() {
    let app = app().await;
    let t = full(&app).await;
    let tenant = default_tenant(&app).await;
    let org = create_org(&app, tenant.id, "acme").await;

    let v = body_json(&req(&app, &t, Method::GET, O, None).await);
    assert_eq!(v["scope"], "org");
    assert_eq!(v["org_id"], org.id.to_string());
    assert_eq!(v["customized"], false);

    let resp = req(
        &app,
        &t,
        Method::PUT,
        O,
        Some(json!({"tokens": {"colors": {"primary": "#0F766E"}}, "custom_css": ".acme { font-weight: 700; }"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let v = body_json(&resp);
    assert_eq!(v["customized"], true);
    assert_eq!(v["tokens"]["colors"]["primary"], "#0F766E");
    // The same validation as the other scopes.
    let resp = req(
        &app,
        &t,
        Method::PUT,
        O,
        Some(json!({"custom_css": ".a{}\n@import \"x.css\";"})),
    )
    .await;
    assert_field_error(&resp, "custom_css");

    // Logo with the same limits.
    let data = anvil_jose::encoding::b64std(PNG);
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{O}/logo"),
        Some(json!({"data": data})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        body_json(&resp)["logo_url"]
            .as_str()
            .unwrap()
            .starts_with("/t/default/theme/logo/")
    );
    let svg = anvil_jose::encoding::b64std(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
    let resp = req(
        &app,
        &t,
        Method::PUT,
        &format!("{O}/logo"),
        Some(json!({"data": svg})),
    )
    .await;
    assert_problem(&resp, 422);
    let resp = req(&app, &t, Method::DELETE, &format!("{O}/logo"), None).await;
    assert_eq!(body_json(&resp)["logo_url"], Value::Null);

    // Preview, then publish.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{O}/preview"),
        Some(json!({"tokens": {"colors": {"primary": "#7C2D12"}}})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let token = body_json(&resp)["token"].as_str().unwrap().to_owned();
    let preview = app
        .get(&format!("/theme/theme.css?preview={token}"))
        .await
        .text();
    assert!(preview.contains("--anvil-primary:#7c2d12"), "{preview}");
    // A draft of another scope cannot be published here.
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{T}/publish"),
        Some(json!({"token": token})),
    )
    .await;
    assert_problem(&resp, 404);
    let resp = req(
        &app,
        &t,
        Method::POST,
        &format!("{O}/publish"),
        Some(json!({"token": token})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["tokens"]["colors"]["primary"], "#7C2D12");

    let resp = req(&app, &t, Method::DELETE, O, None).await;
    assert_eq!(resp.status, 204);
    assert_eq!(
        body_json(&req(&app, &t, Method::GET, O, None).await)["customized"],
        false
    );
    // Unknown org.
    let resp = req(
        &app,
        &t,
        Method::GET,
        "/api/admin/v1/tenants/default/organizations/nope/branding",
        None,
    )
    .await;
    assert_problem(&resp, 404);

    // Audited with the org scope as target.
    let events = app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                action: Some(AuditAction::BrandingUpdated),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    let target = format!("org:{}", org.id);
    assert_eq!(
        events
            .iter()
            .filter(|e| e.target.as_deref() == Some(target.as_str()))
            .count(),
        5
    );
}

/// Starts an authorization request of `client_id` (optionally naming an organization) and
/// returns the theme stylesheet the sign-in page links.
async fn sign_in_theme(app: &TestApp, client_id: &str, organization: Option<&str>) -> String {
    let mut params = authz::pkce_params(client_id);
    if let Some(o) = organization {
        params.push(("organization", o));
    }
    let resp = authz::get(app, &authz::authorize_path("", &params), None).await;
    let request = authz::assert_login_redirect(&resp, &app.issuer(None));
    let page = authz::get(app, &format!("/ui/login?request={request}"), None).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    let marker = "href=\"/theme/theme.css?flow=";
    let start = html.find(marker).expect("the page links the theme") + "href=\"".len();
    let link = &html[start..];
    let link = link[..link.find('"').unwrap()].replace("&amp;", "&");
    let css = app.get(&link).await;
    assert_eq!(css.status, 200, "{}", css.text());
    css.text()
}

async fn org_client(app: &TestApp, t: &str) -> String {
    let client_id = new_client(app, t).await;
    let resp = req(
        app,
        t,
        Method::PATCH,
        &format!("/api/admin/v1/tenants/default/clients/{client_id}"),
        Some(json!({"organization": "optional", "scopes": ["openid", "profile", "email"]})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    client_id
}

#[tokio::test]
async fn sign_in_page_uses_org_branding_when_request_names_org() {
    let app = app().await;
    let t = full(&app).await;
    let tenant = default_tenant(&app).await;
    let org = create_org(&app, tenant.id, "acme").await;
    let client_id = org_client(&app, &t).await;
    let put = |path: &'static str, color: &'static str, css: &'static str| {
        let app = &app;
        let t = &t;
        async move {
            let resp = req(
                app,
                t,
                Method::PUT,
                path,
                Some(json!({"tokens": {"colors": {"primary": color}}, "custom_css": css})),
            )
            .await;
            assert_eq!(resp.status, 200, "{}", resp.text());
        }
    };
    put(T, "#111111", ".tenant-rule{color:red}").await;
    put(O, "#222222", ".org-rule{color:red}").await;

    // By slug and by id: the org layer wins over the tenant, both custom CSS in order.
    for name in ["acme".to_owned(), org.id.to_string()] {
        let css = sign_in_theme(&app, &client_id, Some(&name)).await;
        assert!(css.contains("--anvil-primary:#222222"), "{name}: {css}");
        let (a, b) = (
            css.find(".tenant-rule").unwrap(),
            css.find(".org-rule").unwrap(),
        );
        assert!(a < b, "{css}");
    }
    // No org named, or an unknown one: the tenant theme.
    for org_param in [None, Some("globex")] {
        let css = sign_in_theme(&app, &client_id, org_param).await;
        assert!(
            css.contains("--anvil-primary:#111111"),
            "{org_param:?}: {css}"
        );
        assert!(!css.contains(".org-rule"), "{css}");
    }

    // Client branding still wins over the org's.
    let client_path = format!("/api/admin/v1/tenants/default/clients/{client_id}/branding");
    let resp = req(&app, &t, Method::PUT, &client_path, Some(json!({"tokens": {"colors": {"primary": "#333333"}}, "custom_css": ".client-rule{color:red}"}))).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let css = sign_in_theme(&app, &client_id, Some("acme")).await;
    assert!(css.contains("--anvil-primary:#333333"), "{css}");
    let (a, b, c) = (
        css.find(".tenant-rule").unwrap(),
        css.find(".org-rule").unwrap(),
        css.find(".client-rule").unwrap(),
    );
    assert!(a < b && b < c, "{css}");
}

#[tokio::test]
async fn org_admin_can_brand_own_org_only() {
    let app = TestApp::with(|c| c.rate_limits.enabled = false).await;
    let tenant = default_tenant(&app).await;
    let acme = create_org(&app, tenant.id, "acme").await;
    let globex = create_org(&app, tenant.id, "globex").await;
    let role = create_role(&app, tenant.id, Some(acme.id), "org-admins", &["org:admin"]).await;
    let admin = token_support::seed_user(&app, tenant.id, "ada@example.test").await;
    add_member(&app, tenant.id, acme.id, admin.id, &[role.id]).await;
    let token = org_admin_token(&app, &tenant, acme.id, admin.id)
        .await
        .token;
    let body = json!({"tokens": {"colors": {"primary": "#0F766E"}}});

    let resp = req(&app, &token, Method::PUT, O, Some(body.clone())).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let resp = req(&app, &token, Method::GET, O, None).await;
    assert_eq!(resp.status, 200);

    let g = "/api/admin/v1/tenants/default/organizations/globex/branding";
    for (m, path, b) in [
        (Method::GET, g.to_owned(), None),
        (Method::PUT, g.to_owned(), Some(body.clone())),
        (Method::DELETE, g.to_owned(), None),
        (
            Method::PUT,
            format!("{g}/logo"),
            Some(json!({"data": anvil_jose::encoding::b64std(PNG)})),
        ),
        (Method::POST, format!("{g}/preview"), Some(body.clone())),
    ] {
        let resp = req(&app, &token, m, &path, b).await;
        assert_problem(&resp, 403);
    }
    // Tenant and client branding stay closed to org admins.
    let resp = req(&app, &token, Method::PUT, T, Some(body.clone())).await;
    assert_problem(&resp, 401);
    let globex_branding = app
        .storage()
        .branding()
        .get(
            tenant.id,
            &anvil_core::model::BrandingScope::Org(globex.id).scope_key(),
        )
        .await
        .unwrap();
    assert!(globex_branding.is_none());
}
