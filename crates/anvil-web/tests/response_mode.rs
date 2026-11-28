//! Response modes at the authorization endpoint (OIDC-25): `query` (default) and `form_post`,
//! for successes and for every error after redirect-URI validation, including the escaping of
//! reflected values and the per-response CSP of the form_post page.

mod authz;
mod support;

use authz::*;
use support::{TestApp, TestResponse, location};

fn with<'a>(
    mut p: Vec<(&'a str, &'a str)>,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    p.extend_from_slice(extra);
    p
}

fn replace<'a>(
    mut p: Vec<(&'a str, &'a str)>,
    key: &'a str,
    value: &'a str,
) -> Vec<(&'a str, &'a str)> {
    p.retain(|(k, _)| *k != key);
    p.push((key, value));
    p
}

/// Decodes the HTML entities minijinja's autoescape produces.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#x2f;", "/")
        .replace("&amp;", "&")
}

/// The value of attribute `name` inside a single tag's source.
fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = start + tag[start..].find('"')?;
    Some(unescape(&tag[start..end]))
}

/// Every tag `<{name} ...>` in the raw (escaped) body.
fn tags<'a>(raw: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i..];
        let end = after.find('>').expect("tag is closed");
        out.push(&after[..=end]);
        rest = &after[end + 1..];
    }
    out
}

/// A parsed form_post page.
struct FormPost {
    action: String,
    method: String,
    fields: Vec<(String, String)>,
}

impl FormPost {
    fn field(&self, name: &str) -> Option<&str> {
        let all: Vec<&str> = self
            .fields
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect();
        assert!(all.len() <= 1, "{name} appears more than once");
        all.first().copied()
    }
}

/// Asserts a well-formed form_post response (status, headers, markup) and parses its form.
fn assert_form_post(resp: &TestResponse, origin: &str) -> FormPost {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        resp.headers.get("location").is_none(),
        "form_post must not redirect"
    );
    assert!(
        resp.header("content-type")
            .is_some_and(|c| c.starts_with("text/html")),
        "{:?}",
        resp.header("content-type")
    );
    let csp = resp.header("content-security-policy").expect("CSP");
    assert!(csp.contains(&format!("form-action {origin};")), "{csp}");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("font-src 'self';"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    assert_eq!(resp.header("referrer-policy"), Some("no-referrer"));

    let raw = resp.text();
    let forms = tags(&raw, "form");
    assert_eq!(forms.len(), 1, "{raw}");
    let form = forms[0];
    let fields = tags(&raw, "input")
        .into_iter()
        .map(|t| {
            assert_eq!(attr(t, "type").as_deref(), Some("hidden"), "{t}");
            (
                attr(t, "name").expect("name"),
                attr(t, "value").expect("value"),
            )
        })
        .collect();

    // Only the self-hosted script, no inline script.
    let scripts = tags(&raw, "script");
    assert_eq!(scripts.len(), 1, "{raw}");
    assert_eq!(
        attr(scripts[0], "src").as_deref(),
        Some("/assets/form_post.js")
    );
    assert_eq!(raw.matches("</script>").count(), 1);
    assert!(raw.contains("<script src=") && !raw.contains("<script>"));
    // A visible fallback for browsers without JavaScript.
    let html = resp.html();
    assert!(html.contains("<noscript><button type=\"submit\""), "{html}");
    assert!(html.contains(">Continue</button></noscript>"), "{html}");

    FormPost {
        action: attr(form, "action").expect("action"),
        method: attr(form, "method").expect("method"),
        fields,
    }
}

const ORIGIN: &str = "https://rp.example";

#[tokio::test]
async fn form_post_success_posts_code_state_and_iss() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    let p = with(pkce_params(&c.client_id), &[("response_mode", "form_post")]);
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.action, RP);
    assert_eq!(f.method, "post");
    let names: Vec<&str> = f.fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["code", "state", "iss"]);
    assert_eq!(f.field("code").map(str::len), Some(43));
    assert_eq!(f.field("state"), Some("st-1"));
    assert_eq!(f.field("iss"), Some(iss.as_str()));
    assert!(f.field("error").is_none());
    // The page carries the visible "Continuing…" text.
    assert!(resp.html().contains("Continuing…"));
}

#[tokio::test]
async fn form_post_page_script_is_served_as_a_static_asset() {
    let app = TestApp::new().await;
    let resp = app.get("/assets/form_post.js").await;
    assert_eq!(resp.status, 200);
    assert!(
        resp.header("content-type")
            .is_some_and(|c| c.contains("javascript")),
        "{:?}",
        resp.header("content-type")
    );
    assert!(resp.text().contains("form-post"));
}

#[tokio::test]
async fn form_post_escapes_reflected_state() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    let evil = "\"><script>alert(1)</script><input name=\"code\" value=\"x";
    let p = replace(pkce_params(&c.client_id), "state", evil);
    let p = with(p, &[("response_mode", "form_post")]);
    let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
    let f = assert_form_post(&resp, ORIGIN);
    // The decoded value equals the original, and nothing was injected.
    assert_eq!(f.field("state"), Some(evil));
    assert_eq!(f.fields.len(), 3);
    let raw = resp.text();
    assert!(!raw.contains("<script>alert"), "{raw}");
    assert!(raw.contains("&lt;script&gt;alert(1)&lt;"), "{raw}");
}

#[tokio::test]
async fn form_post_login_required_is_a_post_form() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let p = with(
        pkce_params(&c.client_id),
        &[("response_mode", "form_post"), ("prompt", "none")],
    );
    let resp = get(&app, &authorize_path("", &p), None).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.action, RP);
    let names: Vec<&str> = f.fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["error", "error_description", "state", "iss"]);
    assert_eq!(f.field("error"), Some("login_required"));
    assert_eq!(f.field("state"), Some("st-1"));
    assert_eq!(f.field("iss"), Some(iss.as_str()));
    assert!(f.field("code").is_none());
}

#[tokio::test]
async fn form_post_validation_errors_are_post_forms() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let fp = with(pkce_params(&c.client_id), &[("response_mode", "form_post")]);
    let cases = [
        (
            replace(fp.clone(), "response_type", "token"),
            "unsupported_response_type",
        ),
        (replace(fp.clone(), "scope", "profile"), "invalid_scope"),
        (with(fp.clone(), &[("scope", "openid")]), "invalid_request"),
        (
            replace(fp.clone(), "code_challenge_method", "plain"),
            "invalid_request",
        ),
    ];
    for (p, error) in cases {
        let resp = get(&app, &authorize_path("", &p), None).await;
        let f = assert_form_post(&resp, ORIGIN);
        assert_eq!(f.field("error"), Some(error), "{p:?}");
        assert_eq!(f.field("iss"), Some(iss.as_str()));
    }
    // POST parity.
    let p = replace(fp, "response_type", "token");
    let resp = post(&app, "/authorize", &p, None).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.field("error"), Some("unsupported_response_type"));
    assert_eq!(f.field("state"), Some("st-1"));
}

#[tokio::test]
async fn invalid_redirect_with_form_post_is_an_error_page_without_a_form() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let fp = with(pkce_params(&c.client_id), &[("response_mode", "form_post")]);
    let cases = [
        (
            replace(fp.clone(), "redirect_uri", "https://evil.example/cb"),
            "redirect_uri_mismatch",
        ),
        (
            replace(fp.clone(), "client_id", "unknown"),
            "unknown_client",
        ),
    ];
    for (p, key) in cases {
        let resp = get(&app, &authorize_path("", &p), None).await;
        assert_error_page(&resp, key);
        let raw = resp.text();
        assert!(!raw.contains("<form"), "{raw}");
        assert!(!raw.contains("evil.example"), "{raw}");
        assert!(
            !resp
                .header("content-security-policy")
                .unwrap_or_default()
                .contains("form-action"),
            "the error page keeps the global CSP"
        );
    }
}

#[tokio::test]
async fn unsupported_response_mode_is_invalid_request_via_query() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    for mode in ["fragment", "FORM_POST", "x", "query.jwt"] {
        let p = with(pkce_params(&c.client_id), &[("response_mode", mode)]);
        let resp = get(&app, &authorize_path("", &p), None).await;
        assert_error_redirect(&resp, RP, "invalid_request", &iss);
        assert_eq!(param(&resp, "state").as_deref(), Some("st-1"), "{mode}");
    }
    // Repeated response_mode, even with supported values.
    let p = with(
        pkce_params(&c.client_id),
        &[
            ("response_mode", "form_post"),
            ("response_mode", "form_post"),
        ],
    );
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_redirect(&resp, RP, "invalid_request", &iss);
}

#[tokio::test]
async fn explicit_query_mode_redirects_like_the_default() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let cookie = session(&app, &t, u).await;
    for p in [
        with(pkce_params(&c.client_id), &[("response_mode", "query")]),
        pkce_params(&c.client_id),
    ] {
        let resp = get(&app, &authorize_path("", &p), Some(&cookie)).await;
        assert_eq!(resp.status, 303, "{}", resp.text());
        assert!(location(&resp).starts_with(&format!("{RP}?code=")));
        assert_eq!(param(&resp, "iss").as_deref(), Some(iss.as_str()));
        assert!(
            !resp
                .header("content-security-policy")
                .unwrap_or_default()
                .contains("form-action")
        );
    }
}

#[tokio::test]
async fn continue_after_login_honours_the_stored_form_post_mode() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let u = user(&app, &t, "alice@example.com").await;
    let p = with(pkce_params(&c.client_id), &[("response_mode", "form_post")]);
    let resp = get(&app, &authorize_path("", &p), None).await;
    let id = assert_login_redirect(&resp, &iss);
    let cookie = session(&app, &t, u).await;
    let path = format!("/authorize/continue?request={id}");
    let resp = get(&app, &path, Some(&cookie)).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.action, RP);
    assert_eq!(f.field("code").map(str::len), Some(43));
    assert_eq!(f.field("state"), Some("st-1"));
    assert_eq!(f.field("iss"), Some(iss.as_str()));
    // Still single-use.
    let resp = get(&app, &path, Some(&cookie)).await;
    assert_error_page(&resp, "flow_expired");
}

#[tokio::test]
async fn form_post_on_a_path_tenant_uses_that_tenant() {
    let app = TestApp::new().await;
    let t = path_tenant(&app, "acme").await;
    let iss = app.issuer(Some("acme"));
    let c = web_client(&app, &t).await;
    let p = with(
        pkce_params(&c.client_id),
        &[("response_mode", "form_post"), ("prompt", "none")],
    );
    let resp = get(&app, &authorize_path("/t/acme", &p), None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let raw = resp.text();
    let forms = tags(&raw, "form");
    assert_eq!(forms.len(), 1);
    assert_eq!(attr(forms[0], "action").as_deref(), Some(RP));
    assert!(
        resp.html().contains(&format!("value=\"{iss}\"")),
        "{}",
        resp.html()
    );
    assert!(resp.html().contains("src=\"/t/acme/assets/form_post.js\""));
}

#[tokio::test]
async fn form_post_to_a_loopback_redirect_allows_exactly_that_origin() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = native_client(&app, &t, &["http://127.0.0.1/cb"]).await;
    let p = vec![
        ("response_type", "code"),
        ("client_id", c.client_id.as_str()),
        ("redirect_uri", "http://127.0.0.1:53111/cb"),
        ("scope", "openid"),
        ("state", "s"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("response_mode", "form_post"),
        ("prompt", "none"),
    ];
    let resp = get(&app, &authorize_path("", &p), None).await;
    let f = assert_form_post(&resp, "http://127.0.0.1:53111");
    assert_eq!(f.action, "http://127.0.0.1:53111/cb");
    assert_eq!(f.field("error"), Some("login_required"));
}

/// An unsecured (`alg: none`) request object with `claims`.
fn unsigned_request_object(claims: &str) -> String {
    format!(
        "{}.{}.",
        anvil_jose::encoding::b64url(br#"{"alg":"none"}"#),
        anvil_jose::encoding::b64url(claims.as_bytes())
    )
}

#[tokio::test]
async fn rejected_request_object_is_delivered_with_its_form_post_mode() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let jwt = unsigned_request_object(&format!(
        r#"{{"iss":"{id}","aud":"{iss}","client_id":"{id}","response_type":"code","scope":"openid","redirect_uri":"{RP}","response_mode":"form_post","state":"obj-st"}}"#,
        id = c.client_id
    ));
    let mut p = pkce_params(&c.client_id);
    p.retain(|(k, _)| *k != "state");
    p.push(("request", jwt.as_str()));

    let resp = get(&app, &authorize_path("", &p), None).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.action, RP);
    assert_eq!(f.method, "post");
    let names: Vec<&str> = f.fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["error", "error_description", "state", "iss"]);
    assert_eq!(f.field("error"), Some("request_not_supported"));
    assert_eq!(f.field("state"), Some("obj-st"));
    assert_eq!(f.field("iss"), Some(iss.as_str()));

    // POST parity.
    let resp = post(&app, "/authorize", &p, None).await;
    let f = assert_form_post(&resp, ORIGIN);
    assert_eq!(f.field("error"), Some("request_not_supported"));
    assert_eq!(f.field("state"), Some("obj-st"));

    // The outer response_mode and state win over the object's.
    let p = with(
        pkce_params(&c.client_id),
        &[("response_mode", "query"), ("request", &jwt)],
    );
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_redirect(&resp, RP, "request_not_supported", &iss);
    assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
}

#[tokio::test]
async fn rejected_request_object_with_unusable_mode_falls_back_to_query() {
    let app = TestApp::new().await;
    let iss = app.issuer(None);
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let fragment = unsigned_request_object(r#"{"response_mode":"fragment","state":"obj-st"}"#);
    let oversized = unsigned_request_object(&format!(
        r#"{{"response_mode":"form_post","pad":"{}"}}"#,
        "a".repeat(8 * 1024)
    ));
    for jwt in [fragment.as_str(), "not.a-jwt", oversized.as_str()] {
        let p = with(pkce_params(&c.client_id), &[("request", jwt)]);
        let resp = get(&app, &authorize_path("", &p), None).await;
        assert_error_redirect(&resp, RP, "request_not_supported", &iss);
        assert_eq!(param(&resp, "state").as_deref(), Some("st-1"));
    }
}

#[tokio::test]
async fn request_object_with_invalid_redirect_is_an_error_page() {
    let app = TestApp::new().await;
    let t = default_tenant(&app);
    let c = web_client(&app, &t).await;
    let jwt = unsigned_request_object(&format!(
        r#"{{"response_mode":"form_post","redirect_uri":"{RP}","state":"obj-st"}}"#
    ));
    let p = replace(
        pkce_params(&c.client_id),
        "redirect_uri",
        "https://evil.example/cb",
    );
    let p = with(p, &[("request", &jwt)]);
    let resp = get(&app, &authorize_path("", &p), None).await;
    assert_error_page(&resp, "redirect_uri_mismatch");
    let raw = resp.text();
    assert!(!raw.contains("<form"), "{raw}");
    assert!(!raw.contains("evil.example"), "{raw}");
}
