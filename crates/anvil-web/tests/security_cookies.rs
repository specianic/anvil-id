//! Cookie attributes of the session and flow cookies (SEC-04) in production (https) and
//! development (http://localhost) mode. Selected backend via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use axum::http::header;
use support::{TestApp, TestResponse, csrf_from};
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

fn set_cookie(resp: &TestResponse, kind: &str) -> String {
    resp.headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.contains(kind) && !v.contains("Max-Age=0"))
        .unwrap_or_else(|| panic!("a Set-Cookie for {kind}: {:?}", resp.headers))
        .to_owned()
}

/// Returns the flow cookie header of the login GET and the session cookie header of the login
/// POST.
async fn cookies_of_a_login(app: &TestApp) -> (String, String) {
    register(app, "", EMAIL, PASSWORD).await;
    let get = app.get("/ui/login").await;
    let flow = set_cookie(&get, "anvil_flow_");
    let html = get.html();
    let resp = app
        .post_form(
            &form_action(app, &html),
            &[
                ("csrf_token", &csrf_from(&html)),
                ("identifier", EMAIL),
                ("password", PASSWORD),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    (flow, set_cookie(&resp, "anvil_session_"))
}

fn attrs(cookie: &str) -> Vec<String> {
    cookie
        .split(';')
        .skip(1)
        .map(|a| a.trim().to_ascii_lowercase())
        .collect()
}

#[tokio::test]
async fn production_cookies_are_host_prefixed_secure_and_strict() {
    let app = TestApp::new().await;
    let (flow, session) = cookies_of_a_login(&app).await;
    for (cookie, same_site) in [(&flow, "samesite=strict"), (&session, "samesite=lax")] {
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        let a = attrs(cookie);
        assert!(a.contains(&"secure".to_owned()), "{cookie}");
        assert!(a.contains(&"httponly".to_owned()), "{cookie}");
        assert!(a.contains(&"path=/".to_owned()), "{cookie}");
        assert!(a.contains(&same_site.to_owned()), "{cookie}");
        assert!(!a.iter().any(|x| x.starts_with("domain")), "{cookie}");
    }
}

#[tokio::test]
async fn development_cookies_have_no_prefix_and_no_secure() {
    let app = TestApp::dev().await;
    let (flow, session) = cookies_of_a_login(&app).await;
    for cookie in [&flow, &session] {
        assert!(!cookie.starts_with("__Host-"), "{cookie}");
        let a = attrs(cookie);
        assert!(!a.contains(&"secure".to_owned()), "{cookie}");
        assert!(a.contains(&"httponly".to_owned()), "{cookie}");
        assert!(a.contains(&"path=/".to_owned()), "{cookie}");
        assert!(!a.iter().any(|x| x.starts_with("domain")), "{cookie}");
    }
}

#[tokio::test]
async fn completing_a_flow_clears_the_flow_cookie() {
    let app = TestApp::new().await;
    cookies_of_a_login(&app).await;
    assert!(flow_cookie(&app).is_none());
    assert!(session_cookie(&app).is_some());
}
