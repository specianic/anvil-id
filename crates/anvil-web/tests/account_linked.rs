//! Linked accounts page (AUTH-11, AUTH-13) on the selected backend (`ANVILID_TEST_DB`), against a
//! generic OIDC [`MockProvider`]: the list and the navigation entry, connecting a provider from
//! the page (purpose `Link`), disconnecting, and every refusal: the last way to sign in, another
//! user's link, a missing or wrong CSRF token or flow cookie, and a stale sign-in.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use std::time::Duration;

use anvil_core::model::{AuditAction, ConnectionUpdate, IdentityLink, User};
use anvil_core::ports::Clock as _;
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from};
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::MOCK_EMAIL;

const PASSWORD: &str = "correct horse battery";
const BOB: &str = "bob@example.com";
const PAGE: &str = "/ui/account/linked";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// Bob registers with a password and signs in.
async fn bob_signed_in(u: &Upstream) -> User {
    register(&u.app, "", BOB, PASSWORD).await;
    let resp = login(&u.app, "", BOB, PASSWORD).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    user(&u.app, BOB).await.expect("bob")
}

/// The linked accounts page (200).
async fn page(app: &TestApp) -> String {
    let resp = app.get(PAGE).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    resp.html()
}

/// The `action` of the form with `id` in `html`, as a path.
fn action_of(app: &TestApp, html: &str, id: &str) -> String {
    let marker = format!("<form id=\"{id}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("form {id} in {html}"));
    form_action(app, &html[start..])
}

/// Connects [`SLUG`] from the page: start (303 to the provider), token reply, callback.
async fn connect(u: &Upstream) -> TestResponse {
    let html = page(&u.app).await;
    let action = action_of(&u.app, &html, &format!("linked-connect-{SLUG}"));
    assert!(
        action.starts_with(&format!("{PAGE}/connect/{SLUG}?flow=")),
        "{action}"
    );
    let started = post_start(&u.app, &action, &csrf_from(&html)).await;
    reply_for(u, &started, json!({}));
    callback(u, &started).await
}

/// The page's unlink action and CSRF token for `link`.
async fn unlink_form(app: &TestApp, link: &IdentityLink) -> (String, String) {
    let html = page(app).await;
    (
        action_of(app, &html, &format!("linked-unlink-{}", link.id)),
        csrf_from(&html),
    )
}

fn assert_message(resp: &TestResponse, status: u16, key: &str) {
    assert_eq!(resp.status, status, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&key.to_owned()),
        "{key}: {}",
        resp.text()
    );
}

/// The upstream identity registers its own account (no password, one link) and is signed in.
async fn upstream_only_user(u: &Upstream) -> User {
    let resp = sign_in(u, json!({})).await;
    assert!(resp.status == 200 || resp.status == 303, "{}", resp.text());
    assert!(session(&u.app).await.is_some());
    user(&u.app, MOCK_EMAIL).await.expect("registered")
}

// ---------------------------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn page_needs_a_session_and_is_in_the_navigation() {
    let u = setup(true).await;
    let resp = u.app.get(PAGE).await;
    assert_eq!(resp.status, 303);
    assert!(support::location(&resp).ends_with("/ui/login"));

    bob_signed_in(&u).await;
    let resp = u.app.get(PAGE).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        resp.headers
            .get("cache-control")
            .map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    let html = resp.html().replace("&#x2f;", "/");
    assert!(
        html.contains(r#"id="account-nav-linked" href="/ui/account/linked" aria-current="page""#),
        "{html}"
    );
    assert!(html.contains("id=\"linked-none\""), "{html}");
    assert!(!html.contains("<script"), "no script");
    // The other account pages link here too.
    let security = u.app.get("/ui/account/security").await.html();
    assert!(security.contains("id=\"account-nav-linked\""));
}

#[tokio::test]
async fn page_lists_links_and_only_unlinked_enabled_connections() {
    let u = setup(true).await;
    let user = upstream_only_user(&u).await;
    let other = add_connection(&u.app, "other-id", "Other ID", u.conn.config.clone(), true).await;
    let disabled = add_connection(&u.app, "off-id", "Off ID", u.conn.config.clone(), true).await;
    u.app
        .storage()
        .connections()
        .update(
            tenant(&u.app).id,
            disabled.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            u.app.clock().now(),
        )
        .await
        .expect("update")
        .expect("connection");

    let html = page(&u.app).await;
    let link = &links(&u.app, &user).await[0];
    let row_start = html
        .find(&format!("id=\"linked-{}\"", link.id))
        .expect("row of the link");
    let row = &html[row_start..html[row_start..].find("</tr>").unwrap() + row_start];
    assert!(row.contains(NAME), "{row}");
    assert!(row.contains(MOCK_EMAIL), "email at link time: {row}");
    assert!(row.contains("<time datetime="), "{row}");
    // Connect buttons: the unlinked enabled connection only.
    assert!(html.contains(&format!("id=\"linked-connect-{}\"", other.slug)));
    assert!(!html.contains(&format!("id=\"linked-connect-{SLUG}\"")));
    assert!(!html.contains("id=\"linked-connect-off-id\""));
    // The upstream subject is never shown.
    assert!(!html.contains(&link.subject), "{html}");
}

// ---------------------------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn connect_links_the_signed_in_user() {
    let u = setup(true).await;
    let bob = bob_signed_in(&u).await;
    let resp = connect(&u).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let l = links(&u.app, &bob).await;
    assert_eq!(l.len(), 1);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].details.as_map()["mode"], "account");
    assert!(
        user(&u.app, MOCK_EMAIL).await.is_none(),
        "no account created"
    );

    let html = page(&u.app).await;
    assert!(
        html.contains(&format!("id=\"linked-{}\"", l[0].id)),
        "{html}"
    );
    assert!(!html.contains(&format!("id=\"linked-connect-{SLUG}\"")));
}

#[tokio::test]
async fn connect_refuses_an_identity_linked_to_another_user() {
    let u = setup(true).await;
    let first = upstream_only_user(&u).await;
    u.app.clear_cookies();
    let bob = bob_signed_in(&u).await;
    let resp = connect(&u).await;
    assert_message(&resp, 400, "upstream.already_linked");
    assert!(links(&u.app, &bob).await.is_empty());
    assert_eq!(links(&u.app, &first).await.len(), 1);
}

#[tokio::test]
async fn connect_needs_a_recent_sign_in_and_the_binding() {
    let u = setup(true).await;
    let bob = bob_signed_in(&u).await;
    let html = page(&u.app).await;
    let action = action_of(&u.app, &html, &format!("linked-connect-{SLUG}"));

    // No or a wrong CSRF token: 403, no redirect to the provider.
    for pairs in [vec![], vec![("csrf_token", "wrong")]] {
        let resp = u.app.post_form(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{pairs:?}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }

    // A stale sign-in on a live flow: the page shows the refusal, nothing starts.
    u.app.clock().advance(Duration::from_secs(10 * 60));
    let html = page(&u.app).await;
    let (action, csrf) = (
        action_of(&u.app, &html, &format!("linked-connect-{SLUG}")),
        csrf_from(&html),
    );
    u.app.clock().advance(Duration::from_secs(6 * 60));
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 400, "account.reauth_required");
    assert!(resp.html().contains("id=\"account-reauth\""));
    assert!(links(&u.app, &bob).await.is_empty());
    assert!(
        u.app
            .cookies()
            .keys()
            .all(|k| !k.contains("anvil_upstream_"))
    );
}

#[tokio::test]
async fn connect_to_an_unknown_connection_is_not_found() {
    let u = setup(true).await;
    bob_signed_in(&u).await;
    let html = page(&u.app).await;
    let action = action_of(&u.app, &html, &format!("linked-connect-{SLUG}"))
        .replace(&format!("/connect/{SLUG}"), "/connect/nope");
    let resp = u
        .app
        .post_form(&action, &[("csrf_token", &csrf_from(&html))])
        .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
}

// ---------------------------------------------------------------------------------------------
// Unlink
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn unlink_removes_the_link_when_a_password_remains() {
    let u = setup(true).await;
    let bob = bob_signed_in(&u).await;
    connect(&u).await;
    let link = links(&u.app, &bob).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &link).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 200, "linked.unlinked");
    assert!(links(&u.app, &bob).await.is_empty());
    let events = audit(&u.app, AuditAction::IdentityUnlinked).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].details.as_map()["connection"], SLUG);
    assert_eq!(events[0].details.as_map()["mode"], "account");
    // The page offers the connection again.
    assert!(
        resp.html()
            .contains(&format!("id=\"linked-connect-{SLUG}\""))
    );
}

#[tokio::test]
async fn unlink_of_the_only_sign_in_method_is_refused() {
    let u = setup(true).await;
    let user = upstream_only_user(&u).await;
    let link = links(&u.app, &user).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &link).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 409, "account.last_sign_in_method");
    assert_eq!(links(&u.app, &user).await.len(), 1);
    assert!(
        audit(&u.app, AuditAction::IdentityUnlinked)
            .await
            .is_empty()
    );

    // Once the tenant offers email sign-in codes, the link may go.
    tenant_settings(&u.app, |s| s.email_otp = true).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 200, "linked.unlinked");
    assert!(links(&u.app, &user).await.is_empty());
}

/// Sets the user's `email_verified` directly (independent of the connection's trust setting).
async fn set_email_verified(app: &TestApp, user: &User, verified: bool) {
    app.storage()
        .users()
        .update(
            user.tenant_id,
            user.id,
            &anvil_core::model::UserUpdate {
                email_verified: Some(verified),
                ..anvil_core::model::UserUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("user update")
        .expect("user exists");
}

#[tokio::test]
async fn unverified_email_is_not_a_remaining_sign_in_method() {
    let u = setup(true).await;
    let user = upstream_only_user(&u).await;
    set_email_verified(&u.app, &user, false).await;
    tenant_settings(&u.app, |s| {
        s.email_otp = true;
        s.magic_link = true;
    })
    .await;
    let link = links(&u.app, &user).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &link).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 409, "account.last_sign_in_method");
    assert_eq!(
        links(&u.app, &user).await.len(),
        1,
        "the link is kept: an unverified email is no way to sign in"
    );
    assert!(
        audit(&u.app, AuditAction::IdentityUnlinked)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn verified_email_with_email_sign_in_allows_unlink() {
    let u = setup(true).await;
    let user = upstream_only_user(&u).await;
    set_email_verified(&u.app, &user, true).await;
    tenant_settings(&u.app, |s| s.email_otp = true).await;
    let link = links(&u.app, &user).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &link).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 200, "linked.unlinked");
    assert!(links(&u.app, &user).await.is_empty());
    let events = audit(&u.app, AuditAction::IdentityUnlinked).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].details.as_map()["connection"], SLUG);
    assert_eq!(events[0].details.as_map()["mode"], "account");
}

#[tokio::test]
async fn unlink_with_another_link_left_is_allowed() {
    let u = setup(true).await;
    let user = upstream_only_user(&u).await;
    // A second connection to the same provider: the identity links there from the page.
    let second = add_connection(
        &u.app,
        "second-id",
        "Second ID",
        u.conn.config.clone(),
        true,
    )
    .await;
    let html = page(&u.app).await;
    let action = action_of(&u.app, &html, "linked-connect-second-id");
    let started = post_start(&u.app, &action, &csrf_from(&html)).await;
    reply_for(&u, &started, json!({}));
    let iss = u.mock.issuer();
    let resp = u
        .app
        .get(&callback_path(
            &second.slug,
            &[("code", "code-2"), ("state", &started.state), ("iss", &iss)],
        ))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(links(&u.app, &user).await.len(), 2);

    let first = links(&u.app, &user)
        .await
        .into_iter()
        .find(|l| l.connection_id == u.conn.id)
        .expect("first link");
    let (action, csrf) = unlink_form(&u.app, &first).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 200, "linked.unlinked");
    // The remaining link is now the last way in.
    let last = links(&u.app, &user).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &last).await;
    let resp = u.app.post_form(&action, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 409, "account.last_sign_in_method");
}

#[tokio::test]
async fn unlink_of_another_users_link_is_not_found() {
    let u = setup(true).await;
    let alice = upstream_only_user(&u).await;
    let alice_link = links(&u.app, &alice).await.remove(0);
    u.app.clear_cookies();
    bob_signed_in(&u).await;
    let html = page(&u.app).await;
    let i = html.find("flow=").expect("settings flow") + 5;
    let flow = &html[i..i + 36];
    let csrf = csrf_from(&html);
    let path = format!("{PAGE}/{}/unlink?flow={flow}", alice_link.id);
    let resp = u.app.post_form(&path, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 404, "account.link_not_found");
    assert_eq!(links(&u.app, &alice).await.len(), 1);
    // A malformed id is not found either.
    let path = format!("{PAGE}/not-a-uuid/unlink?flow={flow}");
    let resp = u.app.post_form(&path, &[("csrf_token", &csrf)]).await;
    assert_message(&resp, 404, "account.link_not_found");
    assert!(
        audit(&u.app, AuditAction::IdentityUnlinked)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn unlink_without_csrf_or_flow_cookie_is_forbidden() {
    let u = setup(true).await;
    let bob = bob_signed_in(&u).await;
    connect(&u).await;
    let link = links(&u.app, &bob).await.remove(0);
    let (action, csrf) = unlink_form(&u.app, &link).await;
    for pairs in [vec![], vec![("csrf_token", "wrong")]] {
        let resp = u.app.post_form(&action, &pairs).await;
        assert_eq!(resp.status, 403, "{pairs:?}");
        assert_eq!(error_key(&resp.html()).as_deref(), Some("csrf"));
    }
    // Without the query's flow id.
    let bare = action.split('?').next().unwrap().to_owned();
    let resp = u.app.post_form(&bare, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 403);
    // Without the flow cookie.
    let flow_name = flow_cookie(&u.app).expect("flow cookie").0;
    let cookies: Vec<String> = u
        .app
        .cookies()
        .into_iter()
        .filter(|(k, _)| *k != flow_name)
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let req = axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri(&action)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::COOKIE, cookies.join("; "))
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::from(format!("csrf_token={csrf}")))
        .expect("request");
    let resp = u.app.send(req).await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(links(&u.app, &bob).await.len(), 1);
    assert!(
        audit(&u.app, AuditAction::IdentityUnlinked)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn unlink_needs_a_recent_sign_in() {
    let u = setup(true).await;
    let bob = bob_signed_in(&u).await;
    connect(&u).await;
    let link = links(&u.app, &bob).await.remove(0);
    u.app.clock().advance(Duration::from_secs(16 * 60));
    let html = page(&u.app).await;
    assert!(html.contains("id=\"account-reauth\""), "{html}");
    let action = action_of(&u.app, &html, &format!("linked-unlink-{}", link.id));
    let resp = u
        .app
        .post_form(&action, &[("csrf_token", &csrf_from(&html))])
        .await;
    assert_message(&resp, 400, "account.reauth_required");
    assert_eq!(links(&u.app, &bob).await.len(), 1);
}
