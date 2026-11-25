//! RP-initiated logout (OIDC-12, OpenID Connect RP-Initiated Logout 1.0) end to end over HTTP on
//! the selected backend (`ANVILID_TEST_DB`): valid hint + registered URI logs out and redirects
//! with exactly `state`, revokes the session and its token families, clears the cookie, audits
//! `logout`, enqueues one back-channel delivery, and a later `prompt=none` is `login_required`;
//! expired hints; the confirmation page (no parameters, `client_id` without hint); logout without
//! a session; `ui_locales`; POST; discovery.

mod logout_support;
mod support;
mod token_support;

use anvil_core::model::AuditAction;
use anvil_core::ports::Clock as _;
use logout_support::*;
use support::json;
use token_support::REDIRECT;

fn query_of(url: &str) -> Vec<(String, String)> {
    url::Url::parse(url)
        .expect("absolute URL")
        .query_pairs()
        .into_owned()
        .collect()
}

#[tokio::test]
async fn valid_hint_and_registered_uri_log_out_and_redirect_with_state_only() {
    let f = fixture().await;
    let (id_token, refresh) = f.tokens().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &id_token),
            ("post_logout_redirect_uri", BYE),
            ("state", "xyz 1"),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=xyz+1"));
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    // The session cookie is cleared.
    let cleared = resp
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| c.contains("anvil_session") && c.contains("Max-Age=0"));
    assert!(cleared, "{:?}", resp.headers);

    assert!(!f.session_active().await, "the session is revoked");
    let audit = f.audit(AuditAction::Logout).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].target.as_deref(),
        Some(f.session.id.to_string().as_str())
    );
    assert_eq!(audit[0].details.as_map()["client_id"], f.rp.id());
    assert_eq!(
        f.deliveries().await,
        1,
        "one back-channel delivery enqueued"
    );

    // The token family issued under the session is revoked.
    let rt = refresh.expect("offline_access issues a refresh token");
    let r = token_support::refresh(&f.app, &f.rp, &rt, None).await;
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(json(&r)["error"], "invalid_grant");

    // The old cookie no longer signs in silently.
    let resp = f.authorize_prompt_none(Some(&f.cookie)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let l = loc(&resp);
    assert!(l.starts_with(REDIRECT), "{l}");
    assert!(
        query_of(&l).contains(&("error".into(), "login_required".into())),
        "{l}"
    );
}

#[tokio::test]
async fn a_registered_uri_with_its_own_query_keeps_it_and_no_state_adds_nothing() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", BYE_Q),
            ("state", "s"),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE_Q}&state=s"));

    // A second logout (no session any more) without state: exactly the registered URI.
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", BYE),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), BYE);
}

#[tokio::test]
async fn an_expired_hint_is_accepted() {
    let f = fixture().await;
    let now = f.app.clock().now().unix_timestamp();
    let mut claims = f.claims();
    claims["iat"] = (now - 7200).into();
    claims["exp"] = (now - 3600).into();
    let hint = f.sign(&claims).await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", BYE),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), BYE);
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn a_valid_hint_without_uri_shows_the_signed_out_page() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("state", "s"),
        ]))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert!(
        html.contains(r#"data-message-key="logout.signed_out""#),
        "{html}"
    );
    assert!(html.contains("You have been signed out."), "{html}");
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn no_parameters_confirm_then_sign_out() {
    let f = fixture().await;
    let resp = f.get("/logout").await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let l = loc(&resp);
    assert_eq!(l, format!("{}/ui/logout", f.iss));
    assert!(
        f.session_active().await,
        "nothing changes before confirming"
    );

    let page = f.get("/ui/logout").await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(page.header("cache-control"), Some("no-store"));
    let html = page.html();
    assert!(html.contains(">Sign out</button>"), "{html}");
    assert!(html.contains(r#"id="logout-cancel""#), "{html}");
    let (action, csrf) = confirm_form(&f.app, &page);
    assert!(action.starts_with("/ui/logout?flow="), "{action}");

    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let l = loc(&resp);
    assert_eq!(l, format!("{}/ui/signed-out", f.iss));
    assert!(
        !l.contains("/ui/logout"),
        "the signed-out page is not under /ui/logout"
    );
    assert!(!f.session_active().await);
    assert_eq!(f.audit(AuditAction::Logout).await.len(), 1);

    let done = f.get("/ui/signed-out").await;
    assert_eq!(done.status, 200);
    assert!(done.html().contains("You have been signed out."));

    // The flow is single use.
    let again = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(again.status, 400, "{}", again.text());
    assert!(
        again
            .html()
            .contains(r#"data-message-key="logout.expired""#)
    );
}

#[tokio::test]
async fn client_id_and_registered_uri_without_hint_confirm_then_redirect_with_state() {
    let f = fixture().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("client_id", f.rp.id()),
            ("post_logout_redirect_uri", BYE),
            ("state", "st"),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let l = loc(&resp);
    assert!(l.starts_with(&format!("{}/ui/logout?", f.iss)), "{l}");
    assert!(f.session_active().await);

    let page = f.get(l.strip_prefix(&f.iss).expect("same origin")).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert!(page.html().contains("Test RP"), "the page names the client");
    let (action, csrf) = confirm_form(&f.app, &page);
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=st"));
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn a_hint_for_another_session_asks_and_does_not_redirect() {
    let f = fixture().await;
    let mut claims = f.claims();
    claims["sid"] = "another-session".into();
    let hint = f.sign(&claims).await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", BYE),
            ("state", "s"),
        ]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let l = loc(&resp);
    assert!(l.starts_with(&format!("{}/ui/logout", f.iss)), "{l}");
    assert!(!l.contains("post_logout_redirect_uri"), "{l}");
    assert!(f.session_active().await);
}

#[tokio::test]
async fn logout_without_a_session_is_idempotent() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let path = Fx::logout_path(&[
        ("id_token_hint", &hint),
        ("post_logout_redirect_uri", BYE),
        ("state", "s"),
    ]);
    let resp = f.get_with(&path, None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=s"));
    assert!(
        f.session_active().await,
        "another browser's session is untouched"
    );
    assert!(f.audit(AuditAction::Logout).await.is_empty());
    assert_eq!(f.deliveries().await, 0);

    let resp = f
        .get_with(&Fx::logout_path(&[("id_token_hint", &hint)]), None)
        .await;
    assert_eq!(resp.status, 200);
    assert!(resp.html().contains("You have been signed out."));
}

#[tokio::test]
async fn post_logout_works_cross_site() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let resp = f
        .post(
            "/logout",
            &[
                ("id_token_hint", &hint),
                ("post_logout_redirect_uri", BYE),
                ("state", "p"),
            ],
            Some(&f.cookie),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=p"));
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn unknown_ui_locales_are_not_an_error() {
    let f = fixture().await;
    let resp = f.get("/logout?ui_locales=xx").await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let page = f.get("/ui/logout?ui_locales=xx").await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert!(page.html().contains(r#"lang="en""#));
    let hint = f.id_token().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("ui_locales", "xx yy"),
        ]))
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn cancel_keeps_the_session() {
    let f = fixture().await;
    let page = f.get("/ui/logout").await;
    let html = page.html().replace("&#x2f;", "/");
    assert!(html.contains("/ui/account/sessions"), "{html}");
    assert!(f.session_active().await);
}

#[tokio::test]
async fn discovery_advertises_logout() {
    let f = fixture().await;
    let resp = f.get_with("/.well-known/openid-configuration", None).await;
    assert_eq!(resp.status, 200);
    let doc = json(&resp);
    assert_eq!(doc["end_session_endpoint"], format!("{}/logout", f.iss));
    assert_eq!(doc["backchannel_logout_supported"], true);
    assert_eq!(doc["backchannel_logout_session_supported"], true);
    for absent in [
        "frontchannel_logout_supported",
        "frontchannel_logout_session_supported",
        "check_session_iframe",
    ] {
        assert!(doc.get(absent).is_none(), "{absent}");
    }
}
