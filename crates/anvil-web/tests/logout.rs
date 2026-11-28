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

// ---------------------------------------------------------------------------------------------
// No dead ends (07.1-20): no prompt without a session, "Stay signed in" back to the app, the
// signed-out and error pages offer a way forward; third-party client URLs are never rendered.
// ---------------------------------------------------------------------------------------------

/// A static client's sign-in entry point (preferred home).
const APP_LOGIN: &str = "https://shop.test/login";
/// A static client's home page.
const APP_HOME: &str = "https://shop.test/";
/// A URL a DCR or CIMD client chose itself.
const THIRD_PARTY: &str = "https://third-party.test/home";

/// The `href` of the element with `id` (escapes decoded).
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

/// Gives the fixture's (static) client a home.
async fn set_home(f: &Fx, initiate_login_uri: Option<&str>, client_uri: Option<&str>) {
    f.app
        .storage()
        .clients()
        .update(
            f.tenant.id,
            f.rp.id(),
            &anvil_core::model::ClientUpdate {
                initiate_login_uri: Some(initiate_login_uri.map(str::to_owned)),
                client_uri: Some(client_uri.map(str::to_owned)),
                ..anvil_core::model::ClientUpdate::default()
            },
            f.app.clock().now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
}

/// A client registered through `source` (DCR or CIMD) that chose `THIRD_PARTY` as its home.
async fn third_party(f: &Fx, source: anvil_core::model::ClientSource) -> String {
    let rp = token_support::register_with(
        &f.app,
        f.tenant.id,
        token_support::web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
        |c| {
            c.name = "Third Party".into();
            c.registration_source = source;
            c.client_uri = Some(THIRD_PARTY.into());
            c.initiate_login_uri = Some(THIRD_PARTY.into());
            c.post_logout_redirect_uris = vec![BYE.into()];
        },
    )
    .await;
    rp.id().to_owned()
}

#[tokio::test]
async fn without_a_session_logout_never_asks_and_offers_sign_in() {
    let f = fixture().await;
    // End-session endpoint: no prompt, the signed-out page with a way forward.
    let resp = f.get_with("/logout", None).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let html = resp.html();
    assert!(html.contains("You have been signed out."), "{html}");
    assert!(!html.contains("logout-confirm-submit"), "{html}");
    assert_eq!(
        href(&html, "link-login").as_deref(),
        Some(format!("{}/ui/login", f.iss).as_str()),
        "{html}"
    );
    assert!(html.contains("Sign in again"), "{html}");

    // The confirmation page itself: no prompt, no flow, 303 to the signed-out page (outside
    // /ui/logout, the conformance contract).
    let resp = f.get_with("/ui/logout", None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{}/ui/signed-out", f.iss));
    assert!(
        resp.headers
            .get_all("set-cookie")
            .iter()
            .all(|c| !c.to_str().unwrap_or("").contains("flow")),
        "no flow cookie without a session"
    );
    // The other browser's session and the audit log are untouched.
    assert!(f.session_active().await);
    assert!(f.audit(AuditAction::Logout).await.is_empty());
}

#[tokio::test]
async fn without_a_session_a_registered_uri_is_followed_with_state() {
    let f = fixture().await;
    let pairs = [
        ("client_id", f.rp.id()),
        ("post_logout_redirect_uri", BYE),
        ("state", "st"),
    ];
    let resp = f.get_with(&Fx::logout_path(&pairs), None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=st"));

    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let resp = f.get_with(&format!("/ui/logout?{q}"), None).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), format!("{BYE}?state=st"));
    assert!(f.session_active().await);
    assert!(f.audit(AuditAction::Logout).await.is_empty());
    assert_eq!(f.deliveries().await, 0);
}

#[tokio::test]
async fn without_a_session_bad_requests_are_still_refused() {
    let f = fixture().await;
    for path in [
        Fx::logout_path(&[
            ("client_id", f.rp.id()),
            ("post_logout_redirect_uri", "https://evil.test/bye"),
        ]),
        format!(
            "/ui/logout?client_id={}&post_logout_redirect_uri=https%3A%2F%2Fevil.test%2Fbye",
            f.rp.id()
        ),
    ] {
        let resp = f.get_with(&path, None).await;
        assert_logout_error(&resp, "logout.redirect_uri_not_registered");
        assert!(
            resp.html().contains(
                "The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client."
            ),
            "contract sentence unchanged"
        );
        assert!(!resp.text().contains("evil.test"));
        // Signed out: the way forward is sign-in.
        assert!(
            href(&resp.html(), "link-login").is_some(),
            "{}",
            resp.html()
        );
    }
    let resp = f
        .get_with(&Fx::logout_path(&[("post_logout_redirect_uri", BYE)]), None)
        .await;
    assert_logout_error(&resp, "logout.id_token_hint_required");
    let resp = f
        .get_with(&Fx::logout_path(&[("client_id", "nope")]), None)
        .await;
    assert_logout_error(&resp, "logout.unknown_client");
}

#[tokio::test]
async fn with_a_session_the_confirmation_is_still_asked() {
    let f = fixture().await;
    let resp = f.get("/logout").await;
    assert_eq!(resp.status, 303);
    assert_eq!(loc(&resp), format!("{}/ui/logout", f.iss));
    let page = f.get("/ui/logout").await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert!(page.html().contains("logout-confirm-submit"));
    assert!(f.session_active().await);
}

#[tokio::test]
async fn stay_signed_in_returns_to_the_static_client_home() {
    let f = fixture().await;
    set_home(&f, None, Some(APP_HOME)).await;
    let page = f.get(&format!("/ui/logout?client_id={}", f.rp.id())).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(
        href(&page.html(), "logout-cancel").as_deref(),
        Some(APP_HOME)
    );
    // initiate_login_uri is preferred.
    set_home(&f, Some(APP_LOGIN), Some(APP_HOME)).await;
    let page = f.get(&format!("/ui/logout?client_id={}", f.rp.id())).await;
    assert_eq!(
        href(&page.html(), "logout-cancel").as_deref(),
        Some(APP_LOGIN)
    );
    assert!(f.session_active().await, "the session is kept");

    // Without a client, or a client without a home: the account page.
    let page = f.get("/ui/logout").await;
    assert_eq!(
        href(&page.html(), "logout-cancel").as_deref(),
        Some(format!("{}/ui/account/sessions", f.iss).as_str())
    );
    set_home(&f, None, None).await;
    let page = f.get(&format!("/ui/logout?client_id={}", f.rp.id())).await;
    assert_eq!(
        href(&page.html(), "logout-cancel").as_deref(),
        Some(format!("{}/ui/account/sessions", f.iss).as_str())
    );
}

#[tokio::test]
async fn logout_cancel_never_uses_dynamic_client_uri() {
    use anvil_core::model::ClientSource;
    let f = fixture().await;
    for source in [ClientSource::Dynamic, ClientSource::Cimd] {
        let id = third_party(&f, source).await;
        let page = f.get(&format!("/ui/logout?client_id={id}")).await;
        assert_eq!(page.status, 200, "{}", page.text());
        let html = page.html();
        assert_eq!(
            href(&html, "logout-cancel").as_deref(),
            Some(format!("{}/ui/account/sessions", f.iss).as_str()),
            "{source:?}"
        );
        assert!(!html.contains("third-party.test"), "{source:?}: {html}");

        // The signed-out page and the error page never show it either.
        let done = f
            .get_with(&format!("/ui/signed-out?client_id={id}"), None)
            .await;
        assert!(!done.html().contains("third-party.test"), "{source:?}");
        assert!(href(&done.html(), "link-back-to-app").is_none());
        let err = f
            .get(&Fx::logout_path(&[
                ("client_id", &id),
                ("post_logout_redirect_uri", "https://evil.test/"),
            ]))
            .await;
        assert_logout_error(&err, "logout.redirect_uri_not_registered");
        assert!(!err.html().contains("third-party.test"), "{source:?}");
    }
    assert!(f.session_active().await);
}

#[tokio::test]
async fn the_signed_out_page_offers_back_to_the_static_app() {
    let f = fixture().await;
    set_home(&f, None, Some(APP_HOME)).await;
    let page = f.get(&format!("/ui/logout?client_id={}", f.rp.id())).await;
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
    let l = loc(&resp);
    assert_eq!(
        l,
        format!("{}/ui/signed-out?client_id={}", f.iss, f.rp.id())
    );
    assert!(!l.contains("/ui/logout"));
    assert!(!f.session_active().await);

    let done = f
        .get_with(l.strip_prefix(&f.iss).expect("same origin"), None)
        .await;
    assert_eq!(done.status, 200);
    let html = done.html();
    assert!(html.contains("You have been signed out."));
    assert_eq!(href(&html, "link-back-to-app").as_deref(), Some(APP_HOME));
    assert!(html.contains("Back to Test RP"), "{html}");
    assert!(href(&html, "link-login").is_some(), "sign in again too");
    // "Back to <app>" comes first.
    assert!(html.find("link-back-to-app") < html.find("link-login"));

    // The end-session endpoint's own signed-out page (valid hint, no URI) does the same.
    let f = fixture().await;
    set_home(&f, Some(APP_LOGIN), None).await;
    let hint = f.id_token().await;
    let resp = f.get(&Fx::logout_path(&[("id_token_hint", &hint)])).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        href(&resp.html(), "link-back-to-app").as_deref(),
        Some(APP_LOGIN)
    );
}

#[tokio::test]
async fn the_signed_out_page_ignores_unknown_repeated_or_url_client_ids() {
    let f = fixture().await;
    set_home(&f, None, Some(APP_HOME)).await;
    for q in [
        "client_id=nope".to_owned(),
        format!("client_id={0}&client_id={0}", f.rp.id()),
        "client_id=https%3A%2F%2Fevil.test%2F".to_owned(),
    ] {
        let resp = f.get_with(&format!("/ui/signed-out?{q}"), None).await;
        assert_eq!(resp.status, 200, "{q}");
        let html = resp.html();
        assert!(href(&html, "link-back-to-app").is_none(), "{q}: {html}");
        assert!(!html.contains("evil.test"), "{q}");
        assert!(href(&html, "link-login").is_some(), "{q}");
    }
}

#[tokio::test]
async fn logout_errors_keep_the_contract_and_offer_a_way_forward() {
    let f = fixture().await;
    set_home(&f, None, Some(APP_HOME)).await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("client_id", f.rp.id()),
            ("post_logout_redirect_uri", "https://evil.test/bye"),
        ]))
        .await;
    assert_logout_error(&resp, "logout.redirect_uri_not_registered");
    let html = resp.html();
    assert!(html.contains(
        "role=\"alert\">The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client.</p>"
    ), "{html}");
    // Signed in: back to the app first, then the account page and the sign-out form.
    assert_eq!(href(&html, "link-back-to-app").as_deref(), Some(APP_HOME));
    assert!(href(&html, "link-account").is_some(), "{html}");
    assert!(html.contains("id=\"form-sign-out\""), "{html}");
    assert!(f.session_active().await, "nothing changed");

    // An expired confirmation also has a way forward.
    let resp = f
        .post(
            "/ui/logout?flow=0192d0b4-0000-7000-8000-000000000000",
            &[("csrf_token", "x")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(href(&resp.html(), "link-account").is_some());
}
