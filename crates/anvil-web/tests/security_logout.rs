//! RP-initiated logout rejections (OIDC-12). Every refusal is a 400 page with the contract
//! sentence, never a redirect, and the session stays active: `alg: none`, a foreign key, another
//! tenant's hint, a tampered payload, a non-ID token, unregistered or modified
//! `post_logout_redirect_uri`, a URI without hint or `client_id`, `client_id` not matching the
//! hint, an unknown `client_id`, repeated parameters, a non-form POST. The confirmation POST needs
//! the flow cookie and the CSRF token and is behind Fetch-Metadata; the end-session POST is not.

mod logout_support;
mod support;
mod token_support;

use anvil_core::model::AuditAction;
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::{b64url, b64url_decode};
use anvil_jose::keys::{Alg, SigningKey};
use axum::body::Body;
use axum::http::{Method, Request, header};
use logout_support::*;
use token_support::{acme, forged};

/// Asserts the refusal of `pairs` on GET and POST: error page `key`, session intact.
async fn assert_refused(f: &Fx, pairs: &[(&str, &str)], key: &str) {
    let resp = f.get(&Fx::logout_path(pairs)).await;
    assert_logout_error(&resp, key);
    let resp = f
        .post("/logout", pairs, Some(&f.cookie), "cross-site")
        .await;
    assert_logout_error(&resp, key);
    assert!(f.session_active().await, "{key}: the session stays active");
    assert!(f.audit(AuditAction::Logout).await.is_empty());
    assert_eq!(f.deliveries().await, 0);
}

#[tokio::test]
async fn alg_none_hint_is_rejected() {
    let f = fixture().await;
    let hint = forged(
        &serde_json::json!({"alg": "none", "typ": "JWT"}),
        &f.claims(),
        b"",
    );
    assert_refused(
        &f,
        &[("id_token_hint", &hint), ("post_logout_redirect_uri", BYE)],
        "logout.invalid_id_token_hint",
    )
    .await;
    let resp = f.get(&Fx::logout_path(&[("id_token_hint", &hint)])).await;
    assert!(
        resp.html()
            .contains("The sign-out request is invalid: the id_token_hint could not be verified."),
        "{}",
        resp.html()
    );
}

#[tokio::test]
async fn a_hint_signed_by_a_foreign_key_is_rejected() {
    let f = fixture().await;
    let g = anvil_jose::keys::generate_rs256().expect("key");
    // Even reusing the tenant's kid does not help.
    let kid = f.signer().await.kid().to_owned();
    let foreign = SigningKey::from_pkcs8(&kid, Alg::RS256, &g.pkcs8).expect("signer");
    let hint = foreign.sign_jwt(Some("JWT"), &f.claims()).expect("sign");
    assert_refused(
        &f,
        &[("id_token_hint", &hint), ("post_logout_redirect_uri", BYE)],
        "logout.invalid_id_token_hint",
    )
    .await;
}

#[tokio::test]
async fn a_hint_from_another_tenant_is_rejected() {
    let f = fixture().await;
    let other = acme(&f.app).await;
    let signer = anvil_core::service::key::KeyService {
        storage: f.app.storage_arc(),
        kek: f.app.kek_arc(),
        clock: std::sync::Arc::new(Frozen(f.app.clock().now())),
    }
    .signer(other.id)
    .await
    .expect("acme key");
    let mut claims = f.claims();
    claims["iss"] = f.app.issuer(Some("acme")).into();
    let hint = signer.sign_jwt(Some("JWT"), &claims).expect("sign");
    assert_refused(
        &f,
        &[("id_token_hint", &hint), ("post_logout_redirect_uri", BYE)],
        "logout.invalid_id_token_hint",
    )
    .await;
    // Signed by this tenant's key but naming the other issuer: also invalid.
    let hint = f.sign(&claims).await;
    assert_refused(
        &f,
        &[("id_token_hint", &hint)],
        "logout.invalid_id_token_hint",
    )
    .await;
}

#[tokio::test]
async fn a_tampered_payload_is_rejected() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let parts: Vec<&str> = hint.split('.').collect();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&b64url_decode(parts[1]).expect("b64")).expect("json");
    claims["sub"] = "someone-else".into();
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        b64url(claims.to_string().as_bytes()),
        parts[2]
    );
    assert_refused(
        &f,
        &[
            ("id_token_hint", &tampered),
            ("post_logout_redirect_uri", BYE),
        ],
        "logout.invalid_id_token_hint",
    )
    .await;
    assert_refused(
        &f,
        &[("id_token_hint", "not-a-jwt")],
        "logout.invalid_id_token_hint",
    )
    .await;
}

#[tokio::test]
async fn a_token_that_is_not_an_id_token_is_rejected() {
    let f = fixture().await;
    let hint = f
        .signer()
        .await
        .sign_jwt(Some("at+jwt"), &f.claims())
        .expect("sign");
    assert_refused(
        &f,
        &[("id_token_hint", &hint)],
        "logout.invalid_id_token_hint",
    )
    .await;
}

#[tokio::test]
async fn a_hint_for_an_unknown_client_is_rejected() {
    let f = fixture().await;
    let mut claims = f.claims();
    claims["aud"] = "no-such-client".into();
    claims["azp"] = "no-such-client".into();
    let hint = f.sign(&claims).await;
    assert_refused(
        &f,
        &[("id_token_hint", &hint)],
        "logout.invalid_id_token_hint",
    )
    .await;
}

#[tokio::test]
async fn unregistered_or_modified_redirect_uris_are_rejected() {
    let f = fixture().await;
    let hint = f.id_token().await;
    for uri in [
        "https://evil.example/bye",
        "https://rp.test/bye?foo=bar",
        "https://rp.test/bye/",
        "https://RP.test/bye",
        "https://rp.test/bye#x",
        "https://rp.test/bye?from=op&foo=bar",
    ] {
        assert_refused(
            &f,
            &[("id_token_hint", &hint), ("post_logout_redirect_uri", uri)],
            "logout.redirect_uri_not_registered",
        )
        .await;
    }
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", "https://rp.test/bye?foo=bar"),
        ]))
        .await;
    assert!(resp.html().contains(
        "The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client."
    ));
    // Also through client_id without a hint.
    assert_refused(
        &f,
        &[
            ("client_id", f.rp.id()),
            ("post_logout_redirect_uri", "https://evil.example/bye"),
        ],
        "logout.redirect_uri_not_registered",
    )
    .await;
}

#[tokio::test]
async fn a_uri_without_hint_or_client_id_is_rejected() {
    let f = fixture().await;
    assert_refused(
        &f,
        &[("post_logout_redirect_uri", BYE), ("state", "s")],
        "logout.id_token_hint_required",
    )
    .await;
    let resp = f
        .get(&Fx::logout_path(&[("post_logout_redirect_uri", BYE)]))
        .await;
    assert!(resp.html().contains(
        "The sign-out request is invalid: post_logout_redirect_uri requires id_token_hint or client_id."
    ));
}

#[tokio::test]
async fn client_id_must_match_the_hint() {
    let f = fixture().await;
    let hint = f.id_token().await;
    assert_refused(
        &f,
        &[
            ("id_token_hint", &hint),
            ("client_id", "other-client"),
            ("post_logout_redirect_uri", BYE),
        ],
        "logout.client_mismatch",
    )
    .await;
}

#[tokio::test]
async fn an_unknown_client_id_is_rejected() {
    let f = fixture().await;
    assert_refused(
        &f,
        &[("client_id", "no-such-client")],
        "logout.unknown_client",
    )
    .await;
    // The confirmation page validates again: a hand-made URL cannot add an unregistered URI.
    let resp = f
        .get(&format!(
            "/ui/logout?client_id={}&post_logout_redirect_uri=https%3A%2F%2Fevil.example%2F",
            f.rp.id()
        ))
        .await;
    assert_logout_error(&resp, "logout.redirect_uri_not_registered");
    let resp = f
        .get("/ui/logout?post_logout_redirect_uri=https%3A%2F%2Frp.test%2Fbye")
        .await;
    assert_logout_error(&resp, "logout.id_token_hint_required");
}

#[tokio::test]
async fn repeated_parameters_and_non_form_posts_are_invalid_requests() {
    let f = fixture().await;
    let hint = f.id_token().await;
    let resp = f
        .get(&Fx::logout_path(&[
            ("id_token_hint", &hint),
            ("state", "a"),
            ("state", "b"),
        ]))
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(resp.header("location").is_none());
    assert!(resp.html().contains(r#"data-error-key="invalid_request""#));
    let resp = f
        .post(
            "/logout",
            &[("id_token_hint", &hint), ("id_token_hint", &hint)],
            Some(&f.cookie),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let body = format!("{{\"id_token_hint\":\"{hint}\"}}");
    let resp = f
        .app
        .send(
            Request::builder()
                .method(Method::POST)
                .uri("/logout")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &f.cookie)
                .header(header::CONTENT_LENGTH, body.len())
                .body(Body::from(body))
                .expect("request"),
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let resp = f.get("/ui/logout?client_id=a&client_id=b").await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(f.session_active().await);
}

#[tokio::test]
async fn confirmation_requires_flow_cookie_and_csrf() {
    let f = fixture().await;
    let page = f.get("/ui/logout").await;
    let (action, csrf) = confirm_form(&f.app, &page);
    // No flow cookie.
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookie),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // Wrong CSRF token.
    let resp = f
        .post(
            &action,
            &[("csrf_token", "wrong")],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // No CSRF token, no flow id.
    let resp = f
        .post(&action, &[], Some(&f.cookies()), "same-origin")
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    let resp = f
        .post(
            "/ui/logout",
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(f.session_active().await, "nothing changed");

    // A consent-kind or other flow id does not confirm: an unknown flow is expired.
    let resp = f
        .post(
            "/ui/logout?flow=0192d0b4-0000-7000-8000-000000000000",
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(f.session_active().await);

    // The correct binding still works afterwards.
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "same-origin",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn confirmation_post_is_behind_fetch_metadata_but_end_session_post_is_not() {
    let f = fixture().await;
    let page = f.get("/ui/logout").await;
    let (action, csrf) = confirm_form(&f.app, &page);
    let resp = f
        .post(
            &action,
            &[("csrf_token", &csrf)],
            Some(&f.cookies()),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert!(f.session_active().await);

    let hint = f.id_token().await;
    let resp = f
        .post(
            "/logout",
            &[("id_token_hint", &hint), ("post_logout_redirect_uri", BYE)],
            Some(&f.cookie),
            "cross-site",
        )
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert_eq!(loc(&resp), BYE);
    assert!(!f.session_active().await);
}

#[tokio::test]
async fn a_cross_site_post_without_a_valid_hint_never_logs_out() {
    let f = fixture().await;
    let resp = f
        .post("/logout", &[("state", "s")], Some(&f.cookie), "cross-site")
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(loc(&resp).contains("/ui/logout"));
    assert!(f.session_active().await);
}

#[tokio::test]
async fn without_a_session_the_confirmation_creates_no_flow_and_posts_stay_forbidden() {
    let f = fixture().await;
    // No session: no prompt, so no flow cookie and no CSRF token to replay.
    let resp = f
        .get_with(&format!("/ui/logout?client_id={}", f.rp.id()), None)
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        resp.headers
            .get_all("set-cookie")
            .iter()
            .all(|c| !c.to_str().unwrap_or("").contains("flow")),
        "no flow cookie without a session"
    );
    assert!(!resp.text().contains("csrf_token"));
    // A POST without the flow cookie or the CSRF token is still the csrf page; nothing changes.
    for (cookie, pairs) in [
        (None, vec![]),
        (Some(f.cookie.as_str()), vec![]),
        (Some(f.cookie.as_str()), vec![("csrf_token", "guess")]),
    ] {
        let resp = f
            .post(
                "/ui/logout?flow=0192d0b4-0000-7000-8000-000000000001",
                &pairs,
                cookie,
                "same-origin",
            )
            .await;
        assert!(
            resp.status == 403 || resp.status == 400,
            "{}: {}",
            resp.status,
            resp.text()
        );
        assert!(resp.header("location").is_none());
    }
    assert!(f.session_active().await, "nothing changed");
}

#[tokio::test]
async fn a_hand_made_signed_out_url_never_renders_a_request_value() {
    let f = fixture().await;
    for q in [
        "client_id=javascript%3Aalert(1)",
        "client_id=https%3A%2F%2Fevil.test%2F",
        "client_id=%22%3E%3Cscript%3E",
        "post_logout_redirect_uri=https%3A%2F%2Fevil.test%2F",
    ] {
        let resp = f.get_with(&format!("/ui/signed-out?{q}"), None).await;
        assert_eq!(resp.status, 200, "{q}");
        let html = resp.text();
        assert!(!html.contains("evil.test"), "{q}");
        assert!(!html.contains("javascript:"), "{q}");
        assert!(!html.contains("<script>"), "{q}");
        assert!(!html.contains("link-back-to-app"), "{q}");
    }
}
