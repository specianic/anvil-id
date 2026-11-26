//! Identifier-first sign-in with home-realm discovery (ORG-04, 06-22): a tenant with a verified,
//! routed domain asks for the email first and routes it by its domain only, to the org's OIDC or
//! SAML IdP, to the single-sign-on choice (`allow_local_password = true`, the Q6/Q7 default) or to
//! the password step. Every other tenant keeps the combined form.
//!
//! Domains, routing and `allow_local_password` are set through the storage traits (the admin
//! API's lockout guard is tested in `security_domains.rs`). The account enumeration control is
//! `security_enumeration::non_routed_known_and_unknown_emails_get_identical_password_step`.

mod email_code_support;
mod saml_support;
mod support;
mod token_support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{
    CAPTCHA_SECRET_PURPOSE, CaptchaProvider, CaptchaSettings, ClientAuthMethod, Connection,
    ConnectionConfig, ConnectionId, ConnectionUpdate, NameIdFormat, NewConnection, OidcConfig,
    OrgClientPolicy, OrgDomain, OrgDomainUpdate, OrgId, Organization, SamlAttributeMapping,
    SamlConfig,
};
use anvil_core::ports::Clock as _;
use anvil_web::AppConfig;
use anvil_web::adapters::captcha::CaptchaEndpoints;
use anvil_web::adapters::outbound::OutboundPolicy;
use axum::body::Body;
use axum::http::{Method, Request, header};
use email_code_support::{login_codes, one_code, submit_code};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from, location};
use token_support::{CHALLENGE, REDIRECT, register_with, web_input};
use ui_helpers::{
    form_action, hidden_inputs, message_keys, normalize, register, session_cookie, to_path,
};
use upstream_flow::{
    Started, Upstream, add_org_connection, callback_at, claim_domain, create_org, form_id,
    mark_verified, reply_for, session, setup, tenant, tenant_settings, verify_domain,
};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Slug of the org's OIDC connection.
const ORG_SLUG: &str = "acme-sso";
/// The org's routed domain.
const DOMAIN: &str = "acme-corp.com";
/// A user on the routed domain.
const ALICE: &str = "alice@acme-corp.com";
/// A user on a domain nobody routes.
const BOB: &str = "bob@other-corp.com";
const PASSWORD: &str = "correct horse battery";

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

/// The upstream fixture (tenant OIDC connection `acme-id` with a button) plus an org with the
/// verified domain [`DOMAIN`] and its OIDC connection [`ORG_SLUG`], routing **off**.
struct Hrd {
    u: Upstream,
    org: Organization,
    claim: OrgDomain,
    conn: Connection,
}

async fn fixture() -> Hrd {
    let u = setup(true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    let claim = verify_domain(&u.app, &org, DOMAIN).await;
    let conn = add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    Hrd {
        u,
        org,
        claim,
        conn,
    }
}

/// Routes `claim` to `conn` with `allow_local_password` (storage intent).
async fn route(app: &TestApp, claim: &OrgDomain, conn: &Connection, allow_local_password: bool) {
    set_routing(app, claim, Some(conn), true, allow_local_password).await;
}

async fn set_routing(
    app: &TestApp,
    claim: &OrgDomain,
    conn: Option<&Connection>,
    routing: bool,
    allow_local_password: bool,
) {
    app.storage()
        .organizations()
        .update_domain(
            tenant(app).id,
            claim.id,
            &OrgDomainUpdate {
                connection_id: Some(conn.map(|c| c.id)),
                routing: Some(routing),
                allow_local_password: Some(allow_local_password),
            },
            app.clock().now(),
        )
        .await
        .expect("update domain")
        .expect("domain exists");
}

/// Registers `email` with [`PASSWORD`] and marks the address verified.
async fn account(app: &TestApp, email: &str) {
    register(app, "", email, PASSWORD).await;
    mark_verified(app, email).await;
}

/// Posts the first form of `page` (its action, CSRF token and id'd hidden inputs) with `pairs`.
async fn post_page(app: &TestApp, page: &TestResponse, pairs: &[(&str, &str)]) -> TestResponse {
    let html = page.html();
    post_form_in(app, &html, &form_action(app, &html), pairs).await
}

/// Posts the form with id `form` of `page`.
async fn post_form_id(
    app: &TestApp,
    page: &TestResponse,
    form: &str,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let html = page.html();
    let marker = format!("<form id=\"{form}\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("form #{form} in {html}"));
    let action = form_action(app, &html[start..]);
    post_form_in(app, &html, &action, pairs).await
}

async fn post_form_in(
    app: &TestApp,
    html: &str,
    action: &str,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let csrf = csrf_from(html);
    let hidden: Vec<(String, String)> = hidden_inputs(html)
        .into_iter()
        .filter(|(n, _)| !pairs.iter().any(|(k, _)| k == n))
        .collect();
    let mut all: Vec<(&str, &str)> = vec![("csrf_token", &csrf)];
    all.extend(hidden.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    all.extend_from_slice(pairs);
    app.post_form(action, &all).await
}

/// Opens the sign-in page (expects 200).
async fn login_page(app: &TestApp) -> TestResponse {
    let page = app.get("/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    page
}

/// Opens the sign-in page and submits `email` on the email page.
async fn identify(app: &TestApp, email: &str) -> TestResponse {
    let page = login_page(app).await;
    assert_eq!(
        form_id(&page.html()),
        "login-identify-form",
        "{}",
        page.text()
    );
    post_page(app, &page, &[("identifier", email)]).await
}

/// A 303 to the provider, parsed.
fn started(resp: &TestResponse) -> Started {
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = url::Url::parse(&location(resp)).expect("provider URL");
    let find = |n: &str| {
        loc.query_pairs()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.into_owned())
    };
    Started {
        state: find("state").expect("state"),
        nonce: find("nonce"),
        location: loc,
    }
}

fn assert_to_mock(u: &Upstream, resp: &TestResponse) -> Started {
    let s = started(resp);
    assert!(
        s.location.as_str().starts_with(&u.mock.issuer()),
        "to the org IdP: {}",
        s.location
    );
    assert!(
        resp.headers
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap_or_default().contains("anvil_upstream_")),
        "binding cookie set"
    );
    s
}

fn signed_in(resp: &TestResponse) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
}

/// The password step after the email page: the combined form's ids, the email locked.
fn assert_password_step(resp: &TestResponse, email: &str) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(html.contains("id=\"login-email-locked\""), "{html}");
    assert!(html.contains("id=\"login-change-email\""), "{html}");
    assert!(html.contains("type=\"password\""), "{html}");
    assert!(
        hidden_inputs(&html)
            .iter()
            .any(|(n, v)| n == "identifier" && v == email),
        "{html}"
    );
}

/// An app with the SAML flag `flag`, the org with [`DOMAIN`] verified and a SAML connection.
async fn saml_fixture(flag: bool) -> (TestApp, OrgDomain, Connection) {
    let app = TestApp::with(|c| {
        c.outbound = OutboundPolicy::loopback_dev();
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
        c.saml_experimental = flag;
    })
    .await;
    let org = create_org(&app, "acme", &[]).await;
    let claim = verify_domain(&app, &org, DOMAIN).await;
    let key = saml_support::IdpKey::rsa();
    let conn = app
        .storage()
        .connections()
        .create(
            tenant(&app).id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                slug: "acme-saml".into(),
                display_name: "Acme SAML".into(),
                enabled: true,
                config: ConnectionConfig::Saml(SamlConfig {
                    idp_entity_id: saml_support::IDP_ENTITY_ID.into(),
                    sso_url: "https://idp.example.test/sso?app=anvil".into(),
                    signing_certs: vec![key.cert_pem()],
                    name_id_format: NameIdFormat::Persistent,
                    attributes: SamlAttributeMapping {
                        email: Some("mail".into()),
                        ..SamlAttributeMapping::default()
                    },
                    metadata_url: None,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: app.clock().now(),
                org_id: Some(org.id),
            },
        )
        .await
        .expect("create SAML connection");
    (app, claim, conn)
}

/// `/authorize` for a fresh confidential client (organization policy `org`) with `extra`, then
/// the sign-in page path it redirects to.
async fn authorize_login(app: &TestApp, org: OrgClientPolicy, extra: &[(&str, &str)]) -> String {
    let rp = register_with(
        app,
        tenant(app).id,
        web_input(ClientAuthMethod::ClientSecretBasic),
        |c| c.organization = org,
    )
    .await;
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", rp.id()),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("state", "st-1"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let resp = app.get(&format!("/authorize?{q}")).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let login = to_path(app, &location(&resp));
    assert!(login.starts_with("/ui/login?request="), "{login}");
    login
}

// ---------------------------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn combined_form_unchanged_without_routing() {
    // A tenant without orgs, and one whose verified domain does not route: the same page.
    let plain = setup(true).await;
    let before = normalize(&login_page(&plain.app).await.html());

    let h = fixture().await;
    // A pending claim with routing, and the verified claim with routing off: still no routing.
    let pending = claim_domain(&h.u.app, &h.org, "pending-corp.com", false).await;
    set_routing(&h.u.app, &pending, Some(&h.conn), true, false).await;
    set_routing(&h.u.app, &h.claim, Some(&h.conn), false, false).await;
    let page = login_page(&h.u.app).await;
    let html = page.html();
    assert_eq!(normalize(&html), before, "byte-identical combined form");

    // The combined form's selectors (themes/default/README.md contract).
    assert_eq!(form_id(&html), "login");
    for id in [
        "id=\"identifier\"",
        "type=\"email\"",
        "id=\"password\"",
        "id=\"login-submit\"",
        "id=\"upstream-acme-id\"",
        "id=\"login-passkey\"",
    ] {
        assert!(html.contains(id), "{id} in {html}");
    }
    for absent in [
        "login-identify-form",
        "login-email-locked",
        "login-change-email",
        "upstream-acme-sso",
    ] {
        assert!(!html.contains(absent), "{absent} in {html}");
    }
}

#[tokio::test]
async fn email_first_page_when_tenant_has_a_routable_domain() {
    let h = fixture().await;
    route(&h.u.app, &h.claim, &h.conn, true).await;
    let page = login_page(&h.u.app).await;
    let html = page.html();
    assert_eq!(form_id(&html), "login-identify-form", "{html}");
    assert!(html.contains("id=\"login-identify-submit\""), "{html}");
    assert!(html.contains("type=\"email\""), "{html}");
    assert!(
        !html.contains("type=\"password\""),
        "no password yet: {html}"
    );
    // Passkey and social buttons stay; the org connection has no button.
    assert!(html.contains("id=\"login-passkey\""), "{html}");
    assert!(html.contains("id=\"upstream-acme-id\""), "{html}");
    assert!(!html.contains("upstream-acme-sso"), "{html}");
    assert!(html.contains("id=\"link-recovery\""), "{html}");
    // The tenant connection's button still starts from this page.
    let resp = post_form_id(&h.u.app, &page, "upstream-acme-id-form", &[]).await;
    assert_to_mock(&h.u, &resp);
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn routed_domain_redirects_to_org_idp() {
    let h = fixture().await;
    route(&h.u.app, &h.claim, &h.conn, false).await;
    let resp = identify(&h.u.app, ALICE).await;
    let s = assert_to_mock(&h.u, &resp);
    // The org IdP signs the user in (JIT through the org connection).
    reply_for(&h.u, &s, json!({ "email": ALICE, "email_verified": true }));
    let resp = callback_at(&h.u, ORG_SLUG, &s).await;
    signed_in(&resp);
    let alice = upstream_flow::user(&h.u.app, ALICE)
        .await
        .expect("JIT user");
    assert_eq!(session(&h.u.app).await.expect("session").user_id, alice.id);
}

#[tokio::test]
async fn routed_saml_domain_redirects_with_saml_request() {
    let (app, claim, conn) = saml_fixture(true).await;
    route(&app, &claim, &conn, false).await;
    let resp = identify(&app, ALICE).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = url::Url::parse(&location(&resp)).expect("IdP URL");
    assert_eq!(loc.host_str(), Some("idp.example.test"));
    assert_eq!(loc.path(), "/sso");
    let names: Vec<String> = loc.query_pairs().map(|(k, _)| k.into_owned()).collect();
    assert_eq!(names, ["app", "SAMLRequest", "RelayState"], "{loc}");
    assert!(
        resp.headers
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap_or_default().contains("anvil_upstream_")),
        "binding cookie set"
    );
}

#[tokio::test]
async fn routed_domain_with_local_password_offers_choice() {
    let h = fixture().await;
    let app = &h.u.app;
    route(app, &h.claim, &h.conn, true).await;
    account(app, ALICE).await;

    let choice = identify(app, ALICE).await;
    assert_eq!(choice.status, 200, "{}", choice.text());
    let html = choice.html();
    for id in [
        "id=\"login-sso-continue\"",
        "id=\"login-use-password\"",
        "id=\"login-email-locked\"",
        "id=\"login-change-email\"",
    ] {
        assert!(html.contains(id), "{id} in {html}");
    }
    assert!(message_keys(&html).contains(&"hrd.sso_explain".to_owned()));
    assert!(!html.contains("type=\"password\""), "{html}");

    // "Change": back to the email page, prefilled.
    let back = post_form_id(
        app,
        &choice,
        "login-change-email-form",
        &[("choice", "change")],
    )
    .await;
    assert_eq!(back.status, 200, "{}", back.text());
    assert_eq!(form_id(&back.html()), "login-identify-form");
    assert!(back.html().contains(&format!("value=\"{ALICE}\"")));

    // "Continue with single sign-on": the org IdP.
    let choice = post_page(app, &back, &[("identifier", ALICE)]).await;
    let resp = post_form_id(app, &choice, "login-sso-form", &[("choice", "sso")]).await;
    assert_to_mock(&h.u, &resp);

    // "Use password instead": the password step, and the password signs in.
    app.clear_cookies();
    let choice = identify(app, ALICE).await;
    let step = post_form_id(
        app,
        &choice,
        "login-use-password-form",
        &[("choice", "password")],
    )
    .await;
    assert_password_step(&step, ALICE);
    let resp = post_page(app, &step, &[("password", PASSWORD)]).await;
    signed_in(&resp);
    assert!(session(app).await.is_some());
}

#[tokio::test]
async fn password_refused_for_routed_domain_without_local_password() {
    let h = fixture().await;
    let app = &h.u.app;
    account(app, ALICE).await;

    // A combined form opened before the org turned passwords off.
    let page = login_page(app).await;
    route(app, &h.claim, &h.conn, false).await;
    let resp = post_page(app, &page, &[("identifier", ALICE), ("password", PASSWORD)]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        ["hrd.use_sso"],
        "{}",
        resp.text()
    );
    assert!(
        session(app).await.is_none(),
        "the right password signs nobody in"
    );

    // The password step of a non-routed address, posted with a routed one instead.
    app.clear_cookies();
    let step = identify(app, BOB).await;
    assert_password_step(&step, BOB);
    let resp = post_page(app, &step, &[("identifier", ALICE), ("password", PASSWORD)]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(message_keys(&resp.html()), ["hrd.use_sso"]);
    assert!(session(app).await.is_none());

    // Mixed case is the same address.
    let resp = post_page(
        app,
        &step,
        &[
            ("identifier", "Alice@ACME-corp.com"),
            ("password", PASSWORD),
        ],
    )
    .await;
    assert_eq!(message_keys(&resp.html()), ["hrd.use_sso"]);
    assert!(session(app).await.is_none());
}

#[tokio::test]
async fn email_code_refused_for_routed_domain_without_local_password() {
    let h = fixture().await;
    let app = &h.u.app;
    account(app, ALICE).await;
    tenant_settings(app, |s| {
        s.email_otp = true;
        s.magic_link = true;
    })
    .await;

    // A code requested while passwords were allowed, used after they were turned off.
    let page = login_page(app).await;
    let sent = post_form_id(app, &page, "email-code-request", &[("email", ALICE)]).await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    let mail = one_code(app).await;
    route(app, &h.claim, &h.conn, false).await;
    let resp = submit_code(app, &sent, &mail.code).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(message_keys(&resp.html()).contains(&"hrd.use_sso".to_owned()));
    assert!(session(app).await.is_none());

    // Its magic link is refused too, and consumes nothing.
    let link_page = app.get(&mail.link).await;
    assert_eq!(link_page.status, 200, "{}", link_page.text());
    let resp = post_form_id(app, &link_page, "magic-link", &[]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(message_keys(&resp.html()).contains(&"hrd.use_sso".to_owned()));
    assert!(session(app).await.is_none());

    // A new request for the address is refused before anything is sent.
    app.clear_cookies();
    let step = identify(app, BOB).await;
    let resp = post_form_id(app, &step, "email-code-request", &[("email", ALICE)]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(message_keys(&resp.html()).contains(&"hrd.use_sso".to_owned()));
    assert!(login_codes(app).await.is_empty(), "no email sent");
}

#[tokio::test]
async fn subdomain_of_routed_domain_is_not_routed() {
    let h = fixture().await;
    let app = &h.u.app;
    route(app, &h.claim, &h.conn, false).await;
    let sub = "carol@eu.acme-corp.com";
    account(app, sub).await;
    let step = identify(app, sub).await;
    assert_password_step(&step, sub);
    let resp = post_page(app, &step, &[("password", PASSWORD)]).await;
    signed_in(&resp);
}

#[tokio::test]
async fn login_hint_routes_immediately() {
    let h = fixture().await;
    let app = &h.u.app;
    route(app, &h.claim, &h.conn, false).await;
    let login = authorize_login(
        app,
        OrgClientPolicy::Off,
        &[("login_hint", " Alice@Acme-Corp.com ")],
    )
    .await;
    let resp = app.get(&login).await;
    let s = assert_to_mock(&h.u, &resp);
    assert!(
        resp.headers
            .get_all("set-cookie")
            .iter()
            .any(|c| c.to_str().unwrap_or_default().contains("anvil_flow_")),
        "flow cookie set with the redirect"
    );
    // The started sign-in completes and continues the authorization request.
    reply_for(&h.u, &s, json!({ "email": ALICE, "email_verified": true }));
    let resp = callback_at(&h.u, ORG_SLUG, &s).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).contains("/authorize/continue?request="),
        "{}",
        location(&resp)
    );

    // A non-routed hint skips the email page too: the password step.
    app.clear_cookies();
    let login = authorize_login(app, OrgClientPolicy::Off, &[("login_hint", BOB)]).await;
    assert_password_step(&app.get(&login).await, BOB);
}

#[tokio::test]
async fn organization_param_with_single_connection_goes_to_idp() {
    // Even without a routed domain: the org is named explicitly.
    let h = fixture().await;
    let app = &h.u.app;
    let login = authorize_login(app, OrgClientPolicy::Optional, &[("organization", "acme")]).await;
    assert_to_mock(&h.u, &app.get(&login).await);
    // By canonical id as well.
    app.clear_cookies();
    let id = h.org.id.to_string();
    let login = authorize_login(app, OrgClientPolicy::Optional, &[("organization", &id)]).await;
    assert_to_mock(&h.u, &app.get(&login).await);

    // Two enabled connections: no shortcut, the sign-in page.
    app.clear_cookies();
    let second = add_org_connection(app, &h.u.mock, &h.org, "acme-sso-2", true).await;
    let login = authorize_login(app, OrgClientPolicy::Optional, &[("organization", "acme")]).await;
    let page = app.get(&login).await;
    assert_eq!(page.status, 200, "{}", page.text());
    assert_eq!(form_id(&page.html()), "login");

    // One of them disabled: one usable connection again.
    app.storage()
        .connections()
        .update(
            tenant(app).id,
            second.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("connection");
    app.clear_cookies();
    let login = authorize_login(app, OrgClientPolicy::Optional, &[("organization", "acme")]).await;
    assert_to_mock(&h.u, &app.get(&login).await);

    // An unknown org: the sign-in page.
    app.clear_cookies();
    let login = authorize_login(
        app,
        OrgClientPolicy::Optional,
        &[("organization", "nobody")],
    )
    .await;
    assert_eq!(app.get(&login).await.status, 200);
}

#[tokio::test]
async fn routing_ignored_for_saml_when_flag_off() {
    let (app, claim, conn) = saml_fixture(false).await;
    route(&app, &claim, &conn, false).await;
    // A second domain routed to an OIDC connection keeps the email page on.
    let org = org_of(&app, &claim).await;
    let other = verify_domain(&app, &org, "beta-corp.com").await;
    let oidc = static_org_oidc(&app, org.id, "beta-sso").await;
    route(&app, &other, &oidc, false).await;
    account(&app, ALICE).await;
    // Treated as not routed: the password step, and the password is not refused.
    let step = identify(&app, ALICE).await;
    assert_password_step(&step, ALICE);
    let resp = post_page(&app, &step, &[("password", PASSWORD)]).await;
    signed_in(&resp);
}

#[tokio::test]
async fn unverified_or_routing_off_domain_is_local() {
    let h = fixture().await;
    let app = &h.u.app;
    // The verified domain routes (email-first is on) ...
    route(app, &h.claim, &h.conn, false).await;
    // ... a pending claim and a verified claim with routing off, both with passwords "off".
    let pending = claim_domain(app, &h.org, "pending-corp.com", false).await;
    set_routing(app, &pending, Some(&h.conn), true, false).await;
    let other = verify_domain(app, &h.org, "off-corp.com").await;
    set_routing(app, &other, Some(&h.conn), false, false).await;

    for email in ["dave@pending-corp.com", "erin@off-corp.com"] {
        account(app, email).await;
        app.clear_cookies();
        let step = identify(app, email).await;
        assert_password_step(&step, email);
        let resp = post_page(app, &step, &[("password", PASSWORD)]).await;
        signed_in(&resp);
    }
}

#[tokio::test]
async fn disabled_target_connection_restores_password_sign_in() {
    let h = fixture().await;
    let app = &h.u.app;
    account(app, ALICE).await;
    route(app, &h.claim, &h.conn, false).await;
    assert_eq!(
        identify(app, ALICE).await.status,
        303,
        "routed while enabled"
    );

    // A tenant admin disables the org's connection: the domain no longer routes.
    app.storage()
        .connections()
        .update(
            tenant(app).id,
            h.conn.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("connection");
    app.clear_cookies();
    // No routed domain left: the normal (combined) password form, and the password signs in.
    let page = login_page(app).await;
    assert_eq!(form_id(&page.html()), "login");
    let resp = post_page(app, &page, &[("identifier", ALICE), ("password", PASSWORD)]).await;
    signed_in(&resp);
}

#[tokio::test]
async fn email_first_flow_works_without_javascript() {
    let h = fixture().await;
    let app = &h.u.app;
    route(app, &h.claim, &h.conn, true).await;
    account(app, ALICE).await;

    let page = login_page(app).await;
    let html = page.html();
    // A plain form post with a submit button; the only script is the passkey enhancement.
    assert!(
        html.contains("<form id=\"login-identify-form\" method=\"post\""),
        "{html}"
    );
    assert!(
        html.contains("<button type=\"submit\" id=\"login-identify-submit\">"),
        "{html}"
    );
    assert_eq!(html.matches("<script").count(), 1, "{html}");
    assert!(html.contains("webauthn.js"));

    // Every step answers a page (200) or a 303.
    let choice = post_page(app, &page, &[("identifier", ALICE)]).await;
    assert_eq!(choice.status, 200);
    assert!(!choice.html().contains("<script"), "{}", choice.text());
    let step = post_form_id(
        app,
        &choice,
        "login-use-password-form",
        &[("choice", "password")],
    )
    .await;
    assert_eq!(step.status, 200);
    let resp = post_page(app, &step, &[("password", PASSWORD)]).await;
    signed_in(&resp);

    // A malformed email re-renders the email page (400), still without script dependencies.
    app.clear_cookies();
    let page = login_page(app).await;
    let resp = post_page(app, &page, &[("identifier", "not-an-email")]).await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(form_id(&resp.html()), "login-identify-form");
    assert!(message_keys(&resp.html()).contains(&"email.invalid".to_owned()));
}

#[tokio::test]
async fn identify_requires_the_flow_binding() {
    let h = fixture().await;
    let app = &h.u.app;
    route(app, &h.claim, &h.conn, false).await;
    let page = login_page(app).await;
    let action = form_action(app, &page.html());
    // A wrong CSRF token is refused before any routing.
    let resp = app
        .post_form(&action, &[("csrf_token", "wrong"), ("identifier", ALICE)])
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
    // So is a POST without the flow cookie (another browser).
    let csrf = csrf_from(&page.html());
    app.clear_cookies();
    let resp = app
        .post_form(
            &action,
            &[("csrf_token", csrf.as_str()), ("identifier", ALICE)],
        )
        .await;
    assert_eq!(resp.status, 403, "{}", resp.text());
}

// ---------------------------------------------------------------------------------------------
// The email-first decision follows the flag-aware routing rule (06-28)
// ---------------------------------------------------------------------------------------------

/// Creates an enabled OIDC connection owned by `org` with a static configuration (never started
/// by these tests).
async fn static_org_oidc(app: &TestApp, org_id: OrgId, slug: &str) -> Connection {
    app.storage()
        .connections()
        .create(
            tenant(app).id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                slug: slug.into(),
                display_name: format!("{slug} SSO"),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: "https://idp.example.test".into(),
                    client_id: "anvil".into(),
                    scopes: vec![],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: app.clock().now(),
                org_id: Some(org_id),
            },
        )
        .await
        .expect("create OIDC connection")
}

/// The org of `claim`.
async fn org_of(app: &TestApp, claim: &OrgDomain) -> Organization {
    app.storage()
        .organizations()
        .get(tenant(app).id, claim.org_id)
        .await
        .expect("get org")
        .expect("org exists")
}

#[tokio::test]
async fn email_first_not_shown_when_only_route_is_saml_with_flag_off() {
    let (app, claim, conn) = saml_fixture(false).await;
    route(&app, &claim, &conn, false).await;
    account(&app, ALICE).await;
    // Nothing can route while the flag is off: the combined form, and the password signs in.
    let page = login_page(&app).await;
    let html = page.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(!html.contains("login-identify-form"), "{html}");
    let resp = post_page(
        &app,
        &page,
        &[("identifier", ALICE), ("password", PASSWORD)],
    )
    .await;
    signed_in(&resp);
}

#[tokio::test]
async fn email_first_shown_when_only_route_is_saml_with_flag_on() {
    let (app, claim, conn) = saml_fixture(true).await;
    route(&app, &claim, &conn, false).await;
    let page = login_page(&app).await;
    assert_eq!(
        form_id(&page.html()),
        "login-identify-form",
        "{}",
        page.text()
    );
}

#[tokio::test]
async fn email_first_not_shown_for_disabled_or_unverified_route() {
    // An unverified claim with routing on: no email page.
    let h = fixture().await;
    let app = &h.u.app;
    let pending = claim_domain(app, &h.org, "pending-corp.com", false).await;
    set_routing(app, &pending, Some(&h.conn), true, false).await;
    assert_eq!(form_id(&login_page(app).await.html()), "login");
    // The verified claim with routing off: no email page.
    set_routing(app, &h.claim, Some(&h.conn), false, false).await;
    assert_eq!(form_id(&login_page(app).await.html()), "login");
    // Routing on: the email page ...
    route(app, &h.claim, &h.conn, false).await;
    assert_eq!(
        form_id(&login_page(app).await.html()),
        "login-identify-form"
    );
    // ... until the target connection is disabled.
    app.storage()
        .connections()
        .update(
            tenant(app).id,
            h.conn.id,
            &ConnectionUpdate {
                enabled: Some(false),
                ..ConnectionUpdate::default()
            },
            app.clock().now(),
        )
        .await
        .expect("update")
        .expect("connection");
    assert_eq!(form_id(&login_page(app).await.html()), "login");
}

// ---------------------------------------------------------------------------------------------
// Lock and CAPTCHA pages in a routed tenant (06-28)
// ---------------------------------------------------------------------------------------------

const WRONG: &str = "wrong password 123";

fn peer(n: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, n)), 40000)
}

/// An app (`f` applied after the defaults) whose default tenant routes [`DOMAIN`] to an OIDC
/// connection of an org (`allow_local_password = true`), so its sign-in starts at the email page.
async fn routed_app(f: impl FnOnce(&mut AppConfig)) -> TestApp {
    let app = TestApp::with(|c| {
        c.outbound = OutboundPolicy::loopback_dev();
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
        f(c);
    })
    .await;
    let org = create_org(&app, "acme", &[]).await;
    let claim = verify_domain(&app, &org, DOMAIN).await;
    let conn = static_org_oidc(&app, org.id, ORG_SLUG).await;
    route(&app, &claim, &conn, true).await;
    app
}

/// Posts the first form of `page` from `peer` (CSRF token and hidden inputs carried over).
async fn post_page_from(
    app: &TestApp,
    peer: SocketAddr,
    page: &TestResponse,
    pairs: &[(&str, &str)],
) -> TestResponse {
    let html = page.html();
    let action = form_action(app, &html);
    let csrf = csrf_from(&html);
    let hidden: Vec<(String, String)> = hidden_inputs(&html)
        .into_iter()
        .filter(|(n, _)| !pairs.iter().any(|(k, _)| k == n))
        .collect();
    let mut all: Vec<(&str, &str)> = vec![("csrf_token", &csrf)];
    all.extend(hidden.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    all.extend_from_slice(pairs);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(all)
        .finish();
    app.send_from(
        peer,
        Request::builder()
            .method(Method::POST)
            .uri(&action)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("sec-fetch-site", "same-origin")
            .body(Body::from(body))
            .expect("request"),
    )
    .await
}

/// The `flow` parameter of the first form's action.
fn flow_param(app: &TestApp, html: &str) -> String {
    let action = form_action(app, html);
    let url = url::Url::parse(&format!("https://op.test{action}")).expect("action URL");
    url.query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .expect("flow parameter")
}

/// Asserts that `html` carries the email-first form bound to `flow` with `email` echoed.
fn assert_email_first_form(app: &TestApp, html: &str, flow: &str, email: &str) {
    assert_eq!(form_id(html), "login-identify-form", "{html}");
    assert!(!html.contains("type=\"password\""), "{html}");
    assert_eq!(flow_param(app, html), flow, "bound to the posted flow");
    assert!(
        html.contains(&format!("value=\"{email}\"")),
        "identifier echoed: {html}"
    );
}

/// (status, Retry-After, page with per-flow values normalised).
type Observed = (u16, Option<String>, String);

/// The email page, then 5 wrong passwords on the password step of `email` (400), a 6th (429,
/// locked 1 s: the flow's own password step with the lock message) and the right password while
/// locked (429 from the gate, before the flow runs). Returns what each password POST answered,
/// the flow id, and the gate's 429 page.
async fn lock_steps(app: &TestApp, email: &str) -> (Vec<Observed>, String, TestResponse) {
    let mut page = identify(app, email).await;
    assert_password_step(&page, email);
    let flow = flow_param(app, &page.html());
    let mut seen = Vec::new();
    for i in 0..7 {
        let password = if i < 6 { WRONG } else { PASSWORD };
        let resp = post_page(app, &page, &[("password", password)]).await;
        let expected = if i < 5 { 400 } else { 429 };
        assert_eq!(resp.status, expected, "attempt {i}: {}", resp.text());
        if i == 5 {
            // The failure that locks answers with the flow's form (the password step).
            assert_password_step_status(&resp, email);
        }
        seen.push((
            resp.status.as_u16(),
            resp.header("retry-after").map(str::to_owned),
            normalize(&resp.html()),
        ));
        page = resp;
    }
    (seen, flow, page)
}

/// [`assert_password_step`] for a page with any status.
fn assert_password_step_status(resp: &TestResponse, email: &str) {
    let html = resp.html();
    assert_eq!(form_id(&html), "login", "{html}");
    assert!(html.contains("id=\"login-email-locked\""), "{html}");
    assert!(
        hidden_inputs(&html)
            .iter()
            .any(|(n, v)| n == "identifier" && v == email),
        "{html}"
    );
}

#[tokio::test]
async fn locked_page_in_routed_tenant_shows_email_first_form() {
    let app = routed_app(|_| {}).await;
    account(&app, BOB).await;
    let (_, flow, locked) = lock_steps(&app, BOB).await;

    // Locked: the right password is not looked at, and the gate's 429 is the email-first form of
    // the posted flow, not the combined form.
    assert_eq!(locked.header("retry-after"), Some("1"));
    let html = locked.html();
    assert_eq!(
        message_keys(&html),
        vec!["login.too_many_attempts".to_owned()]
    );
    assert_email_first_form(&app, &html, &flow, BOB);
    assert!(session_cookie(&app).is_none());

    // After the lock window the email-first form works on the same flow: routed again, then the
    // password step signs in.
    app.clock().advance(std::time::Duration::from_secs(2));
    let step = post_page(&app, &locked, &[("identifier", BOB)]).await;
    assert_password_step(&step, BOB);
    assert_eq!(flow_param(&app, &step.html()), flow);
    let resp = post_page(&app, &step, &[("password", PASSWORD)]).await;
    signed_in(&resp);
}

#[tokio::test]
async fn locked_page_identical_for_known_and_unknown_identifiers_in_routed_tenant() {
    let known = routed_app(|_| {}).await;
    account(&known, BOB).await;
    let unknown = routed_app(|_| {}).await;
    let (a, ..) = lock_steps(&known, BOB).await;
    let (b, ..) = lock_steps(&unknown, BOB).await;
    assert_eq!(a.len(), b.len());
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(
            x, y,
            "step {i} differs between a known and an unknown identifier"
        );
    }
    // The gate's 429 is the email-first form in both.
    assert!(
        a[6].2.contains("<form id=\"login-identify-form\""),
        "{}",
        a[5].2
    );
    assert_eq!(a[6].1.as_deref(), Some("1"));
}

/// Turnstile settings with `secret` sealed for the default tenant.
fn captcha_settings(app: &TestApp, secret: &str) -> CaptchaSettings {
    let t = tenant(app);
    let sealed = app
        .kek()
        .seal(CAPTCHA_SECRET_PURPOSE, t.id.0.as_bytes(), secret.as_bytes())
        .expect("seal");
    CaptchaSettings {
        provider: CaptchaProvider::Turnstile,
        site_key: "site-key-123".into(),
        secret_sealed: anvil_jose::encoding::b64url(&sealed),
    }
}

#[tokio::test]
async fn captcha_page_in_routed_tenant_shows_email_first_form() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=good-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"success":true}"#))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/siteverify"))
        .and(body_string_contains("response=bad-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"success":false,"error-codes":["invalid-input-response"]}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let uri = server.uri();
    let app = routed_app(|c| {
        c.rate_limits.loose_threshold_per_hour = 5;
        c.captcha_endpoints = CaptchaEndpoints {
            turnstile: format!("{uri}/siteverify"),
            hcaptcha: format!("{uri}/siteverify"),
        };
    })
    .await;
    account(&app, BOB).await;
    let settings = captcha_settings(&app, "provider-secret");
    tenant_settings(&app, |s| s.captcha = Some(settings)).await;

    // Failures from five IPs reach the identifier tier.
    let mut page = identify(&app, BOB).await;
    assert_password_step(&page, BOB);
    let flow = flow_param(&app, &page.html());
    for n in 1..=5 {
        let resp = post_page_from(&app, peer(n), &page, &[("password", WRONG)]).await;
        assert_eq!(resp.status, 400, "ip {n}: {}", resp.text());
        page = resp;
    }
    // A response the provider rejects: the email-first form of the posted flow with the CAPTCHA
    // error, not the combined form.
    let resp = post_page_from(
        &app,
        peer(6),
        &page,
        &[
            ("password", PASSWORD),
            ("cf-turnstile-response", "bad-token"),
        ],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    let html = resp.html();
    assert_eq!(message_keys(&html), vec!["login.captcha_failed".to_owned()]);
    assert_email_first_form(&app, &html, &flow, BOB);
    // The email page posts no CAPTCHA response (the email step is not gated), so it carries no
    // widget; the password step after it does.
    assert!(!html.contains("id=\"captcha-widget\""), "{html}");

    // The email page leads to the password step with the widget (the tier still asks for a
    // CAPTCHA), and a verified CAPTCHA signs in.
    let step = post_page_from(&app, peer(6), &resp, &[("identifier", BOB)]).await;
    assert_password_step(&step, BOB);
    assert!(
        step.html().contains("id=\"captcha-widget\""),
        "{}",
        step.text()
    );
    let resp = post_page_from(
        &app,
        peer(6),
        &step,
        &[
            ("password", PASSWORD),
            ("cf-turnstile-response", "good-token"),
        ],
    )
    .await;
    signed_in(&resp);
}
