//! SAML 2.0 SP sign-in (ORG-03, 06-18), experimental behind `saml_experimental`: start (303 to
//! the IdP with an unsigned HTTP-Redirect AuthnRequest), ACS (cross-site POST, no cookies),
//! continue (binding cookie) and the shared upstream completion. The IdP is the test signer from
//! `saml_support` (06-09); keys and certificates exist only in memory.
//!
//! Every flow-level refusal has a named negative test here; the XML-level attack corpus is
//! `security_saml.rs`.

mod saml_support;
mod support;
mod token_support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;

use anvil_cache::limiter::RateQuota;
use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, ClientAuthMethod, Connection, ConnectionConfig, ConnectionId, ConsentMode,
    MfaPolicy, NameIdFormat, NewConnection, OrgId, Organization, SamlAttributeMapping, SamlConfig,
};
use anvil_core::model::{FlowId, RequestContext};
use anvil_core::ports::{Clock as _, JtiOutcome};
use anvil_core::saml::request::relay_state;
use anvil_core::service::account::{AccountService, SettingsBinding};
use anvil_core::service::flow::{FlowContext, FlowService};
use anvil_core::service::saml::SamlService;
use anvil_jose::encoding::{b64std, b64std_decode, random_bytes};
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use anvil_web::adapters::passkey::WebauthnPasskeys;
use anvil_web::adapters::saml_xml::SamlXmlAdapter;
use anvil_web::adapters::upstream::UpstreamHttp;
use anvil_web::{AppDeps, AppState};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use http_body_util::BodyExt as _;
use saml_support::{IdpKey, ResponseOpts, signed_response};
use support::{DEFAULT_PEER, TestApp, TestClock, TestResponse, csrf_from, location};
use tower::ServiceExt as _;
use ui_helpers::{form_action, message_keys, register};
use upstream_flow::{
    audit, binding_cookie_name, create_org, form_id, get_with_cookies, is_member, links,
    mark_verified, session, tenant, tenant_settings, user, verify_domain,
};

/// Slug of the org's SAML connection.
const SLUG: &str = "acme-saml";
/// The org's verified domain.
const DOMAIN: &str = "acme.example";
/// The user the IdP asserts.
const EMAIL: &str = "alice@acme.example";
/// Her persistent NameID at the IdP.
const SUBJECT: &str = "00u-alice-7f3a";
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const PASSWORD: &str = "correct horse battery";

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

/// An app with the flag on, an org with a verified domain and its SAML connection.
struct Saml {
    app: TestApp,
    key: IdpKey,
    org: Organization,
    conn: Connection,
}

async fn app_with(flag: bool) -> TestApp {
    TestApp::with(|c| {
        c.outbound = OutboundPolicy::loopback_dev();
        c.rate_limits.auth = RateQuota::per_minute(6000, 1000);
        c.saml_experimental = flag;
    })
    .await
}

async fn setup() -> Saml {
    setup_with(true).await
}

async fn setup_with(flag: bool) -> Saml {
    let app = app_with(flag).await;
    let key = IdpKey::rsa();
    let org = create_org(&app, "acme", &[]).await;
    verify_domain(&app, &org, DOMAIN).await;
    let conn = add_saml_connection(&app, Some(org.id), SLUG, &key).await;
    Saml {
        app,
        key,
        org,
        conn,
    }
}

/// Creates an enabled SAML connection through storage (the admin API is 06-17's).
async fn add_saml_connection(
    app: &TestApp,
    org: Option<OrgId>,
    slug: &str,
    key: &IdpKey,
) -> Connection {
    app.storage()
        .connections()
        .create(
            tenant(app).id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                slug: slug.into(),
                display_name: format!("{slug} SAML"),
                enabled: true,
                config: ConnectionConfig::Saml(SamlConfig {
                    idp_entity_id: saml_support::IDP_ENTITY_ID.into(),
                    sso_url: "https://idp.example.test/sso?app=anvil".into(),
                    signing_certs: vec![key.cert_pem()],
                    name_id_format: NameIdFormat::Persistent,
                    attributes: SamlAttributeMapping {
                        email: Some("mail".into()),
                        given_name: Some("givenName".into()),
                        family_name: Some("sn".into()),
                        name: None,
                    },
                    metadata_url: None,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: app.clock().now(),
                org_id: org,
            },
        )
        .await
        .expect("create SAML connection")
}

fn issuer() -> &'static str {
    "https://op.test"
}

fn acs(slug: &str) -> String {
    format!("{}/ui/login/saml/{slug}/acs", issuer())
}

fn sp_entity(slug: &str) -> String {
    format!("{}/saml/{slug}", issuer())
}

// ---------------------------------------------------------------------------------------------
// Driving the flow
// ---------------------------------------------------------------------------------------------

/// A started SAML sign-in: the IdP redirect and what it carries.
#[derive(Debug)]
struct Started {
    location: url::Url,
    relay: String,
    request_id: String,
    request_xml: String,
}

impl Started {
    fn flow_id(&self) -> FlowId {
        let (flow, _) = self.relay.split_once('.').expect("relay state");
        FlowId(uuid::Uuid::parse_str(flow).expect("flow id"))
    }
}

/// The flow id and CSRF token of a sign-in page.
fn page_flow(app: &TestApp, html: &str) -> (String, String) {
    let action = url::Url::parse(&format!("https://op.test{}", form_action(app, html)))
        .expect("login form action");
    let flow = action
        .query_pairs()
        .find(|(k, _)| k == "flow")
        .map(|(_, v)| v.into_owned())
        .expect("login form carries the flow");
    (flow, csrf_from(html))
}

/// Inflates an HTTP-Redirect `SAMLRequest` (raw DEFLATE, base64).
fn inflate(saml_request: &str) -> String {
    let raw = b64std_decode(saml_request).expect("base64 SAMLRequest");
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(raw.as_slice())
        .read_to_string(&mut xml)
        .expect("raw DEFLATE");
    xml
}

/// Posts the SAML start of `slug` from a sign-in page and expects the 303 to the IdP.
async fn start_from(app: &TestApp, html: &str, slug: &str) -> Started {
    let (flow, csrf) = page_flow(app, html);
    let resp = app
        .post_form(
            &format!("/ui/login/saml/{slug}/start?flow={flow}"),
            &[("csrf_token", &csrf)],
        )
        .await;
    assert_eq!(resp.status, 303, "start: {}", resp.text());
    let location = url::Url::parse(&location(&resp)).expect("IdP URL");
    let param = |n: &str| {
        location
            .query_pairs()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.into_owned())
    };
    let request_xml = inflate(&param("SAMLRequest").expect("SAMLRequest"));
    let start = request_xml.find(" ID=\"").expect("request ID") + 5;
    let end = request_xml[start..].find('"').expect("quoted") + start;
    Started {
        relay: param("RelayState").expect("RelayState"),
        request_id: request_xml[start..end].to_owned(),
        request_xml,
        location,
    }
}

/// Opens the sign-in page and starts the SAML sign-in of `slug`.
async fn start(app: &TestApp, slug: &str) -> Started {
    let page = app.get("/ui/login").await;
    assert_eq!(page.status, 200, "{}", page.text());
    start_from(app, &page.html(), slug).await
}

/// A response the core accepts for `started` at the app's current time, posted to `slug`.
fn response_for(app: &TestApp, started: &Started, slug: &str) -> ResponseOpts {
    let now = app.clock().now();
    let acs = acs(slug);
    let mut o = ResponseOpts::valid(now);
    o.assertion_id = format!("_a{}", hex(&random_bytes::<16>()));
    o.response_id = format!("_r{}", hex(&random_bytes::<16>()));
    o.destination = Some(acs.clone());
    o.in_response_to = Some(started.request_id.clone());
    if let Some(c) = o.confirmation.as_mut() {
        c.recipient = Some(acs.clone());
        c.in_response_to = Some(started.request_id.clone());
    }
    if let Some(c) = o.conditions.as_mut() {
        c.audiences = vec![vec![sp_entity(slug)]];
    }
    o.name_id = SUBJECT.into();
    o.name_id_format = Some(PERSISTENT.into());
    o.attributes = vec![
        ("mail".into(), None, vec![EMAIL.into()]),
        ("givenName".into(), None, vec!["Alice".into()]),
        ("sn".into(), None, vec!["Liddell".into()]),
    ];
    o
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `SAMLResponse` form value of `opts` signed by `key`.
fn encode(key: &IdpKey, opts: &ResponseOpts) -> String {
    b64std(signed_response(key, opts).as_bytes())
}

/// The IdP's HTTP-POST binding: a cross-site form post that carries no cookie.
fn acs_request(slug: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    Request::builder()
        .method(Method::POST)
        .uri(format!("/ui/login/saml/{slug}/acs"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .header(header::ORIGIN, "https://idp.example.test")
        // An empty Cookie header keeps the harness from adding the jar: no cookie arrives.
        .header(header::COOKIE, "")
        .header(header::CONTENT_LENGTH, body.len())
        .body(Body::from(body))
        .expect("request")
}

/// Posts `SAMLResponse` / `RelayState` to the ACS of `slug`.
async fn post_acs(
    app: &TestApp,
    slug: &str,
    saml_response: Option<&str>,
    relay: Option<&str>,
) -> TestResponse {
    let mut pairs = Vec::new();
    if let Some(r) = saml_response {
        pairs.push(("SAMLResponse", r));
    }
    if let Some(r) = relay {
        pairs.push(("RelayState", r));
    }
    app.send(acs_request(slug, &pairs)).await
}

/// Starts, lets the IdP answer `opts(started)` and follows to the continue step.
async fn sign_in_with(
    s: &Saml,
    opts: impl FnOnce(&Started, ResponseOpts) -> ResponseOpts,
) -> TestResponse {
    let started = start(&s.app, SLUG).await;
    let o = opts(&started, response_for(&s.app, &started, SLUG));
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_eq!(resp.status, 303, "acs: {}", resp.text());
    s.app.follow(&resp).await
}

async fn sign_in(s: &Saml) -> TestResponse {
    sign_in_with(s, |_, o| o).await
}

/// Reasons of the `saml_login_failed` events, newest first.
async fn saml_failures(app: &TestApp) -> Vec<String> {
    audit(app, AuditAction::SamlLoginFailed)
        .await
        .iter()
        .filter_map(|e| {
            e.details
                .as_map()
                .get("reason")?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

/// Asserts the one generic SAML error page (400) without any identity data.
fn assert_refused(resp: &TestResponse) {
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert!(resp.header("location").is_none());
    let html = resp.html();
    assert!(
        html.contains("data-error-key=\"saml_login_failed\""),
        "{html}"
    );
    assert!(
        html.contains("identity provider did not work"),
        "explains the refusal: {html}"
    );
    for secret in [SUBJECT, EMAIL, "Liddell", "<saml", "Assertion"] {
        assert!(!html.contains(secret), "page leaks {secret}: {html}");
    }
}

async fn flow_state(app: &TestApp, flow: FlowId) -> String {
    app.storage()
        .flows()
        .get(tenant(app).id, flow, app.clock().now())
        .await
        .expect("flow lookup")
        .expect("flow exists")
        .state
}

/// A second app instance on the same database (same KEK, its own router and caches).
fn second_instance(app: &TestApp) -> Router {
    let deps = AppDeps {
        storage: app.storage_arc(),
        clock: Arc::new(TestClock::new(app.clock().now())),
        hasher: Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 2)
                .expect("argon2 pool"),
        ),
        breach: breach_checker(BreachCheckMode::Off),
        kek: app.kek_arc(),
        domain_txt: Arc::new(support::FakeTxt::default()),
    };
    anvil_web::router(AppState::new(app.config.clone(), deps).expect("second instance"))
}

async fn send_to(router: &Router, mut req: Request<Body>) -> TestResponse {
    req.extensions_mut()
        .insert(ConnectInfo::<SocketAddr>(DEFAULT_PEER));
    req.headers_mut()
        .insert(header::HOST, "op.test".parse().expect("host"));
    let resp = router.clone().oneshot(req).await.expect("infallible");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    TestResponse {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn saml_login_happy_path_jit_creates_user_link_membership() {
    let s = setup().await;
    let tenant_id = tenant(&s.app).id;
    let rp = token_support::register_with(
        &s.app,
        tenant_id,
        token_support::web_input(ClientAuthMethod::ClientSecretBasic),
        |c| c.consent_mode = ConsentMode::SkipFirstParty,
    )
    .await;
    let authorize = format!(
        "/authorize?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", rp.id()),
                ("redirect_uri", token_support::REDIRECT),
                ("scope", "openid profile email"),
                ("state", "st-1"),
                ("nonce", token_support::NONCE),
                ("code_challenge", token_support::CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .finish()
    );
    let resp = s.app.get(&authorize).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let page = s.app.follow(&resp).await;
    assert_eq!(page.status, 200, "{}", page.text());

    let started = start_from(&s.app, &page.html(), SLUG).await;
    // Start: the IdP SSO URL keeps its own query, then SAMLRequest and RelayState.
    assert_eq!(started.location.host_str(), Some("idp.example.test"));
    let keys: Vec<String> = started
        .location
        .query_pairs()
        .map(|(k, _)| k.into_owned())
        .collect();
    assert_eq!(keys, ["app", "SAMLRequest", "RelayState"]);
    assert!(started.relay.len() <= 80, "{}", started.relay);
    let xml = &started.request_xml;
    assert!(
        xml.contains("Destination=\"https://idp.example.test/sso?app=anvil\""),
        "{xml}"
    );
    assert!(
        xml.contains(&format!("AssertionConsumerServiceURL=\"{}\"", acs(SLUG))),
        "{xml}"
    );
    assert!(
        xml.contains(&format!("<saml:Issuer>{}</saml:Issuer>", sp_entity(SLUG))),
        "{xml}"
    );
    assert!(xml.contains(PERSISTENT), "{xml}");
    assert!(!xml.contains("ForceAuthn"), "{xml}");
    assert!(!xml.contains("Signature"), "unsigned AuthnRequest: {xml}");
    // The Lax binding cookie is set.
    let binding = binding_cookie_name(&s.app);
    assert!(!binding.is_empty());

    // ACS: validated and sealed, then 303 to the continue step.
    let o = response_for(&s.app, &started, SLUG);
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let cont = location(&resp);
    assert!(
        cont.starts_with(&format!(
            "{}/ui/login/saml/{SLUG}/continue?state=",
            issuer()
        )),
        "{cont}"
    );
    assert!(
        resp.header("set-cookie").is_none(),
        "the ACS sets no cookie"
    );
    assert!(
        session(&s.app).await.is_none(),
        "nothing signed in at the ACS"
    );

    // Continue: signed in, back to the RP with a code.
    let mut resp = s.app.follow(&resp).await;
    for _ in 0..4 {
        if resp.status != 303 || location(&resp).starts_with(token_support::REDIRECT) {
            break;
        }
        resp = s.app.follow(&resp).await;
    }
    assert_eq!(resp.status, 303, "{}", resp.text());
    let back = url::Url::parse(&location(&resp)).expect("RP redirect");
    assert!(back.as_str().starts_with(token_support::REDIRECT), "{back}");
    let code = back
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code for the RP");
    assert!(
        !s.app
            .cookies()
            .keys()
            .any(|k| k.contains("anvil_upstream_")),
        "binding cookie cleared"
    );

    let tokens = token_support::exchange(&s.app, &rp, &code).await;
    assert_eq!(tokens.status, 200, "{}", tokens.text());
    let tokens = support::json(&tokens);
    let claims = token_support::jwt_claims(tokens["id_token"].as_str().expect("id token"));
    assert_eq!(claims["amr"], serde_json::json!(["fed"]), "{claims}");

    // JIT: user with mapped names, trusted email (verified org domain), link and membership.
    let u = user(&s.app, EMAIL).await.expect("JIT user");
    assert!(u.email_verified, "verified org domain trusts the email");
    assert_eq!(u.claims.given_name.as_deref(), Some("Alice"));
    assert_eq!(u.claims.family_name.as_deref(), Some("Liddell"));
    let l = links(&s.app, &u).await;
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].connection_id, s.conn.id);
    assert_eq!(l[0].subject, SUBJECT);
    assert!(is_member(&s.app, &s.org, &u).await);
    assert_eq!(
        audit(&s.app, AuditAction::SamlLoginSucceeded).await.len(),
        1
    );
    assert_eq!(audit(&s.app, AuditAction::OrgMemberAdded).await.len(), 1);
    assert!(saml_failures(&s.app).await.is_empty());
}

#[tokio::test]
async fn saml_existing_linked_user_signs_in() {
    let s = setup().await;
    register(&s.app, "", EMAIL, PASSWORD).await;
    mark_verified(&s.app, EMAIL).await;
    let existing = user(&s.app, EMAIL).await.expect("user");
    upstream_flow::link_identity(&s.app, &existing, &s.conn, SUBJECT).await;

    let resp = sign_in(&s).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
    let sess = session(&s.app).await.expect("session");
    assert_eq!(sess.user_id, existing.id);
    assert_eq!(sess.amr, vec!["fed".to_owned()]);
    // JIT membership for the linked user, and still one link.
    assert!(is_member(&s.app, &s.org, &existing).await);
    assert_eq!(links(&s.app, &existing).await.len(), 1);

    // A second sign-in (new request, new assertion id) works too.
    s.app.clear_cookies();
    let resp = sign_in(&s).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(session(&s.app).await.expect("session").user_id, existing.id);
}

#[tokio::test]
async fn saml_tenant_mfa_policy_applies() {
    let s = setup().await;
    tenant_settings(&s.app, |t| t.mfa_policy = MfaPolicy::Required).await;
    let resp = sign_in(&s).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    // The JIT user has no factor: the required policy enrols one before any session.
    assert_eq!(form_id(&resp.html()), "mfa-enroll", "{}", resp.text());
    assert!(session(&s.app).await.is_none());
}

#[tokio::test]
async fn saml_sp_metadata_served() {
    let s = setup().await;
    let resp = s.app.get(&format!("/saml/{SLUG}/metadata")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        resp.header("content-type"),
        Some("application/samlmetadata+xml")
    );
    let xml = resp.text();
    assert!(
        xml.contains(&format!("entityID=\"{}\"", sp_entity(SLUG))),
        "{xml}"
    );
    assert!(
        xml.contains(&format!("Location=\"{}\"", acs(SLUG))),
        "{xml}"
    );
    assert!(xml.contains("WantAssertionsSigned=\"true\""), "{xml}");
    assert!(xml.contains("AuthnRequestsSigned=\"false\""), "{xml}");
    assert!(
        xml.contains(&format!("<md:NameIDFormat>{PERSISTENT}</md:NameIDFormat>")),
        "{xml}"
    );
    assert!(!xml.contains("Signature"), "unsigned metadata");
    // Unknown and disabled connections: 404.
    assert_eq!(s.app.get("/saml/nope/metadata").await.status, 404);
    s.app
        .storage()
        .connections()
        .update(
            tenant(&s.app).id,
            s.conn.id,
            &anvil_core::model::ConnectionUpdate {
                enabled: Some(false),
                ..Default::default()
            },
            s.app.clock().now(),
        )
        .await
        .expect("disable");
    assert_eq!(
        s.app.get(&format!("/saml/{SLUG}/metadata")).await.status,
        404
    );
}

#[tokio::test]
async fn saml_force_authn_on_prompt_login() {
    let s = setup().await;
    let rp = token_support::register_with(
        &s.app,
        tenant(&s.app).id,
        token_support::web_input(ClientAuthMethod::ClientSecretBasic),
        |c| c.consent_mode = ConsentMode::SkipFirstParty,
    )
    .await;
    let authorize = |prompt: Option<&str>| {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", rp.id()),
            ("redirect_uri", token_support::REDIRECT),
            ("scope", "openid"),
            ("state", "st-1"),
            ("code_challenge", token_support::CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        if let Some(p) = prompt {
            pairs.push(("prompt", p));
        }
        format!(
            "/authorize?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish()
        )
    };
    let resp = s.app.get(&authorize(Some("login"))).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let page = s.app.follow(&resp).await;
    let started = start_from(&s.app, &page.html(), SLUG).await;
    assert!(
        started.request_xml.contains("ForceAuthn=\"true\""),
        "{}",
        started.request_xml
    );

    s.app.clear_cookies();
    let resp = s.app.get(&authorize(None)).await;
    let page = s.app.follow(&resp).await;
    let started = start_from(&s.app, &page.html(), SLUG).await;
    assert!(
        !started.request_xml.contains("ForceAuthn"),
        "{}",
        started.request_xml
    );
}

// ---------------------------------------------------------------------------------------------
// Flow-level refusals
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn saml_unsolicited_response_is_refused() {
    let s = setup().await;
    // IdP-initiated: no InResponseTo anywhere, no RelayState (decision Q4).
    let mut o = ResponseOpts::valid(s.app.clock().now());
    o.destination = Some(acs(SLUG));
    o.in_response_to = None;
    if let Some(c) = o.confirmation.as_mut() {
        c.recipient = Some(acs(SLUG));
        c.in_response_to = None;
    }
    if let Some(c) = o.conditions.as_mut() {
        c.audiences = vec![vec![sp_entity(SLUG)]];
    }
    let unsolicited = encode(&s.key, &o);
    let resp = post_acs(&s.app, SLUG, Some(&unsolicited), None).await;
    assert_refused(&resp);
    // A RelayState that is a URL (a common IdP-initiated convention) is refused too.
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&unsolicited),
        Some("https://rp.example/"),
    )
    .await;
    assert_refused(&resp);
    // A well-formed RelayState of a real flow that has no pending request.
    let page = s.app.get("/ui/login").await;
    let (flow, _) = page_flow(&s.app, &page.html());
    let forged = relay_state(
        FlowId(uuid::Uuid::parse_str(&flow).expect("flow")),
        random_bytes::<16>(),
    );
    let resp = post_acs(&s.app, SLUG, Some(&unsolicited), Some(&forged)).await;
    assert_refused(&resp);
    assert_eq!(
        saml_failures(&s.app).await,
        ["no_pending_request", "relay_state", "relay_state"]
    );
    assert!(session(&s.app).await.is_none());
    assert!(user(&s.app, saml_support::NAME_ID).await.is_none());
}

#[tokio::test]
async fn saml_acs_for_other_connection_is_refused() {
    let s = setup().await;
    let other = add_saml_connection(&s.app, Some(s.org.id), "other-saml", &s.key).await;
    let started = start(&s.app, SLUG).await;
    // A response valid for connection B, posted to B's ACS with A's RelayState.
    let o = response_for(&s.app, &started, &other.slug);
    let resp = post_acs(
        &s.app,
        &other.slug,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["connection_mismatch"]);
    // A's pending request was consumed: the genuine response for A now finds nothing.
    let o = response_for(&s.app, &started, SLUG);
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await[0], "no_pending_request");
    assert!(session(&s.app).await.is_none());
    assert!(user(&s.app, EMAIL).await.is_none());
}

#[tokio::test]
async fn saml_acs_without_binding_cookie_at_continue_is_refused() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let o = response_for(&s.app, &started, SLUG);
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let cont = location(&resp);
    let path = cont.strip_prefix(issuer()).expect("same origin");

    // Another browser (or this one without the cookie) follows the continue link.
    let refused = get_with_cookies(&s.app, path, |k| !k.contains("anvil_upstream_"), None).await;
    assert_refused(&refused);
    assert_eq!(saml_failures(&s.app).await, ["binding"]);
    assert!(session(&s.app).await.is_none());
    assert!(user(&s.app, EMAIL).await.is_none());

    // The flow is intact: the browser with the cookie still completes.
    let resp = s.app.get(path).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session(&s.app).await.is_some());
}

#[tokio::test]
async fn saml_continue_with_foreign_binding_cookie_is_refused() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let name = binding_cookie_name(&s.app);
    let o = response_for(&s.app, &started, SLUG);
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    let cont = location(&resp);
    let path = cont.strip_prefix(issuer()).expect("same origin");

    let refused = get_with_cookies(
        &s.app,
        path,
        |k| !k.contains("anvil_upstream_"),
        Some((&name, "attacker-binding-value")),
    )
    .await;
    assert_refused(&refused);
    assert_eq!(saml_failures(&s.app).await, ["binding"]);
    assert!(session(&s.app).await.is_none());

    let resp = s.app.get(path).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(session(&s.app).await.is_some());
}

#[tokio::test]
async fn saml_replayed_response_is_refused() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let o = response_for(&s.app, &started, SLUG);
    let posted = encode(&s.key, &o);
    let resp = post_acs(&s.app, SLUG, Some(&posted), Some(&started.relay)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    // The same POST again, before and after the continue step.
    assert_refused(&post_acs(&s.app, SLUG, Some(&posted), Some(&started.relay)).await);
    assert_eq!(s.app.follow(&resp).await.status, 200);
    assert_refused(&post_acs(&s.app, SLUG, Some(&posted), Some(&started.relay)).await);
    // Newest first: after the sign-in the flow itself is gone, so the RelayState names nothing.
    assert_eq!(
        saml_failures(&s.app).await,
        ["relay_state", "no_pending_request"]
    );
    // The continue link is single use too.
    let again = s.app.follow(&resp).await;
    assert_refused(&again);
    assert_eq!(
        audit(&s.app, AuditAction::SamlLoginSucceeded).await.len(),
        1
    );
}

#[tokio::test]
async fn saml_replayed_response_is_refused_across_instances() {
    let s = setup().await;
    let second = second_instance(&s.app);
    let started = start(&s.app, SLUG).await;
    let pending_state = flow_state(&s.app, started.flow_id()).await;
    let o = response_for(&s.app, &started, SLUG);
    let posted = encode(&s.key, &o);
    let pairs = [
        ("SAMLResponse", posted.as_str()),
        ("RelayState", started.relay.as_str()),
    ];

    let resp = post_acs(&s.app, SLUG, Some(&posted), Some(&started.relay)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    // The same POST through the second instance: refused (pending request consumed).
    let replay = send_to(&second, acs_request(SLUG, &pairs)).await;
    assert_refused(&replay);
    assert_eq!(saml_failures(&s.app).await, ["no_pending_request"]);

    // Defence in depth: even with the pending request back in the flow (as if the flow-level
    // single use had been bypassed), the assertion id recorded in the database's replay guard
    // refuses the response on the other instance.
    let tenant_id = tenant(&s.app).id;
    let now = s.app.clock().now();
    let current = flow_state(&s.app, started.flow_id()).await;
    assert!(
        s.app
            .storage()
            .flows()
            .swap_state(tenant_id, started.flow_id(), &current, &pending_state, now)
            .await
            .expect("swap")
    );
    let replay = send_to(&second, acs_request(SLUG, &pairs)).await;
    assert_refused(&replay);
    assert_eq!(saml_failures(&s.app).await[0], "replay");
    // The key is sha256(idp entity id || 0x00 || assertion id), kind saml_assertion_id.
    let again = s
        .app
        .storage()
        .grants()
        .record_jti(
            tenant_id,
            anvil_core::model::ReplayKind::SamlAssertionId,
            &anvil_core::saml::validate::replay_key(saml_support::IDP_ENTITY_ID, &o.assertion_id),
            now + time::Duration::minutes(5),
            now,
        )
        .await
        .expect("record_jti");
    assert_eq!(again, JtiOutcome::Replayed);
    assert!(session(&s.app).await.is_none());
}

#[tokio::test]
async fn saml_response_for_other_flow_is_refused() {
    let s = setup().await;
    let first = start(&s.app, SLUG).await;
    s.app.clear_cookies();
    let second = start(&s.app, SLUG).await;
    assert_ne!(first.flow_id(), second.flow_id());
    // The response answers the first flow's request but carries the second flow's RelayState.
    let o = response_for(&s.app, &first, SLUG);
    let resp = post_acs(&s.app, SLUG, Some(&encode(&s.key, &o)), Some(&second.relay)).await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["in_response_to_mismatch"]);
    // A RelayState with the right flow and a wrong nonce does not consume anything.
    let forged = relay_state(first.flow_id(), random_bytes::<16>());
    let o = response_for(&s.app, &first, SLUG);
    let resp = post_acs(&s.app, SLUG, Some(&encode(&s.key, &o)), Some(&forged)).await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await[0], "relay_state");
    let resp = post_acs(&s.app, SLUG, Some(&encode(&s.key, &o)), Some(&first.relay)).await;
    assert_eq!(
        resp.status,
        303,
        "the first flow is still pending: {}",
        resp.text()
    );
}

#[tokio::test]
async fn saml_pending_request_expires() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    s.app.clock().advance(std::time::Duration::from_secs(600));
    // A response that is itself valid at this time.
    let o = response_for(&s.app, &started, SLUG);
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["expired"]);
    assert!(session(&s.app).await.is_none());
}

#[tokio::test]
async fn saml_wrong_audience_is_refused_with_generic_page() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let mut o = response_for(&s.app, &started, SLUG);
    if let Some(c) = o.conditions.as_mut() {
        c.audiences = vec![vec!["https://other-sp.example.test".into()]];
    }
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["audience_mismatch"]);
    // The audit event carries the reason code and the connection, nothing from the assertion.
    let events = audit(&s.app, AuditAction::SamlLoginFailed).await;
    let details = serde_json::to_string(events[0].details.as_map()).expect("json");
    for secret in [SUBJECT, EMAIL, "Alice", "Liddell"] {
        assert!(!details.contains(secret), "{details}");
    }
    assert!(user(&s.app, EMAIL).await.is_none());
}

#[tokio::test]
async fn saml_transient_name_id_is_refused() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let mut o = response_for(&s.app, &started, SLUG);
    o.name_id_format = Some(TRANSIENT.into());
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&s.key, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["transient_name_id"]);
    assert!(user(&s.app, EMAIL).await.is_none());
}

#[tokio::test]
async fn saml_unsigned_or_foreign_signed_response_is_refused() {
    let s = setup().await;
    let started = start(&s.app, SLUG).await;
    let o = response_for(&s.app, &started, SLUG);
    let other = IdpKey::rsa();
    let resp = post_acs(
        &s.app,
        SLUG,
        Some(&encode(&other, &o)),
        Some(&started.relay),
    )
    .await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await, ["untrusted_key"]);
    let started = start(&s.app, SLUG).await;
    let resp = post_acs(&s.app, SLUG, Some("not base64!"), Some(&started.relay)).await;
    assert_refused(&resp);
    assert_eq!(saml_failures(&s.app).await[0], "encoding");
}

#[tokio::test]
async fn saml_foreign_domain_email_is_untrusted() {
    const VICTIM: &str = "victim@orgb.example";
    let s = setup().await;
    tenant_settings(&s.app, |t| t.auto_link = true).await;
    let org_b = create_org(&s.app, "org-b", &[]).await;
    verify_domain(&s.app, &org_b, "orgb.example").await;
    register(&s.app, "", VICTIM, PASSWORD).await;
    mark_verified(&s.app, VICTIM).await;
    let victim = user(&s.app, VICTIM).await.expect("victim");

    // The org's SAML IdP asserts an address on org B's verified domain.
    let resp = sign_in_with(&s, |_, mut o| {
        o.attributes = vec![("mail".into(), None, vec![VICTIM.into()])];
        o
    })
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(!html.contains(VICTIM), "{html}");
    assert!(links(&s.app, &victim).await.is_empty(), "never auto-linked");
    assert!(session(&s.app).await.is_none());
    assert!(!is_member(&s.app, &s.org, &victim).await);
}

// ---------------------------------------------------------------------------------------------
// Body limit and the operator flag
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn saml_acs_body_over_256_kib_is_413() {
    let s = setup().await;
    let big = "A".repeat(300 * 1024);
    let resp = post_acs(&s.app, SLUG, Some(&big), Some("x")).await;
    assert_eq!(resp.status, 413, "{}", resp.text());
    // Above the 64 KiB default but within 256 KiB: the ACS reads it (and refuses the content).
    let medium = "A".repeat(100 * 1024);
    let resp = post_acs(&s.app, SLUG, Some(&medium), None).await;
    assert_refused(&resp);
    // Every other UI form keeps the default limit.
    let resp = s
        .app
        .post_form("/ui/login", &[("identifier", &medium), ("password", "x")])
        .await;
    assert_eq!(resp.status, 413, "{}", resp.text());
}

#[tokio::test]
async fn saml_routes_404_when_flag_off() {
    let s = setup_with(false).await;
    let page = s.app.get("/ui/login").await;
    let (flow, csrf) = page_flow(&s.app, &page.html());
    let resp = s
        .app
        .post_form(
            &format!("/ui/login/saml/{SLUG}/start?flow={flow}"),
            &[("csrf_token", &csrf)],
        )
        .await;
    assert_eq!(resp.status, 404, "{}", resp.text());
    let relay = relay_state(
        FlowId(uuid::Uuid::parse_str(&flow).expect("flow")),
        random_bytes::<16>(),
    );
    assert_eq!(
        post_acs(&s.app, SLUG, Some("PHgvPg=="), Some(&relay))
            .await
            .status,
        404
    );
    let path = format!("/ui/login/saml/{SLUG}/continue?state={relay}");
    assert_eq!(s.app.get(&path).await.status, 404);
    assert_eq!(
        s.app.get(&format!("/saml/{SLUG}/metadata")).await.status,
        404
    );
    assert!(saml_failures(&s.app).await.is_empty(), "nothing reached");

    // The service itself refuses with FeatureDisabled.
    let app = &s.app;
    let clock: Arc<dyn anvil_core::ports::Clock> = Arc::new(TestClock::new(app.clock().now()));
    let flows = FlowService {
        storage: app.storage_arc(),
        clock: Arc::clone(&clock),
        hasher: Arc::new(
            Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 1)
                .expect("argon2"),
        ),
        breach: breach_checker(BreachCheckMode::Off),
        policy: anvil_core::policy::PasswordPolicy::default(),
        kek: app.kek_arc(),
        passkeys: Arc::new(WebauthnPasskeys),
    };
    let accounts = AccountService {
        storage: app.storage_arc(),
        clock,
        kek: app.kek_arc(),
        passkeys: Arc::new(WebauthnPasskeys),
    };
    let upstream = UpstreamHttp::new(Arc::new(
        OutboundClient::new(&OutboundPolicy::default()).expect("outbound"),
    ));
    let svc = SamlService {
        flows: &flows,
        accounts: &accounts,
        client: &upstream,
        saml_xml: &SamlXmlAdapter,
        enabled: false,
    };
    let t = tenant(app);
    let ctx = RequestContext::default();
    let rp = Err(CoreError::Internal("no relying party in this test".into()));
    let cx = FlowContext {
        tenant: &t,
        issuer: issuer(),
        ui_base: "https://op.test/ui",
        rp: &rp,
        ctx: &ctx,
    };
    let disabled = |r: Result<(), CoreError>| {
        assert!(
            matches!(r, Err(CoreError::FeatureDisabled("saml"))),
            "{r:?}"
        );
    };
    let binding = SettingsBinding {
        flow_id: FlowId(uuid::Uuid::parse_str(&flow).expect("flow")),
        cookie_token: None,
        csrf_token: &csrf,
    };
    disabled(svc.start(&cx, &binding, SLUG).await.map(|_| ()));
    disabled(
        svc.acs(&cx, SLUG, Some("PHgvPg=="), Some(&relay))
            .await
            .map(|_| ()),
    );
    disabled(
        svc.continue_login(&cx, SLUG, Some(&relay), None, None)
            .await
            .map(|_| ()),
    );
    disabled(svc.sp_metadata(t.id, issuer(), SLUG).await.map(|_| ()));
}
