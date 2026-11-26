//! RFC 8707 resource indicators (OIDC-16) end to end over HTTP on the selected backend
//! (`ANVILID_TEST_DB`): `resource` is the only parameter that may repeat at /authorize and
//! /token; bad or unlisted resources are `invalid_target` (redirect at /authorize, JSON 400 at
//! /token); the granted resources travel on the code, the token family and opaque tokens; the
//! code, refresh and client-credentials grants can only downscope; access-token `aud` is the
//! selected resource(s) (string or array), the client id without one; ID tokens keep
//! `aud = [client_id]`; introspection returns `aud`; UserInfo refuses tokens whose `aud` holds
//! neither the client id nor `{issuer}/userinfo`; the consent screen lists the resources.
//!
//! MCP prerequisites (AGT-01/AGT-02): the RFC 8414 path-insertion document of a path tenant
//! carries the fields an MCP client relies on (issuer, endpoints, S256, the CIMD flag and the
//! registration endpoint per tenant policy) exactly as the path-appended OIDC document does; a
//! Client ID Metadata Document client asking for an MCP server gets `aud` = that server and
//! cannot obtain or use the token for another resource.
//!
//! Clients are created through storage with `allowed_resources` (the admin API for that field is
//! another plan's); every client skips consent except in the consent-screen test. CIMD clients
//! take their resources from the tenant's `dcr.allowed_resources`.

mod authz;
mod cimd_support;
mod support;
mod token_support;

use anvil_core::model::{
    CimdPolicy, ClientAuthMethod, ClientUpdate, ConsentId, ConsentMode, DcrPolicy, GrantType,
    NewConsent, SecretHash, TenantId, TenantUpdate, TokenFormat,
};
use anvil_jose::encoding::secret_hash;
use serde_json::{Value, json as j};
use support::{TestApp, TestResponse, json, location};
use token_support::{
    CHALLENGE, ClockNow, REDIRECT, Rp, VERIFIER, assert_invalid_token, assert_oauth_error,
    cc_input, jwt_claims, register, seed_user, token, token_at, userinfo_get, web_input,
};

const API: &str = "https://api.example.test";
const MCP: &str = "https://mcp.example.test/mcp";

// ---------------------------------------------------------------------------------------------
// Helpers (test code only)
// ---------------------------------------------------------------------------------------------

/// A signed-in user and a confidential web client allowed to request `allowed`.
struct Fixture {
    app: TestApp,
    tenant: TenantId,
    rp: Rp,
    /// `Cookie` header value of the user's session.
    session: String,
    iss: String,
}

async fn fixture_with(allowed: &[&str], format: TokenFormat, consent: ConsentMode) -> Fixture {
    let app = TestApp::new().await;
    let tenant = authz::default_tenant(&app);
    let mut rp = register(
        &app,
        tenant.id,
        web_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    rp.client = app
        .storage()
        .clients()
        .update(
            tenant.id,
            rp.id(),
            &ClientUpdate {
                allowed_resources: Some(allowed.iter().map(|s| (*s).to_owned()).collect()),
                consent_mode: Some(consent),
                token_format: Some(format),
                ..ClientUpdate::default()
            },
            app.clock_now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    let user = seed_user(&app, tenant.id, "ada@example.test").await;
    let session = authz::session(&app, &tenant, user.id).await;
    let iss = app.issuer(None);
    Fixture {
        app,
        tenant: tenant.id,
        rp,
        session,
        iss,
    }
}

async fn fixture(allowed: &[&str]) -> Fixture {
    fixture_with(allowed, TokenFormat::Jwt, ConsentMode::SkipFirstParty).await
}

impl Fixture {
    /// GET /authorize (with the session) for `scope` and the given `resource` values.
    async fn authorize(
        &self,
        scope: &str,
        resources: &[&str],
        extra: &[(&str, &str)],
    ) -> TestResponse {
        let mut p: Vec<(&str, &str)> = vec![
            ("response_type", "code"),
            ("client_id", self.rp.id()),
            ("redirect_uri", REDIRECT),
            ("scope", scope),
            ("state", "st-1"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        p.extend(resources.iter().map(|r| ("resource", *r)));
        p.extend_from_slice(extra);
        authz::get(
            &self.app,
            &authz::authorize_path("", &p),
            Some(&self.session),
        )
        .await
    }

    /// /authorize → the code (asserting a successful redirect).
    async fn code(&self, scope: &str, resources: &[&str]) -> String {
        let resp = self.authorize(scope, resources, &[]).await;
        assert_eq!(resp.status, 303, "{}", resp.text());
        assert!(location(&resp).starts_with(REDIRECT), "{}", location(&resp));
        assert!(
            authz::param(&resp, "error").is_none(),
            "{}",
            location(&resp)
        );
        authz::param(&resp, "code").expect("code")
    }

    /// Exchanges `code`, asking for `resources` at the token endpoint.
    async fn exchange(&self, code: &str, resources: &[&str]) -> TestResponse {
        let mut p = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ];
        p.extend(resources.iter().map(|r| ("resource", *r)));
        token(&self.app, &self.rp.auth(), &p).await
    }

    /// Code flow to a 200 token response.
    async fn tokens(&self, scope: &str, at_authorize: &[&str], at_token: &[&str]) -> Value {
        let code = self.code(scope, at_authorize).await;
        let resp = self.exchange(&code, at_token).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        json(&resp)
    }

    async fn refresh(&self, rt: &str, resources: &[&str]) -> TestResponse {
        let mut p = vec![("grant_type", "refresh_token"), ("refresh_token", rt)];
        p.extend(resources.iter().map(|r| ("resource", *r)));
        token(&self.app, &self.rp.auth(), &p).await
    }

    async fn introspect(&self, tok: &str) -> Value {
        let resp = token_at(&self.app, "/introspect", &self.rp.auth(), &[("token", tok)]).await;
        assert_eq!(resp.status, 200, "{}", resp.text());
        json(&resp)
    }
}

fn field(body: &Value, name: &str) -> String {
    body[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} in {body}"))
        .to_owned()
}

fn aud_of(body: &Value) -> Value {
    jwt_claims(&field(body, "access_token"))["aud"].clone()
}

/// Asserts a 303 error redirect to the client with `error`, `state` and `iss`.
fn assert_redirect_error(resp: &TestResponse, error: &str, iss: &str) {
    authz::assert_error_redirect(resp, REDIRECT, error, iss);
    assert_eq!(authz::param(resp, "state").as_deref(), Some("st-1"));
}

// ---------------------------------------------------------------------------------------------
// Audience of the tokens
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn one_resource_makes_aud_that_string_and_the_id_token_keeps_the_client() {
    let f = fixture(&[API, MCP]).await;
    let body = f.tokens("openid", &[API], &[]).await;
    let claims = jwt_claims(&field(&body, "access_token"));
    assert_eq!(claims["aud"], j!(API));
    assert_eq!(claims["client_id"], j!(f.rp.id()));
    let id = jwt_claims(&field(&body, "id_token"));
    assert_eq!(id["aud"], j!([f.rp.id()]), "ID token aud stays the client");

    // The grant is stored on the family.
    let fid = anvil_core::service::userinfo::parse_family_id(claims["fid"].as_str().expect("fid"))
        .expect("uuid");
    let family = f
        .app
        .storage()
        .grants()
        .get_family(f.tenant, fid)
        .await
        .expect("family lookup")
        .expect("family");
    assert_eq!(family.resource, [API]);
}

#[tokio::test]
async fn two_resources_make_aud_an_array_in_request_order() {
    let f = fixture(&[API, MCP]).await;
    let body = f.tokens("openid", &[MCP, API], &[]).await;
    assert_eq!(aud_of(&body), j!([MCP, API]));
}

#[tokio::test]
async fn no_resource_keeps_aud_the_client_id() {
    let f = fixture(&[API]).await;
    let body = f.tokens("openid", &[], &[]).await;
    assert_eq!(aud_of(&body), j!(f.rp.id()));
}

// ---------------------------------------------------------------------------------------------
// /authorize validation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn other_repeated_parameters_stay_invalid_request() {
    let f = fixture(&[API, MCP]).await;
    let resp = f
        .authorize("openid", &[API, MCP], &[("scope", "openid")])
        .await;
    assert_redirect_error(&resp, "invalid_request", &f.iss);
    let resp = f
        .authorize("openid", &[API], &[("nonce", "a"), ("nonce", "b")])
        .await;
    assert_redirect_error(&resp, "invalid_request", &f.iss);
}

#[tokio::test]
async fn unlisted_or_malformed_resources_redirect_invalid_target() {
    let f = fixture(&[API, MCP]).await;
    for bad in [
        "https://other.example.test",
        // Exact match only: no normalisation.
        "https://api.example.test/",
        "https://API.example.test",
        // RFC 8707 §2: absolute, no fragment, no query.
        "/relative",
        "api",
        "https://api.example.test#frag",
        "https://api.example.test?q=1",
    ] {
        let resp = f.authorize("openid", &[API, bad], &[]).await;
        assert_redirect_error(&resp, "invalid_target", &f.iss);
    }
    // A client with no allowed resources may not ask for any.
    let none = fixture(&[]).await;
    let resp = none.authorize("openid", &[API], &[]).await;
    assert_redirect_error(&resp, "invalid_target", &none.iss);
}

#[tokio::test]
async fn a_bad_resource_with_an_untrusted_redirect_is_an_error_page() {
    let f = fixture(&[API]).await;
    // The redirect URI is checked first: a bad resource never turns an untrusted redirect URI
    // into a redirect.
    let p = [
        ("response_type", "code"),
        ("client_id", f.rp.id()),
        ("redirect_uri", "https://evil.example.test/cb"),
        ("scope", "openid"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("resource", "https://other.example.test"),
        ("resource", "/relative"),
    ];
    let resp = authz::get(&f.app, &authz::authorize_path("", &p), Some(&f.session)).await;
    authz::assert_error_page(&resp, "redirect_uri_mismatch");
}

// ---------------------------------------------------------------------------------------------
// /token: downscoping
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn code_exchange_downscopes_to_a_subset() {
    let f = fixture(&[API, MCP]).await;
    let body = f.tokens("openid", &[API, MCP], &[MCP]).await;
    assert_eq!(aud_of(&body), j!(MCP));
    // Repeating the same resource is fine (deduplicated).
    let body = f.tokens("openid", &[API, MCP], &[API, API]).await;
    assert_eq!(aud_of(&body), j!(API));
}

#[tokio::test]
async fn code_exchange_outside_the_grant_is_invalid_target_and_burns_the_code() {
    let f = fixture(&[API, MCP]).await;
    let code = f.code("openid", &[API]).await;
    let resp = f.exchange(&code, &[MCP]).await;
    assert_oauth_error(&resp, 400, "invalid_target");
    // The code is single use: it cannot be retried with a valid resource.
    let resp = f.exchange(&code, &[API]).await;
    assert_oauth_error(&resp, 400, "invalid_grant");

    // No resource at /authorize: none can be added at /token.
    let code = f.code("openid", &[]).await;
    assert_oauth_error(&f.exchange(&code, &[API]).await, 400, "invalid_target");
}

#[tokio::test]
async fn malformed_resources_at_token_are_invalid_target_before_the_code_is_used() {
    let f = fixture(&[API]).await;
    let code = f.code("openid", &[API]).await;
    for bad in [
        "/relative",
        "https://api.example.test#f",
        "https://api.example.test?q",
    ] {
        assert_oauth_error(&f.exchange(&code, &[bad]).await, 400, "invalid_target");
    }
    // The code survived the malformed attempts.
    let resp = f.exchange(&code, &[API]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}

#[tokio::test]
async fn other_repeated_token_parameters_stay_invalid_request() {
    let f = fixture(&[API, MCP]).await;
    let code = f.code("openid", &[API, MCP]).await;
    let resp = token(
        &f.app,
        &f.rp.auth(),
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
            ("resource", API),
            ("resource", MCP),
        ],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_request");
}

#[tokio::test]
async fn refresh_downscopes_and_the_refresh_token_keeps_the_full_grant() {
    let f = fixture(&[API, MCP]).await;
    let body = f.tokens("openid offline_access", &[API, MCP], &[API]).await;
    assert_eq!(aud_of(&body), j!(API));
    let rt = field(&body, "refresh_token");

    // Downscope to the other granted resource at refresh.
    let resp = f.refresh(&rt, &[MCP]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert_eq!(aud_of(&body), j!(MCP));
    let rt = field(&body, "refresh_token");

    // Outside the grant: invalid_target, and the refresh token is not consumed.
    assert_oauth_error(
        &f.refresh(&rt, &["https://other.example.test"]).await,
        400,
        "invalid_target",
    );
    assert_oauth_error(&f.refresh(&rt, &["/relative"]).await, 400, "invalid_target");

    // No resource: the whole grant again.
    let resp = f.refresh(&rt, &[]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(aud_of(&json(&resp)), j!([API, MCP]));
}

// ---------------------------------------------------------------------------------------------
// Client credentials
// ---------------------------------------------------------------------------------------------

async fn cc_client(app: &TestApp, tenant: TenantId, allowed: &[&str]) -> Rp {
    let mut rp = register(app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    assert_eq!(rp.client.grant_types, [GrantType::ClientCredentials]);
    rp.client = app
        .storage()
        .clients()
        .update(
            tenant,
            rp.id(),
            &ClientUpdate {
                allowed_resources: Some(allowed.iter().map(|s| (*s).to_owned()).collect()),
                ..ClientUpdate::default()
            },
            app.clock_now(),
        )
        .await
        .expect("client update")
        .expect("client exists");
    rp
}

#[tokio::test]
async fn client_credentials_accepts_allowed_resources_only() {
    let app = TestApp::new().await;
    let tenant = authz::default_tenant(&app).id;
    let rp = cc_client(&app, tenant, &[API, MCP]).await;
    let cc = |resources: Vec<&'static str>| {
        let mut p = vec![("grant_type", "client_credentials")];
        p.extend(resources.into_iter().map(|r| ("resource", r)));
        let auth = rp.auth();
        let app = &app;
        async move { token(app, &auth, &p).await }
    };

    let resp = cc(vec![API]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(aud_of(&json(&resp)), j!(API));

    let resp = cc(vec![API, MCP]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(aud_of(&json(&resp)), j!([API, MCP]));

    let resp = cc(vec![]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(aud_of(&json(&resp)), j!(rp.id()));

    assert_oauth_error(
        &cc(vec!["https://other.example.test"]).await,
        400,
        "invalid_target",
    );
    assert_oauth_error(
        &cc(vec![API, "https://api.example.test/"]).await,
        400,
        "invalid_target",
    );
    assert_oauth_error(
        &cc(vec!["https://api.example.test#x"]).await,
        400,
        "invalid_target",
    );

    // A client without allowed resources gets none.
    let plain = cc_client(&app, tenant, &[]).await;
    let resp = token(
        &app,
        &plain.auth(),
        &[("grant_type", "client_credentials"), ("resource", API)],
    )
    .await;
    assert_oauth_error(&resp, 400, "invalid_target");
}

// ---------------------------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn introspection_returns_aud_for_opaque_and_jwt_tokens() {
    let f = fixture_with(
        &[API, MCP],
        TokenFormat::Opaque,
        ConsentMode::SkipFirstParty,
    )
    .await;
    let body = f.tokens("openid", &[API, MCP], &[MCP]).await;
    let at = field(&body, "access_token");
    assert!(!at.contains('.'), "opaque token");
    let stored = f
        .app
        .storage()
        .grants()
        .find_access_token(f.tenant, &SecretHash(secret_hash(&at)))
        .await
        .expect("lookup")
        .expect("stored");
    assert_eq!(
        stored.0.resource,
        [MCP],
        "the selection is stored on the opaque row"
    );
    let v = f.introspect(&at).await;
    assert_eq!(v["active"], true);
    assert_eq!(v["aud"], j!(MCP));
    assert_eq!(v["client_id"], j!(f.rp.id()));

    let both = f.tokens("openid", &[API, MCP], &[]).await;
    let v = f.introspect(&field(&both, "access_token")).await;
    assert_eq!(v["aud"], j!([API, MCP]));

    let plain = f.tokens("openid", &[], &[]).await;
    let v = f.introspect(&field(&plain, "access_token")).await;
    assert_eq!(v["aud"], j!(f.rp.id()));

    // JWT tokens: aud from the claims.
    let jf = fixture(&[API, MCP]).await;
    let body = jf.tokens("openid", &[API, MCP], &[]).await;
    let v = jf.introspect(&field(&body, "access_token")).await;
    assert_eq!(v["active"], true);
    assert_eq!(v["aud"], j!([API, MCP]));
}

// ---------------------------------------------------------------------------------------------
// UserInfo audience rule
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn userinfo_refuses_tokens_bound_only_to_other_resources() {
    let probe = TestApp::new().await;
    let userinfo_aud = format!("{}/userinfo", probe.issuer(None));
    drop(probe);
    let f = fixture(&[API, &userinfo_aud]).await;
    assert_eq!(format!("{}/userinfo", f.iss), userinfo_aud);

    // aud = [API] only: invalid_token.
    let body = f.tokens("openid email", &[API], &[]).await;
    assert_invalid_token(&userinfo_get(&f.app, &field(&body, "access_token")).await);

    // aud contains {issuer}/userinfo: accepted.
    let body = f.tokens("openid email", &[API, &userinfo_aud], &[]).await;
    let resp = userinfo_get(&f.app, &field(&body, "access_token")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp)["email"], "ada@example.test");

    // No resource (aud = client_id): accepted, as in 0.2.
    let body = f.tokens("openid", &[], &[]).await;
    let resp = userinfo_get(&f.app, &field(&body, "access_token")).await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // Opaque tokens follow the same rule.
    let o = fixture_with(&[API], TokenFormat::Opaque, ConsentMode::SkipFirstParty).await;
    let body = o.tokens("openid", &[API], &[]).await;
    assert_invalid_token(&userinfo_get(&o.app, &field(&body, "access_token")).await);
}

// ---------------------------------------------------------------------------------------------
// Consent screen
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_consent_screen_lists_the_requested_resources() {
    let f = fixture_with(&[API, MCP], TokenFormat::Jwt, ConsentMode::Required).await;
    let resp = f.authorize("openid", &[MCP, API], &[]).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let loc = location(&resp);
    let prefix = format!("{}/ui/consent?request=", f.iss);
    assert!(loc.starts_with(&prefix), "{loc}");
    let path = format!("/ui/consent?request={}", &loc[prefix.len()..]);
    let page = authz::get(&f.app, &path, Some(&f.session)).await;
    assert_eq!(page.status, 200, "{}", page.text());
    let html = page.html();
    assert!(
        html.contains("id=\"consent-resources-heading\">Access to</h2>"),
        "{html}"
    );
    let first = html.find(&format!(
        "id=\"consent-resource-1\" data-resource=\"{MCP}\""
    ));
    let second = html.find(&format!(
        "id=\"consent-resource-2\" data-resource=\"{API}\""
    ));
    assert!(first.is_some() && second.is_some(), "{html}");
    assert!(first < second, "request order");
    assert!(
        html.contains(&format!("<bdi><code>{API}</code></bdi>")),
        "{html}"
    );

    // Without resources the section is absent.
    let resp = f.authorize("openid", &[], &[]).await;
    let loc = location(&resp);
    let path = format!("/ui/consent?request={}", &loc[prefix.len()..]);
    let html = authz::get(&f.app, &path, Some(&f.session)).await.html();
    assert!(!html.contains("consent-resources"), "{html}");
}

// ---------------------------------------------------------------------------------------------
// MCP prerequisites: RFC 8414 path insertion and CIMD clients bound to one resource
// ---------------------------------------------------------------------------------------------

/// Metadata fields an MCP client reads (MCP authorization, revision 2026-07-28: endpoints, PKCE
/// S256 support, the CIMD flag, the registration endpoint, RFC 9207 `iss`).
const MCP_FIELDS: [&str; 9] = [
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
    "code_challenge_methods_supported",
    "client_id_metadata_document_supported",
    "registration_endpoint",
    "authorization_response_iss_parameter_supported",
    "scopes_supported",
];

async fn discovery(app: &TestApp, path: &str) -> Value {
    let resp = app.get(path).await;
    assert_eq!(resp.status, 200, "{path}: {}", resp.text());
    json(&resp)
}

#[tokio::test]
async fn rfc8414_path_insertion_serves_the_mcp_fields_of_a_path_tenant() {
    let app = TestApp::new().await;
    let tenant = authz::path_tenant(&app, "agents").await;
    let inserted = "/.well-known/oauth-authorization-server/t/agents";
    let appended = "/t/agents/.well-known/openid-configuration";
    let iss = app.issuer(Some("agents"));

    // Default policies (disabled): no CIMD flag and no registration endpoint on either form.
    for path in [inserted, appended] {
        let doc = discovery(&app, path).await;
        assert!(
            doc.get("client_id_metadata_document_supported").is_none(),
            "{path}"
        );
        assert!(doc.get("registration_endpoint").is_none(), "{path}");
    }

    let mut settings = tenant.settings.clone();
    settings.cimd.policy = CimdPolicy::Open;
    settings.dcr.policy = DcrPolicy::Open;
    app.storage()
        .tenants()
        .update(
            tenant.id,
            &TenantUpdate {
                settings: Some(settings),
                ..TenantUpdate::default()
            },
        )
        .await
        .expect("tenant update")
        .expect("tenant exists");

    let a = discovery(&app, inserted).await;
    let b = discovery(&app, appended).await;
    for f in MCP_FIELDS {
        assert!(!a[f].is_null(), "{f} missing: {a}");
        assert_eq!(a[f], b[f], "{f}");
    }
    // MCP clients compare `issuer` with the issuer they built the well-known URL from.
    assert_eq!(a["issuer"], j!(iss));
    assert_eq!(a["authorization_endpoint"], j!(format!("{iss}/authorize")));
    assert_eq!(a["token_endpoint"], j!(format!("{iss}/token")));
    assert_eq!(a["registration_endpoint"], j!(format!("{iss}/register")));
    assert_eq!(a["client_id_metadata_document_supported"], true);
    assert_eq!(a["authorization_response_iss_parameter_supported"], true);
    assert!(
        a["code_challenge_methods_supported"]
            .as_array()
            .is_some_and(|m| m.iter().any(|v| v == "S256")),
        "{a}"
    );

    // The root RFC 8414 document is the default tenant's, unaffected by the path tenant.
    let root = discovery(&app, "/.well-known/oauth-authorization-server").await;
    assert_ne!(root["issuer"], j!(iss));
    assert!(root.get("client_id_metadata_document_supported").is_none());
    assert!(root.get("registration_endpoint").is_none());
}

#[tokio::test]
async fn a_cimd_client_gets_a_token_for_the_mcp_server_and_no_other_resource() {
    use cimd_support::{DOC_PATH, DocServer};

    // Development mode: the metadata document is served over http on loopback.
    let app = TestApp::dev().await;
    let tenant = cimd_support::set_policy(&app, CimdPolicy::Open, &[], &[MCP]).await;
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &cimd_support::doc(&client_id), None)
        .await;
    let user = authz::user(&app, &tenant, "ada@example.test").await;
    let session = authz::session(&app, &tenant, user).await;
    let iss = app.issuer(None);
    let authorize =
        |resource: &str| cimd_support::authorize_path(&client_id, &[("resource", resource)]);

    // A resource outside `dcr.allowed_resources`: invalid_target to the document's redirect URI.
    let resp = authz::get(&app, &authorize(API), Some(&session)).await;
    authz::assert_error_redirect(&resp, authz::RP, "invalid_target", &iss);

    // The user consented to the MCP server (the consent screen is covered in consent.rs).
    app.storage()
        .grants()
        .upsert_consent(
            tenant.id,
            &NewConsent {
                id: ConsentId::new_v7(),
                user_id: user,
                client_id: client_id.clone(),
                scopes: vec!["openid".into(), "profile".into()],
                resources: vec![MCP.into()],
                created_at: app.clock_now(),
            },
            app.clock_now(),
        )
        .await
        .expect("consent");
    let code = cimd_code(&app, &authorize(MCP), &session).await;

    // Token request for another resource: invalid_target, and the code is gone.
    let exchange = |code: String, resource: &'static str| {
        let client_id = client_id.clone();
        let app = &app;
        async move {
            app.post_form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", authz::RP),
                    ("code_verifier", VERIFIER),
                    ("client_id", &client_id),
                    ("resource", resource),
                ],
            )
            .await
        }
    };
    assert_oauth_error(&exchange(code.clone(), API).await, 400, "invalid_target");
    assert_oauth_error(&exchange(code, MCP).await, 400, "invalid_grant");

    // The MCP-shaped request (resource at /authorize and /token): aud is exactly the MCP server.
    let code = cimd_code(&app, &authorize(MCP), &session).await;
    let resp = exchange(code, MCP).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    let claims = jwt_claims(&field(&body, "access_token"));
    assert_eq!(claims["aud"], j!(MCP));
    assert_eq!(claims["iss"], j!(iss));
    assert_eq!(claims["client_id"], j!(client_id));
    let id = jwt_claims(&field(&body, "id_token"));
    assert_eq!(id["aud"], j!([client_id]), "ID token aud stays the client");

    // Another resource server refuses it: UserInfo is not in aud.
    assert_invalid_token(&userinfo_get(&app, &field(&body, "access_token")).await);
}

/// /authorize for a consented CIMD client → the code.
async fn cimd_code(app: &TestApp, path: &str, session: &str) -> String {
    let resp = authz::get(app, path, Some(session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    authz::param(&resp, "code").unwrap_or_else(|| panic!("{}", location(&resp)))
}
