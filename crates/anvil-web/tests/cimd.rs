//! Client ID Metadata Documents (AGT-02) on the selected backend (`ANVILID_TEST_DB`).
//!
//! `resolver_*`: [`ClientResolver`] on real storage with a scripted fetcher double: policy and
//! allow-list gating before any fetch, materialisation as a `cimd` client row, the cache lifetime
//! (`max-age` clamped to the tenant bounds), errors never cached, a still-valid row served on a
//! transient failure until its hard expiry, the `cimd_client_refreshed` audit event.
//!
//! The other tests run over HTTP in development mode against a wiremock document server on
//! loopback (the only place plain http is fetched): a full code + PKCE + resource flow with a URL
//! client id, the token endpoint's 503 on a transient failure and `invalid_client` on a refused
//! document, and the discovery flag.

mod authz;
mod cimd_support;
mod support;

use std::sync::Arc;

use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditQuery, CimdPolicy, ClientSource, ClientType, ConsentId, ConsentMode,
    NewConsent, Tenant,
};
use anvil_core::ports::{Clock, MetadataFetchError};
use anvil_core::service::client_resolver::ClientResolver;
use cimd_support::{
    DOC_PATH, DocServer, FixedClock, ScriptedFetcher, authorize_path, doc, set_policy, stored,
};
use serde_json::Value;
use support::{TestApp, json, location};
use time::{Duration, OffsetDateTime};

const URL: &str = "https://app.example/client.json";
const MCP: &str = "https://mcp.example/";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// ---------------------------------------------------------------------------------------------
// Resolver (scripted fetcher, real storage)
// ---------------------------------------------------------------------------------------------

struct R {
    app: TestApp,
    fetcher: Arc<ScriptedFetcher>,
    resolver: ClientResolver,
    now: OffsetDateTime,
}

async fn resolver_with(policy: CimdPolicy, hosts: &[&str], allow_http: bool) -> R {
    let app = TestApp::new().await;
    set_policy(&app, policy, hosts, &[MCP]).await;
    let fetcher = Arc::new(ScriptedFetcher::new(allow_http));
    let now = app.clock().now();
    let resolver = ClientResolver {
        storage: app.storage_arc(),
        clock: Arc::new(FixedClock(now)),
        fetcher: Some(fetcher.clone()),
    };
    R {
        app,
        fetcher,
        resolver,
        now,
    }
}

impl R {
    /// Resolves against the stored tenant (the policy lives in its settings).
    async fn resolve(
        &self,
        client_id: &str,
        at: OffsetDateTime,
    ) -> Result<Option<anvil_core::model::Client>, CoreError> {
        let tenant = current_tenant(&self.app).await;
        self.resolver.resolve(&tenant, client_id, at).await
    }
}

async fn current_tenant(app: &TestApp) -> Tenant {
    let id = authz::default_tenant(app).id;
    app.storage()
        .tenants()
        .get(id)
        .await
        .expect("tenant lookup")
        .expect("tenant exists")
}

#[tokio::test]
async fn resolver_materialises_a_document_then_serves_it_from_the_cache() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    r.fetcher.push_doc(&doc(URL), Some(600));

    let client = r
        .resolve(URL, r.now)
        .await
        .expect("resolve")
        .expect("client");
    assert_eq!(r.fetcher.calls(), 1);
    assert_eq!(client.client_id, URL);
    assert_eq!(client.registration_source, ClientSource::Cimd);
    assert_eq!(client.consent_mode, ConsentMode::Required);
    assert_eq!(client.client_type, ClientType::Public);
    assert!(client.require_pkce);
    assert_eq!(client.allowed_resources, vec![MCP.to_owned()]);
    assert_eq!(
        client.metadata_expires_at,
        Some(r.now + Duration::seconds(600))
    );
    assert_eq!(stored(&r.app, URL).await.expect("row").id, client.id);

    // Within max-age: no fetch.
    let again = r
        .resolve(URL, r.now + Duration::seconds(599))
        .await
        .expect("resolve")
        .expect("client");
    assert_eq!(again.id, client.id);
    assert_eq!(r.fetcher.calls(), 1);

    // Expired: fetched again, same row id.
    r.fetcher.push_doc(&doc(URL), None);
    let refreshed = r
        .resolve(URL, r.now + Duration::seconds(600))
        .await
        .expect("resolve")
        .expect("client");
    assert_eq!(r.fetcher.calls(), 2);
    assert_eq!(refreshed.id, client.id);
}

#[tokio::test]
async fn resolver_clamps_max_age_to_the_tenant_bounds() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    for (path, max_age, ttl) in [
        ("/a.json", Some(10), 300),
        ("/b.json", Some(7 * 86_400), 86_400),
        ("/c.json", None, 300),
        ("/d.json", Some(3600), 3600),
    ] {
        let url = format!("https://app.example{path}");
        r.fetcher.push_doc(&doc(&url), max_age);
        let c = r
            .resolve(&url, r.now)
            .await
            .expect("resolve")
            .expect("client");
        assert_eq!(
            c.metadata_expires_at,
            Some(r.now + Duration::seconds(ttl)),
            "{path}"
        );
    }
}

#[tokio::test]
async fn resolver_transient_failure_keeps_the_row_until_hard_expiry() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    r.fetcher.push_doc(&doc(URL), None); // ttl 300 s
    let client = r
        .resolve(URL, r.now)
        .await
        .expect("resolve")
        .expect("client");

    // Expired; the host answers 500: the row is served, nothing is cached.
    r.fetcher.push(Err(MetadataFetchError::Status(500)));
    let served = r
        .resolve(URL, r.now + Duration::seconds(301))
        .await
        .expect("served")
        .expect("client");
    assert_eq!(served.id, client.id);
    assert_eq!(r.fetcher.calls(), 2);
    // The next request fetches again (the error was not cached).
    r.fetcher.push(Err(MetadataFetchError::Network));
    r.resolve(URL, r.now + Duration::seconds(302))
        .await
        .expect("served")
        .expect("client");
    assert_eq!(r.fetcher.calls(), 3);

    // Past the hard expiry (expiry + max_cache_secs): unavailable.
    r.fetcher.push(Err(MetadataFetchError::Timeout));
    let late = r.now + Duration::seconds(300 + 86_400 + 1);
    assert!(matches!(
        r.resolve(URL, late).await,
        Err(CoreError::ClientMetadataUnavailable(_))
    ));
}

#[tokio::test]
async fn resolver_transient_failure_without_a_row_is_unavailable() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    r.fetcher.push(Err(MetadataFetchError::Status(503)));
    assert!(matches!(
        r.resolve(URL, r.now).await,
        Err(CoreError::ClientMetadataUnavailable(_))
    ));
    assert!(stored(&r.app, URL).await.is_none());
}

#[tokio::test]
async fn resolver_refused_documents_are_invalid_client_and_not_stored() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    r.fetcher
        .push_doc(&doc("https://app.example/other.json"), None);
    assert!(matches!(
        r.resolve(URL, r.now).await,
        Err(CoreError::InvalidClient { .. })
    ));
    r.fetcher.push(Err(MetadataFetchError::Status(404)));
    assert!(matches!(
        r.resolve(URL, r.now).await,
        Err(CoreError::InvalidClient { .. })
    ));
    r.fetcher.push(Err(MetadataFetchError::TooLarge));
    assert!(matches!(
        r.resolve(URL, r.now).await,
        Err(CoreError::InvalidClient { .. })
    ));
    assert_eq!(r.fetcher.calls(), 3);
    assert!(stored(&r.app, URL).await.is_none());
}

#[tokio::test]
async fn resolver_disabled_policy_never_fetches_and_hides_cimd_rows() {
    let r = resolver_with(CimdPolicy::Disabled, &[], false).await;
    assert!(r.resolve(URL, r.now).await.expect("resolve").is_none());
    assert_eq!(r.fetcher.calls(), 0);

    // A row materialised while the policy was open is not served once it is disabled.
    set_policy(&r.app, CimdPolicy::Open, &[], &[]).await;
    r.fetcher.push_doc(&doc(URL), Some(3600));
    assert!(r.resolve(URL, r.now).await.expect("resolve").is_some());
    set_policy(&r.app, CimdPolicy::Disabled, &[], &[]).await;
    assert!(r.resolve(URL, r.now).await.expect("resolve").is_none());
    assert_eq!(r.fetcher.calls(), 1);
}

#[tokio::test]
async fn resolver_allow_list_is_checked_before_fetching() {
    let r = resolver_with(CimdPolicy::AllowListed, &["other.example"], false).await;
    assert!(r.resolve(URL, r.now).await.expect("resolve").is_none());
    assert_eq!(r.fetcher.calls(), 0);

    set_policy(&r.app, CimdPolicy::AllowListed, &["APP.example"], &[]).await;
    r.fetcher.push_doc(&doc(URL), None);
    assert!(r.resolve(URL, r.now).await.expect("resolve").is_some());
    assert_eq!(r.fetcher.calls(), 1);
}

#[tokio::test]
async fn resolver_http_client_ids_need_the_development_outbound_policy() {
    let http = "http://127.0.0.1:9/client.json";
    let prod = resolver_with(CimdPolicy::Open, &[], false).await;
    assert!(
        prod.resolve(http, prod.now)
            .await
            .expect("resolve")
            .is_none()
    );
    assert_eq!(prod.fetcher.calls(), 0);

    let dev = resolver_with(CimdPolicy::Open, &[], true).await;
    dev.fetcher.push_doc(&doc(http), None);
    assert!(dev.resolve(http, dev.now).await.expect("resolve").is_some());
    assert_eq!(dev.fetcher.calls(), 1);
}

#[tokio::test]
async fn resolver_non_url_client_ids_use_the_plain_lookup() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    let tenant = authz::default_tenant(&r.app);
    let rp = authz::web_client(&r.app, &tenant).await;
    let found = r
        .resolve(&rp.client_id, r.now)
        .await
        .expect("resolve")
        .expect("client");
    assert_eq!(found.id, rp.id);
    assert!(
        r.resolve("unknown", r.now)
            .await
            .expect("resolve")
            .is_none()
    );
    assert_eq!(r.fetcher.calls(), 0);
}

#[tokio::test]
async fn resolver_every_refresh_is_audited() {
    let r = resolver_with(CimdPolicy::Open, &[], false).await;
    r.fetcher.push_doc(&doc(URL), None);
    r.resolve(URL, r.now)
        .await
        .expect("resolve")
        .expect("client");
    r.fetcher.push_doc(&doc(URL), None);
    r.resolve(URL, r.now + Duration::seconds(301))
        .await
        .expect("resolve")
        .expect("client");
    let tenant = authz::default_tenant(&r.app);
    let events = r
        .app
        .storage()
        .audit()
        .query(
            tenant.id,
            &AuditQuery {
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query")
        .items;
    let refreshed: Vec<_> = events
        .iter()
        .filter(|e| e.action == AuditAction::CimdClientRefreshed)
        .collect();
    assert_eq!(refreshed.len(), 2);
    assert!(refreshed.iter().all(|e| e.target.as_deref() == Some(URL)));
}

// ---------------------------------------------------------------------------------------------
// Over HTTP (development mode, loopback document server)
// ---------------------------------------------------------------------------------------------

fn jwt_claims(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("payload");
    serde_json::from_slice(&anvil_jose::encoding::b64url_decode(payload).expect("b64"))
        .expect("claims json")
}

#[tokio::test]
async fn cimd_client_completes_code_pkce_and_resource_flow() {
    let app = TestApp::dev().await;
    let tenant = set_policy(&app, CimdPolicy::Open, &[], &[MCP]).await;
    let docs = DocServer::start().await;
    let client_id = docs.url(DOC_PATH);
    docs.serve(DOC_PATH, &doc(&client_id), Some("max-age=600"))
        .await;
    let user = authz::user(&app, &tenant, "ada@example.com").await;
    let session = authz::session(&app, &tenant, user).await;
    let iss = app.issuer(None);
    let path = authorize_path(&client_id, &[("resource", MCP)]);

    // First authorization: the client is materialised; CIMD clients always ask for consent.
    let resp = authz::get(&app, &path, Some(&session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    assert!(
        location(&resp).starts_with(&format!("{iss}/ui/consent?request=")),
        "{}",
        location(&resp)
    );
    let row = stored(&app, &client_id).await.expect("materialised");
    assert_eq!(row.registration_source, ClientSource::Cimd);
    assert_eq!(row.consent_mode, ConsentMode::Required);

    // The user consented (consent screen covered in consent.rs): the code is issued.
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
                created_at: app.clock().now(),
            },
            app.clock().now(),
        )
        .await
        .expect("consent");
    let resp = authz::get(&app, &path, Some(&session)).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let code = authz::param(&resp, "code").unwrap_or_else(|| panic!("{}", location(&resp)));

    let resp = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", authz::RP),
                ("code_verifier", VERIFIER),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let tokens = json(&resp);
    let claims = jwt_claims(tokens["access_token"].as_str().expect("access token"));
    let aud = &claims["aud"];
    assert!(
        aud == MCP || aud.as_array().is_some_and(|a| a.iter().any(|v| v == MCP)),
        "{aud}"
    );
    assert_eq!(claims["client_id"], client_id.as_str());
    // One fetch for the whole flow (cached for max-age).
    assert_eq!(docs.hits(DOC_PATH).await, 1);
}

#[tokio::test]
async fn token_endpoint_transient_failure_is_503_and_refused_document_is_invalid_client() {
    let app = TestApp::dev().await;
    set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let docs = DocServer::start().await;
    let down = docs.url("/down.json");
    docs.fail("/down.json", 503, 10).await;
    let resp = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "x"),
                ("redirect_uri", authz::RP),
                ("code_verifier", VERIFIER),
                ("client_id", &down),
            ],
        )
        .await;
    assert_eq!(resp.status, 503, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "temporarily_unavailable");

    let bad = docs.url("/bad.json");
    docs.serve("/bad.json", &doc("https://elsewhere.example/c.json"), None)
        .await;
    let resp = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", "x"),
                ("redirect_uri", authz::RP),
                ("code_verifier", VERIFIER),
                ("client_id", &bad),
            ],
        )
        .await;
    assert_eq!(resp.status, 401, "{}", resp.text());
    assert_eq!(json(&resp)["error"], "invalid_client");
}

#[tokio::test]
async fn discovery_advertises_cimd_only_when_the_policy_allows_it() {
    let app = TestApp::new().await;
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    assert!(doc.get("client_id_metadata_document_supported").is_none());

    set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let doc = json(&app.get("/.well-known/oauth-authorization-server").await);
    assert_eq!(doc["client_id_metadata_document_supported"], true);

    set_policy(&app, CimdPolicy::AllowListed, &["app.example"], &[]).await;
    let doc = json(&app.get("/.well-known/openid-configuration").await);
    assert_eq!(doc["client_id_metadata_document_supported"], true);
}

#[tokio::test]
async fn discovery_never_advertises_cimd_for_the_system_tenant() {
    let app = TestApp::new().await;
    let system = app.system.as_ref().expect("system tenant").tenant.clone();
    let mut settings = system.settings.clone();
    settings.cimd.policy = CimdPolicy::Open;
    app.storage()
        .tenants()
        .update(
            system.id,
            &anvil_core::model::TenantUpdate {
                settings: Some(settings),
                ..Default::default()
            },
        )
        .await
        .expect("update")
        .expect("exists");
    let doc = json(
        &app.get(&format!(
            "/t/{}/.well-known/openid-configuration",
            system.slug
        ))
        .await,
    );
    assert_eq!(
        doc["issuer"].as_str().map(|s| s.ends_with(&system.slug)),
        Some(true),
        "{doc}"
    );
    assert!(doc.get("client_id_metadata_document_supported").is_none());
}
