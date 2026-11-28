//! Client home URLs (`client_uri`, `initiate_login_uri`, 07.1-06) end to end: set, read, clear
//! and keep through the management API; stored and returned by dynamic registration (RFC 7591 /
//! RFC 7592 read); taken from a Client ID Metadata Document. One validation function
//! (`service::client::validate_client_home_uri`) serves every path; its refusals are in
//! `security_admin_rc4.rs`, `security_registration.rs` and `security_cimd.rs`.

mod admin_support;
mod authz;
mod cimd_support;
mod dcr_support;
mod support;

use admin_support::{API, admin_token, call};
use anvil_core::model::{CimdPolicy, ClientSource, DcrPolicy};
use anvil_web::AppConfig;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{TestApp, json as body_json};

async fn app() -> TestApp {
    TestApp::with(|c: &mut AppConfig| c.rate_limits.enabled = false).await
}

fn clients() -> String {
    format!("{API}/tenants/default/clients")
}

async fn get_client(app: &TestApp, token: &str, id: &str) -> Value {
    let resp = call(
        app,
        Method::GET,
        &format!("{}/{id}", clients()),
        Some(token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    body_json(&resp)
}

#[tokio::test]
async fn admin_client_home_uris_round_trip() {
    let app = app().await;
    let token = admin_token(&app, "admin:clients:write").await;

    // Create with both URLs.
    let resp = call(
        &app,
        Method::POST,
        &clients(),
        Some(&token),
        Some(json!({
            "name": "Shop",
            "client_type": "public",
            "redirect_uris": ["https://shop.example/cb"],
            "client_uri": "https://shop.example/",
            "initiate_login_uri": "https://shop.example/login",
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let created = body_json(&resp);
    assert_eq!(created["client_uri"], "https://shop.example/");
    assert_eq!(created["initiate_login_uri"], "https://shop.example/login");
    let id = created["client_id"].as_str().unwrap().to_owned();
    let view = get_client(&app, &token, &id).await;
    assert_eq!(view["client_uri"], "https://shop.example/");
    assert_eq!(view["initiate_login_uri"], "https://shop.example/login");

    // A patch without the fields leaves them unchanged.
    let path = format!("{}/{id}", clients());
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"name": "Shop 2"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = get_client(&app, &token, &id).await;
    assert_eq!(view["client_uri"], "https://shop.example/");
    assert_eq!(view["initiate_login_uri"], "https://shop.example/login");

    // A new value replaces; null clears.
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"client_uri": "https://shop.example/home", "initiate_login_uri": null})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = get_client(&app, &token, &id).await;
    assert_eq!(view["client_uri"], "https://shop.example/home");
    assert_eq!(view["initiate_login_uri"], Value::Null);

    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"client_uri": null})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let view = get_client(&app, &token, &id).await;
    assert_eq!(view["client_uri"], Value::Null);

    // Loopback http is accepted for administrator-registered clients (local development).
    let resp = call(
        &app,
        Method::PATCH,
        &path,
        Some(&token),
        Some(json!({"client_uri": "http://localhost:5173/"})),
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());

    // A client created without the fields shows null.
    let resp = call(
        &app,
        Method::POST,
        &clients(),
        Some(&token),
        Some(json!({
            "name": "Plain",
            "client_type": "public",
            "redirect_uris": ["https://plain.example/cb"],
        })),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let plain = body_json(&resp);
    assert_eq!(plain["client_uri"], Value::Null);
    assert_eq!(plain["initiate_login_uri"], Value::Null);
}

#[tokio::test]
async fn dcr_client_uri_is_stored_and_returned() {
    let app = dcr_support::app().await;
    let tenant = dcr_support::set_policy(&app, DcrPolicy::Open).await;
    let mut req = dcr_support::web_request();
    req["client_uri"] = json!("https://rp.example/");
    req["initiate_login_uri"] = json!("https://rp.example/login");
    let resp = dcr_support::register(&app, &req, None).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.text());
    let body = body_json(&resp);
    assert_eq!(body["client_uri"], "https://rp.example/");
    assert_eq!(body["initiate_login_uri"], "https://rp.example/login");
    let client_id = body["client_id"].as_str().unwrap().to_owned();
    let rat = body["registration_access_token"].as_str().unwrap();
    let uri = body["registration_client_uri"].as_str().unwrap();

    // Stored.
    let row = app
        .storage()
        .clients()
        .get(tenant.id, &client_id)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(row.registration_source, ClientSource::Dynamic);
    assert_eq!(row.client_uri.as_deref(), Some("https://rp.example/"));
    assert_eq!(
        row.initiate_login_uri.as_deref(),
        Some("https://rp.example/login")
    );

    // RFC 7592 read returns what was registered.
    let path = dcr_support::client_path(&app, uri);
    let resp = dcr_support::send_json(&app, Method::GET, &path, Some(rat), None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let read = body_json(&resp);
    assert_eq!(read["client_uri"], "https://rp.example/");
    assert_eq!(read["initiate_login_uri"], "https://rp.example/login");

    // RFC 7592 update replaces every value: omitting the home URLs removes them.
    let update = json!({"client_id": client_id, "redirect_uris": [authz::RP]});
    let resp = dcr_support::send_json(&app, Method::PUT, &path, Some(rat), Some(&update)).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text());
    let updated = body_json(&resp);
    assert!(updated.get("client_uri").is_none(), "{updated}");
    assert!(updated.get("initiate_login_uri").is_none(), "{updated}");

    // The admin API shows the stored values of dynamic clients too.
    let token = admin_token(&app, "admin:clients:read").await;
    let resp = dcr_support::register(&app, &req, None).await;
    let second = body_json(&resp)["client_id"].as_str().unwrap().to_owned();
    let view = get_client(&app, &token, &second).await;
    assert_eq!(view["client_uri"], "https://rp.example/");
    assert_eq!(view["registration_source"], "dynamic");
}

#[tokio::test]
async fn cimd_client_takes_home_uris_from_the_document() {
    let app = TestApp::dev().await;
    cimd_support::set_policy(&app, CimdPolicy::Open, &[], &[]).await;
    let docs = cimd_support::DocServer::start().await;
    let client_id = docs.url(cimd_support::DOC_PATH);
    let mut doc = cimd_support::doc(&client_id);
    doc["client_uri"] = json!("https://agent.example/");
    doc["initiate_login_uri"] = json!("https://agent.example/login");
    docs.serve(cimd_support::DOC_PATH, &doc, None).await;

    let resp = app
        .get(&cimd_support::authorize_path(&client_id, &[]))
        .await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let row = cimd_support::stored(&app, &client_id)
        .await
        .expect("materialised");
    assert_eq!(row.registration_source, ClientSource::Cimd);
    assert_eq!(row.client_uri.as_deref(), Some("https://agent.example/"));
    assert_eq!(
        row.initiate_login_uri.as_deref(),
        Some("https://agent.example/login")
    );

    // A document without them gives a client without them.
    let other = docs.url("/plain.json");
    docs.serve("/plain.json", &cimd_support::doc(&other), None)
        .await;
    let resp = app.get(&cimd_support::authorize_path(&other, &[])).await;
    assert_eq!(resp.status, 303, "{}", resp.text());
    let row = cimd_support::stored(&app, &other).await.expect("stored");
    assert_eq!(row.client_uri, None);
    assert_eq!(row.initiate_login_uri, None);
}
