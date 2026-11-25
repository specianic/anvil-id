//! Client authentication at `POST /token` (client_secret_basic, client_secret_post, none):
//! every failure is `invalid_client`, Basic failures carry `WWW-Authenticate: Basic`, and an
//! unknown client is indistinguishable from a wrong secret.

mod support;
mod token_support;

use anvil_core::model::{ClientAuthMethod, SecretHash};
use anvil_jose::encoding::secret_hash;
use support::{TestApp, json};
use token_support::*;

const CC: &[(&str, &str)] = &[("grant_type", "client_credentials")];

fn assert_basic_challenge(resp: &support::TestResponse) {
    assert_oauth_error(resp, 401, "invalid_client");
    assert!(
        resp.header("www-authenticate")
            .is_some_and(|h| h.starts_with("Basic")),
        "{:?}",
        resp.headers
    );
}

#[tokio::test]
async fn wrong_secret_with_basic_is_401_with_challenge() {
    let app = TestApp::new().await;
    let rp = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let resp = token(
        &app,
        &Auth::Basic(rp.id().into(), "wrong-secret".into()),
        CC,
    )
    .await;
    assert_basic_challenge(&resp);

    // Positive control.
    assert_eq!(token(&app, &rp.auth(), CC).await.status, 200);
}

#[tokio::test]
async fn unknown_client_is_indistinguishable_from_a_wrong_secret() {
    let app = TestApp::new().await;
    let rp = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let wrong = token(
        &app,
        &Auth::Basic(rp.id().into(), "wrong-secret".into()),
        CC,
    )
    .await;
    let unknown = token(
        &app,
        &Auth::Basic("no-such-client".into(), "wrong-secret".into()),
        CC,
    )
    .await;
    assert_basic_challenge(&unknown);
    assert_eq!(wrong.body, unknown.body);
    assert_eq!(
        wrong.header("www-authenticate"),
        unknown.header("www-authenticate")
    );

    // Same for client_secret_post (no challenge there).
    let post = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretPost),
    )
    .await;
    let wrong = token(&app, &Auth::Post(post.id().into(), "wrong".into()), CC).await;
    let unknown = token(
        &app,
        &Auth::Post("no-such-client".into(), "wrong".into()),
        CC,
    )
    .await;
    assert_oauth_error(&wrong, 401, "invalid_client");
    assert!(wrong.header("www-authenticate").is_none());
    assert_eq!(wrong.body, unknown.body);
}

#[tokio::test]
async fn basic_and_body_secret_together_are_rejected() {
    let app = TestApp::new().await;
    let rp = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let auth = Auth::Raw(
        Some(basic(rp.id(), rp.secret())),
        vec![
            ("client_id".into(), rp.id().into()),
            ("client_secret".into(), rp.secret().into()),
        ],
    );
    assert_basic_challenge(&token(&app, &auth, CC).await);
}

#[tokio::test]
async fn wrong_method_for_the_client_is_rejected() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    // Registered for basic, authenticates with post (correct secret).
    let b = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(&app, &Auth::Post(b.id().into(), b.secret().into()), CC).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    // Registered for post, authenticates with basic (correct secret).
    let p = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretPost)).await;
    let resp = token(&app, &Auth::Basic(p.id().into(), p.secret().into()), CC).await;
    assert_basic_challenge(&resp);
}

#[tokio::test]
async fn confidential_client_without_credentials_is_rejected() {
    let app = TestApp::new().await;
    let rp = register(
        &app,
        default_tenant(&app),
        cc_input(ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let resp = token(&app, &Auth::None(rp.id().into()), CC).await;
    assert_oauth_error(&resp, 401, "invalid_client");
    let resp = token(&app, &Auth::Raw(None, vec![]), CC).await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn public_client_presenting_a_secret_is_rejected() {
    let app = TestApp::new().await;
    let rp = register(&app, default_tenant(&app), public_input()).await;
    let resp = token(
        &app,
        &Auth::Post(rp.id().into(), "anything".into()),
        &[("grant_type", "authorization_code"), ("code", "x")],
    )
    .await;
    assert_oauth_error(&resp, 401, "invalid_client");
}

#[tokio::test]
async fn malformed_basic_headers_are_rejected() {
    let app = TestApp::new().await;
    for header in [
        "Basic",
        "Basic !!!notbase64",
        "Basic Zm9v",
        "Bearer abc",
        "Basic Og==",
    ] {
        let resp = token(&app, &Auth::Raw(Some(header.into()), vec![]), CC).await;
        assert_basic_challenge(&resp);
    }
}

#[tokio::test]
async fn url_encoded_special_characters_in_basic_credentials_decode() {
    let app = TestApp::new().await;
    let tenant = default_tenant(&app);
    let rp = register(&app, tenant, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let secret = "s3cr+t/=:%&é ü";
    app.storage()
        .clients()
        .set_secret_hash(
            tenant,
            rp.id(),
            Some(SecretHash(secret_hash(secret))),
            app.clock_now(),
        )
        .await
        .expect("set secret");
    // `basic` form-urlencodes both parts before base64 (RFC 6749 §2.3.1).
    let resp = token(&app, &Auth::Basic(rp.id().into(), secret.into()), CC).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(json(&resp)["access_token"].is_string());

    // The same secret sent without the urlencoding step does not match ("+" decodes to " ").
    let raw = format!(
        "Basic {}",
        anvil_jose::encoding::b64std(format!("{}:{}", rp.id(), "s3cr+t").as_bytes())
    );
    let resp = token(&app, &Auth::Raw(Some(raw), vec![]), CC).await;
    assert_basic_challenge(&resp);
}

#[tokio::test]
async fn client_of_another_tenant_is_unknown_here() {
    let app = TestApp::new().await;
    let acme = acme(&app).await;
    let rp = register(&app, acme.id, cc_input(ClientAuthMethod::ClientSecretBasic)).await;
    let resp = token(&app, &rp.auth(), CC).await;
    assert_basic_challenge(&resp);
    // Positive control at the tenant's own endpoint.
    let resp = token_at(&app, "/t/acme/token", &rp.auth(), CC).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
}
