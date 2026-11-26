//! Account enumeration resistance (SEC-04): recovery and login answer identically for existing
//! and unknown accounts, and login always runs an Argon2 verification (the dummy hash for unknown
//! users). Identifier-first sign-in (ORG-04) routes by the email's domain only: every non-routed
//! address, known or unknown, gets the same password step without any hashing. Selected backend
//! via `ANVILID_TEST_DB`.

mod support;
mod ui_helpers;

use anvil_core::model::{
    ConnectionConfig, ConnectionId, NewConnection, NewOrgDomain, NewOrganization, OidcConfig,
    OrgDomainId, OrgDomainUpdate, OrgId, OrgSettings,
};
use anvil_core::ports::Clock as _;
use ui_helpers::*;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

async fn app() -> OwnApp {
    let app = OwnApp::installed().await;
    register(&app, "", EMAIL, PASSWORD).await;
    app
}

#[tokio::test]
async fn recovery_for_an_existing_and_an_unknown_email_is_identical() {
    let app = app().await;
    let existing = submit_form(&app, "/ui/recovery", &[("email", EMAIL)]).await;
    app.clear_cookies();
    let unknown = submit_form(&app, "/ui/recovery", &[("email", "nobody@example.com")]).await;
    assert_eq!(existing.status, unknown.status);
    assert_eq!(existing.status, 200);
    assert_eq!(normalize(&existing.html()), normalize(&unknown.html()));
    assert_eq!(
        message_keys(&existing.html()),
        vec!["recovery.sent".to_owned()]
    );
}

#[tokio::test]
async fn unknown_user_and_wrong_password_are_identical_and_both_run_argon2() {
    let app = app().await;

    let before = app.hasher.verifications();
    let wrong = login(&app, "", EMAIL, "not the password").await;
    let after_wrong = app.hasher.verifications();
    app.clear_cookies();
    let unknown = login(&app, "", "nobody@example.com", "not the password").await;
    let after_unknown = app.hasher.verifications();

    assert_eq!(wrong.status, 400);
    assert_eq!(wrong.status, unknown.status);
    // The identifier is echoed, so compare with it masked.
    let w = normalize(&wrong.html()).replace(EMAIL, "IDENTIFIER");
    let u = normalize(&unknown.html()).replace("nobody@example.com", "IDENTIFIER");
    assert_eq!(w, u);
    assert_eq!(
        message_keys(&wrong.html()),
        vec!["login.invalid_credentials".to_owned()]
    );
    assert_eq!(after_wrong, before + 1, "wrong password verified once");
    assert_eq!(
        after_unknown,
        after_wrong + 1,
        "unknown user ran the dummy hash"
    );
}

/// Gives the default tenant an org whose verified domain `acme-corp.com` routes to an org OIDC
/// connection (storage intent), so its sign-in page asks for the email first.
async fn route_a_domain(app: &OwnApp) {
    let tenant = app.tenant("default").await.id;
    let now = app.clock.now();
    let org = app
        .storage
        .organizations()
        .create(
            tenant,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                mfa_policy: None,
                settings: OrgSettings::default(),
                metadata: serde_json::json!({}),
                created_at: now,
            },
        )
        .await
        .expect("org");
    let conn = app
        .storage
        .connections()
        .create(
            tenant,
            &NewConnection {
                id: ConnectionId::new_v7(),
                slug: "acme-sso".into(),
                display_name: "Acme SSO".into(),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: "https://idp.acme.test".into(),
                    client_id: "anvil".into(),
                    scopes: vec![],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: None,
                trust_email_verified: false,
                created_at: now,
                org_id: Some(org.id),
            },
        )
        .await
        .expect("connection");
    let orgs = app.storage.organizations();
    let claim = orgs
        .create_domain(
            tenant,
            &NewOrgDomain {
                id: OrgDomainId::new_v7(),
                org_id: org.id,
                domain: "acme-corp.com".into(),
                token: "test-challenge-token".into(),
                connection_id: None,
                routing: false,
                allow_local_password: true,
                created_at: now,
            },
        )
        .await
        .expect("claim");
    orgs.mark_verified(tenant, claim.id, now)
        .await
        .expect("verify")
        .expect("claim exists");
    orgs.update_domain(
        tenant,
        claim.id,
        &OrgDomainUpdate {
            connection_id: Some(Some(conn.id)),
            routing: Some(true),
            allow_local_password: Some(false),
        },
        now,
    )
    .await
    .expect("route")
    .expect("claim exists");
}

#[tokio::test]
async fn non_routed_known_and_unknown_emails_get_identical_password_step() {
    let app = app().await;
    route_a_domain(&app).await;

    let identify = |email: &'static str| {
        let app = &app;
        async move {
            app.clear_cookies();
            let page = app.get("/ui/login").await;
            assert_eq!(page.status, 200);
            let html = page.html();
            assert!(html.contains("id=\"login-identify-form\""), "{html}");
            let action = form_action(app, &html);
            let csrf = crate::support::csrf_from(&html);
            app.post_form(&action, &[("csrf_token", &csrf), ("identifier", email)])
                .await
        }
    };

    let before = app.hasher.verifications();
    let known = identify(EMAIL).await;
    let unknown = identify("nobody@example.com").await;
    assert_eq!(
        app.hasher.verifications(),
        before,
        "routing hashes nothing and looks up no account"
    );
    assert_eq!(known.status, 200, "{}", known.text());
    assert_eq!(known.status, unknown.status);
    let k = normalize(&known.html()).replace(EMAIL, "IDENTIFIER");
    let u = normalize(&unknown.html()).replace("nobody@example.com", "IDENTIFIER");
    assert_eq!(k, u);
    // It is the password step (the email locked), not a routing hint.
    assert!(k.contains("id=\"login-email-locked\""), "{k}");
    assert!(k.contains("type=\"password\""), "{k}");
    assert!(message_keys(&k).is_empty(), "{k}");
}
