//! Enterprise OIDC per organization (ORG-03), on the selected backend (`ANVILID_TEST_DB`).
//!
//! An org-owned OIDC connection runs through the Phase 4 upstream routes (start, callback) and the
//! shared completion path:
//!
//! - just-in-time registration creates the user, the identity link and the org membership with
//!   the org's default roles, with the mapped names, audited `user_registered` and
//!   `org_member_added`;
//! - an already linked user who is not a member becomes one (JIT membership);
//! - the upstream email is trusted only on one of the org's **verified** domains and only when
//!   the IdP says `email_verified: true`; otherwise a matching local account needs the Phase 4
//!   confirmation (no auto-link, no membership);
//! - the start route accepts an org connection by slug (org connections have no button).
//!
//! The cross-org takeover case (org A's IdP asserting an address on org B's verified domain) is
//! in `security_linking.rs`.

mod support;
mod ui_helpers;
mod upstream_flow;
mod upstream_support;

use anvil_core::model::{AuditAction, IdentityLink};
use serde_json::json;
use support::TestResponse;
use ui_helpers::*;
use upstream_flow::*;
use upstream_support::MOCK_SUBJECT;

const PASSWORD: &str = "correct horse battery";
/// Slug of the org connection.
const ORG_SLUG: &str = "acme-sso";
/// The org's domain.
const DOMAIN: &str = "acme.example";
const JANE: &str = "jane@acme.example";

/// The answer is the link confirmation page: nothing linked, nobody signed in, the address not
/// revealed.
async fn assert_needs_confirmation(u: &Upstream, resp: &TestResponse, email: &str) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    let html = resp.html();
    assert_eq!(form_id(&html), "upstream-link", "{html}");
    assert!(
        !html.contains(email),
        "the candidate is not revealed: {html}"
    );
    assert!(session(&u.app).await.is_none(), "no session");
    assert!(audit(&u.app, AuditAction::IdentityLinked).await.is_empty());
}

fn signed_in(resp: &TestResponse) {
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        message_keys(&resp.html()).contains(&"login.signed_in".to_owned()),
        "{}",
        resp.text()
    );
}

#[tokio::test]
async fn org_oidc_jit_creates_user_link_and_membership() {
    let u = setup(true).await;
    let viewer = create_role(&u.app, None, "viewer").await;
    let org = create_org(&u.app, "acme", &[]).await;
    let member = create_role(&u.app, Some(org.id), "member").await;
    // Default roles: an org-owned role and a tenant role, set once the org role exists.
    set_default_roles(&u.app, &org, &[member.id, viewer.id]).await;
    verify_domain(&u.app, &org, DOMAIN).await;
    let conn = add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;

    let resp = sign_in_at(
        &u,
        ORG_SLUG,
        json!({
            "email": JANE,
            "email_verified": true,
            "given_name": "Jane",
            "family_name": "Doe",
            "name": "Jane Doe",
        }),
    )
    .await;
    signed_in(&resp);

    let jane = user(&u.app, JANE).await.expect("user registered");
    assert!(jane.email_verified, "verified org domain + email_verified");
    assert_eq!(jane.claims.given_name.as_deref(), Some("Jane"));
    assert_eq!(jane.claims.family_name.as_deref(), Some("Doe"));
    assert_eq!(jane.claims.name.as_deref(), Some("Jane Doe"));
    let jane_links: Vec<IdentityLink> = links(&u.app, &jane).await;
    assert_eq!(jane_links.len(), 1);
    assert_eq!(jane_links[0].connection_id, conn.id);
    assert_eq!(jane_links[0].subject, MOCK_SUBJECT);
    assert!(is_member(&u.app, &org, &jane).await);
    assert_eq!(
        org_role_names(&u.app, &org, &jane).await,
        vec!["member".to_owned(), "viewer".to_owned()]
    );
    assert_eq!(session(&u.app).await.expect("session").user_id, jane.id);

    let added = audit(&u.app, AuditAction::OrgMemberAdded).await;
    assert_eq!(added.len(), 1, "{added:?}");
    assert_eq!(
        added[0].target.as_deref(),
        Some(jane.id.to_string().as_str())
    );
    let details = added[0].details.as_map();
    assert_eq!(
        details.get("org_id").and_then(|v| v.as_str()),
        Some(org.id.to_string().as_str())
    );
    assert_eq!(
        details.get("org_slug").and_then(|v| v.as_str()),
        Some("acme")
    );
    assert_eq!(audit(&u.app, AuditAction::UserRegistered).await.len(), 1);
}

#[tokio::test]
async fn org_oidc_jit_skips_default_roles_that_no_longer_exist() {
    let u = setup(true).await;
    let gone = create_role(&u.app, None, "retired").await;
    let org = create_org(&u.app, "acme", &[gone.id]).await;
    u.app
        .storage()
        .roles()
        .delete(tenant(&u.app).id, gone.id)
        .await
        .expect("delete role");
    verify_domain(&u.app, &org, DOMAIN).await;
    add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    let resp = sign_in_at(&u, ORG_SLUG, json!({ "email": JANE })).await;
    signed_in(&resp);
    let jane = user(&u.app, JANE).await.expect("user registered");
    assert!(is_member(&u.app, &org, &jane).await);
    assert!(org_role_names(&u.app, &org, &jane).await.is_empty());
}

#[tokio::test]
async fn org_oidc_existing_linked_user_gets_membership() {
    let u = setup(true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    let member = create_role(&u.app, Some(org.id), "member").await;
    set_default_roles(&u.app, &org, &[member.id]).await;
    let conn = add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    // A local account already linked to the org IdP subject, not a member of the org.
    register(&u.app, "", "pat@elsewhere.example", PASSWORD).await;
    let pat = user(&u.app, "pat@elsewhere.example").await.expect("pat");
    link_identity(&u.app, &pat, &conn, MOCK_SUBJECT).await;
    assert!(!is_member(&u.app, &org, &pat).await);

    let resp = sign_in_at(&u, ORG_SLUG, json!({ "email": "pat@elsewhere.example" })).await;
    signed_in(&resp);
    assert_eq!(session(&u.app).await.expect("session").user_id, pat.id);
    assert!(is_member(&u.app, &org, &pat).await, "JIT membership");
    assert_eq!(
        org_role_names(&u.app, &org, &pat).await,
        vec!["member".to_owned()]
    );
    let added = audit(&u.app, AuditAction::OrgMemberAdded).await;
    assert_eq!(added.len(), 1, "{added:?}");
    assert_eq!(
        added[0].target.as_deref(),
        Some(pat.id.to_string().as_str())
    );

    // A second sign-in keeps the membership and audits nothing new.
    let resp = sign_in_at(&u, ORG_SLUG, json!({ "email": "pat@elsewhere.example" })).await;
    signed_in(&resp);
    assert_eq!(audit(&u.app, AuditAction::OrgMemberAdded).await.len(), 1);
}

#[tokio::test]
async fn verified_domain_email_auto_links_existing_local_user() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    verify_domain(&u.app, &org, DOMAIN).await;
    add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    register(&u.app, "", JANE, PASSWORD).await;
    mark_verified(&u.app, JANE).await;
    let jane = user(&u.app, JANE).await.expect("jane");

    let resp = sign_in_at(
        &u,
        ORG_SLUG,
        json!({ "email": JANE, "email_verified": true }),
    )
    .await;
    signed_in(&resp);
    assert_eq!(session(&u.app).await.expect("session").user_id, jane.id);
    assert_eq!(links(&u.app, &jane).await.len(), 1);
    let linked = audit(&u.app, AuditAction::IdentityLinked).await;
    assert_eq!(linked.len(), 1);
    assert_eq!(
        linked[0]
            .details
            .as_map()
            .get("mode")
            .and_then(|v| v.as_str()),
        Some("auto")
    );
    assert!(is_member(&u.app, &org, &jane).await, "JIT membership");
}

#[tokio::test]
async fn unverified_domain_email_is_untrusted() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    // Claimed, but the DNS check never passed.
    claim_domain(&u.app, &org, DOMAIN, false).await;
    add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    register(&u.app, "", JANE, PASSWORD).await;
    mark_verified(&u.app, JANE).await;
    let jane = user(&u.app, JANE).await.expect("jane");

    let resp = sign_in_at(
        &u,
        ORG_SLUG,
        json!({ "email": JANE, "email_verified": true }),
    )
    .await;
    assert_needs_confirmation(&u, &resp, JANE).await;
    assert!(links(&u.app, &jane).await.is_empty());
    assert!(!is_member(&u.app, &org, &jane).await);
    assert!(audit(&u.app, AuditAction::OrgMemberAdded).await.is_empty());

    // Without a local match, JIT creates an account whose address is not verified.
    let resp = sign_in_at(
        &u,
        ORG_SLUG,
        json!({ "sub": "emp-2", "email": "new@acme.example", "email_verified": true }),
    )
    .await;
    signed_in(&resp);
    let new = user(&u.app, "new@acme.example").await.expect("jit user");
    assert!(!new.email_verified, "unverified org domain is not trusted");
}

#[tokio::test]
async fn upstream_email_verified_false_is_untrusted_even_on_verified_domain() {
    let u = setup(true).await;
    tenant_settings(&u.app, |s| s.auto_link = true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    verify_domain(&u.app, &org, DOMAIN).await;
    add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    register(&u.app, "", JANE, PASSWORD).await;
    mark_verified(&u.app, JANE).await;
    let jane = user(&u.app, JANE).await.expect("jane");

    for verified in [json!(false), json!("true"), json!(null)] {
        let resp = sign_in_at(
            &u,
            ORG_SLUG,
            json!({ "email": JANE, "email_verified": verified }),
        )
        .await;
        assert_needs_confirmation(&u, &resp, JANE).await;
    }
    assert!(links(&u.app, &jane).await.is_empty());
    assert!(!is_member(&u.app, &org, &jane).await);

    // An untrusted connection is not made trusted by the verified domain either.
    add_org_connection(&u.app, &u.mock, &org, "acme-untrusted", false).await;
    let resp = sign_in_at(
        &u,
        "acme-untrusted",
        json!({ "email": JANE, "email_verified": true }),
    )
    .await;
    assert_needs_confirmation(&u, &resp, JANE).await;
    assert!(links(&u.app, &jane).await.is_empty());
    assert!(!is_member(&u.app, &org, &jane).await);
}

#[tokio::test]
async fn org_connection_start_by_slug_works() {
    let u = setup(true).await;
    let org = create_org(&u.app, "acme", &[]).await;
    add_org_connection(&u.app, &u.mock, &org, ORG_SLUG, true).await;
    let started = start_at(&u.app, ORG_SLUG).await;
    let issuer = url::Url::parse(&u.mock.issuer()).expect("issuer URL");
    assert_eq!(started.location.host_str(), issuer.host_str());
    assert_eq!(started.location.port(), issuer.port());
    assert!(started.nonce.is_some(), "OIDC nonce");
    assert_eq!(
        started.param("code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(started.state.contains('.'), "state is {{flow}}.{{random}}");
    // The redirect URI is the org connection's own callback.
    let redirect = started.param("redirect_uri").expect("redirect_uri");
    assert!(
        redirect.ends_with(&format!("/ui/login/upstream/{ORG_SLUG}/callback")),
        "{redirect}"
    );
}
