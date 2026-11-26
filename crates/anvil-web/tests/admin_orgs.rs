//! Organization administration through the management API (ORG-02, plan 06-12): org CRUD,
//! members, org roles, in-org assignments of tenant and org roles, member removal revoking the
//! member's org-bound tokens, invitations, and the audit events (with their webhook
//! classification). Plan 06-29: the per-user membership list
//! (`GET /tenants/{slug}/users/{user_id}/organizations`).

mod admin_support;
mod support;
mod token_support;

use admin_support::{API, admin_token, assert_problem, call, create_org, create_role};
use anvil_core::model::{
    AuditAction, AuditQuery, EmailKind, NewAuditEvent, NewRefreshToken, NewTokenFamily,
    ORG_INVITATION_TTL, SecretHash, TokenFamilyId,
};
use anvil_core::ports::Clock as _;
use anvil_jose::encoding::{random_token, secret_hash};
use axum::http::Method;
use serde_json::{Value, json};
use support::{TestApp, json as body_json};
use token_support::{
    acme, assert_oauth_error, default_tenant, refresh, register, seed_user, web_input,
};

const WRITE: &str = "admin:organizations:write";

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.enabled = false).await
}

fn orgs() -> String {
    format!("{API}/tenants/default/organizations")
}

#[tokio::test]
async fn org_crud_round_trip() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;

    let resp = call(
        &app,
        Method::POST,
        &orgs(),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": " Acme Corp ", "metadata": {"tier": "gold"}})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let org = body_json(&resp);
    let id = org["id"].as_str().unwrap().to_owned();
    assert_eq!(org["slug"], "acme");
    assert_eq!(org["display_name"], "Acme Corp");
    assert_eq!(org["metadata"]["tier"], "gold");
    assert_eq!(org["mfa_policy"], Value::Null);
    assert_eq!(
        resp.header("location"),
        Some(format!("{API}/tenants/default/organizations/{id}").as_str())
    );

    // Duplicate slug, bad slug.
    let dup = call(
        &app,
        Method::POST,
        &orgs(),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": "Again"})),
    )
    .await;
    assert_problem(&dup, 409);
    let bad = call(
        &app,
        Method::POST,
        &orgs(),
        Some(&token),
        Some(json!({"slug": "Bad_Slug", "display_name": "x"})),
    )
    .await;
    assert_problem(&bad, 422);

    // Read by id and by slug; list.
    for key in [id.as_str(), "acme"] {
        let got = call(
            &app,
            Method::GET,
            &format!("{}/{key}", orgs()),
            Some(&token),
            None,
        )
        .await;
        assert_eq!(got.status, 200, "{}", got.text());
        assert_eq!(body_json(&got)["id"], id.as_str());
    }
    let list = call(&app, Method::GET, &orgs(), Some(&token), None).await;
    assert_eq!(list.status, 200);
    assert_eq!(body_json(&list)["items"].as_array().unwrap().len(), 1);

    // Update.
    let tenant = default_tenant(&app);
    let viewer = create_role(&app, tenant, None, "viewer", &["docs:read"]).await;
    let patched = call(
        &app,
        Method::PATCH,
        &format!("{}/acme", orgs()),
        Some(&token),
        Some(json!({
            "display_name": "Acme Inc",
            "mfa_policy": "required",
            "default_role_ids": [viewer.id.0],
        })),
    )
    .await;
    assert_eq!(patched.status, 200, "{}", patched.text());
    let p = body_json(&patched);
    assert_eq!(p["display_name"], "Acme Inc");
    assert_eq!(p["mfa_policy"], "required");
    assert_eq!(p["default_role_ids"][0], viewer.id.0.to_string());
    let cleared = call(
        &app,
        Method::PATCH,
        &format!("{}/acme", orgs()),
        Some(&token),
        Some(json!({"mfa_policy": null})),
    )
    .await;
    assert_eq!(body_json(&cleared)["mfa_policy"], Value::Null);

    // Delete.
    let del = call(
        &app,
        Method::DELETE,
        &format!("{}/{id}", orgs()),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204, "{}", del.text());
    let gone = call(
        &app,
        Method::GET,
        &format!("{}/{id}", orgs()),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&gone, 404);
}

#[tokio::test]
async fn members_add_list_remove() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant, "acme").await;
    let ada = seed_user(&app, tenant, "ada@example.test").await;
    let members = format!("{}/acme/members", orgs());

    let add = call(
        &app,
        Method::POST,
        &members,
        Some(&token),
        Some(json!({"user_id": ada.id.0})),
    )
    .await;
    assert_eq!(add.status, 201, "{}", add.text());
    assert_eq!(body_json(&add)["added"], true);
    let again = call(
        &app,
        Method::POST,
        &members,
        Some(&token),
        Some(json!({"user_id": ada.id.0})),
    )
    .await;
    assert_eq!(again.status, 200, "{}", again.text());
    assert_eq!(body_json(&again)["added"], false);

    // A user of another tenant (or unknown) cannot be added.
    let unknown = call(
        &app,
        Method::POST,
        &members,
        Some(&token),
        Some(json!({"user_id": uuid::Uuid::now_v7()})),
    )
    .await;
    assert_problem(&unknown, 404);

    let list = call(&app, Method::GET, &members, Some(&token), None).await;
    assert_eq!(list.status, 200);
    let items = body_json(&list)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["user_id"], ada.id.0.to_string());
    assert_eq!(items[0]["email"], "ada@example.test");

    let del = call(
        &app,
        Method::DELETE,
        &format!("{members}/{}", ada.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204, "{}", del.text());
    assert!(
        !app.storage()
            .organizations()
            .is_member(tenant, org.id, ada.id)
            .await
            .unwrap()
    );
    let again = call(
        &app,
        Method::DELETE,
        &format!("{members}/{}", ada.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&again, 404);
}

#[tokio::test]
async fn org_roles_crud() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant, "acme").await;
    // A tenant role may share an org role's name.
    create_role(&app, tenant, None, "editor", &["docs:read"]).await;
    let roles = format!("{}/acme/roles", orgs());

    let created = call(
        &app,
        Method::POST,
        &roles,
        Some(&token),
        Some(json!({"name": "editor", "permissions": ["docs:write", "org:admin", "docs:write"]})),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.text());
    let r = body_json(&created);
    assert_eq!(r["scope"], "org");
    assert_eq!(r["permissions"], json!(["docs:write", "org:admin"]));

    let dup = call(
        &app,
        Method::POST,
        &roles,
        Some(&token),
        Some(json!({"name": "editor"})),
    )
    .await;
    assert_problem(&dup, 409);

    let list = call(&app, Method::GET, &roles, Some(&token), None).await;
    let items = body_json(&list)["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 1, "tenant roles are not listed as org roles");

    let got = call(
        &app,
        Method::GET,
        &format!("{roles}/editor"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(got.status, 200);
    let patched = call(
        &app,
        Method::PATCH,
        &format!("{roles}/editor"),
        Some(&token),
        Some(json!({"name": "writer", "description": "Writes"})),
    )
    .await;
    assert_eq!(patched.status, 200, "{}", patched.text());
    assert_eq!(body_json(&patched)["name"], "writer");
    let del = call(
        &app,
        Method::DELETE,
        &format!("{roles}/writer"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204);
    let gone = call(
        &app,
        Method::GET,
        &format!("{roles}/writer"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&gone, 404);
}

#[tokio::test]
async fn assignments_of_tenant_and_org_roles_within_the_org() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant, "acme").await;
    let ada = seed_user(&app, tenant, "ada@example.test").await;
    admin_support::add_member(&app, tenant, org.id, ada.id, &[]).await;
    create_role(&app, tenant, None, "viewer", &["docs:read"]).await;
    create_role(&app, tenant, Some(org.id), "editor", &["docs:write"]).await;
    // Same name as an org role: `?scope=tenant` selects the tenant one.
    create_role(&app, tenant, None, "editor", &["tenant:edit"]).await;
    let base = format!("{}/acme/members/{}/roles", orgs(), ada.id);

    for path in [
        format!("{base}/viewer"),
        format!("{base}/editor"),
        format!("{base}/editor?scope=tenant"),
    ] {
        let resp = call(&app, Method::PUT, &path, Some(&token), None).await;
        assert_eq!(resp.status, 200, "{path}: {}", resp.text());
    }
    let list = call(&app, Method::GET, &base, Some(&token), None).await;
    assert_eq!(list.status, 200);
    let items = body_json(&list)["items"].as_array().unwrap().clone();
    let mut got: Vec<(String, String)> = items
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_owned(),
                r["scope"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("editor".into(), "org".into()),
            ("editor".into(), "tenant".into()),
            ("viewer".into(), "tenant".into()),
        ]
    );
    // In-org assignments never show up tenant-wide.
    assert!(
        app.storage()
            .roles()
            .roles_for_user(tenant, ada.id)
            .await
            .unwrap()
            .is_empty()
    );

    let del = call(
        &app,
        Method::DELETE,
        &format!("{base}/editor?scope=tenant"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204, "{}", del.text());
    let again = call(
        &app,
        Method::DELETE,
        &format!("{base}/editor?scope=tenant"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&again, 404);

    // A non-member cannot be assigned.
    let bob = seed_user(&app, tenant, "bob@example.test").await;
    let resp = call(
        &app,
        Method::PUT,
        &format!("{}/acme/members/{}/roles/viewer", orgs(), bob.id),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&resp, 404);
}

/// An org-bound family with a refresh token of `rp` for `user`.
async fn family_with_refresh(
    app: &TestApp,
    rp: &token_support::Rp,
    user: anvil_core::model::UserId,
    org: Option<anvil_core::model::OrgId>,
) -> (TokenFamilyId, String) {
    let tenant = default_tenant(app);
    let now = app.clock().now();
    let id = TokenFamilyId::new_v7();
    app.storage()
        .grants()
        .create_family(
            tenant,
            &NewTokenFamily {
                id,
                client_id: rp.id().to_owned(),
                user_id: Some(user),
                scope: "openid offline_access".to_owned(),
                resource: vec![],
                auth_time: Some(now),
                acr: None,
                amr: vec!["pwd".to_owned()],
                session_id: None,
                claims: None,
                org_id: org,
                created_at: now,
                absolute_expires_at: now + time::Duration::days(30),
            },
        )
        .await
        .unwrap();
    let rt = random_token();
    app.storage()
        .grants()
        .create_refresh_token(
            tenant,
            &NewRefreshToken {
                token_hash: SecretHash(secret_hash(&rt)),
                family_id: id,
                parent_hash: None,
                scope: "openid offline_access".to_owned(),
                created_at: now,
                expires_at: now + time::Duration::days(30),
            },
        )
        .await
        .unwrap();
    (id, rt)
}

#[tokio::test]
async fn removing_a_member_revokes_only_their_org_bound_tokens() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant, "acme").await;
    let ada = seed_user(&app, tenant, "ada@example.test").await;
    admin_support::add_member(&app, tenant, org.id, ada.id, &[]).await;
    let rp = register(
        &app,
        tenant,
        web_input(anvil_core::model::ClientAuthMethod::ClientSecretBasic),
    )
    .await;
    let (org_family, org_rt) = family_with_refresh(&app, &rp, ada.id, Some(org.id)).await;
    let (_, plain_rt) = family_with_refresh(&app, &rp, ada.id, None).await;

    let del = call(
        &app,
        Method::DELETE,
        &format!("{}/acme/members/{}", orgs(), ada.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204, "{}", del.text());

    let family = app
        .storage()
        .grants()
        .get_family(tenant, org_family)
        .await
        .unwrap()
        .unwrap();
    assert!(
        family.revoked_at.is_some(),
        "the org-bound family is revoked"
    );
    let resp = refresh(&app, &rp, &org_rt, None).await;
    assert_oauth_error(&resp, 400, "invalid_grant");
    let resp = refresh(&app, &rp, &plain_rt, None).await;
    assert_eq!(
        resp.status,
        200,
        "an org-less token keeps working: {}",
        resp.text()
    );
}

#[tokio::test]
async fn invitations_create_list_revoke() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    let org = create_org(&app, tenant, "acme").await;
    let viewer = create_role(&app, tenant, None, "viewer", &["docs:read"]).await;
    let inv = format!("{}/acme/invitations", orgs());

    let resp = call(
        &app,
        Method::POST,
        &inv,
        Some(&token),
        Some(json!({"email": "  Bob@Example.TEST ", "role_ids": [viewer.id.0]})),
    )
    .await;
    assert_eq!(resp.status, 201, "{}", resp.text());
    let body = body_json(&resp);
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(body["email"], "bob@example.test");
    assert_eq!(body["status"], "open");
    assert_eq!(body["role_ids"][0], viewer.id.0.to_string());

    // Stored: only the hash, 7 days.
    let stored = app
        .storage()
        .organizations()
        .list_invitations(tenant, org.id, true)
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].expires_at,
        stored[0].created_at + ORG_INVITATION_TTL
    );
    assert_eq!(stored[0].email, "bob@example.test");
    // The email is queued with the org_invitation template and a sealed payload.
    let now = app.clock().now();
    let mails = app
        .storage()
        .outbox()
        .claim_due(now, 10, std::time::Duration::from_secs(60))
        .await
        .unwrap();
    let mail = mails
        .iter()
        .find(|m| m.template == EmailKind::OrgInvitation.as_str())
        .expect("an org_invitation email is queued");
    assert_eq!(mail.to, "bob@example.test");
    let payload = format!("{:?}", mail.payload);
    assert!(
        !payload.contains("/ui/invitation"),
        "the payload is sealed at rest: {payload}"
    );

    let list = call(&app, Method::GET, &inv, Some(&token), None).await;
    assert_eq!(body_json(&list)["items"].as_array().unwrap().len(), 1);

    let del = call(
        &app,
        Method::DELETE,
        &format!("{inv}/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(del.status, 204, "{}", del.text());
    let again = call(
        &app,
        Method::DELETE,
        &format!("{inv}/{id}"),
        Some(&token),
        None,
    )
    .await;
    assert_problem(&again, 404);
    let open = call(&app, Method::GET, &inv, Some(&token), None).await;
    assert!(body_json(&open)["items"].as_array().unwrap().is_empty());
    let all = call(
        &app,
        Method::GET,
        &format!("{inv}?include_closed=true"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(body_json(&all)["items"][0]["status"], "revoked");
}

#[tokio::test]
async fn org_changes_are_audited_and_webhook_classified() {
    let app = app().await;
    let token = admin_token(&app, WRITE).await;
    let tenant = default_tenant(&app);
    let ada = seed_user(&app, tenant, "ada@example.test").await;
    create_role(&app, tenant, None, "viewer", &["docs:read"]).await;

    let c = call(
        &app,
        Method::POST,
        &orgs(),
        Some(&token),
        Some(json!({"slug": "acme", "display_name": "Acme"})),
    )
    .await;
    assert_eq!(c.status, 201);
    let org_id = body_json(&c)["id"].as_str().unwrap().to_owned();
    let base = format!("{}/acme", orgs());
    let steps: Vec<(Method, String, Option<Value>)> = vec![
        (
            Method::PATCH,
            base.clone(),
            Some(json!({"display_name": "Acme 2"})),
        ),
        (
            Method::POST,
            format!("{base}/members"),
            Some(json!({"user_id": ada.id.0})),
        ),
        (
            Method::PUT,
            format!("{base}/members/{}/roles/viewer", ada.id),
            None,
        ),
        (
            Method::DELETE,
            format!("{base}/members/{}/roles/viewer", ada.id),
            None,
        ),
        (
            Method::POST,
            format!("{base}/invitations"),
            Some(json!({"email": "bob@example.test"})),
        ),
    ];
    for (m, p, b) in steps {
        let resp = call(&app, m, &p, Some(&token), b).await;
        assert!(resp.status.is_success(), "{p}: {}", resp.text());
    }
    let invs = call(
        &app,
        Method::GET,
        &format!("{base}/invitations"),
        Some(&token),
        None,
    )
    .await;
    let inv_id = body_json(&invs)["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for p in [
        format!("{base}/invitations/{inv_id}"),
        format!("{base}/members/{}", ada.id),
        base.clone(),
    ] {
        let resp = call(&app, Method::DELETE, &p, Some(&token), None).await;
        assert_eq!(resp.status, 204, "{p}: {}", resp.text());
    }

    let events = app
        .storage()
        .audit()
        .query(
            tenant,
            &AuditQuery {
                limit: 200,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap()
        .items;
    let find = |a: AuditAction| {
        events
            .iter()
            .find(|e| e.action == a)
            .unwrap_or_else(|| panic!("{} audited", a.as_str()))
    };
    for (action, target, webhook) in [
        (AuditAction::OrganizationCreated, org_id.clone(), true),
        (AuditAction::OrganizationUpdated, org_id.clone(), false),
        (AuditAction::OrgMemberAdded, ada.id.to_string(), true),
        (AuditAction::OrgRoleAssigned, ada.id.to_string(), false),
        (AuditAction::OrgRoleUnassigned, ada.id.to_string(), false),
        (AuditAction::OrgInvitationCreated, inv_id.clone(), false),
        (AuditAction::OrgInvitationRevoked, inv_id.clone(), false),
        (AuditAction::OrgMemberRemoved, ada.id.to_string(), true),
        (AuditAction::OrganizationDeleted, org_id.clone(), true),
    ] {
        let e = find(action);
        assert_eq!(
            e.target.as_deref(),
            Some(target.as_str()),
            "{}",
            action.as_str()
        );
        assert_eq!(e.details.as_map()["org_id"], org_id.as_str());
        assert!(
            !format!("{:?}", e.details).contains("bob@example.test"),
            "the invited address is not in the audit details"
        );
        let classified = anvil_core::policy::webhook_event::webhook_event(
            &tenant.to_string(),
            &NewAuditEvent {
                id: e.id,
                at: e.at,
                actor: e.actor.clone(),
                action: e.action,
                target: e.target.clone(),
                outcome: e.outcome,
                ctx: e.ctx.clone(),
                details: e.details.clone(),
                webhook: None,
            },
        );
        assert_eq!(classified.is_some(), webhook, "{}", action.as_str());
        if let Some(w) = classified {
            assert!(
                w.payload_json.contains(&org_id),
                "{} names its org",
                action.as_str()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Per-user memberships (06-29)
// ---------------------------------------------------------------------------------------------

fn user_orgs(tenant: &str, user: impl std::fmt::Display) -> String {
    format!("{API}/tenants/{tenant}/users/{user}/organizations")
}

#[tokio::test]
async fn user_organizations_lists_memberships_with_roles() {
    let app = app().await;
    let token = admin_token(&app, "admin:users:read").await;
    let tenant = default_tenant(&app);
    // Created out of slug order: the answer is in slug order.
    let zeta = create_org(&app, tenant, "zeta").await;
    let alpha = create_org(&app, tenant, "alpha").await;
    create_org(&app, tenant, "other").await;
    let editor = create_role(&app, tenant, Some(alpha.id), "editor", &["docs:write"]).await;
    let viewer = create_role(&app, tenant, None, "viewer", &["docs:read"]).await;
    let ada = seed_user(&app, tenant, "ada@example.test").await;
    admin_support::add_member(&app, tenant, alpha.id, ada.id, &[editor.id, viewer.id]).await;
    admin_support::add_member(&app, tenant, zeta.id, ada.id, &[]).await;

    let resp = call(
        &app,
        Method::GET,
        &user_orgs("default", ada.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    let items = body_json(&resp)["items"].as_array().unwrap().clone();
    let slugs: Vec<&str> = items
        .iter()
        .map(|i| i["organization"]["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, ["alpha", "zeta"], "the non-member org is absent");
    assert_eq!(items[0]["organization"]["id"], alpha.id.0.to_string());
    let roles: Vec<(String, String)> = items[0]["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_owned(),
                r["scope"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        roles,
        vec![
            ("editor".to_owned(), "org".to_owned()),
            ("viewer".to_owned(), "tenant".to_owned()),
        ]
    );
    assert_eq!(items[1]["roles"], json!([]));

    // The organizations read scope works too.
    let orgs_read = admin_token(&app, "admin:organizations:read").await;
    let resp = call(
        &app,
        Method::GET,
        &user_orgs("default", ada.id),
        Some(&orgs_read),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp)["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn user_organizations_empty_for_user_without_memberships() {
    let app = app().await;
    let token = admin_token(&app, "admin:read").await;
    let tenant = default_tenant(&app);
    create_org(&app, tenant, "acme").await;
    let bob = seed_user(&app, tenant, "bob@example.test").await;
    let resp = call(
        &app,
        Method::GET,
        &user_orgs("default", bob.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(body_json(&resp), json!({"items": []}));
}

#[tokio::test]
async fn user_organizations_unknown_or_foreign_user_is_404() {
    let app = app().await;
    let token = admin_token(&app, "admin:read").await;
    let other = acme(&app).await;
    let org = create_org(&app, other.id, "foreign-org").await;
    let foreign = seed_user(&app, other.id, "eve@example.test").await;
    admin_support::add_member(&app, other.id, org.id, foreign.id, &[]).await;

    for path in [
        user_orgs("default", uuid::Uuid::now_v7()),
        user_orgs("default", "not-a-uuid"),
        // A user of another tenant, asked through this tenant.
        user_orgs("default", foreign.id),
        user_orgs("no-such-tenant", foreign.id),
    ] {
        let resp = call(&app, Method::GET, &path, Some(&token), None).await;
        assert_problem(&resp, 404);
    }
    // Through its own tenant the same user is found.
    let resp = call(
        &app,
        Method::GET,
        &user_orgs("acme", foreign.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        body_json(&resp)["items"][0]["organization"]["slug"],
        "foreign-org"
    );
}
