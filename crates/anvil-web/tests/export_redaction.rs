//! User export (ADM-09) on the selected backend (`ANVILID_TEST_DB`): the allow-list DTOs of the
//! single, bulk and GDPR exports, keyset paging of the bulk export, the GDPR inventory, the
//! redaction of other people's identities in the GDPR audit section, and the no-secrets guarantee.
//!
//! The fixture is seeded through the storage traits only: a fully populated subject (password,
//! TOTP with recovery codes, passkey, session, consent, token families, identity link, tenant and
//! org roles, pending self-service token, attributes, audit events by the subject, by an
//! administrator and by the system) plus other users with bcrypt and Firebase hashes.

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use anvil_core::model::{
    ActorKind, ApplicationType, AuditAction, AuditActor, AuditDetails, AuditEventId, AuditOutcome,
    AuditQuery, ClientAuthMethod, ClientId, ClientKind, ClientSource, ClientType, ConnectionConfig,
    ConnectionId, ConsentId, ConsentMode, CredentialId, GrantType, IdentityLinkId, NewAuditEvent,
    NewBrowserSession, NewClient, NewConnection, NewConsent, NewIdentityLink, NewMembership,
    NewOrganization, NewPasskey, NewPasswordCredential, NewRole, NewSelfServiceToken,
    NewTokenFamily, NewTotp, NewUser, OidcConfig, OrgClientPolicy, OrgId, OrgSettings,
    RecoveryCodeHash, RequestContext, RevokeReason, RoleId, SecretHash, SelfServiceKind, SessionId,
    StandardClaims, TenantId, TokenFamilyId, TokenFormat, UserId, UserStatus,
};
use anvil_core::ports::{AddMemberOutcome, Clock, Storage};
use anvil_core::service::user_export::{ExportOptions, UserExportService};
use anvil_jose::encoding::{b64std, b64url};
use serde_json::{Value, json};
use support::{TestApp, start_time};
use time::Duration;

const SUBJECT_EMAIL: &str = "alice@example.test";
const ADMIN_EMAIL: &str = "admin-person@example.test";
const OTHER_EMAIL: &str = "bob@example.test";
const PENDING_ADDRESS: &str = "pending-address@example.test";
const SUBJECT_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ViamVjdHNhbHQ$c3ViamVjdGhhc2g";
const BCRYPT_PHC: &str = "$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
const LEGACY_BCRYPT_PHC: &str = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ56789";
const FIREBASE_PHC: &str =
    "$anvil-firebase-scrypt$profile=0190a000-0000-7000-8000-000000000001$c2FsdA$aGFzaA";
const PASSKEY_MARKER: &str = "PASSKEY-PRIVATE-MATERIAL-MARKER";
const TOTP_SEED_SEALED: &[u8] = b"sealed-totp-seed-bytes-0123456789abcdef";
const CONNECTION_SECRET_SEALED: &[u8] = b"sealed-connection-secret-0123456789abcd";

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every textual form a secret byte string could take in an export.
fn encodings(data: &[u8]) -> Vec<String> {
    vec![b64std(data), b64url(data), hex(data)]
}

/// The app's start time (the fixture is seeded relative to it).
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> time::OffsetDateTime {
        start_time()
    }
}

struct Fixture {
    app: TestApp,
    tenant: TenantId,
    subject: UserId,
    admin: UserId,
    other: UserId,
    /// Every user of the tenant, in id order.
    users: Vec<UserId>,
    /// Byte strings that must never appear in any export, in any encoding.
    secret_bytes: Vec<Vec<u8>>,
}

impl Fixture {
    fn service(&self) -> UserExportService {
        UserExportService {
            storage: self.app.storage_arc(),
            clock: Arc::new(FixedClock) as Arc<dyn Clock>,
        }
    }

    fn storage(&self) -> &dyn Storage {
        self.app.storage()
    }
}

fn hash(tag: u8) -> SecretHash {
    let mut b = [tag; 32];
    b[0] = 0xA5;
    b[31] = tag.wrapping_mul(7);
    SecretHash(b)
}

fn new_user(email: &str, created: time::OffsetDateTime) -> NewUser {
    NewUser {
        id: UserId::new_v7(),
        email: email.to_owned(),
        email_verified: true,
        username: Some(email.split('@').next().unwrap_or("u").to_owned()),
        claims: StandardClaims {
            name: Some(format!("Name of {email}")),
            given_name: Some("Given".into()),
            family_name: Some("Family".into()),
            locale: Some("en".into()),
            phone_number: Some("+15555550100".into()),
            ..StandardClaims::default()
        },
        status: UserStatus::Active,
        created_at: created,
    }
}

async fn create_user(s: &dyn Storage, tenant: TenantId, email: &str, phc: Option<&str>) -> UserId {
    let now = start_time() - Duration::days(30);
    let u = new_user(email, now);
    let pw = phc.map(|p| NewPasswordCredential {
        phc: p.to_owned(),
        created_at: now,
    });
    s.users()
        .create(tenant, &u, pw.as_ref(), None, None)
        .await
        .expect("create user")
        .id
}

fn audit_event(
    actor: AuditActor,
    action: AuditAction,
    target: Option<String>,
    at: time::OffsetDateTime,
) -> NewAuditEvent {
    NewAuditEvent {
        id: AuditEventId::new_v7(),
        at,
        actor,
        action,
        target,
        outcome: AuditOutcome::Success,
        ctx: RequestContext::new(
            Some("198.51.100.23".parse().expect("ip")),
            Some("Mozilla/5.0 (fixture)"),
            Some("trace-fixture".into()),
        ),
        details: AuditDetails::fields(&["name"]),
        webhook: None,
    }
}

async fn fixture() -> Fixture {
    let app = TestApp::new().await;
    let tenant = app.default.as_ref().expect("default tenant").tenant.id;
    let s = app.storage();
    let now = start_time();

    let admin = create_user(s, tenant, ADMIN_EMAIL, Some(LEGACY_BCRYPT_PHC)).await;
    let subject = create_user(s, tenant, SUBJECT_EMAIL, Some(SUBJECT_PHC)).await;
    let other = create_user(s, tenant, OTHER_EMAIL, Some(BCRYPT_PHC)).await;
    let carol = create_user(s, tenant, "carol@example.test", Some(FIREBASE_PHC)).await;
    let mut users = vec![admin, subject, other, carol];
    for i in 0..3 {
        users.push(create_user(s, tenant, &format!("filler-{i}@example.test"), None).await);
    }
    users.sort();

    // Credentials: passkey, TOTP with five recovery codes (one used).
    s.users()
        .create_passkey(
            tenant,
            subject,
            &NewPasskey {
                id: CredentialId::new_v7(),
                credential_id: b"webauthn-credential-id-bytes".to_vec(),
                passkey_json: format!(r#"{{"cred":{{"key":"{PASSKEY_MARKER}","counter":0}}}}"#),
                counter: 0,
                backup_eligible: true,
                label: "Work laptop".into(),
                created_at: now - Duration::days(10),
            },
        )
        .await
        .expect("passkey");
    let codes: Vec<RecoveryCodeHash> = (1..=5).map(|i| RecoveryCodeHash(hash(i).0)).collect();
    s.users()
        .create_totp(
            tenant,
            subject,
            &NewTotp {
                id: CredentialId::new_v7(),
                secret_enc: TOTP_SEED_SEALED.to_vec(),
                created_at: now - Duration::days(9),
            },
            &codes,
            now - Duration::days(9),
        )
        .await
        .expect("totp");
    assert!(
        s.users()
            .consume_recovery_code(tenant, subject, &codes[0], now, None)
            .await
            .expect("consume code")
    );

    // Session.
    let session_id = SessionId::new_v7();
    s.sessions()
        .create(
            tenant,
            &NewBrowserSession {
                id: session_id,
                user_id: subject,
                token_hash: hash(20),
                auth_time: now - Duration::hours(1),
                acr: "1".into(),
                amr: vec!["pwd".into()],
                created_at: now - Duration::hours(1),
                expires_at: now + Duration::hours(8),
                idle_expires_at: now + Duration::hours(1),
                ip: Some("192.0.2.44".into()),
                user_agent: Some("Mozilla/5.0 (subject browser)".into()),
            },
        )
        .await
        .expect("session");

    // Client, consent, two token families (one revoked).
    let client_id = "photo-app".to_owned();
    s.clients()
        .create(
            tenant,
            &NewClient {
                id: ClientId::new_v7(),
                client_id: client_id.clone(),
                name: "Photo App".into(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                secret_hash: Some(hash(30)),
                jwks: None,
                redirect_uris: vec!["https://photos.example.test/cb".into()],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes: vec!["openid".into(), "profile".into()],
                require_pkce: true,
                token_format: TokenFormat::Jwt,
                consent_mode: ConsentMode::Required,
                id_token_signed_response_alg: None,
                can_introspect: false,
                created_at: now - Duration::days(20),
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                allowed_resources: vec![],
                mfa_policy: None,
                registration_source: ClientSource::Static,
                metadata_expires_at: None,
                registration_access_token_hash: None,
                organization: OrgClientPolicy::Off,
                require_pushed_authorization_requests: false,
                client_kind: ClientKind::Application,
                headless_native: false,
            },
        )
        .await
        .expect("client");
    s.grants()
        .upsert_consent(
            tenant,
            &NewConsent {
                id: ConsentId::new_v7(),
                user_id: subject,
                client_id: client_id.clone(),
                scopes: vec!["openid".into(), "profile".into()],
                resources: vec![],
                created_at: now - Duration::days(5),
            },
            now - Duration::days(5),
        )
        .await
        .expect("consent");
    let mut family_ids = Vec::new();
    for _ in 0..2 {
        let id = TokenFamilyId::new_v7();
        s.grants()
            .create_family(
                tenant,
                &NewTokenFamily {
                    id,
                    client_id: client_id.clone(),
                    user_id: Some(subject),
                    scope: "openid profile offline_access".into(),
                    resource: vec![],
                    auth_time: Some(now - Duration::hours(1)),
                    acr: Some("1".into()),
                    amr: vec!["pwd".into()],
                    session_id: Some(session_id),
                    claims: None,
                    org_id: None,
                    created_at: now - Duration::hours(1),
                    absolute_expires_at: now + Duration::days(30),
                },
            )
            .await
            .expect("family");
        family_ids.push(id);
    }
    assert!(
        s.grants()
            .revoke_family(tenant, family_ids[0], RevokeReason::Admin, now)
            .await
            .expect("revoke")
    );

    // Connection and identity link.
    let connection = ConnectionId::new_v7();
    s.connections()
        .create(
            tenant,
            &NewConnection {
                id: connection,
                org_id: None,
                slug: "corp-oidc".into(),
                display_name: "Corporate".into(),
                enabled: true,
                config: ConnectionConfig::Oidc(OidcConfig {
                    issuer: "https://idp.example.test".into(),
                    client_id: "rp-anvil".into(),
                    scopes: vec!["openid".into()],
                    use_pkce: true,
                    fetch_userinfo: false,
                }),
                secret_enc: Some(CONNECTION_SECRET_SEALED.to_vec()),
                trust_email_verified: false,
                created_at: now - Duration::days(20),
            },
        )
        .await
        .expect("connection");
    let mut metadata = serde_json::Map::new();
    metadata.insert("tid".into(), Value::from("upstream-tenant-guid"));
    s.connections()
        .create_link(
            tenant,
            &NewIdentityLink {
                id: IdentityLinkId::new_v7(),
                user_id: subject,
                connection_id: connection,
                subject: "upstream-sub-123".into(),
                email_at_link: Some("alice@corp.example.test".into()),
                metadata,
                created_at: now - Duration::days(8),
            },
        )
        .await
        .expect("link");

    // Tenant role, organization with an org-owned role.
    let tenant_role = s
        .roles()
        .create(
            tenant,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: None,
                name: "editor".into(),
                description: "Editors".into(),
                permissions: vec!["posts:write".into()],
                created_at: now - Duration::days(20),
            },
        )
        .await
        .expect("tenant role");
    assert!(
        s.roles()
            .assign(tenant, tenant_role.id, subject, now)
            .await
            .expect("assign")
    );
    let org = s
        .organizations()
        .create(
            tenant,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme Inc".into(),
                mfa_policy: None,
                settings: OrgSettings::default(),
                metadata: json!({}),
                created_at: now - Duration::days(20),
            },
        )
        .await
        .expect("org");
    let org_role = s
        .roles()
        .create(
            tenant,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: Some(org.id),
                name: "billing".into(),
                description: "Billing".into(),
                permissions: vec!["invoices:read".into()],
                created_at: now - Duration::days(20),
            },
        )
        .await
        .expect("org role");
    assert_eq!(
        s.organizations()
            .add_member(
                tenant,
                &NewMembership {
                    org_id: org.id,
                    user_id: subject,
                    role_ids: vec![org_role.id],
                    created_at: now - Duration::days(7),
                },
            )
            .await
            .expect("member"),
        AddMemberOutcome::Added
    );

    // Pending self-service token and attributes.
    s.users()
        .issue_self_service_token(
            tenant,
            &NewSelfServiceToken {
                token_hash: hash(40),
                kind: SelfServiceKind::EmailChange,
                user_id: subject,
                email: PENDING_ADDRESS.into(),
                created_at: now - Duration::minutes(5),
                expires_at: now + Duration::hours(1),
            },
            None,
        )
        .await
        .expect("token");
    let mut attrs = serde_json::Map::new();
    attrs.insert("department".into(), Value::from("R&D"));
    assert!(
        s.attributes()
            .set_user_values(tenant, subject, &attrs, now)
            .await
            .expect("attributes")
    );

    // Audit: by the subject, about the subject by an administrator (by id and by email), by the
    // system, and an event of the subject's about another user.
    let audit = s.audit();
    for e in [
        audit_event(
            AuditActor::user(subject),
            AuditAction::LoginSucceeded,
            Some(subject.to_string()),
            now - Duration::hours(1),
        ),
        audit_event(
            AuditActor::admin(admin),
            AuditAction::UserUpdated,
            Some(subject.to_string()),
            now - Duration::minutes(50),
        ),
        audit_event(
            AuditActor::admin(ADMIN_EMAIL),
            AuditAction::UserUpdated,
            Some(subject.to_string()),
            now - Duration::minutes(40),
        ),
        audit_event(
            AuditActor::system(),
            AuditAction::UserUpdated,
            Some(subject.to_string()),
            now - Duration::minutes(30),
        ),
        audit_event(
            AuditActor::admin(subject),
            AuditAction::UserUpdated,
            Some(other.to_string()),
            now - Duration::minutes(20),
        ),
        // Not about the subject: must not appear.
        audit_event(
            AuditActor::admin(admin),
            AuditAction::UserUpdated,
            Some(other.to_string()),
            now - Duration::minutes(10),
        ),
    ] {
        audit.append(tenant, &e).await.expect("audit");
    }

    let mut secret_bytes: Vec<Vec<u8>> = vec![
        TOTP_SEED_SEALED.to_vec(),
        CONNECTION_SECRET_SEALED.to_vec(),
        hash(20).0.to_vec(),
        hash(30).0.to_vec(),
        hash(40).0.to_vec(),
    ];
    secret_bytes.extend(codes.iter().map(|c| c.0.to_vec()));
    let _ = carol;
    Fixture {
        app,
        tenant,
        subject,
        admin,
        other,
        users,
        secret_bytes,
    }
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn cli() -> AuditActor {
    AuditActor {
        kind: ActorKind::System,
        id: Some("cli".into()),
    }
}

async fn bulk_all(f: &Fixture, options: ExportOptions, page_size: u32) -> (Vec<Value>, usize) {
    let mut export = f
        .service()
        .bulk(f.tenant, options)
        .with_page_size(page_size);
    let mut out = Vec::new();
    let mut pages = 0;
    while let Some(page) = export.next_page().await.expect("page") {
        assert!(
            page.len() <= page_size as usize,
            "page bounded by page size"
        );
        pages += 1;
        out.extend(page.iter().map(|r| serde_json::to_value(r).expect("json")));
    }
    assert_eq!(
        export
            .finish(&cli(), &RequestContext::system())
            .await
            .expect("finish"),
        out.len() as u64
    );
    (out, pages)
}

#[tokio::test]
async fn single_export_has_exactly_the_allowed_fields() {
    let f = fixture().await;
    let rec = f
        .service()
        .export_user(f.tenant, f.subject, &cli(), &RequestContext::system())
        .await
        .expect("export");
    let v = serde_json::to_value(&rec).expect("json");
    assert_eq!(
        keys(&v),
        set(&[
            "id",
            "email",
            "email_verified",
            "username",
            "status",
            "claims",
            "attributes",
            "created_at",
            "updated_at",
            "last_login_at",
            "roles",
            "organizations",
            "identity_links",
            "credentials",
        ])
    );
    assert_eq!(v["id"], f.subject.to_string());
    assert_eq!(v["email"], SUBJECT_EMAIL);
    assert_eq!(v["status"], "active");
    assert_eq!(v["claims"]["given_name"], "Given");
    assert_eq!(v["attributes"]["department"], "R&D");
    assert_eq!(v["roles"][0]["name"], "editor");
    assert_eq!(v["organizations"][0]["slug"], "acme");
    assert_eq!(v["organizations"][0]["roles"][0]["name"], "billing");
    assert_eq!(
        v["identity_links"][0],
        json!({"connection_id": v["identity_links"][0]["connection_id"], "connection": "corp-oidc", "subject": "upstream-sub-123"})
    );
    let kinds: BTreeSet<&str> = v["credentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .map(|c| {
            assert_eq!(
                keys(c),
                set(&["id", "kind", "label", "created_at", "last_used_at"])
            );
            c["kind"].as_str().expect("kind")
        })
        .collect();
    assert_eq!(kinds, BTreeSet::from(["password", "webauthn", "totp"]));

    // Unknown user: NotFound, nothing exported.
    let err = f
        .service()
        .export_user(
            f.tenant,
            UserId::new_v7(),
            &cli(),
            &RequestContext::system(),
        )
        .await
        .expect_err("unknown user");
    assert!(
        matches!(err, anvil_core::error::CoreError::NotFound),
        "{err:?}"
    );
}

#[tokio::test]
async fn bulk_stream_pages_every_user_once_in_order() {
    let f = fixture().await;
    let (records, pages) = bulk_all(&f, ExportOptions::default(), 3).await;
    assert_eq!(pages, 3, "7 users in pages of 3");
    let ids: Vec<String> = records
        .iter()
        .map(|r| r["id"].as_str().expect("id").to_owned())
        .collect();
    let expected: Vec<String> = f.users.iter().map(ToString::to_string).collect();
    assert_eq!(ids, expected, "every user exactly once, id order");
    for r in &records {
        assert!(r.get("password_hash").is_none(), "no hash by default: {r}");
    }

    // A second run with the default page size returns the same records.
    let (again, pages) = bulk_all(&f, ExportOptions::default(), 100).await;
    assert_eq!(pages, 1);
    assert_eq!(again.len(), records.len());
}

#[tokio::test]
async fn gdpr_bundle_contains_every_inventory_category() {
    let f = fixture().await;
    let b = f
        .service()
        .gdpr_bundle(f.tenant, f.subject, &cli(), &RequestContext::system())
        .await
        .expect("bundle");
    let v = serde_json::to_value(&b).expect("json");
    assert_eq!(
        keys(&v),
        set(&[
            "export_format_version",
            "generated_at",
            "subject",
            "attributes",
            "credentials",
            "sessions",
            "consents",
            "token_families",
            "identity_links",
            "roles",
            "organizations",
            "audit_events",
            "pending_self_service_tokens",
            "operator_statement",
        ])
    );
    assert_eq!(v["export_format_version"], 1);
    assert_eq!(v["generated_at"], "2026-11-25T12:00:00.000Z");
    assert_eq!(v["operator_statement"], Value::Null);
    assert_eq!(v["subject"]["email"], SUBJECT_EMAIL);
    assert_eq!(v["subject"]["claims"]["phone_number"], "+15555550100");
    assert_eq!(v["attributes"]["department"], "R&D");

    let c = &v["credentials"];
    assert_eq!(c["password_set"], true);
    assert_eq!(c["totp_enrolled"], true);
    assert_eq!(c["recovery_codes_remaining"], 4);
    let passkey = c["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|i| i["kind"] == "webauthn")
        .expect("passkey");
    assert_eq!(passkey["label"], "Work laptop");

    assert_eq!(v["sessions"].as_array().expect("sessions").len(), 1);
    assert_eq!(v["sessions"][0]["ip"], "192.0.2.44");
    assert_eq!(
        v["sessions"][0]["user_agent"],
        "Mozilla/5.0 (subject browser)"
    );

    assert_eq!(v["consents"][0]["client_id"], "photo-app");
    assert_eq!(v["consents"][0]["scopes"], json!(["openid", "profile"]));

    let families = v["token_families"].as_array().expect("families");
    assert_eq!(families.len(), 2);
    assert_eq!(families[0]["revoked_reason"], "admin");
    assert_eq!(families[1]["revoked_at"], Value::Null);
    for fam in families {
        assert_eq!(
            keys(fam),
            set(&[
                "id",
                "client_id",
                "scope",
                "resources",
                "created_at",
                "expires_at",
                "revoked_at",
                "revoked_reason"
            ])
        );
    }

    assert_eq!(v["identity_links"][0]["connection"], "corp-oidc");
    assert_eq!(v["identity_links"][0]["subject"], "upstream-sub-123");
    assert_eq!(
        v["identity_links"][0]["email_at_link"],
        "alice@corp.example.test"
    );

    assert_eq!(v["roles"][0]["name"], "editor");
    assert_eq!(v["organizations"][0]["roles"][0]["name"], "billing");

    // Five events are about or by the subject; the admin's event about Bob is not.
    let events = v["audit_events"].as_array().expect("events");
    assert_eq!(events.len(), 5, "{events:#?}");

    assert_eq!(
        v["pending_self_service_tokens"],
        json!([{"kind": "email_change", "expires_at": "2026-11-25T13:00:00.000Z"}])
    );
}

#[tokio::test]
async fn gdpr_export_redacts_other_actors() {
    let f = fixture().await;
    let b = f
        .service()
        .gdpr_bundle(f.tenant, f.subject, &cli(), &RequestContext::system())
        .await
        .expect("bundle");
    let v = serde_json::to_value(&b).expect("json");
    let text = v.to_string();
    assert!(!text.contains(ADMIN_EMAIL), "admin email leaked");
    assert!(!text.contains(&f.admin.to_string()), "admin id leaked");
    assert!(
        !text.contains(&f.other.to_string()),
        "other user's id leaked"
    );
    assert!(!text.contains(OTHER_EMAIL));

    let events = v["audit_events"].as_array().expect("events");
    let actors: Vec<&str> = events
        .iter()
        .map(|e| e["actor"].as_str().expect("actor"))
        .collect();
    // Newest first.
    assert_eq!(
        actors,
        [
            "subject",
            "system",
            "administrator",
            "administrator",
            "subject"
        ]
    );
    // The subject's action on another user names that user only as a role.
    assert_eq!(events[0]["target"], "another_user");
    assert_eq!(events[1]["target"], "subject");
    // Request context only on the subject's own events.
    assert_eq!(events[2]["ip"], Value::Null);
    assert_eq!(events[4]["ip"], "198.51.100.23");
    for e in events {
        assert_eq!(e["actor_client_id"], Value::Null);
    }
}

/// Every string that marks a secret.
fn assert_no_secrets(f: &Fixture, mode: &str, text: &str) {
    for marker in [
        "$argon2",
        "$2a$",
        "$2b$",
        "$anvil-",
        PASSKEY_MARKER,
        PENDING_ADDRESS,
        ADMIN_EMAIL,
        // As a key (the audit detail `include_password_hashes` is allowed).
        "\"password_hash\"",
        "secret",
        "token_hash",
    ] {
        assert!(!text.contains(marker), "{mode}: found {marker:?} in {text}");
    }
    for bytes in &f.secret_bytes {
        for enc in encodings(bytes) {
            assert!(!text.contains(&enc), "{mode}: found encoded secret {enc}");
        }
    }
}

#[tokio::test]
async fn export_dto_contains_no_secrets() {
    let f = fixture().await;
    let svc = f.service();
    let ctx = RequestContext::system();

    let single = svc
        .export_user(f.tenant, f.subject, &cli(), &ctx)
        .await
        .expect("single");
    let single = serde_json::to_string(&single).expect("json");
    // The single export of the subject never names the administrator either.
    assert_no_secrets(&f, "single", &single);

    let (bulk, _) = bulk_all(&f, ExportOptions::default(), 2).await;
    let bulk_text: String = bulk.iter().map(|r| format!("{r}\n")).collect();
    // The bulk export lists the admin as a user (their own record); check the rest without
    // the admin's email marker.
    for line in bulk_text.lines() {
        let v: Value = serde_json::from_str(line).expect("ndjson line");
        if v["email"] == ADMIN_EMAIL {
            assert!(!line.contains("$2a$"), "admin hash leaked: {line}");
            continue;
        }
        assert_no_secrets(&f, "bulk", line);
    }

    let gdpr = svc
        .gdpr_bundle(f.tenant, f.subject, &cli(), &ctx)
        .await
        .expect("gdpr");
    let gdpr = serde_json::to_string(&gdpr).expect("json");
    assert_no_secrets(&f, "gdpr", &gdpr);
}

#[tokio::test]
async fn gdpr_bundle_has_no_password_field_even_with_flag() {
    let f = fixture().await;
    let svc = f.service();
    // A hash-including bulk export first: it must not change what the GDPR bundle contains.
    let (with_hashes, _) = bulk_all(
        &f,
        ExportOptions {
            include_password_hashes: true,
        },
        100,
    )
    .await;
    assert!(with_hashes.iter().any(|r| r.get("password_hash").is_some()));

    let b = svc
        .gdpr_bundle(f.tenant, f.subject, &cli(), &RequestContext::system())
        .await
        .expect("bundle");
    let text = serde_json::to_string(&b).expect("json");
    assert!(!text.contains("\"password_hash\""), "{text}");
    assert!(!text.contains("phc"), "{text}");
    assert!(!text.contains(SUBJECT_PHC), "{text}");
    assert!(!text.contains("$argon2"), "{text}");
}

#[tokio::test]
async fn bulk_hashes_only_with_explicit_option() {
    let f = fixture().await;

    // The HTTP entry point has no options: never a hash.
    let mut http = f.service().bulk_without_hashes(f.tenant);
    assert!(!http.includes_password_hashes());
    while let Some(page) = http.next_page().await.expect("page") {
        for r in page {
            assert!(r.password_hash.is_none());
        }
    }
    http.finish(&AuditActor::admin("console"), &RequestContext::system())
        .await
        .expect("finish");

    let (records, _) = bulk_all(
        &f,
        ExportOptions {
            include_password_hashes: true,
        },
        3,
    )
    .await;
    let hash_of = |email: &str| {
        records
            .iter()
            .find(|r| r["email"] == email)
            .and_then(|r| r.get("password_hash").cloned())
    };
    assert_eq!(hash_of(SUBJECT_EMAIL), Some(Value::from(SUBJECT_PHC)));
    assert_eq!(hash_of(OTHER_EMAIL), Some(Value::from(BCRYPT_PHC)));
    assert_eq!(
        hash_of("carol@example.test"),
        Some(Value::from(FIREBASE_PHC))
    );
    assert_eq!(
        hash_of("filler-0@example.test"),
        None,
        "no password, no field"
    );

    // Both runs are audited; the hash run says so, with the count.
    let page = f
        .storage()
        .audit()
        .query(
            f.tenant,
            &AuditQuery {
                from: None,
                to: None,
                actor_id: None,
                action: Some(AuditAction::UserExported),
                outcome: None,
                target: None,
                before: None,
                limit: 50,
            },
        )
        .await
        .expect("audit");
    assert_eq!(page.items.len(), 2);
    let newest = &page.items[0];
    assert_eq!(newest.actor, cli());
    assert_eq!(newest.target, None);
    assert_eq!(
        Value::Object(newest.details.as_map().clone()),
        json!({"mode": "bulk", "count": 7, "include_password_hashes": true})
    );
    let oldest = &page.items[1];
    assert_eq!(
        Value::Object(oldest.details.as_map().clone()),
        json!({"mode": "bulk", "count": 7, "include_password_hashes": false})
    );
}

#[tokio::test]
async fn single_and_gdpr_exports_are_audited_with_target() {
    let f = fixture().await;
    let svc = f.service();
    let ctx = RequestContext::system();
    svc.export_user(f.tenant, f.subject, &cli(), &ctx)
        .await
        .expect("single");
    svc.gdpr_bundle(f.tenant, f.subject, &cli(), &ctx)
        .await
        .expect("gdpr");
    let page = f
        .storage()
        .audit()
        .query(
            f.tenant,
            &AuditQuery {
                from: None,
                to: None,
                actor_id: None,
                action: Some(AuditAction::UserExported),
                outcome: None,
                target: Some(f.subject.to_string()),
                before: None,
                limit: 50,
            },
        )
        .await
        .expect("audit");
    let modes: Vec<Value> = page
        .items
        .iter()
        .map(|e| e.details.as_map()["mode"].clone())
        .collect();
    assert_eq!(modes, [json!("gdpr"), json!("single")]);
    for e in &page.items {
        assert_eq!(e.details.as_map()["include_password_hashes"], false);
        assert_eq!(e.details.as_map()["count"], 1);
    }
}
