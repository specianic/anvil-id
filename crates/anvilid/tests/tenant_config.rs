//! `anvilid tenant export|plan|apply` (ADM-06, ADM-07) on SQLite installations:
//!
//! - `round_trip_into_fresh_instance`: instance A is configured through the services, exported
//!   as YAML, applied to a fresh instance B with secrets from `{env}` / `{file}` references, and
//!   B's export equals A's (generated secrets are printed once); re-applying prints "No changes";
//! - `apply` without `--yes` on a non-terminal stdin refuses and changes nothing;
//! - deletions need `--prune`;
//! - invalid documents are reported by path and change nothing.

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use anvil_core::clock::SystemClock;
use anvil_core::model::{
    ApplicationType, AuditActor, ClientAuthMethod, ClientType, ConnectionConfig, GrantType,
    PublicUrl, RequestContext, SocialConfig, SocialProvider, Tenant, ThemeTokens, WebhookEventType,
};
use anvil_core::model::{Scope, SmtpTls};
use anvil_core::policy::PasswordPolicy;
use anvil_core::ports::Storage as _;
use anvil_core::service::attribute::AttributeService;
use anvil_core::service::bootstrap::{BootstrapService, InstallResult};
use anvil_core::service::branding::{BrandingInput, BrandingService};
use anvil_core::service::client::{ClientInput, ClientOptions, ClientService};
use anvil_core::service::connection::{ConnectionService, NewConnectionInput};
use anvil_core::service::mail_settings::{MailSettingsService, SmtpInput};
use anvil_core::service::role::{RoleInput, RoleService};
use anvil_core::service::tenant::{TenantPatch, TenantService};
use anvil_core::service::webhook::{NewWebhookInput, WebhookService};
use anvil_jose::Kek;
use anvil_storage_sqlite::SqliteStorage;
use anvil_web::adapters::Argon2Pool;
use anvil_web::adapters::attribute_schema::JsonSchemaCheck;
use anvil_web::adapters::outbound::{OutboundClient, OutboundPolicy};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_anvilid");
const GOOGLE_SECRET: &str = "google-upstream-secret-from-env";
const SMTP_PASSWORD: &str = "smtp-password-from-file";

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// An installed data directory (in-process install, KEK file written).
struct Instance {
    dir: tempfile::TempDir,
    storage: Arc<SqliteStorage>,
    kek: Arc<Kek>,
}

impl Instance {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("anvilid-data");
        std::fs::create_dir(&data).expect("data dir");
        let kek = Kek::generate();
        std::fs::write(data.join("kek"), kek.to_base64().expose_secret()).expect("kek file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(data.join("kek"), std::fs::Permissions::from_mode(0o600))
                .expect("chmod kek");
        }
        let storage = SqliteStorage::connect(&format!(
            "sqlite://{}?mode=rwc",
            data.join("anvilid.db").display()
        ))
        .await
        .expect("connect");
        storage.migrate().await.expect("migrate");
        let instance = Self {
            dir,
            storage: Arc::new(storage),
            kek: Arc::new(kek),
        };
        let bootstrap = BootstrapService {
            storage: instance.storage.clone(),
            clock: Arc::new(SystemClock),
            kek: instance.kek.clone(),
            hasher: Arc::new(Argon2Pool::new(Argon2Pool::owasp_params(), 1).expect("argon2")),
            policy: PasswordPolicy::default(),
            public_url: PublicUrl::parse("https://id.example.test").expect("public url"),
        };
        assert!(matches!(
            bootstrap.ensure_installed().await.expect("install"),
            InstallResult::Installed { .. }
        ));
        instance
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(self.dir.path())
            .env_clear()
            .env("ANVILID_PUBLIC_URL", "https://id.example.test")
            .env("ANVILID_BREACH_CHECK", "off")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null());
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().expect("run anvilid")
    }

    async fn tenant(&self, slug: &str) -> Tenant {
        self.storage
            .tenants()
            .get_by_slug(slug)
            .await
            .expect("lookup")
            .expect("tenant")
    }

    fn clock(&self) -> Arc<dyn anvil_core::ports::Clock> {
        Arc::new(SystemClock)
    }
}

/// Configures instance A's default tenant through the services.
async fn configure(a: &Instance) -> String {
    let storage: Arc<dyn anvil_core::ports::Storage> = a.storage.clone();
    let actor = AuditActor::system();
    let ctx = RequestContext::system();
    let tenants = TenantService {
        storage: storage.clone(),
        clock: a.clock(),
        kek: a.kek.clone(),
    };
    let mut settings = a.tenant("default").await.settings;
    settings.default_locale = "de".into();
    tenants
        .update(
            "default",
            TenantPatch {
                settings: Some(settings),
                ..TenantPatch::default()
            },
            None,
            actor.clone(),
            &ctx,
        )
        .await
        .expect("settings");
    let tenant = a.tenant("default").await;
    RoleService {
        storage: storage.clone(),
        clock: a.clock(),
    }
    .create(
        &tenant,
        RoleInput {
            name: "editor".into(),
            description: "Edits documents".into(),
            permissions: vec!["docs:write".into(), "docs:read".into()],
        },
        &Scope::parse("admin:write").unwrap(),
        actor.clone(),
        &ctx,
    )
    .await
    .expect("role");
    AttributeService {
        storage: storage.clone(),
        clock: a.clock(),
        check: Arc::new(JsonSchemaCheck::new()),
    }
    .define(
        tenant.id,
        actor.clone(),
        &serde_json::from_value(json!({
            "name": "department",
            "schema": {"type": "string", "enum": ["sales", "engineering"]},
            "user_editable": true,
            "claim": {"claim": "department", "tokens": ["access_token"], "scope": "profile"},
        }))
        .expect("attribute"),
        &ctx,
    )
    .await
    .expect("define");
    let clients = ClientService {
        storage: storage.clone(),
        clock: a.clock(),
        redirect_validator: anvil_core::oauth::redirect::validate_redirect_uri,
    };
    let web = clients
        .create(
            &tenant,
            ClientInput {
                name: "Billing".into(),
                client_type: ClientType::Confidential,
                application_type: ApplicationType::Web,
                auth_method: ClientAuthMethod::ClientSecretBasic,
                redirect_uris: vec!["https://billing.example.test/cb".into()],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                scopes: vec!["openid".into(), "profile".into()],
                require_pkce: None,
                jwks: None,
                jwks_uri: None,
            },
            ClientOptions {
                post_logout_redirect_uris: vec!["https://billing.example.test/".into()],
                ..ClientOptions::default()
            },
            actor.clone(),
            &ctx,
        )
        .await
        .expect("client");
    BrandingService {
        storage: storage.clone(),
        clock: a.clock(),
    }
    .put(
        tenant.id,
        &anvil_core::model::BrandingScope::Client(web.client.client_id.clone()),
        BrandingInput {
            tokens: serde_json::from_value::<ThemeTokens>(json!({"radius_px": 6})).expect("tokens"),
            custom_css: None,
        },
        actor.clone(),
        &ctx,
    )
    .await
    .expect("branding");
    ConnectionService {
        storage: storage.clone(),
        clock: a.clock(),
        kek: a.kek.clone(),
        saml_enabled: false,
        saml_xml: None,
        upstream: None,
    }
    .create(
        tenant.id,
        NewConnectionInput {
            slug: "google".into(),
            display_name: "Google".into(),
            enabled: true,
            config: ConnectionConfig::Social(SocialConfig {
                provider: SocialProvider::Google,
                client_id: "abc.apps.example.test".into(),
                scopes: vec![],
                endpoints: Default::default(),
                microsoft_tenant: None,
                allowed_tenants: vec![],
                hosted_domains: vec![],
                apple: None,
            }),
            secret: Some(SecretString::from("google-secret-of-instance-a")),
            trust_email_verified: Some(true),
            accept_email_trust_risk: false,
        },
        actor.clone(),
        &ctx,
    )
    .await
    .expect("connection");
    WebhookService {
        storage: storage.clone(),
        kek: a.kek.clone(),
        clock: a.clock(),
        url_check: Arc::new(OutboundClient::new(&OutboundPolicy::default()).expect("outbound")),
    }
    .create(
        tenant.id,
        NewWebhookInput {
            name: "crm".into(),
            url: "https://hooks.example.test/anvil".into(),
            events: vec![WebhookEventType::UserCreated, WebhookEventType::UserDeleted],
            enabled: true,
            secret: None,
        },
        actor.clone(),
        &ctx,
    )
    .await
    .expect("webhook");
    MailSettingsService {
        storage,
        clock: a.clock(),
        kek: a.kek.clone(),
        checker: Arc::new(anvil_mail::TemplateChecker),
        tester: Arc::new(anvil_mail::LettreSmtpTester::default()),
    }
    .put_smtp(
        tenant.id,
        SmtpInput {
            host: "smtp.example.test".into(),
            port: 587,
            username: Some("mailer".into()),
            password: Some(SecretString::from("smtp-password-of-instance-a")),
            from: "id@example.test".into(),
            tls: SmtpTls::Starttls,
        },
        actor,
        &ctx,
    )
    .await
    .expect("smtp");
    web.client.client_id
}

fn yaml(path: &Path) -> Value {
    serde_saphyr::from_str(&std::fs::read_to_string(path).expect("read yaml")).expect("parse yaml")
}

fn write_yaml(path: &Path, v: &Value) {
    std::fs::write(path, serde_saphyr::to_string(v).expect("yaml")).expect("write yaml");
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_into_fresh_instance() {
    let a = Instance::new().await;
    let client_id = configure(&a).await;

    let out = a.run(&["tenant", "export", "default", "-o", "a.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let raw = std::fs::read_to_string(a.path("a.yaml")).unwrap();
    assert!(raw.starts_with("# AnvilID tenant configuration"), "{raw}");
    for secret in [
        "google-secret-of-instance-a",
        "smtp-password-of-instance-a",
        "whsec_",
    ] {
        assert!(!raw.contains(secret), "export leaks {secret}");
    }
    let exported_a = yaml(&a.path("a.yaml"));
    assert_eq!(exported_a["clients"][0]["client_id"], client_id.as_str());
    assert_eq!(
        exported_a["connections"][0]["secret"],
        json!({"configured": true})
    );

    // The operator replaces kept secrets by references for the new instance.
    let b = Instance::new().await;
    let mut doc = exported_a.clone();
    doc["connections"][0]["secret"] = json!({"env": "GOOGLE_SECRET"});
    doc["smtp"]["password"] = json!({"file": "secrets/smtp-password.txt"});
    std::fs::create_dir(b.path("secrets")).unwrap();
    std::fs::write(
        b.path("secrets/smtp-password.txt"),
        format!("{SMTP_PASSWORD}\n"),
    )
    .unwrap();
    write_yaml(&b.path("b.yaml"), &doc);

    // Plan only: nothing changes.
    let out = b.run(
        &["tenant", "plan", "-f", "b.yaml"],
        &[("GOOGLE_SECRET", GOOGLE_SECRET)],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("+ role editor"), "{}", text(&out));
    let tenant_b = b.tenant("default").await;
    assert!(
        b.storage
            .roles()
            .list(tenant_b.id)
            .await
            .unwrap()
            .is_empty()
    );

    let out = b.run(
        &["tenant", "apply", "-f", "b.yaml", "--yes"],
        &[("GOOGLE_SECRET", GOOGLE_SECRET)],
    );
    assert!(out.status.success(), "{}", text(&out));
    let printed = text(&out);
    assert!(printed.contains("Applied:"), "{printed}");
    assert!(
        printed.contains(&format!("Generated secret of client {client_id}")),
        "{printed}"
    );
    assert!(
        printed.contains("Generated secret of webhook crm"),
        "{printed}"
    );
    assert!(!printed.contains(GOOGLE_SECRET) && !printed.contains(SMTP_PASSWORD));

    // B's export equals A's.
    let out = b.run(&["tenant", "export", "default", "-o", "b-export.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(yaml(&b.path("b-export.yaml")), exported_a);

    // The referenced secrets were stored (sealed) on B.
    let conn = &b.storage.connections().list(tenant_b.id).await.unwrap()[0];
    let opened = ConnectionService {
        storage: b.storage.clone(),
        clock: b.clock(),
        kek: b.kek.clone(),
        saml_enabled: false,
        saml_xml: None,
        upstream: None,
    }
    .open_secret(conn)
    .unwrap()
    .unwrap();
    assert_eq!(opened.expose_secret(), GOOGLE_SECRET);
    let smtp = b
        .storage
        .mail_settings()
        .smtp(tenant_b.id)
        .await
        .unwrap()
        .unwrap();
    let opened = anvil_core::service::mail_settings::smtp_connection(&b.kek, tenant_b.id, &smtp)
        .unwrap()
        .password
        .unwrap();
    assert_eq!(opened.expose_secret(), SMTP_PASSWORD);

    // Re-applying changes nothing.
    let out = b.run(
        &["tenant", "apply", "-f", "b.yaml", "--yes"],
        &[("GOOGLE_SECRET", GOOGLE_SECRET)],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("No changes."), "{}", text(&out));
    assert!(!text(&out).contains("Generated"), "{}", text(&out));
}

#[tokio::test(flavor = "multi_thread")]
async fn apply_without_yes_on_a_non_terminal_refuses() {
    let a = Instance::new().await;
    configure(&a).await;
    let out = a.run(&["tenant", "export", "default", "-o", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let mut doc = yaml(&a.path("doc.yaml"));
    doc["roles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "auditor", "permissions": ["docs:read"]}));
    write_yaml(&a.path("doc.yaml"), &doc);

    let out = a.run(&["tenant", "apply", "-f", "doc.yaml"], &[]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("--yes"), "{}", text(&out));
    // The plan was shown, nothing was applied.
    assert!(text(&out).contains("+ role auditor"), "{}", text(&out));
    let tenant = a.tenant("default").await;
    assert!(
        a.storage
            .roles()
            .get_by_name(tenant.id, "auditor")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deletions_need_prune() {
    let a = Instance::new().await;
    configure(&a).await;
    let out = a.run(&["tenant", "export", "default", "-o", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let mut doc = yaml(&a.path("doc.yaml"));
    doc["roles"] = json!([]);
    write_yaml(&a.path("doc.yaml"), &doc);
    let tenant = a.tenant("default").await;

    let out = a.run(&["tenant", "apply", "-f", "doc.yaml", "--yes"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("- role editor (prune only)"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).contains("Nothing to apply without --prune."),
        "{}",
        text(&out)
    );
    assert!(
        a.storage
            .roles()
            .get_by_name(tenant.id, "editor")
            .await
            .unwrap()
            .is_some()
    );

    let out = a.run(
        &["tenant", "apply", "-f", "doc.yaml", "--yes", "--prune"],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("1 deleted"), "{}", text(&out));
    assert!(
        a.storage
            .roles()
            .get_by_name(tenant.id, "editor")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_documents_are_reported_by_path() {
    let a = Instance::new().await;
    configure(&a).await;
    let out = a.run(&["tenant", "export", "default", "-o", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let mut doc = yaml(&a.path("doc.yaml"));
    doc["clients"][0]["redirect_uris"] = json!(["http://evil.example.test/cb"]);
    doc["roles"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "auditor"}));
    doc["webhooks"][0]["secret"] = json!({"env": "ANVILID_TEST_UNSET_SECRET"});
    write_yaml(&a.path("doc.yaml"), &doc);
    // An unset reference fails before anything is opened.
    let out = a.run(&["tenant", "apply", "-f", "doc.yaml", "--yes"], &[]);
    assert!(!out.status.success());
    assert!(text(&out).contains("webhooks[0].secret"), "{}", text(&out));

    doc["webhooks"][0]["secret"] = json!({"configured": true});
    write_yaml(&a.path("doc.yaml"), &doc);
    let out = a.run(&["tenant", "apply", "-f", "doc.yaml", "--yes"], &[]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("clients[0].redirect_uris[0]"),
        "{}",
        text(&out)
    );
    let tenant = a.tenant("default").await;
    assert!(
        a.storage
            .roles()
            .get_by_name(tenant.id, "auditor")
            .await
            .unwrap()
            .is_none()
    );
}

/// The 1.0 client fields and tenant PAR/headless settings round-trip through YAML apply and
/// export; the client policy and origin rules refuse a document by path and change nothing.
#[tokio::test(flavor = "multi_thread")]
async fn yaml_v10_fields_round_trip_and_refusals() {
    let a = Instance::new().await;
    let client_id = configure(&a).await;
    let out = a.run(&["tenant", "export", "default", "-o", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let mut doc = yaml(&a.path("doc.yaml"));
    // Defaults are omitted from the export.
    for key in [
        "require_pushed_authorization_requests",
        "client_kind",
        "headless_native",
    ] {
        assert!(doc["clients"][0].get(key).is_none(), "{key}");
    }
    assert!(doc["tenant"]["settings"].get("par").is_none());
    assert!(doc["tenant"]["settings"].get("headless").is_none());

    doc["clients"][0]["require_pushed_authorization_requests"] = json!(true);
    doc["clients"][0]["client_kind"] = json!("agent");
    doc["clients"].as_array_mut().unwrap().push(json!({
        "client_id": "native-app",
        "name": "Native app",
        "client_type": "public",
        "application_type": "native",
        "auth_method": "none",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "consent_mode": "skip_first_party",
        "headless_native": true,
    }));
    doc["tenant"]["settings"]["par"] = json!({"require_pushed_authorization_requests": true});
    doc["tenant"]["settings"]["headless"] =
        json!({"allowed_origins": ["https://spa.example.test"]});
    write_yaml(&a.path("doc.yaml"), &doc);

    let out = a.run(&["tenant", "plan", "-f", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let plan = text(&out);
    for shown in [
        "client_kind",
        "require_pushed_authorization_requests",
        "settings.par",
        "settings.headless",
        "+ client native-app",
    ] {
        assert!(plan.contains(shown), "plan misses {shown}: {plan}");
    }

    let out = a.run(&["tenant", "apply", "-f", "doc.yaml", "--yes"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let tenant = a.tenant("default").await;
    assert!(tenant.settings.par.require_pushed_authorization_requests);
    assert_eq!(
        tenant.settings.headless.allowed_origins,
        ["https://spa.example.test"]
    );
    let billing = a
        .storage
        .clients()
        .get(tenant.id, &client_id)
        .await
        .unwrap()
        .unwrap();
    assert!(billing.require_pushed_authorization_requests);
    assert_eq!(billing.client_kind, anvil_core::model::ClientKind::Agent);
    let native = a
        .storage
        .clients()
        .get(tenant.id, "native-app")
        .await
        .unwrap()
        .unwrap();
    assert!(native.headless_native);

    // The export carries every value, and re-applying it changes nothing.
    let out = a.run(&["tenant", "export", "default", "-o", "export.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let exported = yaml(&a.path("export.yaml"));
    // The export sorts clients by client_id; the billing client's id is generated, so find it.
    let bi = exported["clients"]
        .as_array()
        .unwrap()
        .iter()
        .position(|c| c["client_id"] == client_id.as_str())
        .expect("billing client exported");
    assert_eq!(exported["clients"][bi]["client_kind"], "agent");
    assert_eq!(
        exported["clients"][bi]["require_pushed_authorization_requests"],
        true
    );
    let native = exported["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["client_id"] == "native-app")
        .expect("native-app exported");
    assert_eq!(native["headless_native"], true);
    assert_eq!(
        exported["tenant"]["settings"]["par"]["require_pushed_authorization_requests"],
        true
    );
    assert_eq!(
        exported["tenant"]["settings"]["headless"]["allowed_origins"],
        json!(["https://spa.example.test"])
    );
    let out = a.run(&["tenant", "apply", "-f", "export.yaml", "--yes"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("No changes."), "{}", text(&out));

    // An agent that skips consent, a wildcard origin and a path origin are refused by path.
    let mut bad = exported.clone();
    bad["clients"][bi]["consent_mode"] = json!("skip_first_party");
    bad["tenant"]["settings"]["headless"]["allowed_origins"] =
        json!(["https://*.example.test", "https://a.example.test/path"]);
    write_yaml(&a.path("bad.yaml"), &bad);
    let out = a.run(&["tenant", "apply", "-f", "bad.yaml", "--yes"], &[]);
    assert!(!out.status.success(), "{}", text(&out));
    let printed = text(&out);
    for path in [
        format!("clients[{bi}].consent_mode"),
        "tenant.settings.headless.allowed_origins[0]".to_owned(),
        "tenant.settings.headless.allowed_origins[1]".to_owned(),
    ] {
        assert!(printed.contains(&path), "{path}: {printed}");
    }
    let tenant = a.tenant("default").await;
    assert_eq!(
        tenant.settings.headless.allowed_origins,
        ["https://spa.example.test"]
    );
    let billing = a
        .storage
        .clients()
        .get(tenant.id, &client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        billing.consent_mode,
        anvil_core::model::ConsentMode::Required
    );
}

/// Org-owned objects (ORG-02, Pitfall 8): an org with an org-owned role named `editor` (the same
/// name as the tenant role of [`configure`]), an org connection `acme-sso` with an identity link,
/// and a member holding the org role. Written through storage as the organization services do.
async fn seed_org(
    a: &Instance,
    tenant: &Tenant,
) -> (
    anvil_core::model::OrgId,
    anvil_core::model::UserId,
    anvil_core::model::RoleId,
    anvil_core::model::ConnectionId,
) {
    use anvil_core::model::{
        ConnectionId, IdentityLinkId, NewConnection, NewIdentityLink, NewMembership,
        NewOrganization, NewRole, NewUser, OrgId, RoleId, StandardClaims, UserId, UserStatus,
    };
    use anvil_core::ports::Clock as _;
    let now = SystemClock.now();
    let org = a
        .storage
        .organizations()
        .create(
            tenant.id,
            &NewOrganization {
                id: OrgId::new_v7(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                mfa_policy: None,
                settings: Default::default(),
                metadata: json!({}),
                created_at: now,
            },
        )
        .await
        .expect("org");
    let role = a
        .storage
        .roles()
        .create(
            tenant.id,
            &NewRole {
                id: RoleId::new_v7(),
                org_id: Some(org.id),
                name: "editor".into(),
                description: "Org-owned".into(),
                permissions: vec!["org:members:read".into()],
                created_at: now,
            },
        )
        .await
        .expect("org role");
    let connection = a
        .storage
        .connections()
        .create(
            tenant.id,
            &NewConnection {
                id: ConnectionId::new_v7(),
                org_id: Some(org.id),
                slug: "acme-sso".into(),
                display_name: "Acme SSO".into(),
                enabled: true,
                config: serde_json::from_value(
                    json!({"type": "social", "provider": "google", "client_id": "acme-client"}),
                )
                .expect("social config"),
                secret_enc: None,
                trust_email_verified: false,
                created_at: now,
            },
        )
        .await
        .expect("org connection");
    let user = a
        .storage
        .users()
        .create(
            tenant.id,
            &NewUser {
                id: UserId::new_v7(),
                email: "member@acme.example.test".into(),
                email_verified: true,
                username: None,
                claims: StandardClaims::default(),
                status: UserStatus::Active,
                created_at: now,
            },
            None,
            None,
            None,
        )
        .await
        .expect("user");
    assert_eq!(
        a.storage
            .organizations()
            .add_member(
                tenant.id,
                &NewMembership {
                    org_id: org.id,
                    user_id: user.id,
                    role_ids: vec![role.id],
                    created_at: now,
                },
            )
            .await
            .expect("membership"),
        anvil_core::ports::AddMemberOutcome::Added
    );
    a.storage
        .connections()
        .create_link(
            tenant.id,
            &NewIdentityLink {
                id: IdentityLinkId::new_v7(),
                user_id: user.id,
                connection_id: connection.id,
                subject: "acme-user-1".into(),
                email_at_link: None,
                metadata: serde_json::Map::new(),
                created_at: now,
            },
        )
        .await
        .expect("identity link");
    (org.id, user.id, role.id, connection.id)
}

#[tokio::test(flavor = "multi_thread")]
async fn tenant_config_prune_keeps_org_objects() {
    let a = Instance::new().await;
    configure(&a).await;
    let tenant = a.tenant("default").await;
    let (org, user, role, connection) = seed_org(&a, &tenant).await;

    // The export never contains the org's objects.
    let out = a.run(&["tenant", "export", "default", "-o", "doc.yaml"], &[]);
    assert!(out.status.success(), "{}", text(&out));
    let raw = std::fs::read_to_string(a.path("doc.yaml")).expect("read yaml");
    assert!(!raw.contains("acme-sso"), "{raw}");
    assert!(!raw.contains("Org-owned"), "{raw}");

    // A document without any role or connection, applied with --prune, deletes the tenant's
    // role `editor` and connection `google` only.
    let mut doc = yaml(&a.path("doc.yaml"));
    doc["roles"] = json!([]);
    doc["connections"] = json!([]);
    write_yaml(&a.path("doc.yaml"), &doc);
    let out = a.run(
        &["tenant", "apply", "-f", "doc.yaml", "--yes", "--prune"],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    let shown = text(&out);
    assert!(shown.contains("- role editor (prune only)"), "{shown}");
    assert!(
        shown.contains("- connection google (prune only)"),
        "{shown}"
    );
    assert!(!shown.contains("acme-sso"), "{shown}");
    assert!(shown.contains("2 deleted"), "{shown}");
    assert!(
        a.storage
            .roles()
            .get_by_name(tenant.id, "editor")
            .await
            .unwrap()
            .is_none(),
        "tenant role pruned"
    );
    assert!(
        a.storage
            .connections()
            .get_by_slug(tenant.id, "google")
            .await
            .unwrap()
            .is_none(),
        "tenant connection pruned"
    );

    // The org role, connection, identity link, membership and org assignment are intact.
    let org_roles = a
        .storage
        .roles()
        .list_org_roles(tenant.id, org)
        .await
        .unwrap();
    assert_eq!(org_roles.iter().map(|r| r.id).collect::<Vec<_>>(), [role]);
    let org_conns = a
        .storage
        .connections()
        .list_for_org(tenant.id, org)
        .await
        .unwrap();
    assert_eq!(
        org_conns.iter().map(|c| c.id).collect::<Vec<_>>(),
        [connection]
    );
    assert!(
        a.storage
            .connections()
            .has_links(tenant.id, connection)
            .await
            .unwrap()
    );
    assert!(
        a.storage
            .organizations()
            .is_member(tenant.id, org, user)
            .await
            .unwrap()
    );
    let held = a
        .storage
        .roles()
        .roles_for_user_in_org(tenant.id, user, org)
        .await
        .unwrap();
    assert!(held.iter().any(|r| r.id == role), "{held:?}");

    // Re-applying the same document is a no-op (the org objects never show up as deletes).
    let out = a.run(
        &["tenant", "apply", "-f", "doc.yaml", "--yes", "--prune"],
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("(prune only)"), "{}", text(&out));
}
