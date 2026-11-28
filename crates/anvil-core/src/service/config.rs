//! Declarative tenant configuration: plan/diff (05-10), export, validation and apply (05-20)
//! (ADM-06, ADM-07).
//!
//! [`plan`] is pure: it compares the current document (as exported) with the desired one and
//! lists creates, updates and deletes by natural key. Identical documents give an empty plan,
//! which is what makes `apply` idempotent.
//!
//! - Natural keys only: tenant slug, `client_id`, connection slug, branding `client_id`
//!   (`(tenant)` for tenant-wide branding), role name, attribute name, template kind, `smtp`,
//!   webhook name.
//! - `deletes` lists objects present only in the current document. They are **prune-only**:
//!   apply performs them only when pruning was requested, and [`render`] labels them so.
//! - Secrets are never compared or printed by value. A secret field changes when its
//!   configured state changes, or when the desired document carries an inline value that the
//!   caller-supplied `secrets_equal` reports as different from the stored secret. An omitted
//!   secret (`None`) keeps the current one. Secret field diffs carry no values.
//! - Dynamic and CIMD clients are runtime state, not configuration: [`plan_excluding`] drops
//!   them from both sides.
//! - Organization-owned objects (`org_id = Some`) appear only under `organizations[]`: the
//!   tenant sections ([`StoredConfig::tenant_connections`], [`StoredConfig::tenant_roles`]) never
//!   contain them, so tenant-section prune never deletes them. An absent `organizations` key
//!   (rc.3 documents) plans nothing for organizations, even with prune. A listed organization is
//!   created or updated, never deleted; with prune, its roles, connections, domain claims and
//!   branding missing from its entry are deleted. Members, invitations, identity links, org role
//!   assignments and domain verification are never part of the document.
//! - Logos compare by SHA-256 (inline data is hashed first). An absent `logo` keeps the stored
//!   logo; `null` clears it.
//!
//! [`ConfigService`] exports a tenant ([`StoredConfig::document`]) and applies a document:
//!
//! 1. [`validate_document`] runs the services' own validators over the whole document and
//!    collects every problem by path (`clients[2].redirect_uris[0]`); then the document is
//!    checked against the stored state (fixed client fields, secrets that must be provided,
//!    SMTP) and, for the system tenant, the role guards run for the whole batch (escalation and
//!    last administrator). Any problem: nothing is written.
//! 2. [`normalize_document`] brings the document into the form the services store, so that a
//!    re-applied document plans empty.
//! 3. The plan is applied resource by resource through the owning services (tenant settings,
//!    roles, attributes, connections, organizations with their roles, connections, domain
//!    claims, default roles and branding, clients, branding, email templates and SMTP, webhooks),
//!    which validate and audit each write as usual. Deletes run only with `prune`. Roles go
//!    through [`RoleService`] only, so its last-administrator and escalation guards hold for
//!    every change. Finally `tenant_config_applied` is recorded with the counts.
//!
//! Inline secrets equal to the stored ones are no change: client secrets are compared by hash,
//! sealed secrets are opened with the KEK, both in constant time.
//!
//! **Partial failure and convergence:** the writes are not one transaction. If a write fails
//! after validation (a storage error, a concurrent change such as a name taken in the meantime),
//! the writes already made stay (each audited by its service), the error is returned and
//! `tenant_config_applied` is not recorded. Applying the same document again plans against the
//! new state and converges.
//!
//! The server never reads environment variables or files for a document: secret references
//! (`{env: …}`, `{file: …}`) are resolved by the CLI on the operator's machine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{b64std_decode, ct_eq, secret_hash, sha256};
use anvil_jose::webhook::parse_webhook_secret;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::CoreError;
use crate::model::{
    ApplicationType, AttributeDefinition, AuditAction, AuditActor, AuditDetails, AuditOutcome,
    Branding, BrandingScope, BrandingSection, CimdPolicy, Client, ClientSection, ClientSource,
    ConfigChange, ConfigKind, ConfigObjectKind, ConfigPlan, Connection, ConnectionSection,
    DcrPolicy, EmailKind, EmailTemplate, EmailTemplateSection, FieldDiff, LogoInput,
    OrgBrandingSection, OrgDomain, OrgDomainSection, OrgDomainStatus, OrgId, OrgSettingsSection,
    Organization, OrganizationSection, PageRequest, RequestContext, Role, RoleId, RoleSection,
    RoleUpdate, SYSTEM_TENANT_SLUG, Scope, SecretInput, SmtpSection, SmtpSettings, SmtpTls,
    TENANT_CONFIG_VERSION, Tenant, TenantConfigDocument, TenantId, TenantSection, TenantSettings,
    WebhookEndpoint, WebhookEndpointUpdate, WebhookSection, normalize_permissions,
    validate_org_slug, validate_role_name,
};
use crate::policy::branding::{LogoError, MAX_LOGO_BYTES, sniff_logo};
use crate::policy::claims_mapping::validate_mapping;
use crate::policy::home_realm::normalize_domain;
use crate::ports::{AttributeSchemaCheck, EmailTemplateCheck, Storage};
use crate::service::admin_scope::ADMIN_WRITE;
use crate::service::attribute::{AttributeService, check_definition};
use crate::service::audit::AuditService;
use crate::service::bootstrap::CONSOLE_CLIENT_ID;
use crate::service::branding::{
    BrandingInput, BrandingService, is_sha256_hex, validate_input as validate_branding,
};
use crate::service::client::{
    ClientInput, ClientOptions, ClientOptionsPatch, ClientPatch, ClientPolicyView, ClientService,
    RedirectValidator, check_admin_scopes, check_org_policy, uses_secret, validate_client,
    validate_client_home_uri, validate_client_id, validate_client_options, validate_client_phase4,
    validate_client_policy, validate_client_secret,
};
use crate::service::connection::{
    ConnectionOwner, ConnectionPatch, ConnectionService, NewConnectionInput, validate_config,
    validate_config_for, validate_connection_slug, validate_secret as validate_connection_secret,
};
use crate::service::mail_settings::{
    MAX_SMTP_PASSWORD_LEN, MailSettingsService, SmtpInput, TemplateInput, plan_smtp, plan_template,
    smtp_connection,
};
use crate::service::org_domain::{DomainPatch, OrgDomainService};
use crate::service::organization::{
    MAX_DEFAULT_ROLES, OrgActor, OrgInput, OrgPatch, OrgService, refuse_admin_permissions,
    validate_display_name as validate_org_display_name, validate_metadata,
};
use crate::service::role::{
    RoleInput, RoleService, check_escalation, guard_roles_losing_admin, validate_description,
};
use crate::service::tenant::{
    NewTenantInput, TenantPatch, TenantService, headless_origin_issues, normalize_signing_algs,
    registration_settings_issues, validate_display_name, validate_host, validate_locale_tag,
    validate_new_slug, validate_phase4_settings, validate_slug,
};
use crate::service::webhook::{
    NewWebhookInput, WebhookService, WebhookUrlCheck, signing_keys, validate_webhook_events,
    validate_webhook_name, validate_webhook_url,
};

/// Key of tenant-wide branding (branding without a `client_id`).
pub const TENANT_BRANDING_KEY: &str = "(tenant)";

/// Key of the single SMTP section.
pub const SMTP_KEY: &str = "smtp";

/// The secret field `secrets_equal` is asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretRef<'a> {
    pub kind: ConfigObjectKind,
    /// The object's natural key.
    pub key: &'a str,
    /// `secret` (clients, connections, webhooks) or `password` (SMTP).
    pub field: &'static str,
}

/// One object reduced to comparable JSON (secret fields removed) plus its secret fields.
struct Item<'a> {
    value: Value,
    secrets: Vec<(&'static str, Option<&'a SecretInput>)>,
}

fn item<'a, T: Serialize>(
    t: &T,
    secrets: Vec<(&'static str, Option<&'a SecretInput>)>,
) -> Item<'a> {
    // Serializing these plain document structs cannot fail; an error would only lose the field
    // comparison, never a secret.
    let mut value = serde_json::to_value(t).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut value {
        for (field, _) in &secrets {
            m.remove(*field);
        }
    }
    Item { value, secrets }
}

fn field_diffs(prefix: &str, before: &Value, after: &Value, out: &mut Vec<FieldDiff>) {
    if let (Value::Object(b), Value::Object(a)) = (before, after) {
        let mut keys: Vec<&String> = b.keys().chain(a.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match (b.get(k), a.get(k)) {
                (Some(bv), Some(av)) => field_diffs(&path, bv, av, out),
                (bv, av) => out.push(FieldDiff {
                    field: path,
                    before: bv.cloned(),
                    after: av.cloned(),
                }),
            }
        }
    } else if before != after {
        out.push(FieldDiff {
            field: prefix.to_owned(),
            before: Some(before.clone()),
            after: Some(after.clone()),
        });
    }
}

fn configured(s: Option<&SecretInput>) -> bool {
    s.is_some_and(SecretInput::is_configured)
}

fn secret_changes(
    r: &SecretRef<'_>,
    current: Option<&SecretInput>,
    desired: Option<&SecretInput>,
    secrets_equal: &dyn Fn(&SecretRef<'_>, &SecretInput) -> bool,
) -> bool {
    match desired {
        None => false,
        Some(SecretInput::Configured { configured: want }) => *want != configured(current),
        Some(inline @ SecretInput::Inline { .. }) => {
            !configured(current) || !secrets_equal(r, inline)
        }
    }
}

struct Differ<'p, 'f> {
    plan: &'p mut ConfigPlan,
    secrets_equal: &'f dyn Fn(&SecretRef<'_>, &SecretInput) -> bool,
}

impl Differ<'_, '_> {
    fn section(
        &mut self,
        kind: ConfigObjectKind,
        current: BTreeMap<String, Item<'_>>,
        mut desired: BTreeMap<String, Item<'_>>,
    ) {
        for (key, cur) in current {
            let Some(des) = desired.remove(&key) else {
                self.plan.deletes.push(ConfigChange {
                    kind,
                    key,
                    fields: Vec::new(),
                });
                continue;
            };
            let mut fields = Vec::new();
            field_diffs("", &cur.value, &des.value, &mut fields);
            for (field, d) in &des.secrets {
                let c = cur
                    .secrets
                    .iter()
                    .find(|(f, _)| f == field)
                    .and_then(|(_, s)| *s);
                let r = SecretRef {
                    kind,
                    key: &key,
                    field,
                };
                if secret_changes(&r, c, *d, self.secrets_equal) {
                    fields.push(FieldDiff {
                        field: (*field).to_owned(),
                        before: None,
                        after: None,
                    });
                }
            }
            if !fields.is_empty() {
                self.plan.updates.push(ConfigChange { kind, key, fields });
            }
        }
        for key in desired.into_keys() {
            self.plan.creates.push(ConfigChange {
                kind,
                key,
                fields: Vec::new(),
            });
        }
    }
}

fn keyed<'a, T, I>(
    items: I,
    key: impl Fn(&T) -> String,
    f: impl Fn(&'a T) -> Item<'a>,
) -> BTreeMap<String, Item<'a>>
where
    T: 'a,
    I: IntoIterator<Item = &'a T>,
{
    items.into_iter().map(|t| (key(t), f(t))).collect()
}

fn sections<'a>(
    doc: &'a TenantConfigDocument,
    is_runtime_client: &dyn Fn(&str) -> bool,
) -> Vec<(ConfigObjectKind, BTreeMap<String, Item<'a>>)> {
    use ConfigObjectKind as K;
    vec![
        (
            K::Tenant,
            keyed([&doc.tenant], |t| t.slug.clone(), |t| item(t, vec![])),
        ),
        (
            K::Client,
            keyed(
                doc.clients
                    .iter()
                    .filter(|c| !is_runtime_client(&c.client_id)),
                |c| c.client_id.clone(),
                |c| item(c, vec![("secret", c.secret.as_ref())]),
            ),
        ),
        (
            K::Connection,
            keyed(
                &doc.connections,
                |c| c.slug.clone(),
                |c| item(c, vec![("secret", c.secret.as_ref())]),
            ),
        ),
        (
            K::Branding,
            keyed(
                &doc.branding,
                |b| {
                    b.client_id
                        .clone()
                        .unwrap_or_else(|| TENANT_BRANDING_KEY.to_owned())
                },
                |b| item(b, vec![]),
            ),
        ),
        (
            K::Role,
            keyed(&doc.roles, |r| r.name.clone(), |r| item(r, vec![])),
        ),
        (
            K::Attribute,
            keyed(&doc.attributes, |a| a.name.clone(), |a| item(a, vec![])),
        ),
        (
            K::EmailTemplate,
            keyed(
                &doc.email_templates,
                |t| t.kind.clone(),
                |t| item(t, vec![]),
            ),
        ),
        (
            K::Smtp,
            keyed(
                &doc.smtp,
                |_| SMTP_KEY.to_owned(),
                |s| item(s, vec![("password", s.password.as_ref())]),
            ),
        ),
        (
            K::Webhook,
            keyed(
                &doc.webhooks,
                |w| w.name.clone(),
                |w| item(w, vec![("secret", w.secret.as_ref())]),
            ),
        ),
    ]
}

/// Longest base64 text of a logo ([`MAX_LOGO_BYTES`] once decoded).
const MAX_LOGO_BASE64: usize = MAX_LOGO_BYTES.div_ceil(3) * 4;

/// The image types a logo may have (what [`sniff_logo`] recognises).
const LOGO_TYPES: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes and checks inline logo data (standard base64; ASCII whitespace such as YAML line
/// breaks is ignored) with the upload rules: PNG, JPEG or WebP by magic bytes, at most 256 KiB,
/// SVG refused. The size is checked before decoding. Returns the bytes and the content type.
pub fn decode_logo(data: &str) -> Result<(Vec<u8>, &'static str), String> {
    // Cheap bound first, then the exact one on the text without whitespace.
    if data.len() > MAX_LOGO_BASE64 * 2 {
        return Err(LogoError::TooLarge.to_string());
    }
    let compact: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() > MAX_LOGO_BASE64 {
        return Err(LogoError::TooLarge.to_string());
    }
    let bytes = b64std_decode(&compact)
        .map_err(|_| "logo data must be base64 (standard alphabet)".to_owned())?;
    let content_type = sniff_logo(&bytes).map_err(|e| e.to_string())?;
    Ok((bytes, content_type))
}

/// The lowercase hex SHA-256 of logo bytes (the stored key).
fn logo_hash(bytes: &[u8]) -> String {
    hex_lower(&sha256(bytes))
}

/// Inline logo data in a comparable item becomes `{sha256, content_type}`, the form the stored
/// side exports, so a re-applied image is no change. Invalid data is left alone (validation
/// reports it).
fn comparable_logo(value: &mut Value) {
    let Value::Object(m) = value else {
        return;
    };
    let Some(data) = m
        .get("logo")
        .and_then(|l| l.get("data"))
        .and_then(Value::as_str)
    else {
        return;
    };
    if let Ok((bytes, content_type)) = decode_logo(data) {
        m.insert(
            "logo".to_owned(),
            serde_json::json!({"sha256": logo_hash(&bytes), "content_type": content_type}),
        );
    }
}

/// Logo rules of the plan: an absent desired `logo` is not compared (the stored logo is kept);
/// a desired `null` equals "no stored logo".
fn align_logos(cur: &mut BTreeMap<String, Item<'_>>, des: &mut BTreeMap<String, Item<'_>>) {
    for (key, d) in des.iter_mut() {
        comparable_logo(&mut d.value);
        let Some(c) = cur.get_mut(key) else {
            continue;
        };
        let (Value::Object(dm), Value::Object(cm)) = (&d.value, &mut c.value) else {
            continue;
        };
        match dm.get("logo") {
            None => {
                cm.remove("logo");
            }
            Some(Value::Null) if !cm.contains_key("logo") => {
                cm.insert("logo".to_owned(), Value::Null);
            }
            _ => {}
        }
    }
}

/// An organization without what it owns (compared on its own; roles, connections, domains and
/// branding are separate objects of the plan).
fn org_head(o: &OrganizationSection) -> Item<'_> {
    let mut value = serde_json::to_value(o).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut value {
        for k in ["roles", "connections", "domains", "branding"] {
            m.remove(k);
        }
    }
    Item {
        value,
        secrets: Vec::new(),
    }
}

/// The plan of the organizations the desired document lists (none when it has no
/// `organizations` key). An organization is never planned as a delete; the objects it owns are,
/// when its entry no longer lists them (prune only).
fn plan_organizations<'a>(
    differ: &mut Differ<'_, '_>,
    current: &'a TenantConfigDocument,
    desired: &'a TenantConfigDocument,
) {
    use ConfigObjectKind as K;
    let Some(wanted) = &desired.organizations else {
        return;
    };
    let stored = current.organizations.as_deref().unwrap_or_default();
    for d in wanted {
        let c = stored.iter().find(|c| c.slug == d.slug);
        let slug = d.slug.as_str();
        let nested = |name: &str| format!("{slug}/{name}");
        differ.section(
            K::Organization,
            c.map(|c| (c.slug.clone(), org_head(c)))
                .into_iter()
                .collect(),
            [(d.slug.clone(), org_head(d))].into_iter().collect(),
        );
        let roles = |o: Option<&'a OrganizationSection>| {
            keyed(
                o.map(|o| o.roles.as_slice()).unwrap_or_default(),
                |r| nested(&r.name),
                |r| item(r, vec![]),
            )
        };
        differ.section(K::OrgRole, roles(c), roles(Some(d)));
        let conns = |o: Option<&'a OrganizationSection>| {
            keyed(
                o.map(|o| o.connections.as_slice()).unwrap_or_default(),
                |x| nested(&x.slug),
                |x| item(x, vec![("secret", x.secret.as_ref())]),
            )
        };
        differ.section(K::OrgConnection, conns(c), conns(Some(d)));
        let domains = |o: Option<&'a OrganizationSection>| {
            keyed(
                o.map(|o| o.domains.as_slice()).unwrap_or_default(),
                |x| nested(&x.domain),
                |x| item(x, vec![]),
            )
        };
        differ.section(K::OrgDomain, domains(c), domains(Some(d)));
        let branding = |o: Option<&'a OrganizationSection>| {
            keyed(
                o.and_then(|o| o.branding.as_ref()),
                |_| slug.to_owned(),
                |b| item(b, vec![]),
            )
        };
        let (mut cb, mut db) = (branding(c), branding(Some(d)));
        align_logos(&mut cb, &mut db);
        differ.section(K::OrgBranding, cb, db);
    }
}

/// The plan turning `current` into `desired`. See the module docs for the rules. Assumes both
/// documents passed [`check_unique_keys`] (a duplicated key keeps only its last entry here).
pub fn plan(
    current: &TenantConfigDocument,
    desired: &TenantConfigDocument,
    secrets_equal: &dyn Fn(&SecretRef<'_>, &SecretInput) -> bool,
) -> ConfigPlan {
    plan_excluding(current, desired, secrets_equal, &|_| false)
}

/// [`plan`], ignoring the clients for which `is_runtime_client(client_id)` holds (dynamic and
/// CIMD clients) on both sides.
pub fn plan_excluding(
    current: &TenantConfigDocument,
    desired: &TenantConfigDocument,
    secrets_equal: &dyn Fn(&SecretRef<'_>, &SecretInput) -> bool,
    is_runtime_client: &dyn Fn(&str) -> bool,
) -> ConfigPlan {
    let mut plan = ConfigPlan::default();
    let mut differ = Differ {
        plan: &mut plan,
        secrets_equal,
    };
    let desired_sections = sections(desired, is_runtime_client);
    for ((kind, cur), (_, des)) in sections(current, is_runtime_client)
        .into_iter()
        .zip(desired_sections)
    {
        if kind == ConfigObjectKind::Tenant {
            // One tenant per document: a different slug is a field change, not a delete+create.
            let cur = cur.into_values().next();
            let des = des.into_values().next();
            if let (Some(c), Some(d)) = (cur, des) {
                let key = d
                    .value
                    .get("slug")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut c_map = BTreeMap::new();
                c_map.insert(key.clone(), c);
                let mut d_map = BTreeMap::new();
                d_map.insert(key, d);
                differ.section(kind, c_map, d_map);
            }
            continue;
        }
        let (mut cur, mut des) = (cur, des);
        if kind == ConfigObjectKind::Branding {
            align_logos(&mut cur, &mut des);
        }
        differ.section(kind, cur, des);
    }
    plan_organizations(&mut differ, current, desired);
    plan
}

/// Rejects a document in which two objects of the same kind share a natural key.
pub fn check_unique_keys(doc: &TenantConfigDocument) -> Result<(), CoreError> {
    use ConfigObjectKind as K;
    for kind in [
        K::Client,
        K::Connection,
        K::Branding,
        K::Role,
        K::Attribute,
        K::EmailTemplate,
        K::Webhook,
    ] {
        let keys: Vec<String> = match kind {
            ConfigObjectKind::Tenant
            | ConfigObjectKind::Smtp
            | ConfigObjectKind::Organization
            | ConfigObjectKind::OrgRole
            | ConfigObjectKind::OrgConnection
            | ConfigObjectKind::OrgDomain
            | ConfigObjectKind::OrgBranding => continue,
            ConfigObjectKind::Client => doc.clients.iter().map(|c| c.client_id.clone()).collect(),
            ConfigObjectKind::Connection => {
                doc.connections.iter().map(|c| c.slug.clone()).collect()
            }
            ConfigObjectKind::Branding => doc
                .branding
                .iter()
                .map(|b| {
                    b.client_id
                        .clone()
                        .unwrap_or_else(|| TENANT_BRANDING_KEY.to_owned())
                })
                .collect(),
            ConfigObjectKind::Role => doc.roles.iter().map(|r| r.name.clone()).collect(),
            ConfigObjectKind::Attribute => doc.attributes.iter().map(|a| a.name.clone()).collect(),
            ConfigObjectKind::EmailTemplate => {
                doc.email_templates.iter().map(|t| t.kind.clone()).collect()
            }
            ConfigObjectKind::Webhook => doc.webhooks.iter().map(|w| w.name.clone()).collect(),
        };
        let mut seen = std::collections::BTreeSet::new();
        for k in keys {
            if !seen.insert(k.clone()) {
                return Err(CoreError::Validation {
                    field: "document",
                    message: format!("duplicate {} {k:?}", kind_name(kind)),
                });
            }
        }
    }
    Ok(())
}

fn kind_name(kind: ConfigObjectKind) -> &'static str {
    match kind {
        ConfigObjectKind::Tenant => "tenant",
        ConfigObjectKind::Client => "client",
        ConfigObjectKind::Connection => "connection",
        ConfigObjectKind::Branding => "branding",
        ConfigObjectKind::Role => "role",
        ConfigObjectKind::Attribute => "attribute",
        ConfigObjectKind::EmailTemplate => "email template",
        ConfigObjectKind::Smtp => "smtp",
        ConfigObjectKind::Webhook => "webhook",
        ConfigObjectKind::Organization => "organization",
        ConfigObjectKind::OrgRole => "organization role",
        ConfigObjectKind::OrgConnection => "organization connection",
        ConfigObjectKind::OrgDomain => "organization domain",
        ConfigObjectKind::OrgBranding => "organization branding",
    }
}

fn show(v: Option<&Value>) -> String {
    v.map_or_else(|| "(unset)".to_owned(), Value::to_string)
}

/// A human-readable plan for the CLI and the console: `+` create, `~` update (one line per
/// field), `-` delete (prune only). Secret fields print as `(secret changed)`, never a value.
pub fn render(plan: &ConfigPlan) -> String {
    if plan.is_empty() {
        return "No changes.\n".to_owned();
    }
    let mut out = String::new();
    for c in &plan.creates {
        let _ = writeln!(out, "+ {} {}", kind_name(c.kind), c.key);
    }
    for c in &plan.updates {
        let _ = writeln!(out, "~ {} {}", kind_name(c.kind), c.key);
        for f in &c.fields {
            if f.before.is_none() && f.after.is_none() {
                let _ = writeln!(out, "    {}: (secret changed)", f.field);
            } else {
                let _ = writeln!(
                    out,
                    "    {}: {} -> {}",
                    f.field,
                    show(f.before.as_ref()),
                    show(f.after.as_ref())
                );
            }
        }
    }
    for c in &plan.deletes {
        let _ = writeln!(out, "- {} {} (prune only)", kind_name(c.kind), c.key);
    }
    let _ = writeln!(
        out,
        "{} to create, {} to update, {} to delete with prune.",
        plan.creates.len(),
        plan.updates.len(),
        plan.deletes.len()
    );
    out
}

// ---------------------------------------------------------------------------------------------
// Validation (pure)
// ---------------------------------------------------------------------------------------------

/// One problem of a document, by path (`clients[2].redirect_uris[0]`, `tenant.settings.dcr`).
/// Messages never carry secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigIssue {
    pub path: String,
    pub message: String,
}

/// The checks [`validate_document`] runs: the ones the services run when they write.
#[derive(Clone, Copy)]
pub struct Validators<'a> {
    pub redirect: RedirectValidator,
    pub attribute_check: &'a dyn AttributeSchemaCheck,
    pub url_check: &'a dyn WebhookUrlCheck,
    pub template_check: &'a dyn EmailTemplateCheck,
    /// Development mode: `headless.allowed_origins` may list localhost http origins.
    pub dev_mode: bool,
}

#[derive(Default)]
struct Issues(Vec<ConfigIssue>);

fn join(prefix: &str, field: &str) -> String {
    match (prefix.is_empty(), field.is_empty()) {
        (_, true) => prefix.to_owned(),
        (true, false) => field.to_owned(),
        (false, false) => format!("{prefix}.{field}"),
    }
}

fn message_of(e: CoreError) -> String {
    match e {
        CoreError::Validation { message, .. } | CoreError::InvalidTarget(message) => message,
        other => other.to_string(),
    }
}

impl Issues {
    fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(ConfigIssue {
            path: path.into(),
            message: message.into(),
        });
    }

    /// A service error at `prefix`: a validation error's field is appended to the path.
    fn core(&mut self, prefix: &str, e: CoreError) {
        match e {
            CoreError::Validation { field, message } => self.push(join(prefix, field), message),
            other => self.push(prefix, message_of(other)),
        }
    }

    fn check<T>(&mut self, prefix: &str, r: Result<T, CoreError>) {
        if let Err(e) = r {
            self.core(prefix, e);
        }
    }

    fn into_result(self) -> Result<(), Vec<ConfigIssue>> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

/// A redirect-URI list error of `validate_client` / `validate_client_phase4` pinned to the
/// failing entry when one entry is at fault (`clients[2].redirect_uris[0]`).
fn uri_error(
    issues: &mut Issues,
    prefix: &str,
    list_field: &str,
    uris: &[String],
    app: ApplicationType,
    validator: RedirectValidator,
    e: CoreError,
) {
    if matches!(&e, CoreError::Validation { field, .. } if *field == list_field) {
        for (j, uri) in uris.iter().enumerate() {
            if let Err(bad) = validator(uri, app) {
                issues.push(format!("{prefix}.{list_field}[{j}]"), message_of(bad));
                return;
            }
        }
    }
    issues.core(prefix, e);
}

fn client_input(c: &ClientSection) -> (ClientInput, ClientOptions) {
    (
        ClientInput {
            name: c.name.clone(),
            client_type: c.client_type,
            application_type: c.application_type,
            auth_method: c.auth_method,
            redirect_uris: c.redirect_uris.clone(),
            grant_types: c.grant_types.clone(),
            scopes: c.scopes.clone(),
            require_pkce: Some(c.require_pkce),
            jwks: c.jwks.clone(),
            jwks_uri: None,
        },
        ClientOptions {
            token_format: c.token_format,
            consent_mode: c.consent_mode,
            id_token_signed_response_alg: c.id_token_signed_response_alg.clone(),
            can_introspect: c.can_introspect,
            post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
            backchannel_logout_uri: c.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: c.backchannel_logout_session_required,
            allowed_resources: c.allowed_resources.clone(),
            mfa_policy: c.mfa_policy,
            organization: c.organization,
            require_pushed_authorization_requests: c.require_pushed_authorization_requests,
            client_kind: c.client_kind,
            headless_native: c.headless_native,
            client_uri: c.client_uri.clone(),
            initiate_login_uri: c.initiate_login_uri.clone(),
        },
    )
}

fn duplicates(issues: &mut Issues, section: &str, field: &str, keys: Vec<String>) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (i, k) in keys.into_iter().enumerate() {
        if let Some(first) = seen.get(&k) {
            issues.push(
                format!("{section}[{i}].{field}"),
                format!("duplicate {k:?} (also {section}[{first}])"),
            );
        } else {
            seen.insert(k, i);
        }
    }
}

fn validate_tenant_section(
    issues: &mut Issues,
    doc: &TenantConfigDocument,
    system: bool,
    dev_mode: bool,
) {
    let t = &doc.tenant;
    issues.check("tenant", validate_slug(&t.slug));
    issues.check("tenant", validate_display_name(&t.display_name));
    if let Some(host) = &t.host {
        issues.check("tenant", validate_host(host));
    }
    let s = &t.settings;
    if s.captcha.is_some() {
        issues.push(
            "tenant.settings.captcha",
            "CAPTCHA is configured through the admin API (its secret is not part of the document)",
        );
    }
    issues.check("tenant.settings", normalize_signing_algs(&s.signing_algs));
    issues.check("tenant.settings", validate_locale_tag(&s.default_locale));
    // The same DCR/CIMD rules as TenantService (system tenant disabled, hosts, scopes,
    // resources, cache bounds).
    for (field, message) in registration_settings_issues(system, &s.dcr, &s.cimd) {
        issues.push(join("tenant.settings", field), message);
    }
    if let Err(e) = validate_mapping(&s.claims, &doc.attributes) {
        issues.push("tenant.settings.claims", message_of(e));
    }
    // The same origin rules as TenantService.
    for (index, message) in headless_origin_issues(&s.headless, dev_mode) {
        let path = match index {
            Some(i) => format!("tenant.settings.headless.allowed_origins[{i}]"),
            None => "tenant.settings.headless.allowed_origins".to_owned(),
        };
        issues.push(path, message);
    }
}

fn validate_client_section(
    issues: &mut Issues,
    p: &str,
    c: &ClientSection,
    settings: &TenantSettings,
    system: bool,
    v: &Validators<'_>,
) {
    issues.check(p, validate_client_id(&c.client_id));
    if system && c.client_id == CONSOLE_CLIENT_ID {
        issues.push(
            format!("{p}.client_id"),
            "the console client is managed by the installation and is not part of the document",
        );
    }
    let (input, options) = client_input(c);
    if let Err(e) = validate_client(&input, v.redirect) {
        uri_error(
            issues,
            p,
            "redirect_uris",
            &c.redirect_uris,
            c.application_type,
            v.redirect,
            e,
        );
    }
    issues.check(p, check_admin_scopes(system, &input.scopes));
    issues.check(p, check_org_policy(system, options.organization));
    issues.check(p, validate_client_options(&input, &options, settings));
    // Document clients are static (administrator-managed).
    issues.check(
        p,
        validate_client_policy(
            &ClientPolicyView::of(&input, &options),
            ClientSource::Static,
        ),
    );
    if let Err(e) = validate_client_phase4(&input, &options, v.redirect) {
        uri_error(
            issues,
            p,
            "post_logout_redirect_uris",
            &c.post_logout_redirect_uris,
            c.application_type,
            v.redirect,
            e,
        );
    }
    // Document clients are static: the administrator rule (loopback http allowed).
    if let Some(uri) = &c.client_uri {
        issues.check(p, validate_client_home_uri("client_uri", uri, true));
    }
    if let Some(uri) = &c.initiate_login_uri {
        issues.check(p, validate_client_home_uri("initiate_login_uri", uri, true));
    }
    match (uses_secret(c.auth_method), &c.secret) {
        (true, Some(SecretInput::Configured { configured: false })) => issues.push(
            format!("{p}.secret"),
            "clients using client_secret_basic or client_secret_post always have a secret",
        ),
        (true, Some(SecretInput::Inline { value })) => {
            issues.check(p, validate_client_secret(value));
        }
        (false, Some(s)) if s.is_configured() => issues.push(
            format!("{p}.secret"),
            "only clients using client_secret_basic or client_secret_post have a secret",
        ),
        _ => {}
    }
}

fn validate_webhook_section(issues: &mut Issues, p: &str, w: &WebhookSection, v: &Validators<'_>) {
    issues.check(p, validate_webhook_name(&w.name));
    issues.check(p, validate_webhook_url(&w.url, v.url_check));
    issues.check(p, validate_webhook_events(&w.events));
    match &w.secret {
        Some(SecretInput::Configured { configured: false }) => issues.push(
            format!("{p}.secret"),
            "a webhook endpoint always has a signing secret",
        ),
        Some(SecretInput::Inline { value })
            if parse_webhook_secret(value.expose_secret()).is_err() =>
        {
            issues.push(
                format!("{p}.secret"),
                "must be whsec_ followed by base64 of 24 to 64 bytes",
            );
        }
        _ => {}
    }
}

/// A branding logo: inline data with the upload rules, a stored reference by shape (whether it
/// exists is checked against the tenant before anything is written).
fn validate_logo(issues: &mut Issues, path: &str, logo: Option<&Option<LogoInput>>) {
    match logo {
        Some(Some(LogoInput::Data { data })) => {
            if let Err(message) = decode_logo(data) {
                issues.push(path, message);
            }
        }
        Some(Some(LogoInput::Stored {
            sha256,
            content_type,
        })) => {
            if !is_sha256_hex(sha256) {
                issues.push(
                    format!("{path}.sha256"),
                    "must be a lowercase hex SHA-256 (64 characters)",
                );
            }
            if !LOGO_TYPES.contains(&content_type.as_str()) {
                issues.push(
                    format!("{path}.content_type"),
                    "must be image/png, image/jpeg or image/webp",
                );
            }
        }
        _ => {}
    }
}

/// Tokens and custom CSS of a branding section at `p`.
fn validate_branding_at(issues: &mut Issues, p: &str, input: &BrandingInput) {
    if let Err(e) = validate_branding(input) {
        let prefix = match &e {
            CoreError::Validation {
                field: "custom_css",
                ..
            } => p.to_owned(),
            _ => format!("{p}.tokens"),
        };
        issues.core(&prefix, e);
    }
}

/// The `organizations` section: the organization services' rules for each organization, its
/// roles (no `admin:*` permissions), connections (OIDC or SAML; one slug namespace with the
/// tenant's connections), domain claims and branding. Refused for the system tenant.
#[allow(
    clippy::too_many_lines,
    reason = "one pass over the parts of an organization entry"
)]
fn validate_organizations(issues: &mut Issues, doc: &TenantConfigDocument, system: bool) {
    let Some(orgs) = &doc.organizations else {
        return;
    };
    if system {
        issues.push(
            "organizations",
            "organizations do not exist in the system tenant",
        );
        return;
    }
    duplicates(
        issues,
        "organizations",
        "slug",
        orgs.iter().map(|o| o.slug.clone()).collect(),
    );
    // Tenant and organization connections share one slug namespace.
    let mut slugs: BTreeMap<&str, String> = BTreeMap::new();
    for (i, c) in doc.connections.iter().enumerate() {
        slugs
            .entry(c.slug.as_str())
            .or_insert_with(|| format!("connections[{i}]"));
    }
    for (i, o) in orgs.iter().enumerate() {
        let p = format!("organizations[{i}]");
        issues.check(&p, validate_org_slug(&o.slug));
        issues.check(&p, validate_org_display_name(&o.display_name));
        issues.check(&p, validate_metadata(&o.metadata));
        if o.settings.default_roles.len() > MAX_DEFAULT_ROLES {
            issues.push(
                format!("{p}.settings.default_roles"),
                format!("at most {MAX_DEFAULT_ROLES} roles"),
            );
        }
        duplicates(
            issues,
            &format!("{p}.roles"),
            "name",
            o.roles.iter().map(|r| r.name.clone()).collect(),
        );
        duplicates(
            issues,
            &format!("{p}.connections"),
            "slug",
            o.connections.iter().map(|c| c.slug.clone()).collect(),
        );
        duplicates(
            issues,
            &format!("{p}.domains"),
            "domain",
            o.domains
                .iter()
                .map(|d| normalize_domain(&d.domain).unwrap_or_else(|_| d.domain.clone()))
                .collect(),
        );
        for (j, r) in o.roles.iter().enumerate() {
            let rp = format!("{p}.roles[{j}]");
            issues.check(&rp, validate_role_name(&r.name));
            issues.check(&rp, validate_description(&r.description));
            match normalize_permissions(&r.permissions) {
                Ok(perms) => issues.check(&rp, refuse_admin_permissions(&perms)),
                Err(e) => issues.core(&rp, e),
            }
        }
        for (j, c) in o.connections.iter().enumerate() {
            let cp = format!("{p}.connections[{j}]");
            issues.check(&cp, validate_connection_slug(&c.slug));
            issues.check(&cp, validate_display_name(&c.display_name));
            issues.check(&cp, validate_config_for(&c.config, true));
            let saml = matches!(c.config, crate::model::ConnectionConfig::Saml(_));
            match &c.secret {
                Some(s) if saml && s.is_configured() => {
                    issues.push(format!("{cp}.secret"), "a SAML connection has no secret");
                }
                Some(SecretInput::Inline { value }) => {
                    issues.check(&cp, validate_connection_secret(c.config.kind(), value));
                }
                _ => {}
            }
            match slugs.get(c.slug.as_str()) {
                Some(first) => issues.push(
                    format!("{cp}.slug"),
                    format!(
                        "duplicate {:?} (also {first}); tenant and organization connections \
                         share one slug namespace",
                        c.slug
                    ),
                ),
                None => {
                    slugs.insert(c.slug.as_str(), cp.clone());
                }
            }
        }
        for (j, d) in o.domains.iter().enumerate() {
            let dp = format!("{p}.domains[{j}]");
            if let Err(e) = normalize_domain(&d.domain) {
                issues.push(format!("{dp}.domain"), message_of(e.into()));
            }
            match &d.connection {
                None if d.routing => issues.push(
                    format!("{dp}.connection"),
                    "routing needs a target connection of this organization",
                ),
                Some(slug) if !o.connections.iter().any(|c| &c.slug == slug) => issues.push(
                    format!("{dp}.connection"),
                    "names no connection of this organization's entry",
                ),
                _ => {}
            }
            if !d.allow_local_password && !d.routing {
                issues.push(
                    format!("{dp}.allow_local_password"),
                    "password sign-in can only be turned off for a routed domain",
                );
            }
        }
        if let Some(b) = &o.branding {
            let bp = format!("{p}.branding");
            validate_branding_at(
                issues,
                &bp,
                &BrandingInput {
                    tokens: b.tokens.clone(),
                    custom_css: b.custom_css.clone(),
                },
            );
            validate_logo(issues, &format!("{bp}.logo"), b.logo.as_ref());
        }
    }
}

/// Validates a whole document with the services' own rules, without storage: header, tenant
/// settings (CAPTCHA is not part of the document; DCR and CIMD must stay disabled for the system
/// tenant), unique natural keys, and every object. Collects every problem instead of stopping at
/// the first. Checks against the stored state (immutable client fields, secrets that must be
/// provided, SMTP) run in [`ConfigService::apply`] before anything is written.
pub fn validate_document(
    doc: &TenantConfigDocument,
    v: &Validators<'_>,
) -> Result<(), Vec<ConfigIssue>> {
    let mut issues = Issues::default();
    issues.check("", doc.check_header());
    let system = doc.tenant.slug == SYSTEM_TENANT_SLUG;
    validate_tenant_section(&mut issues, doc, system, v.dev_mode);

    duplicates(
        &mut issues,
        "clients",
        "client_id",
        doc.clients.iter().map(|c| c.client_id.clone()).collect(),
    );
    duplicates(
        &mut issues,
        "connections",
        "slug",
        doc.connections.iter().map(|c| c.slug.clone()).collect(),
    );
    duplicates(
        &mut issues,
        "branding",
        "client_id",
        doc.branding
            .iter()
            .map(|b| {
                b.client_id
                    .clone()
                    .unwrap_or_else(|| TENANT_BRANDING_KEY.to_owned())
            })
            .collect(),
    );
    duplicates(
        &mut issues,
        "roles",
        "name",
        doc.roles.iter().map(|r| r.name.clone()).collect(),
    );
    duplicates(
        &mut issues,
        "attributes",
        "name",
        doc.attributes.iter().map(|a| a.name.clone()).collect(),
    );
    duplicates(
        &mut issues,
        "email_templates",
        "kind",
        doc.email_templates.iter().map(|t| t.kind.clone()).collect(),
    );
    duplicates(
        &mut issues,
        "webhooks",
        "name",
        doc.webhooks.iter().map(|w| w.name.clone()).collect(),
    );

    for (i, c) in doc.clients.iter().enumerate() {
        validate_client_section(
            &mut issues,
            &format!("clients[{i}]"),
            c,
            &doc.tenant.settings,
            system,
            v,
        );
    }
    for (i, c) in doc.connections.iter().enumerate() {
        let p = format!("connections[{i}]");
        issues.check(&p, validate_connection_slug(&c.slug));
        issues.check(&p, validate_display_name(&c.display_name));
        issues.check(&format!("{p}.config"), validate_config(&c.config));
        if let Some(SecretInput::Inline { value }) = &c.secret {
            issues.check(&p, validate_connection_secret(c.config.kind(), value));
        }
    }
    for (i, b) in doc.branding.iter().enumerate() {
        let p = format!("branding[{i}]");
        if let Some(id) = &b.client_id
            && !doc.clients.iter().any(|c| &c.client_id == id)
        {
            issues.push(format!("{p}.client_id"), "names no client of this document");
        }
        let input = BrandingInput {
            tokens: b.tokens.clone(),
            custom_css: b.custom_css.clone(),
        };
        validate_branding_at(&mut issues, &p, &input);
        validate_logo(&mut issues, &format!("{p}.logo"), b.logo.as_ref());
    }
    for (i, r) in doc.roles.iter().enumerate() {
        let p = format!("roles[{i}]");
        issues.check(&p, validate_role_name(&r.name));
        issues.check(&p, validate_description(&r.description));
        issues.check(&p, normalize_permissions(&r.permissions));
    }
    for (i, a) in doc.attributes.iter().enumerate() {
        issues.check(
            &format!("attributes[{i}]"),
            check_definition(
                a,
                &doc.attributes,
                &doc.tenant.settings.claims,
                v.attribute_check,
            ),
        );
    }
    for (i, t) in doc.email_templates.iter().enumerate() {
        let p = format!("email_templates[{i}]");
        match EmailKind::parse(&t.kind) {
            None => issues.push(
                format!("{p}.kind"),
                format!(
                    "unknown template kind; one of {}",
                    EmailKind::ALL
                        .iter()
                        .map(EmailKind::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            Some(kind) => {
                let input = TemplateInput {
                    subject: t.subject.clone(),
                    body_html: t.body_html.clone(),
                    body_text: t.body_text.clone(),
                };
                if let Err(e) =
                    plan_template(v.template_check, kind, input, OffsetDateTime::UNIX_EPOCH)
                {
                    issues.core(&p, e.into());
                }
            }
        }
    }
    if let Some(s) = &doc.smtp {
        if SmtpTls::parse(&s.tls).is_none() {
            issues.push("smtp.tls", "must be starttls, implicit or none");
        }
        if let Some(SecretInput::Inline { value }) = &s.password {
            if s.username
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty)
            {
                issues.push("smtp.password", "a password needs a username");
            }
            if value.expose_secret().len() > MAX_SMTP_PASSWORD_LEN {
                issues.push("smtp.password", "password is too long");
            }
        }
    }
    for (i, w) in doc.webhooks.iter().enumerate() {
        validate_webhook_section(&mut issues, &format!("webhooks[{i}]"), w, v);
    }
    validate_organizations(&mut issues, doc, system);
    issues.into_result()
}

fn dedup(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

/// The document as the services store it (trimmed names, de-duplicated and sorted lists,
/// normalised signing algorithms and permissions, blank CSS dropped), so that the plan of a
/// re-applied document is empty. Call it on a document that passed [`validate_document`].
pub fn normalize_document(doc: &TenantConfigDocument) -> TenantConfigDocument {
    let mut d = doc.clone();
    d.tenant.display_name = d.tenant.display_name.trim().to_owned();
    d.tenant.host = d
        .tenant
        .host
        .as_deref()
        .map(|h| validate_host(h).unwrap_or_else(|_| h.to_owned()));
    if let Ok(algs) = normalize_signing_algs(&d.tenant.settings.signing_algs) {
        d.tenant.settings.signing_algs = algs;
    }
    for c in &mut d.clients {
        c.name = c.name.trim().to_owned();
        c.redirect_uris = dedup(&c.redirect_uris);
        c.grant_types.sort();
        c.grant_types.dedup();
        c.scopes = dedup(&c.scopes);
        c.post_logout_redirect_uris = dedup(&c.post_logout_redirect_uris);
        c.allowed_resources = dedup(&c.allowed_resources);
    }
    for c in &mut d.connections {
        c.display_name = c.display_name.trim().to_owned();
    }
    for b in &mut d.branding {
        b.custom_css = b.custom_css.take().filter(|c| !c.trim().is_empty());
    }
    for r in &mut d.roles {
        r.description = r.description.trim().to_owned();
        if let Ok(p) = normalize_permissions(&r.permissions) {
            r.permissions = p;
        }
    }
    if let Some(s) = &mut d.smtp {
        s.host = s.host.trim().to_ascii_lowercase();
        s.username = s
            .username
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_owned);
        s.from = s.from.trim().to_owned();
    }
    for w in &mut d.webhooks {
        if let Ok(e) = validate_webhook_events(&w.events) {
            w.events = e;
        }
    }
    for o in d.organizations.iter_mut().flatten() {
        o.display_name = o.display_name.trim().to_owned();
        o.settings.default_roles.sort();
        o.settings.default_roles.dedup();
        for r in &mut o.roles {
            r.description = r.description.trim().to_owned();
            if let Ok(p) = normalize_permissions(&r.permissions) {
                r.permissions = p;
            }
        }
        for c in &mut o.connections {
            c.display_name = c.display_name.trim().to_owned();
        }
        for dm in &mut o.domains {
            if let Ok(n) = normalize_domain(&dm.domain) {
                dm.domain = n;
            }
        }
        if let Some(b) = &mut o.branding {
            b.custom_css = b.custom_css.take().filter(|c| !c.trim().is_empty());
        }
    }
    d
}

// ---------------------------------------------------------------------------------------------
// Export (pure part)
// ---------------------------------------------------------------------------------------------

/// A tenant's stored configuration as the services return it.
#[derive(Debug, Clone)]
pub struct StoredConfig {
    pub tenant: Tenant,
    /// Every client of the tenant (static, dynamic and CIMD).
    pub clients: Vec<Client>,
    pub connections: Vec<Connection>,
    /// Branding records by client id (`None` = tenant-wide), of exported scopes only.
    pub branding: Vec<(Option<String>, Branding)>,
    pub roles: Vec<Role>,
    pub attributes: Vec<AttributeDefinition>,
    pub templates: Vec<EmailTemplate>,
    pub smtp: Option<SmtpSettings>,
    pub webhooks: Vec<WebhookEndpoint>,
    /// The tenant's organizations with their domain claims and branding (their roles and
    /// connections are in `roles` and `connections`, `org_id = Some`). Empty for the system
    /// tenant.
    pub orgs: Vec<StoredOrg>,
}

/// One stored organization as the export needs it.
#[derive(Debug, Clone)]
pub struct StoredOrg {
    pub org: Organization,
    pub domains: Vec<OrgDomain>,
    pub branding: Option<Branding>,
}

fn is_system(tenant: &Tenant) -> bool {
    tenant.slug == SYSTEM_TENANT_SLUG
}

/// Whether an object owned by `org_id` belongs to the document: tenant-level objects only.
/// The one filter for org-owned connections and roles (export, plan and prune).
fn is_document_managed(org_id: Option<OrgId>) -> bool {
    org_id.is_none()
}

impl StoredConfig {
    /// The tenant-level connections (organization connections are never part of the document).
    pub fn tenant_connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections
            .iter()
            .filter(|c| is_document_managed(c.org_id))
    }

    /// The tenant-level roles (org-owned roles are never part of the document).
    pub fn tenant_roles(&self) -> impl Iterator<Item = &Role> {
        self.roles.iter().filter(|r| is_document_managed(r.org_id))
    }

    /// The stored organization connection with `slug`, if any (slugs are unique per tenant
    /// across tenant and organization connections).
    fn org_connection(&self, slug: &str) -> Option<&Connection> {
        self.connections
            .iter()
            .find(|c| !is_document_managed(c.org_id) && c.slug == slug)
    }

    /// The stored organization with `slug`.
    fn org(&self, slug: &str) -> Option<&StoredOrg> {
        self.orgs.iter().find(|o| o.org.slug == slug)
    }

    /// The `organizations` entry of a stored organization: its roles, connections, domain
    /// claims (target by connection slug) and branding; default roles by name. Never members,
    /// invitations, links, assignments or verification state.
    fn org_section(&self, so: &StoredOrg) -> OrganizationSection {
        let id = so.org.id;
        let mut roles: Vec<RoleSection> = self
            .roles
            .iter()
            .filter(|r| r.org_id == Some(id))
            .map(role_section)
            .collect();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        let mut connections: Vec<ConnectionSection> = self
            .connections
            .iter()
            .filter(|c| c.org_id == Some(id))
            .map(connection_section)
            .collect();
        connections.sort_by(|a, b| a.slug.cmp(&b.slug));
        let mut domains: Vec<OrgDomainSection> = so
            .domains
            .iter()
            .map(|d| OrgDomainSection {
                domain: d.domain.clone(),
                connection: d.connection_id.and_then(|cid| {
                    self.connections
                        .iter()
                        .find(|c| c.id == cid)
                        .map(|c| c.slug.clone())
                }),
                routing: d.routing,
                allow_local_password: d.allow_local_password,
            })
            .collect();
        domains.sort_by(|a, b| a.domain.cmp(&b.domain));
        let mut default_roles: Vec<String> = so
            .org
            .settings
            .default_role_ids
            .iter()
            .filter_map(|rid| self.roles.iter().find(|r| r.id == *rid))
            .map(|r| r.name.clone())
            .collect();
        default_roles.sort();
        default_roles.dedup();
        OrganizationSection {
            slug: so.org.slug.clone(),
            display_name: so.org.display_name.clone(),
            mfa_policy: so.org.mfa_policy,
            metadata: so.org.metadata.clone(),
            settings: OrgSettingsSection { default_roles },
            roles,
            connections,
            domains,
            branding: so.branding.as_ref().map(|b| OrgBrandingSection {
                tokens: b.tokens.clone(),
                custom_css: b.custom_css.clone(),
                logo: exported_logo(b),
            }),
        }
    }
}

fn connection_section(c: &Connection) -> ConnectionSection {
    ConnectionSection {
        slug: c.slug.clone(),
        display_name: c.display_name.clone(),
        enabled: c.enabled,
        config: c.config.clone(),
        // SAML connections have no secret.
        secret: (c.kind() != crate::model::ConnectionKind::Saml).then(|| SecretInput::Configured {
            configured: c.secret_enc.is_some(),
        }),
        trust_email_verified: c.trust_email_verified,
    }
}

fn role_section(r: &Role) -> RoleSection {
    RoleSection {
        name: r.name.clone(),
        description: r.description.clone(),
        permissions: r.permissions.clone(),
    }
}

/// Whether a client belongs in the document: static clients only, and never the system tenant's
/// console client (owned by bootstrap reconciliation).
fn is_exported_client(tenant: &Tenant, c: &Client) -> bool {
    c.registration_source == ClientSource::Static
        && !(is_system(tenant) && c.client_id == CONSOLE_CLIENT_ID)
}

/// The exported logo of a branding record: `{sha256, content_type}`, or absent when none.
fn exported_logo(b: &Branding) -> Option<Option<LogoInput>> {
    match (&b.logo_sha256, &b.logo_type) {
        (Some(sha256), Some(content_type)) => Some(Some(LogoInput::Stored {
            sha256: sha256.clone(),
            content_type: content_type.clone(),
        })),
        _ => None,
    }
}

fn configured_secret(set: bool) -> Option<SecretInput> {
    Some(SecretInput::Configured { configured: set })
}

fn client_section(c: &Client) -> ClientSection {
    ClientSection {
        client_id: c.client_id.clone(),
        name: c.name.clone(),
        client_type: c.client_type,
        application_type: c.application_type,
        auth_method: c.auth_method,
        secret: if uses_secret(c.auth_method) {
            configured_secret(c.secret_hash.is_some())
        } else {
            None
        },
        jwks: c.jwks.clone(),
        redirect_uris: c.redirect_uris.clone(),
        grant_types: c.grant_types.clone(),
        scopes: c.scopes.clone(),
        require_pkce: c.require_pkce,
        token_format: c.token_format,
        consent_mode: c.consent_mode,
        id_token_signed_response_alg: c.id_token_signed_response_alg.clone(),
        can_introspect: c.can_introspect,
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: c.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: c.backchannel_logout_session_required,
        allowed_resources: c.allowed_resources.clone(),
        mfa_policy: c.mfa_policy,
        organization: c.organization,
        require_pushed_authorization_requests: c.require_pushed_authorization_requests,
        client_kind: c.client_kind,
        headless_native: c.headless_native,
        client_uri: c.client_uri.clone(),
        initiate_login_uri: c.initiate_login_uri.clone(),
    }
}

impl StoredConfig {
    /// The exported document: natural keys only, secrets as `{configured: bool}`, objects in a
    /// stable order (so two exports of equal state are equal).
    ///
    /// - CAPTCHA settings are left out (their secret cannot be exported; manage CAPTCHA through
    ///   the admin API).
    /// - The system tenant's DCR and CIMD policies are exported as `disabled`, the only value in
    ///   force there.
    /// - Dynamic and CIMD clients, the system console client and role assignments are runtime
    ///   state and never part of the document.
    pub fn document(&self) -> TenantConfigDocument {
        let t = &self.tenant;
        let mut settings = t.settings.clone();
        settings.captcha = None;
        if is_system(t) {
            settings.dcr.policy = DcrPolicy::Disabled;
            settings.cimd.policy = CimdPolicy::Disabled;
        }
        let mut clients: Vec<ClientSection> = self
            .clients
            .iter()
            .filter(|c| is_exported_client(t, c))
            .map(client_section)
            .collect();
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        let mut connections: Vec<ConnectionSection> =
            self.tenant_connections().map(connection_section).collect();
        connections.sort_by(|a, b| a.slug.cmp(&b.slug));
        let mut branding: Vec<BrandingSection> = self
            .branding
            .iter()
            .map(|(client_id, b)| BrandingSection {
                client_id: client_id.clone(),
                tokens: b.tokens.clone(),
                custom_css: b.custom_css.clone(),
                logo: exported_logo(b),
            })
            .collect();
        branding.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        let mut roles: Vec<RoleSection> = self.tenant_roles().map(role_section).collect();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        let mut attributes = self.attributes.clone();
        attributes.sort_by(|a, b| (a.position, &a.name).cmp(&(b.position, &b.name)));
        let mut email_templates: Vec<EmailTemplateSection> = self
            .templates
            .iter()
            .map(|e| EmailTemplateSection {
                kind: e.kind.as_str().to_owned(),
                subject: e.subject.clone(),
                body_html: e.body_html.clone(),
                body_text: e.body_text.clone(),
            })
            .collect();
        email_templates.sort_by(|a, b| a.kind.cmp(&b.kind));
        let smtp = self.smtp.as_ref().map(|s| SmtpSection {
            host: s.host.clone(),
            port: s.port,
            username: s.username.clone(),
            password: configured_secret(s.password_enc.is_some()),
            from: s.from.clone(),
            tls: s.tls.as_str().to_owned(),
        });
        let mut webhooks: Vec<WebhookSection> = self
            .webhooks
            .iter()
            .map(|w| WebhookSection {
                name: w.name.clone(),
                url: w.url.clone(),
                events: w.events.clone(),
                enabled: w.enabled,
                secret: configured_secret(true),
            })
            .collect();
        webhooks.sort_by(|a, b| a.name.cmp(&b.name));
        TenantConfigDocument {
            version: TENANT_CONFIG_VERSION,
            kind: ConfigKind::TenantConfig,
            tenant: TenantSection {
                slug: t.slug.clone(),
                display_name: t.display_name.clone(),
                host: t.host.clone(),
                settings,
            },
            clients,
            connections,
            branding,
            roles,
            attributes,
            email_templates,
            smtp,
            webhooks,
            organizations: self.organizations(),
        }
    }

    /// The `organizations` section: absent for the system tenant and for a tenant without
    /// organizations (so documents of tenants without organizations stay as before).
    fn organizations(&self) -> Option<Vec<OrganizationSection>> {
        if is_system(&self.tenant) || self.orgs.is_empty() {
            return None;
        }
        let mut orgs: Vec<OrganizationSection> =
            self.orgs.iter().map(|o| self.org_section(o)).collect();
        orgs.sort_by(|a, b| a.slug.cmp(&b.slug));
        Some(orgs)
    }

    /// Whether `client_id` is a client the document never manages (dynamic, CIMD, console).
    fn is_runtime_client(&self, client_id: &str) -> bool {
        (is_system(&self.tenant) && client_id == CONSOLE_CLIENT_ID)
            || self
                .clients
                .iter()
                .any(|c| c.client_id == client_id && !is_exported_client(&self.tenant, c))
    }
}

/// The settings the first tenant write stores: `email_otp` and `magic_link` stay as they are
/// until SMTP is available (the document's SMTP section is applied later; the final settings
/// write turns them on).
fn first_pass_settings(
    desired: &TenantSettings,
    current: Option<&TenantSettings>,
    smtp_now: bool,
) -> TenantSettings {
    let mut s = desired.clone();
    if !smtp_now {
        s.email_otp = desired.email_otp && current.is_some_and(|c| c.email_otp);
        s.magic_link = desired.magic_link && current.is_some_and(|c| c.magic_link);
    }
    s
}

/// Checks of the desired document against the stored state that `validate_document` cannot do.
fn check_against_stored(
    current: Option<&StoredConfig>,
    desired: &TenantConfigDocument,
    prune: bool,
    installation_smtp: bool,
    kek: &Kek,
) -> Vec<ConfigIssue> {
    let mut issues = Issues::default();
    let Some(cur) = current else {
        issues.check("tenant", validate_new_slug(&desired.tenant.slug));
        for (i, c) in desired.connections.iter().enumerate() {
            if matches!(c.secret, Some(SecretInput::Configured { configured: true })) {
                issues.push(
                    format!("connections[{i}].secret"),
                    "no secret is stored yet: provide it inline",
                );
            }
        }
        check_smtp(&mut issues, None, desired, None, kek);
        let smtp_at_end = installation_smtp || desired.smtp.is_some();
        issues.check(
            "tenant.settings",
            validate_phase4_settings(None, &desired.tenant.settings, smtp_at_end),
        );
        return issues.0;
    };
    for (i, c) in desired.clients.iter().enumerate() {
        let p = format!("clients[{i}]");
        let Some(stored) = cur.clients.iter().find(|s| s.client_id == c.client_id) else {
            continue;
        };
        if !is_exported_client(&cur.tenant, stored) {
            issues.push(
                format!("{p}.client_id"),
                "belongs to a dynamically registered or metadata-document client",
            );
            continue;
        }
        for (field, same) in [
            ("client_type", stored.client_type == c.client_type),
            (
                "application_type",
                stored.application_type == c.application_type,
            ),
            ("auth_method", stored.auth_method == c.auth_method),
        ] {
            if !same {
                issues.push(
                    format!("{p}.{field}"),
                    "is fixed when a client is created; remove the client (apply with prune) and \
                     add it again",
                );
            }
        }
    }
    for (i, c) in desired.connections.iter().enumerate() {
        let p = format!("connections[{i}]");
        if cur.org_connection(&c.slug).is_some() {
            issues.push(
                format!("{p}.slug"),
                "is used by an organization connection; organization connections are listed \
                 under their organization (organizations[].connections)",
            );
            continue;
        }
        let stored = cur.tenant_connections().find(|s| s.slug == c.slug);
        if let Some(s) = stored
            && s.kind() != c.config.kind()
        {
            issues.push(
                format!("{p}.config"),
                "the kind of a connection cannot change; remove it (apply with prune) and add a \
                 new one",
            );
        }
        if matches!(c.secret, Some(SecretInput::Configured { configured: true }))
            && stored.is_none_or(|s| s.secret_enc.is_none())
        {
            issues.push(
                format!("{p}.secret"),
                "no secret is stored yet: provide it inline",
            );
        }
    }
    check_smtp(
        &mut issues,
        Some(cur.tenant.id),
        desired,
        cur.smtp.as_ref(),
        kek,
    );
    let smtp_at_end = installation_smtp || desired.smtp.is_some() || (cur.smtp.is_some() && !prune);
    issues.check(
        "tenant.settings",
        validate_phase4_settings(
            Some(&cur.tenant.settings),
            &desired.tenant.settings,
            smtp_at_end,
        ),
    );
    issues.0
}

/// Checks of the `organizations` section against the stored state: connection slugs owned by
/// someone else (the tenant or another organization), kind changes, secrets that must be
/// provided, and default roles that name no role.
fn check_organizations(
    current: Option<&StoredConfig>,
    desired: &TenantConfigDocument,
    prune: bool,
) -> Vec<ConfigIssue> {
    let mut issues = Issues::default();
    let Some(orgs) = &desired.organizations else {
        return issues.0;
    };
    for (i, o) in orgs.iter().enumerate() {
        let p = format!("organizations[{i}]");
        let org_id = current.and_then(|c| c.org(&o.slug)).map(|s| s.org.id);
        for (j, c) in o.connections.iter().enumerate() {
            let cp = format!("{p}.connections[{j}]");
            let stored = current.and_then(|cur| cur.connections.iter().find(|s| s.slug == c.slug));
            if let Some(s) = stored {
                if s.org_id.is_none() {
                    issues.push(
                        format!("{cp}.slug"),
                        "is used by a tenant connection (tenant and organization connections \
                         share one slug namespace)",
                    );
                    continue;
                }
                if s.org_id != org_id {
                    issues.push(
                        format!("{cp}.slug"),
                        "is used by a connection of another organization",
                    );
                    continue;
                }
                if s.kind() != c.config.kind() {
                    issues.push(
                        format!("{cp}.config"),
                        "the kind of a connection cannot change; remove it (apply with prune) \
                         and add a new one",
                    );
                }
            }
            if matches!(c.secret, Some(SecretInput::Configured { configured: true }))
                && stored.is_none_or(|s| s.secret_enc.is_none())
            {
                issues.push(
                    format!("{cp}.secret"),
                    "no secret is stored yet: provide it inline",
                );
            }
        }
        for (k, name) in o.settings.default_roles.iter().enumerate() {
            let in_entry = o.roles.iter().any(|r| &r.name == name);
            let in_doc = desired.roles.iter().any(|r| &r.name == name);
            let stored_tenant_role =
                !prune && current.is_some_and(|c| c.tenant_roles().any(|r| &r.name == name));
            if !(in_entry || in_doc || stored_tenant_role) {
                issues.push(
                    format!("{p}.settings.default_roles[{k}]"),
                    "names no role of this organization or of the tenant",
                );
            }
        }
    }
    issues.0
}

/// A document cannot turn on routing (or turn off password sign-in) for a domain that is not
/// verified through DNS: for such a claim the routing settings stay as stored (a new claim:
/// routing off, password sign-in allowed) and are applied by an apply after verification. The
/// routing target is set either way.
fn defer_unverified_routing(desired: &mut TenantConfigDocument, current: Option<&StoredConfig>) {
    for o in desired.organizations.iter_mut().flatten() {
        let stored_org = current.and_then(|c| c.org(&o.slug));
        for d in &mut o.domains {
            let stored = stored_org.and_then(|so| so.domains.iter().find(|x| x.domain == d.domain));
            if stored.is_some_and(|x| x.status == OrgDomainStatus::Verified) {
                continue;
            }
            d.routing = stored.is_some_and(|x| x.routing);
            d.allow_local_password = stored.is_none_or(|x| x.allow_local_password);
        }
    }
}

/// The logo positions of a document with their paths.
fn logo_slots(doc: &TenantConfigDocument) -> Vec<(String, &LogoInput)> {
    let mut out = Vec::new();
    for (i, b) in doc.branding.iter().enumerate() {
        if let Some(Some(l)) = &b.logo {
            out.push((format!("branding[{i}].logo"), l));
        }
    }
    for (i, o) in doc.organizations.iter().flatten().enumerate() {
        if let Some(Some(l)) = o.branding.as_ref().and_then(|b| b.logo.as_ref()) {
            out.push((format!("organizations[{i}].branding.logo"), l));
        }
    }
    out
}

fn smtp_input(s: &SmtpSection) -> SmtpInput {
    SmtpInput {
        host: s.host.clone(),
        port: s.port,
        username: s.username.clone(),
        password: match &s.password {
            Some(SecretInput::Inline { value }) => Some(value.clone()),
            _ => None,
        },
        from: s.from.clone(),
        tls: SmtpTls::parse(&s.tls).unwrap_or(SmtpTls::Starttls),
    }
}

fn check_smtp(
    issues: &mut Issues,
    tenant: Option<TenantId>,
    desired: &TenantConfigDocument,
    stored: Option<&SmtpSettings>,
    kek: &Kek,
) {
    let Some(s) = &desired.smtp else {
        return;
    };
    let has_user = s
        .username
        .as_deref()
        .map(str::trim)
        .is_some_and(|u| !u.is_empty());
    let stored_password = stored.is_some_and(|c| c.password_enc.is_some());
    match &s.password {
        Some(SecretInput::Configured { configured: true }) if has_user && !stored_password => {
            issues.push(
                "smtp.password",
                "no password is stored yet: provide it inline",
            );
        }
        Some(SecretInput::Configured { configured: false }) if has_user && stored_password => {
            issues.push(
                "smtp.password",
                "a stored password cannot be cleared while a username is set; remove the \
                 username to send without authentication",
            );
        }
        _ => {}
    }
    // Same checks as MailSettingsService::put_smtp (the sealed result is discarded).
    let tenant = tenant.unwrap_or_else(TenantId::new_v7);
    if let Err(e) = plan_smtp(
        kek,
        tenant,
        smtp_input(s),
        stored,
        OffsetDateTime::UNIX_EPOCH,
    ) {
        issues.core("smtp", e);
    }
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// Why a document was not applied.
#[derive(Debug)]
pub enum ConfigError {
    /// The document (or its relation to the stored state) is invalid; nothing was changed.
    Invalid(Vec<ConfigIssue>),
    /// A service refused or failed (`LastAdministrator`, `InsufficientScope`, storage errors, a
    /// tenant that does not exist on export).
    Core(CoreError),
}

impl From<CoreError> for ConfigError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(issues) => {
                write!(f, "the document is invalid:")?;
                for i in issues {
                    write!(f, "\n  {}: {}", i.path, i.message)?;
                }
                Ok(())
            }
            Self::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A secret the server generated while applying (a client or webhook created without an inline
/// secret, or a client secret that had to be set). Shown to the operator once; never stored in
/// clear and never part of an export.
#[derive(Debug)]
pub struct GeneratedSecret {
    pub kind: ConfigObjectKind,
    pub key: String,
    pub field: &'static str,
    pub value: SecretString,
}

/// What [`ConfigService::apply`] did.
#[derive(Debug, Default)]
pub struct ApplyOutcome {
    /// The plan against the stored state before the apply (deletes are prune-only).
    pub plan: ConfigPlan,
    /// Whether changes were written (`false` for a dry run or an empty plan).
    pub applied: bool,
    /// Whether the plan's deletes were performed.
    pub pruned: bool,
    pub generated: Vec<GeneratedSecret>,
}

/// One apply request.
#[derive(Debug, Clone, Copy)]
pub struct ApplyRequest<'a> {
    /// The acting administrator (audit).
    pub actor: &'a AuditActor,
    /// The caller's scope: in the system tenant role changes must stay within it (escalation
    /// guard of [`RoleService`]).
    pub caller: &'a Scope,
    pub document: &'a TenantConfigDocument,
    /// Perform the plan's deletes.
    pub prune: bool,
    /// Validate and plan only.
    pub dry_run: bool,
    pub ctx: &'a RequestContext,
}

/// Export, plan and apply of a tenant's declarative configuration through the existing services
/// (every write is validated and audited by the service that owns it).
pub struct ConfigService {
    pub tenants: TenantService,
    pub clients: ClientService,
    pub connections: ConnectionService,
    pub branding: BrandingService,
    pub roles: RoleService,
    pub attributes: AttributeService,
    pub webhooks: WebhookService,
    pub mail: MailSettingsService,
    /// Organizations and their roles (as a tenant administrator).
    pub orgs: OrgService,
    /// Organization domain claims (never verified by a document; the TXT lookup is unused).
    pub domains: OrgDomainService,
    /// Whether the installation SMTP (`smtp_url`) is configured.
    pub installation_smtp: bool,
    /// Whether the server runs in development mode (`AppConfig::dev_mode`): headless origins
    /// may then be localhost http origins.
    pub dev_mode: bool,
}

fn top_fields(c: &ConfigChange) -> BTreeSet<&str> {
    c.fields
        .iter()
        .map(|f| f.field.split('.').next().unwrap_or_default())
        .collect()
}

fn of_kind(
    changes: &[ConfigChange],
    kind: ConfigObjectKind,
) -> impl Iterator<Item = &ConfigChange> {
    changes.iter().filter(move |c| c.kind == kind)
}

/// The changes of `kind` inside the organization `org` (keys `{org}/{name}`), with the name.
fn org_changes<'a>(
    changes: &'a [ConfigChange],
    kind: ConfigObjectKind,
    org: &'a str,
) -> impl Iterator<Item = (&'a ConfigChange, &'a str)> + 'a {
    changes
        .iter()
        .filter(move |c| c.kind == kind)
        .filter_map(move |c| {
            c.key
                .strip_prefix(org)
                .and_then(|rest| rest.strip_prefix('/'))
                .map(|name| (c, name))
        })
}

fn branding_scope(key: &str) -> BrandingScope {
    if key == TENANT_BRANDING_KEY {
        BrandingScope::Tenant
    } else {
        BrandingScope::Client(key.to_owned())
    }
}

fn missing(what: &str, key: &str) -> CoreError {
    CoreError::Internal(format!("planned {what} {key:?} is not in the document"))
}

impl ConfigService {
    /// The validators of the services this one writes through.
    pub fn validators(&self) -> Validators<'_> {
        Validators {
            redirect: self.clients.redirect_validator,
            attribute_check: self.attributes.check.as_ref(),
            url_check: self.webhooks.url_check.as_ref(),
            template_check: self.mail.checker.as_ref(),
            dev_mode: self.dev_mode,
        }
    }

    fn storage(&self) -> &dyn Storage {
        self.tenants.storage.as_ref()
    }

    /// Reads a tenant's configuration through the services.
    pub async fn load(&self, tenant: Tenant) -> Result<StoredConfig, CoreError> {
        let mut clients = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .clients
                .list(tenant.id, PageRequest { after, limit: 200 })
                .await?;
            clients.extend(page.items);
            match page.next_cursor {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let mut branding = Vec::new();
        if let Some(b) = self.branding.get(tenant.id, &BrandingScope::Tenant).await? {
            branding.push((None, b));
        }
        for c in clients.iter().filter(|c| is_exported_client(&tenant, c)) {
            let scope = BrandingScope::Client(c.client_id.clone());
            if let Some(b) = self.branding.get(tenant.id, &scope).await? {
                branding.push((Some(c.client_id.clone()), b));
            }
        }
        let mut orgs = Vec::new();
        // Tenant roles; the organizations' own roles are appended below.
        let mut roles = self.roles.list(tenant.id).await?;
        if !is_system(&tenant) {
            let mut after = None;
            loop {
                let page = self
                    .orgs
                    .list(tenant.id, PageRequest { after, limit: 200 })
                    .await?;
                for org in page.items {
                    roles.extend(self.orgs.list_roles(tenant.id, org.id).await?);
                    let domains = self.domains.list(&org).await?;
                    let branding = self
                        .branding
                        .get(tenant.id, &BrandingScope::Org(org.id))
                        .await?;
                    orgs.push(StoredOrg {
                        org,
                        domains,
                        branding,
                    });
                }
                match page.next_cursor {
                    Some(next) => after = Some(next),
                    None => break,
                }
            }
        }
        Ok(StoredConfig {
            orgs,
            connections: self.connections.list(tenant.id).await?,
            roles,
            attributes: self.attributes.list(tenant.id).await?,
            templates: self.mail.list_templates(tenant.id).await?,
            smtp: self.storage().mail_settings().smtp(tenant.id).await?,
            webhooks: self.webhooks.list(tenant.id).await?,
            clients,
            branding,
            tenant,
        })
    }

    /// The tenant's document ([`StoredConfig::document`]). `NotFound` for an unknown slug.
    pub async fn export(&self, slug: &str) -> Result<TenantConfigDocument, CoreError> {
        let tenant = self.tenants.get(slug).await?;
        Ok(self.load(tenant).await?.document())
    }

    /// Whether an inline secret equals the stored one: client secrets by hash, sealed secrets
    /// opened with the KEK, compared in constant time. Anything that cannot be compared counts
    /// as different (the secret is then written again).
    fn secret_matches(&self, cur: &StoredConfig, r: &SecretRef<'_>, input: &SecretInput) -> bool {
        let SecretInput::Inline { value } = input else {
            return false;
        };
        let presented = value.expose_secret();
        match r.kind {
            ConfigObjectKind::Client => cur
                .clients
                .iter()
                .find(|c| c.client_id == r.key)
                .and_then(|c| c.secret_hash.as_ref())
                .is_some_and(|h| ct_eq(&secret_hash(presented), &h.0)),
            ConfigObjectKind::Connection => cur
                .tenant_connections()
                .find(|c| c.slug == r.key)
                .and_then(|c| self.connections.open_secret(c).ok().flatten())
                .is_some_and(|s| ct_eq(s.expose_secret().as_bytes(), presented.as_bytes())),
            ConfigObjectKind::OrgConnection => r
                .key
                .split_once('/')
                .and_then(|(org, slug)| {
                    let id = cur.org(org)?.org.id;
                    cur.connections
                        .iter()
                        .find(|c| c.org_id == Some(id) && c.slug == slug)
                })
                .and_then(|c| self.connections.open_secret(c).ok().flatten())
                .is_some_and(|s| ct_eq(s.expose_secret().as_bytes(), presented.as_bytes())),
            ConfigObjectKind::Webhook => {
                let Ok(wanted) = parse_webhook_secret(presented) else {
                    return false;
                };
                cur.webhooks
                    .iter()
                    .find(|w| w.name == r.key)
                    .and_then(|w| signing_keys(&self.tenants.kek, w, self.tenants.clock.now()).ok())
                    .and_then(|keys| keys.into_iter().next())
                    .is_some_and(|k| ct_eq(&k, &wanted))
            }
            ConfigObjectKind::Smtp => cur
                .smtp
                .as_ref()
                .and_then(|s| smtp_connection(&self.tenants.kek, cur.tenant.id, s).ok())
                .and_then(|c| c.password)
                .is_some_and(|p| ct_eq(p.expose_secret().as_bytes(), presented.as_bytes())),
            _ => false,
        }
    }

    fn plan_for(
        &self,
        current: Option<&StoredConfig>,
        desired: &TenantConfigDocument,
    ) -> ConfigPlan {
        match current {
            Some(cur) => plan_excluding(
                &cur.document(),
                desired,
                &|r, s| self.secret_matches(cur, r, s),
                &|id| cur.is_runtime_client(id),
            ),
            None => {
                // A new tenant: everything is a create.
                let empty = TenantConfigDocument {
                    version: TENANT_CONFIG_VERSION,
                    kind: ConfigKind::TenantConfig,
                    tenant: desired.tenant.clone(),
                    clients: Vec::new(),
                    connections: Vec::new(),
                    branding: Vec::new(),
                    roles: Vec::new(),
                    attributes: Vec::new(),
                    email_templates: Vec::new(),
                    smtp: None,
                    webhooks: Vec::new(),
                    organizations: None,
                };
                let mut p = plan(&empty, desired, &|_, _| false);
                p.creates.insert(
                    0,
                    ConfigChange {
                        kind: ConfigObjectKind::Tenant,
                        key: desired.tenant.slug.clone(),
                        fields: Vec::new(),
                    },
                );
                p
            }
        }
    }

    /// The role guards of the whole batch, before anything is written: the escalation guard for
    /// every role the plan touches and, in the system tenant, the last-administrator guard for
    /// the roles that stop granting `admin:write`.
    async fn check_roles(
        &self,
        cur: &StoredConfig,
        desired: &TenantConfigDocument,
        plan: &ConfigPlan,
        prune: bool,
        caller: &Scope,
    ) -> Result<(), CoreError> {
        if !is_system(&cur.tenant) {
            return Ok(());
        }
        let desired_role = |name: &str| desired.roles.iter().find(|r| r.name == name);
        let stored_role = |name: &str| cur.tenant_roles().find(|r| r.name == name);
        for c in of_kind(&plan.creates, ConfigObjectKind::Role)
            .chain(of_kind(&plan.updates, ConfigObjectKind::Role))
        {
            if let Some(r) = stored_role(&c.key) {
                check_escalation(caller, &r.permissions)?;
            }
            if let Some(r) = desired_role(&c.key) {
                check_escalation(caller, &normalize_permissions(&r.permissions)?)?;
            }
        }
        if prune {
            for c in of_kind(&plan.deletes, ConfigObjectKind::Role) {
                if let Some(r) = stored_role(&c.key) {
                    check_escalation(caller, &r.permissions)?;
                }
            }
        }
        let losing: Vec<RoleId> = cur
            .tenant_roles()
            .filter(|r| r.permissions.iter().any(|p| p == ADMIN_WRITE))
            .filter(|r| match desired_role(&r.name) {
                Some(d) => !d.permissions.iter().any(|p| p == ADMIN_WRITE),
                None => prune,
            })
            .map(|r| r.id)
            .collect();
        guard_roles_losing_admin(self.storage(), &cur.tenant, &losing).await
    }

    /// Stored logo references (`{sha256, content_type}`) must name a logo stored in the tenant,
    /// with its content type; a document for another instance must carry the image.
    async fn check_logos(
        &self,
        current: Option<&StoredConfig>,
        desired: &TenantConfigDocument,
    ) -> Result<Vec<ConfigIssue>, CoreError> {
        let mut issues = Issues::default();
        for (path, logo) in logo_slots(desired) {
            let LogoInput::Stored {
                sha256,
                content_type,
            } = logo
            else {
                continue;
            };
            let stored = match current {
                Some(cur) => self.branding.logo(cur.tenant.id, sha256).await?,
                None => None,
            };
            match stored {
                None => issues.push(
                    path,
                    "unknown logo hash: no logo with this sha256 is stored in the tenant; send \
                     the image as {data: <base64>} (the CLI also accepts {file: path})",
                ),
                Some(l) if &l.content_type != content_type => issues.push(
                    format!("{path}.content_type"),
                    format!("the stored logo with this sha256 is {}", l.content_type),
                ),
                Some(_) => {}
            }
        }
        Ok(issues.0)
    }

    /// SAML organization connections are created or changed only while the operator flag
    /// `saml_experimental` is on (disabling one always works), refused before anything is
    /// written.
    fn check_saml(&self, desired: &TenantConfigDocument, plan: &ConfigPlan) -> Vec<ConfigIssue> {
        let mut issues = Issues::default();
        if self.connections.saml_enabled {
            return issues.0;
        }
        for (i, o) in desired.organizations.iter().flatten().enumerate() {
            for (j, c) in o.connections.iter().enumerate() {
                if !matches!(c.config, crate::model::ConnectionConfig::Saml(_)) {
                    continue;
                }
                let key = format!("{}/{}", o.slug, c.slug);
                let created =
                    of_kind(&plan.creates, ConfigObjectKind::OrgConnection).any(|x| x.key == key);
                let changed = of_kind(&plan.updates, ConfigObjectKind::OrgConnection)
                    .find(|x| x.key == key)
                    .is_some_and(|x| !(top_fields(x) == BTreeSet::from(["enabled"]) && !c.enabled));
                if created || changed {
                    issues.push(
                        format!("organizations[{i}].connections[{j}].config"),
                        "SAML connections need the operator flag saml_experimental",
                    );
                }
            }
        }
        issues.0
    }

    /// Applies a branding section's logo to `scope`: absent keeps it, `null` clears a stored
    /// one, inline data or a stored reference sets it (checked like an upload).
    async fn write_logo(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        logo: Option<&Option<LogoInput>>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let bytes = match logo {
            None => return Ok(()),
            Some(None) => {
                let has_logo = self
                    .branding
                    .get(tenant, scope)
                    .await?
                    .is_some_and(|b| b.logo_sha256.is_some());
                if has_logo {
                    self.branding.clear_logo(tenant, scope, actor, ctx).await?;
                }
                return Ok(());
            }
            Some(Some(LogoInput::Data { data })) => {
                decode_logo(data)
                    .map_err(|message| CoreError::Validation {
                        field: "logo",
                        message,
                    })?
                    .0
            }
            Some(Some(LogoInput::Stored { sha256, .. })) => {
                self.branding
                    .logo(tenant, sha256)
                    .await?
                    .ok_or_else(|| CoreError::Validation {
                        field: "logo",
                        message: "unknown logo hash".to_owned(),
                    })?
                    .bytes
            }
        };
        self.branding
            .set_logo(tenant, scope, bytes, actor, ctx)
            .await?;
        Ok(())
    }

    /// Validates `document` completely (the services' rules, then the checks against the stored
    /// state and the role guards), computes the plan and, unless `dry_run`, applies it through
    /// the services in dependency order: tenant settings, roles, attributes, connections,
    /// organizations (with their roles, connections, domain claims, default roles and branding),
    /// clients, branding, email templates and SMTP, webhooks. Deletes run only with `prune`.
    /// Records `tenant_config_applied` (counts only) when something was written. A missing
    /// tenant is created.
    pub async fn apply(&self, req: ApplyRequest<'_>) -> Result<ApplyOutcome, ConfigError> {
        validate_document(req.document, &self.validators()).map_err(ConfigError::Invalid)?;
        let mut desired = normalize_document(req.document);
        let current = match self.tenants.get(&desired.tenant.slug).await {
            Ok(t) => Some(self.load(t).await?),
            Err(CoreError::NotFound) => None,
            Err(e) => return Err(e.into()),
        };
        defer_unverified_routing(&mut desired, current.as_ref());
        let mut issues = check_against_stored(
            current.as_ref(),
            &desired,
            req.prune,
            self.installation_smtp,
            &self.tenants.kek,
        );
        issues.extend(check_organizations(current.as_ref(), &desired, req.prune));
        issues.extend(self.check_logos(current.as_ref(), &desired).await?);
        if !issues.is_empty() {
            return Err(ConfigError::Invalid(issues));
        }
        let plan = self.plan_for(current.as_ref(), &desired);
        let issues = self.check_saml(&desired, &plan);
        if !issues.is_empty() {
            return Err(ConfigError::Invalid(issues));
        }
        if let Some(cur) = &current {
            self.check_roles(cur, &desired, &plan, req.prune, req.caller)
                .await?;
        }
        let writes = !plan.creates.is_empty()
            || !plan.updates.is_empty()
            || (req.prune && !plan.deletes.is_empty());
        let mut outcome = ApplyOutcome {
            plan,
            applied: false,
            pruned: false,
            generated: Vec::new(),
        };
        if req.dry_run || !writes {
            return Ok(outcome);
        }
        self.write(&req, current.as_ref(), &desired, &mut outcome)
            .await?;
        outcome.applied = true;
        outcome.pruned = req.prune;
        let deletes = if req.prune {
            outcome.plan.deletes.len()
        } else {
            0
        };
        let tenant = self.tenants.get(&desired.tenant.slug).await?;
        AuditService {
            storage: Arc::clone(&self.tenants.storage),
            clock: Arc::clone(&self.tenants.clock),
        }
        .record(
            tenant.id,
            req.actor.clone(),
            AuditAction::TenantConfigApplied,
            Some(tenant.id.to_string()),
            AuditOutcome::Success,
            req.ctx,
            AuditDetails::config_plan(
                outcome.plan.creates.len() as u64,
                outcome.plan.updates.len() as u64,
                deletes as u64,
            ),
        )
        .await?;
        Ok(outcome)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear pass over the object kinds in dependency order"
    )]
    async fn write(
        &self,
        req: &ApplyRequest<'_>,
        current: Option<&StoredConfig>,
        desired: &TenantConfigDocument,
        outcome: &mut ApplyOutcome,
    ) -> Result<(), CoreError> {
        use ConfigObjectKind as K;
        let plan = outcome.plan.clone();
        let actor = || req.actor.clone();
        let ctx = req.ctx;
        let prune = req.prune;
        let smtp_now = self.installation_smtp || current.is_some_and(|c| c.smtp.is_some());

        // 1. Tenant.
        let tenant = match current {
            None => {
                self.tenants
                    .create(
                        NewTenantInput {
                            slug: desired.tenant.slug.clone(),
                            display_name: desired.tenant.display_name.clone(),
                            host: desired.tenant.host.clone(),
                            settings: first_pass_settings(&desired.tenant.settings, None, smtp_now),
                            installation_smtp: self.installation_smtp,
                            dev_mode: self.dev_mode,
                        },
                        actor(),
                        ctx,
                    )
                    .await?
            }
            Some(cur) => match of_kind(&plan.updates, K::Tenant).next() {
                None => cur.tenant.clone(),
                Some(change) => {
                    let f = top_fields(change);
                    let patch = TenantPatch {
                        display_name: f
                            .contains("display_name")
                            .then(|| desired.tenant.display_name.clone()),
                        host: f.contains("host").then(|| desired.tenant.host.clone()),
                        settings: f.contains("settings").then(|| {
                            first_pass_settings(
                                &desired.tenant.settings,
                                Some(&cur.tenant.settings),
                                smtp_now,
                            )
                        }),
                        installation_smtp: self.installation_smtp,
                        dev_mode: self.dev_mode,
                    };
                    self.tenants
                        .update(&cur.tenant.slug, patch, None, actor(), ctx)
                        .await?
                }
            },
        };
        let tid = tenant.id;

        // 2. Roles (the batch guards ran before any write; the service checks each change too).
        for c in of_kind(&plan.creates, K::Role) {
            let r = desired
                .roles
                .iter()
                .find(|r| r.name == c.key)
                .ok_or_else(|| missing("role", &c.key))?;
            self.roles
                .create(
                    &tenant,
                    RoleInput {
                        name: r.name.clone(),
                        description: r.description.clone(),
                        permissions: r.permissions.clone(),
                    },
                    req.caller,
                    actor(),
                    ctx,
                )
                .await?;
        }
        for c in of_kind(&plan.updates, K::Role) {
            let r = desired
                .roles
                .iter()
                .find(|r| r.name == c.key)
                .ok_or_else(|| missing("role", &c.key))?;
            let f = top_fields(c);
            let update = RoleUpdate {
                name: None,
                description: f.contains("description").then(|| r.description.clone()),
                permissions: f.contains("permissions").then(|| r.permissions.clone()),
            };
            self.roles
                .update(&tenant, &c.key, update, req.caller, actor(), ctx)
                .await?;
        }
        if prune {
            for c in of_kind(&plan.deletes, K::Role) {
                self.roles
                    .delete(&tenant, &c.key, req.caller, actor(), ctx)
                    .await?;
            }
        }

        // 3. Attributes.
        if prune {
            for c in of_kind(&plan.deletes, K::Attribute) {
                self.attributes.delete(tid, actor(), &c.key, ctx).await?;
            }
        }
        for c in of_kind(&plan.creates, K::Attribute).chain(of_kind(&plan.updates, K::Attribute)) {
            let a = desired
                .attributes
                .iter()
                .find(|a| a.name == c.key)
                .ok_or_else(|| missing("attribute", &c.key))?;
            self.attributes.define(tid, actor(), a, ctx).await?;
        }

        // 4. Connections.
        let stored_conn = |slug: &str| {
            current
                .and_then(|cur| cur.tenant_connections().find(|c| c.slug == slug))
                .map(|c| c.id)
                .ok_or_else(|| missing("connection", slug))
        };
        for c in of_kind(&plan.creates, K::Connection) {
            let s = desired
                .connections
                .iter()
                .find(|s| s.slug == c.key)
                .ok_or_else(|| missing("connection", &c.key))?;
            self.connections
                .create(
                    tid,
                    NewConnectionInput {
                        slug: s.slug.clone(),
                        display_name: s.display_name.clone(),
                        enabled: s.enabled,
                        config: s.config.clone(),
                        secret: match &s.secret {
                            Some(SecretInput::Inline { value }) => Some(value.clone()),
                            _ => None,
                        },
                        trust_email_verified: Some(s.trust_email_verified),
                        // The document states the trust explicitly (see docs/CONFIG-YAML.md).
                        accept_email_trust_risk: true,
                    },
                    actor(),
                    ctx,
                )
                .await?;
        }
        for c in of_kind(&plan.updates, K::Connection) {
            let s = desired
                .connections
                .iter()
                .find(|s| s.slug == c.key)
                .ok_or_else(|| missing("connection", &c.key))?;
            let id = stored_conn(&c.key)?;
            let f = top_fields(c);
            // The secret first: enabling a connection needs its secret (`check_enable`), so a
            // document that adds both must not be refused for the order of the calls.
            if f.contains("secret") {
                let secret = match &s.secret {
                    Some(SecretInput::Inline { value }) => Some(value.clone()),
                    _ => None,
                };
                self.connections
                    .set_secret(tid, id, secret, actor(), ctx)
                    .await?;
            }
            let patch = ConnectionPatch {
                display_name: f.contains("display_name").then(|| s.display_name.clone()),
                enabled: f.contains("enabled").then_some(s.enabled),
                config: f.contains("config").then(|| s.config.clone()),
                trust_email_verified: f
                    .contains("trust_email_verified")
                    .then_some(s.trust_email_verified),
                accept_email_trust_risk: true,
            };
            if patch.display_name.is_some()
                || patch.enabled.is_some()
                || patch.config.is_some()
                || patch.trust_email_verified.is_some()
            {
                self.connections
                    .update(tid, id, patch, actor(), ctx)
                    .await?;
            }
        }

        // 4b. Organizations (only those the document lists; never deleted).
        for o in desired.organizations.iter().flatten() {
            self.write_org(req, &tenant, current, o, &plan).await?;
        }

        // 5. Clients (deletes after the branding deletes).
        for c in of_kind(&plan.creates, K::Client) {
            let s = desired
                .clients
                .iter()
                .find(|s| s.client_id == c.key)
                .ok_or_else(|| missing("client", &c.key))?;
            let (input, options) = client_input(s);
            let inline = match &s.secret {
                Some(SecretInput::Inline { value }) => Some(value.clone()),
                _ => None,
            };
            let created = self
                .clients
                .create_static(&tenant, &s.client_id, input, options, inline, actor(), ctx)
                .await?;
            if let Some(value) = created.client_secret {
                outcome.generated.push(GeneratedSecret {
                    kind: K::Client,
                    key: s.client_id.clone(),
                    field: "secret",
                    value,
                });
            }
        }
        for c in of_kind(&plan.updates, K::Client) {
            let s = desired
                .clients
                .iter()
                .find(|s| s.client_id == c.key)
                .ok_or_else(|| missing("client", &c.key))?;
            let f = top_fields(c);
            let has = |n: &str| f.contains(n);
            let patch = ClientPatch {
                name: has("name").then(|| s.name.clone()),
                redirect_uris: has("redirect_uris").then(|| s.redirect_uris.clone()),
                grant_types: has("grant_types").then(|| s.grant_types.clone()),
                scopes: has("scopes").then(|| s.scopes.clone()),
                require_pkce: has("require_pkce").then_some(s.require_pkce),
                jwks: has("jwks").then(|| s.jwks.clone()),
            };
            let options = ClientOptionsPatch {
                token_format: has("token_format").then_some(s.token_format),
                consent_mode: has("consent_mode").then_some(s.consent_mode),
                id_token_signed_response_alg: has("id_token_signed_response_alg")
                    .then(|| s.id_token_signed_response_alg.clone()),
                can_introspect: has("can_introspect").then_some(s.can_introspect),
                post_logout_redirect_uris: has("post_logout_redirect_uris")
                    .then(|| s.post_logout_redirect_uris.clone()),
                backchannel_logout_uri: has("backchannel_logout_uri")
                    .then(|| s.backchannel_logout_uri.clone()),
                backchannel_logout_session_required: has("backchannel_logout_session_required")
                    .then_some(s.backchannel_logout_session_required),
                allowed_resources: has("allowed_resources").then(|| s.allowed_resources.clone()),
                mfa_policy: has("mfa_policy").then_some(s.mfa_policy),
                organization: has("organization").then_some(s.organization),
                require_pushed_authorization_requests: has("require_pushed_authorization_requests")
                    .then_some(s.require_pushed_authorization_requests),
                client_kind: has("client_kind").then_some(s.client_kind),
                headless_native: has("headless_native").then_some(s.headless_native),
                client_uri: has("client_uri").then(|| s.client_uri.clone()),
                initiate_login_uri: has("initiate_login_uri").then(|| s.initiate_login_uri.clone()),
            };
            if patch != ClientPatch::default() || options != ClientOptionsPatch::default() {
                self.clients
                    .update(&tenant, &c.key, patch, options, actor(), ctx)
                    .await?;
            }
            if has("secret") {
                match &s.secret {
                    Some(SecretInput::Inline { value }) => {
                        self.clients
                            .set_secret(tid, &c.key, value.clone(), actor(), ctx)
                            .await?;
                    }
                    Some(SecretInput::Configured { configured: true }) => {
                        let value = self
                            .clients
                            .rotate_secret(tid, &c.key, actor(), ctx)
                            .await?;
                        outcome.generated.push(GeneratedSecret {
                            kind: K::Client,
                            key: c.key.clone(),
                            field: "secret",
                            value,
                        });
                    }
                    _ => {}
                }
            }
        }

        // 6. Branding.
        for c in of_kind(&plan.creates, K::Branding).chain(of_kind(&plan.updates, K::Branding)) {
            let b = desired
                .branding
                .iter()
                .find(|b| b.client_id.as_deref().unwrap_or(TENANT_BRANDING_KEY) == c.key)
                .ok_or_else(|| missing("branding", &c.key))?;
            let scope = branding_scope(&c.key);
            let created = c.fields.is_empty();
            let f = top_fields(c);
            if created || f.contains("tokens") || f.contains("custom_css") {
                self.branding
                    .put(
                        tid,
                        &scope,
                        BrandingInput {
                            tokens: b.tokens.clone(),
                            custom_css: b.custom_css.clone(),
                        },
                        actor(),
                        ctx,
                    )
                    .await?;
            }
            if created || f.contains("logo") {
                self.write_logo(tid, &scope, b.logo.as_ref(), actor(), ctx)
                    .await?;
            }
        }
        if prune {
            for c in of_kind(&plan.deletes, K::Branding) {
                self.branding
                    .delete(tid, &branding_scope(&c.key), actor(), ctx)
                    .await?;
            }
            for c in of_kind(&plan.deletes, K::Client) {
                self.clients.delete(tid, &c.key, actor(), ctx).await?;
            }
            for c in of_kind(&plan.deletes, K::Connection) {
                let id = stored_conn(&c.key)?;
                self.connections.delete(tid, id, actor(), ctx).await?;
            }
        }

        // 7. Email templates and SMTP, then the settings that need SMTP.
        for c in
            of_kind(&plan.creates, K::EmailTemplate).chain(of_kind(&plan.updates, K::EmailTemplate))
        {
            let t = desired
                .email_templates
                .iter()
                .find(|t| t.kind == c.key)
                .ok_or_else(|| missing("email template", &c.key))?;
            let kind =
                EmailKind::parse(&t.kind).ok_or_else(|| missing("email template", &c.key))?;
            self.mail
                .put_template(
                    tid,
                    kind,
                    TemplateInput {
                        subject: t.subject.clone(),
                        body_html: t.body_html.clone(),
                        body_text: t.body_text.clone(),
                    },
                    actor(),
                    ctx,
                )
                .await
                .map_err(CoreError::from)?;
        }
        if prune {
            for c in of_kind(&plan.deletes, K::EmailTemplate) {
                if let Some(kind) = EmailKind::parse(&c.key) {
                    self.mail.reset_template(tid, kind, actor(), ctx).await?;
                }
            }
        }
        if of_kind(&plan.creates, K::Smtp)
            .chain(of_kind(&plan.updates, K::Smtp))
            .next()
            .is_some()
            && let Some(s) = &desired.smtp
        {
            self.mail.put_smtp(tid, smtp_input(s), actor(), ctx).await?;
        }
        if prune && of_kind(&plan.deletes, K::Smtp).next().is_some() {
            self.mail.delete_smtp(tid, actor(), ctx).await?;
        }
        if tenant.settings.email_otp != desired.tenant.settings.email_otp
            || tenant.settings.magic_link != desired.tenant.settings.magic_link
        {
            self.tenants
                .update(
                    &tenant.slug,
                    TenantPatch {
                        settings: Some(desired.tenant.settings.clone()),
                        installation_smtp: self.installation_smtp,
                        dev_mode: self.dev_mode,
                        ..TenantPatch::default()
                    },
                    None,
                    actor(),
                    ctx,
                )
                .await?;
        }

        // 8. Webhooks.
        let stored_hook = |name: &str| {
            current
                .and_then(|cur| cur.webhooks.iter().find(|w| w.name == name))
                .map(|w| w.id)
                .ok_or_else(|| missing("webhook", name))
        };
        for c in of_kind(&plan.creates, K::Webhook) {
            let w = desired
                .webhooks
                .iter()
                .find(|w| w.name == c.key)
                .ok_or_else(|| missing("webhook", &c.key))?;
            let inline = match &w.secret {
                Some(SecretInput::Inline { value }) => Some(value.clone()),
                _ => None,
            };
            let generated = inline.is_none();
            let created = self
                .webhooks
                .create(
                    tid,
                    NewWebhookInput {
                        name: w.name.clone(),
                        url: w.url.clone(),
                        events: w.events.clone(),
                        enabled: w.enabled,
                        secret: inline,
                    },
                    actor(),
                    ctx,
                )
                .await?;
            if generated {
                outcome.generated.push(GeneratedSecret {
                    kind: K::Webhook,
                    key: w.name.clone(),
                    field: "secret",
                    value: created.secret,
                });
            }
        }
        for c in of_kind(&plan.updates, K::Webhook) {
            let w = desired
                .webhooks
                .iter()
                .find(|w| w.name == c.key)
                .ok_or_else(|| missing("webhook", &c.key))?;
            let id = stored_hook(&c.key)?;
            let f = top_fields(c);
            let update = WebhookEndpointUpdate {
                name: None,
                url: f.contains("url").then(|| w.url.clone()),
                events: f.contains("events").then(|| w.events.clone()),
                enabled: f.contains("enabled").then_some(w.enabled),
            };
            if update.url.is_some() || update.events.is_some() || update.enabled.is_some() {
                self.webhooks.update(tid, id, update, actor(), ctx).await?;
            }
            if f.contains("secret")
                && let Some(SecretInput::Inline { value }) = &w.secret
            {
                self.webhooks
                    .set_secret(tid, id, value.clone(), actor(), ctx)
                    .await?;
            }
        }
        if prune {
            for c in of_kind(&plan.deletes, K::Webhook) {
                let id = stored_hook(&c.key)?;
                self.webhooks.delete(tid, id, actor(), ctx).await?;
            }
        }
        Ok(())
    }

    /// Writes one organization entry through the organization services, in order: the
    /// organization, its roles, connections (secret first), domain claims (routing target by
    /// slug), default roles, then the prune-only deletes (domains, connections, roles) and its
    /// branding. Everything is done as a tenant administrator and audited by the services.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear pass over the parts of an organization in dependency order"
    )]
    async fn write_org(
        &self,
        req: &ApplyRequest<'_>,
        tenant: &Tenant,
        current: Option<&StoredConfig>,
        o: &OrganizationSection,
        plan: &ConfigPlan,
    ) -> Result<(), CoreError> {
        use ConfigObjectKind as K;
        let actor = OrgActor::TenantAdmin(req.actor.clone());
        let audit = || req.actor.clone();
        let ctx = req.ctx;
        let prune = req.prune;
        let tid = tenant.id;
        let slug = o.slug.as_str();
        let stored = current.and_then(|c| c.org(slug));

        // The organization.
        let created = of_kind(&plan.creates, K::Organization).any(|c| c.key == slug);
        let head_change = of_kind(&plan.updates, K::Organization).find(|c| c.key == slug);
        let org = if created {
            self.orgs
                .create(
                    tenant,
                    OrgInput {
                        slug: o.slug.clone(),
                        display_name: o.display_name.clone(),
                        mfa_policy: o.mfa_policy,
                        metadata: Some(o.metadata.clone()),
                    },
                    &actor,
                    ctx,
                )
                .await?
        } else {
            let org = stored
                .map(|s| s.org.clone())
                .ok_or_else(|| missing("organization", slug))?;
            let f = head_change.map(top_fields).unwrap_or_default();
            let patch = OrgPatch {
                display_name: f.contains("display_name").then(|| o.display_name.clone()),
                mfa_policy: f.contains("mfa_policy").then_some(o.mfa_policy),
                metadata: f.contains("metadata").then(|| o.metadata.clone()),
                ..OrgPatch::default()
            };
            if patch == OrgPatch::default() {
                org
            } else {
                self.orgs.update(tenant, &org, patch, &actor, ctx).await?
            }
        };
        let default_roles_change = if created {
            !o.settings.default_roles.is_empty()
        } else {
            head_change.is_some_and(|c| top_fields(c).contains("settings"))
        };

        // Roles.
        for (_, name) in org_changes(&plan.creates, K::OrgRole, slug) {
            let r = o
                .roles
                .iter()
                .find(|r| r.name == name)
                .ok_or_else(|| missing("organization role", name))?;
            self.orgs
                .create_role(
                    tenant,
                    &org,
                    RoleInput {
                        name: r.name.clone(),
                        description: r.description.clone(),
                        permissions: r.permissions.clone(),
                    },
                    &actor,
                    ctx,
                )
                .await?;
        }
        for (c, name) in org_changes(&plan.updates, K::OrgRole, slug) {
            let r = o
                .roles
                .iter()
                .find(|r| r.name == name)
                .ok_or_else(|| missing("organization role", name))?;
            let f = top_fields(c);
            let update = RoleUpdate {
                name: None,
                description: f.contains("description").then(|| r.description.clone()),
                permissions: f.contains("permissions").then(|| r.permissions.clone()),
            };
            self.orgs
                .update_role(tenant, &org, name, update, &actor, ctx)
                .await?;
        }

        // Connections.
        let owner = ConnectionOwner::Org(&org);
        let stored_conn = |name: &str| {
            current
                .and_then(|cur| {
                    cur.connections
                        .iter()
                        .find(|c| c.org_id == Some(org.id) && c.slug == name)
                })
                .map(|c| c.id)
                .ok_or_else(|| missing("organization connection", name))
        };
        for (_, name) in org_changes(&plan.creates, K::OrgConnection, slug) {
            let s = o
                .connections
                .iter()
                .find(|s| s.slug == name)
                .ok_or_else(|| missing("organization connection", name))?;
            self.connections
                .create_as(
                    tid,
                    owner,
                    NewConnectionInput {
                        slug: s.slug.clone(),
                        display_name: s.display_name.clone(),
                        enabled: s.enabled,
                        config: s.config.clone(),
                        secret: match &s.secret {
                            Some(SecretInput::Inline { value }) => Some(value.clone()),
                            _ => None,
                        },
                        trust_email_verified: Some(s.trust_email_verified),
                        accept_email_trust_risk: true,
                    },
                    audit(),
                    ctx,
                )
                .await?;
        }
        for (c, name) in org_changes(&plan.updates, K::OrgConnection, slug) {
            let s = o
                .connections
                .iter()
                .find(|s| s.slug == name)
                .ok_or_else(|| missing("organization connection", name))?;
            let id = stored_conn(name)?;
            let f = top_fields(c);
            // The secret first, as for tenant connections (enabling needs it).
            if f.contains("secret") {
                let secret = match &s.secret {
                    Some(SecretInput::Inline { value }) => Some(value.clone()),
                    _ => None,
                };
                self.connections
                    .set_secret_as(tid, owner, id, secret, audit(), ctx)
                    .await?;
            }
            let patch = ConnectionPatch {
                display_name: f.contains("display_name").then(|| s.display_name.clone()),
                enabled: f.contains("enabled").then_some(s.enabled),
                config: f.contains("config").then(|| s.config.clone()),
                trust_email_verified: f
                    .contains("trust_email_verified")
                    .then_some(s.trust_email_verified),
                accept_email_trust_risk: true,
            };
            if patch.display_name.is_some()
                || patch.enabled.is_some()
                || patch.config.is_some()
                || patch.trust_email_verified.is_some()
            {
                self.connections
                    .update_as(tid, owner, id, patch, audit(), ctx)
                    .await?;
            }
        }

        // Domain claims: a new claim is pending with a fresh token (OrgDomainService::add);
        // routing settings of unverified claims were held back (`defer_unverified_routing`).
        let conns = self.connections.list_for_org(tid, &org).await?;
        let conn_id = |name: &str| {
            conns
                .iter()
                .find(|c| c.slug == name)
                .map(|c| c.id)
                .ok_or_else(|| missing("organization connection", name))
        };
        let stored_domain = |name: &str| {
            stored
                .and_then(|so| so.domains.iter().find(|d| d.domain == name))
                .map(|d| d.id)
                .ok_or_else(|| missing("organization domain", name))
        };
        for (_, name) in org_changes(&plan.creates, K::OrgDomain, slug) {
            let d = o
                .domains
                .iter()
                .find(|d| d.domain == name)
                .ok_or_else(|| missing("organization domain", name))?;
            let claim = self.domains.add(&org, &d.domain, audit(), ctx).await?;
            let patch = DomainPatch {
                connection_id: match &d.connection {
                    Some(c) => Some(Some(conn_id(c)?)),
                    None => None,
                },
                routing: (d.routing != claim.routing).then_some(d.routing),
                allow_local_password: (d.allow_local_password != claim.allow_local_password)
                    .then_some(d.allow_local_password),
            };
            if patch != DomainPatch::default() {
                self.domains
                    .update(&org, claim.id, patch, audit(), ctx)
                    .await?;
            }
        }
        for (c, name) in org_changes(&plan.updates, K::OrgDomain, slug) {
            let d = o
                .domains
                .iter()
                .find(|d| d.domain == name)
                .ok_or_else(|| missing("organization domain", name))?;
            let id = stored_domain(name)?;
            let f = top_fields(c);
            let patch = DomainPatch {
                connection_id: if f.contains("connection") {
                    Some(match &d.connection {
                        Some(c) => Some(conn_id(c)?),
                        None => None,
                    })
                } else {
                    None
                },
                routing: f.contains("routing").then_some(d.routing),
                allow_local_password: f
                    .contains("allow_local_password")
                    .then_some(d.allow_local_password),
            };
            if patch != DomainPatch::default() {
                self.domains.update(&org, id, patch, audit(), ctx).await?;
            }
        }

        // Default roles, by name: the organization's role first, then the tenant's.
        if default_roles_change {
            let mut ids = Vec::with_capacity(o.settings.default_roles.len());
            for name in &o.settings.default_roles {
                ids.push(self.orgs.resolve_role(tid, org.id, name, None).await?.id);
            }
            self.orgs
                .update(
                    tenant,
                    &org,
                    OrgPatch {
                        default_role_ids: Some(ids),
                        ..OrgPatch::default()
                    },
                    &actor,
                    ctx,
                )
                .await?;
        }

        // Prune-only deletes of what the entry no longer lists (never the organization).
        if prune {
            for (_, name) in org_changes(&plan.deletes, K::OrgDomain, slug) {
                self.domains
                    .delete(&org, stored_domain(name)?, audit(), ctx)
                    .await?;
            }
            for (_, name) in org_changes(&plan.deletes, K::OrgConnection, slug) {
                self.connections
                    .delete_as(tid, owner, stored_conn(name)?, audit(), ctx)
                    .await?;
            }
            for (_, name) in org_changes(&plan.deletes, K::OrgRole, slug) {
                self.orgs
                    .delete_role(tenant, &org, name, &actor, ctx)
                    .await?;
            }
        }

        // Branding.
        let scope = BrandingScope::Org(org.id);
        let branding_create = of_kind(&plan.creates, K::OrgBranding).any(|c| c.key == slug);
        let branding_update = of_kind(&plan.updates, K::OrgBranding).find(|c| c.key == slug);
        if let Some(b) = &o.branding
            && (branding_create || branding_update.is_some())
        {
            let f = branding_update.map(top_fields).unwrap_or_default();
            if branding_create || f.contains("tokens") || f.contains("custom_css") {
                self.branding
                    .put(
                        tid,
                        &scope,
                        BrandingInput {
                            tokens: b.tokens.clone(),
                            custom_css: b.custom_css.clone(),
                        },
                        audit(),
                        ctx,
                    )
                    .await?;
            }
            if branding_create || f.contains("logo") {
                self.write_logo(tid, &scope, b.logo.as_ref(), audit(), ctx)
                    .await?;
            }
        }
        if prune && of_kind(&plan.deletes, K::OrgBranding).any(|c| c.key == slug) {
            self.branding.delete(tid, &scope, audit(), ctx).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;

    fn doc() -> TenantConfigDocument {
        serde_json::from_value(json!({
            "version": 1,
            "kind": "TenantConfig",
            "tenant": {"slug": "acme", "display_name": "Acme"},
            "clients": [{
                "client_id": "web",
                "name": "Web",
                "client_type": "confidential",
                "application_type": "web",
                "auth_method": "client_secret_basic",
                "secret": {"configured": true},
                "redirect_uris": ["https://app.example.test/cb"],
                "grant_types": ["authorization_code"],
                "scopes": ["openid"],
            }],
            "roles": [
                {"name": "admin", "permissions": ["orders:write"]},
                {"name": "viewer", "permissions": ["orders:read"]},
            ],
            "attributes": [{"name": "department", "schema": {"type": "string"}}],
            "webhooks": [{
                "name": "crm",
                "url": "https://hooks.example.test/anvil",
                "events": ["user.created"],
                "secret": {"configured": true},
            }],
        }))
        .unwrap()
    }

    fn never_equal(_: &SecretRef<'_>, _: &SecretInput) -> bool {
        false
    }

    fn inline(v: &str) -> SecretInput {
        SecretInput::Inline {
            value: SecretString::from(v.to_owned()),
        }
    }

    #[test]
    fn identical_documents_give_an_empty_plan() {
        let d = doc();
        let p = plan(&d, &d, &never_equal);
        assert!(p.is_empty(), "{p:?}");
        assert_eq!(render(&p), "No changes.\n");
    }

    #[test]
    fn changed_redirect_uri_is_one_update_with_a_field_diff() {
        let cur = doc();
        let mut des = doc();
        des.clients[0].redirect_uris = vec!["https://app.example.test/callback".into()];
        let p = plan(&cur, &des, &never_equal);
        assert!(p.creates.is_empty() && p.deletes.is_empty());
        assert_eq!(
            p.updates,
            vec![ConfigChange {
                kind: ConfigObjectKind::Client,
                key: "web".into(),
                fields: vec![FieldDiff {
                    field: "redirect_uris".into(),
                    before: Some(json!(["https://app.example.test/cb"])),
                    after: Some(json!(["https://app.example.test/callback"])),
                }],
            }]
        );
        assert!(render(&p).contains("~ client web"));
    }

    #[test]
    fn role_only_in_current_is_a_prune_only_delete() {
        let cur = doc();
        let mut des = doc();
        des.roles.retain(|r| r.name != "viewer");
        let p = plan(&cur, &des, &never_equal);
        assert!(p.creates.is_empty() && p.updates.is_empty());
        assert_eq!(p.deletes.len(), 1);
        assert_eq!(p.deletes[0].kind, ConfigObjectKind::Role);
        assert_eq!(p.deletes[0].key, "viewer");
        assert!(render(&p).contains("- role viewer (prune only)"));
    }

    #[test]
    fn new_webhook_is_a_create() {
        let cur = doc();
        let mut des = doc();
        let mut hook = des.webhooks[0].clone();
        hook.name = "billing".into();
        hook.secret = None;
        des.webhooks.push(hook);
        let p = plan(&cur, &des, &never_equal);
        assert_eq!(
            p.creates,
            vec![ConfigChange {
                kind: ConfigObjectKind::Webhook,
                key: "billing".into(),
                fields: vec![],
            }]
        );
        assert!(p.updates.is_empty() && p.deletes.is_empty());
    }

    #[test]
    fn configured_secret_on_both_sides_is_unchanged() {
        let d = doc();
        let p = plan(&d, &d, &|_, _| panic!("no inline secret to compare"));
        assert!(p.is_empty());
    }

    #[test]
    fn omitted_secret_keeps_the_current_one() {
        let cur = doc();
        let mut des = doc();
        des.clients[0].secret = None;
        des.webhooks[0].secret = None;
        assert!(plan(&cur, &des, &never_equal).is_empty());
    }

    #[test]
    fn clearing_a_secret_is_an_update() {
        let cur = doc();
        let mut des = doc();
        des.clients[0].secret = Some(SecretInput::Configured { configured: false });
        let p = plan(&cur, &des, &never_equal);
        assert_eq!(p.updates.len(), 1);
        assert_eq!(
            p.updates[0].fields,
            vec![FieldDiff {
                field: "secret".into(),
                before: None,
                after: None,
            }]
        );
    }

    #[test]
    fn inline_secret_uses_the_supplied_equality_and_never_prints_it() {
        let cur = doc();
        let mut des = doc();
        des.webhooks[0].secret = Some(inline("whsec_TOPSECRETVALUE"));

        let asked = std::cell::RefCell::new(Vec::new());
        let p = plan(&cur, &des, &|r, _| {
            asked.borrow_mut().push((r.kind, r.key.to_owned(), r.field));
            true
        });
        assert!(p.is_empty());
        assert_eq!(
            asked.into_inner(),
            vec![(ConfigObjectKind::Webhook, "crm".to_owned(), "secret")]
        );

        let p = plan(&cur, &des, &never_equal);
        assert_eq!(p.updates.len(), 1);
        assert_eq!(p.updates[0].kind, ConfigObjectKind::Webhook);
        assert_eq!(p.updates[0].fields[0].field, "secret");
        assert_eq!(p.updates[0].fields[0].before, None);
        assert_eq!(p.updates[0].fields[0].after, None);
        let text = render(&p);
        assert!(text.contains("secret: (secret changed)"), "{text}");
        assert!(!text.contains("TOPSECRET"));
        assert!(!serde_json::to_string(&p).unwrap().contains("TOPSECRET"));
        assert!(!format!("{p:?}").contains("TOPSECRET"));
    }

    #[test]
    fn inline_secret_against_an_unset_secret_is_an_update_without_asking() {
        let mut cur = doc();
        cur.clients[0].secret = None;
        let mut des = doc();
        des.clients[0].secret = Some(inline("s3cret"));
        let p = plan(&cur, &des, &|_, _| panic!("nothing stored to compare"));
        assert_eq!(p.updates.len(), 1);
    }

    #[test]
    fn nested_settings_diff_uses_dotted_paths() {
        let cur = doc();
        let mut des = doc();
        des.tenant.display_name = "Acme Inc".into();
        des.tenant.settings.claims.permissions = None;
        let p = plan(&cur, &des, &never_equal);
        assert_eq!(p.updates.len(), 1);
        let c = &p.updates[0];
        assert_eq!((c.kind, c.key.as_str()), (ConfigObjectKind::Tenant, "acme"));
        let names: Vec<&str> = c.fields.iter().map(|f| f.field.as_str()).collect();
        assert!(names.contains(&"display_name"), "{names:?}");
        assert!(names.contains(&"settings.claims.permissions"), "{names:?}");
    }

    #[test]
    fn runtime_clients_are_excluded_from_both_sides() {
        let mut cur = doc();
        let mut dynamic = cur.clients[0].clone();
        dynamic.client_id = "dyn-123".into();
        cur.clients.push(dynamic.clone());
        let mut des = doc();
        let mut cimd = des.clients[0].clone();
        cimd.client_id = "https://mcp.example.test/client.json".into();
        des.clients.push(cimd);
        let runtime = |id: &str| id.starts_with("dyn-") || id.starts_with("https://");
        assert!(plan_excluding(&cur, &des, &never_equal, &runtime).is_empty());
        // Without the exclusion they would show up as a delete and a create.
        let p = plan(&cur, &des, &never_equal);
        assert_eq!((p.creates.len(), p.deletes.len()), (1, 1));
    }

    #[test]
    fn smtp_create_update_delete() {
        let none = doc();
        let mut with: TenantConfigDocument = doc();
        with.smtp = Some(
            serde_json::from_value(json!({
                "host": "smtp.example.test", "port": 587, "from": "id@example.test",
                "tls": "starttls", "password": {"configured": true},
            }))
            .unwrap(),
        );
        assert_eq!(plan(&none, &with, &never_equal).creates[0].key, SMTP_KEY);
        assert_eq!(plan(&with, &none, &never_equal).deletes[0].key, SMTP_KEY);
        let mut port = with.clone();
        if let Some(s) = port.smtp.as_mut() {
            s.port = 465;
        }
        let p = plan(&with, &port, &never_equal);
        assert_eq!(p.updates[0].fields[0].field, "port");
    }

    #[test]
    fn plan_is_deterministic_and_sorted() {
        let cur = doc();
        let mut des = doc();
        des.roles.clear();
        des.roles
            .push(serde_json::from_value(json!({"name": "zeta"})).unwrap());
        des.roles
            .push(serde_json::from_value(json!({"name": "alpha"})).unwrap());
        let p = plan(&cur, &des, &never_equal);
        let creates: Vec<&str> = p.creates.iter().map(|c| c.key.as_str()).collect();
        let deletes: Vec<&str> = p.deletes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(creates, ["alpha", "zeta"]);
        assert_eq!(deletes, ["admin", "viewer"]);
        assert_eq!(p, plan(&cur, &des, &never_equal));
    }

    #[test]
    fn duplicate_natural_keys_are_rejected() {
        check_unique_keys(&doc()).unwrap();
        let mut d = doc();
        d.roles.push(d.roles[0].clone());
        assert!(check_unique_keys(&d).is_err());
        let mut d = doc();
        d.webhooks.push(d.webhooks[0].clone());
        assert!(check_unique_keys(&d).is_err());
        let mut d = doc();
        d.branding.push(serde_json::from_value(json!({})).unwrap());
        d.branding.push(serde_json::from_value(json!({})).unwrap());
        assert!(check_unique_keys(&d).is_err());
    }

    // -----------------------------------------------------------------------------------------
    // 05-20: validation, export, normalisation
    // -----------------------------------------------------------------------------------------

    use crate::model::{
        ApplicationType as App, Client as StoredClient, ClientAuthMethod, ClientId, ClientType,
        ConsentMode, GrantType, Role as StoredRole, RoleId, SecretHash, TokenFormat,
        WebhookEndpointId, WebhookEventType,
    };
    use crate::ports::{SchemaIssue, TemplateIssue};
    use crate::service::webhook::UrlRefusal;

    struct AnySchema;
    impl AttributeSchemaCheck for AnySchema {
        fn check_definition(&self, schema: &Value) -> Result<(), SchemaIssue> {
            if schema.is_object() {
                Ok(())
            } else {
                Err(SchemaIssue {
                    message: "schema must be an object".into(),
                })
            }
        }
        fn validate(&self, _: &Value, _: &Value) -> Result<(), Vec<String>> {
            Ok(())
        }
    }

    struct HttpsOnly;
    impl WebhookUrlCheck for HttpsOnly {
        fn check(&self, url: &url::Url) -> Result<(), UrlRefusal> {
            if url.scheme() != "https" {
                Err(UrlRefusal::Invalid)
            } else if url.host_str() == Some("127.0.0.1") {
                Err(UrlRefusal::Blocked)
            } else {
                Ok(())
            }
        }
    }

    struct NoBraces;
    impl EmailTemplateCheck for NoBraces {
        fn check(
            &self,
            _: EmailKind,
            subject: &str,
            _: &str,
            _: &str,
        ) -> Result<(), TemplateIssue> {
            if subject.contains("{{") {
                Err(TemplateIssue {
                    line: Some(1),
                    message: "subject: unknown variable".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn https_only(uri: &str, _: App) -> Result<(), CoreError> {
        if uri.starts_with("https://") {
            Ok(())
        } else {
            Err(CoreError::Validation {
                field: "redirect_uri",
                message: "redirect URI must use https".into(),
            })
        }
    }

    fn validators() -> Validators<'static> {
        Validators {
            redirect: https_only,
            attribute_check: &AnySchema,
            url_check: &HttpsOnly,
            template_check: &NoBraces,
            dev_mode: false,
        }
    }

    fn paths(r: Result<(), Vec<ConfigIssue>>) -> Vec<String> {
        r.err()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.path)
            .collect()
    }

    fn three_clients() -> TenantConfigDocument {
        let mut d = doc();
        for id in ["mobile", "spa"] {
            let mut c = d.clients[0].clone();
            c.client_id = id.into();
            d.clients.push(c);
        }
        d
    }

    #[test]
    fn valid_document_passes() {
        validate_document(&doc(), &validators()).unwrap();
        validate_document(&three_clients(), &validators()).unwrap();
    }

    #[test]
    fn client_policy_and_headless_origins_are_validated_with_paths() {
        let mut d = three_clients();
        // clients[0]: an agent that skips consent.
        d.clients[0].client_kind = crate::model::ClientKind::Agent;
        d.clients[0].consent_mode = ConsentMode::SkipFirstParty;
        // clients[1]: native headless without first-party consent.
        d.clients[1].headless_native = true;
        // clients[2]: a valid native headless client, with PAR required.
        d.clients[2].headless_native = true;
        d.clients[2].consent_mode = ConsentMode::SkipFirstParty;
        d.clients[2].require_pushed_authorization_requests = true;
        d.tenant.settings.headless.allowed_origins = vec![
            "https://spa.example.test".into(),
            "https://*.example.test".into(),
            "https://a.example.test/path".into(),
            "http://localhost:5173".into(),
        ];
        d.tenant.settings.par.require_pushed_authorization_requests = true;
        let got = paths(validate_document(&d, &validators()));
        assert_eq!(
            got,
            [
                "tenant.settings.headless.allowed_origins[1]",
                "tenant.settings.headless.allowed_origins[2]",
                "tenant.settings.headless.allowed_origins[3]",
                "clients[0].consent_mode",
                "clients[1].headless_native",
            ]
        );
        // Development mode accepts the localhost origin.
        let dev = Validators {
            dev_mode: true,
            ..validators()
        };
        let got = paths(validate_document(&d, &dev));
        assert!(
            !got.contains(&"tenant.settings.headless.allowed_origins[3]".to_owned()),
            "{got:?}"
        );
    }

    #[test]
    fn invalid_redirect_uri_names_the_exact_path() {
        let mut d = three_clients();
        d.clients[2].redirect_uris = vec!["http://evil.example.test/cb".into()];
        let issues = validate_document(&d, &validators()).unwrap_err();
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].path, "clients[2].redirect_uris[0]");
        assert!(issues[0].message.contains("https"), "{issues:?}");
    }

    #[test]
    fn every_problem_is_reported_with_its_path() {
        let mut d = three_clients();
        d.clients[1].post_logout_redirect_uris =
            vec!["https://ok.example.test/".into(), "http://x.test/".into()];
        d.roles[1].name = "Not Valid".into();
        d.webhooks[0].url = "http://hooks.example.test/".into();
        d.webhooks[0].events.clear();
        d.email_templates.push(EmailTemplateSection {
            kind: "nope".into(),
            subject: "s".into(),
            body_html: "h".into(),
            body_text: "t".into(),
        });
        d.email_templates.push(EmailTemplateSection {
            kind: "verification".into(),
            subject: "{{ bad }}".into(),
            body_html: "h".into(),
            body_text: "t".into(),
        });
        d.attributes[0].schema = json!(true);
        let got = paths(validate_document(&d, &validators()));
        for want in [
            "clients[1].post_logout_redirect_uris[1]",
            "roles[1].name",
            "webhooks[0].url",
            "webhooks[0].events",
            "email_templates[0].kind",
            "email_templates[1].subject",
            "attributes[0].schema",
        ] {
            assert!(got.iter().any(|p| p == want), "{want} missing in {got:?}");
        }
    }

    #[test]
    fn duplicate_keys_name_the_later_entry() {
        let mut d = doc();
        d.roles.push(d.roles[0].clone());
        let issues = validate_document(&d, &validators()).unwrap_err();
        assert_eq!(issues[0].path, "roles[2].name");
        assert!(issues[0].message.contains("roles[0]"));
    }

    #[test]
    fn secret_rules_per_kind() {
        let mut d = doc();
        d.clients[0].secret = Some(SecretInput::Configured { configured: false });
        d.webhooks[0].secret = Some(SecretInput::Configured { configured: false });
        let got = paths(validate_document(&d, &validators()));
        assert!(got.contains(&"clients[0].secret".to_owned()), "{got:?}");
        assert!(got.contains(&"webhooks[0].secret".to_owned()), "{got:?}");

        let mut d = doc();
        d.clients[0].secret = Some(inline("short"));
        d.webhooks[0].secret = Some(inline("not-a-whsec"));
        let issues = validate_document(&d, &validators()).unwrap_err();
        let got: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(got, ["clients[0].secret", "webhooks[0].secret"]);
        // Messages never echo the value.
        assert!(issues.iter().all(|i| !i.message.contains("short")));

        let mut d = doc();
        d.clients[0].client_type = ClientType::Public;
        d.clients[0].auth_method = ClientAuthMethod::None;
        d.clients[0].secret = Some(inline("a-secret-for-a-public-client-xxxxxx"));
        assert!(paths(validate_document(&d, &validators())).contains(&"clients[0].secret".into()));
    }

    #[test]
    fn system_tenant_rules() {
        let mut d = doc();
        d.tenant.slug = SYSTEM_TENANT_SLUG.into();
        validate_document(&d, &validators()).unwrap();
        d.tenant.settings.dcr.policy = DcrPolicy::Open;
        d.tenant.settings.cimd.policy = CimdPolicy::AllowListed;
        d.tenant.settings.cimd.allowed_hosts = vec!["mcp.example".into()];
        d.clients[0].client_id = CONSOLE_CLIENT_ID.into();
        let got = paths(validate_document(&d, &validators()));
        assert_eq!(
            got,
            [
                "tenant.settings.dcr.policy",
                "tenant.settings.cimd.policy",
                "clients[0].client_id"
            ]
        );
        // Other tenants may enable both.
        let mut d = doc();
        d.tenant.settings.dcr.policy = DcrPolicy::Open;
        validate_document(&d, &validators()).unwrap();
    }

    #[test]
    fn captcha_and_unknown_versions_are_refused() {
        let mut d = doc();
        d.version = 2;
        d.tenant.settings.captcha = Some(crate::model::CaptchaSettings {
            provider: crate::model::CaptchaProvider::Turnstile,
            site_key: "k".into(),
            secret_sealed: "sealed".into(),
        });
        let got = paths(validate_document(&d, &validators()));
        assert_eq!(got, ["version", "tenant.settings.captcha"]);
    }

    #[test]
    fn branding_must_name_a_client_of_the_document() {
        let mut d = doc();
        d.branding
            .push(serde_json::from_value(json!({"client_id": "ghost"})).unwrap());
        assert_eq!(
            paths(validate_document(&d, &validators())),
            ["branding[0].client_id"]
        );
    }

    fn at() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn stored_tenant(slug: &str) -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: slug.into(),
            display_name: "Acme".into(),
            host: None,
            settings: TenantSettings::default(),
            created_at: at(),
        }
    }

    fn stored_client(t: &Tenant, client_id: &str, source: ClientSource) -> StoredClient {
        StoredClient {
            id: ClientId::new_v7(),
            tenant_id: t.id,
            client_id: client_id.into(),
            name: "Web".into(),
            client_type: ClientType::Confidential,
            application_type: App::Web,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            secret_hash: Some(SecretHash([7; 32])),
            jwks: None,
            redirect_uris: vec!["https://app.example.test/cb".into()],
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec!["openid".into()],
            require_pkce: true,
            token_format: TokenFormat::default(),
            consent_mode: ConsentMode::default(),
            id_token_signed_response_alg: None,
            can_introspect: false,
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            allowed_resources: vec![],
            mfa_policy: None,
            registration_source: source,
            metadata_expires_at: None,
            registration_access_token_hash: None,
            created_at: at(),
            updated_at: at(),
            organization: crate::model::OrgClientPolicy::Off,
            require_pushed_authorization_requests: false,
            client_kind: crate::model::ClientKind::Application,
            headless_native: false,
            client_uri: None,
            initiate_login_uri: None,
        }
    }

    fn stored(t: Tenant, clients: Vec<StoredClient>) -> StoredConfig {
        let role = StoredRole {
            id: RoleId::new_v7(),
            tenant_id: t.id,
            org_id: None,
            name: "viewer".into(),
            description: String::new(),
            permissions: vec!["orders:read".into()],
            created_at: at(),
            updated_at: at(),
        };
        let hook = WebhookEndpoint {
            id: WebhookEndpointId::new_v7(),
            tenant_id: t.id,
            name: "crm".into(),
            url: "https://hooks.example.test/anvil".into(),
            events: vec![WebhookEventType::UserCreated],
            enabled: true,
            secret_enc: vec![1, 2, 3],
            previous_secret_enc: None,
            previous_secret_expires_at: None,
            disabled_reason: None,
            created_at: at(),
            updated_at: at(),
        };
        StoredConfig {
            clients,
            connections: vec![],
            branding: vec![],
            roles: vec![role],
            attributes: vec![],
            templates: vec![],
            smtp: Some(SmtpSettings {
                host: "smtp.example.test".into(),
                port: 587,
                username: Some("mailer".into()),
                password_enc: Some(vec![9; 40]),
                from: "id@example.test".into(),
                tls: SmtpTls::Starttls,
                updated_at: at(),
            }),
            webhooks: vec![hook],
            tenant: t,
            orgs: vec![],
        }
    }

    #[test]
    fn export_keeps_static_clients_only_and_secrets_as_configured() {
        let t = stored_tenant("acme");
        let clients = vec![
            stored_client(&t, "web", ClientSource::Static),
            stored_client(&t, "dyn-123", ClientSource::Dynamic),
            stored_client(
                &t,
                "https://mcp.example.test/client.json",
                ClientSource::Cimd,
            ),
        ];
        let s = stored(t, clients);
        let d = s.document();
        let ids: Vec<&str> = d.clients.iter().map(|c| c.client_id.as_str()).collect();
        assert_eq!(ids, ["web"]);
        assert_eq!(
            d.clients[0].secret,
            Some(SecretInput::Configured { configured: true })
        );
        assert_eq!(
            d.webhooks[0].secret,
            Some(SecretInput::Configured { configured: true })
        );
        assert_eq!(
            d.smtp.as_ref().unwrap().password,
            Some(SecretInput::Configured { configured: true })
        );
        assert!(s.is_runtime_client("dyn-123") && !s.is_runtime_client("web"));
        let text = serde_json::to_string(&d).unwrap();
        // Natural keys only: no database ids, no hashes, no sealed bytes.
        for id in [
            s.tenant.id.to_string(),
            s.clients[0].id.to_string(),
            s.roles[0].id.to_string(),
            s.webhooks[0].id.to_string(),
        ] {
            assert!(!text.contains(&id), "{id} in {text}");
        }
        assert!(!text.contains("secret_hash") && !text.contains("password_enc"));
        assert!(!text.contains("secret_enc"));
        // The export is a valid document and plans empty against itself.
        validate_document(&d, &validators()).unwrap();
        assert!(plan(&d, &normalize_document(&d), &never_equal).is_empty());
    }

    #[test]
    fn system_export_omits_the_console_client_and_forces_dcr_off() {
        let mut t = stored_tenant(SYSTEM_TENANT_SLUG);
        t.settings.dcr.policy = DcrPolicy::Open;
        t.settings.cimd.policy = CimdPolicy::AllowListed;
        let clients = vec![
            stored_client(&t, CONSOLE_CLIENT_ID, ClientSource::Static),
            stored_client(&t, "automation", ClientSource::Static),
        ];
        let s = stored(t, clients);
        let d = s.document();
        let ids: Vec<&str> = d.clients.iter().map(|c| c.client_id.as_str()).collect();
        assert_eq!(ids, ["automation"]);
        assert_eq!(d.tenant.settings.dcr.policy, DcrPolicy::Disabled);
        assert_eq!(d.tenant.settings.cimd.policy, CimdPolicy::Disabled);
        assert!(s.is_runtime_client(CONSOLE_CLIENT_ID));
        validate_document(&d, &validators()).unwrap();
    }

    #[test]
    fn normalisation_makes_reapplying_plan_empty() {
        let t = stored_tenant("acme");
        let s = stored(t, vec![]);
        let mut messy = s.document();
        messy.tenant.display_name = "  Acme ".into();
        messy.roles[0].permissions = vec!["orders:read".into(), "orders:read".into()];
        messy.roles[0].description = "  ".into();
        messy.webhooks[0].events = vec![WebhookEventType::UserCreated; 2];
        if let Some(smtp) = messy.smtp.as_mut() {
            smtp.host = " SMTP.Example.TEST ".into();
        }
        assert!(!plan(&s.document(), &messy, &never_equal).is_empty());
        assert!(plan(&s.document(), &normalize_document(&messy), &never_equal).is_empty());
    }

    #[test]
    fn email_settings_wait_for_smtp() {
        let desired = TenantSettings {
            email_otp: true,
            magic_link: true,
            ..TenantSettings::default()
        };
        let s = first_pass_settings(&desired, None, false);
        assert!(!s.email_otp && !s.magic_link);
        assert_eq!(first_pass_settings(&desired, None, true), desired);
        let on = TenantSettings {
            email_otp: true,
            ..TenantSettings::default()
        };
        let s = first_pass_settings(&desired, Some(&on), false);
        assert!(s.email_otp && !s.magic_link);
    }

    #[test]
    fn stored_state_checks() {
        let kek = Kek::generate();
        let t = stored_tenant("acme");
        let mut s = stored(
            t,
            vec![stored_client(
                &stored_tenant("x"),
                "web",
                ClientSource::Static,
            )],
        );
        s.clients
            .push(stored_client(&s.tenant, "dyn-1", ClientSource::Dynamic));
        let mut d = s.document();
        d.clients[0].auth_method = ClientAuthMethod::ClientSecretPost;
        let mut dynamic = d.clients[0].clone();
        dynamic.client_id = "dyn-1".into();
        d.clients.push(dynamic);
        // SMTP password kept but none stored.
        s.smtp.as_mut().unwrap().password_enc = None;
        let got: Vec<String> = check_against_stored(Some(&s), &d, false, false, &kek)
            .into_iter()
            .map(|i| i.path)
            .collect();
        assert_eq!(
            got,
            [
                "clients[0].auth_method",
                "clients[1].client_id",
                "smtp.password"
            ]
        );
        // A new tenant must get its connection secrets inline.
        let mut fresh = d.clone();
        fresh.clients.clear();
        fresh.smtp = None;
        fresh.connections.push(
            serde_json::from_value(json!({
                "slug": "google", "display_name": "Google",
                "config": {"type": "social", "provider": "google", "client_id": "abc"},
                "secret": {"configured": true},
            }))
            .unwrap_or_else(|e| panic!("connection fixture: {e}")),
        );
        let got: Vec<String> = check_against_stored(None, &fresh, false, false, &kek)
            .into_iter()
            .map(|i| i.path)
            .collect();
        assert_eq!(got, ["connections[0].secret"]);
    }

    fn org_owned(s: &mut StoredConfig) {
        let org = Some(OrgId::new_v7());
        let mut org_role = s.roles[0].clone();
        org_role.id = RoleId::new_v7();
        org_role.org_id = org;
        org_role.name = "org-admin".into();
        s.roles.push(org_role);
        s.connections.push(Connection {
            id: crate::model::ConnectionId::new_v7(),
            tenant_id: s.tenant.id,
            org_id: org,
            slug: "acme-sso".into(),
            display_name: "Acme SSO".into(),
            enabled: true,
            config: serde_json::from_value(
                json!({"type": "social", "provider": "google", "client_id": "abc"}),
            )
            .unwrap_or_else(|e| panic!("connection config: {e}")),
            secret_enc: None,
            trust_email_verified: false,
            created_at: at(),
            updated_at: at(),
        });
    }

    #[test]
    fn org_owned_objects_are_neither_exported_nor_pruned() {
        let mut s = stored(stored_tenant("acme"), vec![]);
        let before = s.document();
        org_owned(&mut s);
        let d = s.document();
        assert_eq!(d, before, "org-owned objects never appear in the document");
        assert!(d.connections.is_empty());
        assert_eq!(d.roles.len(), 1);
        // A document without them plans no delete, even for a prune.
        let mut empty = d.clone();
        empty.roles.clear();
        let p = plan(&s.document(), &empty, &never_equal);
        let deletes: Vec<&str> = p.deletes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(deletes, ["viewer"]);
    }

    #[test]
    fn a_document_connection_cannot_take_an_org_connection_slug() {
        let kek = Kek::generate();
        let mut s = stored(stored_tenant("acme"), vec![]);
        org_owned(&mut s);
        let mut d = s.document();
        d.connections.push(
            serde_json::from_value(json!({
                "slug": "acme-sso", "display_name": "Mine",
                "config": {"type": "social", "provider": "google", "client_id": "abc"},
                "secret": {"value": "s3cret"},
            }))
            .unwrap_or_else(|e| panic!("connection fixture: {e}")),
        );
        let got: Vec<String> = check_against_stored(Some(&s), &d, false, false, &kek)
            .into_iter()
            .map(|i| i.path)
            .collect();
        assert_eq!(got, ["connections[0].slug"]);
    }

    #[test]
    fn system_clients_refuse_org_admin_and_org_policy() {
        let mut d = doc();
        d.tenant.slug = SYSTEM_TENANT_SLUG.into();
        d.clients.truncate(1);
        d.clients[0]
            .scopes
            .push(crate::service::admin_scope::ORG_ADMIN_SCOPE.into());
        d.clients[0].organization = crate::model::OrgClientPolicy::Required;
        let got = paths(validate_document(&d, &validators()));
        assert!(got.contains(&"clients[0].scopes".to_owned()), "{got:?}");
        assert!(
            got.contains(&"clients[0].organization".to_owned()),
            "{got:?}"
        );
        // The same client is valid in an application tenant.
        let mut app = doc();
        app.clients.truncate(1);
        app.clients[0]
            .scopes
            .push(crate::service::admin_scope::ORG_ADMIN_SCOPE.into());
        app.clients[0].organization = crate::model::OrgClientPolicy::Required;
        assert_eq!(
            paths(validate_document(&app, &validators())),
            Vec::<String>::new()
        );
    }

    fn with_orgs(orgs: Value) -> TenantConfigDocument {
        let mut d = serde_json::to_value(doc()).unwrap();
        d["organizations"] = orgs;
        serde_json::from_value(d).unwrap()
    }

    fn acme_org() -> Value {
        json!([{
            "slug": "globex",
            "display_name": "Globex",
            "settings": {"default_roles": ["member"]},
            "roles": [{"name": "member", "permissions": ["docs:read"]}],
            "connections": [{
                "slug": "globex-sso",
                "display_name": "Globex SSO",
                "enabled": false,
                "config": {"type": "oidc", "issuer": "https://idp.globex.example.test", "client_id": "anvil"},
                "secret": {"configured": true},
            }],
            "domains": [{"domain": "globex.example.test", "connection": "globex-sso"}],
            "branding": {"tokens": {"radius_px": 2}},
        }])
    }

    #[test]
    fn config_absent_organizations_plans_nothing_for_them() {
        let cur = with_orgs(acme_org());
        let des = doc();
        let p = plan(&cur, &des, &never_equal);
        assert!(p.is_empty(), "{p:?}");
        // An empty list manages organizations but never deletes one.
        let des = with_orgs(json!([]));
        assert!(plan(&cur, &des, &never_equal).is_empty());
    }

    #[test]
    fn org_objects_plan_by_natural_key_and_the_org_is_never_deleted() {
        use ConfigObjectKind as K;
        let des = with_orgs(acme_org());
        let p = plan(&doc(), &des, &never_equal);
        let creates: Vec<(K, &str)> = p.creates.iter().map(|c| (c.kind, c.key.as_str())).collect();
        assert_eq!(
            creates,
            [
                (K::Organization, "globex"),
                (K::OrgRole, "globex/member"),
                (K::OrgConnection, "globex/globex-sso"),
                (K::OrgDomain, "globex/globex.example.test"),
                (K::OrgBranding, "globex"),
            ]
        );
        assert!(render(&p).contains("+ organization role globex/member"));
        // The entry without its roles, connections, domains and branding: prune-only deletes of
        // the owned objects, never of the organization.
        let mut fewer = serde_json::to_value(&des).unwrap();
        for k in ["roles", "connections", "domains", "branding"] {
            fewer["organizations"][0].as_object_mut().unwrap().remove(k);
        }
        fewer["organizations"][0]["settings"]["default_roles"] = json!([]);
        let fewer: TenantConfigDocument = serde_json::from_value(fewer).unwrap();
        let p = plan(&des, &fewer, &never_equal);
        let mut deletes: Vec<(K, &str)> =
            p.deletes.iter().map(|c| (c.kind, c.key.as_str())).collect();
        deletes.sort();
        assert_eq!(
            deletes,
            [
                (K::OrgRole, "globex/member"),
                (K::OrgConnection, "globex/globex-sso"),
                (K::OrgDomain, "globex/globex.example.test"),
                (K::OrgBranding, "globex"),
            ]
        );
        assert!(!p.deletes.iter().any(|c| c.kind == K::Organization));
        assert_eq!(p.updates.len(), 1, "{p:?}");
        assert_eq!(p.updates[0].kind, K::Organization);
        // An organization missing from the list is not deleted either.
        let other = with_orgs(json!([{"slug": "initech", "display_name": "Initech"}]));
        let p = plan(&des, &other, &never_equal);
        assert!(p.deletes.is_empty(), "{p:?}");
        assert_eq!(p.creates[0].kind, K::Organization);
    }

    const PNG_1X1: &[u8] = &[
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, b'I', b'H', b'D', b'R',
    ];

    #[test]
    fn logos_compare_by_hash_absent_keeps_and_null_equals_none() {
        let sha = logo_hash(PNG_1X1);
        let mut cur = doc();
        cur.branding = vec![
            serde_json::from_value(json!({
                "logo": {"sha256": sha, "content_type": "image/png"}
            }))
            .unwrap(),
        ];
        // Absent logo: the stored logo is kept, no change.
        let mut des = cur.clone();
        des.branding[0].logo = None;
        assert!(plan(&cur, &des, &never_equal).is_empty());
        // The same image inline: no change.
        des.branding[0].logo = Some(Some(LogoInput::Data {
            data: anvil_jose::encoding::b64std(PNG_1X1),
        }));
        assert!(plan(&cur, &des, &never_equal).is_empty());
        // null clears it.
        des.branding[0].logo = Some(None);
        let p = plan(&cur, &des, &never_equal);
        assert_eq!(p.updates.len(), 1);
        assert_eq!(p.updates[0].fields[0].field, "logo");
        // null against no stored logo: no change.
        let mut none = cur.clone();
        none.branding[0].logo = None;
        assert!(plan(&none, &des, &never_equal).is_empty());
    }

    #[test]
    fn decode_logo_applies_the_upload_rules() {
        let b64 = anvil_jose::encoding::b64std;
        let (bytes, ty) = decode_logo(&b64(PNG_1X1)).unwrap();
        assert_eq!((bytes.as_slice(), ty), (PNG_1X1, "image/png"));
        // Line breaks (YAML block scalars) are ignored.
        let wrapped = b64(PNG_1X1).chars().fold(String::new(), |mut s, c| {
            s.push(c);
            if s.len() % 9 == 0 {
                s.push('\n');
            }
            s
        });
        assert!(decode_logo(&wrapped).is_ok());
        let svg = b64(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        assert!(decode_logo(&svg).unwrap_err().contains("PNG, JPEG or WebP"));
        assert!(decode_logo(&b64(b"plain text")).is_err());
        assert!(decode_logo("not base64 !!").unwrap_err().contains("base64"));
        // Too large is refused from the length, before decoding.
        let big = "A".repeat(MAX_LOGO_BASE64 + 4);
        assert!(decode_logo(&big).unwrap_err().contains("256 KiB"));
        let mut over = PNG_1X1.to_vec();
        over.resize(MAX_LOGO_BYTES + 1, 0);
        assert!(decode_logo(&b64(&over)).unwrap_err().contains("256 KiB"));
    }
}
