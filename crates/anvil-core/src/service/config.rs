//! Declarative tenant configuration: plan/diff (05-10), export and apply (05-20) (ADM-07).
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

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;

use crate::error::CoreError;
use crate::model::{
    ConfigChange, ConfigObjectKind, ConfigPlan, FieldDiff, SecretInput, TenantConfigDocument,
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
        differ.section(kind, cur, des);
    }
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
            ConfigObjectKind::Tenant | ConfigObjectKind::Smtp => continue,
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
}
