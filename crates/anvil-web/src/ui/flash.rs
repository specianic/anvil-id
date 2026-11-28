//! The one-shot flash of Post/Redirect/Get on the end-user flow pages (U-M1).
//!
//! A failed form POST (wrong password, invalid email, wrong code, ...) does not render the form
//! in the POST response. It answers `303 See Other` to a `GET` of the same flow page
//! (`?flow={id}`) and sets this cookie; the `GET` shows the current step of the flow again with
//! the messages and the non-secret values from the flash and clears it. Back never lands on a
//! POST answer (no `ERR_CACHE_MISS`) and reload never posts the credentials again.
//!
//! | | |
//! |---|---|
//! | name | `{prefix}anvil_flash_{t}` (the tenant part and prefix of the flow cookie, `cookies.rs`) |
//! | attributes | HttpOnly, SameSite=Strict, Path=/ (a `__Host-` cookie cannot be scoped by path; the tenant is part of the name), Secure on https, Max-Age [`MAX_AGE_SECS`] |
//! | value | base64url of the payload sealed with the KEK, purpose [`FLASH_PURPOSE`], AAD tenant id ‖ flow id |
//!
//! The payload ([`Flash`]) holds message keys and arguments (form- and field-level), the id of
//! the form they belong to, whether the CAPTCHA widget is due, and only the values in
//! [`FlashValues`]: the identifier (or email) and the name. Passwords, codes, CAPTCHA answers and
//! factor tokens are never in it; the type has no place for them. The one exception is the
//! reset token of the new-password form (a failed reset must keep the emailed link usable): it
//! is sealed with the rest, never in plaintext, and the flow state never stores it.
//!
//! A flash that does not open for the flow and tenant of the `GET` (another flow, another
//! tenant, tampered, another key) is ignored, and every read clears the cookie.

use std::collections::BTreeMap;

use anvil_core::flow::form::{FieldKind, FormDescription, FormMessage, MessageLevel};
use anvil_core::model::{FlowId, Tenant, TenantId};
use anvil_jose::Kek;
use anvil_jose::encoding::{b64url, b64url_decode};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// KEK purpose of the flash payload.
pub(crate) const FLASH_PURPOSE: &str = "anvilid/ui-flash/v1";

/// Lifetime of the flash cookie: it only has to survive the redirect.
pub(crate) const MAX_AGE_SECS: i64 = 60;

/// The form id of the new-password form, the only form whose (sealed) flash keeps a token.
const RESET_FORM_ID: &str = "recovery-reset";

/// The values a re-shown form gets back. Nothing secret has a field here: no password, code,
/// one-time password, CAPTCHA answer or token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FlashValues {
    /// The identifier or email address that was typed (field `identifier` or `email`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) identifier: Option<String>,
    /// The display name of a registration (field `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
}

/// A message key with its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FlashMessage {
    error: bool,
    key: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    args: BTreeMap<String, String>,
}

impl FlashMessage {
    fn of(m: &FormMessage) -> Self {
        Self {
            error: m.level == MessageLevel::Error,
            key: m.key.clone(),
            args: m.args.clone(),
        }
    }

    fn to_message(&self) -> FormMessage {
        let level = if self.error {
            MessageLevel::Error
        } else {
            MessageLevel::Info
        };
        let mut m = FormMessage::new(level, &self.key);
        m.args = self.args.clone();
        m
    }
}

/// The flash of a failed POST (module docs).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Flash {
    /// The form the messages belong to; a `GET` showing another form ignores them.
    form_id: String,
    #[serde(default)]
    messages: Vec<FlashMessage>,
    /// Field-level messages by field name.
    #[serde(default)]
    field_errors: BTreeMap<String, Vec<FlashMessage>>,
    #[serde(default)]
    values: FlashValues,
    /// The brute-force gate asks for the CAPTCHA widget on the next attempt.
    #[serde(default)]
    captcha: bool,
    /// The reset token of the new-password form (sealed with the rest; module docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reset_token: Option<String>,
}

impl Flash {
    /// The flash of a rendered `form`: its messages and the values [`FlashValues`] allows.
    pub(crate) fn from_form(form: &FormDescription, captcha: bool) -> Self {
        let value_of = |names: &[&str]| {
            form.fields
                .iter()
                .find(|f| names.contains(&f.name.as_str()) && f.kind != FieldKind::Password)
                .and_then(|f| f.value.clone())
                .filter(|v| !v.trim().is_empty())
        };
        let field_errors = form
            .fields
            .iter()
            .filter(|f| !f.messages.is_empty())
            .map(|f| {
                (
                    f.name.clone(),
                    f.messages.iter().map(FlashMessage::of).collect(),
                )
            })
            .collect();
        let reset_token = (form.id == RESET_FORM_ID)
            .then(|| {
                form.fields
                    .iter()
                    .find(|f| f.name == "token" && f.kind == FieldKind::Hidden)
                    .and_then(|f| f.value.clone())
            })
            .flatten();
        Self {
            form_id: form.id.clone(),
            messages: form.messages.iter().map(FlashMessage::of).collect(),
            field_errors,
            values: FlashValues {
                identifier: value_of(&["identifier", "email"]),
                name: value_of(&["name"]),
            },
            captcha,
            reset_token,
        }
    }

    /// The id of the form the flash belongs to.
    pub(crate) fn form_id(&self) -> &str {
        &self.form_id
    }

    /// Whether the brute-force gate asked for the CAPTCHA widget.
    pub(crate) fn captcha(&self) -> bool {
        self.captcha
    }

    /// Puts the messages and values back into `form` when it is the form the flash belongs to
    /// (else `form` is unchanged). A value goes only into an empty, non-password field.
    pub(crate) fn apply(&self, form: &mut FormDescription) {
        if form.id != self.form_id {
            return;
        }
        form.messages = self.messages.iter().map(FlashMessage::to_message).collect();
        for field in &mut form.fields {
            if let Some(msgs) = self.field_errors.get(&field.name) {
                field.messages = msgs.iter().map(FlashMessage::to_message).collect();
            }
            if field.kind == FieldKind::Password || field.value.is_some() {
                continue;
            }
            field.value = match field.name.as_str() {
                "identifier" | "email" => self.values.identifier.clone(),
                "name" => self.values.name.clone(),
                "token" if self.form_id == RESET_FORM_ID => self.reset_token.clone(),
                _ => None,
            };
        }
    }
}

fn aad(tenant: TenantId, flow: FlowId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(flow.0.as_bytes());
    aad
}

/// Seals `flash` for `flow` of `tenant` (base64url).
pub(crate) fn seal(kek: &Kek, tenant: TenantId, flow: FlowId, flash: &Flash) -> Option<String> {
    let json = serde_json::to_vec(flash).ok()?;
    kek.seal(FLASH_PURPOSE, &aad(tenant, flow), &json)
        .inspect_err(|e| tracing::error!(error = %e, "sealing the flash failed"))
        .ok()
        .map(|s| b64url(&s))
}

/// Opens a sealed flash, if it was sealed for `flow` of `tenant` with this key.
pub(crate) fn open(kek: &Kek, tenant: TenantId, flow: FlowId, value: &str) -> Option<Flash> {
    let raw = b64url_decode(value).ok()?;
    let plain = kek.open(FLASH_PURPOSE, &aad(tenant, flow), &raw).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// The flash cookie's name for `tenant`: the flow cookie's prefix and tenant id.
pub(crate) fn cookie_name(state: &AppState, tenant: &Tenant) -> String {
    state
        .cookies()
        .flow_name(tenant)
        .replacen("anvil_flow_", "anvil_flash_", 1)
}

fn build(state: &AppState, tenant: &Tenant, value: String, max_age: i64) -> Cookie<'static> {
    Cookie::build((cookie_name(state, tenant), value))
        .http_only(true)
        .secure(state.cookies().is_secure())
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(max_age))
        .build()
}

/// The cookie carrying `flash` for `flow`; `None` (logged) when sealing fails, in which case the
/// `GET` shows the step without messages.
pub(crate) fn write(
    state: &AppState,
    tenant: &Tenant,
    flow: FlowId,
    flash: &Flash,
) -> Option<Cookie<'static>> {
    let value = seal(state.kek(), tenant.id, flow, flash)?;
    Some(build(state, tenant, value, MAX_AGE_SECS))
}

/// Reads the flash for `flow` from `jar` and returns it (when it opens for this flow and tenant)
/// together with `jar` clearing the cookie (whenever one was sent: a flash is read once).
pub(crate) fn take(
    state: &AppState,
    tenant: &Tenant,
    flow: FlowId,
    jar: &CookieJar,
    out: CookieJar,
) -> (Option<Flash>, CookieJar) {
    let name = cookie_name(state, tenant);
    let Some(cookie) = jar.get(&name) else {
        return (None, out);
    };
    let flash = open(state.kek(), tenant.id, flow, cookie.value());
    (flash, out.add(build(state, tenant, String::new(), 0)))
}

#[cfg(test)]
mod tests {
    use anvil_core::flow::form::FormField;

    use super::*;

    fn field(name: &str, kind: FieldKind, value: Option<&str>) -> FormField {
        FormField {
            name: name.into(),
            kind,
            label_key: format!("field.{name}"),
            label: String::new(),
            value: value.map(str::to_owned),
            required: true,
            autocomplete: None,
            messages: Vec::new(),
        }
    }

    fn form(id: &str, fields: Vec<FormField>) -> FormDescription {
        FormDescription {
            id: id.into(),
            action: "/ui/login?flow=x".into(),
            method: "post",
            fields,
            messages: vec![FormMessage::error("login.invalid_credentials")],
            csrf_token: "csrf-value".into(),
        }
    }

    #[test]
    fn round_trip_restores_messages_and_values_once_for_its_form() {
        let kek = Kek::generate();
        let (tenant, flow) = (TenantId::new_v7(), FlowId::new_v7());
        let mut posted = form(
            "registration",
            vec![
                field("email", FieldKind::Email, Some("a@example.com")),
                field("password", FieldKind::Password, None),
                field("name", FieldKind::Text, Some("Ada")),
            ],
        );
        posted.fields[1]
            .messages
            .push(FormMessage::error("password.too_short").with_arg("min", 12));
        let flash = Flash::from_form(&posted, true);
        let sealed = seal(&kek, tenant, flow, &flash).expect("seal");
        let opened = open(&kek, tenant, flow, &sealed).expect("opens");
        assert_eq!(opened, flash);
        assert!(opened.captcha());

        let mut shown = form(
            "registration",
            vec![
                field("email", FieldKind::Email, None),
                field("password", FieldKind::Password, None),
                field("name", FieldKind::Text, None),
            ],
        );
        shown.messages.clear();
        opened.apply(&mut shown);
        assert_eq!(shown.messages, posted.messages);
        assert_eq!(shown.fields[0].value.as_deref(), Some("a@example.com"));
        assert_eq!(shown.fields[1].value, None);
        assert_eq!(shown.fields[1].messages, posted.fields[1].messages);
        assert_eq!(shown.fields[2].value.as_deref(), Some("Ada"));

        // Another form: untouched.
        let mut other = form("login", vec![field("identifier", FieldKind::Email, None)]);
        other.messages.clear();
        let before = other.clone();
        opened.apply(&mut other);
        assert_eq!(other, before);
    }

    #[test]
    fn flash_from_other_flow_or_tenant_is_ignored() {
        let kek = Kek::generate();
        let (tenant, flow) = (TenantId::new_v7(), FlowId::new_v7());
        let flash = Flash::from_form(&form("login", Vec::new()), false);
        let sealed = seal(&kek, tenant, flow, &flash).expect("seal");
        assert!(open(&kek, tenant, FlowId::new_v7(), &sealed).is_none());
        assert!(open(&kek, TenantId::new_v7(), flow, &sealed).is_none());
        assert!(open(&Kek::generate(), tenant, flow, &sealed).is_none());
        assert!(open(&kek, tenant, flow, "garbage").is_none());
        let mut tampered = sealed.clone();
        let last = if sealed.ends_with('A') { "B" } else { "A" };
        tampered.replace_range(sealed.len() - 1.., last);
        assert!(open(&kek, tenant, flow, &tampered).is_none());
    }

    #[test]
    fn flash_never_contains_password_or_code() {
        let kek = Kek::generate();
        let (tenant, flow) = (TenantId::new_v7(), FlowId::new_v7());
        // Even a form that (wrongly) carried secret values: only identifier and name survive.
        let posted = form(
            "second-factor",
            vec![
                field("identifier", FieldKind::Email, Some("a@example.com")),
                field("password", FieldKind::Password, Some("hunter2-secret")),
                field("code", FieldKind::Text, Some("123456")),
                field("recovery_code", FieldKind::Text, Some("ABCD-EFGH")),
                field("otp", FieldKind::Text, Some("654321")),
                field(
                    "cf-turnstile-response",
                    FieldKind::Hidden,
                    Some("captcha-x"),
                ),
                field("factor_token", FieldKind::Hidden, Some("factor-tok")),
                field("token", FieldKind::Hidden, Some("reset-tok")),
            ],
        );
        let flash = Flash::from_form(&posted, false);
        let plain = serde_json::to_string(&flash).expect("json");
        for secret in [
            "hunter2-secret",
            "123456",
            "ABCD-EFGH",
            "654321",
            "captcha-x",
            "factor-tok",
            "reset-tok",
            "csrf-value",
        ] {
            assert!(!plain.contains(secret), "{secret} in {plain}");
        }
        assert!(plain.contains("a@example.com"));
        // And the cookie value is sealed: not even the identifier is readable.
        let sealed = seal(&kek, tenant, flow, &flash).expect("seal");
        assert!(!sealed.contains("example"));
    }

    #[test]
    fn reset_token_is_kept_sealed_for_the_new_password_form_only() {
        let kek = Kek::generate();
        let (tenant, flow) = (TenantId::new_v7(), FlowId::new_v7());
        let posted = form(
            RESET_FORM_ID,
            vec![
                field("token", FieldKind::Hidden, Some("reset-token-value")),
                field("password", FieldKind::Password, None),
            ],
        );
        let flash = Flash::from_form(&posted, false);
        let sealed = seal(&kek, tenant, flow, &flash).expect("seal");
        assert!(!sealed.contains("reset-token-value"));
        let mut shown = form(
            RESET_FORM_ID,
            vec![
                field("token", FieldKind::Hidden, None),
                field("password", FieldKind::Password, None),
            ],
        );
        open(&kek, tenant, flow, &sealed)
            .expect("opens")
            .apply(&mut shown);
        assert_eq!(shown.fields[0].value.as_deref(), Some("reset-token-value"));
    }
}
