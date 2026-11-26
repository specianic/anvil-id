//! Versioned wire types of the headless flow API (`/api/flows/v1`), mapped from the engine's
//! [`FormDescription`]. The internal struct is never serialised: the engine can change without
//! breaking v1, and nothing internal (the form `action`, the method, the CSRF token inside the
//! form, flow state, cookie values, password values) can leak through a new field.
//!
//! # Versioning rules (v1)
//!
//! Additions are backwards compatible and need no new version: new response fields, new
//! `step` values, new form ids, new field kinds, new method kinds and new message keys. Clients
//! must ignore unknown fields, steps and methods, and treat a field kind they do not know as
//! [`FieldKindDto::Unknown`] (do not render it; never submit a value for it). Removing or
//! renaming anything is a new version (`/api/flows/v2`).
//!
//! Labels and messages are keys plus arguments (`label_key`, `key` + `args`). `label` and `text`
//! are only present when the request asked for a locale (`?ui_locales=`), filled by the same
//! catalogs as the built-in pages.

use std::collections::BTreeMap;

use anvil_core::flow::form::{FieldKind, FormDescription, FormField, FormMessage, MessageLevel};
use anvil_core::model::{CaptchaProvider, CaptchaSettings, FlowKind};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::ToSchema;

use crate::ui::flow_driver::LoginMethod;

/// RFC 3339 timestamp. The domain only holds times inside years 0..=9999, which always format.
pub(crate) fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

/// The answer to every flow request that is not a problem.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FlowResponse {
    pub flow: FlowRef,
    pub step: Step,
    /// Browser mode: the flow's CSRF token. Send it back in the `X-CSRF-Token` header with every
    /// request about this flow. Present while the flow continues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csrf_token: Option<String>,
    /// Native mode, start answer only: the flow token (high entropy, returned once). Send it in
    /// the `Authorization: AnvilFlow <flow_token>` header with every later request about this
    /// flow; keep it in memory only and never log it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_token: Option<String>,
    /// `step = form`: what to show and submit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form: Option<FormDto>,
    /// `step = message`: the flow finished with this message (for example "check your email").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageDto>,
    /// `step = completed`: where the browser goes next (browser mode), or the authorization
    /// code (native mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultDto>,
    /// `step = browser_required`: navigate the top-level browser window here (the built-in
    /// pages finish the step: upstream, SAML and enterprise single sign-on). Native mode: open
    /// this authorization URL in the system browser (RFC 8252); the same authorization request
    /// continues there and the code arrives at the app's redirect URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Seconds until the form can be submitted again (a lock, HTTP 429; also `Retry-After`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

/// The flow a response belongs to.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FlowRef {
    /// Flow id (UUID): the `{flow_id}` of the follow-up requests.
    pub id: String,
    pub kind: FlowKindDto,
    /// When the flow expires (RFC 3339). Absent once the flow has finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// The flow kinds of the API (the `{kind}` path segment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowKindDto {
    Login,
    Registration,
    Recovery,
    Verification,
}

impl FlowKindDto {
    pub(crate) fn core(self) -> FlowKind {
        match self {
            Self::Login => FlowKind::Login,
            Self::Registration => FlowKind::Registration,
            Self::Recovery => FlowKind::Recovery,
            Self::Verification => FlowKind::Verification,
        }
    }

    /// The API kind of a core flow kind (`None` for kinds the API does not run).
    pub(crate) fn from_core(kind: FlowKind) -> Option<Self> {
        match kind {
            FlowKind::Login => Some(Self::Login),
            FlowKind::Registration => Some(Self::Registration),
            FlowKind::Recovery => Some(Self::Recovery),
            FlowKind::Verification => Some(Self::Verification),
            _ => None,
        }
    }
}

/// What the client does next. New values may be added (clients must ignore unknown steps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Step {
    /// Render `form` and submit it.
    Form,
    /// Show `message`; the flow is finished.
    Message,
    /// Signed in (or stepped up): follow `result`.
    Completed,
    /// Navigate the top-level window to `url`.
    BrowserRequired,
}

/// A form to render (`form.id` names the step: `login`, `login-identify`, `login-sso-choice`,
/// `second-factor`, `mfa-enroll`, `email-code`, `registration`, `recovery`, `recovery-reset`,
/// `verification`; more may be added).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FormDto {
    pub id: String,
    pub fields: Vec<FieldDto>,
    /// Form-level messages.
    pub messages: Vec<MessageDto>,
    /// Ways to sign in this form offers (sign-in forms only; empty otherwise).
    pub methods: Vec<MethodDto>,
    /// `mfa-enroll`: the authenticator-app secret to show once (as text and as a QR code of
    /// `otpauth_uri`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpDto>,
    /// The next submission must carry a CAPTCHA response of this provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha: Option<CaptchaDto>,
}

/// One input field. Hidden fields (for example `factor_token`) are submitted back unchanged.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FieldDto {
    pub name: String,
    pub kind: FieldKindDto,
    /// Message key of the label (`field.email`).
    pub label_key: String,
    /// The label in the requested locale (only with `?ui_locales=`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub required: bool,
    /// HTML `autocomplete` token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autocomplete: Option<String>,
    /// Prefill value. Never present for `password` fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub messages: Vec<MessageDto>,
}

/// Input kind. `unknown` stands for any kind a newer server may add: clients must not render
/// it and must not submit a value for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldKindDto {
    Text,
    Email,
    Password,
    Hidden,
    Unknown,
}

impl From<FieldKind> for FieldKindDto {
    fn from(kind: FieldKind) -> Self {
        match kind {
            FieldKind::Text => Self::Text,
            FieldKind::Email => Self::Email,
            FieldKind::Password => Self::Password,
            FieldKind::Hidden => Self::Hidden,
        }
    }
}

/// A message on a form or field.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MessageDto {
    pub level: MessageLevelDto,
    /// Stable message key (`login.invalid_credentials`).
    pub key: String,
    /// Values interpolated into the text, by argument name.
    pub args: BTreeMap<String, String>,
    /// The text in the requested locale (only with `?ui_locales=`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Message severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageLevelDto {
    Info,
    Error,
}

/// A way to sign in. New kinds may be added (clients must ignore unknown kinds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MethodDto {
    /// Submit `method: password` with `identifier` and `password`.
    Password,
    /// WebAuthn: `POST …/login/{flow_id}/passkey/options`, then `POST …/login/{flow_id}/passkey`.
    Passkey,
    /// Submit `method: email_code_request` with `email`.
    EmailCode,
    /// The emailed link (sent by the same `email_code_request`); it opens the built-in page.
    MagicLink,
    /// A social or OIDC connection: submit `method: upstream` with `slug` for the
    /// `browser_required` URL.
    Upstream { slug: String, name: String },
    /// "Continue with single sign-on" (submit `method: identify` with `choice: sso`).
    Sso,
}

impl From<&LoginMethod> for MethodDto {
    fn from(m: &LoginMethod) -> Self {
        match m {
            LoginMethod::Password => Self::Password,
            LoginMethod::Passkey => Self::Passkey,
            LoginMethod::EmailCode => Self::EmailCode,
            LoginMethod::MagicLink => Self::MagicLink,
            LoginMethod::Upstream { slug, name } => Self::Upstream {
                slug: slug.clone(),
                name: name.clone(),
            },
            LoginMethod::Sso => Self::Sso,
        }
    }
}

/// The pending authenticator-app secret of the enrolment step.
#[derive(Clone, Serialize, ToSchema)]
pub struct TotpDto {
    pub secret: String,
    pub otpauth_uri: String,
}

impl std::fmt::Debug for TotpDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpDto { .. }")
    }
}

/// The CAPTCHA widget to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CaptchaDto {
    pub provider: CaptchaProviderDto,
    pub site_key: String,
}

/// CAPTCHA providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaProviderDto {
    Turnstile,
    Hcaptcha,
}

impl From<&CaptchaSettings> for CaptchaDto {
    fn from(s: &CaptchaSettings) -> Self {
        Self {
            provider: match s.provider {
                CaptchaProvider::Turnstile => CaptchaProviderDto::Turnstile,
                CaptchaProvider::Hcaptcha => CaptchaProviderDto::Hcaptcha,
            },
            site_key: s.site_key.clone(),
        }
    }
}

/// The outcome of a completed sign-in.
#[derive(Clone, Default, Serialize, ToSchema)]
pub struct ResultDto {
    /// Browser mode: absolute URL on the AnvilID origin: navigate the top-level window there
    /// (the authorization request continues and the client receives its code). Absent when the
    /// sign-in continues nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continue_to: Option<String>,
    /// Native mode: the authorization code. Redeem it at the token endpoint with the PKCE
    /// `code_verifier` of the pushed request (single use, 60 seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Native mode: the issuer of the response (RFC 9207); compare it with the expected issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Native mode: the pushed request's `state`, when it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Native mode: the authorization ended with this OAuth error instead of a code (for
    /// example `access_denied`); `error_description` is client-safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// Recovery codes of a second factor enrolled in this flow: show them once before
    /// following `continue_to`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for ResultDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResultDto")
            .field("continue_to", &self.continue_to)
            .field("code", &self.code.as_ref().map(|_| "[redacted]"))
            .field("iss", &self.iss)
            .field("state", &self.state)
            .field("error", &self.error)
            .field("recovery_codes", &self.recovery_codes.len())
            .finish()
    }
}

/// RFC 9457 problem details (`application/problem+json`) of the flow API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FlowProblem {
    /// `urn:anvilid:problem:flows:{code}`.
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    /// Stable error code (`forbidden_origin`, `csrf`, `unsupported_media_type`,
    /// `invalid_request`, `not_found`, `flow_not_found`, `invalid_flow_state`,
    /// `registration_disabled`, `method_not_available`, `captcha_required`, `captcha_failed`,
    /// `passkey_failed`, `too_many_requests`, `server_error`; native mode: `browser_signals`,
    /// `flow_token`, `client_not_eligible`, `invalid_request_uri`, `pkce_required`,
    /// `login_required`, `authorization_failed`; more may be added).
    pub code: String,
    /// Seconds to wait (`too_many_requests`; also `Retry-After`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// The CAPTCHA to solve (`captcha_required`, `captcha_failed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha: Option<CaptchaDto>,
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/// `POST /api/flows/v1/{kind}`: start a flow. Every member is optional; an empty object starts a
/// plain flow. A body with `client_id` or `request_uri` is a native start (login only, both
/// required).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct StartRequest {
    /// The authorization request (`request` query parameter of the sign-in redirect) the flow
    /// continues.
    pub request: Option<String>,
    /// Verification and recovery: the token from the emailed link.
    pub token: Option<String>,
    /// Native mode: the client the `request_uri` was pushed by (a `headless_native` client).
    pub client_id: Option<String>,
    /// Native mode: the `request_uri` from the client's `POST /par` (single use).
    pub request_uri: Option<String>,
}

impl StartRequest {
    /// Whether the body asks for a native start.
    pub(crate) fn is_native(&self) -> bool {
        self.client_id.is_some() || self.request_uri.is_some()
    }
}

/// `POST /api/flows/v1/{kind}/{flow_id}`: submit the current step.
#[derive(Clone, Default, Deserialize, ToSchema)]
pub struct SubmitRequest {
    /// What is submitted. Defaults: `password` (login), `register` (registration), `verify`
    /// (verification), `recovery_reset` when `values.token` is present, else `recovery_request`
    /// (recovery).
    pub method: Option<SubmitMethod>,
    /// The form's field values by field name (hidden fields included).
    #[serde(default)]
    pub values: BTreeMap<String, String>,
    /// CAPTCHA widget response, when the form asked for one.
    pub captcha: Option<CaptchaAnswerDto>,
}

impl std::fmt::Debug for SubmitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Values carry passwords and codes: names only.
        f.debug_struct("SubmitRequest")
            .field("method", &self.method)
            .field("values", &self.values.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SubmitRequest {
    /// A submitted value, `None` when absent or blank.
    pub(crate) fn value(&self, name: &str) -> Option<String> {
        self.values
            .get(name)
            .filter(|v| !v.trim().is_empty())
            .cloned()
    }
}

/// What a submission is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubmitMethod {
    /// Login: `identifier`, `password`.
    Password,
    /// Login, email-first page: `identifier`; on the single-sign-on choice `choice` = `sso`,
    /// `password` or `change`.
    Identify,
    /// Login, second factor or enrolment: `code`, `factor_token`.
    Totp,
    /// Login, second factor: `recovery_code`, `factor_token`.
    RecoveryCode,
    /// Login: send a sign-in email to `email` (or, with `factor_token` only, a new one).
    EmailCodeRequest,
    /// Login, email step: `code`, `factor_token`.
    EmailCode,
    /// Login: sign in with the connection `slug` (answers `browser_required`).
    Upstream,
    /// Registration: `email`, `password`, optional `name`.
    Register,
    /// Recovery: `email`.
    RecoveryRequest,
    /// Recovery, reset step: `token`, `password`.
    RecoveryReset,
    /// Verification: `token`.
    Verify,
}

/// A CAPTCHA widget response.
#[derive(Clone, Default, Deserialize, ToSchema)]
pub struct CaptchaAnswerDto {
    /// Cloudflare Turnstile (`cf-turnstile-response`).
    pub turnstile: Option<String>,
    /// hCaptcha (`h-captcha-response`).
    pub hcaptcha: Option<String>,
}

/// Passkey sub-routes: the WebAuthn response from `navigator.credentials.*` (its `toJSON()`).
#[derive(Clone, Default, Deserialize, ToSchema)]
pub struct PasskeyRequest {
    /// `PublicKeyCredential.toJSON()` (object). Not needed for the options requests.
    #[schema(value_type = Object)]
    pub response: Option<serde_json::Value>,
    /// The second-factor token of the enrolment or second-factor form (finish routes).
    pub factor_token: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------------------------

/// What a form shows beyond the engine's description.
#[derive(Default)]
pub(crate) struct FormExtras {
    /// Added as the hidden field `factor_token` (second-factor, enrolment and email steps).
    pub(crate) factor_token: Option<String>,
    pub(crate) totp: Option<TotpDto>,
    pub(crate) captcha: Option<CaptchaDto>,
    /// Native start only: the flow token, answered once as [`FlowResponse::flow_token`] (never
    /// part of the form).
    pub(crate) flow_token: Option<String>,
}

/// The hidden field that carries the step's binding token.
const FACTOR_TOKEN_FIELD: &str = "factor_token";

/// Maps an engine form to the v1 DTO. `localized`: copy the display texts (the form was
/// localised for an explicit `ui_locales`). Password values are never copied.
pub(crate) fn form_dto(
    form: &FormDescription,
    methods: &[LoginMethod],
    localized: bool,
    extras: FormExtras,
) -> FormDto {
    let mut fields: Vec<FieldDto> = form
        .fields
        .iter()
        .filter(|f| f.name != FACTOR_TOKEN_FIELD)
        .map(|f| field_dto(f, localized))
        .collect();
    if let Some(token) = extras.factor_token {
        fields.push(FieldDto {
            name: FACTOR_TOKEN_FIELD.into(),
            kind: FieldKindDto::Hidden,
            label_key: String::new(),
            label: None,
            required: true,
            autocomplete: None,
            value: Some(token),
            messages: Vec::new(),
        });
    }
    FormDto {
        id: form.id.clone(),
        fields,
        messages: form
            .messages
            .iter()
            .map(|m| message_dto(m, localized))
            .collect(),
        methods: methods.iter().map(MethodDto::from).collect(),
        totp: extras.totp,
        captcha: extras.captcha,
    }
}

fn field_dto(f: &FormField, localized: bool) -> FieldDto {
    let kind = FieldKindDto::from(f.kind);
    FieldDto {
        name: f.name.clone(),
        kind,
        label_key: f.label_key.clone(),
        label: (localized && !f.label.is_empty()).then(|| f.label.clone()),
        required: f.required,
        autocomplete: f.autocomplete.clone(),
        // Secrets are never echoed back.
        value: if kind == FieldKindDto::Password {
            None
        } else {
            f.value.clone()
        },
        messages: f
            .messages
            .iter()
            .map(|m| message_dto(m, localized))
            .collect(),
    }
}

/// Maps an engine message (`localized`: copy its text).
pub(crate) fn message_dto(m: &FormMessage, localized: bool) -> MessageDto {
    MessageDto {
        level: match m.level {
            MessageLevel::Info => MessageLevelDto::Info,
            MessageLevel::Error => MessageLevelDto::Error,
        },
        key: m.key.clone(),
        args: m.args.clone(),
        text: (localized && !m.text.is_empty()).then(|| m.text.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, kind: FieldKind, value: Option<&str>) -> FormField {
        FormField {
            name: name.into(),
            kind,
            label_key: format!("field.{name}"),
            label: format!("Label {name}"),
            value: value.map(str::to_owned),
            required: true,
            autocomplete: Some("username".into()),
            messages: vec![FormMessage::error("field.invalid").with_arg("n", 1)],
        }
    }

    fn form() -> FormDescription {
        let mut m = FormMessage::error("login.invalid_credentials");
        m.text = "Wrong".into();
        FormDescription {
            id: "login".into(),
            action: "https://op.test/ui/login?flow=0190a6d4-0000-7000-8000-000000000001".into(),
            method: "post",
            fields: vec![
                field("identifier", FieldKind::Email, Some("a@example.com")),
                field("password", FieldKind::Password, Some("hunter2-secret")),
                field("note", FieldKind::Text, None),
                field("token", FieldKind::Hidden, Some("tok")),
            ],
            messages: vec![m],
            csrf_token: "csrf-secret-value".into(),
        }
    }

    #[test]
    fn each_field_kind_maps_to_its_dto_kind() {
        let dto = form_dto(&form(), &[], false, FormExtras::default());
        let kinds: Vec<_> = dto.fields.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FieldKindDto::Email,
                FieldKindDto::Password,
                FieldKindDto::Text,
                FieldKindDto::Hidden
            ]
        );
        let json = serde_json::to_value(FieldKindDto::Unknown).expect("json");
        assert_eq!(json, "unknown");
    }

    #[test]
    fn password_values_are_never_echoed() {
        let dto = form_dto(&form(), &[], true, FormExtras::default());
        let pw = dto
            .fields
            .iter()
            .find(|f| f.name == "password")
            .expect("pw");
        assert_eq!(pw.value, None);
        let json = serde_json::to_string(&dto).expect("json");
        assert!(!json.contains("hunter2-secret"), "{json}");
    }

    #[test]
    fn internal_members_are_not_serialised() {
        let dto = form_dto(&form(), &[], false, FormExtras::default());
        let json = serde_json::to_value(&dto).expect("json");
        let obj = json.as_object().expect("object");
        for k in ["action", "method", "csrf_token"] {
            assert!(!obj.contains_key(k), "{k} in {json}");
        }
        let text = json.to_string();
        assert!(!text.contains("csrf-secret-value"));
        assert!(!text.contains("/ui/login"));
    }

    #[test]
    fn texts_only_when_localized() {
        let plain = serde_json::to_value(form_dto(&form(), &[], false, FormExtras::default()))
            .expect("json");
        assert!(plain["fields"][0].get("label").is_none());
        assert!(plain["messages"][0].get("text").is_none());
        assert_eq!(plain["messages"][0]["key"], "login.invalid_credentials");
        assert_eq!(plain["fields"][0]["messages"][0]["args"]["n"], "1");
        let localized = serde_json::to_value(form_dto(&form(), &[], true, FormExtras::default()))
            .expect("json");
        assert_eq!(localized["fields"][0]["label"], "Label identifier");
        assert_eq!(localized["messages"][0]["text"], "Wrong");
    }

    #[test]
    fn methods_come_from_the_driver_list() {
        let methods = vec![
            LoginMethod::Password,
            LoginMethod::Passkey,
            LoginMethod::EmailCode,
            LoginMethod::MagicLink,
            LoginMethod::Upstream {
                slug: "gh".into(),
                name: "GitHub".into(),
            },
            LoginMethod::Sso,
        ];
        let dto = form_dto(&form(), &methods, false, FormExtras::default());
        let json = serde_json::to_value(&dto.methods).expect("json");
        assert_eq!(
            json,
            serde_json::json!([
                {"kind": "password"},
                {"kind": "passkey"},
                {"kind": "email_code"},
                {"kind": "magic_link"},
                {"kind": "upstream", "slug": "gh", "name": "GitHub"},
                {"kind": "sso"}
            ])
        );
    }

    #[test]
    fn factor_token_is_one_hidden_field() {
        let mut f = form();
        f.fields
            .push(field("factor_token", FieldKind::Hidden, Some("old")));
        let dto = form_dto(
            &f,
            &[],
            false,
            FormExtras {
                factor_token: Some("sealed".into()),
                ..FormExtras::default()
            },
        );
        let tokens: Vec<_> = dto
            .fields
            .iter()
            .filter(|f| f.name == "factor_token")
            .collect();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, FieldKindDto::Hidden);
        assert_eq!(tokens[0].value.as_deref(), Some("sealed"));
    }

    #[test]
    fn submit_request_debug_hides_values() {
        let r: SubmitRequest = serde_json::from_value(serde_json::json!({
            "method": "password",
            "values": {"identifier": "a@example.com", "password": "hunter2-secret"}
        }))
        .expect("parses");
        let dbg = format!("{r:?}");
        assert!(!dbg.contains("hunter2-secret"), "{dbg}");
        assert_eq!(r.method, Some(SubmitMethod::Password));
        assert_eq!(r.value("password").as_deref(), Some("hunter2-secret"));
        assert_eq!(r.value("missing"), None);
    }

    #[test]
    fn captcha_settings_map_without_the_secret() {
        let s = CaptchaSettings {
            provider: CaptchaProvider::Hcaptcha,
            site_key: "site".into(),
            secret_sealed: "sealed-secret".into(),
        };
        let json = serde_json::to_string(&CaptchaDto::from(&s)).expect("json");
        assert_eq!(json, r#"{"provider":"hcaptcha","site_key":"site"}"#);
    }
}
