//! Form description: the contract between the flow engine, the themes and the web renderer.
//!
//! Templates render `id = name = field.name` for every field and `id = "{form.id}-submit"` for
//! the submit button.

use serde::Serialize;

/// A form to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormDescription {
    /// `login`, `registration`, `recovery`, `recovery-reset`, `verification` or `setup`.
    pub id: String,
    pub action: String,
    /// Always `"post"`.
    pub method: &'static str,
    pub fields: Vec<FormField>,
    /// Form-level messages.
    pub messages: Vec<FormMessage>,
    pub csrf_token: String,
}

/// One input field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormField {
    pub name: String,
    pub kind: FieldKind,
    pub label: String,
    /// Prefill value. Never set for [`FieldKind::Password`].
    pub value: Option<String>,
    pub required: bool,
    pub autocomplete: Option<String>,
    /// Field-level messages.
    pub messages: Vec<FormMessage>,
}

/// HTML input kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Email,
    Password,
    Hidden,
}

/// A message shown on a form or field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FormMessage {
    pub level: MessageLevel,
    /// Stable id, e.g. `login.invalid_credentials`.
    pub key: String,
    /// Display text.
    pub text: String,
}

/// Message severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLevel {
    Info,
    Error,
}
