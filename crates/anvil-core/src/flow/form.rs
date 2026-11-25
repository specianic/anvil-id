//! Form description: the contract between the flow engine, the themes and the web renderer.
//!
//! Templates render `id = name = field.name` for every field and `id = "{form.id}-submit"` for
//! the submit button.
//!
//! Core produces no display text: fields carry a `label_key` and messages a `key` (plus `args`
//! for interpolated values). `label` and `text` are left empty by core and filled by the
//! presentation layer for the negotiated locale (anvil-web `i18n::localize_form`); headless API
//! clients may translate the keys themselves.

use std::collections::BTreeMap;

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
    /// Stable message key of the label, e.g. `field.email`.
    pub label_key: String,
    /// Display label: empty from core, filled by the presentation layer.
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
    /// Values interpolated into the text (e.g. `seconds` of a lock), by argument name.
    pub args: BTreeMap<String, String>,
    /// Display text: empty from core, filled by the presentation layer.
    pub text: String,
}

impl FormMessage {
    /// A message without arguments.
    pub fn new(level: MessageLevel, key: &str) -> Self {
        Self {
            level,
            key: key.to_owned(),
            args: BTreeMap::new(),
            text: String::new(),
        }
    }

    /// An error message without arguments.
    pub fn error(key: &str) -> Self {
        Self::new(MessageLevel::Error, key)
    }

    /// Adds an interpolated argument.
    #[must_use]
    pub fn with_arg(mut self, name: &str, value: impl ToString) -> Self {
        self.args.insert(name.to_owned(), value.to_string());
        self
    }
}

/// Message severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLevel {
    Info,
    Error,
}
