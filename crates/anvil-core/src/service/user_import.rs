//! User import (ADM-08): record validation, idempotency and audit, shared by the admin API and
//! the `anvilid users import` CLI. There is no other import path.
//!
//! # Records
//!
//! Input is NDJSON, one user per line ([`RawRecord`]). A line is a JSON object with these keys
//! (unknown keys are refused):
//!
//! - `email` (required): normalised like admin user creation (`model::normalize_email`);
//! - `email_verified` (default `false`);
//! - `claims`: OIDC standard claims (`StandardClaims`);
//! - `attributes`: custom attribute values, validated against the tenant's definitions like an
//!   administrator write (`attribute::plan_values`, replace mode);
//! - `id`: optional UUID. A valid UUID that is not used yet becomes the user id, so `sub`
//!   survives an AnvilID-to-AnvilID migration (decision Q11). A used id is `id_conflict`; any
//!   other id format is `invalid_record` (keep non-UUID source ids in a custom attribute);
//! - `password`: optional imported hash, the `policy::password_import::ImportPassword` shapes,
//!   converted once into the stored encoding (`convert_import`).
//!
//! # Outcomes
//!
//! The idempotency key is (tenant, normalised email). Per record: `created`; `unchanged` (the user
//! exists and the content hash matches); `conflict` (exists with different data; never
//! overwritten unless `update` is set, then `updated`); `rejected` with a reason code
//! ([`RejectReason`]). Re-running the same input yields only `unchanged`. A dry run returns the
//! same report and writes nothing (apart from its one `users_imported` audit event, which says
//! `dry_run: true`).
//!
//! The content hash is SHA-256 over the canonical JSON (sorted keys) of the record without the
//! password, plus the SHA-256 of the converted stored hash, computed in memory on both the
//! record and the stored user; it is never stored or logged. A record without `password` leaves
//! the stored credential out of the comparison and untouched. After the first sign-in rehash
//! (Argon2id) a re-run reports `conflict` for a record with a password, and `update` would reset
//! the password to the imported hash.
//!
//! A user and its password credential are created in one storage transaction
//! (`UserRepo::create`); custom attributes are written right after (validated beforehand, so only
//! a storage failure can separate them; a re-run then reports `conflict`).
//!
//! # Audit and secrecy
//!
//! One `users_imported` event per batch (counts per outcome, weak count, source label, dry-run
//! flag), and `user_created` / `user_updated` per written user (details: reason `imported`, or the
//! changed field names). No hash, salt or password field appears in audit details, errors, the
//! report or any `Debug` output of the types here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use anvil_jose::encoding::sha256;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AttributeDefinition, AuditAction, AuditActor, AuditDetails, AuditOutcome,
    NewPasswordCredential, NewUser, RequestContext, StandardClaims, TenantId, User, UserId,
    UserStatus, UserUpdate, normalize_email,
};
use crate::policy::password_import::{
    HashPolicyError, ImportPassword, convert_import, parse_import_value,
};
use crate::ports::{AttributeSchemaCheck, Storage, StorageError};
use crate::service::attribute::{WriteMode, plan_values};
use crate::service::audit::AuditService;

/// Hard cap on the records of one [`UserImportService::import`] call (the CLI batches files in
/// chunks of this size; the admin route refuses larger bodies).
pub const IMPORT_BATCH_MAX: usize = 1000;
/// Longest accepted record line in bytes.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Longest source label in characters.
pub const MAX_SOURCE_LEN: usize = 64;

/// One input line: its 1-based line number and text. `Debug` prints the line number and length
/// only (the text can carry a password hash).
#[derive(Clone, PartialEq, Eq)]
pub struct RawRecord {
    pub line: usize,
    pub text: String,
}

impl fmt::Debug for RawRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRecord")
            .field("line", &self.line)
            .field("len", &self.text.len())
            .finish()
    }
}

impl RawRecord {
    /// Splits an NDJSON body into records, skipping blank lines (line numbers stay those of the
    /// body).
    pub fn from_ndjson(body: &str) -> Vec<RawRecord> {
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| RawRecord {
                line: i + 1,
                text: l.to_owned(),
            })
            .collect()
    }
}

/// A parsed record. `Debug` redacts the password.
#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecord {
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub claims: StandardClaims,
    #[serde(default)]
    pub attributes: Map<String, Value>,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub password: Option<Value>,
}

impl fmt::Debug for ImportRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportRecord")
            .field("email", &self.email)
            .field("email_verified", &self.email_verified)
            .field("claims", &self.claims)
            .field("attributes", &self.attributes.keys().collect::<Vec<_>>())
            .field("id", &self.id)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Per-record outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Created,
    Unchanged,
    Conflict,
    Updated,
    Rejected,
}

/// Why a record was rejected (the report's reason code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    InvalidEmail,
    InvalidRecord,
    UnknownScheme,
    WeakParameters,
    OverCap,
    RefusedVariant,
    UnknownProfile,
    IdConflict,
}

impl RejectReason {
    /// The reason code (same string as the serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidEmail => "invalid_email",
            Self::InvalidRecord => "invalid_record",
            Self::UnknownScheme => "unknown_scheme",
            Self::WeakParameters => "weak_parameters",
            Self::OverCap => "over_cap",
            Self::RefusedVariant => "refused_variant",
            Self::UnknownProfile => "unknown_profile",
            Self::IdConflict => "id_conflict",
        }
    }
}

impl From<HashPolicyError> for RejectReason {
    fn from(e: HashPolicyError) -> Self {
        match e {
            HashPolicyError::UnknownScheme => Self::UnknownScheme,
            HashPolicyError::WeakParameters => Self::WeakParameters,
            HashPolicyError::OverCap => Self::OverCap,
            HashPolicyError::RefusedVariant => Self::RefusedVariant,
            HashPolicyError::Malformed => Self::InvalidRecord,
        }
    }
}

/// The outcome of one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordOutcome {
    pub line: usize,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RejectReason>,
    /// The created, updated or matching user (for a dry-run `created`, the preserved id if the
    /// record named one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    /// The imported hash is accepted but below the recommended parameters.
    pub weak: bool,
}

/// Counts per outcome; `weak` counts accepted records with a weak hash.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportCounts {
    pub created: u64,
    pub unchanged: u64,
    pub conflict: u64,
    pub updated: u64,
    pub rejected: u64,
    pub weak: u64,
}

impl ImportCounts {
    fn add(&mut self, r: &RecordOutcome) {
        match r.outcome {
            Outcome::Created => self.created += 1,
            Outcome::Unchanged => self.unchanged += 1,
            Outcome::Conflict => self.conflict += 1,
            Outcome::Updated => self.updated += 1,
            Outcome::Rejected => self.rejected += 1,
        }
        if r.weak && r.outcome != Outcome::Rejected {
            self.weak += 1;
        }
    }

    /// Adds another batch's counts (the CLI aggregates batches).
    pub fn merge(&mut self, other: &ImportCounts) {
        self.created += other.created;
        self.unchanged += other.unchanged;
        self.conflict += other.conflict;
        self.updated += other.updated;
        self.rejected += other.rejected;
        self.weak += other.weak;
    }
}

/// The result of one import call. Serialisable for the admin API; carries no hash material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub dry_run: bool,
    pub counts: ImportCounts,
    pub records: Vec<RecordOutcome>,
}

/// One import call.
#[derive(Debug)]
pub struct ImportRequest<'a> {
    pub records: Vec<RawRecord>,
    pub dry_run: bool,
    /// Overwrite existing users whose data differs (`updated`) instead of reporting `conflict`.
    pub update: bool,
    /// Label of the source system, recorded in the batch audit event.
    pub source: Option<&'a str>,
    pub actor: AuditActor,
    pub ctx: &'a RequestContext,
}

/// Checks the source label (pure).
pub fn check_source(source: Option<&str>) -> Result<(), CoreError> {
    if let Some(s) = source
        && (s.trim().is_empty()
            || s.chars().count() > MAX_SOURCE_LEN
            || s.chars().any(char::is_control))
    {
        return Err(CoreError::Validation {
            field: "source",
            message: "must be 1-64 characters without control characters".into(),
        });
    }
    Ok(())
}

/// Refuses a batch above [`IMPORT_BATCH_MAX`] as a whole (pure).
pub fn check_batch_size(n: usize) -> Result<(), CoreError> {
    if n > IMPORT_BATCH_MAX {
        return Err(CoreError::Validation {
            field: "records",
            message: format!("at most {IMPORT_BATCH_MAX} records per import call"),
        });
    }
    Ok(())
}

/// JSON with object keys sorted at every level (deterministic for hashing).
fn canonical(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let sorted: BTreeMap<&String, Value> =
                    m.iter().map(|(k, v)| (k, sort(v))).collect();
                Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    // Serialising a Value cannot fail.
    serde_json::to_string(&sort(v)).unwrap_or_default()
}

/// The comparable content of a user: what an import record can set.
struct Content<'a> {
    email: &'a str,
    email_verified: bool,
    claims: &'a StandardClaims,
    attributes: &'a Map<String, Value>,
    /// Compared only when the record names an id.
    id: Option<Uuid>,
    /// SHA-256 of the stored hash; compared only when the record carries a password.
    password: Option<Option<[u8; 32]>>,
}

/// SHA-256 over the canonical JSON of the content without the password, followed by the
/// password digest (see the module docs).
fn content_hash(c: &Content<'_>) -> [u8; 32] {
    let mut doc = serde_json::json!({
        "email": c.email,
        "email_verified": c.email_verified,
        "claims": serde_json::to_value(c.claims).unwrap_or(Value::Null),
        "attributes": Value::Object(c.attributes.clone()),
    });
    if let Some(id) = c.id {
        doc["id"] = Value::from(id.to_string());
    }
    let mut bytes = canonical(&doc).into_bytes();
    match c.password {
        None => {}
        Some(None) => bytes.extend_from_slice(b"\0no-password"),
        Some(Some(d)) => {
            bytes.extend_from_slice(b"\0password");
            bytes.extend_from_slice(&d);
        }
    }
    sha256(&bytes)
}

/// A record that passed validation.
struct Validated {
    record: ImportRecord,
    email: String,
    id: Option<Uuid>,
    /// The converted stored hash (never logged) and its weak flag.
    stored: Option<(String, bool)>,
}

/// Parses and validates one line without storage access, except for the Firebase profile
/// lookup done by the caller (the profile id is returned).
fn validate(
    raw: &RawRecord,
    definitions: &[AttributeDefinition],
    check: &dyn AttributeSchemaCheck,
) -> Result<(Validated, Option<Uuid>), RejectReason> {
    if raw.text.len() > MAX_RECORD_BYTES {
        return Err(RejectReason::InvalidRecord);
    }
    // The serde error is dropped: it can quote input.
    let mut record: ImportRecord =
        serde_json::from_str(&raw.text).map_err(|_| RejectReason::InvalidRecord)?;
    let email = normalize_email(&record.email).map_err(|_| RejectReason::InvalidEmail)?;
    let id = match &record.id {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            let u = Uuid::try_parse(s).map_err(|_| RejectReason::InvalidRecord)?;
            if u.is_nil() || u.is_max() {
                return Err(RejectReason::InvalidRecord);
            }
            Some(u)
        }
        Some(_) => return Err(RejectReason::InvalidRecord),
    };
    plan_values(
        definitions,
        &Map::new(),
        &record.attributes,
        WriteMode::Replace,
        check,
    )
    .map_err(|_| RejectReason::InvalidRecord)?;
    let (stored, profile) = match record.password.take() {
        None | Some(Value::Null) => (None, None),
        Some(v) => {
            let input = parse_import_value(v)?;
            let profile = match &input {
                ImportPassword::FirebaseScrypt { profile, .. } => Some(*profile),
                _ => None,
            };
            let converted = convert_import(&input)?;
            (Some((converted.stored, converted.weak)), profile)
        }
    };
    Ok((
        Validated {
            record,
            email,
            id,
            stored,
        },
        profile,
    ))
}

fn rejected(line: usize, reason: RejectReason) -> RecordOutcome {
    RecordOutcome {
        line,
        outcome: Outcome::Rejected,
        reason: Some(reason),
        user_id: None,
        weak: false,
    }
}

/// The user import service (one implementation for the admin API and the CLI).
pub struct UserImportService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub check: Arc<dyn AttributeSchemaCheck>,
}

impl UserImportService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    /// Imports one batch (at most [`IMPORT_BATCH_MAX`] records, else a `Validation` error and
    /// nothing is done). See the module docs for outcomes, idempotency and audit.
    pub async fn import(
        &self,
        tenant: TenantId,
        req: ImportRequest<'_>,
    ) -> Result<ImportReport, CoreError> {
        check_batch_size(req.records.len())?;
        check_source(req.source)?;
        let definitions = self.storage.attributes().list(tenant).await?;
        let mut profiles: HashMap<Uuid, bool> = HashMap::new();
        let mut seen_emails: HashSet<String> = HashSet::new();
        let mut seen_ids: HashSet<Uuid> = HashSet::new();
        let mut records = Vec::with_capacity(req.records.len());
        let mut counts = ImportCounts::default();

        for raw in &req.records {
            let outcome = match validate(raw, &definitions, self.check.as_ref()) {
                Err(reason) => rejected(raw.line, reason),
                Ok((v, profile)) => {
                    let profile_ok = match profile {
                        None => true,
                        Some(p) => match profiles.get(&p) {
                            Some(known) => *known,
                            None => {
                                let known = self
                                    .storage
                                    .password_profiles()
                                    .get(tenant, p)
                                    .await?
                                    .is_some();
                                profiles.insert(p, known);
                                known
                            }
                        },
                    };
                    if !profile_ok {
                        rejected(raw.line, RejectReason::UnknownProfile)
                    } else if !seen_emails.insert(v.email.clone()) {
                        // The same address twice in one batch: ambiguous, refused (a dry run and
                        // a real run must agree).
                        rejected(raw.line, RejectReason::InvalidRecord)
                    } else if v.id.is_some_and(|id| !seen_ids.insert(id)) {
                        rejected(raw.line, RejectReason::IdConflict)
                    } else {
                        self.apply(tenant, raw.line, v, &definitions, &req).await?
                    }
                }
            };
            counts.add(&outcome);
            records.push(outcome);
        }

        let mut details = Map::new();
        for (k, n) in [
            ("created", counts.created),
            ("unchanged", counts.unchanged),
            ("conflict", counts.conflict),
            ("updated", counts.updated),
            ("rejected", counts.rejected),
            ("weak", counts.weak),
        ] {
            details.insert(k.to_owned(), Value::from(n));
        }
        details.insert("dry_run".to_owned(), Value::from(req.dry_run));
        if let Some(s) = req.source {
            details.insert("source".to_owned(), Value::from(s.trim()));
        }
        self.audit()
            .record(
                tenant,
                req.actor.clone(),
                AuditAction::UsersImported,
                None,
                AuditOutcome::Success,
                req.ctx,
                AuditDetails::from_stored(details),
            )
            .await?;
        Ok(ImportReport {
            dry_run: req.dry_run,
            counts,
            records,
        })
    }

    /// Decides and (unless dry run) writes one validated record.
    async fn apply(
        &self,
        tenant: TenantId,
        line: usize,
        v: Validated,
        definitions: &[AttributeDefinition],
        req: &ImportRequest<'_>,
    ) -> Result<RecordOutcome, CoreError> {
        let weak = v.stored.as_ref().is_some_and(|(_, w)| *w);
        let users = self.storage.users();
        let existing = users.get_by_email(tenant, &v.email).await?;
        let Some(user) = existing else {
            if let Some(id) = v.id
                && users.get(tenant, UserId(id)).await?.is_some()
            {
                return Ok(rejected(line, RejectReason::IdConflict));
            }
            if req.dry_run {
                return Ok(RecordOutcome {
                    line,
                    outcome: Outcome::Created,
                    reason: None,
                    user_id: v.id,
                    weak,
                });
            }
            return self.create(tenant, line, v, weak, req).await;
        };

        if v.id.is_some_and(|id| id != user.id.0) {
            return Ok(rejected(line, RejectReason::IdConflict));
        }
        let stored_values = self
            .storage
            .attributes()
            .user_values(tenant, user.id)
            .await?
            .unwrap_or_default();
        let defined: Map<String, Value> = stored_values
            .iter()
            .filter(|(k, _)| definitions.iter().any(|d| &d.name == *k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let stored_phc = if v.stored.is_some() {
            Some(users.password(tenant, user.id).await?.map(|c| c.phc))
        } else {
            None
        };
        let theirs = content_hash(&Content {
            email: &user.email,
            email_verified: user.email_verified,
            claims: &user.claims,
            attributes: &defined,
            id: v.id.map(|_| user.id.0),
            password: stored_phc
                .as_ref()
                .map(|p| p.as_ref().map(|s| sha256(s.as_bytes()))),
        });
        let ours = content_hash(&Content {
            email: &v.email,
            email_verified: v.record.email_verified,
            claims: &v.record.claims,
            attributes: &v.record.attributes,
            id: v.id,
            password: v.stored.as_ref().map(|(s, _)| Some(sha256(s.as_bytes()))),
        });
        let mut outcome = RecordOutcome {
            line,
            outcome: Outcome::Unchanged,
            reason: None,
            user_id: Some(user.id.0),
            weak,
        };
        if ours == theirs {
            return Ok(outcome);
        }
        if !req.update {
            outcome.outcome = Outcome::Conflict;
            return Ok(outcome);
        }
        outcome.outcome = Outcome::Updated;
        if req.dry_run {
            return Ok(outcome);
        }
        self.update(
            tenant,
            &user,
            &v,
            &stored_values,
            &defined,
            stored_phc,
            definitions,
            req,
        )
        .await?;
        Ok(outcome)
    }

    async fn create(
        &self,
        tenant: TenantId,
        line: usize,
        v: Validated,
        weak: bool,
        req: &ImportRequest<'_>,
    ) -> Result<RecordOutcome, CoreError> {
        let now = self.clock.now();
        let id = v.id.map_or_else(UserId::new_v7, UserId);
        let new = NewUser {
            id,
            email: v.email.clone(),
            email_verified: v.record.email_verified,
            username: None,
            claims: v.record.claims.clone(),
            status: UserStatus::Active,
            created_at: now,
        };
        let credential = v.stored.as_ref().map(|(phc, _)| NewPasswordCredential {
            phc: phc.clone(),
            created_at: now,
        });
        let user = match self
            .storage
            .users()
            .create(tenant, &new, credential.as_ref(), None, None)
            .await
        {
            Ok(u) => u,
            // A preserved id used in another tenant, or a concurrent writer of the same email.
            Err(StorageError::Conflict(_)) => {
                return Ok(if v.id.is_some() {
                    rejected(line, RejectReason::IdConflict)
                } else {
                    RecordOutcome {
                        line,
                        outcome: Outcome::Conflict,
                        reason: None,
                        user_id: None,
                        weak,
                    }
                });
            }
            Err(e) => return Err(e.into()),
        };
        if !v.record.attributes.is_empty() {
            self.storage
                .attributes()
                .set_user_values(tenant, user.id, &v.record.attributes, now)
                .await?;
        }
        self.audit()
            .record(
                tenant,
                req.actor.clone(),
                AuditAction::UserCreated,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                req.ctx,
                AuditDetails::reason("imported"),
            )
            .await?;
        Ok(RecordOutcome {
            line,
            outcome: Outcome::Created,
            reason: None,
            user_id: Some(user.id.0),
            weak,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn update(
        &self,
        tenant: TenantId,
        user: &User,
        v: &Validated,
        stored_values: &Map<String, Value>,
        defined: &Map<String, Value>,
        stored_phc: Option<Option<String>>,
        definitions: &[AttributeDefinition],
        req: &ImportRequest<'_>,
    ) -> Result<(), CoreError> {
        let now = self.clock.now();
        let mut fields: Vec<&'static str> = Vec::new();
        let patch = UserUpdate {
            email_verified: (v.record.email_verified != user.email_verified)
                .then_some(v.record.email_verified),
            claims: (v.record.claims != user.claims).then(|| v.record.claims.clone()),
            ..UserUpdate::default()
        };
        if patch.email_verified.is_some() {
            fields.push("email_verified");
        }
        if patch.claims.is_some() {
            fields.push("claims");
        }
        if !fields.is_empty() {
            self.storage
                .users()
                .update(tenant, user.id, &patch, now)
                .await?
                .ok_or(CoreError::NotFound)?;
        }
        if &v.record.attributes != defined {
            let planned = plan_values(
                definitions,
                stored_values,
                &v.record.attributes,
                WriteMode::Replace,
                self.check.as_ref(),
            )
            .map_err(|_| CoreError::Validation {
                field: "attributes",
                message: "stored attribute values do not validate".into(),
            })?;
            self.storage
                .attributes()
                .set_user_values(tenant, user.id, &planned.values, now)
                .await?;
            fields.push("attributes");
        }
        if let Some((phc, _)) = &v.stored
            && stored_phc.flatten().as_deref() != Some(phc.as_str())
        {
            self.storage
                .users()
                .set_password(tenant, user.id, phc, now)
                .await?;
            fields.push("password");
        }
        self.audit()
            .record(
                tenant,
                req.actor.clone(),
                AuditAction::UserUpdated,
                Some(user.id.to_string()),
                AuditOutcome::Success,
                req.ctx,
                AuditDetails::fields(&fields).with(AuditDetails::reason("imported")),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::SchemaIssue;

    /// Accepts every schema and value (attribute validation has its own tests).
    struct AnyValue;
    impl AttributeSchemaCheck for AnyValue {
        fn check_definition(&self, _: &Value) -> Result<(), SchemaIssue> {
            Ok(())
        }
        fn validate(&self, _: &Value, _: &Value) -> Result<(), Vec<String>> {
            Ok(())
        }
    }

    fn raw(text: &str) -> RawRecord {
        RawRecord {
            line: 1,
            text: text.to_owned(),
        }
    }

    fn reason(text: &str) -> RejectReason {
        match validate(&raw(text), &[], &AnyValue) {
            Err(r) => r,
            Ok(_) => panic!("expected a rejection for {text}"),
        }
    }

    const BCRYPT: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

    #[test]
    fn import_batch_cap_enforced() {
        assert!(check_batch_size(IMPORT_BATCH_MAX).is_ok());
        assert!(matches!(
            check_batch_size(IMPORT_BATCH_MAX + 1),
            Err(CoreError::Validation {
                field: "records",
                ..
            })
        ));
    }

    #[test]
    fn rejection_reason_codes() {
        assert_eq!(reason("not json"), RejectReason::InvalidRecord);
        assert_eq!(
            reason(r#"{"email":"a@example.com","nope":1}"#),
            RejectReason::InvalidRecord
        );
        assert_eq!(
            reason(r#"{"email":"no-at-sign"}"#),
            RejectReason::InvalidEmail
        );
        assert_eq!(
            reason(r#"{"email":"a@example.com","id":"legacy-42"}"#),
            RejectReason::InvalidRecord
        );
        assert_eq!(
            reason(r#"{"email":"a@example.com","id":42}"#),
            RejectReason::InvalidRecord
        );
        assert_eq!(
            reason(r#"{"email":"a@example.com","id":"00000000-0000-0000-0000-000000000000"}"#),
            RejectReason::InvalidRecord
        );
        assert_eq!(
            reason(r#"{"email":"a@example.com","password":{"scheme":"md5","hash":"x"}}"#),
            RejectReason::UnknownScheme
        );
        assert_eq!(
            reason(
                r#"{"email":"a@example.com","password":{"scheme":"bcrypt","hash":"$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"}}"#
            ),
            RejectReason::RefusedVariant
        );
        assert_eq!(
            reason(
                r#"{"email":"a@example.com","password":{"scheme":"pbkdf2","prf":"sha256","iterations":10,"salt":{"hex":"0001020304050607"},"hash":{"hex":"000102030405060708090a0b0c0d0e0f"}}}"#
            ),
            RejectReason::WeakParameters
        );
        assert_eq!(
            reason(
                r#"{"email":"a@example.com","password":{"scheme":"scrypt","log_n":24,"r":8,"p":1,"salt":{"hex":"00"},"hash":{"hex":"000102030405060708090a0b0c0d0e0f"}}}"#
            ),
            RejectReason::OverCap
        );
        let long = format!(
            r#"{{"email":"a@example.com","claims":{{"name":"{}"}}}}"#,
            "x".repeat(MAX_RECORD_BYTES)
        );
        assert_eq!(reason(&long), RejectReason::InvalidRecord);
    }

    #[test]
    fn valid_record_keeps_id_and_converts_password() {
        let id = "0192f0c1-1111-7aaa-8bbb-0123456789ab";
        let text = format!(
            r#"{{"email":" Alice@Example.com ","email_verified":true,"id":"{id}","password":{{"scheme":"bcrypt","hash":"{BCRYPT}"}}}}"#
        );
        let (v, profile) = validate(&raw(&text), &[], &AnyValue).unwrap();
        assert_eq!(v.email, "alice@example.com");
        assert_eq!(v.id, Some(Uuid::parse_str(id).unwrap()));
        assert!(profile.is_none());
        let (stored, weak) = v.stored.unwrap();
        assert_eq!(stored, BCRYPT);
        assert!(weak, "bcrypt cost 5 is weak");
        assert!(
            v.record.password.is_none(),
            "the raw password value is dropped"
        );
    }

    #[test]
    fn firebase_record_names_its_profile() {
        let text = r#"{"email":"f@example.com","password":{"scheme":"firebase_scrypt","profile":"0b9a6b7e-1c2d-4e3f-8a9b-0c1d2e3f4a5b","salt":{"base64":"42xEC+ixf3L2lw=="},"hash":{"base64":"lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ=="}}}"#;
        let (_, profile) = validate(&raw(text), &[], &AnyValue).unwrap();
        assert_eq!(
            profile,
            Some(Uuid::parse_str("0b9a6b7e-1c2d-4e3f-8a9b-0c1d2e3f4a5b").unwrap())
        );
    }

    #[test]
    fn content_hash_ignores_key_order_and_sees_every_field() {
        let claims = StandardClaims::default();
        let mut a = Map::new();
        a.insert("b".into(), Value::from(1));
        a.insert("a".into(), serde_json::json!({"y": 1, "x": 2}));
        let mut b = Map::new();
        b.insert("a".into(), serde_json::json!({"x": 2, "y": 1}));
        b.insert("b".into(), Value::from(1));
        let base = |attrs| Content {
            email: "a@example.com",
            email_verified: false,
            claims: &claims,
            attributes: attrs,
            id: None,
            password: None,
        };
        assert_eq!(content_hash(&base(&a)), content_hash(&base(&b)));
        let mut c = base(&a);
        c.email_verified = true;
        assert_ne!(content_hash(&c), content_hash(&base(&a)));
        let mut c = base(&a);
        c.password = Some(Some([1; 32]));
        let mut d = base(&a);
        d.password = Some(Some([2; 32]));
        assert_ne!(content_hash(&c), content_hash(&d));
        let mut e = base(&a);
        e.password = Some(None);
        assert_ne!(content_hash(&c), content_hash(&e));
        let mut f = base(&a);
        f.id = Some(Uuid::now_v7());
        assert_ne!(content_hash(&f), content_hash(&base(&a)));
    }

    #[test]
    fn debug_and_report_never_carry_the_hash() {
        let text = format!(
            r#"{{"email":"a@example.com","password":{{"scheme":"bcrypt","hash":"{BCRYPT}"}}}}"#
        );
        let r = raw(&text);
        assert!(!format!("{r:?}").contains("$2a$"));
        let rec: ImportRecord = serde_json::from_str(&text).unwrap();
        let dbg = format!("{rec:?}");
        assert!(!dbg.contains("$2a$") && dbg.contains("[redacted]"), "{dbg}");
        let mut counts = ImportCounts::default();
        let o = RecordOutcome {
            line: 1,
            outcome: Outcome::Created,
            reason: None,
            user_id: Some(Uuid::now_v7()),
            weak: true,
        };
        counts.add(&o);
        counts.add(&rejected(2, RejectReason::OverCap));
        let report = ImportReport {
            dry_run: false,
            counts,
            records: vec![o, rejected(2, RejectReason::OverCap)],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""reason":"over_cap""#), "{json}");
        assert!(json.contains(r#""weak":1"#), "{json}");
        assert!(!json.contains('$'), "{json}");
    }

    #[test]
    fn ndjson_split_keeps_line_numbers() {
        let recs = RawRecord::from_ndjson("{\"a\":1}\n\n  \n{\"b\":2}\n");
        assert_eq!(recs.iter().map(|r| r.line).collect::<Vec<_>>(), vec![1, 4]);
    }

    #[test]
    fn source_label_checked() {
        assert!(check_source(None).is_ok());
        assert!(check_source(Some("firebase")).is_ok());
        assert!(check_source(Some("")).is_err());
        assert!(check_source(Some(&"x".repeat(65))).is_err());
        assert!(check_source(Some("a\nb")).is_err());
    }
}
