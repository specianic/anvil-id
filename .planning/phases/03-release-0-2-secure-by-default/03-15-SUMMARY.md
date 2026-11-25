---
phase: 03-release-0-2-secure-by-default
plan: 15
subsystem: mail
tags: [email-templates, minijinja, fuel, smtp, lettre, audit, kek]
requires:
  - phase: 03-release-0-2-secure-by-default
    provides: "03-02 MailSettingsRepo, EmailTemplateCheck, SmtpTester, EmailKind/EmailTemplate/SmtpSettings, AuditService; 03-05/03-06 backend implementations"
  - phase: 02-release-0-1-first-login
    provides: "EmailRenderer, OutboxWorker, sealed outbox payloads, SmtpTransport"
provides:
  - "Tenant template overrides rendered by the outbox worker (theme default otherwise)"
  - "TemplateChecker: compile + unknown-variable + fuel-bounded sample render, field and line in the issue"
  - "Per-tenant SMTP transports (TransportFactory / SmtpTransportFactory), installation SMTP optional"
  - "LettreSmtpTester: synchronous 10 s test send with redacted errors"
  - "MailSettingsService for the management API (03-23) and console (03-25)"
affects: [03-12, 03-23, 03-24, 03-25]
tech-stack:
  added: []
  patterns:
    - "One minijinja environment factory (strict undefined, .html autoescape, fuel)"
    - "Seal/open of the SMTP password only in service::mail_settings::{seal_smtp_password, smtp_connection}"
    - "TemplateIssue messages are prefixed with the part name (subject|body_html|body_text) so the field survives the port"
key-files:
  created:
    - crates/anvil-mail/src/check.rs
    - crates/anvil-mail/src/tester.rs
    - crates/anvil-mail/tests/templates.rs
    - crates/anvil-mail/tests/smtp_test.rs
  modified:
    - crates/anvil-mail/src/{lib,render,worker,transport}.rs
    - crates/anvil-mail/tests/{support/mod.rs,worker.rs}
    - crates/anvil-core/src/service/mail_settings.rs
    - crates/anvilid/src/jobs.rs
key-decisions:
  - "Fuel 50,000 per render; the default templates render with 5,000 (tested), so they use under 10%"
  - "Template variable contract = payload keys the core seals: verification/recovery/invitation {tenant_name, email, link, expires_in}; password_changed {tenant_name, email}; recovery_code_used {tenant_name, remaining}"
  - "Unknown variables are found statically (undeclared_variables minus contract minus minijinja globals), so unused branches are checked too; overrides render in a loader-less environment (no include/extends of theme files)"
  - "The outbox worker always runs; transport resolution is tenant SMTP, then installation SMTP, else last_error 'no SMTP configured' with normal backoff"
  - "MailSettingsService.put_template returns TemplateError::Invalid{field,line,message} (From<TemplateError> for CoreError maps to Validation with 'line N: ...')"
  - "test_send only tests the tenant's stored SMTP settings (no settings -> Validation field smtp); the audit event stores outcome and reason smtp_error, never the SMTP error text or recipient"
duration: 55min
completed: 2026-11-25
---

# Phase 3 Plan 15: Tenant email templates, per-tenant SMTP and test send Summary

**Tenants can now override email templates; overrides are compiled and test-rendered with a fuel limit before they are saved. Each tenant can also have its own SMTP settings with a KEK-sealed password, which the outbox worker uses, and a synchronous, audited 10 s test send. MailSettingsService provides all of this to the API and console.**

## Performance

- **Duration:** about 55 min
- **Tasks:** 2
- **Files:** 12 (4 created, 8 modified)

## Accomplishments

- **render.rs:** `environment()` is the single factory. It sets strict undefined, autoescape for `.html` names, and `set_fuel(Some(RENDER_FUEL = 50_000))`. `EmailRenderer::render_with(override, kind, payload)` renders a tenant override when one exists, otherwise it uses `render(kind)` (theme dir, then embedded). Override subjects are their own one-line template. Control characters in a rendered subject become spaces. Fuel errors show up as "template ran out of fuel (runaway loop)".
- **check.rs:** `TemplateChecker` implements `EmailTemplateCheck`. Each part (subject, body_text, body_html) goes through compile, then the static unknown-variable check, then a sample render. The subject must be one line and render non-empty. `variables(kind)` and `sample_context(kind)` are public for 03-23.
- **worker.rs:**
  - `OutboxAccess::mail_settings()` is new, and `StorageOutbox` forwards it to `Storage::mail_settings()`.
  - `OutboxWorker.transport` is now `Option<Arc<dyn MailTransport>>` (installation SMTP), plus a new `transports: Arc<dyn TransportFactory>` field.
  - `SmtpTransportFactory` opens the password with the KEK and caches one transport per tenant, keyed by `updated_at`. It evicts the entry when a tenant's settings disappear.
  - Mail sent through a tenant transport uses the tenant's `from`. If neither tenant nor installation SMTP exists, the row fails with `NO_SMTP_ERROR` and is retried with the normal backoff.
- **transport.rs:** adds `SmtpTransport::from_settings(&SmtpConnection)` and `from_settings_with_timeout`, which validate host, port and sender. It also adds `shutdown()`.
- **tester.rs:** `LettreSmtpTester { timeout }` (default `TEST_SEND_TIMEOUT` = 10 s) builds a transport for each call and wraps the whole send in `tokio::time::timeout`. It shuts the transport down afterwards. Lettre error text (including the server reply) is returned with the username, the password and their base64 forms (AUTH PLAIN token, AUTH LOGIN args) replaced by `[redacted]`.
- **anvilid/jobs.rs:** the worker always starts. Without `smtp_url` the binary logs one warning: only tenants with their own SMTP settings receive mail.

## Variable contract (public, shown by the management API)

| Kind | Variables |
|------|-----------|
| `verification` | `tenant_name`, `email`, `link`, `expires_in` |
| `recovery` | `tenant_name`, `email`, `link`, `expires_in` |
| `invitation` | `tenant_name`, `email`, `link`, `expires_in` |
| `password_changed` | `tenant_name`, `email` |
| `recovery_code_used` | `tenant_name`, `remaining` |

**Note for 03-12:** the `recovery_code_used` payload must use exactly the keys `tenant_name` and `remaining`. Any other key name, such as `remaining_count`, makes valid tenant overrides fail at send time, and the checker rejects templates that use the other name.

## MailSettingsService API (anvil_core::service::mail_settings)

```rust
pub struct MailSettingsService { storage, clock, kek: Arc<Kek>, checker: Arc<dyn EmailTemplateCheck>, tester: Arc<dyn SmtpTester> }
list_templates(tenant) -> Result<Vec<EmailTemplate>, CoreError>
get_template(tenant, kind) -> Result<Option<EmailTemplate>, CoreError>          // None = theme default
put_template(tenant, kind, TemplateInput{subject, body_html, body_text}, actor, &ctx)
    -> Result<EmailTemplate, TemplateError>                                     // Invalid{field, line, message} | Core
reset_template(tenant, kind, actor, &ctx) -> Result<bool, CoreError>            // false = no override, no event
get_smtp(tenant) -> Result<Option<SmtpView>, CoreError>                         // password_set: bool, never the password
put_smtp(tenant, SmtpInput{host, port, username, password: Option<SecretString>, from, tls}, actor, &ctx)
    -> Result<SmtpView, CoreError>
delete_smtp(tenant, actor, &ctx) -> Result<bool, CoreError>
test_send(tenant, to, actor, &ctx) -> Result<TestSendResult{delivered, error}, CoreError>
```

- Limits: subject up to 1,000 bytes, each body up to 64 KiB, password up to 1,024 bytes.
- SMTP validation: the host is lowercased and may not contain a scheme, `@`, `/` or whitespace. Port must be 1..=65535. `from` is `addr` or `Name <addr>`, checked with the core email normaliser.
- An empty or absent password keeps the stored one. Without a username, no password is stored.
- Audit events:
  - `email_template_updated` and `email_template_reset`: target = kind, details `{template}`.
  - `smtp_settings_updated`: details `{fields: [changed field names]}`. On delete, details are `{reason: "deleted"}` instead.
  - `smtp_test_sent`: outcome success or failure. A failure has details `{reason: "smtp_error"}`.
- Helpers for any caller that needs the password: `seal_smtp_password(kek, tenant, &SecretString)` and `smtp_connection(kek, tenant, &SmtpSettings) -> SmtpConnection`.

## Task Commits

1. **Task 1: Template override resolution, checker with fuel, per-tenant transports:** `f2886f5`
2. **Task 2: SMTP tester and MailSettingsService:** `e36a91d`

## Tests

- `cargo test -p anvil-mail`: 19 unit tests, 14 worker tests, 10 template tests and 5 SMTP tests all pass.
  - Worker tests cover override vs default, a broken override failing the row with backoff and no payload leak, tenant vs installation transport, the no-SMTP backoff followed by recovery, and the production factory (sealed password opened, cached by `updated_at`, wrong KEK or tenant refused generically).
  - Template tests cover syntax errors with line numbers, unknown variables (including in branches that are never taken), blocked includes, fuel exhaustion in under 500 ms, `'x' * 1e9` charged before allocation, and autoescape.
  - SMTP tests cover delivery to the sink, a closed port, 535 with the echoed credentials redacted, and a silent server timing out.
- `cargo test -p anvil-core service::mail_settings`: 9 tests, all pass. They cover the planning functions: field and line errors, size limits, sealing and opening per tenant, keeping the stored password, per-field SMTP validation, the redacted view, and the test-send audit mapping.
- `cargo clippy -p anvil-mail -p anvil-core -p anvilid --all-targets -D warnings` is clean, `cargo test -p anvilid` passes, and rustfmt is clean.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] The service's storage path is tested by plan functions, not a fake Storage**
- **Found during:** Task 2
- **Issue:** anvil-core has no in-memory `Storage`. A fake would need about 120 trait methods, and anvil-core cannot dev-depend on a backend because that creates a crate cycle.
- **Fix:** The service methods are thin I/O around pure planners (`plan_template`, `issue_to_error`, `plan_smtp`, `validate_sender`, `changed_fields`, `test_send_audit`). The planners have unit tests. The worker and tester paths are covered end to end in anvil-mail. 03-23's `admin_email` tests (SQLite) should cover the full storage, audit and HTTP path: PUT invalid → 422 with line, GET after PUT, DELETE, test send against a closed port.
- **Commit:** e36a91d

**2. [Rule 2 - Correctness] Field information carried through TemplateIssue**
- **Found during:** Task 1
- **Issue:** The `TemplateIssue` port has only `line` and `message`, but 03-23 needs the field (`subject`, `body_html` or `body_text`).
- **Fix:** `TemplateChecker` prefixes each message with `"{part}: "`. `MailSettingsService` turns the prefix into `TemplateError::Invalid.field` (unprefixed messages get field `template`). `ports.rs` is unchanged.
- **Commits:** f2886f5, e36a91d

### Notes

- The `seal_smtp_password` and `smtp_connection` helpers in `service/mail_settings.rs` landed with Task 1 because the worker's factory needed them. The service itself came in Task 2.
- When the installation has no `smtp_url`, the worker now runs and parks tenant mail after 8 failed attempts (about 2 h of backoff). Before this change such rows stayed queued forever. This follows the plan's specification.

## Issues Encountered

- Other wave-3 plans' in-progress or partially committed files broke the main tree build: 03-12/03-14 in flow/login.rs, and 03-11's committed core change without its anvil-web half. I verified everything in the temporary worktree `target/wt-03-15`, checked out at `8d138c4` with only this plan's files applied, and removed the worktree afterwards.
- `cargo doc -p anvil-core` with `-D warnings` fails on a redundant link that 03-02 left in `service/audit.rs`. This is out of scope and was not changed. `cargo doc -p anvil-mail` is clean.

## Next Phase Readiness

- 03-23 can wire `MailSettingsService { storage, clock, kek, checker: Arc::new(anvil_mail::TemplateChecker), tester: Arc::new(anvil_mail::LettreSmtpTester::default()) }` and use `anvil_mail::check::variables(kind)` for the variable list. Use `EmailRenderer::embedded()` / `render(kind)` sources for the "default" view.
- 03-24 owns the rest of `jobs.rs`. The worker construction there is now final for this plan.

## Self-Check: PASSED
