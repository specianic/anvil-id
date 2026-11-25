---
phase: 02-release-0-1-first-login
plan: 02
subsystem: core-domain-and-storage-contract
tags: [anvil-core, ports, storage-contract, error-mapping, interface-first]
requires: []
provides:
  - anvil_core::model (complete 0.1 domain model, PublicUrl, issuer(), normalize_email, Scope)
  - anvil_core::ports (9 storage repos + Storage::purge_expired, Clock, PasswordHasher, BreachChecker)
  - anvil_core::error::CoreError (single oauth_error/http_status/description mapping)
  - anvil_core::policy (PasswordPolicy, check_password)
  - anvil_core::flow::form (FormDescription contract)
  - core module skeleton (oauth/, service/, flow/) for 02-07..02-10
  - anvil_storage::contract (67 contract tests, fixtures)
affects: [02-05, 02-06, 02-07, 02-08, 02-09, 02-10, 02-12, anvil-web, anvilid]
tech-stack:
  added: []
  patterns:
    - intent methods per atomic unit instead of a generic begin()/Tx
    - str_enum! macro gives every stored enum stable as_str()/parse()/ALL
    - TRANSITIONAL pending.rs shims returning StorageError::Unsupported
key-files:
  created:
    - crates/anvil-core/src/model/{ids,tenant,user,client,key,session,flow,grant,outbox,setup}.rs
    - crates/anvil-core/src/error.rs
    - crates/anvil-core/src/clock.rs
    - crates/anvil-core/src/policy.rs
    - crates/anvil-core/src/flow/form.rs
    - crates/anvil-core/src/{oauth,service,flow}/*.rs (empty skeleton modules)
    - crates/anvil-storage-sqlite/src/pending.rs
    - crates/anvil-storage-postgres/src/pending.rs
    - crates/anvil-storage/src/contract/{fixtures,tenants,users,clients,keys,sessions,flows,grants,setup,outbox}.rs
  modified:
    - crates/anvil-core/src/lib.rs
    - crates/anvil-core/src/model/mod.rs (was model.rs)
    - crates/anvil-core/src/ports.rs
    - crates/anvil-storage/src/contract/mod.rs
    - crates/anvil-storage-{sqlite,postgres}/src/{lib,convert}.rs
    - docs/ARCHITECTURE.md
key-decisions:
  - "Intent methods replace begin()/Tx (ARCHITECTURE §7.1): dyn-safe, no forgotten commit, each atomic unit contract-tested"
  - "CoreError: Validation -> invalid_request/422; NotFound/Conflict/Forbidden use management codes not_found/conflict/forbidden (404/409/403); Overloaded -> temporarily_unavailable/503; Internal/Storage -> server_error/500 with generic description"
  - "From<StorageError> for CoreError always yields CoreError::Storage (500); services map storage Conflict to domain errors explicitly"
  - "purge_expired keeps consumed-but-unexpired codes and refresh tokens so reuse detection keeps working after a purge"
  - "Page.next_cursor is Some iff more items follow (backends fetch limit+1)"
  - "create_code rejects code.token_family_id != family.id with Conflict and stores nothing"
  - "rotate_refresh concurrency contract: exactly 1 Rotated; losers ReuseDetected or NotFound; family revoked at the end"
  - "OutboxRepo::claim_due increments attempts and sets next_attempt_at = now + lease"
  - "SetupOutcome::Completed holds User and Client unboxed (documented clippy expect), like ConsumeOutcome"
requirements-completed: []
requirements-addressed: [OIDC-03, OIDC-05, QUAL-02]  # contracts specified + tested; delivered when 02-05/02-06/02-08 land
duration: 31min
completed: 2026-11-25
---

# Phase 2 Plan 02: Domain model, ports, CoreError and storage contract suite Summary

**This plan defines the interface the rest of Phase 2 codes against.** It contains the full 0.1 domain model, nine intent-based storage repos, the Clock/PasswordHasher/BreachChecker ports and CoreError with a single OAuth mapping. It also adds the FormDescription contract and a 67-test storage contract suite with concurrency tests. Both backends still compile, through explicit-error transitional shims.

## Performance

- **Duration:** about 31 min
- **Completed:** 2026-11-25
- **Tasks:** 3/3
- **Files:** about 50 created or modified

## Accomplishments

- `anvil_core::model` is now split per aggregate. It covers tenants (host and settings), users with typed `StandardClaims`, password credentials (Debug redacted), clients (`require_pkce`, `application_type`), signing keys (Debug redacted, `signing_key_aad`), sessions, flows, authorization requests and params with a claims request, codes, token families carrying the authentication context (G2), refresh tokens, replay kinds, self-service tokens (G6), the outbox and `InstallPlan`.
- `PublicUrl` is a strict hand-written parser. `issuer()` is the single issuer function: Root, `/t/{slug}` or host, never ending in a trailing `/`.
- `CoreError` maps through one `oauth_error()` / `http_status()` / `description()` function, with a table test covering every variant. Internal and storage details never leak into `description()`.
- The ports document an atomicity and tenant-isolation contract on every method. A dyn-compatibility test covers all 13 traits.
- The storage contract suite has 67 tests: Phase 1's 8, adapted, plus 59 new ones. The concurrency tests are 32-way `consume_code`, 16-way `rotate_refresh`, 16-way `record_jti`, 16-way `complete_recovery` and 8-way `complete_setup`.
- ARCHITECTURE.md is updated in three places: §4 (core deps), §6.1 (0.1 additions G2/G3/G4/G6, tenant host and settings, client `require_pkce`/`application_type`) and §7.1 (the intent-method design and the list of atomic methods).

## Final port signatures (downstream plans read this)

```rust
// all repos: #[async_trait] pub trait X: Send + Sync; errors: StorageError
trait Storage: Send + Sync + 'static {
  fn tenants/users/clients/keys/sessions/flows/grants/setup/outbox(&self) -> &dyn …Repo;
  async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64>;
}
TenantRepo:
  create(&NewTenant) -> Tenant                         // Conflict: slug, host
  get(TenantId) -> Option<Tenant>; get_by_slug(&str) -> Option<Tenant>; get_by_host(&str) -> Option<Tenant>
  list(PageRequest) -> Page<Tenant>
  update(TenantId, &TenantUpdate) -> Option<Tenant>    // Conflict: host
  delete(TenantId) -> bool                             // cascades
UserRepo:
  create(TenantId, &NewUser, Option<&NewPasswordCredential>, Option<&NewSelfServiceToken>, Option<&NewEmail>) -> User  // 1 tx
  get(TenantId, UserId) -> Option<User>; get_by_email(TenantId, &str) -> Option<User>
  list(TenantId, PageRequest) -> Page<User>
  update(TenantId, UserId, &UserUpdate, now) -> Option<User>       // Conflict
  delete(TenantId, UserId) -> bool                                  // + creds/sessions/tokens, revokes families (UserDeleted)
  password(TenantId, UserId) -> Option<PasswordCredential>
  set_password(TenantId, UserId, &str phc, now) -> bool             // upsert
  record_login(TenantId, UserId, now) -> ()
  issue_self_service_token(TenantId, &NewSelfServiceToken, Option<&NewEmail>) -> ()   // 1 tx
  complete_verification(TenantId, &SecretHash, now) -> Option<User>
  complete_recovery(TenantId, &SecretHash, &str new_phc, now, Option<&NewEmail>) -> Option<User>  // 1 tx, Recovery|Invitation
ClientRepo:
  create(TenantId, &NewClient) -> Client; get(TenantId, &str) -> Option<Client>
  list(TenantId, PageRequest) -> Page<Client>
  update(TenantId, &str, &ClientUpdate, now) -> Option<Client>
  set_secret_hash(TenantId, &str, Option<SecretHash>, now) -> bool
  delete(TenantId, &str) -> bool                                    // revokes families (ClientDeleted)
KeyRepo:
  insert(TenantId, &NewSigningKey) -> ()               // Conflict: 2nd Active per (tenant, alg)
  active(TenantId, &str alg) -> Option<SigningKey>
  published(TenantId, now) -> Vec<SigningKey>          // expires_at null or > now, id order
SessionRepo:
  create(TenantId, &NewBrowserSession) -> ()
  get_active(TenantId, &SecretHash, now) -> Option<BrowserSession>
  touch(TenantId, SessionId, now, idle_expires_at) -> bool
  revoke(TenantId, SessionId, now) -> bool
FlowRepo:
  create(TenantId, &NewFlow) -> (); get(TenantId, FlowId, now) -> Option<Flow>
  update_state(TenantId, FlowId, &str, now) -> bool; delete(TenantId, FlowId) -> bool
GrantRepo:
  create_authorization_request(TenantId, &NewAuthorizationRequest) -> ()
  get_authorization_request(TenantId, AuthRequestId, now) -> Option<AuthorizationRequest>
  delete_authorization_request(TenantId, AuthRequestId) -> bool
  create_code(TenantId, &NewAuthorizationCode, &NewTokenFamily) -> ()   // 1 tx; ids must match
  consume_code(TenantId, &CodeHash, now) -> ConsumeOutcome
  get_family(TenantId, TokenFamilyId) -> Option<TokenFamily>
  revoke_family(TenantId, TokenFamilyId, RevokeReason, now) -> bool     // idempotent, first reason kept
  create_refresh_token(TenantId, &NewRefreshToken) -> ()
  find_refresh_token(TenantId, &SecretHash) -> Option<(RefreshToken, TokenFamily)>
  rotate_refresh(TenantId, &SecretHash presented, &NewRefreshToken child, now) -> RotateOutcome
  record_jti(TenantId, ReplayKind, &SecretHash, expires_at, now) -> JtiOutcome
SetupRepo:  // installation-wide
  is_installed() -> bool; install(&InstallPlan) -> InstallOutcome
  create_setup_token(&NewSetupToken) -> (); peek_setup_token(&SecretHash, now) -> bool
  complete_setup(&SecretHash, now, TenantId admin_tenant, &NewUser, &NewPasswordCredential,
                 TenantId client_tenant, &NewClient) -> SetupOutcome
OutboxRepo:
  enqueue(TenantId, &NewEmail) -> ()
  claim_due(now, limit: u32, lease: std::time::Duration) -> Vec<OutboxEmail>
  mark_sent(OutboxId, now) -> bool; mark_failed(OutboxId, &str, next_attempt_at) -> bool

enum ConsumeOutcome { Consumed(AuthorizationCode), AlreadyConsumed { family_id: Option<TokenFamilyId> }, NotFound }
enum RotateOutcome  { Rotated(TokenFamily), ReuseDetected { family_id: TokenFamilyId }, NotFound }
enum JtiOutcome { Recorded, Replayed }   enum InstallOutcome { Installed, AlreadyInstalled }
enum SetupOutcome { Completed { user: User, client: Client }, InvalidToken }
enum StorageError { Conflict(String), Corrupt(String), Backend(Box<dyn Error+Send+Sync>), Unsupported(&'static str) }

trait Clock: Send + Sync { fn now(&self) -> OffsetDateTime }   struct SystemClock;  // re-exported from ports
#[async_trait] trait PasswordHasher { async fn hash(&self, &str) -> Result<String, CoreError>;
                                      async fn verify(&self, Option<&str>, &str) -> Result<PasswordCheck, CoreError>; }
struct PasswordCheck { valid: bool, needs_rehash: bool }
#[async_trait] trait BreachChecker { async fn is_breached(&self, &str) -> Result<bool, CoreError>; }
```

Model helpers available to downstream plans: every stored enum has `as_str()`, `parse(&str) -> Option<Self>` and `ALL` (RegistrationMode, UserStatus, ClientType, ApplicationType, ClientAuthMethod, GrantType, KeyState, FlowKind, RevokeReason, ReplayKind, SelfServiceKind). There is also `PageRequest::clamped_limit()`, `Scope::{parse, contains, is_subset, iter}` with sorted `Display`, and `SecretHash::{from_slice, as_bytes}`.

## Task Commits

1. **Task 1: Domain model, issuer, CoreError, policy, clock, skeleton** (`2e49c06`, feat)
2. **Task 2: Storage and service ports, transitional backend shims, ARCHITECTURE** (`3104817`, feat)
3. **Task 3: Storage contract suite** (`3540452`, test)

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 2 - Correctness] purge_expired keeps consumed-but-unexpired codes and refresh tokens**
- **Found during:** Task 3
- **Issue:** The plan listed "consumed/expired refresh tokens" for purging. Deleting a consumed token before it expires would turn a later reuse into NotFound instead of ReuseDetected, which silently disables refresh-token reuse detection (OIDC-05).
- **Fix:** The port doc now says purge deletes rows with `expires_at <= now` and keeps consumed rows until they expire. `purge_expired_removes_only_expired_rows` asserts that reuse is still detected after a purge.
- **Commit:** 3540452

**2. [Rule 2 - Contract precision] Page cursor semantics**
- **Issue:** "next_cursor on the last page" was ambiguous. The pagination tests need a deterministic rule.
- **Fix:** `next_cursor` is Some if and only if more items follow, so backends fetch `limit + 1` rows. This is documented on `Page`.
- **Commit:** 3540452

**3. [Rule 3 - Blocking] Contract tests seed real users, clients and sessions for grants**
- **Issue:** Codes and families reference user, session and client. Backends will very likely use foreign keys, so seeding hashes alone would break on 02-05/02-06.
- **Fix:** `seed_grant_ctx` creates a tenant, user, client and session before any code or family.

**4. [Process] The model.rs to model/mod.rs rename landed in a parallel plan's commit**
- During Task 1 I staged `git mv model.rs model/mod.rs`. A concurrent 02-03 commit (`7bbd4d3`) picked it up as a 0-line rename, with the content unchanged. My Task 1 commit (`2e49c06`) then carries the actual content change. Nothing was lost and history is correct, only split.

### Additions beyond the listed tests

- `user_list_pagination`, `user_record_login` and invitation completion through `complete_recovery` were added, so that every port method is covered.
- `str_enum!` helpers (`as_str`/`parse`/`ALL`) were added so backends share one name mapping per enum.

## Expected failures (until wave 2)

The backend contract binaries compile and instantiate the full suite: 67 tests × 2 SQLite variants = 134, plus Postgres. **Every one of them fails with `StorageError::Unsupported(...)`** until plan 02-05 (SQLite) and plan 02-06 (Postgres) replace `pending.rs`. This is the designed transitional state. The shims never return `Ok`, which the plan's grep checks. `tenants.rs` and `grants.rs` stay on disk in both backends as reference and are no longer compiled. Backend `convert.rs` helpers carry `cfg_attr(not(test), expect(dead_code))` until they are used again.

## Notes for downstream plans

- **02-05 / 02-06:** each backend must add a `secrets_never_stored_plaintext` row-inspection test. A generic version is impossible behind the trait; the suite's module doc says so. Remove `pending.rs` and the `convert.rs` dead-code expects.
- **02-07..02-10:** the skeleton files contain only a `//!` line naming the owner plan. Fill your own files only.
- `anvil-core` manifest warns about unused `secrecy`, `serde_json` and `url` (added by 02-01). They are left untouched for the wave-2 plans to use.

## Verification

- `cargo test -p anvil-core`: 32 passed
- `cargo clippy -p anvil-core -p anvil-storage-sqlite -p anvil-storage-postgres --all-targets -D warnings`: clean
- `cargo clippy -p anvil-storage --features contract --all-targets -D warnings`: clean
- `cargo test -p anvil-storage-{sqlite,postgres} --no-run`: compile. `cargo check -p anvilid --all-targets`: OK
- `scripts/check-deps.sh`: dependency rules OK
- The pending.rs files contain `TRANSITIONAL` and no `Ok(`

## Self-Check: PASSED
