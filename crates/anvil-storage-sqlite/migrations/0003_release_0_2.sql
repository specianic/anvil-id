-- Release 0.2 schema (forward-only expand migration on top of 0002_release_0_1).
--
-- Conventions (as in 0001/0002): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT, enums are snake_case TEXT guarded by
-- CHECK constraints. Every tenant-scoped table references tenant(id) ON DELETE CASCADE;
-- user-scoped tables also cascade from user through the composite (tenant_id, user_id) key.
-- Secrets are stored hashed (recovery codes, opaque access tokens) or sealed with the KEK
-- (TOTP seeds, SMTP passwords); never in plaintext.
--
-- This migration runs in one transaction. The two table rebuilds below (credential, flow) copy
-- every row and have no inbound foreign keys, so dropping the old table inside the transaction
-- (foreign keys on) cascades nothing. The token_family rebuild needs foreign keys off and lives
-- in 0004 (no-transaction).

-- ---------------------------------------------------------------------------------------------
-- Credentials: one row per credential (password, passkey, TOTP) with its own id.
--
-- `secret` keeps its name for expand/contract: PHC string (password) | webauthn-rs Passkey JSON
-- (webauthn) | base64url of the KEK-sealed seed (totp). `external_id` is the WebAuthn credential
-- id (NULL otherwise). `counter` is the passkey signature counter or the last accepted TOTP step.
-- Migrated password rows get random 16-byte ids (`randomblob(16)`): opaque identifiers that are
-- not RFC 9562 version-tagged, which is acceptable because ids are only compared for equality.

CREATE TABLE credential_new (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id         BLOB    NOT NULL CHECK (length(user_id) = 16),
  kind            TEXT    NOT NULL CHECK (kind IN ('password', 'webauthn', 'totp')),
  secret          TEXT    NOT NULL,
  external_id     BLOB    CHECK (external_id IS NULL OR length(external_id) BETWEEN 1 AND 1023),
  counter         INTEGER CHECK (counter IS NULL OR counter >= 0),
  backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK (backup_eligible IN (0, 1)),
  label           TEXT    NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  last_used_at    INTEGER,
  CHECK ((kind = 'webauthn') = (external_id IS NOT NULL)),
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
INSERT INTO credential_new (id, tenant_id, user_id, kind, secret, created_at, updated_at)
  SELECT randomblob(16), tenant_id, user_id, kind, secret, created_at, updated_at
    FROM credential;
-- anvil:non-destructive-rebuild
DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;
CREATE UNIQUE INDEX credential_password_uq ON credential (tenant_id, user_id) WHERE kind = 'password';
CREATE UNIQUE INDEX credential_totp_uq ON credential (tenant_id, user_id) WHERE kind = 'totp';
CREATE UNIQUE INDEX credential_external_id_uq ON credential (tenant_id, external_id)
  WHERE external_id IS NOT NULL;
CREATE INDEX credential_user_idx ON credential (tenant_id, user_id);

-- ---------------------------------------------------------------------------------------------
-- Flows: new kinds `settings` and `consent` (CHECK constraints cannot be altered in place).

CREATE TABLE flow_new (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind            TEXT    NOT NULL CHECK (kind IN
                    ('login', 'registration', 'verification', 'recovery', 'setup', 'settings',
                     'consent')),
  state           TEXT    NOT NULL,
  csrf_hash       BLOB    NOT NULL CHECK (length(csrf_hash) = 32),
  cookie_hash     BLOB    NOT NULL CHECK (length(cookie_hash) = 32),
  auth_request_id BLOB    CHECK (auth_request_id IS NULL OR length(auth_request_id) = 16),
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
) STRICT;
INSERT INTO flow_new (id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id,
                      created_at, expires_at)
  SELECT id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id, created_at,
         expires_at
    FROM flow;
-- anvil:non-destructive-rebuild
DROP TABLE flow;
ALTER TABLE flow_new RENAME TO flow;
CREATE INDEX flow_expires_idx ON flow (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Recovery codes (SHA-256 digests of peppered, normalised codes).

CREATE TABLE recovery_code (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  code_hash  BLOB    NOT NULL CHECK (length(code_hash) = 32),
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  PRIMARY KEY (tenant_id, user_id, code_hash),
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Consent grants: one per (tenant, user, client); scopes is the JSON array of granted scopes.

CREATE TABLE consent_grant (
  id         BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  client_id  TEXT    NOT NULL,
  scopes     TEXT    NOT NULL CHECK (json_valid(scopes)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX consent_grant_uq ON consent_grant (tenant_id, user_id, client_id);

-- ---------------------------------------------------------------------------------------------
-- Opaque access tokens (looked up by hash). A family-bound token dies with its family.

CREATE TABLE access_token (
  token_hash BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  family_id  BLOB    REFERENCES token_family (id) ON DELETE CASCADE,
  client_id  TEXT    NOT NULL,
  user_id    BLOB    CHECK (user_id IS NULL OR length(user_id) = 16),
  scope      TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
) STRICT;
CREATE INDEX access_token_family_idx ON access_token (family_id);
CREATE INDEX access_token_expires_idx ON access_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Audit log (append-only; purged by the retention job only).

CREATE TABLE audit_event (
  id         BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  at         INTEGER NOT NULL,
  actor_kind TEXT    NOT NULL CHECK (actor_kind IN ('user', 'client', 'admin', 'system')),
  actor_id   TEXT,
  action     TEXT    NOT NULL CHECK (length(action) >= 1),
  target     TEXT,
  outcome    TEXT    NOT NULL CHECK (outcome IN ('success', 'failure')),
  ip         TEXT,
  user_agent TEXT,
  trace_id   TEXT,
  details    TEXT    NOT NULL CHECK (json_valid(details))
) STRICT;
CREATE INDEX audit_event_tenant_idx ON audit_event (tenant_id, id DESC);
CREATE INDEX audit_event_action_idx ON audit_event (tenant_id, action, id);
CREATE INDEX audit_event_at_idx ON audit_event (at);

-- ---------------------------------------------------------------------------------------------
-- Per-tenant email template overrides and SMTP settings.

CREATE TABLE email_template (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN
               ('verification', 'recovery', 'invitation', 'password_changed',
                'recovery_code_used')),
  subject    TEXT    NOT NULL,
  body_html  TEXT    NOT NULL,
  body_text  TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind)
) STRICT;

CREATE TABLE smtp_settings (
  tenant_id    BLOB    NOT NULL PRIMARY KEY REFERENCES tenant (id) ON DELETE CASCADE,
  host         TEXT    NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  port         INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  username     TEXT,
  password_enc BLOB    CHECK (password_enc IS NULL OR length(password_enc) >= 1),
  from_address TEXT    NOT NULL,
  tls          TEXT    NOT NULL CHECK (tls IN ('starttls', 'implicit', 'none')),
  updated_at   INTEGER NOT NULL
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Installation-wide background job leases.

CREATE TABLE job_lease (
  name         TEXT    NOT NULL PRIMARY KEY CHECK (length(name) >= 1),
  owner        TEXT    NOT NULL,
  leased_until INTEGER NOT NULL
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Clients: access-token format, consent mode, ID-token algorithm, introspection right.
-- 0.1 clients get the secure defaults (JWT, consent required, RS256, no introspection).

ALTER TABLE client ADD COLUMN token_format TEXT NOT NULL DEFAULT 'jwt'
  CHECK (token_format IN ('jwt', 'opaque'));
ALTER TABLE client ADD COLUMN consent_mode TEXT NOT NULL DEFAULT 'required'
  CHECK (consent_mode IN ('required', 'skip_first_party'));
ALTER TABLE client ADD COLUMN id_token_signed_response_alg TEXT
  CHECK (id_token_signed_response_alg IS NULL OR
         id_token_signed_response_alg IN ('RS256', 'ES256', 'Ed25519'));
ALTER TABLE client ADD COLUMN can_introspect INTEGER NOT NULL DEFAULT 0
  CHECK (can_introspect IN (0, 1));

-- ---------------------------------------------------------------------------------------------
-- Browser sessions: request context at sign-in (sessions page).

ALTER TABLE browser_session ADD COLUMN ip TEXT;
ALTER TABLE browser_session ADD COLUMN user_agent TEXT;
