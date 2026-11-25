-- Release 0.1 schema (forward-only expand migration on top of 0001_init).
--
-- Conventions (as in 0001): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT, enums are snake_case TEXT guarded by
-- CHECK constraints. Every tenant-scoped table references tenant(id) ON DELETE CASCADE, so
-- deleting a tenant removes all of its rows. Secrets (codes, refresh tokens, session cookies,
-- client secrets, setup and self-service tokens) are only ever stored as their hash.

-- ---------------------------------------------------------------------------------------------
-- Tenants: custom host (unique when set) and JSON settings.

ALTER TABLE tenant ADD COLUMN host TEXT CHECK (host IS NULL OR length(host) BETWEEN 1 AND 253);
ALTER TABLE tenant ADD COLUMN settings TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(settings));
CREATE UNIQUE INDEX tenant_host_uq ON tenant (host) WHERE host IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Users and credentials.

CREATE TABLE user (
  id             BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id      BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  email          TEXT    NOT NULL CHECK (length(email) BETWEEN 1 AND 254),
  email_verified INTEGER NOT NULL CHECK (email_verified IN (0, 1)),
  username       TEXT,
  claims         TEXT    NOT NULL CHECK (json_valid(claims)),
  status         TEXT    NOT NULL CHECK (status IN ('active', 'blocked')),
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  last_login_at  INTEGER
) STRICT;
-- (tenant_id, id) is the target of the composite foreign keys below and serves keyset pagination.
CREATE UNIQUE INDEX user_tenant_id_uq ON user (tenant_id, id);
CREATE UNIQUE INDEX user_email_uq ON user (tenant_id, email);
CREATE UNIQUE INDEX user_username_uq ON user (tenant_id, username) WHERE username IS NOT NULL;

CREATE TABLE credential (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  kind       TEXT    NOT NULL CHECK (kind IN ('password')),
  secret     TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, user_id, kind),
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Clients.

CREATE TABLE client (
  id               BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id        BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  client_id        TEXT    NOT NULL CHECK (length(client_id) >= 1),
  name             TEXT    NOT NULL,
  client_type      TEXT    NOT NULL CHECK (client_type IN ('confidential', 'public')),
  application_type TEXT    NOT NULL CHECK (application_type IN ('web', 'native')),
  auth_method      TEXT    NOT NULL CHECK (auth_method IN
                     ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
  secret_hash      BLOB    CHECK (secret_hash IS NULL OR length(secret_hash) = 32),
  jwks             TEXT,
  redirect_uris    TEXT    NOT NULL CHECK (json_valid(redirect_uris)),
  grant_types      TEXT    NOT NULL CHECK (json_valid(grant_types)),
  scopes           TEXT    NOT NULL CHECK (json_valid(scopes)),
  require_pkce     INTEGER NOT NULL CHECK (require_pkce IN (0, 1)),
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX client_client_id_uq ON client (tenant_id, client_id);
CREATE INDEX client_tenant_id_idx ON client (tenant_id, id);

-- ---------------------------------------------------------------------------------------------
-- Signing keys: at most one active key per (tenant, alg).

CREATE TABLE signing_key (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kid             TEXT    NOT NULL CHECK (length(kid) >= 1),
  alg             TEXT    NOT NULL CHECK (length(alg) >= 1),
  state           TEXT    NOT NULL CHECK (state IN ('next', 'active', 'retired')),
  private_key_enc BLOB    NOT NULL CHECK (length(private_key_enc) >= 1),
  public_jwk      TEXT    NOT NULL CHECK (json_valid(public_jwk)),
  created_at      INTEGER NOT NULL,
  activated_at    INTEGER,
  retired_at      INTEGER,
  expires_at      INTEGER
) STRICT;
CREATE UNIQUE INDEX signing_key_kid_uq ON signing_key (tenant_id, kid);
CREATE UNIQUE INDEX signing_key_active_uq ON signing_key (tenant_id, alg) WHERE state = 'active';

-- ---------------------------------------------------------------------------------------------
-- Browser sessions (looked up by cookie hash).

CREATE TABLE browser_session (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id         BLOB    NOT NULL CHECK (length(user_id) = 16),
  token_hash      BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  auth_time       INTEGER NOT NULL,
  acr             TEXT    NOT NULL,
  amr             TEXT    NOT NULL CHECK (json_valid(amr)),
  created_at      INTEGER NOT NULL,
  last_seen_at    INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  idle_expires_at INTEGER NOT NULL,
  revoked_at      INTEGER,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX browser_session_user_idx ON browser_session (tenant_id, user_id);
CREATE INDEX browser_session_expires_idx ON browser_session (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Self-service flows and stored authorization requests.

CREATE TABLE flow (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind            TEXT    NOT NULL CHECK (kind IN
                    ('login', 'registration', 'verification', 'recovery', 'setup')),
  state           TEXT    NOT NULL,
  csrf_hash       BLOB    NOT NULL CHECK (length(csrf_hash) = 32),
  cookie_hash     BLOB    NOT NULL CHECK (length(cookie_hash) = 32),
  auth_request_id BLOB    CHECK (auth_request_id IS NULL OR length(auth_request_id) = 16),
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
) STRICT;
CREATE INDEX flow_expires_idx ON flow (expires_at);

CREATE TABLE authorization_request (
  id         BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  client_id  TEXT    NOT NULL,
  params     TEXT    NOT NULL CHECK (json_valid(params)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX authorization_request_expires_idx ON authorization_request (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Token families (no foreign key to user, session or client: families outlive them, revoked).

CREATE TABLE token_family (
  id                  BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id           BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  client_id           TEXT    NOT NULL,
  user_id             BLOB    CHECK (user_id IS NULL OR length(user_id) = 16),
  scope               TEXT    NOT NULL,
  auth_time           INTEGER,
  acr                 TEXT,
  amr                 TEXT    NOT NULL CHECK (json_valid(amr)),
  session_id          BLOB    CHECK (session_id IS NULL OR length(session_id) = 16),
  claims              TEXT    CHECK (claims IS NULL OR json_valid(claims)),
  created_at          INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  revoked_at          INTEGER,
  revoked_reason      TEXT    CHECK (revoked_reason IS NULL OR revoked_reason IN
                        ('code_reuse', 'refresh_reuse', 'user_recovery', 'client_deleted',
                         'user_deleted', 'admin')),
  CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
) STRICT;
CREATE INDEX token_family_user_idx ON token_family (tenant_id, user_id);
CREATE INDEX token_family_client_idx ON token_family (tenant_id, client_id);
CREATE INDEX token_family_expires_idx ON token_family (absolute_expires_at);

-- ---------------------------------------------------------------------------------------------
-- Authorization codes: recreated with the authentication context and a mandatory family
-- (SQLite cannot add NOT NULL columns or foreign keys in place: create new, drop, rename).
-- Phase 1 rows lack the new NOT NULL context (user, session, auth_time, acr, family) and codes
-- live for minutes, so they are deliberately not carried over; on a Phase 1 database the old
-- table is simply replaced.

CREATE TABLE authorization_code_new (
  code_hash       BLOB    NOT NULL PRIMARY KEY CHECK (length(code_hash) = 32),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  client_id       TEXT    NOT NULL,
  user_id         BLOB    NOT NULL CHECK (length(user_id) = 16),
  session_id      BLOB    NOT NULL CHECK (length(session_id) = 16),
  redirect_uri    TEXT    NOT NULL,
  scope           TEXT    NOT NULL,
  nonce           TEXT,
  code_challenge  TEXT,
  auth_time       INTEGER NOT NULL,
  acr             TEXT    NOT NULL,
  amr             TEXT    NOT NULL CHECK (json_valid(amr)),
  token_family_id BLOB    NOT NULL REFERENCES token_family (id) ON DELETE CASCADE,
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER,
  created_at      INTEGER NOT NULL,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
DROP TABLE authorization_code;
ALTER TABLE authorization_code_new RENAME TO authorization_code;
CREATE INDEX authorization_code_family_idx ON authorization_code (token_family_id);
CREATE INDEX authorization_code_user_idx ON authorization_code (tenant_id, user_id);
CREATE INDEX authorization_code_expires_idx ON authorization_code (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Refresh tokens (parent_hash is informational: a parent may already be purged).

CREATE TABLE refresh_token (
  token_hash  BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  family_id   BLOB    NOT NULL REFERENCES token_family (id) ON DELETE CASCADE,
  parent_hash BLOB    CHECK (parent_hash IS NULL OR length(parent_hash) = 32),
  scope       TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT;
CREATE INDEX refresh_token_family_idx ON refresh_token (family_id);
CREATE INDEX refresh_token_expires_idx ON refresh_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Replay guards (insert-or-fail on the primary key).

CREATE TABLE replay_guard (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN ('client_assertion_jti')),
  value_hash BLOB    NOT NULL CHECK (length(value_hash) = 32),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind, value_hash)
) STRICT;
CREATE INDEX replay_guard_expires_idx ON replay_guard (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Self-service tokens (verification, recovery, invitation) and the installation setup token.

CREATE TABLE self_service_token (
  token_hash  BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL CHECK (kind IN ('verification', 'recovery', 'invitation')),
  user_id     BLOB    NOT NULL CHECK (length(user_id) = 16),
  email       TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX self_service_token_user_idx ON self_service_token (tenant_id, user_id);
CREATE INDEX self_service_token_expires_idx ON self_service_token (expires_at);

CREATE TABLE admin_setup_token (
  token_hash  BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER
) STRICT;
CREATE INDEX admin_setup_token_expires_idx ON admin_setup_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Transactional email outbox.

CREATE TABLE email_outbox (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  recipient       TEXT    NOT NULL,
  template        TEXT    NOT NULL,
  payload         TEXT    NOT NULL CHECK (json_valid(payload)),
  attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  sent_at         INTEGER,
  last_error      TEXT
) STRICT;
CREATE INDEX email_outbox_due_idx ON email_outbox (sent_at, next_attempt_at);
CREATE INDEX email_outbox_expires_idx ON email_outbox (expires_at);
