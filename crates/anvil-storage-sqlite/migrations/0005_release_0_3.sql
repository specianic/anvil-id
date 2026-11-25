-- Release 0.3 schema (forward-only expand migration on top of 0004_release_0_2_token_family).
--
-- Conventions (as in 0001-0004): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT, enums are snake_case TEXT guarded by
-- CHECK constraints. Every tenant-scoped table references tenant(id) ON DELETE CASCADE;
-- user-scoped tables also cascade from user through the composite (tenant_id, user_id) key.
-- Connection secrets are stored KEK-sealed (secret_enc), preview tokens only as their hash.
--
-- This migration runs in one transaction. The three table rebuilds below (flow,
-- self_service_token, email_template) widen CHECK constraints, which SQLite cannot alter in
-- place. None of the three tables is referenced by a foreign key (checked with
-- pragma_foreign_key_list on every table), so dropping the old table inside the transaction
-- (foreign keys on) cascades nothing. Every row is copied before the drop.
--
-- anvil:non-destructive-rebuild

-- ---------------------------------------------------------------------------------------------
-- Flows: new kind `logout` (RP-initiated logout confirmation).

CREATE TABLE flow_new (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind            TEXT    NOT NULL CHECK (kind IN
                    ('login', 'registration', 'verification', 'recovery', 'setup', 'settings',
                     'consent', 'logout')),
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
-- Self-service tokens: new kind `email_change` (the token's email is the new address).

CREATE TABLE self_service_token_new (
  token_hash  BLOB    NOT NULL PRIMARY KEY CHECK (length(token_hash) = 32),
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL CHECK (kind IN
                ('verification', 'recovery', 'invitation', 'email_change')),
  user_id     BLOB    NOT NULL CHECK (length(user_id) = 16),
  email       TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
INSERT INTO self_service_token_new (token_hash, tenant_id, kind, user_id, email, created_at,
                                    expires_at, consumed_at)
  SELECT token_hash, tenant_id, kind, user_id, email, created_at, expires_at, consumed_at
    FROM self_service_token;
-- anvil:non-destructive-rebuild
DROP TABLE self_service_token;
ALTER TABLE self_service_token_new RENAME TO self_service_token;
CREATE INDEX self_service_token_user_idx ON self_service_token (tenant_id, user_id);
CREATE INDEX self_service_token_expires_idx ON self_service_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- Email templates: new kinds `login_code`, `email_change`, `email_changed`.

CREATE TABLE email_template_new (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN
               ('verification', 'recovery', 'invitation', 'password_changed',
                'recovery_code_used', 'login_code', 'email_change', 'email_changed')),
  subject    TEXT    NOT NULL,
  body_html  TEXT    NOT NULL,
  body_text  TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind)
) STRICT;
INSERT INTO email_template_new (tenant_id, kind, subject, body_html, body_text, updated_at)
  SELECT tenant_id, kind, subject, body_html, body_text, updated_at
    FROM email_template;
-- anvil:non-destructive-rebuild
DROP TABLE email_template;
ALTER TABLE email_template_new RENAME TO email_template;

-- ---------------------------------------------------------------------------------------------
-- Upstream identity-provider connections. `config` is the tagged ConnectionConfig JSON (never
-- the secret); `secret_enc` is the KEK-sealed client secret (purpose anvilid/connection-secret/v1,
-- AAD tenant id || connection id).

CREATE TABLE connection (
  id                   BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id            BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  slug                 TEXT    NOT NULL CHECK (length(slug) >= 1),
  display_name         TEXT    NOT NULL,
  kind                 TEXT    NOT NULL CHECK (kind IN
                         ('google', 'apple', 'microsoft', 'github', 'oidc', 'oauth2')),
  enabled              INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  config               TEXT    NOT NULL CHECK (json_valid(config)),
  secret_enc           BLOB    CHECK (secret_enc IS NULL OR length(secret_enc) >= 1),
  trust_email_verified INTEGER NOT NULL CHECK (trust_email_verified IN (0, 1)),
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX connection_slug_uq ON connection (tenant_id, slug);
-- Target of identity_link's composite foreign key (a link never crosses tenants).
CREATE UNIQUE INDEX connection_tenant_id_uq ON connection (tenant_id, id);

-- Links between local users and upstream identities.

CREATE TABLE identity_link (
  id            BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id     BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  user_id       BLOB    NOT NULL CHECK (length(user_id) = 16),
  connection_id BLOB    NOT NULL CHECK (length(connection_id) = 16),
  subject       TEXT    NOT NULL CHECK (length(subject) >= 1),
  email_at_link TEXT,
  metadata      TEXT    NOT NULL CHECK (json_valid(metadata)),
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connection (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE UNIQUE INDEX identity_link_subject_uq ON identity_link (tenant_id, connection_id, subject);
CREATE INDEX identity_link_user_idx ON identity_link (tenant_id, user_id);

-- ---------------------------------------------------------------------------------------------
-- RP sessions: a browser session signed in to a client (written by create_code). They go with
-- the browser session.

CREATE TABLE rp_session (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  session_id BLOB    NOT NULL REFERENCES browser_session (id) ON DELETE CASCADE,
  client_id  TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, session_id, client_id)
) STRICT;
CREATE INDEX rp_session_session_idx ON rp_session (session_id);

-- Back-channel logout deliveries (enqueued by the revoking intents). No foreign key to the
-- session, user or client: a delivery outlives them (user deletion logs the user out).

CREATE TABLE logout_delivery (
  id              BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id       BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  client_id       TEXT    NOT NULL,
  uri             TEXT    NOT NULL,
  sub             TEXT    NOT NULL,
  sid             TEXT    NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at INTEGER NOT NULL,
  give_up_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  delivered_at    INTEGER,
  last_error      TEXT
) STRICT;
CREATE INDEX logout_delivery_due_idx ON logout_delivery (delivered_at, next_attempt_at);
CREATE INDEX logout_delivery_client_idx ON logout_delivery (tenant_id, client_id);
CREATE INDEX logout_delivery_give_up_idx ON logout_delivery (give_up_at);

-- ---------------------------------------------------------------------------------------------
-- Branding per tenant (scope_key '') and client (scope_key 'client:{client_id}'). The published
-- columns (tokens, custom_css, logo_*) are NULL for a scope that only has a preview draft.

CREATE TABLE branding (
  tenant_id          BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  scope_key          TEXT    NOT NULL,
  tokens             TEXT    CHECK (tokens IS NULL OR json_valid(tokens)),
  custom_css         TEXT,
  logo_sha256        TEXT    CHECK (logo_sha256 IS NULL OR length(logo_sha256) = 64),
  logo_type          TEXT,
  draft_tokens       TEXT    CHECK (draft_tokens IS NULL OR json_valid(draft_tokens)),
  draft_css          TEXT,
  preview_hash       BLOB    UNIQUE CHECK (preview_hash IS NULL OR length(preview_hash) = 32),
  preview_expires_at INTEGER,
  updated_at         INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, scope_key),
  CHECK ((logo_sha256 IS NULL) = (logo_type IS NULL)),
  CHECK ((draft_tokens IS NULL) = (preview_hash IS NULL)),
  CHECK ((preview_hash IS NULL) = (preview_expires_at IS NULL))
) STRICT;

-- Logo images, deduplicated by content hash per tenant.

CREATE TABLE branding_logo (
  tenant_id    BLOB NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  sha256       TEXT NOT NULL CHECK (length(sha256) = 64),
  content_type TEXT NOT NULL,
  bytes        BLOB NOT NULL,
  PRIMARY KEY (tenant_id, sha256)
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Clients: RP-initiated and back-channel logout, RFC 8707 resources, per-client MFA policy.
-- 0.2 clients get the defaults (no logout URIs, no resources, tenant MFA policy).

ALTER TABLE client ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(post_logout_redirect_uris));
ALTER TABLE client ADD COLUMN backchannel_logout_uri TEXT;
ALTER TABLE client ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0
  CHECK (backchannel_logout_session_required IN (0, 1));
ALTER TABLE client ADD COLUMN allowed_resources TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(allowed_resources));
ALTER TABLE client ADD COLUMN mfa_policy TEXT
  CHECK (mfa_policy IS NULL OR mfa_policy IN ('off', 'optional', 'required'));

-- ---------------------------------------------------------------------------------------------
-- RFC 8707 resource indicators (JSON array of absolute URIs) on codes, families and opaque
-- access tokens. Existing rows: no resource.

ALTER TABLE authorization_code ADD COLUMN resource TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(resource));
ALTER TABLE token_family ADD COLUMN resource TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(resource));
ALTER TABLE access_token ADD COLUMN resource TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(resource));
