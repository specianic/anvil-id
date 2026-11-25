-- Release 0.3 "Real-world logins": upstream connections and identity links, RP sessions and
-- back-channel logout deliveries, branding, client logout/MFA/resource settings, RFC 8707
-- resource indicators, logout flows, email change tokens and the new email templates.
--
-- Additive only: no DROP TABLE / DROP COLUMN, no RENAME, no column type change. CHECK swaps use
-- DROP CONSTRAINT / ADD CONSTRAINT inside this migration's transaction, so a failure leaves the
-- 0.2 schema untouched. New columns have constant defaults (metadata-only, no table rewrite).
-- The logical schema matches the SQLite 0005 migration (same semantics, native Postgres types).

-- ---------------------------------------------------------------------------------------------
-- Widened kinds: logout flows, email change tokens, three new email templates.

ALTER TABLE flow DROP CONSTRAINT flow_kind_check;
ALTER TABLE flow ADD CONSTRAINT flow_kind_check CHECK (kind IN
  ('login', 'registration', 'verification', 'recovery', 'setup', 'settings', 'consent',
   'logout'));

ALTER TABLE self_service_token DROP CONSTRAINT self_service_token_kind_check;
ALTER TABLE self_service_token ADD CONSTRAINT self_service_token_kind_check CHECK (kind IN
  ('verification', 'recovery', 'invitation', 'email_change'));

ALTER TABLE email_template DROP CONSTRAINT email_template_kind_check;
ALTER TABLE email_template ADD CONSTRAINT email_template_kind_check CHECK (kind IN
  ('verification', 'recovery', 'invitation', 'password_changed', 'recovery_code_used',
   'login_code', 'email_change', 'email_changed'));

-- ---------------------------------------------------------------------------------------------
-- Client additions: RP-initiated and back-channel logout, RFC 8707 audiences, per-client MFA.

ALTER TABLE client
  ADD COLUMN post_logout_redirect_uris jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(post_logout_redirect_uris) = 'array'),
  ADD COLUMN backchannel_logout_uri text,
  ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false,
  ADD COLUMN allowed_resources jsonb NOT NULL DEFAULT '[]'
    CHECK (jsonb_typeof(allowed_resources) = 'array'),
  ADD COLUMN mfa_policy text CHECK (mfa_policy IN ('off', 'optional', 'required'));

-- RFC 8707 resource indicators bound to codes, families and access tokens.
ALTER TABLE authorization_code
  ADD COLUMN resource jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(resource) = 'array');
ALTER TABLE token_family
  ADD COLUMN resource jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(resource) = 'array');
ALTER TABLE access_token
  ADD COLUMN resource jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(resource) = 'array');

-- ---------------------------------------------------------------------------------------------
-- Upstream connections. The provider client secret is KEK-sealed (purpose
-- anvilid/connection-secret/v1, AAD tenant id || connection id) and never stored in plaintext;
-- `config` never contains it.

CREATE TABLE connection (
  id                   uuid        NOT NULL PRIMARY KEY,
  tenant_id            uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  slug                 text        NOT NULL,
  display_name         text        NOT NULL,
  -- Derived from config (ConnectionConfig::kind) for listing and filtering.
  kind                 text        NOT NULL CHECK (kind IN
                         ('google', 'apple', 'microsoft', 'github', 'oidc', 'oauth2')),
  enabled              boolean     NOT NULL,
  config               jsonb       NOT NULL CHECK (jsonb_typeof(config) = 'object'),
  secret_enc           bytea,
  trust_email_verified boolean     NOT NULL,
  created_at           timestamptz NOT NULL,
  updated_at           timestamptz NOT NULL,
  CONSTRAINT connection_tenant_slug_key UNIQUE (tenant_id, slug),
  -- Composite FK target for identity links (tenant isolation by schema).
  CONSTRAINT connection_tenant_id_key UNIQUE (tenant_id, id)
);

-- A local user's link to an upstream identity. Both references are composite, so a link can
-- never name a user or connection of another tenant.
CREATE TABLE identity_link (
  id            uuid        NOT NULL PRIMARY KEY,
  tenant_id     uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  user_id       uuid        NOT NULL,
  connection_id uuid        NOT NULL,
  -- The upstream subject, matched exactly (case-sensitive).
  subject       text        NOT NULL,
  email_at_link text,
  metadata      jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(metadata) = 'object'),
  created_at    timestamptz NOT NULL,
  last_used_at  timestamptz,
  CONSTRAINT identity_link_subject_key UNIQUE (tenant_id, connection_id, subject),
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connection (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX identity_link_user_idx ON identity_link (tenant_id, user_id);

-- ---------------------------------------------------------------------------------------------
-- RP sessions and back-channel logout deliveries.

-- Composite FK target so an RP session can only reference a browser session of its tenant.
ALTER TABLE browser_session ADD CONSTRAINT browser_session_tenant_id_key UNIQUE (tenant_id, id);

-- Which relying parties a browser session signed in to (written by create_code).
CREATE TABLE rp_session (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  session_id uuid        NOT NULL,
  client_id  text        NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, session_id, client_id),
  FOREIGN KEY (tenant_id, session_id) REFERENCES browser_session (tenant_id, id)
    ON DELETE CASCADE
);

-- One row per (revoked session x RP with a backchannel_logout_uri), enqueued by the revoking
-- intents in their transaction. No FK to user, session or client on purpose: deliveries must
-- survive the deletion that caused them. Installation-wide queue leased with SKIP LOCKED.
CREATE TABLE logout_delivery (
  id              uuid        NOT NULL PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  client_id       text        NOT NULL,
  uri             text        NOT NULL,
  sub             text        NOT NULL,
  sid             text        NOT NULL,
  attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL,
  give_up_at      timestamptz NOT NULL,
  created_at      timestamptz NOT NULL,
  delivered_at    timestamptz,
  last_error      text
);
-- The worker's claim query scans undelivered rows by due time.
CREATE INDEX logout_delivery_due_idx ON logout_delivery (next_attempt_at)
  WHERE delivered_at IS NULL;
CREATE INDEX logout_delivery_client_idx ON logout_delivery (tenant_id, client_id);

-- ---------------------------------------------------------------------------------------------
-- Branding per tenant ('' scope) and per client ('client:<id>' scope).

-- Logos are content-addressed (lowercase hex sha256) and stored once per tenant.
CREATE TABLE branding_logo (
  tenant_id    uuid  NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  sha256       text  NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  content_type text  NOT NULL,
  bytes        bytea NOT NULL,
  PRIMARY KEY (tenant_id, sha256)
);

CREATE TABLE branding (
  tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  scope_key   text        NOT NULL,
  tokens      jsonb       NOT NULL CHECK (jsonb_typeof(tokens) = 'object'),
  custom_css  text,
  logo_sha256 text,
  logo_type   text,
  updated_at  timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, scope_key),
  CHECK ((logo_sha256 IS NULL) = (logo_type IS NULL)),
  FOREIGN KEY (tenant_id, logo_sha256) REFERENCES branding_logo (tenant_id, sha256)
);

-- The console's live-preview draft of a scope (at most one per scope), looked up by the SHA-256
-- of its preview token (never the token).
CREATE TABLE branding_draft (
  tenant_id          uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  scope_key          text        NOT NULL,
  tokens             jsonb       NOT NULL CHECK (jsonb_typeof(tokens) = 'object'),
  custom_css         text,
  preview_hash       bytea       NOT NULL CHECK (octet_length(preview_hash) = 32),
  preview_expires_at timestamptz NOT NULL,
  updated_at         timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, scope_key),
  CONSTRAINT branding_draft_preview_hash_key UNIQUE (preview_hash)
);
