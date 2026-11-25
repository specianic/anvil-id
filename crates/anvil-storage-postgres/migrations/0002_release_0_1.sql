-- Release 0.1 "First login": every table behind the 0.1 storage ports.
--
-- Native types: uuid ids, bytea hashes (CHECK octet_length = 32), timestamptz timestamps, jsonb for
-- structured values that are only (de)serialised as a whole, text[] for lists, text for values
-- that must round-trip byte for byte (JWKs, flow state). Enums are snake_case text with CHECK
-- constraints. Every tenant-scoped table references tenant(id) ON DELETE CASCADE.
--
-- Token families, codes and refresh tokens deliberately do not reference user, client or
-- browser_session: deleting a user or client revokes its families instead of deleting them, so
-- reuse detection and audit keep working.

-- ---------------------------------------------------------------------------------------------
-- tenant: custom host for host-based tenants (unique when set). `settings` exists since 0001.

ALTER TABLE tenant ADD COLUMN host text;
CREATE UNIQUE INDEX tenant_host_key ON tenant (host) WHERE host IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- users and credentials

CREATE TABLE "user" (
  id             uuid        NOT NULL PRIMARY KEY,
  tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  email          text        NOT NULL,
  email_verified boolean     NOT NULL,
  username       text,
  claims         jsonb       NOT NULL DEFAULT '{}',
  status         text        NOT NULL CHECK (status IN ('active', 'blocked')),
  created_at     timestamptz NOT NULL,
  updated_at     timestamptz NOT NULL,
  last_login_at  timestamptz
);
CREATE UNIQUE INDEX user_tenant_email_key ON "user" (tenant_id, email);
CREATE UNIQUE INDEX user_tenant_username_key ON "user" (tenant_id, username) WHERE username IS NOT NULL;
-- Keyset pagination per tenant.
CREATE INDEX user_tenant_id_idx ON "user" (tenant_id, id);

CREATE TABLE credential (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  kind       text        NOT NULL CHECK (kind IN ('password')),
  -- Password: Argon2id PHC string.
  data       text        NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (user_id, kind)
);
CREATE INDEX credential_tenant_idx ON credential (tenant_id);

CREATE TABLE self_service_token (
  token_hash  bytea       NOT NULL PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  kind        text        NOT NULL CHECK (kind IN ('verification', 'recovery', 'invitation')),
  user_id     uuid        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  email       text        NOT NULL,
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX self_service_token_user_idx ON self_service_token (user_id);
CREATE INDEX self_service_token_expires_idx ON self_service_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- clients and keys

CREATE TABLE client (
  id               uuid        NOT NULL PRIMARY KEY,
  tenant_id        uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  client_id        text        NOT NULL,
  name             text        NOT NULL,
  client_type      text        NOT NULL CHECK (client_type IN ('confidential', 'public')),
  application_type text        NOT NULL CHECK (application_type IN ('web', 'native')),
  auth_method      text        NOT NULL CHECK (auth_method IN
                     ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
  secret_hash      bytea       CHECK (octet_length(secret_hash) = 32),
  jwks             text,
  redirect_uris    text[]      NOT NULL,
  grant_types      text[]      NOT NULL CHECK (grant_types <@
                     ARRAY['authorization_code', 'refresh_token', 'client_credentials']::text[]),
  scopes           text[]      NOT NULL,
  require_pkce     boolean     NOT NULL,
  created_at       timestamptz NOT NULL,
  updated_at       timestamptz NOT NULL
);
CREATE UNIQUE INDEX client_tenant_client_id_key ON client (tenant_id, client_id);
CREATE INDEX client_tenant_id_idx ON client (tenant_id, id);

CREATE TABLE signing_key (
  id              uuid        NOT NULL PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  kid             text        NOT NULL,
  alg             text        NOT NULL,
  state           text        NOT NULL CHECK (state IN ('next', 'active', 'retired')),
  -- AES-256-GCM envelope (KEK); never the raw private key.
  private_key_enc bytea       NOT NULL,
  public_jwk      text        NOT NULL,
  created_at      timestamptz NOT NULL,
  activated_at    timestamptz,
  retired_at      timestamptz,
  expires_at      timestamptz
);
CREATE UNIQUE INDEX signing_key_tenant_kid_key ON signing_key (tenant_id, kid);
-- At most one active key per tenant and algorithm.
CREATE UNIQUE INDEX signing_key_one_active ON signing_key (tenant_id, alg) WHERE state = 'active';

-- ---------------------------------------------------------------------------------------------
-- sessions, flows, authorization requests

CREATE TABLE browser_session (
  id              uuid        NOT NULL PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  user_id         uuid        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
  token_hash      bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  auth_time       timestamptz NOT NULL,
  acr             text        NOT NULL,
  amr             text[]      NOT NULL,
  created_at      timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  revoked_at      timestamptz
);
CREATE INDEX browser_session_user_idx ON browser_session (user_id);
CREATE INDEX browser_session_expires_idx ON browser_session (expires_at);

CREATE TABLE authorization_request (
  id         uuid        NOT NULL PRIMARY KEY,
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  client_id  text        NOT NULL,
  params     jsonb       NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX authorization_request_expires_idx ON authorization_request (expires_at);

CREATE TABLE flow (
  id              uuid        NOT NULL PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  kind            text        NOT NULL CHECK (kind IN
                    ('login', 'registration', 'verification', 'recovery', 'setup')),
  -- Opaque to storage; text (not jsonb) so it round-trips byte for byte.
  state           text        NOT NULL,
  csrf_hash       bytea       NOT NULL CHECK (octet_length(csrf_hash) = 32),
  cookie_hash     bytea       NOT NULL CHECK (octet_length(cookie_hash) = 32),
  -- No foreign key: the request may be purged or deleted while the flow is still read.
  auth_request_id uuid,
  created_at      timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL
);
CREATE INDEX flow_expires_idx ON flow (expires_at);

-- ---------------------------------------------------------------------------------------------
-- token families, codes, refresh tokens, replay guards

CREATE TABLE token_family (
  id                  uuid        NOT NULL PRIMARY KEY,
  tenant_id           uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  client_id           text        NOT NULL,
  user_id             uuid,
  scope               text        NOT NULL,
  auth_time           timestamptz,
  acr                 text,
  amr                 text[]      NOT NULL,
  session_id          uuid,
  claims              jsonb,
  created_at          timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at          timestamptz,
  revoked_reason      text        CHECK (revoked_reason IN ('code_reuse', 'refresh_reuse',
                        'user_recovery', 'client_deleted', 'user_deleted', 'admin'))
);
CREATE INDEX token_family_user_idx ON token_family (tenant_id, user_id);
CREATE INDEX token_family_client_idx ON token_family (tenant_id, client_id);

-- authorization_code (0001): add the authentication context and bind every code to its family.
-- 0.1 has never been released; the ALTERs are still valid on an empty Phase 1 table.
ALTER TABLE authorization_code
  ADD COLUMN user_id    uuid        NOT NULL,
  ADD COLUMN session_id uuid        NOT NULL,
  ADD COLUMN auth_time  timestamptz NOT NULL,
  ADD COLUMN acr        text        NOT NULL,
  ADD COLUMN amr        text[]      NOT NULL,
  ALTER COLUMN code_challenge DROP NOT NULL,
  ALTER COLUMN token_family_id SET NOT NULL,
  DROP CONSTRAINT authorization_code_tenant_id_fkey,
  ADD CONSTRAINT authorization_code_tenant_id_fkey
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
  ADD CONSTRAINT authorization_code_token_family_id_fkey
    FOREIGN KEY (token_family_id) REFERENCES token_family(id) ON DELETE CASCADE;
CREATE INDEX authorization_code_family_idx ON authorization_code (token_family_id);
CREATE INDEX authorization_code_expires_idx ON authorization_code (expires_at);

CREATE TABLE refresh_token (
  token_hash  bytea       NOT NULL PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  family_id   uuid        NOT NULL REFERENCES token_family(id) ON DELETE CASCADE,
  parent_hash bytea       CHECK (octet_length(parent_hash) = 32),
  scope       text        NOT NULL,
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX refresh_token_family_idx ON refresh_token (family_id);
CREATE INDEX refresh_token_expires_idx ON refresh_token (expires_at);

CREATE TABLE replay_guard (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  kind       text        NOT NULL CHECK (kind IN ('client_assertion_jti')),
  value_hash bytea       NOT NULL CHECK (octet_length(value_hash) = 32),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, kind, value_hash)
);
CREATE INDEX replay_guard_expires_idx ON replay_guard (expires_at);

-- ---------------------------------------------------------------------------------------------
-- installation-wide setup token, email outbox

CREATE TABLE admin_setup_token (
  token_hash bytea       NOT NULL PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

CREATE TABLE email_outbox (
  id              uuid        NOT NULL PRIMARY KEY,
  tenant_id       uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  recipient       text        NOT NULL,
  template        text        NOT NULL,
  payload         jsonb       NOT NULL,
  attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL,
  created_at      timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL,
  sent_at         timestamptz,
  last_error      text
);
-- The worker's claim query scans unsent rows by due time.
CREATE INDEX email_outbox_due_idx ON email_outbox (next_attempt_at) WHERE sent_at IS NULL;
CREATE INDEX email_outbox_expires_idx ON email_outbox (expires_at);
