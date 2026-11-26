-- Release 1.0, Phase 7 additive part (forward-only expand migration on top of 0007_release_1_0).
-- 0007 is the pinned 1.0.0-beta.1 schema and stays untouched.
--
-- Adds, without changing any existing row:
--   pushed_authorization_request  RFC 9126 pushed requests, stored by the SHA-256 hash of the
--                                 request_uri, consumed once (OIDC-18)
--   password_hash_profile         per-tenant legacy hash parameters for imported passwords
--                                 (Firebase scrypt); the signer key is stored KEK-sealed only
--   client.require_pushed_authorization_requests, client.client_kind, client.headless_native
--                                 ADD COLUMN with constant defaults (false, 'application', false):
--                                 metadata-only, no table rewrite
--
-- The logical schema matches SQLite 0010 (native Postgres types: uuid, timestamptz, jsonb,
-- bytea). client_kind and password_hash_profile.kind have no CHECK on purpose: adding a kind later
-- must not need a constraint swap; the backend maps an unknown value to StorageError::Corrupt.

-- ---------------------------------------------------------------------------------------------
-- Pushed authorization requests. The composite foreign key keeps the client in the same tenant
-- and deletes the client's pushed requests with it (target: client_tenant_client_id_key).
-- purge_expired deletes rows with expires_at <= now (consumed or not).

CREATE TABLE pushed_authorization_request (
  tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  uri_hash    bytea       NOT NULL CHECK (octet_length(uri_hash) = 32),
  client_id   text        NOT NULL,
  params      jsonb       NOT NULL CHECK (jsonb_typeof(params) = 'object'),
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, uri_hash),
  FOREIGN KEY (tenant_id, client_id) REFERENCES client (tenant_id, client_id) ON DELETE CASCADE
);
CREATE INDEX pushed_authorization_request_expires_idx ON pushed_authorization_request (expires_at);
CREATE INDEX pushed_authorization_request_client_idx
  ON pushed_authorization_request (tenant_id, client_id);

-- ---------------------------------------------------------------------------------------------
-- Password hash profiles (e.g. kind 'firebase_scrypt').

CREATE TABLE password_hash_profile (
  id             uuid        NOT NULL PRIMARY KEY,
  tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  name           text        NOT NULL CHECK (length(name) >= 1),
  kind           text        NOT NULL,
  salt_separator bytea       NOT NULL,
  rounds         bigint      NOT NULL CHECK (rounds BETWEEN 0 AND 4294967295),
  mem_cost       integer     NOT NULL CHECK (mem_cost BETWEEN 0 AND 255),
  -- AES-256-GCM envelope (KEK); never the raw signer key.
  signer_key_enc bytea       NOT NULL,
  created_at     timestamptz NOT NULL,
  CONSTRAINT password_hash_profile_tenant_name_key UNIQUE (tenant_id, name),
  -- Composite FK target (tenant isolation by schema).
  CONSTRAINT password_hash_profile_tenant_id_key UNIQUE (tenant_id, id)
);

-- ---------------------------------------------------------------------------------------------
-- Client fields: PAR requirement, client kind (application | agent) and headless native mode.

ALTER TABLE client ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;
ALTER TABLE client ADD COLUMN client_kind text NOT NULL DEFAULT 'application';
ALTER TABLE client ADD COLUMN headless_native boolean NOT NULL DEFAULT false;
