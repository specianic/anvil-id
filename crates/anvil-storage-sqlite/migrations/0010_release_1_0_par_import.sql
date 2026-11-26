-- Release 1.0, Phase 7 additive part (forward-only expand migration on top of
-- 0009_release_1_0_rebuild). 0008 and 0009 are the pinned 1.0.0-beta.1 schema and stay untouched.
--
-- Adds, without changing any existing row:
--   pushed_authorization_request  RFC 9126 pushed requests, stored by the SHA-256 hash of the
--                                 request_uri, consumed once (OIDC-18)
--   password_hash_profile         per-tenant legacy hash parameters for imported passwords
--                                 (Firebase scrypt); the signer key is stored KEK-sealed only
--   client.require_pushed_authorization_requests, client.client_kind, client.headless_native
--                                 ADD COLUMN with defaults (false, 'application', false)
--
-- Conventions (as in 0001-0009): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT guarded by json_valid. client_kind has
-- no CHECK on purpose: adding a kind later must not need a table rebuild; the backend maps an
-- unknown value to StorageError::Corrupt.

-- ---------------------------------------------------------------------------------------------
-- Pushed authorization requests. The composite foreign key keeps the client in the same tenant
-- and deletes the client's pushed requests with it. purge_expired deletes rows with
-- expires_at <= now (consumed or not).

CREATE TABLE pushed_authorization_request (
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  uri_hash    BLOB    NOT NULL CHECK (length(uri_hash) = 32),
  client_id   TEXT    NOT NULL,
  params      TEXT    NOT NULL CHECK (json_valid(params)),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed_at INTEGER,
  PRIMARY KEY (tenant_id, uri_hash),
  FOREIGN KEY (tenant_id, client_id) REFERENCES client (tenant_id, client_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX pushed_authorization_request_expires_idx ON pushed_authorization_request (expires_at);
CREATE INDEX pushed_authorization_request_client_idx
  ON pushed_authorization_request (tenant_id, client_id);

-- ---------------------------------------------------------------------------------------------
-- Password hash profiles. kind (e.g. 'firebase_scrypt') has no CHECK for the same reason as
-- client_kind; an unknown value reads as StorageError::Corrupt.

CREATE TABLE password_hash_profile (
  id             BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id      BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  name           TEXT    NOT NULL CHECK (length(name) >= 1),
  kind           TEXT    NOT NULL,
  salt_separator BLOB    NOT NULL,
  rounds         INTEGER NOT NULL CHECK (rounds >= 0),
  mem_cost       INTEGER NOT NULL CHECK (mem_cost BETWEEN 0 AND 255),
  signer_key_enc BLOB    NOT NULL,
  created_at     INTEGER NOT NULL,
  UNIQUE (tenant_id, name)
) STRICT;

-- ---------------------------------------------------------------------------------------------
-- Client fields: PAR requirement, client kind (application | agent) and headless native mode.

ALTER TABLE client ADD COLUMN require_pushed_authorization_requests INTEGER NOT NULL DEFAULT 0
  CHECK (require_pushed_authorization_requests IN (0, 1));
ALTER TABLE client ADD COLUMN client_kind TEXT NOT NULL DEFAULT 'application';
ALTER TABLE client ADD COLUMN headless_native INTEGER NOT NULL DEFAULT 0
  CHECK (headless_native IN (0, 1));
