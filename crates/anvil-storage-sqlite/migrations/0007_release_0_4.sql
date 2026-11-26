-- Release 0.4 schema (forward-only expand migration on top of 0006_release_0_3_logout_issuer).
--
-- Additive only (new tables, ADD COLUMN with defaults), except the administrator backfill at the
-- end, which inserts rows and changes none.
--
-- Conventions (as in 0001-0006): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT guarded by json_valid, enums are
-- snake_case TEXT guarded by CHECK constraints. Every tenant-scoped table references tenant(id)
-- ON DELETE CASCADE; rows that point at other tenant rows use composite (tenant_id, id) foreign
-- keys so a reference can never cross tenants. Webhook signing secrets are stored KEK-sealed
-- (secret_enc, previous_secret_enc); initial access tokens and registration access tokens only as
-- their hash.

-- ---------------------------------------------------------------------------------------------
-- Roles (ADM-05): tenant-level permission sets. `org_id` is always NULL in 0.4 (Phase 6 adds
-- org-scoped roles); tenant-level names are unique per tenant.

CREATE TABLE role (
  id          BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  org_id      BLOB    CHECK (org_id IS NULL OR length(org_id) = 16),
  name        TEXT    NOT NULL CHECK (length(name) >= 1),
  description TEXT    NOT NULL,
  permissions TEXT    NOT NULL CHECK (json_valid(permissions)),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT;
-- Target of role_assignment's composite foreign key.
CREATE UNIQUE INDEX role_tenant_id_uq ON role (tenant_id, id);
CREATE UNIQUE INDEX role_tenant_name_uq ON role (tenant_id, name) WHERE org_id IS NULL;

CREATE TABLE role_assignment (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  role_id    BLOB    NOT NULL CHECK (length(role_id) = 16),
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, role_id, user_id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES role (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX role_assignment_user_idx ON role_assignment (tenant_id, user_id);

-- ---------------------------------------------------------------------------------------------
-- Custom user attributes (ADM-06): per-tenant definitions and one JSON object per user. Values
-- outlive their definition (deleting a definition leaves user.attributes untouched).

CREATE TABLE attribute_definition (
  tenant_id     BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  schema        TEXT    NOT NULL CHECK (json_valid(schema)),
  required      INTEGER NOT NULL CHECK (required IN (0, 1)),
  user_editable INTEGER NOT NULL CHECK (user_editable IN (0, 1)),
  claim         TEXT    CHECK (claim IS NULL OR json_valid(claim)),
  position      INTEGER NOT NULL CHECK (position >= 0),
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, name)
) STRICT;

ALTER TABLE user ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}'
  CHECK (json_valid(attributes) AND json_type(attributes) = 'object');

-- ---------------------------------------------------------------------------------------------
-- Webhooks: endpoints and the delivery queue (enqueued by AuditRepo::append in the audit
-- transaction). `events` is the JSON array of subscribed event types.

CREATE TABLE webhook_endpoint (
  id                         BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id                  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  name                       TEXT    NOT NULL CHECK (length(name) >= 1),
  url                        TEXT    NOT NULL CHECK (length(url) >= 1),
  events                     TEXT    NOT NULL CHECK (json_valid(events)),
  enabled                    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  secret_enc                 BLOB    NOT NULL CHECK (length(secret_enc) >= 1),
  previous_secret_enc        BLOB    CHECK (previous_secret_enc IS NULL
                                            OR length(previous_secret_enc) >= 1),
  previous_secret_expires_at INTEGER,
  disabled_reason            TEXT,
  created_at                 INTEGER NOT NULL,
  updated_at                 INTEGER NOT NULL,
  CHECK ((previous_secret_enc IS NULL) = (previous_secret_expires_at IS NULL))
) STRICT;
CREATE UNIQUE INDEX webhook_endpoint_name_uq ON webhook_endpoint (tenant_id, name);
-- Target of webhook_delivery's composite foreign key.
CREATE UNIQUE INDEX webhook_endpoint_tenant_id_uq ON webhook_endpoint (tenant_id, id);

CREATE TABLE webhook_delivery (
  id               BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id        BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  endpoint_id      BLOB    NOT NULL CHECK (length(endpoint_id) = 16),
  event_type       TEXT    NOT NULL CHECK (length(event_type) >= 1),
  payload_json     TEXT    NOT NULL CHECK (json_valid(payload_json)),
  attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at  INTEGER NOT NULL,
  status           TEXT    NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
  last_http_status INTEGER CHECK (last_http_status IS NULL
                                  OR last_http_status BETWEEN 100 AND 999),
  last_error       TEXT,
  created_at       INTEGER NOT NULL,
  completed_at     INTEGER,
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES webhook_endpoint (tenant_id, id)
    ON DELETE CASCADE,
  CHECK ((status = 'pending') = (completed_at IS NULL))
) STRICT;
CREATE INDEX webhook_delivery_due_idx ON webhook_delivery (status, next_attempt_at);
CREATE INDEX webhook_delivery_endpoint_idx ON webhook_delivery (tenant_id, endpoint_id, id);
CREATE INDEX webhook_delivery_completed_idx ON webhook_delivery (completed_at)
  WHERE completed_at IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Dynamic client registration (AUTH-14) and Client ID Metadata Documents (OIDC-17).

CREATE TABLE initial_access_token (
  id             BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id      BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  description    TEXT    NOT NULL,
  token_hash     BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  expires_at     INTEGER,
  uses_remaining INTEGER CHECK (uses_remaining IS NULL OR uses_remaining >= 0),
  created_at     INTEGER NOT NULL,
  revoked_at     INTEGER
) STRICT;
CREATE INDEX initial_access_token_tenant_idx ON initial_access_token (tenant_id, id);

-- Existing clients are static registrations.
ALTER TABLE client ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'static'
  CHECK (registration_source IN ('static', 'dynamic', 'cimd'));
ALTER TABLE client ADD COLUMN metadata_expires_at INTEGER;
ALTER TABLE client ADD COLUMN registration_access_token_hash BLOB
  CHECK (registration_access_token_hash IS NULL OR length(registration_access_token_hash) = 32);
CREATE INDEX client_source_idx ON client (tenant_id, registration_source);

-- ---------------------------------------------------------------------------------------------
-- Consent grants: RFC 8707 resources covered by the grant (sorted JSON array). Existing grants
-- cover no resources.

ALTER TABLE consent_grant ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'
  CHECK (json_valid(resources));

-- ---------------------------------------------------------------------------------------------
-- Backfill: upgraded installations keep their administrators. Before 0.4 every user of the
-- system tenant was an administrator; 0.4 gates the admin API on the `admin:write` permission,
-- so the system tenant gets its `administrator` role and every existing system-tenant user holds
-- it. New installations get the role from SetupRepo::install instead (this statement then finds
-- no system tenant and inserts nothing).
--
-- The role id is a random UUID with the version 7 and RFC 9562 variant bits set, built in SQL in
-- the 16-byte BLOB encoding of every other id. Its first 48 bits are random rather than a
-- timestamp: UUIDv7 ordering is not needed for this single row. Timestamps are the migration
-- time in unix milliseconds.

INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
  SELECT unhex(hex(randomblob(6)) || '7' || substr(hex(randomblob(2)), 2) || '8'
               || substr(hex(randomblob(8)), 2)),
         t.id, NULL, 'administrator', 'Full administrative access', '["admin:write"]',
         CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER),
         CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
    FROM tenant t
   WHERE t.slug = 'system'
     AND NOT EXISTS (SELECT 1 FROM role r
                      WHERE r.tenant_id = t.id AND r.name = 'administrator'
                        AND r.org_id IS NULL);

INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
  SELECT u.tenant_id, r.id, u.id, CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)
    FROM user u
    JOIN tenant t ON t.id = u.tenant_id AND t.slug = 'system'
    JOIN role r ON r.tenant_id = t.id AND r.name = 'administrator' AND r.org_id IS NULL;
