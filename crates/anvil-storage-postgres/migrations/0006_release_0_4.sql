-- Release 0.4 "Operate it": roles and assignments, custom user attributes, webhook endpoints and
-- the delivery queue, dynamic client registration (initial access tokens, client registration
-- columns), Client ID Metadata Document clients, and RFC 8707 resources on consent grants.
--
-- Additive only (no DROP, RENAME or type change), except the administrator backfill at the end.
-- New columns have constant defaults (metadata-only, no table rewrite). The logical schema matches
-- the SQLite 0007 migration (same semantics, native Postgres types: uuid, timestamptz, jsonb,
-- text[], bytea).

-- ---------------------------------------------------------------------------------------------
-- Roles (ORG-05). `org_id` is reserved for organizations (always NULL in 0.4); tenant-level role
-- names are unique per tenant.

CREATE TABLE role (
  id          uuid        NOT NULL PRIMARY KEY,
  tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  org_id      uuid,
  name        text        NOT NULL,
  description text        NOT NULL,
  -- Permission strings in the order given (callers normalise them).
  permissions text[]      NOT NULL,
  created_at  timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  -- Composite FK target for assignments (tenant isolation by schema).
  CONSTRAINT role_tenant_id_key UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX role_tenant_name_key ON role (tenant_id, name) WHERE org_id IS NULL;

-- Both references are composite, so an assignment can never pair a role and a user of different
-- tenants. Deleting the role or the user removes its assignments.
CREATE TABLE role_assignment (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  role_id    uuid        NOT NULL,
  user_id    uuid        NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, role_id, user_id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES role (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX role_assignment_user_idx ON role_assignment (tenant_id, user_id);

-- ---------------------------------------------------------------------------------------------
-- Custom user attributes (ADM-05/ADM-06): per-tenant definitions and one JSON object per user.

CREATE TABLE attribute_definition (
  tenant_id     uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  name          text        NOT NULL,
  -- JSON Schema (at most 16 KiB, checked by the service).
  schema        jsonb       NOT NULL,
  required      boolean     NOT NULL,
  user_editable boolean     NOT NULL,
  -- ClaimRule; NULL = not emitted.
  claim         jsonb       CHECK (claim IS NULL OR jsonb_typeof(claim) = 'object'),
  position      bigint      NOT NULL CHECK (position >= 0 AND position <= 4294967295),
  created_at    timestamptz NOT NULL,
  updated_at    timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, name)
);

ALTER TABLE "user"
  ADD COLUMN attributes jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attributes) = 'object');

-- ---------------------------------------------------------------------------------------------
-- Dynamic client registration (AUTH-14) and Client ID Metadata Documents (OIDC-17).

ALTER TABLE client
  ADD COLUMN registration_source text NOT NULL DEFAULT 'static'
    CHECK (registration_source IN ('static', 'dynamic', 'cimd')),
  ADD COLUMN metadata_expires_at timestamptz,
  ADD COLUMN registration_access_token_hash bytea
    CHECK (registration_access_token_hash IS NULL
           OR octet_length(registration_access_token_hash) = 32);
-- The DCR `max_clients` cap counts clients per source.
CREATE INDEX client_tenant_source_idx ON client (tenant_id, registration_source);

-- RFC 7591 §3 initial access tokens, stored by hash only.
CREATE TABLE initial_access_token (
  id             uuid        NOT NULL PRIMARY KEY,
  tenant_id      uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  description    text        NOT NULL,
  token_hash     bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  expires_at     timestamptz,
  -- NULL = unlimited.
  uses_remaining bigint      CHECK (uses_remaining IS NULL
                                    OR (uses_remaining >= 0 AND uses_remaining <= 4294967295)),
  created_at     timestamptz NOT NULL,
  revoked_at     timestamptz
);
CREATE INDEX initial_access_token_tenant_idx ON initial_access_token (tenant_id, id);

-- ---------------------------------------------------------------------------------------------
-- RFC 8707 resources covered by a consent grant (sorted, de-duplicated JSON array of strings).

ALTER TABLE consent_grant
  ADD COLUMN resources jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(resources) = 'array');

-- ---------------------------------------------------------------------------------------------
-- Webhooks (AGT-02). Signing secrets are KEK-sealed (purpose anvilid/webhook-secret/v1, AAD
-- tenant id || endpoint id) and never stored in plaintext.

CREATE TABLE webhook_endpoint (
  id                         uuid        NOT NULL PRIMARY KEY,
  tenant_id                  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  name                       text        NOT NULL,
  url                        text        NOT NULL,
  -- Subscribed event types (WebhookEventType wire names), in the order given.
  events                     text[]      NOT NULL,
  enabled                    boolean     NOT NULL,
  secret_enc                 bytea       NOT NULL CHECK (octet_length(secret_enc) >= 1),
  previous_secret_enc        bytea       CHECK (previous_secret_enc IS NULL
                                                OR octet_length(previous_secret_enc) >= 1),
  previous_secret_expires_at timestamptz,
  -- Fixed, code-defined reason when the system disabled the endpoint (e.g. 'gone').
  disabled_reason            text,
  created_at                 timestamptz NOT NULL,
  updated_at                 timestamptz NOT NULL,
  CHECK ((previous_secret_enc IS NULL) = (previous_secret_expires_at IS NULL)),
  CONSTRAINT webhook_endpoint_tenant_name_key UNIQUE (tenant_id, name),
  -- Composite FK target for deliveries.
  CONSTRAINT webhook_endpoint_tenant_id_key UNIQUE (tenant_id, id)
);

-- The delivery queue. Workers on any node claim due rows with FOR UPDATE SKIP LOCKED and lease
-- them by moving next_attempt_at forward.
CREATE TABLE webhook_delivery (
  id               uuid        NOT NULL PRIMARY KEY,
  tenant_id        uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  endpoint_id      uuid        NOT NULL,
  -- WebhookEventType wire name (validated when read, like SQLite).
  event_type       text        NOT NULL CHECK (length(event_type) >= 1),
  -- The ids-only body, byte for byte.
  payload_json     text        NOT NULL,
  attempts         integer     NOT NULL CHECK (attempts >= 0),
  next_attempt_at  timestamptz NOT NULL,
  status           text        NOT NULL CHECK (status IN ('pending', 'delivered', 'failed')),
  last_http_status integer     CHECK (last_http_status IS NULL
                                      OR last_http_status BETWEEN 100 AND 999),
  -- Error class only, never a response body.
  last_error       text,
  created_at       timestamptz NOT NULL,
  completed_at     timestamptz,
  FOREIGN KEY (tenant_id, endpoint_id) REFERENCES webhook_endpoint (tenant_id, id)
    ON DELETE CASCADE,
  CHECK ((status = 'pending') = (completed_at IS NULL))
);
CREATE INDEX webhook_delivery_due_idx ON webhook_delivery (status, next_attempt_at);
-- Delivery log per endpoint, newest first.
CREATE INDEX webhook_delivery_endpoint_idx ON webhook_delivery (tenant_id, endpoint_id, id);
-- Retention purge of completed deliveries.
CREATE INDEX webhook_delivery_completed_idx ON webhook_delivery (completed_at)
  WHERE completed_at IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Backfill: upgraded installations keep their administrators. The system tenant (if installed)
-- gets the `administrator` role with [admin:write] (what SetupRepo::install creates on a fresh
-- installation), and every existing system-tenant user is assigned it. This one row uses a random
-- (v4) id: gen_random_uuid() is the only generator available on every supported Postgres version,
-- and nothing depends on role ids being time-ordered.

INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
SELECT gen_random_uuid(), t.id, NULL, 'administrator', 'Full administrative access',
       ARRAY['admin:write']::text[], date_trunc('milliseconds', now()),
       date_trunc('milliseconds', now())
  FROM tenant t
 WHERE t.slug = 'system';

INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
SELECT r.tenant_id, r.id, u.id, r.created_at
  FROM role r
  JOIN tenant t ON t.id = r.tenant_id
  JOIN "user" u ON u.tenant_id = r.tenant_id
 WHERE t.slug = 'system' AND r.name = 'administrator' AND r.org_id IS NULL;
