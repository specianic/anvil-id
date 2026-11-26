-- Release 1.0 schema, additive part (forward-only expand migration on top of 0007_release_0_4).
--
-- New tables and ADD COLUMN with defaults only: no existing row changes. The CHECK and foreign-key
-- changes on referenced tables (connection, role, role_assignment, replay_guard, email_template)
-- need table rebuilds with foreign keys off and live in 0009_release_1_0_rebuild.sql, so a
-- failing rebuild leaves this additive schema intact.
--
-- Conventions (as in 0001-0007): ids are 16-byte UUID BLOBs, secret hashes are 32-byte BLOBs,
-- timestamps are INTEGER unix milliseconds, JSON is TEXT guarded by json_valid, enums are
-- snake_case TEXT guarded by CHECK constraints. Every tenant-scoped table references tenant(id)
-- ON DELETE CASCADE; rows that point at other tenant rows use composite (tenant_id, id) foreign
-- keys so a reference can never cross tenants.

-- ---------------------------------------------------------------------------------------------
-- Organizations (ORG-02): a group of users inside one tenant. The slug rule matches
-- validate_org_slug (2-63 characters of a-z, 0-9 and '-', not starting with '-').

CREATE TABLE organization (
  id           BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id    BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  slug         TEXT    NOT NULL CHECK (length(slug) BETWEEN 2 AND 63
                                       AND slug NOT GLOB '*[^a-z0-9-]*'
                                       AND substr(slug, 1, 1) <> '-'),
  display_name TEXT    NOT NULL,
  mfa_policy   TEXT    CHECK (mfa_policy IS NULL OR mfa_policy IN ('off', 'optional', 'required')),
  settings     TEXT    NOT NULL CHECK (json_valid(settings)),
  metadata     TEXT    NOT NULL CHECK (json_valid(metadata)),
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX organization_slug_uq ON organization (tenant_id, slug);
-- Target of the composite foreign keys below (and of role/connection in 0009).
CREATE UNIQUE INDEX organization_tenant_id_uq ON organization (tenant_id, id);

-- Memberships. Target of role_assignment's (tenant_id, org_id, user_id) foreign key (0009), so
-- removing a membership removes the member's assignments in the org.

CREATE TABLE org_membership (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  org_id     BLOB    NOT NULL CHECK (length(org_id) = 16),
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, org_id, user_id),
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE
) STRICT;
CREATE INDEX org_membership_user_idx ON org_membership (tenant_id, user_id);

-- Invitations: the token only as its SHA-256 hash, the email normalised by the caller, `roles`
-- the JSON array of role ids assigned on acceptance. The inviter is stored like an audit actor
-- (kind + optional id). `accepted_user_id` has no foreign key: the invitation stays as a record
-- after the user is deleted. Acceptance is one conditional UPDATE (accepted_at IS NULL AND
-- revoked_at IS NULL AND expires_at > now) inside the accept intent.

CREATE TABLE org_invitation (
  id               BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id        BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  org_id           BLOB    NOT NULL CHECK (length(org_id) = 16),
  email            TEXT    NOT NULL CHECK (length(email) BETWEEN 1 AND 254),
  roles            TEXT    NOT NULL CHECK (json_valid(roles) AND json_type(roles) = 'array'),
  token_hash       BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  invited_by_kind  TEXT    NOT NULL CHECK (invited_by_kind IN ('user', 'client', 'admin', 'system')),
  invited_by_id    TEXT,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  accepted_at      INTEGER,
  accepted_user_id BLOB    CHECK (accepted_user_id IS NULL OR length(accepted_user_id) = 16),
  revoked_at       INTEGER,
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  CHECK ((accepted_at IS NULL) = (accepted_user_id IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL)
) STRICT;
CREATE INDEX org_invitation_org_idx ON org_invitation (tenant_id, org_id, created_at);

-- Domain claims (ORG-04). Several orgs of a tenant may hold pending claims for one domain; the
-- partial unique index lets at most one org per tenant hold it verified. `connection_id` is the
-- routing target, a connection of the same org (checked by the writing statements); it has no
-- foreign key because SQLite would null tenant_id and org_id too on ON DELETE SET NULL. Deleting
-- the connection clears it through a trigger on connection (created in 0009, after the
-- connection rebuild).

CREATE TABLE org_domain (
  id                   BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id            BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  org_id               BLOB    NOT NULL CHECK (length(org_id) = 16),
  domain               TEXT    NOT NULL CHECK (length(domain) BETWEEN 1 AND 253
                                               AND domain = lower(domain)),
  token                TEXT    NOT NULL CHECK (length(token) >= 1),
  status               TEXT    NOT NULL CHECK (status IN ('pending', 'verified')),
  connection_id        BLOB    CHECK (connection_id IS NULL OR length(connection_id) = 16),
  routing              INTEGER NOT NULL CHECK (routing IN (0, 1)),
  allow_local_password INTEGER NOT NULL DEFAULT 1 CHECK (allow_local_password IN (0, 1)),
  verified_at          INTEGER,
  last_checked_at      INTEGER,
  failing_since        INTEGER,
  created_at           INTEGER NOT NULL,
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  CHECK ((status = 'verified') = (verified_at IS NOT NULL)),
  CHECK (failing_since IS NULL OR verified_at IS NOT NULL)
) STRICT;
CREATE UNIQUE INDEX org_domain_org_uq ON org_domain (tenant_id, org_id, domain);
CREATE INDEX org_domain_domain_idx ON org_domain (tenant_id, domain);
CREATE UNIQUE INDEX org_domain_verified_uq ON org_domain (tenant_id, domain)
  WHERE verified_at IS NOT NULL;
CREATE INDEX org_domain_recheck_idx ON org_domain (last_checked_at, id)
  WHERE verified_at IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- The active org of a grant on codes and families. No foreign key: the intents that end a
-- membership or delete an org revoke the org-bound families in their own transaction (reason
-- `admin`), and an expired code needs no org. Existing rows: no org.

ALTER TABLE authorization_code ADD COLUMN org_id BLOB
  CHECK (org_id IS NULL OR length(org_id) = 16);
ALTER TABLE token_family ADD COLUMN org_id BLOB
  CHECK (org_id IS NULL OR length(org_id) = 16);
CREATE INDEX token_family_org_idx ON token_family (tenant_id, org_id, user_id)
  WHERE org_id IS NOT NULL;

-- Client organization policy (`organization` authorization parameter). Existing clients: off.

ALTER TABLE client ADD COLUMN organization TEXT NOT NULL DEFAULT 'off'
  CHECK (organization IN ('off', 'optional', 'required'));
