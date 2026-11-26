-- no-transaction
--
-- anvil:non-destructive-rebuild
--
-- Release 1.0: rebuild of the tables whose CHECK constraints or foreign keys change. SQLite cannot
-- alter either in place, so each table is rebuilt with the official procedure
-- (https://www.sqlite.org/lang_altertable.html#otheralter): create `x_new`, copy every row with an
-- explicit column list, drop `x`, rename `x_new` to `x`, recreate the indexes.
--
--   connection       kind gains `saml`; org_id + composite FK (tenant_id, org_id) -> organization
--   role             composite FK (tenant_id, org_id) -> organization; per-org unique names
--   role_assignment  org_id; the primary key becomes two partial unique indexes (tenant-wide and
--                    per-org assignments); FK (tenant_id, org_id, user_id) -> org_membership
--   replay_guard     kind gains `saml_assertion_id`
--   email_template   kind gains `org_invitation`
--
-- Why no-transaction (as 0004): identity_link references connection and role_assignment
-- references role ON DELETE CASCADE. With foreign keys on, DROP TABLE connection would
-- cascade-delete every identity link and DROP TABLE role every role assignment. `PRAGMA
-- foreign_keys` is a no-op inside a transaction, so sqlx must not wrap this file in one: the
-- script turns foreign keys off, runs every rebuild in one explicit transaction, verifies
-- referential integrity and turns foreign keys back on.
--
-- Integrity check: the count of `pragma_foreign_key_check` rows is inserted into a temporary table
-- whose CHECK only accepts 0, so any dangling reference aborts the script before COMMIT (nothing
-- is applied and sqlx does not record the migration).
--
-- The rebuilds commit or roll back together. Re-running after a crash between COMMIT and sqlx's
-- bookkeeping insert is safe: no 1.0 binary has written org data yet, so copying every row again
-- (org_id NULL) ends in the same schema; DROP TABLE also drops the indexes and the trigger
-- recreated below.

PRAGMA foreign_keys = OFF;

BEGIN;

-- ---------------------------------------------------------------------------------------------
-- connection

CREATE TABLE connection_new (
  id                   BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id            BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  slug                 TEXT    NOT NULL CHECK (length(slug) >= 1),
  display_name         TEXT    NOT NULL,
  kind                 TEXT    NOT NULL CHECK (kind IN
                         ('google', 'apple', 'microsoft', 'github', 'oidc', 'oauth2', 'saml')),
  enabled              INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  config               TEXT    NOT NULL CHECK (json_valid(config)),
  secret_enc           BLOB    CHECK (secret_enc IS NULL OR length(secret_enc) >= 1),
  trust_email_verified INTEGER NOT NULL CHECK (trust_email_verified IN (0, 1)),
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL,
  org_id               BLOB    CHECK (org_id IS NULL OR length(org_id) = 16),
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO connection_new (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                            trust_email_verified, created_at, updated_at, org_id)
  SELECT id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
         trust_email_verified, created_at, updated_at, NULL
    FROM connection;

DROP TABLE connection;
ALTER TABLE connection_new RENAME TO connection;

CREATE UNIQUE INDEX connection_slug_uq ON connection (tenant_id, slug);
-- Target of identity_link's composite foreign key (a link never crosses tenants).
CREATE UNIQUE INDEX connection_tenant_id_uq ON connection (tenant_id, id);
CREATE INDEX connection_org_idx ON connection (tenant_id, org_id) WHERE org_id IS NOT NULL;

-- A deleted connection stops being a domain's routing target (org_domain has no foreign key to
-- connection, see 0008).
CREATE TRIGGER connection_clears_org_domain AFTER DELETE ON connection
BEGIN
  UPDATE org_domain SET connection_id = NULL
   WHERE tenant_id = old.tenant_id AND connection_id = old.id;
END;

-- ---------------------------------------------------------------------------------------------
-- role

CREATE TABLE role_new (
  id          BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  tenant_id   BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  org_id      BLOB    CHECK (org_id IS NULL OR length(org_id) = 16),
  name        TEXT    NOT NULL CHECK (length(name) >= 1),
  description TEXT    NOT NULL,
  permissions TEXT    NOT NULL CHECK (json_valid(permissions)),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE
) STRICT;

INSERT INTO role_new (id, tenant_id, org_id, name, description, permissions, created_at,
                      updated_at)
  SELECT id, tenant_id, org_id, name, description, permissions, created_at, updated_at
    FROM role;

DROP TABLE role;
ALTER TABLE role_new RENAME TO role;

-- Target of role_assignment's composite foreign key.
CREATE UNIQUE INDEX role_tenant_id_uq ON role (tenant_id, id);
CREATE UNIQUE INDEX role_tenant_name_uq ON role (tenant_id, name) WHERE org_id IS NULL;
CREATE UNIQUE INDEX role_org_name_uq ON role (tenant_id, org_id, name) WHERE org_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- role_assignment: org_id NULL = tenant-wide (as in 0.4), set = holds only in that org. The
-- membership foreign key is MATCH SIMPLE: it is not checked when org_id is NULL.

CREATE TABLE role_assignment_new (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  role_id    BLOB    NOT NULL CHECK (length(role_id) = 16),
  user_id    BLOB    NOT NULL CHECK (length(user_id) = 16),
  org_id     BLOB    CHECK (org_id IS NULL OR length(org_id) = 16),
  created_at INTEGER NOT NULL,
  FOREIGN KEY (tenant_id, role_id) REFERENCES role (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES user (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, org_id, user_id) REFERENCES org_membership (tenant_id, org_id, user_id)
    ON DELETE CASCADE
) STRICT;

INSERT INTO role_assignment_new (tenant_id, role_id, user_id, org_id, created_at)
  SELECT tenant_id, role_id, user_id, NULL, created_at
    FROM role_assignment;

DROP TABLE role_assignment;
ALTER TABLE role_assignment_new RENAME TO role_assignment;

CREATE UNIQUE INDEX role_assignment_tenant_uq ON role_assignment (tenant_id, role_id, user_id)
  WHERE org_id IS NULL;
CREATE UNIQUE INDEX role_assignment_org_uq ON role_assignment (tenant_id, role_id, user_id, org_id)
  WHERE org_id IS NOT NULL;
CREATE INDEX role_assignment_user_idx ON role_assignment (tenant_id, user_id);
CREATE INDEX role_assignment_member_idx ON role_assignment (tenant_id, org_id, user_id)
  WHERE org_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- replay_guard (not referenced by any foreign key)

CREATE TABLE replay_guard_new (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN ('client_assertion_jti', 'saml_assertion_id')),
  value_hash BLOB    NOT NULL CHECK (length(value_hash) = 32),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind, value_hash)
) STRICT;

INSERT INTO replay_guard_new (tenant_id, kind, value_hash, expires_at)
  SELECT tenant_id, kind, value_hash, expires_at
    FROM replay_guard;

DROP TABLE replay_guard;
ALTER TABLE replay_guard_new RENAME TO replay_guard;

CREATE INDEX replay_guard_expires_idx ON replay_guard (expires_at);

-- ---------------------------------------------------------------------------------------------
-- email_template (not referenced by any foreign key)

CREATE TABLE email_template_new (
  tenant_id  BLOB    NOT NULL REFERENCES tenant (id) ON DELETE CASCADE,
  kind       TEXT    NOT NULL CHECK (kind IN
               ('verification', 'recovery', 'invitation', 'password_changed',
                'recovery_code_used', 'login_code', 'email_change', 'email_changed',
                'org_invitation')),
  subject    TEXT    NOT NULL,
  body_html  TEXT    NOT NULL,
  body_text  TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, kind)
) STRICT;

INSERT INTO email_template_new (tenant_id, kind, subject, body_html, body_text, updated_at)
  SELECT tenant_id, kind, subject, body_html, body_text, updated_at
    FROM email_template;

DROP TABLE email_template;
ALTER TABLE email_template_new RENAME TO email_template;

-- ---------------------------------------------------------------------------------------------
-- Integrity: no dangling reference anywhere, or nothing commits.

CREATE TEMP TABLE anvil_fk_violations (n INTEGER NOT NULL CHECK (n = 0));
INSERT INTO anvil_fk_violations (n) SELECT count(*) FROM pragma_foreign_key_check;
DROP TABLE anvil_fk_violations;

COMMIT;

PRAGMA foreign_keys = ON;
