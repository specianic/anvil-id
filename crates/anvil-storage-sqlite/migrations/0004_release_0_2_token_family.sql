-- no-transaction
--
-- Release 0.2: token_family accepts the new revoke reasons consent_revoked, session_revoked and
-- token_revoked. SQLite cannot alter a CHECK constraint, so the table is rebuilt with the
-- official 12-step procedure (https://www.sqlite.org/lang_altertable.html#otheralter).
--
-- Why no-transaction: authorization_code, refresh_token and access_token reference token_family
-- ON DELETE CASCADE. With foreign keys on, DROP TABLE token_family would cascade-delete every
-- code and refresh token. `PRAGMA foreign_keys` is a no-op inside a transaction, so sqlx must not
-- wrap this file in one: the script turns foreign keys off, runs the rebuild in its own
-- transaction, verifies referential integrity and turns foreign keys back on.
--
-- Integrity check: the count of `pragma_foreign_key_check` rows is inserted into a temporary
-- table whose CHECK only accepts 0, so any dangling reference aborts the script before COMMIT
-- (the rebuild is then not applied and sqlx does not record the migration).
--
-- Re-running after a crash between COMMIT and sqlx's bookkeeping insert is safe: the rebuild
-- copies every row again and ends in the same schema.

PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE token_family_new (
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
                         'user_deleted', 'admin', 'consent_revoked', 'session_revoked',
                         'token_revoked')),
  CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
) STRICT;

INSERT INTO token_family_new (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                              session_id, claims, created_at, absolute_expires_at, revoked_at,
                              revoked_reason)
  SELECT id, tenant_id, client_id, user_id, scope, auth_time, acr, amr, session_id, claims,
         created_at, absolute_expires_at, revoked_at, revoked_reason
    FROM token_family;

-- anvil:non-destructive-rebuild
DROP TABLE token_family;
ALTER TABLE token_family_new RENAME TO token_family;

CREATE INDEX token_family_user_idx ON token_family (tenant_id, user_id);
CREATE INDEX token_family_client_idx ON token_family (tenant_id, client_id);
CREATE INDEX token_family_expires_idx ON token_family (absolute_expires_at);

CREATE TEMP TABLE anvil_fk_violations (n INTEGER NOT NULL CHECK (n = 0));
INSERT INTO anvil_fk_violations (n) SELECT count(*) FROM pragma_foreign_key_check;
DROP TABLE anvil_fk_violations;

COMMIT;

PRAGMA foreign_keys = ON;
