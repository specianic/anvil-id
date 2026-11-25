-- Spike scope: tenants and authorization codes.
-- Ids are 16-byte UUID BLOBs, timestamps are INTEGER unix milliseconds.

CREATE TABLE tenant (
  id           BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
  slug         TEXT    NOT NULL UNIQUE,
  display_name TEXT    NOT NULL,
  created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE authorization_code (
  code_hash       BLOB    NOT NULL PRIMARY KEY CHECK (length(code_hash) = 32),
  tenant_id       BLOB    NOT NULL REFERENCES tenant(id),
  client_id       TEXT    NOT NULL,
  redirect_uri    TEXT    NOT NULL,
  scope           TEXT    NOT NULL,
  code_challenge  TEXT    NOT NULL,
  nonce           TEXT,
  token_family_id BLOB    CHECK (token_family_id IS NULL OR length(token_family_id) = 16),
  expires_at      INTEGER NOT NULL,
  consumed_at     INTEGER,
  created_at      INTEGER NOT NULL
) STRICT;
