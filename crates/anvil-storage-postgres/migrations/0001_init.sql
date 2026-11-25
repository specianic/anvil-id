-- Spike scope: tenants and authorization codes.
-- Native types: uuid ids, bytea hashes, timestamptz timestamps, jsonb settings.

CREATE TABLE tenant (
  id           uuid        NOT NULL PRIMARY KEY,
  slug         text        NOT NULL UNIQUE,
  display_name text        NOT NULL,
  settings     jsonb       NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL
);

CREATE TABLE authorization_code (
  code_hash       bytea       NOT NULL PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  tenant_id       uuid        NOT NULL REFERENCES tenant(id),
  client_id       text        NOT NULL,
  redirect_uri    text        NOT NULL,
  scope           text        NOT NULL,
  code_challenge  text        NOT NULL,
  nonce           text,
  token_family_id uuid,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  created_at      timestamptz NOT NULL
);
