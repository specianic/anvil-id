-- Release 0.2 "Secure by default": passkeys, TOTP, recovery codes, consent, opaque access
-- tokens, audit log, per-tenant mail settings and job leases.
--
-- Additive only: no DROP TABLE / DROP COLUMN, no RENAME, no column type change. Constraint swaps
-- use DROP CONSTRAINT / ADD CONSTRAINT inside this migration's transaction, so a failure leaves
-- the 0.1 schema untouched. The logical schema matches the SQLite 0003/0004 migrations (same
-- columns and semantics, native Postgres types).

-- ---------------------------------------------------------------------------------------------
-- Schema-level tenant isolation (parity with SQLite): every user-owned row references its owner
-- through a composite foreign key (tenant_id, user_id) -> "user"(tenant_id, id), so a row can
-- never name a user of another tenant. "user".id is already unique; the (tenant_id, id) key is
-- the composite FK target. The 0.1 single-column user FKs on credential, self_service_token and
-- browser_session are swapped for composite ones (a composite FK implies the old one), and
-- authorization_code gains one; new tables declare the composite key directly. token_family and
-- access_token keep no user FK on purpose (revocation, not deletion).

ALTER TABLE "user" ADD CONSTRAINT user_tenant_id_key UNIQUE (tenant_id, id);

ALTER TABLE credential DROP CONSTRAINT credential_user_id_fkey;
ALTER TABLE credential ADD CONSTRAINT credential_tenant_user_fkey
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE self_service_token DROP CONSTRAINT self_service_token_user_id_fkey;
ALTER TABLE self_service_token ADD CONSTRAINT self_service_token_tenant_user_fkey
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE;

ALTER TABLE browser_session DROP CONSTRAINT browser_session_user_id_fkey;
ALTER TABLE browser_session ADD CONSTRAINT browser_session_tenant_user_fkey
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE;

-- authorization_code had no user FK in 0.1, and deleting a user only revokes its token families,
-- so an upgraded database may hold expired codes of deleted users. NOT VALID skips checking those
-- existing rows (they are unreachable: their family is revoked) while every new or updated row is
-- checked, and deleting a user now cascades to its codes, like SQLite.
ALTER TABLE authorization_code ADD CONSTRAINT authorization_code_tenant_user_fkey
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE NOT VALID;

-- ---------------------------------------------------------------------------------------------
-- credential: one row per credential (password, passkey, TOTP) instead of one per (user, kind).
--
-- `data` keeps its name (expand/contract): Argon2id PHC string | serialised passkey JSON |
-- hex-encoded KEK-sealed TOTP seed. `counter` is the WebAuthn signature counter or the last
-- accepted TOTP step. Migrated password rows get random (v4) ids; new rows get UUIDv7 ids.

ALTER TABLE credential ADD COLUMN id uuid;
UPDATE credential SET id = gen_random_uuid() WHERE id IS NULL;
ALTER TABLE credential ALTER COLUMN id SET NOT NULL;
ALTER TABLE credential DROP CONSTRAINT credential_pkey;
ALTER TABLE credential ADD PRIMARY KEY (id);

ALTER TABLE credential
  ADD COLUMN external_id     bytea,
  ADD COLUMN counter         bigint CHECK (counter >= 0),
  ADD COLUMN backup_eligible boolean NOT NULL DEFAULT false,
  ADD COLUMN label           text    NOT NULL DEFAULT '',
  ADD COLUMN last_used_at    timestamptz;

ALTER TABLE credential DROP CONSTRAINT credential_kind_check;
ALTER TABLE credential ADD CONSTRAINT credential_kind_check
  CHECK (kind IN ('password', 'webauthn', 'totp'));

-- One password and one TOTP credential per user; a WebAuthn credential id is bound to exactly one
-- account per tenant.
CREATE UNIQUE INDEX credential_password_key ON credential (tenant_id, user_id)
  WHERE kind = 'password';
CREATE UNIQUE INDEX credential_totp_key ON credential (tenant_id, user_id)
  WHERE kind = 'totp';
CREATE UNIQUE INDEX credential_external_id_key ON credential (tenant_id, external_id)
  WHERE external_id IS NOT NULL;
CREATE INDEX credential_user_idx ON credential (tenant_id, user_id);

-- Recovery codes (SHA-256 digests of the normalised codes; never the codes).
CREATE TABLE recovery_code (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL,
  code_hash  bytea       NOT NULL CHECK (octet_length(code_hash) = 32),
  created_at timestamptz NOT NULL,
  used_at    timestamptz,
  PRIMARY KEY (tenant_id, user_id, code_hash),
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------------------------
-- flows: settings and consent flows.

ALTER TABLE flow DROP CONSTRAINT flow_kind_check;
ALTER TABLE flow ADD CONSTRAINT flow_kind_check CHECK (kind IN
  ('login', 'registration', 'verification', 'recovery', 'setup', 'settings', 'consent'));

-- ---------------------------------------------------------------------------------------------
-- token families: revocation by consent withdrawal, session sign-out and token revocation.

ALTER TABLE token_family DROP CONSTRAINT token_family_revoked_reason_check;
ALTER TABLE token_family ADD CONSTRAINT token_family_revoked_reason_check
  CHECK (revoked_reason IN ('code_reuse', 'refresh_reuse', 'user_recovery', 'client_deleted',
    'user_deleted', 'admin', 'consent_revoked', 'session_revoked', 'token_revoked'));

-- ---------------------------------------------------------------------------------------------
-- consent

CREATE TABLE consent_grant (
  id         uuid        NOT NULL PRIMARY KEY,
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  user_id    uuid        NOT NULL,
  client_id  text        NOT NULL,
  -- Sorted, de-duplicated JSON array of scope names.
  scopes     jsonb       NOT NULL CHECK (jsonb_typeof(scopes) = 'array'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  revoked_at timestamptz,
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX consent_grant_user_client_key ON consent_grant (tenant_id, user_id, client_id);

-- ---------------------------------------------------------------------------------------------
-- opaque access tokens (no user/client FK, like token families: revocation, not deletion)

CREATE TABLE access_token (
  token_hash bytea       NOT NULL PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  family_id  uuid        REFERENCES token_family(id) ON DELETE CASCADE,
  client_id  text        NOT NULL,
  user_id    uuid,
  scope      text        NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX access_token_family_idx ON access_token (family_id);
CREATE INDEX access_token_expires_idx ON access_token (expires_at);

-- ---------------------------------------------------------------------------------------------
-- audit log (append-only; retention via AuditRepo::purge_before)

CREATE TABLE audit_event (
  id         uuid        NOT NULL PRIMARY KEY,
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  at         timestamptz NOT NULL,
  actor_kind text        NOT NULL CHECK (actor_kind IN ('user', 'client', 'admin', 'system')),
  actor_id   text,
  action     text        NOT NULL,
  target     text,
  outcome    text        NOT NULL CHECK (outcome IN ('success', 'failure')),
  -- text (not inet) for parity with SQLite; written from a parsed IpAddr.
  ip         text,
  user_agent text,
  trace_id   text,
  details    jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_event_tenant_id_idx ON audit_event (tenant_id, id DESC);
CREATE INDEX audit_event_tenant_action_idx ON audit_event (tenant_id, action, id);
CREATE INDEX audit_event_at_idx ON audit_event (at);

-- ---------------------------------------------------------------------------------------------
-- per-tenant mail settings

CREATE TABLE email_template (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  kind       text        NOT NULL CHECK (kind IN ('verification', 'recovery', 'invitation',
               'password_changed', 'recovery_code_used')),
  subject    text        NOT NULL,
  body_html  text        NOT NULL,
  body_text  text        NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, kind)
);

CREATE TABLE smtp_settings (
  tenant_id    uuid        NOT NULL PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
  host         text        NOT NULL,
  port         integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
  username     text,
  -- KEK-sealed password; never the password.
  password_enc bytea,
  from_address text        NOT NULL,
  tls          text        NOT NULL CHECK (tls IN ('starttls', 'implicit', 'none')),
  updated_at   timestamptz NOT NULL
);

-- ---------------------------------------------------------------------------------------------
-- installation-wide background job leases

CREATE TABLE job_lease (
  name         text        NOT NULL PRIMARY KEY,
  owner        text        NOT NULL,
  leased_until timestamptz NOT NULL
);

-- ---------------------------------------------------------------------------------------------
-- client and browser session additions (constant defaults: metadata-only, no table rewrite)

ALTER TABLE client
  ADD COLUMN token_format text NOT NULL DEFAULT 'jwt'
    CHECK (token_format IN ('jwt', 'opaque')),
  ADD COLUMN consent_mode text NOT NULL DEFAULT 'required'
    CHECK (consent_mode IN ('required', 'skip_first_party')),
  ADD COLUMN id_token_signed_response_alg text
    CHECK (id_token_signed_response_alg IN ('RS256', 'ES256', 'Ed25519')),
  ADD COLUMN can_introspect boolean NOT NULL DEFAULT false;

ALTER TABLE browser_session
  ADD COLUMN ip         text,
  ADD COLUMN user_agent text;
