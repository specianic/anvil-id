-- Release 1.0 "Credible for business": organizations (members, invitations, verified domains),
-- org-owned roles and in-org role assignments, organization and SAML connections, org-bound
-- authorization codes and token families, the SAML assertion replay guard, the organization
-- invitation email template and the per-client organization policy.
--
-- In place, in this migration's transaction: no DROP TABLE / DROP COLUMN, no RENAME, no column
-- type change, no row rewritten or deleted. CHECK swaps use DROP CONSTRAINT / ADD CONSTRAINT (the
-- auto-named inline `{table}_{column}_check`, as 0003/0004 did); role_assignment's primary key is
-- replaced by two partial unique indexes. New columns are nullable or have constant defaults
-- (metadata-only, no table rewrite). The logical schema matches the SQLite 0008 + 0009 migrations
-- (same semantics, native Postgres types: uuid, timestamptz, jsonb, bytea).

-- ---------------------------------------------------------------------------------------------
-- Organizations (ORG-02). Slugs follow the tenant slug rule and are unique per tenant.

CREATE TABLE organization (
  id           uuid        NOT NULL PRIMARY KEY,
  tenant_id    uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  slug         text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  display_name text        NOT NULL,
  -- NULL = no org requirement (strictest of tenant, org and client wins).
  mfa_policy   text        CHECK (mfa_policy IN ('off', 'optional', 'required')),
  settings     jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(settings) = 'object'),
  -- Free-form integrator data, never interpreted by the server.
  metadata     jsonb       NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL,
  CONSTRAINT organization_tenant_slug_key UNIQUE (tenant_id, slug),
  -- Composite FK target (tenant isolation by schema).
  CONSTRAINT organization_tenant_id_key UNIQUE (tenant_id, id)
);

-- Both references are composite, so a membership can never pair an org and a user of different
-- tenants. Deleting the org or the user removes the membership (and, through the assignment FK
-- below, its in-org role assignments).
CREATE TABLE org_membership (
  tenant_id  uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  org_id     uuid        NOT NULL,
  user_id    uuid        NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, org_id, user_id),
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES "user" (tenant_id, id) ON DELETE CASCADE
);
-- memberships_of_user.
CREATE INDEX org_membership_user_idx ON org_membership (tenant_id, user_id);

-- Invitations (ORG-02). The token is stored only as its SHA-256; no user is created when
-- inviting. Accepting is one conditional UPDATE (open = not accepted, not revoked, not expired).
CREATE TABLE org_invitation (
  id               uuid        NOT NULL PRIMARY KEY,
  tenant_id        uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  org_id           uuid        NOT NULL,
  -- Normalised (lowercase) by the caller.
  email            text        NOT NULL CHECK (length(email) BETWEEN 1 AND 254),
  -- Roles assigned in the org on acceptance: a JSON array of role id strings, in the order given.
  role_ids         jsonb       NOT NULL CHECK (jsonb_typeof(role_ids) = 'array'),
  token_hash       bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
  invited_by_kind  text        NOT NULL CHECK (invited_by_kind IN ('user', 'client', 'admin',
                                                                   'system')),
  invited_by_id    text,
  created_at       timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  accepted_at      timestamptz,
  -- No foreign key: the invitation keeps its history if the user is deleted later.
  accepted_user_id uuid,
  revoked_at       timestamptz,
  CONSTRAINT org_invitation_token_hash_key UNIQUE (token_hash),
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  CHECK ((accepted_at IS NULL) = (accepted_user_id IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);
-- list_invitations, newest first.
CREATE INDEX org_invitation_org_idx ON org_invitation (tenant_id, org_id, created_at);

-- ---------------------------------------------------------------------------------------------
-- Organization and SAML connections (ORG-03). `org_id` set = the org's enterprise connection,
-- never shown as a tenant sign-in button. Slugs stay unique per tenant.

ALTER TABLE connection DROP CONSTRAINT connection_kind_check;
ALTER TABLE connection ADD CONSTRAINT connection_kind_check CHECK (kind IN
  ('google', 'apple', 'microsoft', 'github', 'oidc', 'oauth2', 'saml'));

ALTER TABLE connection
  ADD COLUMN org_id uuid,
  ADD CONSTRAINT connection_org_id_fkey
    FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  -- Composite FK target for a domain's routing connection (same org by schema).
  ADD CONSTRAINT connection_tenant_org_id_key UNIQUE (tenant_id, org_id, id);
CREATE INDEX connection_org_idx ON connection (tenant_id, org_id) WHERE org_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Verified email domains (ORG-04). Several orgs of a tenant may hold pending claims on a domain;
-- the partial unique index lets at most one hold it verified, which also decides concurrent
-- verifications.

CREATE TABLE org_domain (
  id                   uuid        NOT NULL PRIMARY KEY,
  tenant_id            uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
  org_id               uuid        NOT NULL,
  -- Lowercase A-label.
  domain               text        NOT NULL CHECK (length(domain) BETWEEN 1 AND 253
                                                   AND domain = lower(domain)),
  -- The public DNS challenge value (not a secret).
  token                text        NOT NULL CHECK (length(token) >= 1),
  status               text        NOT NULL CHECK (status IN ('pending', 'verified')),
  -- Routing target: a connection of the same org (composite FK; MATCH SIMPLE, so NULL = none).
  -- Deleting the connection clears it first (ConnectionRepo::delete).
  connection_id        uuid,
  routing              boolean     NOT NULL,
  allow_local_password boolean     NOT NULL DEFAULT true,
  verified_at          timestamptz,
  last_checked_at      timestamptz,
  -- Start of the current run of failed re-checks.
  failing_since        timestamptz,
  created_at           timestamptz NOT NULL,
  CONSTRAINT org_domain_org_domain_key UNIQUE (tenant_id, org_id, domain),
  FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT org_domain_connection_fkey FOREIGN KEY (tenant_id, org_id, connection_id)
    REFERENCES connection (tenant_id, org_id, id),
  CHECK ((status = 'verified') = (verified_at IS NOT NULL)),
  CHECK (failing_since IS NULL OR verified_at IS NOT NULL)
);
CREATE UNIQUE INDEX org_domain_verified_key ON org_domain (tenant_id, domain)
  WHERE verified_at IS NOT NULL;
-- The installation-wide re-check scan.
CREATE INDEX org_domain_recheck_idx ON org_domain (last_checked_at)
  WHERE verified_at IS NOT NULL;
CREATE INDEX org_domain_connection_idx ON org_domain (tenant_id, connection_id)
  WHERE connection_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Org-owned roles and in-org assignments (ORG-02, decision Q5 hybrid). `role.org_id` existed
-- since 0.4 (always NULL); it now references the org, and org-owned role names are unique per
-- org (the tenant-level index from 0006 is unchanged).

ALTER TABLE role
  ADD CONSTRAINT role_org_id_fkey
    FOREIGN KEY (tenant_id, org_id) REFERENCES organization (tenant_id, id) ON DELETE CASCADE;
CREATE UNIQUE INDEX role_tenant_org_name_key ON role (tenant_id, org_id, name)
  WHERE org_id IS NOT NULL;

-- An assignment with `org_id` holds only in that org and references the membership, so ending
-- the membership removes it (MATCH SIMPLE: tenant-wide assignments, org_id NULL, are unchecked).
ALTER TABLE role_assignment ADD COLUMN org_id uuid;
ALTER TABLE role_assignment DROP CONSTRAINT role_assignment_pkey;
CREATE UNIQUE INDEX role_assignment_tenant_key ON role_assignment (tenant_id, role_id, user_id)
  WHERE org_id IS NULL;
CREATE UNIQUE INDEX role_assignment_org_key
  ON role_assignment (tenant_id, role_id, user_id, org_id)
  WHERE org_id IS NOT NULL;
ALTER TABLE role_assignment
  ADD CONSTRAINT role_assignment_membership_fkey
    FOREIGN KEY (tenant_id, org_id, user_id)
    REFERENCES org_membership (tenant_id, org_id, user_id) ON DELETE CASCADE;
CREATE INDEX role_assignment_org_idx ON role_assignment (tenant_id, org_id, user_id)
  WHERE org_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- The active org of a grant. No foreign key: the intents that end a membership or delete an org
-- revoke the org-bound families (reason 'admin') in the same transaction.

ALTER TABLE authorization_code ADD COLUMN org_id uuid;
ALTER TABLE token_family ADD COLUMN org_id uuid;
CREATE INDEX token_family_org_idx ON token_family (tenant_id, org_id, user_id)
  WHERE org_id IS NOT NULL;

-- ---------------------------------------------------------------------------------------------
-- Widened kinds: SAML assertion ids in the replay guard, the organization invitation template.

ALTER TABLE replay_guard DROP CONSTRAINT replay_guard_kind_check;
ALTER TABLE replay_guard ADD CONSTRAINT replay_guard_kind_check CHECK (kind IN
  ('client_assertion_jti', 'saml_assertion_id'));

ALTER TABLE email_template DROP CONSTRAINT email_template_kind_check;
ALTER TABLE email_template ADD CONSTRAINT email_template_kind_check CHECK (kind IN
  ('verification', 'recovery', 'invitation', 'password_changed', 'recovery_code_used',
   'login_code', 'email_change', 'email_changed', 'org_invitation'));

-- ---------------------------------------------------------------------------------------------
-- Per-client organization policy for the `organization` parameter and the org claims.

ALTER TABLE client
  ADD COLUMN organization text NOT NULL DEFAULT 'off'
    CHECK (organization IN ('off', 'optional', 'required'));
