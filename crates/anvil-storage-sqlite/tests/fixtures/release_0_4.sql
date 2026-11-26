-- A populated Release 0.4 database (schema version 7: 0001 through 0007_release_0_4).
-- Loaded by tests/upgrade.rs before migrating to the 1.0 schema (0008_release_1_0 and the
-- no-transaction rebuild 0009_release_1_0_rebuild). Hand-written in the 0.4 shape, aimed at the
-- tables 0009 rebuilds and the rows that reference them:
--
--   - a system tenant with its administrator role held by two users, and a default tenant with
--     tenant roles and assignments (identity_link and role_assignment must survive the rebuild of
--     connection and role, which they reference ON DELETE CASCADE);
--   - connections of four kinds (google, github, oidc, oauth2) in both tenants, with identity
--     links on each;
--   - replay guards and email template overrides (CHECK widened by 0009);
--   - a client, a token family and an authorization code (org_id added by 0008).
--
-- Ids are fixed so the test can address the rows through the storage traits. Timestamps: created
-- 2025-06-01 (1748736000000 ms); far future 2100-01-01 (4102444800000 ms).

INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000040001', 'system', 'System', 1748736000000, NULL,
   '{"registration":"disabled","require_verified_email":false}'),
  (x'00000000000070008000000000040002', 'default', 'Default', 1748736000000, NULL,
   '{"registration":"open","require_verified_email":true}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at, attributes) VALUES
  (x'00000000000070008000000000040010', x'00000000000070008000000000040001',
   'root@example.test', 1, 'root', '{}', 'active', 1748736000000, 1748736000000, NULL, '{}'),
  (x'00000000000070008000000000040011', x'00000000000070008000000000040001',
   'ops@example.test', 1, NULL, '{}', 'active', 1748736000000, 1748736000000, NULL, '{}'),
  (x'00000000000070008000000000040012', x'00000000000070008000000000040002',
   'alice@example.test', 1, NULL, '{"name":"Alice"}', 'active', 1748736000000, 1748736000000,
   NULL, '{"department":"eng"}'),
  (x'00000000000070008000000000040013', x'00000000000070008000000000040002',
   'bob@example.test', 0, 'bob', '{}', 'blocked', 1748736000000, 1748736000000, NULL, '{}');

INSERT INTO credential (id, tenant_id, user_id, kind, secret, created_at, updated_at) VALUES
  (x'00000000000070008000000000040014', x'00000000000070008000000000040002', x'00000000000070008000000000040012', 'password',
   '$argon2id$v=19$release04', 1748736000000, 1748736000000);

-- Roles: the system tenant's administrator role (as SetupRepo::install creates it) and two
-- tenant roles of the default tenant. 0.4 roles never have an org.
INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at,
                  updated_at) VALUES
  (x'00000000000070008000000000040020', x'00000000000070008000000000040001', NULL,
   'administrator', 'Full administrative access', '["admin:write"]', 1748736000000,
   1748736000000),
  (x'00000000000070008000000000040021', x'00000000000070008000000000040002', NULL,
   'editor', 'Edits documents', '["docs:read","docs:write"]', 1748736000000, 1748736000000),
  (x'00000000000070008000000000040022', x'00000000000070008000000000040002', NULL,
   'viewer', 'Reads documents', '["docs:read"]', 1748736000000, 1748736000000);

INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at) VALUES
  (x'00000000000070008000000000040001', x'00000000000070008000000000040020',
   x'00000000000070008000000000040010', 1748736000000),
  (x'00000000000070008000000000040001', x'00000000000070008000000000040020',
   x'00000000000070008000000000040011', 1748736000000),
  (x'00000000000070008000000000040002', x'00000000000070008000000000040021',
   x'00000000000070008000000000040012', 1748736000000),
  (x'00000000000070008000000000040002', x'00000000000070008000000000040022',
   x'00000000000070008000000000040012', 1748736000000),
  (x'00000000000070008000000000040002', x'00000000000070008000000000040022',
   x'00000000000070008000000000040013', 1748736000000);

-- Connections of four kinds (secrets are opaque sealed bytes; storage never opens them).
INSERT INTO connection (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                        trust_email_verified, created_at, updated_at) VALUES
  (x'00000000000070008000000000040030', x'00000000000070008000000000040002', 'google',
   'Google', 'google', 1,
   '{"type":"social","provider":"google","client_id":"g-client","scopes":["openid","email"]}',
   x'0102030405', 1, 1748736000000, 1748736000000),
  (x'00000000000070008000000000040031', x'00000000000070008000000000040002', 'github',
   'GitHub', 'github', 0,
   '{"type":"social","provider":"github","client_id":"gh-client"}',
   x'0607080910', 1, 1748736000000, 1748736000000),
  (x'00000000000070008000000000040032', x'00000000000070008000000000040002', 'corp-oidc',
   'Corp OIDC', 'oidc', 1,
   '{"type":"oidc","issuer":"https://idp.example.test","client_id":"corp","scopes":["openid"],"use_pkce":true,"fetch_userinfo":false}',
   NULL, 0, 1748736000000, 1748736000000),
  (x'00000000000070008000000000040033', x'00000000000070008000000000040001', 'legacy-oauth',
   'Legacy OAuth', 'oauth2', 1,
   '{"type":"oauth2","authorization_endpoint":"https://oauth.example.test/authorize","token_endpoint":"https://oauth.example.test/token","userinfo_endpoint":"https://oauth.example.test/me","client_id":"legacy","use_pkce":true,"mapping":{"subject":"id","email":"email"}}',
   x'aabbcc', 0, 1748736000000, 1748736000000);

INSERT INTO identity_link (id, tenant_id, user_id, connection_id, subject, email_at_link,
                           metadata, created_at, last_used_at) VALUES
  (x'00000000000070008000000000040040', x'00000000000070008000000000040002',
   x'00000000000070008000000000040012', x'00000000000070008000000000040030', 'google-alice',
   'alice@example.test', '{}', 1748736000000, 1748736000000),
  (x'00000000000070008000000000040041', x'00000000000070008000000000040002',
   x'00000000000070008000000000040012', x'00000000000070008000000000040031', 'github-alice',
   NULL, '{"login":"alice"}', 1748736000000, NULL),
  (x'00000000000070008000000000040042', x'00000000000070008000000000040002',
   x'00000000000070008000000000040013', x'00000000000070008000000000040032', 'corp-bob',
   'bob@example.test', '{}', 1748736000000, NULL),
  (x'00000000000070008000000000040043', x'00000000000070008000000000040001',
   x'00000000000070008000000000040011', x'00000000000070008000000000040033', 'legacy-ops',
   'ops@example.test', '{}', 1748736000000, NULL);

INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at) VALUES
  (x'00000000000070008000000000040002', 'client_assertion_jti',
   x'4141414141414141414141414141414141414141414141414141414141414141', 4102444800000),
  (x'00000000000070008000000000040002', 'client_assertion_jti',
   x'4242424242424242424242424242424242424242424242424242424242424242', 1748736000000),
  (x'00000000000070008000000000040001', 'client_assertion_jti',
   x'4343434343434343434343434343434343434343434343434343434343434343', 4102444800000);

INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at) VALUES
  (x'00000000000070008000000000040002', 'verification', 'Verify {{email}}',
   '<p>{{link}}</p>', '{{link}}', 1748736000000),
  (x'00000000000070008000000000040002', 'login_code', 'Your code', '<p>{{code}}</p>',
   '{{code}}', 1748736000000),
  (x'00000000000070008000000000040001', 'recovery', 'Recover', '<p>{{link}}</p>', '{{link}}',
   1748736000000);

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at) VALUES
  (x'00000000000070008000000000040050', x'00000000000070008000000000040002', 'v04-web',
   'v0.4 web app', 'confidential', 'web', 'client_secret_basic',
   x'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', NULL,
   '["https://rp.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","offline_access"]', 1, 1748736000000, 1748736000000);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason) VALUES
  (x'00000000000070008000000000040060', x'00000000000070008000000000040002', 'v04-web',
   x'00000000000070008000000000040012', 'openid offline_access', 1748736000000,
   'urn:anvilid:acr:pwd', '["pwd"]', x'00000000000070008000000000040070', NULL, 1748736000000,
   4102444800000, NULL, NULL);

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at) VALUES
  (x'4444444444444444444444444444444444444444444444444444444444444444',
   x'00000000000070008000000000040002', 'v04-web', x'00000000000070008000000000040012',
   x'00000000000070008000000000040070', 'https://rp.example.test/cb', 'openid offline_access',
   NULL, 'challenge', 1748736000000, 'urn:anvilid:acr:pwd', '["pwd"]',
   x'00000000000070008000000000040060', 4102444800000, NULL, 1748736000000);
