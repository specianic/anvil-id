-- A populated Release 0.1 database (schema version 2: 0001_init + 0002_release_0_1).
-- Loaded by tests/upgrade.rs before migrating to the latest schema. Hand-written in the 0.1 shape;
-- the signing key and the outbox row are sealed at test time with a fixed test KEK and inserted
-- by the test itself. Ids are fixed so the test can address the rows through the storage traits.
-- Timestamps: created 2025-01-01 (1735689600000 ms), "far future" = 2100-01-01 (4102444800000).

INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000000001', 'system', 'System', 1735689600000, NULL,
   '{"registration":"disabled","require_verified_email":false}'),
  (x'00000000000070008000000000000002', 'default', 'Default', 1735689600000, NULL,
   '{"registration":"invite_only","require_verified_email":true}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at) VALUES
  (x'00000000000070008000000000000010', x'00000000000070008000000000000002',
   'ada@example.test', 1, 'ada', '{"name":"Ada"}', 'active', 1735689600000, 1735689600000,
   1735689600000);

INSERT INTO credential (tenant_id, user_id, kind, secret, created_at, updated_at) VALUES
  (x'00000000000070008000000000000002', x'00000000000070008000000000000010', 'password',
   '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$9vYp7ZrIx8DT2eTnNdD0yzKd0Zl0b3gxYk5y0RqFqm8',
   1735689600000, 1735689601000);

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at) VALUES
  (x'00000000000070008000000000000020', x'00000000000070008000000000000002', 'web-app',
   'Web app', 'confidential', 'web', 'client_secret_basic',
   x'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', NULL,
   '["https://rp.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","email","offline_access"]', 0, 1735689600000, 1735689600000),
  (x'00000000000070008000000000000021', x'00000000000070008000000000000002', 'spa',
   'Single-page app', 'public', 'web', 'none', NULL, NULL,
   '["https://spa.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid"]', 1, 1735689600000, 1735689600000);

INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at, revoked_at) VALUES
  (x'00000000000070008000000000000030', x'00000000000070008000000000000002',
   x'00000000000070008000000000000010',
   x'3131313131313131313131313131313131313131313131313131313131313131', 1735689600000,
   'urn:anvilid:acr:pwd', '["pwd"]', 1735689600000, 1735689600000, 4102444800000,
   4102444800000, NULL);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason) VALUES
  (x'00000000000070008000000000000040', x'00000000000070008000000000000002', 'web-app',
   x'00000000000070008000000000000010', 'openid email offline_access', 1735689600000,
   'urn:anvilid:acr:pwd', '["pwd"]', x'00000000000070008000000000000030', NULL, 1735689600000,
   4102444800000, NULL, NULL);

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at) VALUES
  (x'0101010101010101010101010101010101010101010101010101010101010101',
   x'00000000000070008000000000000002', 'web-app', x'00000000000070008000000000000010',
   x'00000000000070008000000000000030', 'https://rp.example.test/cb',
   'openid email offline_access', 'n-0S6_WzA2Mj', NULL, 1735689600000, 'urn:anvilid:acr:pwd',
   '["pwd"]', x'00000000000070008000000000000040', 4102444800000, NULL, 1735689600000);

INSERT INTO refresh_token (token_hash, tenant_id, family_id, parent_hash, scope, created_at,
                           expires_at, consumed_at) VALUES
  (x'0202020202020202020202020202020202020202020202020202020202020202',
   x'00000000000070008000000000000002', x'00000000000070008000000000000040', NULL,
   'openid email offline_access', 1735689600000, 4102444800000, NULL);
