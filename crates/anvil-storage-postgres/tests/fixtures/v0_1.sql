-- A populated Release 0.1 database (schema version 2: 0001_init + 0002_release_0_1).
-- Loaded by tests/upgrade.rs before migrating to the latest schema. Hand-written in the 0.1 shape;
-- the signing key and the outbox row are sealed at test time with a fixed test KEK and inserted
-- by the test itself. Ids are fixed so the test can address the rows through the storage traits.

INSERT INTO tenant (id, slug, display_name, settings, created_at, host) VALUES
  ('00000000-0000-7000-8000-000000000001', 'system', 'System',
   '{"registration":"disabled","require_verified_email":false}', '2025-01-01T00:00:00Z', NULL),
  ('00000000-0000-7000-8000-000000000002', 'default', 'Default',
   '{"registration":"invite_only","require_verified_email":true}', '2025-01-01T00:00:00Z', NULL);

INSERT INTO "user" (id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at) VALUES
  ('00000000-0000-7000-8000-000000000010', '00000000-0000-7000-8000-000000000002',
   'ada@example.test', true, 'ada', '{"name":"Ada"}', 'active', '2025-01-01T00:00:00Z',
   '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');

INSERT INTO credential (tenant_id, user_id, kind, data, created_at, updated_at) VALUES
  ('00000000-0000-7000-8000-000000000002', '00000000-0000-7000-8000-000000000010', 'password',
   '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$9vYp7ZrIx8DT2eTnNdD0yzKd0Zl0b3gxYk5y0RqFqm8',
   '2025-01-01T00:00:00Z', '2025-01-01T00:00:01Z');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at) VALUES
  ('00000000-0000-7000-8000-000000000020', '00000000-0000-7000-8000-000000000002', 'web-app',
   'Web app', 'confidential', 'web', 'client_secret_basic', decode(repeat('aa', 32), 'hex'), NULL,
   ARRAY['https://rp.example.test/cb'], ARRAY['authorization_code', 'refresh_token'],
   ARRAY['openid', 'email', 'offline_access'], false, '2025-01-01T00:00:00Z',
   '2025-01-01T00:00:00Z'),
  ('00000000-0000-7000-8000-000000000021', '00000000-0000-7000-8000-000000000002', 'spa',
   'Single-page app', 'public', 'web', 'none', NULL, NULL,
   ARRAY['https://spa.example.test/cb'], ARRAY['authorization_code', 'refresh_token'],
   ARRAY['openid'], true, '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');

INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at, revoked_at) VALUES
  ('00000000-0000-7000-8000-000000000030', '00000000-0000-7000-8000-000000000002',
   '00000000-0000-7000-8000-000000000010', decode(repeat('31', 32), 'hex'),
   '2025-01-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'], '2025-01-01T00:00:00Z',
   '2025-01-01T00:00:00Z', '2100-01-01T00:00:00Z', '2100-01-01T00:00:00Z', NULL);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason) VALUES
  ('00000000-0000-7000-8000-000000000040', '00000000-0000-7000-8000-000000000002', 'web-app',
   '00000000-0000-7000-8000-000000000010', 'openid email offline_access',
   '2025-01-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'],
   '00000000-0000-7000-8000-000000000030', NULL, '2025-01-01T00:00:00Z',
   '2100-01-01T00:00:00Z', NULL, NULL);

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at) VALUES
  (decode(repeat('01', 32), 'hex'), '00000000-0000-7000-8000-000000000002', 'web-app',
   '00000000-0000-7000-8000-000000000010', '00000000-0000-7000-8000-000000000030',
   'https://rp.example.test/cb', 'openid email offline_access', 'n-0S6_WzA2Mj', NULL,
   '2025-01-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'],
   '00000000-0000-7000-8000-000000000040', '2100-01-01T00:00:00Z', NULL,
   '2025-01-01T00:00:00Z');

INSERT INTO refresh_token (token_hash, tenant_id, family_id, parent_hash, scope, created_at,
                           expires_at, consumed_at) VALUES
  (decode(repeat('02', 32), 'hex'), '00000000-0000-7000-8000-000000000002',
   '00000000-0000-7000-8000-000000000040', NULL, 'openid email offline_access',
   '2025-01-01T00:00:00Z', '2100-01-01T00:00:00Z', NULL);
