-- A populated 0.4 database (schema version 6) for the 0.4 -> 1.0 upgrade test. It holds a row in
-- every table migration 0007 changes in place: connections of several kinds with identity links,
-- roles with assignments (including the system tenant's administrator), replay guards, email
-- template overrides, a client, a token family and an authorization code. Test data only.

INSERT INTO tenant (id, slug, display_name, created_at, settings)
     VALUES ('00000000-0000-7000-8000-000000040001', 'system', 'System', '2026-09-01T00:00:00Z',
             '{"registration":"disabled","require_verified_email":false}'),
            ('00000000-0000-7000-8000-000000040002', 'acme', 'Acme', '2026-09-01T00:00:00Z',
             '{"registration":"open","require_verified_email":false}');

INSERT INTO "user" (id, tenant_id, email, email_verified, username, status, created_at,
                    updated_at)
     VALUES ('00000000-0000-7000-8000-000000040010', '00000000-0000-7000-8000-000000040001',
             'admin@example.test', true, NULL, 'active', '2026-09-01T00:00:00Z',
             '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040011', '00000000-0000-7000-8000-000000040002',
             'ada@example.test', true, 'ada', 'active', '2026-09-01T00:00:00Z',
             '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040012', '00000000-0000-7000-8000-000000040002',
             'bob@example.test', true, 'bob', 'active', '2026-09-01T00:00:00Z',
             '2026-09-01T00:00:00Z');

-- Roles: the system administrator (what 0006 backfills / setup creates) and two tenant roles.
INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000040020', '00000000-0000-7000-8000-000000040001', NULL,
             'administrator', 'Full administrative access', ARRAY['admin:write'],
             '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040021', '00000000-0000-7000-8000-000000040002', NULL,
             'editor', 'Edits documents', ARRAY['docs:read', 'docs:write'],
             '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040022', '00000000-0000-7000-8000-000000040002', NULL,
             'viewer', 'Reads documents', ARRAY['docs:read'],
             '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z');

INSERT INTO role_assignment (tenant_id, role_id, user_id, created_at)
     VALUES ('00000000-0000-7000-8000-000000040001', '00000000-0000-7000-8000-000000040020',
             '00000000-0000-7000-8000-000000040010', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040002', '00000000-0000-7000-8000-000000040021',
             '00000000-0000-7000-8000-000000040011', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040002', '00000000-0000-7000-8000-000000040022',
             '00000000-0000-7000-8000-000000040011', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040002', '00000000-0000-7000-8000-000000040022',
             '00000000-0000-7000-8000-000000040012', '2026-09-01T00:00:00Z');

-- Connections of three kinds in two tenants.
INSERT INTO connection (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                        trust_email_verified, created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000040030', '00000000-0000-7000-8000-000000040002',
             'google', 'Google', 'google', true,
             '{"type":"social","provider":"google","client_id":"g-client"}',
             decode('0102030405', 'hex'), true, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040031', '00000000-0000-7000-8000-000000040002',
             'corp', 'Corp IdP', 'oidc', true,
             '{"type":"oidc","issuer":"https://idp.example.test","client_id":"o-client"}',
             NULL, false, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040032', '00000000-0000-7000-8000-000000040001',
             'github', 'GitHub', 'github', false,
             '{"type":"social","provider":"github","client_id":"gh-client"}',
             NULL, false, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z');

INSERT INTO identity_link (id, tenant_id, user_id, connection_id, subject, email_at_link,
                           metadata, created_at, last_used_at)
     VALUES ('00000000-0000-7000-8000-000000040040', '00000000-0000-7000-8000-000000040002',
             '00000000-0000-7000-8000-000000040011', '00000000-0000-7000-8000-000000040030',
             'google-ada', 'ada@example.test', '{"hd":"example.test"}',
             '2026-09-01T00:00:00Z', '2026-09-02T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040041', '00000000-0000-7000-8000-000000040002',
             '00000000-0000-7000-8000-000000040011', '00000000-0000-7000-8000-000000040031',
             'corp-ada', NULL, '{}', '2026-09-01T00:00:00Z', NULL),
            ('00000000-0000-7000-8000-000000040042', '00000000-0000-7000-8000-000000040002',
             '00000000-0000-7000-8000-000000040012', '00000000-0000-7000-8000-000000040031',
             'corp-bob', 'bob@example.test', '{}', '2026-09-01T00:00:00Z', NULL),
            ('00000000-0000-7000-8000-000000040043', '00000000-0000-7000-8000-000000040001',
             '00000000-0000-7000-8000-000000040010', '00000000-0000-7000-8000-000000040032',
             'gh-admin', NULL, '{}', '2026-09-01T00:00:00Z', NULL);

INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at)
     VALUES ('00000000-0000-7000-8000-000000040002', 'client_assertion_jti',
             decode(repeat('41', 32), 'hex'), '2100-01-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040002', 'client_assertion_jti',
             decode(repeat('42', 32), 'hex'), '2100-01-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040001', 'client_assertion_jti',
             decode(repeat('43', 32), 'hex'), '2100-01-01T00:00:00Z');

INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at)
     VALUES ('00000000-0000-7000-8000-000000040002', 'password_changed', 'Changed',
             '<p>changed</p>', 'changed', '2026-09-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000040002', 'login_code', 'Your code',
             '<p>{{ code }}</p>', '{{ code }}', '2026-09-01T00:00:00Z');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    redirect_uris, grant_types, scopes, require_pkce, created_at, updated_at,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy)
     VALUES ('00000000-0000-7000-8000-000000040050', '00000000-0000-7000-8000-000000040002',
             'rp', 'RP', 'public', 'web', 'none', ARRAY['https://rp.example.test/cb'],
             ARRAY['authorization_code', 'refresh_token'], ARRAY['openid', 'profile'], true,
             '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', 'jwt', 'required', NULL, false,
             '[]', NULL, false, '[]', NULL);

INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at)
     VALUES ('00000000-0000-7000-8000-000000040060', '00000000-0000-7000-8000-000000040002',
             '00000000-0000-7000-8000-000000040011', decode(repeat('44', 32), 'hex'),
             '2026-09-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'], '2026-09-01T00:00:00Z',
             '2026-09-01T00:00:00Z', '2100-01-01T00:00:00Z', '2100-01-01T00:00:00Z');

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, created_at, absolute_expires_at)
     VALUES ('00000000-0000-7000-8000-000000040070', '00000000-0000-7000-8000-000000040002',
             'rp', '00000000-0000-7000-8000-000000040011', 'openid', '2026-09-01T00:00:00Z',
             'urn:anvilid:acr:pwd', ARRAY['pwd'], '00000000-0000-7000-8000-000000040060',
             '2026-09-01T00:00:00Z', '2100-01-01T00:00:00Z');

INSERT INTO authorization_code (code_hash, tenant_id, client_id, redirect_uri, scope, nonce,
                                code_challenge, token_family_id, user_id, session_id, auth_time,
                                acr, amr, expires_at, created_at)
     VALUES (decode(repeat('45', 32), 'hex'), '00000000-0000-7000-8000-000000040002', 'rp',
             'https://rp.example.test/cb', 'openid', 'n-0.4', 'challenge-0.4',
             '00000000-0000-7000-8000-000000040070', '00000000-0000-7000-8000-000000040011',
             '00000000-0000-7000-8000-000000040060', '2026-09-01T00:00:00Z',
             'urn:anvilid:acr:pwd', ARRAY['pwd'], '2100-01-01T00:00:00Z',
             '2026-09-01T00:00:00Z');
