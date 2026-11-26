-- A populated 0.3 database (schema version 5) for the 0.3 -> 0.4 upgrade test: the system tenant
-- with two administrators (0.3 had no roles: every system-tenant user was an administrator), and
-- a regular tenant with one user, a client and a consent grant. Test data only.

INSERT INTO tenant (id, slug, display_name, created_at, settings)
     VALUES ('00000000-0000-7000-8000-000000030001', 'system', 'System', '2026-06-01T00:00:00Z',
             '{"registration":"disabled","require_verified_email":false}'),
            ('00000000-0000-7000-8000-000000030002', 'acme', 'Acme', '2026-06-01T00:00:00Z',
             '{"registration":"open","require_verified_email":false}');

INSERT INTO "user" (id, tenant_id, email, email_verified, username, status, created_at,
                    updated_at)
     VALUES ('00000000-0000-7000-8000-000000030010', '00000000-0000-7000-8000-000000030001',
             'admin-one@example.test', true, NULL, 'active', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000030011', '00000000-0000-7000-8000-000000030001',
             'admin-two@example.test', true, NULL, 'active', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000030012', '00000000-0000-7000-8000-000000030002',
             'ada@example.test', true, 'ada', 'active', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    redirect_uris, grant_types, scopes, require_pkce, created_at, updated_at,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy)
     VALUES ('00000000-0000-7000-8000-000000030020', '00000000-0000-7000-8000-000000030002',
             'rp', 'RP', 'public', 'web', 'none', ARRAY['https://rp.example.test/cb'],
             ARRAY['authorization_code', 'refresh_token'], ARRAY['openid', 'profile'], true,
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z', 'jwt', 'required', NULL, false,
             '["https://rp.example.test/bye"]', NULL, false, '["https://api.example.test"]',
             'optional');

INSERT INTO consent_grant (id, tenant_id, user_id, client_id, scopes, created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000030030', '00000000-0000-7000-8000-000000030002',
             '00000000-0000-7000-8000-000000030012', 'rp', '["openid","profile"]',
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z');
