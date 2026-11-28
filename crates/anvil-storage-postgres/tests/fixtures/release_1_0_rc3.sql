-- A populated 1.0.0-rc.3 database (schema version 8: 0001 through 0008_release_1_0_par_import).
-- Loaded by tests/upgrade.rs before migrating to the rc.4 schema (0009_release_1_0_rc4 and
-- later). Hand-written in the rc.3 shape, aimed at the client table 0009 extends (same rows as the
-- SQLite rc.3 fixture):
--
--   - a system tenant and a default tenant with one user;
--   - four clients of the default tenant, one of each kind rc.3 can hold: a static confidential
--     web client (with the 1.0 PAR / kind / headless columns set), a static public SPA client,
--     a dynamically registered (RFC 7591) client with a registration access token hash, and a
--     CIMD client with a metadata expiry;
--   - a token family of the confidential client.
--
-- Ids are fixed so the test can address the rows through the storage traits. Test data only.

INSERT INTO tenant (id, slug, display_name, created_at, settings)
     VALUES ('00000000-0000-7000-8000-000000110001', 'system', 'System', '2026-11-01T00:00:00Z',
             '{"registration":"disabled","require_verified_email":false}'),
            ('00000000-0000-7000-8000-000000110002', 'default', 'Default', '2026-11-01T00:00:00Z',
             '{"registration":"open","require_verified_email":true}');

INSERT INTO "user" (id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at)
     VALUES ('00000000-0000-7000-8000-000000110011', '00000000-0000-7000-8000-000000110002',
             'carol@example.test', true, NULL, '{"name":"Carol"}', 'active',
             '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, token_format, consent_mode,
                    id_token_signed_response_alg, can_introspect, post_logout_redirect_uris,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    allowed_resources, mfa_policy, registration_source, metadata_expires_at,
                    registration_access_token_hash, organization,
                    require_pushed_authorization_requests, client_kind, headless_native)
     VALUES
            -- Static confidential web client.
            ('00000000-0000-7000-8000-000000110070', '00000000-0000-7000-8000-000000110002',
             'rc3-web', 'rc.3 web app', 'confidential', 'web', 'client_secret_basic',
             decode(repeat('ee', 32), 'hex'), NULL, ARRAY['https://rp.example.test/cb'],
             ARRAY['authorization_code', 'refresh_token'],
             ARRAY['openid', 'profile', 'email', 'offline_access'], true, '2026-11-01T00:00:00Z',
             '2026-11-01T00:00:00Z', 'jwt', 'skip_first_party', 'ES256', true,
             '["https://rp.example.test/"]', 'https://rp.example.test/backchannel', true,
             '["https://api.example.test"]', 'optional', 'static', NULL, NULL, 'optional', true,
             'agent', false),
            -- Static public SPA client.
            ('00000000-0000-7000-8000-000000110071', '00000000-0000-7000-8000-000000110002',
             'rc3-spa', 'rc.3 SPA', 'public', 'web', 'none', NULL, NULL,
             ARRAY['https://spa.example.test/callback'], ARRAY['authorization_code'],
             ARRAY['openid', 'profile'], true, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z',
             'jwt', 'required', NULL, false, '[]', NULL, false, '[]', NULL, 'static', NULL, NULL,
             'off', false, 'application', false),
            -- Dynamically registered client (RFC 7591), with its RFC 7592 registration token hash.
            ('00000000-0000-7000-8000-000000110072', '00000000-0000-7000-8000-000000110002',
             'rc3-dcr', 'rc.3 DCR app', 'confidential', 'web', 'client_secret_post',
             decode(repeat('dd', 32), 'hex'), NULL, ARRAY['https://dcr.example.test/cb'],
             ARRAY['authorization_code'], ARRAY['openid'], true, '2026-11-01T00:00:00Z',
             '2026-11-01T00:00:00Z', 'jwt', 'required', NULL, false, '[]', NULL, false, '[]',
             NULL, 'dynamic', NULL, decode(repeat('72', 32), 'hex'), 'off', false, 'application',
             false),
            -- CIMD client (client_id is the metadata document URL).
            ('00000000-0000-7000-8000-000000110073', '00000000-0000-7000-8000-000000110002',
             'https://mcp.example.test/client.json', 'rc.3 MCP client', 'public', 'native',
             'none', NULL, NULL, ARRAY['http://127.0.0.1:33418/callback'],
             ARRAY['authorization_code', 'refresh_token'], ARRAY['openid', 'offline_access'],
             true, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', 'jwt', 'required', NULL,
             false, '[]', NULL, false, '[]', NULL, 'cimd', '2100-01-01T00:00:00Z', NULL, 'off',
             false, 'agent', false);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason, org_id)
     VALUES ('00000000-0000-7000-8000-000000110080', '00000000-0000-7000-8000-000000110002',
             'rc3-web', '00000000-0000-7000-8000-000000110011', 'openid offline_access',
             '2026-11-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'],
             '00000000-0000-7000-8000-000000110090', NULL, '2026-11-01T00:00:00Z',
             '2100-01-01T00:00:00Z', NULL, NULL, NULL);
