-- A populated 1.0.0-rc.3 database (schema version 10: 0001 through 0010_release_1_0_par_import).
-- Loaded by tests/upgrade.rs before migrating to the rc.4 schema (0011_release_1_0_rc4 and
-- later). Hand-written in the rc.3 shape, aimed at the client table 0011 extends:
--
--   - a system tenant and a default tenant with one user;
--   - four clients of the default tenant, one of each kind rc.3 can hold: a static confidential
--     web client (with the 1.0 PAR / kind / headless columns set), a static public SPA client,
--     a dynamically registered (RFC 7591) client with a registration access token hash, and a
--     CIMD client with a metadata expiry;
--   - a token family of the confidential client.
--
-- Ids are fixed so the test can address the rows through the storage traits. Timestamps: created
-- 2026-11-01 (1793491200000 ms); far future 2100-01-01 (4102444800000 ms). Test data only.

INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000110001', 'system', 'System', 1793491200000, NULL,
   '{"registration":"disabled","require_verified_email":false}'),
  (x'00000000000070008000000000110002', 'default', 'Default', 1793491200000, NULL,
   '{"registration":"open","require_verified_email":true}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at, attributes) VALUES
  (x'00000000000070008000000000110011', x'00000000000070008000000000110002',
   'carol@example.test', 1, NULL, '{"name":"Carol"}', 'active', 1793491200000, 1793491200000,
   1793491200000, '{}');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, token_format, consent_mode,
                    id_token_signed_response_alg, can_introspect, post_logout_redirect_uris,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    allowed_resources, mfa_policy, registration_source, metadata_expires_at,
                    registration_access_token_hash, organization,
                    require_pushed_authorization_requests, client_kind, headless_native) VALUES
  -- Static confidential web client.
  (x'00000000000070008000000000110070', x'00000000000070008000000000110002', 'rc3-web',
   'rc.3 web app', 'confidential', 'web', 'client_secret_basic',
   x'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', NULL,
   '["https://rp.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","profile","email","offline_access"]', 1, 1793491200000, 1793491200000, 'jwt',
   'skip_first_party', 'ES256', 1, '["https://rp.example.test/"]',
   'https://rp.example.test/backchannel', 1, '["https://api.example.test"]', 'optional',
   'static', NULL, NULL, 'optional', 1, 'agent', 0),
  -- Static public SPA client.
  (x'00000000000070008000000000110071', x'00000000000070008000000000110002', 'rc3-spa',
   'rc.3 SPA', 'public', 'web', 'none', NULL, NULL, '["https://spa.example.test/callback"]',
   '["authorization_code"]', '["openid","profile"]', 1, 1793491200000, 1793491200000, 'jwt',
   'required', NULL, 0, '[]', NULL, 0, '[]', NULL, 'static', NULL, NULL, 'off', 0,
   'application', 0),
  -- Dynamically registered client (RFC 7591), with its RFC 7592 registration token hash.
  (x'00000000000070008000000000110072', x'00000000000070008000000000110002', 'rc3-dcr',
   'rc.3 DCR app', 'confidential', 'web', 'client_secret_post',
   x'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', NULL,
   '["https://dcr.example.test/cb"]', '["authorization_code"]', '["openid"]', 1,
   1793491200000, 1793491200000, 'jwt', 'required', NULL, 0, '[]', NULL, 0, '[]', NULL,
   'dynamic', NULL, x'7272727272727272727272727272727272727272727272727272727272727272', 'off',
   0, 'application', 0),
  -- CIMD client (client_id is the metadata document URL).
  (x'00000000000070008000000000110073', x'00000000000070008000000000110002',
   'https://mcp.example.test/client.json', 'rc.3 MCP client', 'public', 'native', 'none', NULL,
   NULL, '["http://127.0.0.1:33418/callback"]', '["authorization_code","refresh_token"]',
   '["openid","offline_access"]', 1, 1793491200000, 1793491200000, 'jwt', 'required', NULL, 0,
   '[]', NULL, 0, '[]', NULL, 'cimd', 4102444800000, NULL, 'off', 0, 'agent', 0);

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason, org_id) VALUES
  (x'00000000000070008000000000110080', x'00000000000070008000000000110002', 'rc3-web',
   x'00000000000070008000000000110011', 'openid offline_access', 1793491200000,
   'urn:anvilid:acr:pwd', '["pwd"]', x'00000000000070008000000000110090', NULL, 1793491200000,
   4102444800000, NULL, NULL, NULL);
