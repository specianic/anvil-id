-- A populated Release 0.3 database (schema version 6: 0001 through 0006_release_0_3_logout_issuer).
-- Loaded by tests/upgrade.rs before migrating to the 0.4 schema (0007_release_0_4). Hand-written in
-- the 0.3 shape: a system tenant with two administrators (before 0.4 every system-tenant user was
-- an administrator), a default tenant with one end user, a 0.3 client with logout URIs and
-- resources, and a consent grant. Ids are fixed so the test can address the rows through the
-- storage traits. Timestamps: created 2025-01-01 (1735689600000 ms).

INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000030001', 'system', 'System', 1735689600000, NULL,
   '{"registration":"disabled","require_verified_email":false}'),
  (x'00000000000070008000000000030002', 'default', 'Default', 1735689600000, NULL,
   '{"registration":"open","require_verified_email":true}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at) VALUES
  (x'00000000000070008000000000030010', x'00000000000070008000000000030001',
   'root@example.test', 1, 'root', '{}', 'active', 1735689600000, 1735689600000, NULL),
  (x'00000000000070008000000000030011', x'00000000000070008000000000030001',
   'ops@example.test', 1, NULL, '{"name":"Ops"}', 'blocked', 1735689600000, 1735689600000,
   1735689600000),
  (x'00000000000070008000000000030012', x'00000000000070008000000000030002',
   'end@example.test', 1, NULL, '{"name":"End User"}', 'active', 1735689600000, 1735689600000,
   NULL);

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, token_format, consent_mode,
                    id_token_signed_response_alg, can_introspect, post_logout_redirect_uris,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    allowed_resources, mfa_policy) VALUES
  (x'00000000000070008000000000030020', x'00000000000070008000000000030002', 'v03-web',
   'v0.3 web app', 'confidential', 'web', 'client_secret_basic',
   x'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', NULL,
   '["https://rp.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","profile","offline_access"]', 1, 1735689600000, 1735689600000, 'jwt', 'required',
   NULL, 0, '["https://rp.example.test/bye"]', 'https://rp.example.test/bc', 1,
   '["https://api.example.test"]', 'required');

INSERT INTO consent_grant (id, tenant_id, user_id, client_id, scopes, created_at, updated_at,
                           revoked_at) VALUES
  (x'00000000000070008000000000030050', x'00000000000070008000000000030002',
   x'00000000000070008000000000030012', 'v03-web', '["openid","profile"]', 1735689600000,
   1735689600000, NULL);
