-- A populated 1.0.0-beta.1 database (schema version 9: 0001 through 0009_release_1_0_rebuild).
-- Loaded by tests/upgrade.rs before migrating to the final 1.0 schema (0010_release_1_0_par_import
-- and later). Hand-written in the beta.1 shape, aimed at the organization data beta.1 introduced
-- and at the client table 0010 extends:
--
--   - a system tenant with its administrator role held by one user, and a default tenant with an
--     organization (acme), a member holding an org-owned role, a pending invitation, a SAML
--     connection of the org with an identity link, and a verified routing domain;
--   - a client with the beta.1 organization policy, an org-bound token family and code;
--   - a SAML assertion replay guard, an org invitation email template and an audit event.
--
-- Ids are fixed so the test can address the rows through the storage traits. Timestamps: created
-- 2026-06-01 (1780272000000 ms); far future 2100-01-01 (4102444800000 ms).

INSERT INTO tenant (id, slug, display_name, created_at, host, settings) VALUES
  (x'00000000000070008000000000100001', 'system', 'System', 1780272000000, NULL,
   '{"registration":"disabled","require_verified_email":false}'),
  (x'00000000000070008000000000100002', 'default', 'Default', 1780272000000, NULL,
   '{"registration":"open","require_verified_email":true}');

INSERT INTO user (id, tenant_id, email, email_verified, username, claims, status, created_at,
                  updated_at, last_login_at, attributes) VALUES
  (x'00000000000070008000000000100010', x'00000000000070008000000000100001',
   'root@example.test', 1, 'root', '{}', 'active', 1780272000000, 1780272000000, NULL, '{}'),
  (x'00000000000070008000000000100011', x'00000000000070008000000000100002',
   'alice@acme.example.test', 1, NULL, '{"name":"Alice"}', 'active', 1780272000000,
   1780272000000, 1780272000000, '{}'),
  (x'00000000000070008000000000100012', x'00000000000070008000000000100002',
   'bob@acme.example.test', 1, 'bob', '{}', 'active', 1780272000000, 1780272000000, NULL, '{}');

INSERT INTO credential (id, tenant_id, user_id, kind, secret, created_at, updated_at) VALUES
  (x'00000000000070008000000000100013', x'00000000000070008000000000100002',
   x'00000000000070008000000000100011', 'password', '$argon2id$v=19$beta1-alice',
   1780272000000, 1780272000000);

INSERT INTO organization (id, tenant_id, slug, display_name, mfa_policy, settings, metadata,
                          created_at, updated_at) VALUES
  (x'00000000000070008000000000100020', x'00000000000070008000000000100002', 'acme',
   'Acme Corp', NULL, '{}', '{"plan":"enterprise"}', 1780272000000, 1780272000000);

INSERT INTO org_membership (tenant_id, org_id, user_id, created_at) VALUES
  (x'00000000000070008000000000100002', x'00000000000070008000000000100020',
   x'00000000000070008000000000100011', 1780272000000);

-- The system administrator role (tenant-wide) and an org-owned role of acme.
INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at,
                  updated_at) VALUES
  (x'00000000000070008000000000100030', x'00000000000070008000000000100001', NULL,
   'administrator', 'Full administrative access', '["admin:write"]', 1780272000000,
   1780272000000),
  (x'00000000000070008000000000100031', x'00000000000070008000000000100002',
   x'00000000000070008000000000100020', 'org-admin', 'Manages acme', '["org:write"]',
   1780272000000, 1780272000000);

INSERT INTO role_assignment (tenant_id, role_id, user_id, org_id, created_at) VALUES
  (x'00000000000070008000000000100001', x'00000000000070008000000000100030',
   x'00000000000070008000000000100010', NULL, 1780272000000),
  (x'00000000000070008000000000100002', x'00000000000070008000000000100031',
   x'00000000000070008000000000100011', x'00000000000070008000000000100020', 1780272000000);

INSERT INTO org_invitation (id, tenant_id, org_id, email, roles, token_hash, invited_by_kind,
                            invited_by_id, created_at, expires_at, accepted_at,
                            accepted_user_id, revoked_at) VALUES
  (x'00000000000070008000000000100040', x'00000000000070008000000000100002',
   x'00000000000070008000000000100020', 'carol@acme.example.test',
   '["00000000-0000-7000-8000-000000100031"]',
   x'5151515151515151515151515151515151515151515151515151515151515151', 'user',
   '00000000-0000-7000-8000-000000100011', 1780272000000, 4102444800000, NULL, NULL, NULL);

-- A SAML connection owned by acme (certificates are public material).
INSERT INTO connection (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                        trust_email_verified, created_at, updated_at, org_id) VALUES
  (x'00000000000070008000000000100050', x'00000000000070008000000000100002', 'acme-saml',
   'Acme SAML', 'saml', 1,
   '{"type":"saml","idp_entity_id":"https://idp.acme.example.test/metadata","sso_url":"https://idp.acme.example.test/sso","signing_certs":["-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----"],"name_id_format":"email_address","attributes":{"email":"mail"},"metadata_url":null}',
   NULL, 1, 1780272000000, 1780272000000, x'00000000000070008000000000100020');

INSERT INTO identity_link (id, tenant_id, user_id, connection_id, subject, email_at_link,
                           metadata, created_at, last_used_at) VALUES
  (x'00000000000070008000000000100051', x'00000000000070008000000000100002',
   x'00000000000070008000000000100012', x'00000000000070008000000000100050',
   'bob@acme.example.test', 'bob@acme.example.test', '{}', 1780272000000, 1780272000000);

INSERT INTO org_domain (id, tenant_id, org_id, domain, token, status, connection_id, routing,
                        allow_local_password, verified_at, last_checked_at, failing_since,
                        created_at) VALUES
  (x'00000000000070008000000000100060', x'00000000000070008000000000100002',
   x'00000000000070008000000000100020', 'acme.example.test', 'anvilid-verify-beta1',
   'verified', x'00000000000070008000000000100050', 1, 0, 1780272000000, 1780272000000, NULL,
   1780272000000);

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, organization) VALUES
  (x'00000000000070008000000000100070', x'00000000000070008000000000100002', 'beta1-web',
   'beta.1 web app', 'confidential', 'web', 'client_secret_basic',
   x'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', NULL,
   '["https://rp.acme.example.test/cb"]', '["authorization_code","refresh_token"]',
   '["openid","offline_access"]', 1, 1780272000000, 1780272000000, 'optional');

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason, org_id) VALUES
  (x'00000000000070008000000000100080', x'00000000000070008000000000100002', 'beta1-web',
   x'00000000000070008000000000100011', 'openid offline_access', 1780272000000,
   'urn:anvilid:acr:pwd', '["pwd"]', x'00000000000070008000000000100090', NULL, 1780272000000,
   4102444800000, NULL, NULL, x'00000000000070008000000000100020');

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at, org_id)
  VALUES
  (x'5252525252525252525252525252525252525252525252525252525252525252',
   x'00000000000070008000000000100002', 'beta1-web', x'00000000000070008000000000100011',
   x'00000000000070008000000000100090', 'https://rp.acme.example.test/cb',
   'openid offline_access', NULL, 'challenge', 1780272000000, 'urn:anvilid:acr:pwd', '["pwd"]',
   x'00000000000070008000000000100080', 4102444800000, NULL, 1780272000000,
   x'00000000000070008000000000100020');

INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at) VALUES
  (x'00000000000070008000000000100002', 'saml_assertion_id',
   x'5353535353535353535353535353535353535353535353535353535353535353', 4102444800000);

INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at) VALUES
  (x'00000000000070008000000000100002', 'org_invitation', 'Join {{org}}', '<p>{{link}}</p>',
   '{{link}}', 1780272000000);

INSERT INTO audit_event (id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                         user_agent, trace_id, details) VALUES
  (x'000000000000700080000000001000a0', x'00000000000070008000000000100002', 1780272000000,
   'user', '00000000-0000-7000-8000-000000100011', 'org_invitation_created',
   'org:00000000-0000-7000-8000-000000100020', 'success', '192.0.2.10', NULL, NULL, '{}');
