-- A populated 1.0.0-beta.1 database (schema version 7: 0001 through 0007_release_1_0). Loaded by
-- tests/upgrade.rs before migrating to the final 1.0 schema (0008_release_1_0_par_import and
-- later). Hand-written in the beta.1 shape, aimed at the organization data beta.1 introduced and
-- at the client table 0008 extends (same rows as the SQLite beta.1 fixture):
--
--   - a system tenant with its administrator role held by one user, and a default tenant with an
--     organization (acme), a member holding an org-owned role, a pending invitation, a SAML
--     connection of the org with an identity link, and a verified routing domain;
--   - a client with the beta.1 organization policy, an org-bound token family and code;
--   - a SAML assertion replay guard, an org invitation email template and an audit event.
--
-- Ids are fixed so the test can address the rows through the storage traits. Test data only.

INSERT INTO tenant (id, slug, display_name, created_at, settings)
     VALUES ('00000000-0000-7000-8000-000000100001', 'system', 'System', '2026-06-01T00:00:00Z',
             '{"registration":"disabled","require_verified_email":false}'),
            ('00000000-0000-7000-8000-000000100002', 'default', 'Default', '2026-06-01T00:00:00Z',
             '{"registration":"open","require_verified_email":true}');

INSERT INTO "user" (id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at)
     VALUES ('00000000-0000-7000-8000-000000100010', '00000000-0000-7000-8000-000000100001',
             'root@example.test', true, 'root', '{}', 'active', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z', NULL),
            ('00000000-0000-7000-8000-000000100011', '00000000-0000-7000-8000-000000100002',
             'alice@acme.example.test', true, NULL, '{"name":"Alice"}', 'active',
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000100012', '00000000-0000-7000-8000-000000100002',
             'bob@acme.example.test', true, 'bob', '{}', 'active', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z', NULL);

INSERT INTO credential (id, tenant_id, user_id, kind, data, created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000100013', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100011', 'password', '$argon2id$v=19$beta1-alice',
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z');

INSERT INTO organization (id, tenant_id, slug, display_name, mfa_policy, settings, metadata,
                          created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000100020', '00000000-0000-7000-8000-000000100002',
             'acme', 'Acme Corp', NULL, '{}', '{"plan":"enterprise"}', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z');

INSERT INTO org_membership (tenant_id, org_id, user_id, created_at)
     VALUES ('00000000-0000-7000-8000-000000100002', '00000000-0000-7000-8000-000000100020',
             '00000000-0000-7000-8000-000000100011', '2026-06-01T00:00:00Z');

-- The system administrator role (tenant-wide) and an org-owned role of acme.
INSERT INTO role (id, tenant_id, org_id, name, description, permissions, created_at, updated_at)
     VALUES ('00000000-0000-7000-8000-000000100030', '00000000-0000-7000-8000-000000100001', NULL,
             'administrator', 'Full administrative access', ARRAY['admin:write'],
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000100031', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100020', 'org-admin', 'Manages acme',
             ARRAY['org:write'], '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z');

INSERT INTO role_assignment (tenant_id, role_id, user_id, org_id, created_at)
     VALUES ('00000000-0000-7000-8000-000000100001', '00000000-0000-7000-8000-000000100030',
             '00000000-0000-7000-8000-000000100010', NULL, '2026-06-01T00:00:00Z'),
            ('00000000-0000-7000-8000-000000100002', '00000000-0000-7000-8000-000000100031',
             '00000000-0000-7000-8000-000000100011', '00000000-0000-7000-8000-000000100020',
             '2026-06-01T00:00:00Z');

INSERT INTO org_invitation (id, tenant_id, org_id, email, role_ids, token_hash, invited_by_kind,
                            invited_by_id, created_at, expires_at, accepted_at, accepted_user_id,
                            revoked_at)
     VALUES ('00000000-0000-7000-8000-000000100040', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100020', 'carol@acme.example.test',
             '["00000000-0000-7000-8000-000000100031"]', decode(repeat('51', 32), 'hex'), 'user',
             '00000000-0000-7000-8000-000000100011', '2026-06-01T00:00:00Z',
             '2100-01-01T00:00:00Z', NULL, NULL, NULL);

-- A SAML connection owned by acme (certificates are public material).
INSERT INTO connection (id, tenant_id, slug, display_name, kind, enabled, config, secret_enc,
                        trust_email_verified, created_at, updated_at, org_id)
     VALUES ('00000000-0000-7000-8000-000000100050', '00000000-0000-7000-8000-000000100002',
             'acme-saml', 'Acme SAML', 'saml', true,
             '{"type":"saml","idp_entity_id":"https://idp.acme.example.test/metadata","sso_url":"https://idp.acme.example.test/sso","signing_certs":["-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----"],"name_id_format":"email_address","attributes":{"email":"mail"},"metadata_url":null}',
             NULL, true, '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z',
             '00000000-0000-7000-8000-000000100020');

INSERT INTO identity_link (id, tenant_id, user_id, connection_id, subject, email_at_link,
                           metadata, created_at, last_used_at)
     VALUES ('00000000-0000-7000-8000-000000100051', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100012', '00000000-0000-7000-8000-000000100050',
             'bob@acme.example.test', 'bob@acme.example.test', '{}', '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z');

INSERT INTO org_domain (id, tenant_id, org_id, domain, token, status, connection_id, routing,
                        allow_local_password, verified_at, last_checked_at, failing_since,
                        created_at)
     VALUES ('00000000-0000-7000-8000-000000100060', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100020', 'acme.example.test', 'anvilid-verify-beta1',
             'verified', '00000000-0000-7000-8000-000000100050', true, false,
             '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z', NULL, '2026-06-01T00:00:00Z');

INSERT INTO client (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, organization)
     VALUES ('00000000-0000-7000-8000-000000100070', '00000000-0000-7000-8000-000000100002',
             'beta1-web', 'beta.1 web app', 'confidential', 'web', 'client_secret_basic',
             decode(repeat('ee', 32), 'hex'), NULL, ARRAY['https://rp.acme.example.test/cb'],
             ARRAY['authorization_code', 'refresh_token'], ARRAY['openid', 'offline_access'],
             true, '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z', 'optional');

INSERT INTO browser_session (id, tenant_id, user_id, token_hash, auth_time, acr, amr, created_at,
                             last_seen_at, expires_at, idle_expires_at)
     VALUES ('00000000-0000-7000-8000-000000100090', '00000000-0000-7000-8000-000000100002',
             '00000000-0000-7000-8000-000000100011', decode(repeat('54', 32), 'hex'),
             '2026-06-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'], '2026-06-01T00:00:00Z',
             '2026-06-01T00:00:00Z', '2100-01-01T00:00:00Z', '2100-01-01T00:00:00Z');

INSERT INTO token_family (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr,
                          session_id, claims, created_at, absolute_expires_at, revoked_at,
                          revoked_reason, org_id)
     VALUES ('00000000-0000-7000-8000-000000100080', '00000000-0000-7000-8000-000000100002',
             'beta1-web', '00000000-0000-7000-8000-000000100011', 'openid offline_access',
             '2026-06-01T00:00:00Z', 'urn:anvilid:acr:pwd', ARRAY['pwd'],
             '00000000-0000-7000-8000-000000100090', NULL, '2026-06-01T00:00:00Z',
             '2100-01-01T00:00:00Z', NULL, NULL, '00000000-0000-7000-8000-000000100020');

INSERT INTO authorization_code (code_hash, tenant_id, client_id, user_id, session_id,
                                redirect_uri, scope, nonce, code_challenge, auth_time, acr, amr,
                                token_family_id, expires_at, consumed_at, created_at, org_id)
     VALUES (decode(repeat('52', 32), 'hex'), '00000000-0000-7000-8000-000000100002',
             'beta1-web', '00000000-0000-7000-8000-000000100011',
             '00000000-0000-7000-8000-000000100090', 'https://rp.acme.example.test/cb',
             'openid offline_access', NULL, 'challenge', '2026-06-01T00:00:00Z',
             'urn:anvilid:acr:pwd', ARRAY['pwd'], '00000000-0000-7000-8000-000000100080',
             '2100-01-01T00:00:00Z', NULL, '2026-06-01T00:00:00Z',
             '00000000-0000-7000-8000-000000100020');

INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at)
     VALUES ('00000000-0000-7000-8000-000000100002', 'saml_assertion_id',
             decode(repeat('53', 32), 'hex'), '2100-01-01T00:00:00Z');

INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at)
     VALUES ('00000000-0000-7000-8000-000000100002', 'org_invitation', 'Join {{org}}',
             '<p>{{link}}</p>', '{{link}}', '2026-06-01T00:00:00Z');

INSERT INTO audit_event (id, tenant_id, at, actor_kind, actor_id, action, target, outcome, ip,
                         user_agent, trace_id, details)
     VALUES ('00000000-0000-7000-8000-0000001000a0', '00000000-0000-7000-8000-000000100002',
             '2026-06-01T00:00:00Z', 'user', '00000000-0000-7000-8000-000000100011',
             'org_invitation_created', 'org:00000000-0000-7000-8000-000000100020', 'success',
             '192.0.2.10', NULL, NULL, '{}');
