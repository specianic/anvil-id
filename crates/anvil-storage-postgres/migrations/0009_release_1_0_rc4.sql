-- Release 1.0.0-rc.4 (Phase 7.1), additive only (forward-only expand migration on top of
-- 0008_release_1_0_par_import). Released migrations 0001-0008 stay untouched.
--
-- Adds, without changing any existing row:
--   client.client_uri          OIDC Registration `client_uri` (the app's home page)
--   client.initiate_login_uri  OIDC Registration `initiate_login_uri` (starts a sign-in at the app)
--
-- Both are nullable text with no default (metadata-only, no table rewrite): every existing client
-- reads NULL. The logical schema matches SQLite 0011.

ALTER TABLE client ADD COLUMN client_uri text NULL;
ALTER TABLE client ADD COLUMN initiate_login_uri text NULL;
