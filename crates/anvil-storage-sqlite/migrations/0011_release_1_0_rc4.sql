-- Release 1.0.0-rc.4 (Phase 7.1), additive only (forward-only expand migration on top of
-- 0010_release_1_0_par_import). Released migrations 0001-0010 stay untouched.
--
-- Adds, without changing any existing row:
--   client.client_uri          OIDC Registration `client_uri` (the app's home page)
--   client.initiate_login_uri  OIDC Registration `initiate_login_uri` (starts a sign-in at the app)
--
-- Both are nullable TEXT with no default: every existing client reads NULL. They are set only by
-- an administrator (admin API / YAML) or stored from DCR/CIMD metadata; never from a request.

ALTER TABLE client ADD COLUMN client_uri TEXT;
ALTER TABLE client ADD COLUMN initiate_login_uri TEXT;
