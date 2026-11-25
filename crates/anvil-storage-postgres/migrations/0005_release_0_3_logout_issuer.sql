-- Release 0.3: the issuer of each RP session, for back-channel logout tokens.
--
-- OIDC Back-Channel Logout 1.0 §2.4: a logout token's `iss` must equal the `iss` of the ID tokens
-- the RP received. A tenant can be reached under more than one issuer (its custom host and
-- `/t/{slug}`), so the issuer is recorded per RP session when an authorization code is issued
-- (the latest code for the same session and client wins) and copied onto each logout delivery
-- when it is enqueued. Rows written before this migration keep `issuer` NULL; the delivery
-- worker falls back to the tenant's canonical issuer for those.
--
-- ADD COLUMN only: existing rows are untouched.

ALTER TABLE rp_session ADD COLUMN issuer text;
ALTER TABLE logout_delivery ADD COLUMN issuer text;
