//! Pushed authorization requests (RFC 9126, OIDC-18): `ParService` authenticates the client
//! through `ClientAuthService`, validates the pushed parameters like `/authorize`, stores and
//! consumes them. Owned by plan 07-13; pre-declared by 07-04 so no later plan edits
//! `service/mod.rs`.
