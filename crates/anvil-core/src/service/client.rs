//! Client registration and management.
//!
//! [`validate_client`] holds every registration rule: redirect URIs (through the injected
//! [`RedirectValidator`]), the PKCE rule (only confidential clients may opt out), auth-method and
//! grant consistency, and the inline-JWKS rules for `private_key_jwt`.

use std::sync::Arc;

use anvil_jose::Jwks;
use anvil_jose::encoding::{random_token, secret_hash};
use secrecy::SecretString;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    ApplicationType, Client, ClientAuthMethod, ClientId, ClientType, ClientUpdate, GrantType,
    NewClient, Page, PageRequest, Scope, SecretHash, TenantId,
};
use crate::ports::{Storage, StorageError};
use crate::service::tenant::{MAX_DISPLAY_NAME_LEN, admin_page};

/// Validates one redirect URI for an application type. Wired to
/// `oauth::redirect::validate_redirect_uri` by the binary; tests inject their own.
pub type RedirectValidator = fn(&str, ApplicationType) -> Result<(), CoreError>;

/// Length of generated `client_id`s (base64url characters, 132 bits).
pub const CLIENT_ID_LEN: usize = 22;

/// Maximum number of redirect URIs per client.
pub const MAX_REDIRECT_URIS: usize = 50;

/// A client registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInput {
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    /// Defaults to `true`. Only confidential clients may set `false`.
    pub require_pkce: Option<bool>,
    /// Inline JWKS JSON (public keys only), required for `private_key_jwt`.
    pub jwks: Option<String>,
    /// Not supported in this release; any value is rejected.
    pub jwks_uri: Option<String>,
}

/// Partial update of a registered client. Type, application type and auth method are fixed at
/// creation (they decide whether a secret exists). `jwks: Some(None)` clears the JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientPatch {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<GrantType>>,
    pub scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub jwks: Option<Option<String>>,
}

/// A created client. `client_secret` is the plaintext secret, returned exactly once and only for
/// secret-based auth methods; only its hash is stored.
#[derive(Debug)]
pub struct CreatedClient {
    pub client: Client,
    pub client_secret: Option<SecretString>,
}

fn invalid(field: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// Whether the auth method authenticates with a shared secret.
pub fn uses_secret(method: ClientAuthMethod) -> bool {
    matches!(
        method,
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
    )
}

/// A fresh client secret (256-bit random, base64url) and its storage hash.
pub fn new_client_secret() -> (SecretString, SecretHash) {
    let secret = random_token();
    let hash = SecretHash(secret_hash(&secret));
    (SecretString::from(secret), hash)
}

/// Checks every registration rule. Errors are `Validation` with the offending field.
pub fn validate_client(
    input: &ClientInput,
    redirect_validator: RedirectValidator,
) -> Result<(), CoreError> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err(invalid("name", "is required"));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_LEN || name.chars().any(char::is_control) {
        return Err(invalid(
            "name",
            "must be at most 200 characters without control characters",
        ));
    }

    if input.jwks_uri.is_some() {
        return Err(invalid("jwks_uri", "not supported in this release"));
    }

    // Grants.
    if input.grant_types.is_empty() {
        return Err(invalid(
            "grant_types",
            "at least one grant type is required",
        ));
    }
    let has = |g: GrantType| input.grant_types.contains(&g);
    if has(GrantType::RefreshToken) && !has(GrantType::AuthorizationCode) {
        return Err(invalid(
            "grant_types",
            "refresh_token requires authorization_code",
        ));
    }

    // Client type and auth method consistency.
    match input.client_type {
        ClientType::Public => {
            if input.auth_method != ClientAuthMethod::None {
                return Err(invalid(
                    "auth_method",
                    "public clients must use token endpoint auth method none",
                ));
            }
            if input.require_pkce == Some(false) {
                return Err(invalid(
                    "require_pkce",
                    "public clients must use PKCE; only confidential clients may disable it",
                ));
            }
            if has(GrantType::ClientCredentials) {
                return Err(invalid(
                    "grant_types",
                    "public clients may not use client_credentials",
                ));
            }
        }
        ClientType::Confidential => {
            if input.auth_method == ClientAuthMethod::None {
                return Err(invalid(
                    "auth_method",
                    "confidential clients must authenticate at the token endpoint",
                ));
            }
        }
    }

    // JWKS.
    match (&input.jwks, input.auth_method) {
        (None, ClientAuthMethod::PrivateKeyJwt) => {
            return Err(invalid("jwks", "private_key_jwt requires an inline jwks"));
        }
        (Some(jwks), ClientAuthMethod::PrivateKeyJwt) => {
            let parsed = Jwks::parse(jwks).map_err(|_| {
                invalid(
                    "jwks",
                    "must be a JWK Set of public keys (private members are not allowed)",
                )
            })?;
            if parsed.keys.is_empty() {
                return Err(invalid("jwks", "must contain at least one key"));
            }
        }
        (Some(_), _) => {
            return Err(invalid("jwks", "only allowed with private_key_jwt"));
        }
        (None, _) => {}
    }

    // Redirect URIs.
    if has(GrantType::AuthorizationCode) && input.redirect_uris.is_empty() {
        return Err(invalid(
            "redirect_uris",
            "authorization_code requires at least one redirect URI",
        ));
    }
    if input.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid("redirect_uris", "too many redirect URIs"));
    }
    for uri in &input.redirect_uris {
        redirect_validator(uri, input.application_type).map_err(|e| {
            let message = match e {
                CoreError::Validation { message, .. } => message,
                other => other.to_string(),
            };
            invalid("redirect_uris", message)
        })?;
    }

    // Scopes: each entry is a single scope token.
    for s in &input.scopes {
        if s.contains(' ') || Scope::parse(s).is_err() {
            return Err(invalid("scopes", format!("invalid scope token {s:?}")));
        }
    }
    Ok(())
}

fn normalized_grants(grants: &[GrantType]) -> Vec<GrantType> {
    let mut g = grants.to_vec();
    g.sort();
    g.dedup();
    g
}

fn normalized_list(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for i in items {
        if !out.contains(i) {
            out.push(i.clone());
        }
    }
    out
}

/// A freshly generated `client_id`.
pub fn new_client_id() -> String {
    random_token()[..CLIENT_ID_LEN].to_owned()
}

/// Client management.
pub struct ClientService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub redirect_validator: RedirectValidator,
}

impl ClientService {
    /// Validates and registers a client. Secret-based clients get a new secret, returned once.
    pub async fn create(
        &self,
        tenant: TenantId,
        input: ClientInput,
    ) -> Result<CreatedClient, CoreError> {
        validate_client(&input, self.redirect_validator)?;
        let (secret, hash) = if uses_secret(input.auth_method) {
            let (s, h) = new_client_secret();
            (Some(s), Some(h))
        } else {
            (None, None)
        };
        let now = self.clock.now();
        let mut new = NewClient {
            id: ClientId::new_v7(),
            client_id: new_client_id(),
            name: input.name.trim().to_owned(),
            client_type: input.client_type,
            application_type: input.application_type,
            auth_method: input.auth_method,
            secret_hash: hash,
            jwks: input.jwks,
            redirect_uris: normalized_list(&input.redirect_uris),
            grant_types: normalized_grants(&input.grant_types),
            scopes: normalized_list(&input.scopes),
            require_pkce: input.require_pkce.unwrap_or(true),
            created_at: now,
            token_format: crate::model::TokenFormat::Jwt,
            consent_mode: crate::model::ConsentMode::Required,
            id_token_signed_response_alg: None,
            can_introspect: false,
        };
        // A client_id collision is astronomically unlikely; retry once with a fresh id.
        let client = match self.storage.clients().create(tenant, &new).await {
            Err(StorageError::Conflict(_)) => {
                new.id = ClientId::new_v7();
                new.client_id = new_client_id();
                self.storage
                    .clients()
                    .create(tenant, &new)
                    .await
                    .map_err(|e| match e {
                        StorageError::Conflict(_) => {
                            CoreError::Conflict("client_id already in use".to_owned())
                        }
                        other => other.into(),
                    })?
            }
            other => other?,
        };
        Ok(CreatedClient {
            client,
            client_secret: secret,
        })
    }

    pub async fn get(&self, tenant: TenantId, client_id: &str) -> Result<Client, CoreError> {
        self.storage
            .clients()
            .get(tenant, client_id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Client>, CoreError> {
        Ok(self
            .storage
            .clients()
            .list(tenant, admin_page(page))
            .await?)
    }

    /// Applies a patch. The merged registration is re-validated with the same rules as create.
    pub async fn update(
        &self,
        tenant: TenantId,
        client_id: &str,
        patch: ClientPatch,
    ) -> Result<Client, CoreError> {
        let current = self.get(tenant, client_id).await?;
        let merged = ClientInput {
            name: patch.name.clone().unwrap_or_else(|| current.name.clone()),
            client_type: current.client_type,
            application_type: current.application_type,
            auth_method: current.auth_method,
            redirect_uris: patch
                .redirect_uris
                .clone()
                .unwrap_or_else(|| current.redirect_uris.clone()),
            grant_types: patch
                .grant_types
                .clone()
                .unwrap_or_else(|| current.grant_types.clone()),
            scopes: patch
                .scopes
                .clone()
                .unwrap_or_else(|| current.scopes.clone()),
            require_pkce: Some(patch.require_pkce.unwrap_or(current.require_pkce)),
            jwks: match &patch.jwks {
                None => current.jwks.clone(),
                Some(j) => j.clone(),
            },
            jwks_uri: None,
        };
        validate_client(&merged, self.redirect_validator)?;
        let update = ClientUpdate {
            name: patch.name.map(|n| n.trim().to_owned()),
            redirect_uris: patch.redirect_uris.as_deref().map(normalized_list),
            grant_types: patch.grant_types.as_deref().map(normalized_grants),
            scopes: patch.scopes.as_deref().map(normalized_list),
            require_pkce: patch.require_pkce,
            jwks: patch.jwks,
            ..ClientUpdate::default()
        };
        self.storage
            .clients()
            .update(tenant, client_id, &update, self.clock.now())
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Replaces the secret of a secret-based client. The new secret is returned once; the old
    /// one stops working immediately.
    pub async fn rotate_secret(
        &self,
        tenant: TenantId,
        client_id: &str,
    ) -> Result<SecretString, CoreError> {
        let current = self.get(tenant, client_id).await?;
        if !uses_secret(current.auth_method) {
            return Err(invalid(
                "auth_method",
                "only clients using client_secret_basic or client_secret_post have a secret",
            ));
        }
        let (secret, hash) = new_client_secret();
        if self
            .storage
            .clients()
            .set_secret_hash(tenant, client_id, Some(hash), self.clock.now())
            .await?
        {
            Ok(secret)
        } else {
            Err(CoreError::NotFound)
        }
    }

    /// Deletes the client; its token families are revoked by the repository.
    pub async fn delete(&self, tenant: TenantId, client_id: &str) -> Result<(), CoreError> {
        if self.storage.clients().delete(tenant, client_id).await? {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    /// Test validator: accepts https URIs, and http loopback URIs for native clients.
    fn test_validator(uri: &str, app: ApplicationType) -> Result<(), CoreError> {
        if uri.starts_with("https://")
            || (app == ApplicationType::Native && uri.starts_with("http://127.0.0.1"))
        {
            Ok(())
        } else {
            Err(CoreError::Validation {
                field: "redirect_uri",
                message: "redirect URI rejected by test validator".to_owned(),
            })
        }
    }

    fn confidential() -> ClientInput {
        ClientInput {
            name: "Web app".into(),
            client_type: ClientType::Confidential,
            application_type: ApplicationType::Web,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            redirect_uris: vec!["https://app.example/cb".into()],
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: vec!["openid".into(), "profile".into()],
            require_pkce: None,
            jwks: None,
            jwks_uri: None,
        }
    }

    fn public() -> ClientInput {
        ClientInput {
            name: "SPA".into(),
            client_type: ClientType::Public,
            auth_method: ClientAuthMethod::None,
            ..confidential()
        }
    }

    const PUBLIC_JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

    fn field_of(r: Result<(), CoreError>) -> &'static str {
        match r {
            Err(CoreError::Validation { field, .. }) => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    fn check(input: &ClientInput) -> Result<(), CoreError> {
        validate_client(input, test_validator)
    }

    #[test]
    fn valid_registrations_pass() {
        assert!(check(&confidential()).is_ok());
        assert!(check(&public()).is_ok());
        let m2m = ClientInput {
            redirect_uris: vec![],
            grant_types: vec![GrantType::ClientCredentials],
            ..confidential()
        };
        assert!(check(&m2m).is_ok());
    }

    #[test]
    fn confidential_client_may_disable_pkce_c1() {
        let c = ClientInput {
            require_pkce: Some(false),
            grant_types: vec![GrantType::AuthorizationCode],
            ..confidential()
        };
        assert!(check(&c).is_ok());
    }

    #[test]
    fn public_client_may_not_disable_pkce() {
        let c = ClientInput {
            require_pkce: Some(false),
            ..public()
        };
        assert_eq!(field_of(check(&c)), "require_pkce");
    }

    #[test]
    fn public_client_must_use_auth_method_none() {
        for m in [
            ClientAuthMethod::ClientSecretBasic,
            ClientAuthMethod::ClientSecretPost,
            ClientAuthMethod::PrivateKeyJwt,
        ] {
            let c = ClientInput {
                auth_method: m,
                ..public()
            };
            assert_eq!(field_of(check(&c)), "auth_method", "{m:?}");
        }
    }

    #[test]
    fn confidential_client_must_authenticate() {
        let c = ClientInput {
            auth_method: ClientAuthMethod::None,
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "auth_method");
    }

    #[test]
    fn public_client_may_not_use_client_credentials() {
        let c = ClientInput {
            grant_types: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            ..public()
        };
        assert_eq!(field_of(check(&c)), "grant_types");
    }

    #[test]
    fn private_key_jwt_requires_public_inline_jwks() {
        let base = ClientInput {
            auth_method: ClientAuthMethod::PrivateKeyJwt,
            ..confidential()
        };
        assert_eq!(field_of(check(&base)), "jwks");

        let ok = ClientInput {
            jwks: Some(PUBLIC_JWKS.into()),
            ..base.clone()
        };
        assert!(check(&ok).is_ok());

        let private = PUBLIC_JWKS.replace(r#""e":"AQAB""#, r#""e":"AQAB","d":"c2VjcmV0""#);
        let with_d = ClientInput {
            jwks: Some(private),
            ..base.clone()
        };
        assert_eq!(field_of(check(&with_d)), "jwks");

        for bad in ["not json", r#"{"keys":[]}"#, r#"{"nokeys":1}"#] {
            let c = ClientInput {
                jwks: Some(bad.into()),
                ..base.clone()
            };
            assert_eq!(field_of(check(&c)), "jwks", "{bad}");
        }
    }

    #[test]
    fn jwks_only_with_private_key_jwt() {
        let c = ClientInput {
            jwks: Some(PUBLIC_JWKS.into()),
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "jwks");
    }

    #[test]
    fn jwks_uri_is_not_supported() {
        let c = ClientInput {
            auth_method: ClientAuthMethod::PrivateKeyJwt,
            jwks: Some(PUBLIC_JWKS.into()),
            jwks_uri: Some("https://app.example/jwks".into()),
            ..confidential()
        };
        match check(&c) {
            Err(CoreError::Validation { field, message }) => {
                assert_eq!(field, "jwks_uri");
                assert!(message.contains("not supported in this release"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn authorization_code_requires_redirect_uris() {
        let c = ClientInput {
            redirect_uris: vec![],
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "redirect_uris");
    }

    #[test]
    fn redirect_validator_error_is_propagated_as_redirect_uris() {
        let c = ClientInput {
            redirect_uris: vec![
                "https://ok.example/cb".into(),
                "http://evil.example/cb".into(),
            ],
            ..confidential()
        };
        match check(&c) {
            Err(CoreError::Validation { field, message }) => {
                assert_eq!(field, "redirect_uris");
                assert!(message.contains("test validator"));
            }
            other => panic!("unexpected {other:?}"),
        }
        // The application type is passed to the validator.
        let native = ClientInput {
            application_type: ApplicationType::Native,
            redirect_uris: vec!["http://127.0.0.1:4000/cb".into()],
            ..public()
        };
        assert!(check(&native).is_ok());
        let web = ClientInput {
            application_type: ApplicationType::Web,
            ..native
        };
        assert_eq!(field_of(check(&web)), "redirect_uris");
    }

    #[test]
    fn refresh_token_requires_authorization_code() {
        let c = ClientInput {
            grant_types: vec![GrantType::RefreshToken, GrantType::ClientCredentials],
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "grant_types");
        let none = ClientInput {
            grant_types: vec![],
            ..confidential()
        };
        assert_eq!(field_of(check(&none)), "grant_types");
    }

    #[test]
    fn name_and_scopes_are_validated() {
        let c = ClientInput {
            name: "  ".into(),
            ..confidential()
        };
        assert_eq!(field_of(check(&c)), "name");
        for bad in ["open id", "", "a\"b"] {
            let c = ClientInput {
                scopes: vec![bad.into()],
                ..confidential()
            };
            assert_eq!(field_of(check(&c)), "scopes", "{bad:?}");
        }
    }

    #[test]
    fn secrets_and_ids_are_random_and_hashed() {
        let (s1, h1) = new_client_secret();
        let (s2, h2) = new_client_secret();
        assert_eq!(s1.expose_secret().len(), 43);
        assert_ne!(s1.expose_secret(), s2.expose_secret());
        assert_ne!(h1, h2);
        assert_eq!(h1, SecretHash(secret_hash(s1.expose_secret())));
        assert!(!format!("{s1:?}").contains(s1.expose_secret()));
        let id = new_client_id();
        assert_eq!(id.len(), CLIENT_ID_LEN);
        assert_ne!(id, new_client_id());
        assert!(uses_secret(ClientAuthMethod::ClientSecretPost));
        assert!(!uses_secret(ClientAuthMethod::PrivateKeyJwt));
        assert!(!uses_secret(ClientAuthMethod::None));
    }

    #[test]
    fn normalisation_dedups() {
        assert_eq!(
            normalized_grants(&[
                GrantType::RefreshToken,
                GrantType::AuthorizationCode,
                GrantType::RefreshToken
            ]),
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(
            normalized_list(&["b".into(), "a".into(), "b".into()]),
            vec!["b".to_owned(), "a".to_owned()]
        );
    }
}
