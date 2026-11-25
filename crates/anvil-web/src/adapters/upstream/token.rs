//! Authorization-code exchange at an upstream token endpoint (RFC 6749 §4.1.3, RFC 7636 §4.5).
//!
//! - `client_secret_basic`: `Authorization: Basic` over the form-urlencoded client id and secret
//!   (RFC 6749 §2.3.1). `client_secret_post`: `client_id` and `client_secret` in the body. A
//!   connection without a secret (public client) sends only `client_id` in the body.
//! - The PKCE `code_verifier` is sent when the caller has one.
//! - `Accept: application/json` is always sent: GitHub answers form-encoded otherwise.
//! - The response is read up to [`LIMIT_TOKEN`]. A non-2xx status is
//!   [`UpstreamError::Status`] (the body is not echoed); a 200 carrying `error` (GitHub style) is
//!   `InvalidResponse("error response")`.
//! - Nothing here logs the code, the verifier, the secret or a token.

use anvil_core::ports::{CodeExchange, TokenEndpointAuth, TokenSet, UpstreamError};
use reqwest::header::{ACCEPT, HeaderValue};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::adapters::outbound::{LIMIT_TOKEN, OutboundClient};

#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The request body (already form-encoded) and, for `client_secret_basic`, the encoded
/// credentials.
fn build_request(
    exchange: &CodeExchange,
) -> (Zeroizing<String>, Option<(String, Zeroizing<String>)>) {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code");
    form.append_pair("code", exchange.code.expose_secret());
    form.append_pair("redirect_uri", &exchange.redirect_uri);
    if let Some(verifier) = &exchange.code_verifier {
        form.append_pair("code_verifier", verifier.expose_secret());
    }
    let mut basic = None;
    match (&exchange.client_secret, exchange.auth) {
        (Some(secret), TokenEndpointAuth::Basic) => {
            basic = Some((
                form_encode(&exchange.client_id),
                Zeroizing::new(form_encode(secret.expose_secret())),
            ));
        }
        (Some(secret), TokenEndpointAuth::Post) => {
            form.append_pair("client_id", &exchange.client_id);
            form.append_pair("client_secret", secret.expose_secret());
        }
        (None, _) => {
            form.append_pair("client_id", &exchange.client_id);
        }
    }
    (Zeroizing::new(form.finish()), basic)
}

/// Exchanges the code; see the module docs.
pub async fn exchange_code(
    outbound: &OutboundClient,
    exchange: &CodeExchange,
) -> Result<TokenSet, UpstreamError> {
    tracing::debug!(
        host = %super::log_host(&exchange.token_endpoint),
        auth = ?exchange.auth,
        pkce = exchange.code_verifier.is_some(),
        "exchanging upstream authorization code"
    );
    let (body, basic) = build_request(exchange);
    let mut req = outbound
        .post(&exchange.token_endpoint)?
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .form_body(body.to_string());
    if let Some((id, secret)) = &basic {
        req = req.basic_auth(id, secret);
    }
    let bytes = Zeroizing::new(req.fetch(LIMIT_TOKEN).await?);
    parse_token_response(&bytes)
}

/// Parses a token-endpoint JSON body.
pub fn parse_token_response(body: &[u8]) -> Result<TokenSet, UpstreamError> {
    let raw: RawTokenResponse = serde_json::from_slice(body)
        .map_err(|_| UpstreamError::InvalidResponse("malformed token response"))?;
    if raw.error.is_some() {
        return Err(UpstreamError::InvalidResponse("error response"));
    }
    let access_token = raw
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or(UpstreamError::InvalidResponse("missing access_token"))?;
    let token_type = raw
        .token_type
        .ok_or(UpstreamError::InvalidResponse("missing token_type"))?;
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err(UpstreamError::InvalidResponse("unsupported token_type"));
    }
    Ok(TokenSet {
        access_token: SecretString::from(access_token),
        id_token: raw.id_token.filter(|t| !t.is_empty()),
        token_type,
        scope: raw.scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(auth: TokenEndpointAuth, secret: Option<&str>) -> CodeExchange {
        CodeExchange {
            token_endpoint: "https://idp.example/token".into(),
            client_id: "my client:1".into(),
            client_secret: secret.map(|s| SecretString::from(s.to_owned())),
            auth,
            code: SecretString::from("c0de".to_owned()),
            redirect_uri: "https://rp.example/cb?x=1".into(),
            code_verifier: Some(SecretString::from("v".repeat(43))),
        }
    }

    #[test]
    fn basic_encodes_credentials_and_keeps_them_out_of_the_body() {
        let (body, basic) = build_request(&exchange(TokenEndpointAuth::Basic, Some("s&cret+/")));
        let (id, secret) = basic.expect("basic credentials");
        assert_eq!(id, "my+client%3A1");
        assert_eq!(secret.as_str(), "s%26cret%2B%2F");
        assert!(!body.contains("client_secret"));
        assert!(!body.contains("client_id"));
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code_verifier="));
        assert!(body.contains("redirect_uri=https%3A%2F%2Frp.example%2Fcb%3Fx%3D1"));
    }

    #[test]
    fn post_and_public_put_the_client_in_the_body() {
        let (body, basic) = build_request(&exchange(TokenEndpointAuth::Post, Some("s")));
        assert!(basic.is_none());
        assert!(body.contains("client_id=my+client%3A1"));
        assert!(body.contains("client_secret=s"));
        let (body, basic) = build_request(&exchange(TokenEndpointAuth::Basic, None));
        assert!(basic.is_none());
        assert!(body.contains("client_id="));
        assert!(!body.contains("client_secret"));
    }

    #[test]
    fn token_response_shapes() {
        let ok = parse_token_response(br#"{"access_token":"a","token_type":"bearer"}"#).unwrap();
        assert_eq!(ok.access_token.expose_secret(), "a");
        assert!(ok.id_token.is_none());
        for (body, reason) in [
            (
                &br#"{"error":"bad_verification_code"}"#[..],
                "error response",
            ),
            (br#"{"token_type":"Bearer"}"#, "missing access_token"),
            (
                br#"{"access_token":"","token_type":"Bearer"}"#,
                "missing access_token",
            ),
            (br#"{"access_token":"a"}"#, "missing token_type"),
            (
                br#"{"access_token":"a","token_type":"DPoP"}"#,
                "unsupported token_type",
            ),
            (
                b"access_token=a&token_type=bearer",
                "malformed token response",
            ),
        ] {
            assert_eq!(
                parse_token_response(body).err(),
                Some(UpstreamError::InvalidResponse(reason))
            );
        }
    }
}
