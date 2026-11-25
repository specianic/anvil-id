//! Bearer-authenticated JSON API calls (OIDC userinfo, OAuth2 profile endpoints, GitHub REST).
//!
//! [`ApiProfile::Standard`] sends `Accept: application/json`. [`ApiProfile::Github`] sends the
//! headers the GitHub REST API requires: `Accept: application/vnd.github+json`,
//! `X-GitHub-Api-Version: 2022-11-28` and a `User-Agent`. Responses are read up to
//! [`LIMIT_DOCUMENT`] and must be JSON (a signed userinfo JWT is not supported).

use anvil_core::ports::{ApiProfile, UpstreamError};
use reqwest::header::{ACCEPT, HeaderName, HeaderValue, USER_AGENT};
use secrecy::{ExposeSecret as _, SecretString};

use crate::adapters::outbound::{LIMIT_DOCUMENT, OutboundClient};

/// The GitHub REST API version this adapter speaks.
pub const GITHUB_API_VERSION: &str = "2022-11-28";

/// GET `url` with `Authorization: Bearer` and the profile's headers; a JSON body.
pub async fn get_json(
    outbound: &OutboundClient,
    url: &str,
    bearer: &SecretString,
    profile: ApiProfile,
) -> Result<serde_json::Value, UpstreamError> {
    tracing::debug!(host = %super::log_host(url), ?profile, "upstream API request");
    let mut req = outbound.get(url)?.bearer_auth(bearer.expose_secret());
    req = match profile {
        ApiProfile::Standard => req.header(ACCEPT, HeaderValue::from_static("application/json")),
        ApiProfile::Github => req
            .header(
                ACCEPT,
                HeaderValue::from_static("application/vnd.github+json"),
            )
            .header(
                HeaderName::from_static("x-github-api-version"),
                HeaderValue::from_static(GITHUB_API_VERSION),
            )
            .header(USER_AGENT, HeaderValue::from_static("anvilid")),
    };
    let body = req.fetch(LIMIT_DOCUMENT).await?;
    serde_json::from_slice(&body).map_err(|_| UpstreamError::InvalidResponse("malformed JSON"))
}
