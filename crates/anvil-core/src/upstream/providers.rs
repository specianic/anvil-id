//! Provider presets (Google, Apple, Microsoft, GitHub) and endpoint resolution for every
//! connection kind (research provider matrix, 04-RESEARCH.md).
//!
//! [`resolve`] turns a stored [`Connection`] (plus, for generic OIDC, the discovered
//! [`ProviderMetadata`]) into one [`ResolvedProvider`]: endpoints, issuer rule, ID-token
//! algorithm allow-list, scopes, PKCE, response mode, token-endpoint authentication and email
//! trust. Per-connection endpoint overrides always win over preset values.
//!
//! Provider facts encoded here:
//! - Google: issuer `https://accounts.google.com` or `accounts.google.com` (preset only), PKCE.
//! - Microsoft: multi-tenant issuer template `https://login.microsoftonline.com/{tenantid}/v2.0`
//!   (the token's `tid` is substituted), email never trusted.
//! - Apple: issuer [`APPLE_ISSUER`], `form_post` when `name`/`email` is requested, no PKCE,
//!   `client_secret_post` with an ES256 client-secret JWT ([`apple_client_secret_claims`]).
//! - GitHub: plain OAuth2, scopes `read:user user:email`, REST API at `https://api.github.com`.
//! - Generic OIDC: discovery metadata required, issuer must equal the configured issuer, ID-token
//!   algorithms = metadata ∩ {RS256, PS256, ES256, Ed25519} (`EdDSA` unsupported by design).
//!
//! Pure: no I/O. Discovery and JWKS fetching go through `ports::UpstreamClient`.

use anvil_jose::Alg;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use url::Url;

use crate::error::CoreError;
use crate::model::{Connection, ConnectionConfig, ConnectionKind, SocialConfig, SocialProvider};
use crate::ports::{ApiProfile, ProviderMetadata, TokenEndpointAuth};

/// Apple's issuer: the expected ID-token `iss` and the client-secret `aud` of the Apple preset.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Google's canonical issuer (the preset also accepts the scheme-less `accounts.google.com`).
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// Microsoft identity platform v2.0 issuer template; `{tenantid}` is the token's `tid`.
pub const MICROSOFT_ISSUER_TEMPLATE: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";

/// Placeholder substituted by the token's `tid` in a [`IssuerRule::MicrosoftTemplate`].
pub const TENANT_PLACEHOLDER: &str = "{tenantid}";

/// Lifetime of an Apple client-secret JWT (seconds). Apple allows up to six months; AnvilID mints
/// one per code exchange.
pub const APPLE_CLIENT_SECRET_TTL_SECS: i64 = 300;

const GOOGLE_AUTHORIZATION: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GOOGLE_JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";

const MICROSOFT_LOGIN: &str = "https://login.microsoftonline.com";
const MICROSOFT_USERINFO: &str = "https://graph.microsoft.com/oidc/userinfo";

const APPLE_AUTHORIZATION: &str = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN: &str = "https://appleid.apple.com/auth/token";
const APPLE_JWKS: &str = "https://appleid.apple.com/auth/keys";

const GITHUB_AUTHORIZATION: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
/// Default GitHub REST API base.
pub const GITHUB_API_BASE: &str = "https://api.github.com";

/// ID-token algorithms AnvilID can verify. HMAC and `none` do not exist in [`Alg`].
pub const SUPPORTED_ID_TOKEN_ALGS: &[Alg] = &[Alg::RS256, Alg::PS256, Alg::ES256, Alg::Ed25519];

/// Upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// OpenID Connect: an ID token is validated with [`super::claims::validate_id_token`].
    Oidc,
    /// Plain OAuth2: identity comes from a profile API.
    OAuth2,
}

/// How the ID-token `iss` is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerRule {
    /// `iss` must equal this string exactly.
    Exact(String),
    /// Google preset: `https://accounts.google.com` or `accounts.google.com`.
    Google,
    /// Microsoft multi-tenant: substitute the token's `tid` (a canonical UUID) for
    /// [`TENANT_PLACEHOLDER`], then compare exactly.
    MicrosoftTemplate(String),
}

/// How the upstream returns the authorization response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    /// `response_mode=form_post` (Apple, when `name` or `email` is requested).
    FormPost,
}

/// Everything needed to run one upstream login, derived from a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProvider {
    pub kind: ConnectionKind,
    pub protocol: Protocol,
    pub authorization_endpoint: Url,
    pub token_endpoint: String,
    /// OIDC UserInfo or the OAuth2 profile endpoint (GitHub: `{api}/user`).
    pub userinfo_endpoint: Option<String>,
    /// `None` for plain OAuth2.
    pub jwks_uri: Option<String>,
    /// `None` for plain OAuth2.
    pub issuer_rule: Option<IssuerRule>,
    /// Empty for plain OAuth2 (no ID token is ever accepted).
    pub allowed_algs: Vec<Alg>,
    pub scopes: Vec<String>,
    pub use_pkce: bool,
    pub response_mode: ResponseMode,
    pub token_auth: TokenEndpointAuth,
    /// The connection trusts upstream `email_verified` (always `false` for Microsoft).
    pub email_trusted: bool,
    pub api_profile: ApiProfile,
    /// GitHub REST API base (`None` for other kinds).
    pub api_base_url: Option<String>,
    /// Apple only: expected ID-token `iss` and client-secret `aud` (the `endpoints.issuer`
    /// override when set, else [`APPLE_ISSUER`]).
    pub apple_audience: Option<String>,
    /// Microsoft only: accepted `tid` values, lowercase (empty = any).
    pub allowed_tenants: Vec<String>,
    /// Google only: accepted `hd` values, lowercase (empty = any).
    pub hosted_domains: Vec<String>,
}

/// Resolve a connection into endpoints and validation rules. Generic OIDC requires `metadata`
/// (discovery) whose `issuer` equals the configured issuer.
pub fn resolve(
    conn: &Connection,
    metadata: Option<&ProviderMetadata>,
) -> Result<ResolvedProvider, CoreError> {
    match &conn.config {
        ConnectionConfig::Social(s) => resolve_social(s, conn.trust_email_verified),
        ConnectionConfig::Oidc(o) => {
            let md = metadata.ok_or_else(|| {
                CoreError::Internal("generic OIDC connection resolved without metadata".into())
            })?;
            if md.issuer != o.issuer {
                return Err(invalid(
                    "issuer",
                    "discovery issuer does not match the configured issuer",
                ));
            }
            let allowed_algs = alg_intersection(&md.id_token_signing_alg_values_supported)?;
            Ok(ResolvedProvider {
                kind: ConnectionKind::Oidc,
                protocol: Protocol::Oidc,
                authorization_endpoint: parse_url(
                    "authorization_endpoint",
                    &md.authorization_endpoint,
                )?,
                token_endpoint: checked("token_endpoint", &md.token_endpoint)?,
                userinfo_endpoint: md
                    .userinfo_endpoint
                    .as_deref()
                    .map(|u| checked("userinfo_endpoint", u))
                    .transpose()?,
                jwks_uri: Some(checked("jwks_uri", &md.jwks_uri)?),
                issuer_rule: Some(IssuerRule::Exact(o.issuer.clone())),
                allowed_algs,
                scopes: with_openid(scopes_or(&o.scopes, &["openid", "email", "profile"])),
                use_pkce: o.use_pkce,
                response_mode: ResponseMode::Query,
                token_auth: TokenEndpointAuth::Basic,
                email_trusted: conn.trust_email_verified,
                api_profile: ApiProfile::Standard,
                api_base_url: None,
                apple_audience: None,
                allowed_tenants: vec![],
                hosted_domains: vec![],
            })
        }
        ConnectionConfig::Oauth2(o) => Ok(ResolvedProvider {
            kind: ConnectionKind::Oauth2,
            protocol: Protocol::OAuth2,
            authorization_endpoint: parse_url("authorization_endpoint", &o.authorization_endpoint)?,
            token_endpoint: checked("token_endpoint", &o.token_endpoint)?,
            userinfo_endpoint: Some(checked("userinfo_endpoint", &o.userinfo_endpoint)?),
            jwks_uri: None,
            issuer_rule: None,
            allowed_algs: vec![],
            scopes: o.scopes.clone(),
            use_pkce: o.use_pkce,
            response_mode: ResponseMode::Query,
            token_auth: TokenEndpointAuth::Basic,
            email_trusted: conn.trust_email_verified,
            api_profile: ApiProfile::Standard,
            api_base_url: None,
            apple_audience: None,
            allowed_tenants: vec![],
            hosted_domains: vec![],
        }),
    }
}

/// Built-in endpoints of a social preset before overrides.
struct PresetEndpoints {
    authorization: String,
    token: String,
    userinfo: Option<String>,
    jwks: Option<String>,
}

fn resolve_social(s: &SocialConfig, trust: bool) -> Result<ResolvedProvider, CoreError> {
    let o = &s.endpoints;
    let kind = s.provider.kind();
    let (preset, default_rule, default_scopes): (PresetEndpoints, Option<IssuerRule>, &[&str]) =
        match s.provider {
            SocialProvider::Google => (
                PresetEndpoints {
                    authorization: GOOGLE_AUTHORIZATION.into(),
                    token: GOOGLE_TOKEN.into(),
                    userinfo: Some(GOOGLE_USERINFO.into()),
                    jwks: Some(GOOGLE_JWKS.into()),
                },
                Some(IssuerRule::Google),
                &["openid", "email", "profile"],
            ),
            SocialProvider::Microsoft => {
                let tenant = microsoft_tenant(s.microsoft_tenant.as_deref())?;
                let rule = match tenant.as_str() {
                    "common" | "organizations" | "consumers" => {
                        IssuerRule::MicrosoftTemplate(MICROSOFT_ISSUER_TEMPLATE.into())
                    }
                    uuid => IssuerRule::Exact(
                        MICROSOFT_ISSUER_TEMPLATE.replace(TENANT_PLACEHOLDER, uuid),
                    ),
                };
                (
                    PresetEndpoints {
                        authorization: format!("{MICROSOFT_LOGIN}/{tenant}/oauth2/v2.0/authorize"),
                        token: format!("{MICROSOFT_LOGIN}/{tenant}/oauth2/v2.0/token"),
                        userinfo: Some(MICROSOFT_USERINFO.into()),
                        jwks: Some(format!("{MICROSOFT_LOGIN}/{tenant}/discovery/v2.0/keys")),
                    },
                    Some(rule),
                    &["openid", "email", "profile"],
                )
            }
            SocialProvider::Apple => {
                if s.apple.is_none() {
                    return Err(invalid(
                        "apple",
                        "Apple connections need team_id and key_id",
                    ));
                }
                (
                    PresetEndpoints {
                        authorization: APPLE_AUTHORIZATION.into(),
                        token: APPLE_TOKEN.into(),
                        userinfo: None,
                        jwks: Some(APPLE_JWKS.into()),
                    },
                    Some(IssuerRule::Exact(APPLE_ISSUER.into())),
                    &["name", "email"],
                )
            }
            SocialProvider::Github => {
                let api = o
                    .api_base_url
                    .as_deref()
                    .map(|b| checked("api_base_url", b.trim_end_matches('/')))
                    .transpose()?
                    .unwrap_or_else(|| GITHUB_API_BASE.into());
                (
                    PresetEndpoints {
                        authorization: GITHUB_AUTHORIZATION.into(),
                        token: GITHUB_TOKEN.into(),
                        userinfo: Some(format!("{api}/user")),
                        jwks: None,
                    },
                    None,
                    &["read:user", "user:email"],
                )
            }
        };

    let protocol = if default_rule.is_some() {
        Protocol::Oidc
    } else {
        Protocol::OAuth2
    };
    let issuer_override = o
        .issuer
        .as_deref()
        .map(|i| checked("issuer", i))
        .transpose()?;
    let issuer_rule = match (default_rule, issuer_override.clone()) {
        (None, _) => None,
        (Some(rule), None) => Some(rule),
        (Some(_), Some(i))
            if kind == ConnectionKind::Microsoft && i.contains(TENANT_PLACEHOLDER) =>
        {
            Some(IssuerRule::MicrosoftTemplate(i))
        }
        (Some(_), Some(i)) => Some(IssuerRule::Exact(i)),
    };
    let scopes = scopes_or(&s.scopes, default_scopes);
    let apple = s.provider == SocialProvider::Apple;
    let response_mode = if apple && scopes.iter().any(|sc| sc == "name" || sc == "email") {
        ResponseMode::FormPost
    } else {
        ResponseMode::Query
    };
    let jwks_uri = match protocol {
        Protocol::Oidc => override_or("jwks_uri", o.jwks_uri.as_deref(), preset.jwks)?,
        Protocol::OAuth2 => None,
    };

    Ok(ResolvedProvider {
        kind,
        protocol,
        authorization_endpoint: parse_url(
            "authorization_endpoint",
            o.authorization_endpoint
                .as_deref()
                .unwrap_or(&preset.authorization),
        )?,
        token_endpoint: checked(
            "token_endpoint",
            o.token_endpoint.as_deref().unwrap_or(&preset.token),
        )?,
        userinfo_endpoint: override_or(
            "userinfo_endpoint",
            o.userinfo_endpoint.as_deref(),
            preset.userinfo,
        )?,
        jwks_uri,
        issuer_rule,
        allowed_algs: match protocol {
            Protocol::Oidc => vec![Alg::RS256],
            Protocol::OAuth2 => vec![],
        },
        scopes,
        use_pkce: !apple,
        response_mode,
        token_auth: match s.provider {
            SocialProvider::Apple | SocialProvider::Github => TokenEndpointAuth::Post,
            SocialProvider::Google | SocialProvider::Microsoft => TokenEndpointAuth::Basic,
        },
        email_trusted: trust && kind != ConnectionKind::Microsoft,
        api_profile: if s.provider == SocialProvider::Github {
            ApiProfile::Github
        } else {
            ApiProfile::Standard
        },
        api_base_url: (s.provider == SocialProvider::Github)
            .then(|| preset_api_base(o.api_base_url.as_deref())),
        apple_audience: apple.then(|| issuer_override.unwrap_or_else(|| APPLE_ISSUER.into())),
        allowed_tenants: if kind == ConnectionKind::Microsoft {
            lowercase(&s.allowed_tenants)
        } else {
            vec![]
        },
        hosted_domains: if kind == ConnectionKind::Google {
            lowercase(&s.hosted_domains)
        } else {
            vec![]
        },
    })
}

fn preset_api_base(over: Option<&str>) -> String {
    over.map_or_else(
        || GITHUB_API_BASE.into(),
        |b| b.trim_end_matches('/').to_owned(),
    )
}

/// `common` (default), `organizations`, `consumers` or a canonical tenant UUID.
fn microsoft_tenant(t: Option<&str>) -> Result<String, CoreError> {
    let t = t.unwrap_or("common");
    if matches!(t, "common" | "organizations" | "consumers") {
        return Ok(t.into());
    }
    match uuid::Uuid::try_parse(t) {
        Ok(u) if u.hyphenated().to_string() == t.to_ascii_lowercase() => {
            Ok(u.hyphenated().to_string())
        }
        _ => Err(invalid(
            "microsoft_tenant",
            "must be common, organizations, consumers or a tenant UUID",
        )),
    }
}

fn lowercase(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.trim().to_ascii_lowercase()).collect()
}

fn scopes_or(configured: &[String], defaults: &[&str]) -> Vec<String> {
    if configured.is_empty() {
        defaults.iter().map(|s| (*s).to_owned()).collect()
    } else {
        configured.to_vec()
    }
}

fn with_openid(mut scopes: Vec<String>) -> Vec<String> {
    if !scopes.iter().any(|s| s == "openid") {
        scopes.insert(0, "openid".into());
    }
    scopes
}

/// metadata algorithms ∩ [`SUPPORTED_ID_TOKEN_ALGS`], in metadata order.
fn alg_intersection(advertised: &[String]) -> Result<Vec<Alg>, CoreError> {
    let mut algs: Vec<Alg> = Vec::new();
    for a in advertised {
        if let Ok(alg) = a.parse::<Alg>()
            && SUPPORTED_ID_TOKEN_ALGS.contains(&alg)
            && !algs.contains(&alg)
        {
            algs.push(alg);
        }
    }
    if algs.is_empty() {
        return Err(invalid(
            "id_token_signing_alg_values_supported",
            "the provider advertises no supported ID-token algorithm (RS256, PS256, ES256, Ed25519)",
        ));
    }
    Ok(algs)
}

fn invalid(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// An absolute http(s) URL.
fn parse_url(field: &'static str, s: &str) -> Result<Url, CoreError> {
    let url = Url::parse(s).map_err(|_| invalid(field, "must be an absolute URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(invalid(field, "must be an http(s) URL"));
    }
    Ok(url)
}

fn checked(field: &'static str, s: &str) -> Result<String, CoreError> {
    parse_url(field, s).map(|_| s.to_owned())
}

fn override_or(
    field: &'static str,
    over: Option<&str>,
    preset: Option<String>,
) -> Result<Option<String>, CoreError> {
    match over {
        Some(o) => checked(field, o).map(Some),
        None => Ok(preset),
    }
}

/// Claims of an Apple client-secret JWT (`iss` = team id, `sub` = services id, `aud` =
/// `audience`, `iat` = now, `exp` = now + [`APPLE_CLIENT_SECRET_TTL_SECS`]). Callers pass
/// [`ResolvedProvider::apple_audience`] and sign the result as ES256 with the team's key.
pub fn apple_client_secret_claims(
    team_id: &str,
    services_id: &str,
    audience: &str,
    now: OffsetDateTime,
) -> Map<String, Value> {
    let iat = now.unix_timestamp();
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::from(team_id));
    claims.insert("sub".into(), Value::from(services_id));
    claims.insert("aud".into(), Value::from(audience));
    claims.insert("iat".into(), Value::from(iat));
    claims.insert(
        "exp".into(),
        Value::from(iat + APPLE_CLIENT_SECRET_TTL_SECS),
    );
    claims
}

/// The upstream authorization URL (RFC 6749 §4.1.1 query encoding). `response_mode=form_post`
/// is added only when the resolved provider requires it (Apple).
pub fn authorization_url(
    resolved: &ResolvedProvider,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: Option<&str>,
    code_challenge: Option<&str>,
    login_hint: Option<&str>,
) -> Url {
    let mut url = resolved.authorization_endpoint.clone();
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &resolved.scopes.join(" "));
        q.append_pair("state", state);
        if let Some(n) = nonce {
            q.append_pair("nonce", n);
        }
        if let Some(c) = code_challenge {
            q.append_pair("code_challenge", c);
            q.append_pair("code_challenge_method", "S256");
        }
        if let Some(h) = login_hint {
            q.append_pair("login_hint", h);
        }
        if resolved.response_mode == ResponseMode::FormPost {
            q.append_pair("response_mode", "form_post");
        }
    }
    url
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AppleConfig, ClaimMapping, ConnectionId, EndpointOverrides, OAuth2Config, OidcConfig,
        TenantId,
    };

    fn conn(config: ConnectionConfig, trust: bool) -> Connection {
        let now = OffsetDateTime::UNIX_EPOCH;
        Connection {
            id: ConnectionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            slug: "c".into(),
            display_name: "C".into(),
            enabled: true,
            config,
            secret_enc: None,
            trust_email_verified: trust,
            created_at: now,
            updated_at: now,
        }
    }

    pub(crate) fn social(provider: SocialProvider) -> SocialConfig {
        SocialConfig {
            provider,
            client_id: "client-1".into(),
            scopes: vec![],
            endpoints: EndpointOverrides::default(),
            microsoft_tenant: None,
            allowed_tenants: vec![],
            hosted_domains: vec![],
            apple: (provider == SocialProvider::Apple).then(|| AppleConfig {
                team_id: "TEAM123456".into(),
                key_id: "KEY1234567".into(),
            }),
        }
    }

    fn resolved_social(s: SocialConfig) -> ResolvedProvider {
        let trust = s.provider.kind().default_email_trust();
        resolve(&conn(ConnectionConfig::Social(s), trust), None).unwrap()
    }

    fn oidc_config(issuer: &str) -> OidcConfig {
        OidcConfig {
            issuer: issuer.into(),
            client_id: "c".into(),
            scopes: vec![],
            use_pkce: true,
            fetch_userinfo: false,
        }
    }

    fn metadata(issuer: &str, algs: &[&str]) -> ProviderMetadata {
        ProviderMetadata {
            issuer: issuer.into(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            userinfo_endpoint: Some(format!("{issuer}/userinfo")),
            jwks_uri: format!("{issuer}/jwks"),
            id_token_signing_alg_values_supported: algs.iter().map(|a| (*a).into()).collect(),
            authorization_response_iss_parameter_supported: false,
            code_challenge_methods_supported: vec!["S256".into()],
        }
    }

    #[test]
    fn google_preset() {
        let r = resolved_social(social(SocialProvider::Google));
        assert_eq!(r.kind, ConnectionKind::Google);
        assert_eq!(r.protocol, Protocol::Oidc);
        assert_eq!(r.issuer_rule, Some(IssuerRule::Google));
        assert_eq!(r.scopes, ["openid", "email", "profile"]);
        assert!(r.use_pkce);
        assert_eq!(r.response_mode, ResponseMode::Query);
        assert_eq!(r.token_auth, TokenEndpointAuth::Basic);
        assert!(r.email_trusted);
        assert_eq!(r.apple_audience, None);
        assert_eq!(r.authorization_endpoint.as_str(), GOOGLE_AUTHORIZATION);
        assert_eq!(r.token_endpoint, GOOGLE_TOKEN);
        assert_eq!(r.jwks_uri.as_deref(), Some(GOOGLE_JWKS));
        assert_eq!(r.allowed_algs, [Alg::RS256]);
        assert_eq!(r.api_profile, ApiProfile::Standard);
    }

    #[test]
    fn google_hosted_domains_lowercased() {
        let mut s = social(SocialProvider::Google);
        s.hosted_domains = vec!["Example.COM".into()];
        assert_eq!(resolved_social(s).hosted_domains, ["example.com"]);
    }

    #[test]
    fn microsoft_common_uses_template_and_never_trusts_email() {
        let s = social(SocialProvider::Microsoft);
        let r = resolve(&conn(ConnectionConfig::Social(s), true), None).unwrap();
        assert_eq!(
            r.issuer_rule,
            Some(IssuerRule::MicrosoftTemplate(
                MICROSOFT_ISSUER_TEMPLATE.into()
            ))
        );
        assert!(!r.email_trusted, "Microsoft email is never trusted");
        assert!(r.use_pkce);
        assert!(
            r.authorization_endpoint
                .as_str()
                .starts_with("https://login.microsoftonline.com/common/")
        );
        assert_eq!(
            r.jwks_uri.as_deref(),
            Some("https://login.microsoftonline.com/common/discovery/v2.0/keys")
        );
    }

    #[test]
    fn microsoft_single_tenant_is_exact_and_allowed_tenants_kept() {
        let mut s = social(SocialProvider::Microsoft);
        let tid = "72f988bf-86f1-41af-91ab-2d7cd011db47";
        s.microsoft_tenant = Some(tid.into());
        s.allowed_tenants = vec![tid.to_uppercase()];
        let r = resolved_social(s);
        assert_eq!(
            r.issuer_rule,
            Some(IssuerRule::Exact(format!(
                "https://login.microsoftonline.com/{tid}/v2.0"
            )))
        );
        assert_eq!(r.allowed_tenants, [tid]);
    }

    #[test]
    fn microsoft_bad_tenant_segment_rejected() {
        let mut s = social(SocialProvider::Microsoft);
        s.microsoft_tenant = Some("evil/../x".into());
        assert!(resolve(&conn(ConnectionConfig::Social(s), false), None).is_err());
    }

    #[test]
    fn apple_preset() {
        let r = resolved_social(social(SocialProvider::Apple));
        assert_eq!(r.issuer_rule, Some(IssuerRule::Exact(APPLE_ISSUER.into())));
        assert_eq!(r.apple_audience.as_deref(), Some(APPLE_ISSUER));
        assert!(!r.use_pkce, "Apple does not support PKCE");
        assert_eq!(r.token_auth, TokenEndpointAuth::Post);
        assert_eq!(r.response_mode, ResponseMode::FormPost);
        assert_eq!(r.authorization_endpoint.as_str(), APPLE_AUTHORIZATION);
        assert_eq!(r.token_endpoint, APPLE_TOKEN);
        assert_eq!(r.jwks_uri.as_deref(), Some(APPLE_JWKS));
        assert_eq!(r.userinfo_endpoint, None);
        assert_eq!(r.allowed_algs, [Alg::RS256]);
    }

    #[test]
    fn apple_without_name_or_email_scope_uses_query() {
        let mut s = social(SocialProvider::Apple);
        s.scopes = vec!["openid".into()];
        assert_eq!(resolved_social(s).response_mode, ResponseMode::Query);
    }

    #[test]
    fn apple_requires_team_config() {
        let mut s = social(SocialProvider::Apple);
        s.apple = None;
        assert!(resolve(&conn(ConnectionConfig::Social(s), true), None).is_err());
    }

    #[test]
    fn apple_issuer_override_is_audience_and_issuer() {
        let mut s = social(SocialProvider::Apple);
        s.endpoints.issuer = Some("http://127.0.0.1:9000/apple".into());
        let r = resolved_social(s);
        assert_eq!(
            r.apple_audience.as_deref(),
            Some("http://127.0.0.1:9000/apple")
        );
        assert_eq!(
            r.issuer_rule,
            Some(IssuerRule::Exact("http://127.0.0.1:9000/apple".into()))
        );
    }

    #[test]
    fn github_preset_and_api_override() {
        let r = resolved_social(social(SocialProvider::Github));
        assert_eq!(r.protocol, Protocol::OAuth2);
        assert_eq!(r.scopes, ["read:user", "user:email"]);
        assert!(r.use_pkce);
        assert_eq!(r.api_base_url.as_deref(), Some(GITHUB_API_BASE));
        assert_eq!(
            r.userinfo_endpoint.as_deref(),
            Some("https://api.github.com/user")
        );
        assert_eq!(r.api_profile, ApiProfile::Github);
        assert!(r.allowed_algs.is_empty());
        assert_eq!(r.issuer_rule, None);
        assert_eq!(r.jwks_uri, None);
        assert_eq!(r.authorization_endpoint.as_str(), GITHUB_AUTHORIZATION);
        assert_eq!(r.token_endpoint, GITHUB_TOKEN);

        let mut s = social(SocialProvider::Github);
        s.endpoints.api_base_url = Some("http://127.0.0.1:9000/gh/".into());
        let r = resolved_social(s);
        assert_eq!(r.api_base_url.as_deref(), Some("http://127.0.0.1:9000/gh"));
        assert_eq!(
            r.userinfo_endpoint.as_deref(),
            Some("http://127.0.0.1:9000/gh/user")
        );
    }

    #[test]
    fn every_endpoint_override_wins() {
        for p in SocialProvider::ALL {
            let mut s = social(*p);
            s.endpoints = EndpointOverrides {
                issuer: Some("http://127.0.0.1:9000".into()),
                authorization_endpoint: Some("http://127.0.0.1:9000/a".into()),
                token_endpoint: Some("http://127.0.0.1:9000/t".into()),
                userinfo_endpoint: Some("http://127.0.0.1:9000/u".into()),
                jwks_uri: Some("http://127.0.0.1:9000/k".into()),
                api_base_url: None,
            };
            let r = resolved_social(s);
            assert_eq!(r.authorization_endpoint.as_str(), "http://127.0.0.1:9000/a");
            assert_eq!(r.token_endpoint, "http://127.0.0.1:9000/t");
            assert_eq!(
                r.userinfo_endpoint.as_deref(),
                Some("http://127.0.0.1:9000/u")
            );
            if r.protocol == Protocol::Oidc {
                assert_eq!(r.jwks_uri.as_deref(), Some("http://127.0.0.1:9000/k"));
                assert_eq!(
                    r.issuer_rule,
                    Some(IssuerRule::Exact("http://127.0.0.1:9000".into())),
                    "{p:?}: an issuer override replaces the preset rule"
                );
            }
        }
    }

    #[test]
    fn microsoft_template_override_kept_as_template() {
        let mut s = social(SocialProvider::Microsoft);
        s.endpoints.issuer = Some("http://127.0.0.1:9000/{tenantid}/v2.0".into());
        assert_eq!(
            resolved_social(s).issuer_rule,
            Some(IssuerRule::MicrosoftTemplate(
                "http://127.0.0.1:9000/{tenantid}/v2.0".into()
            ))
        );
    }

    #[test]
    fn invalid_override_url_rejected() {
        let mut s = social(SocialProvider::Google);
        s.endpoints.authorization_endpoint = Some("not a url".into());
        assert!(resolve(&conn(ConnectionConfig::Social(s), true), None).is_err());
        let mut s = social(SocialProvider::Google);
        s.endpoints.token_endpoint = Some("ftp://x/token".into());
        assert!(resolve(&conn(ConnectionConfig::Social(s), true), None).is_err());
    }

    #[test]
    fn custom_scopes_win() {
        let mut s = social(SocialProvider::Google);
        s.scopes = vec!["openid".into(), "email".into()];
        assert_eq!(resolved_social(s).scopes, ["openid", "email"]);
    }

    #[test]
    fn oidc_requires_metadata_with_matching_issuer() {
        let c = conn(
            ConnectionConfig::Oidc(oidc_config("https://idp.example")),
            false,
        );
        assert!(resolve(&c, None).is_err(), "metadata required");
        let wrong = metadata("https://evil.example", &["RS256"]);
        assert!(resolve(&c, Some(&wrong)).is_err(), "issuer mismatch");
        let r = resolve(&c, Some(&metadata("https://idp.example", &["RS256"]))).unwrap();
        assert_eq!(r.protocol, Protocol::Oidc);
        assert_eq!(
            r.issuer_rule,
            Some(IssuerRule::Exact("https://idp.example".into()))
        );
        assert_eq!(r.jwks_uri.as_deref(), Some("https://idp.example/jwks"));
        assert_eq!(r.token_endpoint, "https://idp.example/token");
        assert_eq!(
            r.userinfo_endpoint.as_deref(),
            Some("https://idp.example/userinfo")
        );
        assert_eq!(r.scopes, ["openid", "email", "profile"]);
        assert!(r.use_pkce);
        assert!(!r.email_trusted);
    }

    #[test]
    fn oidc_alg_intersection() {
        let c = conn(
            ConnectionConfig::Oidc(oidc_config("https://idp.example")),
            true,
        );
        let r = resolve(
            &c,
            Some(&metadata(
                "https://idp.example",
                &["HS256", "none", "EdDSA", "ES256", "RS256", "Ed25519"],
            )),
        )
        .unwrap();
        assert_eq!(r.allowed_algs, [Alg::ES256, Alg::RS256, Alg::Ed25519]);
        assert!(r.email_trusted);
        for algs in [&["HS256", "none"][..], &["EdDSA"][..], &[][..]] {
            assert!(
                resolve(&c, Some(&metadata("https://idp.example", algs))).is_err(),
                "{algs:?}: empty intersection must be rejected"
            );
        }
    }

    #[test]
    fn oidc_scopes_always_include_openid() {
        let mut o = oidc_config("https://idp.example");
        o.scopes = vec!["email".into()];
        o.use_pkce = false;
        let c = conn(ConnectionConfig::Oidc(o), false);
        let r = resolve(&c, Some(&metadata("https://idp.example", &["RS256"]))).unwrap();
        assert_eq!(r.scopes, ["openid", "email"]);
        assert!(!r.use_pkce);
    }

    #[test]
    fn oauth2_generic() {
        let c = conn(
            ConnectionConfig::Oauth2(OAuth2Config {
                authorization_endpoint: "https://a.example/auth".into(),
                token_endpoint: "https://a.example/token".into(),
                userinfo_endpoint: "https://a.example/me".into(),
                client_id: "c".into(),
                scopes: vec!["read".into()],
                use_pkce: false,
                mapping: ClaimMapping {
                    subject: "/id".into(),
                    email: None,
                    email_verified: None,
                    name: None,
                },
            }),
            false,
        );
        let r = resolve(&c, None).unwrap();
        assert_eq!(r.protocol, Protocol::OAuth2);
        assert_eq!(r.scopes, ["read"]);
        assert!(!r.use_pkce);
        assert!(r.allowed_algs.is_empty());
        assert_eq!(r.userinfo_endpoint.as_deref(), Some("https://a.example/me"));
        assert_eq!(r.issuer_rule, None);
    }

    #[test]
    fn apple_client_secret_production_audience() {
        let r = resolved_social(social(SocialProvider::Apple));
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let claims = apple_client_secret_claims(
            "TEAM123456",
            "com.example.web",
            r.apple_audience.as_deref().unwrap(),
            now,
        );
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], "com.example.web");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        assert_eq!(claims["iat"], 1_700_000_000_i64);
        assert_eq!(claims["exp"], 1_700_000_300_i64);
        let mut keys: Vec<&str> = claims.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["aud", "exp", "iat", "iss", "sub"]);
    }

    #[test]
    fn apple_client_secret_override_audience() {
        let mut s = social(SocialProvider::Apple);
        s.endpoints.issuer = Some("http://127.0.0.1:9000/apple".into());
        let r = resolved_social(s);
        let claims = apple_client_secret_claims(
            "T",
            "S",
            r.apple_audience.as_deref().unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(claims["aud"], "http://127.0.0.1:9000/apple");
        assert_eq!(claims.len(), 5);
    }

    fn query(url: &Url) -> Vec<(String, String)> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn authorization_url_google() {
        let r = resolved_social(social(SocialProvider::Google));
        let u = authorization_url(
            &r,
            "client-1",
            "https://id.example/t/default/connections/google/callback",
            "st&ate",
            Some("n0nce"),
            Some("chal"),
            Some("a@b.example"),
        );
        assert!(u.as_str().starts_with(GOOGLE_AUTHORIZATION));
        let q = query(&u);
        let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("response_type"), Some("code"));
        assert_eq!(get("client_id"), Some("client-1"));
        assert_eq!(
            get("redirect_uri"),
            Some("https://id.example/t/default/connections/google/callback")
        );
        assert_eq!(get("scope"), Some("openid email profile"));
        assert_eq!(get("state"), Some("st&ate"));
        assert_eq!(get("nonce"), Some("n0nce"));
        assert_eq!(get("code_challenge"), Some("chal"));
        assert_eq!(get("code_challenge_method"), Some("S256"));
        assert_eq!(get("login_hint"), Some("a@b.example"));
        assert_eq!(get("response_mode"), None);
        assert!(u.as_str().contains("st%26ate"), "query encoded");
    }

    #[test]
    fn authorization_url_apple_form_post_and_optional_params() {
        let r = resolved_social(social(SocialProvider::Apple));
        let u = authorization_url(&r, "svc", "https://cb.example/", "s", None, None, None);
        let q = query(&u);
        let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("response_mode"), Some("form_post"));
        assert_eq!(get("nonce"), None);
        assert_eq!(get("code_challenge"), None);
        assert_eq!(get("code_challenge_method"), None);
        assert_eq!(get("login_hint"), None);
    }

    #[test]
    fn authorization_url_keeps_existing_query() {
        let mut s = social(SocialProvider::Google);
        s.endpoints.authorization_endpoint = Some("https://idp.example/auth?prompt=x".into());
        let r = resolved_social(s);
        let u = authorization_url(&r, "c", "https://cb.example/", "s", None, None, None);
        let q = query(&u);
        assert_eq!(q[0], ("prompt".to_string(), "x".to_string()));
        assert!(q.iter().any(|(k, v)| k == "state" && v == "s"));
    }
}
