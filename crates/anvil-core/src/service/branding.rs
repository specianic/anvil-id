//! Branding administration, drafts and live preview (UI-03).
//!
//! A branding record exists per tenant ([`BrandingScope::Tenant`]) and per client
//! ([`BrandingScope::Client`]). It holds design tokens, optional custom CSS and an optional logo.
//! Everything an administrator submits is checked by [`crate::policy::branding`]: token syntax and
//! WCAG contrast (below 3:1 refused, below 4.5:1 returned as [`ThemeWarning`]s) and the custom
//! CSS allow-list (errors carry the 1-based line). Logos are identified by their magic bytes
//! (PNG, JPEG, WebP, at most 256 KiB; SVG is refused) and stored by SHA-256.
//!
//! Pages get one generated stylesheet ([`BrandingService::effective`]): the tokens merged client >
//! tenant > default as CSS variables, then a generated `.anvil-logo` rule (hidden without a logo,
//! otherwise a background image `url("logo/{sha256}")`, resolved relative to the stylesheet URL
//! `{tenant_base}/theme/theme.css`), then the tenant's and the client's custom CSS. The logo rule
//! is always generated here, never taken from custom CSS (which cannot contain `url(` anyway).
//!
//! Drafts back the console's live preview: [`BrandingService::put_draft`] stores a validated draft
//! reachable with a random 256-bit preview token (only its SHA-256 is stored) for
//! [`PREVIEW_TTL`]; [`BrandingService::publish`] copies a draft live. A draft has no logo of its
//! own: the preview shows the scope's live logo.
//!
//! Every live change records one `branding_updated` audit event in the tenant, target = `tenant`
//! or `client:{client_id}`, details = changed field names (`tokens`, `custom_css`) or a fixed
//! reason (`logo_set`, `logo_cleared`, `deleted`, `published`). Drafts change nothing live and
//! are not audited. Failed calls record nothing.
//!
//! Logos are content-addressed and may be shared by several scopes; replaced logos stay stored.
//! Removing unreferenced logo rows needs a storage intent that the port does not have yet.

use std::sync::Arc;

use anvil_jose::encoding::{random_token, secret_hash, sha256};
use time::{Duration, OffsetDateTime};

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, Branding, BrandingDraft, BrandingScope,
    BrandingUpdate, Logo, LogoChange, RequestContext, SecretHash, TenantId, ThemeTokens,
    truncate_to_ms,
};
use crate::policy::branding::{
    CssError, ThemeCss, ThemeError, ThemeWarning, merge_tokens, sniff_logo, theme_stylesheet,
    validate_custom_css, validate_tokens,
};
use crate::ports::Storage;
use crate::service::audit::AuditService;

/// Lifetime of a preview token.
pub const PREVIEW_TTL: Duration = Duration::minutes(15);

/// Tokens and custom CSS as submitted by an administrator (live or draft).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandingInput {
    pub tokens: ThemeTokens,
    /// `None` or blank = no custom CSS.
    pub custom_css: Option<String>,
}

/// A new preview draft: the token (shown once, part of the preview URL), its expiry and the
/// contrast warnings of the draft.
#[derive(Debug, Clone)]
pub struct PreviewToken {
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub warnings: Vec<ThemeWarning>,
}

/// The logo a page shows: lowercase hex SHA-256 and the stored content type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoRef {
    pub sha256: String,
    pub content_type: String,
}

/// The stylesheet of a page and the logo it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTheme {
    /// The complete stylesheet; `hash` is the lowercase hex SHA-256 of `css`.
    pub css: ThemeCss,
    pub logo: Option<LogoRef>,
}

/// Field names of every token, so validation errors can name the exact field.
const COLOR_FIELDS: [&str; 18] = [
    "colors.primary",
    "colors.primary_text",
    "colors.bg",
    "colors.surface",
    "colors.text",
    "colors.muted",
    "colors.border",
    "colors.focus",
    "colors.danger",
    "colors_dark.primary",
    "colors_dark.primary_text",
    "colors_dark.bg",
    "colors_dark.surface",
    "colors_dark.text",
    "colors_dark.muted",
    "colors_dark.border",
    "colors_dark.focus",
    "colors_dark.danger",
];

/// Maps a policy error to a validation error on the named field.
fn theme_error(e: &ThemeError) -> CoreError {
    let field: &'static str = match e {
        ThemeError::Color { field } => COLOR_FIELDS
            .iter()
            .copied()
            .find(|f| f == field)
            .unwrap_or("tokens"),
        ThemeError::Radius { .. } => "radius_px",
        ThemeError::FontFamily => "font_family",
        ThemeError::Contrast { scheme, .. } => match scheme {
            crate::policy::branding::ColorScheme::Light => "colors",
            crate::policy::branding::ColorScheme::Dark => "colors_dark",
        },
        ThemeError::Css(_) => "custom_css",
    };
    CoreError::Validation {
        field,
        message: e.to_string(),
    }
}

/// Custom CSS error: `line N: …` on `custom_css`.
fn css_error(e: &CssError) -> CoreError {
    CoreError::Validation {
        field: "custom_css",
        message: e.to_string(),
    }
}

/// Blank custom CSS is no custom CSS.
fn normalize_css(css: Option<String>) -> Option<String> {
    css.filter(|c| !c.trim().is_empty())
}

/// Validates tokens and custom CSS; returns the contrast warnings.
pub fn validate_input(input: &BrandingInput) -> Result<Vec<ThemeWarning>, CoreError> {
    let warnings = validate_tokens(&input.tokens).map_err(|e| theme_error(&e))?;
    if let Some(css) = input.custom_css.as_deref() {
        validate_custom_css(css).map_err(|e| css_error(&e))?;
    }
    Ok(warnings)
}

/// Whether `s` is a lowercase hex SHA-256 (64 characters).
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether `s` has the shape of a preview token (base64url, 43 characters).
fn is_preview_token(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

/// Tokens and custom CSS of one layer of the effective theme.
struct Layer<'a> {
    tokens: &'a ThemeTokens,
    custom_css: Option<&'a str>,
}

/// The generated rule of the logo element (`<span class="anvil-logo" role="img">`).
fn logo_rule(logo: Option<&LogoRef>) -> String {
    match logo {
        None => ".anvil-logo{display:none}\n".to_owned(),
        Some(l) => format!(
            ".anvil-logo{{display:block;inline-size:12rem;max-inline-size:100%;block-size:3rem;\
             margin-block-end:1rem;background-image:url(\"logo/{}\");background-repeat:no-repeat;\
             background-size:contain;background-position:left center}}\n\
             [dir=rtl] .anvil-logo{{background-position:right center}}\n",
            l.sha256
        ),
    }
}

/// Builds the page stylesheet: merged variables, the logo rule, then the custom CSS of each layer
/// (tenant first, so the client's rules win the cascade). Stored input is re-checked by the
/// policy functions; a stored record that no longer passes is an internal error.
fn compose(
    tenant: Option<Layer<'_>>,
    client: Option<Layer<'_>>,
    logo: Option<LogoRef>,
) -> Result<EffectiveTheme, CoreError> {
    let merged = merge_tokens(
        &ThemeTokens::default(),
        tenant.as_ref().map(|l| l.tokens),
        client.as_ref().map(|l| l.tokens),
    );
    let vars = theme_stylesheet(&merged, None)
        .map_err(|e| CoreError::Internal(format!("stored branding tokens are invalid: {e}")))?;
    let mut css = vars.css;
    css.push_str(&logo_rule(logo.as_ref()));
    for layer in [tenant.as_ref(), client.as_ref()].into_iter().flatten() {
        if let Some(custom) = layer.custom_css {
            validate_custom_css(custom)
                .map_err(|e| CoreError::Internal(format!("stored custom CSS is invalid: {e}")))?;
            css.push_str(custom);
            if !css.ends_with('\n') {
                css.push('\n');
            }
        }
    }
    let hash = hex(&sha256(css.as_bytes()));
    Ok(EffectiveTheme {
        css: ThemeCss { css, hash },
        logo,
    })
}

fn logo_of(b: &Branding) -> Option<LogoRef> {
    match (&b.logo_sha256, &b.logo_type) {
        (Some(sha), Some(ty)) if is_sha256_hex(sha) => Some(LogoRef {
            sha256: sha.clone(),
            content_type: ty.clone(),
        }),
        _ => None,
    }
}

/// The audit target of a scope: `tenant` or `client:{client_id}`.
fn target(scope: &BrandingScope) -> String {
    match scope {
        BrandingScope::Tenant => "tenant".to_owned(),
        BrandingScope::Client(_) => scope.scope_key(),
    }
}

/// Branding administration, preview drafts and the effective theme of pages.
#[derive(Clone)]
pub struct BrandingService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
}

impl BrandingService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    async fn record(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        actor: AuditActor,
        ctx: &RequestContext,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                tenant,
                actor,
                AuditAction::BrandingUpdated,
                Some(target(scope)),
                AuditOutcome::Success,
                ctx,
                details,
            )
            .await
    }

    /// A client scope must name an existing client of the tenant (`NotFound` otherwise).
    async fn check_scope(&self, tenant: TenantId, scope: &BrandingScope) -> Result<(), CoreError> {
        if let BrandingScope::Client(id) = scope {
            self.storage
                .clients()
                .get(tenant, id)
                .await?
                .ok_or(CoreError::NotFound)?;
        }
        Ok(())
    }

    /// The scope's live branding (`None` = not customised, inherits).
    pub async fn get(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
    ) -> Result<Option<Branding>, CoreError> {
        self.check_scope(tenant, scope).await?;
        Ok(self
            .storage
            .branding()
            .get(tenant, &scope.scope_key())
            .await?)
    }

    /// Validates and stores the scope's tokens and custom CSS (the logo is kept). Returns the
    /// stored record and the contrast warnings. Audited (`fields: tokens, custom_css`).
    pub async fn put(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        input: BrandingInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(Branding, Vec<ThemeWarning>), CoreError> {
        let input = BrandingInput {
            tokens: input.tokens,
            custom_css: normalize_css(input.custom_css),
        };
        let warnings = validate_input(&input)?;
        self.check_scope(tenant, scope).await?;
        let stored = self
            .storage
            .branding()
            .put(
                tenant,
                &scope.scope_key(),
                &BrandingUpdate {
                    tokens: input.tokens,
                    custom_css: input.custom_css,
                    logo: LogoChange::Keep,
                },
                truncate_to_ms(self.clock.now()),
            )
            .await?;
        self.record(
            tenant,
            scope,
            actor,
            ctx,
            AuditDetails::fields(&["tokens", "custom_css"]),
        )
        .await?;
        Ok((stored, warnings))
    }

    /// Sets the scope's logo from image bytes (PNG, JPEG or WebP by magic bytes, at most
    /// 256 KiB). A scope without branding gets a record with default tokens. Audited
    /// (`reason: logo_set`).
    pub async fn set_logo(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        bytes: Vec<u8>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Branding, CoreError> {
        let content_type = sniff_logo(&bytes).map_err(|e| CoreError::Validation {
            field: "logo",
            message: e.to_string(),
        })?;
        self.check_scope(tenant, scope).await?;
        let key = scope.scope_key();
        let current = self.storage.branding().get(tenant, &key).await?;
        let (tokens, custom_css) = current
            .map(|b| (b.tokens, b.custom_css))
            .unwrap_or_default();
        let logo = Logo {
            content_type: content_type.to_owned(),
            sha256: hex(&sha256(&bytes)),
            bytes,
        };
        let stored = self
            .storage
            .branding()
            .put(
                tenant,
                &key,
                &BrandingUpdate {
                    tokens,
                    custom_css,
                    logo: LogoChange::Set(logo),
                },
                truncate_to_ms(self.clock.now()),
            )
            .await?;
        self.record(tenant, scope, actor, ctx, AuditDetails::reason("logo_set"))
            .await?;
        Ok(stored)
    }

    /// Removes the scope's logo reference (`NotFound` when the scope has no logo). Audited
    /// (`reason: logo_cleared`).
    pub async fn clear_logo(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Branding, CoreError> {
        self.check_scope(tenant, scope).await?;
        let key = scope.scope_key();
        let current = self
            .storage
            .branding()
            .get(tenant, &key)
            .await?
            .filter(|b| b.logo_sha256.is_some())
            .ok_or(CoreError::NotFound)?;
        let stored = self
            .storage
            .branding()
            .put(
                tenant,
                &key,
                &BrandingUpdate {
                    tokens: current.tokens,
                    custom_css: current.custom_css,
                    logo: LogoChange::Clear,
                },
                truncate_to_ms(self.clock.now()),
            )
            .await?;
        self.record(
            tenant,
            scope,
            actor,
            ctx,
            AuditDetails::reason("logo_cleared"),
        )
        .await?;
        Ok(stored)
    }

    /// Removes the scope's branding (back to the inherited theme; `NotFound` when there is
    /// none). Audited (`reason: deleted`).
    pub async fn delete(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        self.check_scope(tenant, scope).await?;
        if !self
            .storage
            .branding()
            .delete(tenant, &scope.scope_key())
            .await?
        {
            return Err(CoreError::NotFound);
        }
        self.record(tenant, scope, actor, ctx, AuditDetails::reason("deleted"))
            .await
    }

    /// The effective theme of a page: the tenant's branding, overridden by the client's when
    /// `client_id` is given and that client has branding. The logo is the client's, else the
    /// tenant's.
    pub async fn effective(
        &self,
        tenant: TenantId,
        client_id: Option<&str>,
    ) -> Result<EffectiveTheme, CoreError> {
        let repo = self.storage.branding();
        let tenant_b = repo.get(tenant, &BrandingScope::Tenant.scope_key()).await?;
        let client_b = match client_id {
            Some(id) => {
                repo.get(tenant, &BrandingScope::Client(id.to_owned()).scope_key())
                    .await?
            }
            None => None,
        };
        let logo = client_b
            .as_ref()
            .and_then(logo_of)
            .or_else(|| tenant_b.as_ref().and_then(logo_of));
        compose(
            tenant_b.as_ref().map(|b| Layer {
                tokens: &b.tokens,
                custom_css: b.custom_css.as_deref(),
            }),
            client_b.as_ref().map(|b| Layer {
                tokens: &b.tokens,
                custom_css: b.custom_css.as_deref(),
            }),
            logo,
        )
    }

    /// A stored logo of the tenant by lowercase hex SHA-256 (`None` for another tenant's logo
    /// or a malformed hash).
    pub async fn logo(&self, tenant: TenantId, sha: &str) -> Result<Option<Logo>, CoreError> {
        if !is_sha256_hex(sha) {
            return Ok(None);
        }
        Ok(self.storage.branding().logo(tenant, sha).await?)
    }

    /// Validates and stores a preview draft of the scope (replacing its previous draft) and
    /// returns a new preview token valid for [`PREVIEW_TTL`].
    pub async fn put_draft(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        input: BrandingInput,
    ) -> Result<PreviewToken, CoreError> {
        let input = BrandingInput {
            tokens: input.tokens,
            custom_css: normalize_css(input.custom_css),
        };
        let warnings = validate_input(&input)?;
        self.check_scope(tenant, scope).await?;
        let now = truncate_to_ms(self.clock.now());
        let token = random_token();
        let expires_at = now + PREVIEW_TTL;
        self.storage
            .branding()
            .put_draft(
                tenant,
                &scope.scope_key(),
                &BrandingDraft {
                    tokens: input.tokens,
                    custom_css: input.custom_css,
                    preview_token_hash: SecretHash(secret_hash(&token)),
                    preview_expires_at: expires_at,
                },
                now,
            )
            .await?;
        Ok(PreviewToken {
            token,
            expires_at,
            warnings,
        })
    }

    /// The unexpired draft of this tenant with this preview token, with its scope.
    async fn draft(
        &self,
        tenant: TenantId,
        token: &str,
    ) -> Result<Option<(BrandingScope, BrandingDraft)>, CoreError> {
        if !is_preview_token(token) {
            return Ok(None);
        }
        let found = self
            .storage
            .branding()
            .draft_by_preview(tenant, &SecretHash(secret_hash(token)), self.clock.now())
            .await?;
        Ok(found.and_then(|(key, draft)| BrandingScope::from_key(&key).map(|s| (s, draft))))
    }

    /// The theme a preview token shows: the draft in place of its scope's live branding (a
    /// client draft on top of the live tenant branding), with the scope's live logo. `None` for
    /// an unknown, expired or other-tenant token.
    pub async fn draft_for_preview(
        &self,
        tenant: TenantId,
        token: &str,
    ) -> Result<Option<EffectiveTheme>, CoreError> {
        let Some((scope, draft)) = self.draft(tenant, token).await? else {
            return Ok(None);
        };
        let repo = self.storage.branding();
        let tenant_b = repo.get(tenant, &BrandingScope::Tenant.scope_key()).await?;
        let draft_layer = Layer {
            tokens: &draft.tokens,
            custom_css: draft.custom_css.as_deref(),
        };
        let theme = match &scope {
            BrandingScope::Tenant => {
                compose(Some(draft_layer), None, tenant_b.as_ref().and_then(logo_of))?
            }
            BrandingScope::Client(_) => {
                let client_b = repo.get(tenant, &scope.scope_key()).await?;
                let logo = client_b
                    .as_ref()
                    .and_then(logo_of)
                    .or_else(|| tenant_b.as_ref().and_then(logo_of));
                compose(
                    tenant_b.as_ref().map(|b| Layer {
                        tokens: &b.tokens,
                        custom_css: b.custom_css.as_deref(),
                    }),
                    Some(draft_layer),
                    logo,
                )?
            }
        };
        Ok(Some(theme))
    }

    /// Copies the draft behind `token` live (tokens and custom CSS; the logo is kept). The draft
    /// must belong to `scope` (`NotFound` otherwise, also for an expired token). Audited
    /// (`reason: published`).
    pub async fn publish(
        &self,
        tenant: TenantId,
        scope: &BrandingScope,
        token: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(Branding, Vec<ThemeWarning>), CoreError> {
        self.check_scope(tenant, scope).await?;
        let (draft_scope, draft) = self
            .draft(tenant, token)
            .await?
            .ok_or(CoreError::NotFound)?;
        if &draft_scope != scope {
            return Err(CoreError::NotFound);
        }
        let input = BrandingInput {
            tokens: draft.tokens,
            custom_css: draft.custom_css,
        };
        // Re-checked: the policy may have changed since the draft was stored.
        let warnings = validate_input(&input)?;
        let stored = self
            .storage
            .branding()
            .put(
                tenant,
                &scope.scope_key(),
                &BrandingUpdate {
                    tokens: input.tokens,
                    custom_css: input.custom_css,
                    logo: LogoChange::Keep,
                },
                truncate_to_ms(self.clock.now()),
            )
            .await?;
        self.record(tenant, scope, actor, ctx, AuditDetails::reason("published"))
            .await?;
        Ok((stored, warnings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ThemeColors;

    fn colors(primary: &str) -> ThemeTokens {
        ThemeTokens {
            colors: ThemeColors {
                primary: Some(primary.into()),
                ..ThemeColors::default()
            },
            ..ThemeTokens::default()
        }
    }

    #[test]
    fn unbranded_theme_hides_the_logo() {
        let t = compose(None, None, None).unwrap();
        assert_eq!(t.css.css, ".anvil-logo{display:none}\n");
        assert_eq!(t.css.hash, hex(&sha256(t.css.css.as_bytes())));
        assert!(t.logo.is_none());
    }

    #[test]
    fn client_layer_wins_and_custom_css_follows_the_logo_rule() {
        let tenant = colors("#112233");
        let client = colors("#445566");
        let logo = LogoRef {
            sha256: "a".repeat(64),
            content_type: "image/png".into(),
        };
        let t = compose(
            Some(Layer {
                tokens: &tenant,
                custom_css: Some(".a{color:red}"),
            }),
            Some(Layer {
                tokens: &client,
                custom_css: Some(".b{color:blue}"),
            }),
            Some(logo),
        )
        .unwrap();
        let css = &t.css.css;
        assert!(css.contains("--anvil-primary:#445566"), "{css}");
        assert!(!css.contains("#112233"), "{css}");
        let logo_at = css.find(".anvil-logo{display:block").expect("logo rule");
        let a = css.find(".a{color:red}").expect("tenant css");
        let b = css.find(".b{color:blue}").expect("client css");
        assert!(logo_at < a && a < b, "{css}");
        assert!(css.contains(&format!("url(\"logo/{}\")", "a".repeat(64))));
    }

    #[test]
    fn validation_errors_name_the_field() {
        let bad = BrandingInput {
            tokens: ThemeTokens {
                colors_dark: Some(ThemeColors {
                    bg: Some("red".into()),
                    ..ThemeColors::default()
                }),
                ..ThemeTokens::default()
            },
            custom_css: None,
        };
        match validate_input(&bad) {
            Err(CoreError::Validation { field, .. }) => assert_eq!(field, "colors_dark.bg"),
            other => panic!("{other:?}"),
        }
        let css = BrandingInput {
            tokens: ThemeTokens::default(),
            custom_css: Some(".a{}\n@import \"x.css\";".into()),
        };
        match validate_input(&css) {
            Err(CoreError::Validation { field, message }) => {
                assert_eq!(field, "custom_css");
                assert!(message.starts_with("line 2:"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        let radius = BrandingInput {
            tokens: ThemeTokens {
                radius_px: Some(40),
                ..ThemeTokens::default()
            },
            custom_css: None,
        };
        assert!(matches!(
            validate_input(&radius),
            Err(CoreError::Validation {
                field: "radius_px",
                ..
            })
        ));
    }

    #[test]
    fn shapes() {
        assert!(is_sha256_hex(&"0f".repeat(32)));
        assert!(!is_sha256_hex(&"0F".repeat(32)));
        assert!(!is_sha256_hex("../etc"));
        assert!(is_preview_token(&random_token()));
        assert!(!is_preview_token("short"));
        assert_eq!(normalize_css(Some("  \n".into())), None);
    }
}
