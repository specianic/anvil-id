//! BrandingRepo contract: tenant and client theming, logos and preview drafts.

use anvil_core::model::{BrandingScope, LogoChange};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

pub async fn branding_put_get_scopes(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.branding();
    let tenant_key = BrandingScope::Tenant.scope_key();
    let client_key = BrandingScope::Client("app".into()).scope_key();
    assert_eq!(repo.get(tenant, &tenant_key).await.expect("get"), None);

    let t_update = new_branding_update("#112233", LogoChange::Keep);
    let now = now_ms();
    let stored = repo
        .put(tenant, &tenant_key, &t_update, now)
        .await
        .expect("put");
    assert_eq!(stored.tenant_id, tenant);
    assert_eq!(stored.scope_key, tenant_key);
    assert_eq!(stored.tokens, t_update.tokens);
    assert_eq!(stored.custom_css, t_update.custom_css);
    assert_eq!(stored.logo_sha256, None);
    assert_eq!(stored.logo_type, None);
    assert_eq!(stored.updated_at, now);
    assert_eq!(
        repo.get(tenant, &tenant_key).await.expect("get"),
        Some(stored.clone())
    );

    let c_update = new_branding_update("#445566", LogoChange::Keep);
    let c_stored = repo
        .put(tenant, &client_key, &c_update, now)
        .await
        .expect("put");
    assert_eq!(c_stored.tokens, c_update.tokens);
    assert_eq!(
        repo.get(tenant, &tenant_key).await.expect("get"),
        Some(stored),
        "client branding does not touch the tenant branding"
    );

    // Upsert replaces tokens and CSS.
    let later = now + Duration::seconds(2);
    let replaced = repo
        .put(
            tenant,
            &client_key,
            &anvil_core::model::BrandingUpdate {
                tokens: theme_tokens("#000000"),
                custom_css: None,
                logo: LogoChange::Keep,
            },
            later,
        )
        .await
        .expect("put");
    assert_eq!(replaced.tokens, theme_tokens("#000000"));
    assert_eq!(replaced.custom_css, None);
    assert_eq!(replaced.updated_at, later);
    assert_eq!(
        repo.get(tenant, &client_key).await.expect("get"),
        Some(replaced)
    );
}

pub async fn branding_logo_keep_clear_set(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.branding();
    let key = BrandingScope::Tenant.scope_key();
    let logo = new_logo();

    let set = repo
        .put(
            tenant,
            &key,
            &new_branding_update("#111111", LogoChange::Set(logo.clone())),
            now_ms(),
        )
        .await
        .expect("put");
    assert_eq!(set.logo_sha256.as_deref(), Some(logo.sha256.as_str()));
    assert_eq!(set.logo_type.as_deref(), Some("image/png"));
    assert_eq!(
        repo.logo(tenant, &logo.sha256).await.expect("logo"),
        Some(logo.clone())
    );

    let kept = repo
        .put(
            tenant,
            &key,
            &new_branding_update("#222222", LogoChange::Keep),
            now_ms(),
        )
        .await
        .expect("put");
    assert_eq!(
        kept.logo_sha256.as_deref(),
        Some(logo.sha256.as_str()),
        "Keep keeps the logo"
    );
    assert_eq!(kept.logo_type.as_deref(), Some("image/png"));

    let replacement = new_logo();
    let replaced = repo
        .put(
            tenant,
            &key,
            &new_branding_update("#333333", LogoChange::Set(replacement.clone())),
            now_ms(),
        )
        .await
        .expect("put");
    assert_eq!(
        replaced.logo_sha256.as_deref(),
        Some(replacement.sha256.as_str())
    );
    assert_eq!(
        repo.logo(tenant, &replacement.sha256).await.expect("logo"),
        Some(replacement)
    );

    let cleared = repo
        .put(
            tenant,
            &key,
            &new_branding_update("#444444", LogoChange::Clear),
            now_ms(),
        )
        .await
        .expect("put");
    assert_eq!(cleared.logo_sha256, None);
    assert_eq!(cleared.logo_type, None);
    assert_eq!(
        repo.logo(tenant, "0".repeat(64).as_str())
            .await
            .expect("logo"),
        None
    );
}

pub async fn branding_draft_replace_and_preview(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.branding();
    let key = BrandingScope::Client("app".into()).scope_key();

    let first = new_branding_draft(Duration::minutes(30));
    repo.put_draft(tenant, &key, &first, now_ms())
        .await
        .expect("put_draft");
    assert_eq!(
        repo.draft_by_preview(tenant, &first.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        Some((key.clone(), first.clone()))
    );

    let second = new_branding_draft(Duration::minutes(30));
    repo.put_draft(tenant, &key, &second, now_ms())
        .await
        .expect("put_draft");
    assert_eq!(
        repo.draft_by_preview(tenant, &first.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        None,
        "a new draft replaces the scope's previous draft"
    );
    assert_eq!(
        repo.draft_by_preview(tenant, &second.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        Some((key.clone(), second.clone()))
    );
    assert_eq!(
        repo.draft_by_preview(
            tenant,
            &second.preview_token_hash,
            second.preview_expires_at
        )
        .await
        .expect("draft_by_preview"),
        None,
        "a draft is not previewable at its expiry"
    );

    let other_scope = BrandingScope::Tenant.scope_key();
    let expired = new_branding_draft(Duration::seconds(-1));
    repo.put_draft(tenant, &other_scope, &expired, now_ms())
        .await
        .expect("put_draft");
    assert_eq!(
        repo.draft_by_preview(tenant, &expired.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        None,
        "expired drafts are never returned"
    );
    assert_eq!(
        repo.draft_by_preview(tenant, &unique_hash(), now_ms())
            .await
            .expect("draft_by_preview"),
        None
    );
}

pub async fn branding_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.branding();
    let key = BrandingScope::Client("gone".into()).scope_key();
    assert!(!repo.delete(tenant, &key).await.expect("delete"));
    repo.put(
        tenant,
        &key,
        &new_branding_update("#555555", LogoChange::Keep),
        now_ms(),
    )
    .await
    .expect("put");
    assert!(repo.delete(tenant, &key).await.expect("delete"));
    assert_eq!(repo.get(tenant, &key).await.expect("get"), None);
    assert!(!repo.delete(tenant, &key).await.expect("delete"));
}

pub async fn branding_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.branding();
    let key = BrandingScope::Tenant.scope_key();
    let logo = new_logo();
    repo.put(
        tenant,
        &key,
        &new_branding_update("#666666", LogoChange::Set(logo.clone())),
        now_ms(),
    )
    .await
    .expect("put");
    let draft = new_branding_draft(Duration::minutes(10));
    repo.put_draft(tenant, &key, &draft, now_ms())
        .await
        .expect("put_draft");

    assert_eq!(repo.get(other, &key).await.expect("get"), None);
    assert_eq!(repo.logo(other, &logo.sha256).await.expect("logo"), None);
    assert_eq!(
        repo.draft_by_preview(other, &draft.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        None,
        "a preview token never shows another tenant's draft"
    );
    assert!(!repo.delete(other, &key).await.expect("delete"));
    assert!(repo.get(tenant, &key).await.expect("get").is_some());
}
