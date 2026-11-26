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

pub async fn purge_expired_removes_unreferenced_logos(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.branding();
    let tenant_key = BrandingScope::Tenant.scope_key();
    let app = BrandingScope::Client("app".into()).scope_key();
    let app2 = BrandingScope::Client("app2".into()).scope_key();
    let app3 = BrandingScope::Client("app3".into()).scope_key();
    let put = |t, key: String, logo: LogoChange| async move {
        s.storage
            .branding()
            .put(t, &key, &new_branding_update("#101010", logo), now_ms())
            .await
            .expect("put");
    };
    let (replaced, current, shared, cleared) = (new_logo(), new_logo(), new_logo(), new_logo());

    // Replaced on the tenant scope: the old logo is unreferenced.
    put(
        tenant,
        tenant_key.clone(),
        LogoChange::Set(replaced.clone()),
    )
    .await;
    put(tenant, tenant_key.clone(), LogoChange::Set(current.clone())).await;
    // Referenced by one client scope, set then cleared on another: still referenced.
    put(tenant, app.clone(), LogoChange::Set(shared.clone())).await;
    put(tenant, app2.clone(), LogoChange::Set(shared.clone())).await;
    put(tenant, app2.clone(), LogoChange::Clear).await;
    // Set then cleared, referenced nowhere else.
    put(tenant, app3.clone(), LogoChange::Set(cleared.clone())).await;
    put(tenant, app3.clone(), LogoChange::Clear).await;
    // The replaced logo's bytes are still in use in another tenant.
    put(other, tenant_key.clone(), LogoChange::Set(replaced.clone())).await;

    s.storage
        .purge_expired(now_ms())
        .await
        .expect("purge_expired");

    assert_eq!(
        repo.logo(tenant, &replaced.sha256).await.expect("logo"),
        None,
        "a replaced logo is purged"
    );
    assert_eq!(
        repo.logo(tenant, &current.sha256).await.expect("logo"),
        Some(current.clone()),
        "the current logo stays"
    );
    assert_eq!(
        repo.logo(tenant, &shared.sha256).await.expect("logo"),
        Some(shared.clone()),
        "a logo another scope of the tenant references stays"
    );
    assert_eq!(
        repo.logo(tenant, &cleared.sha256).await.expect("logo"),
        None,
        "a cleared logo is purged"
    );
    assert_eq!(
        repo.logo(other, &replaced.sha256).await.expect("logo"),
        Some(replaced.clone()),
        "references are judged per tenant"
    );
    assert_eq!(
        repo.get(tenant, &tenant_key)
            .await
            .expect("get")
            .expect("branding")
            .logo_sha256
            .as_deref(),
        Some(current.sha256.as_str())
    );
}

pub async fn client_delete_removes_its_branding(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let client = seed_client(s, tenant).await;
    let survivor = seed_client(s, tenant).await;
    let repo = s.storage.branding();
    let tenant_key = BrandingScope::Tenant.scope_key();
    let client_key = BrandingScope::Client(client.client_id.clone()).scope_key();
    let survivor_key = BrandingScope::Client(survivor.client_id.clone()).scope_key();
    let logo = new_logo();
    let now = now_ms();

    let tenant_branding = repo
        .put(
            tenant,
            &tenant_key,
            &new_branding_update("#202020", LogoChange::Keep),
            now,
        )
        .await
        .expect("put");
    repo.put(
        tenant,
        &client_key,
        &new_branding_update("#303030", LogoChange::Set(logo.clone())),
        now,
    )
    .await
    .expect("put");
    let draft = new_branding_draft(Duration::minutes(10));
    repo.put_draft(tenant, &client_key, &draft, now)
        .await
        .expect("put_draft");
    let survivor_branding = repo
        .put(
            tenant,
            &survivor_key,
            &new_branding_update("#404040", LogoChange::Keep),
            now,
        )
        .await
        .expect("put");
    let survivor_draft = new_branding_draft(Duration::minutes(10));
    repo.put_draft(tenant, &survivor_key, &survivor_draft, now)
        .await
        .expect("put_draft");

    assert!(
        s.storage
            .clients()
            .delete(tenant, &client.client_id)
            .await
            .expect("delete")
    );

    assert_eq!(
        repo.get(tenant, &client_key).await.expect("get"),
        None,
        "deleting a client deletes its branding"
    );
    assert_eq!(
        repo.draft_by_preview(tenant, &draft.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview"),
        None,
        "and its preview draft"
    );
    assert_eq!(
        repo.get(tenant, &tenant_key).await.expect("get"),
        Some(tenant_branding),
        "the tenant branding is untouched"
    );
    assert_eq!(
        repo.get(tenant, &survivor_key).await.expect("get"),
        Some(survivor_branding),
        "another client's branding is untouched"
    );
    assert!(
        repo.draft_by_preview(tenant, &survivor_draft.preview_token_hash, now_ms())
            .await
            .expect("draft_by_preview")
            .is_some()
    );

    s.storage
        .purge_expired(now_ms())
        .await
        .expect("purge_expired");
    assert_eq!(
        repo.logo(tenant, &logo.sha256).await.expect("logo"),
        None,
        "the deleted client's logo goes with the next purge"
    );
}

// ---- Phase 6 (plan 06-04): organization branding scope; the backends refuse it with
// StorageError::Unsupported until 06-07 / 06-08 ----

pub async fn branding_org_scope_independent(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.branding();
    let org = seed_org(s, tenant).await;
    let org_key = BrandingScope::Org(org.id).scope_key();
    let tenant_key = BrandingScope::Tenant.scope_key();
    let client_key = BrandingScope::Client("app".into()).scope_key();
    repo.put(
        tenant,
        &tenant_key,
        &new_branding_update("#111111", LogoChange::Keep),
        now_ms(),
    )
    .await
    .expect("tenant");
    repo.put(
        tenant,
        &client_key,
        &new_branding_update("#222222", LogoChange::Keep),
        now_ms(),
    )
    .await
    .expect("client");
    let org_update = new_branding_update("#333333", LogoChange::Set(new_logo()));
    let stored = repo
        .put(tenant, &org_key, &org_update, now_ms())
        .await
        .expect("org");
    assert_eq!(stored.scope_key, org_key);
    assert_eq!(stored.tokens, org_update.tokens);
    assert_eq!(repo.get(tenant, &org_key).await.expect("get"), Some(stored));
    // The scopes do not affect each other.
    assert!(repo.delete(tenant, &org_key).await.expect("delete org"));
    assert_eq!(repo.get(tenant, &org_key).await.expect("get"), None);
    assert!(repo.get(tenant, &tenant_key).await.expect("get").is_some());
    assert!(repo.get(tenant, &client_key).await.expect("get").is_some());
    // A draft of the org scope previews independently.
    let draft = new_branding_draft(Duration::minutes(10));
    repo.put_draft(tenant, &org_key, &draft, now_ms())
        .await
        .expect("org draft");
    assert_eq!(
        repo.draft_by_preview(tenant, &draft.preview_token_hash, now_ms())
            .await
            .expect("preview")
            .map(|(k, _)| k),
        Some(org_key)
    );
}
