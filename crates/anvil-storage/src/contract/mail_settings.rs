//! MailSettingsRepo contract: template overrides and SMTP settings per tenant.

use anvil_core::model::EmailKind;

use super::TestStorage;
use super::fixtures::*;

pub async fn mail_template_put_get_list_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.mail_settings();
    assert_eq!(
        repo.template(tenant, EmailKind::Recovery)
            .await
            .expect("get"),
        None
    );
    assert!(repo.list_templates(tenant).await.expect("list").is_empty());

    let recovery = new_email_template(EmailKind::Recovery);
    let verification = new_email_template(EmailKind::Verification);
    repo.put_template(tenant, &verification).await.expect("put");
    repo.put_template(tenant, &recovery).await.expect("put");
    assert_eq!(
        repo.template(tenant, EmailKind::Recovery)
            .await
            .expect("get"),
        Some(recovery.clone())
    );
    assert_eq!(
        repo.list_templates(tenant).await.expect("list"),
        vec![recovery.clone(), verification.clone()],
        "kind-name order"
    );

    let replaced = new_email_template(EmailKind::Recovery);
    repo.put_template(tenant, &replaced)
        .await
        .expect("put replaces");
    assert_eq!(
        repo.template(tenant, EmailKind::Recovery)
            .await
            .expect("get"),
        Some(replaced)
    );

    assert!(
        repo.delete_template(tenant, EmailKind::Recovery)
            .await
            .expect("delete")
    );
    assert!(
        !repo
            .delete_template(tenant, EmailKind::Recovery)
            .await
            .expect("delete")
    );
    assert_eq!(
        repo.template(tenant, EmailKind::Recovery)
            .await
            .expect("get"),
        None
    );
    assert_eq!(
        repo.list_templates(tenant).await.expect("list"),
        vec![verification]
    );
}

pub async fn mail_smtp_put_get_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.mail_settings();
    assert_eq!(repo.smtp(tenant).await.expect("smtp"), None);
    let settings = new_smtp_settings();
    repo.put_smtp(tenant, &settings).await.expect("put");
    assert_eq!(repo.smtp(tenant).await.expect("smtp"), Some(settings));

    let minimal = anvil_core::model::SmtpSettings {
        username: None,
        password_enc: None,
        tls: anvil_core::model::SmtpTls::Implicit,
        port: 465,
        ..new_smtp_settings()
    };
    repo.put_smtp(tenant, &minimal).await.expect("put replaces");
    assert_eq!(repo.smtp(tenant).await.expect("smtp"), Some(minimal));

    assert!(repo.delete_smtp(tenant).await.expect("delete"));
    assert!(!repo.delete_smtp(tenant).await.expect("delete"));
    assert_eq!(repo.smtp(tenant).await.expect("smtp"), None);
}

pub async fn mail_settings_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let repo = s.storage.mail_settings();
    repo.put_template(tenant, &new_email_template(EmailKind::Invitation))
        .await
        .expect("put");
    repo.put_smtp(tenant, &new_smtp_settings())
        .await
        .expect("put");

    assert_eq!(
        repo.template(other, EmailKind::Invitation)
            .await
            .expect("get"),
        None
    );
    assert!(repo.list_templates(other).await.expect("list").is_empty());
    assert_eq!(repo.smtp(other).await.expect("smtp"), None);
    assert!(
        !repo
            .delete_template(other, EmailKind::Invitation)
            .await
            .expect("delete")
    );
    assert!(!repo.delete_smtp(other).await.expect("delete"));
    assert!(repo.smtp(tenant).await.expect("smtp").is_some());
}

// ---- Phase 6 (plan 06-04): the org invitation template ----

pub async fn mail_template_org_invitation_round_trip(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let repo = s.storage.mail_settings();
    let template = new_email_template(EmailKind::OrgInvitation);
    repo.put_template(tenant, &template).await.expect("put");
    assert_eq!(
        repo.template(tenant, EmailKind::OrgInvitation)
            .await
            .expect("get"),
        Some(template.clone())
    );
    assert_eq!(
        repo.list_templates(tenant).await.expect("list"),
        vec![template]
    );
    assert!(
        repo.delete_template(tenant, EmailKind::OrgInvitation)
            .await
            .expect("delete")
    );
}
