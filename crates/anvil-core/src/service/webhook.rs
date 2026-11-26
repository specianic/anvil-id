//! Webhook endpoints: create, update, secret rotation, test sends and redelivery (ADM-05).
//!
//! - **Endpoints** are validated when written: a name (`^[a-z0-9][a-z0-9_-]{0,63}$`, unique per
//!   tenant, the declarative-config key), an absolute URL that passes the outbound destination
//!   policy ([`WebhookUrlCheck`], implemented by the web layer's single `OutboundClient`), and a
//!   non-empty list of lifecycle event types (never `test`). A private or loopback literal is
//!   refused here and blocked again at send time (DNS answers are checked on every connection).
//! - **Secrets** are `whsec_` + base64 of 32 random bytes ([`generate_webhook_secret`]), sealed
//!   with the KEK ([`WEBHOOK_SECRET_PURPOSE`], AAD [`webhook_aad`] = tenant id || endpoint id)
//!   before they reach storage, and returned exactly once (by [`WebhookService::create`] and
//!   [`WebhookService::rotate_secret`]). Rotation keeps the previous secret for
//!   [`WEBHOOK_ROTATION_GRACE`]; during that window both secrets sign ([`signing_keys`]).
//! - **Events** are not sent from here: [`AuditService::record`] computes the ids-only payload
//!   and storage enqueues it in the audit transaction. This service only queues the console's
//!   test event ([`WebhookService::send_test`]) and redeliveries.
//!
//! Every mutation records one audit event in the endpoint's tenant (target = endpoint id,
//! details = endpoint name; redelivery and test sends add the delivery). Nothing here returns,
//! logs or audits secret material, and failed calls record nothing.

use std::collections::BTreeSet;
use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::webhook::{generate_webhook_secret, parse_webhook_secret};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;
use url::Url;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, NewWebhookEndpoint, Page, PageRequest,
    RequestContext, TenantId, WEBHOOK_SECRET_PURPOSE, WebhookDelivery, WebhookDeliveryId,
    WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEventType, truncate_to_ms,
    webhook_aad,
};
use crate::policy::webhook_event::test_event;
use crate::ports::{Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::tenant::admin_page;

/// How long the previous secret keeps signing after a rotation.
pub const WEBHOOK_ROTATION_GRACE: time::Duration = time::Duration::hours(24);
/// Longest accepted endpoint URL.
pub const MAX_WEBHOOK_URL_LEN: usize = 2048;
/// Longest endpoint name.
pub const MAX_WEBHOOK_NAME_LEN: usize = 64;

/// Why the destination policy refused an endpoint URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRefusal {
    /// Unusable URL: scheme (https only outside development mode), userinfo, no host.
    Invalid,
    /// The destination is in a blocked range (private, loopback, link-local, ...).
    Blocked,
}

/// The outbound destination policy, as checked before connecting (the web layer implements it
/// with the single `OutboundClient::check_url`, so create-time checks and send-time checks are
/// the same rules).
pub trait WebhookUrlCheck: Send + Sync {
    fn check(&self, url: &Url) -> Result<(), UrlRefusal>;
}

/// An endpoint as submitted by an administrator (or the declarative config).
#[derive(Debug, Clone)]
pub struct NewWebhookInput {
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub enabled: bool,
    /// A caller-provided `whsec_` secret (declarative config). `None` = generate one.
    pub secret: Option<SecretString>,
}

/// An endpoint with its signing secret, returned once by create and rotate. The secret is never
/// readable again.
#[derive(Debug)]
pub struct EndpointWithSecret {
    pub endpoint: WebhookEndpoint,
    pub secret: SecretString,
}

fn invalid(field: &'static str, message: impl Into<String>) -> CoreError {
    CoreError::Validation {
        field,
        message: message.into(),
    }
}

/// Endpoint name syntax: `^[a-z0-9][a-z0-9_-]{0,63}$`.
pub fn validate_webhook_name(name: &str) -> Result<(), CoreError> {
    let b = name.as_bytes();
    let ok = (1..=MAX_WEBHOOK_NAME_LEN).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_');
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "name",
            "must be 1-64 characters of a-z, 0-9, '-' and '_', starting with a letter or digit",
        ))
    }
}

/// An absolute endpoint URL without fragment or whitespace that the destination policy allows.
pub fn validate_webhook_url(raw: &str, check: &dyn WebhookUrlCheck) -> Result<(), CoreError> {
    if raw.is_empty()
        || raw.len() > MAX_WEBHOOK_URL_LEN
        || raw.chars().any(|c| c.is_whitespace() || c.is_control())
        || raw.contains('#')
    {
        return Err(invalid("url", "must be an absolute https URL"));
    }
    let url = Url::parse(raw).map_err(|_| invalid("url", "must be an absolute https URL"))?;
    match check.check(&url) {
        Ok(()) => Ok(()),
        Err(UrlRefusal::Invalid) => Err(invalid(
            "url",
            "must be an absolute https URL without credentials",
        )),
        Err(UrlRefusal::Blocked) => Err(invalid("url", "destination not allowed")),
    }
}

/// Subscriptions: at least one lifecycle event type, never `test`; returned sorted without
/// duplicates.
pub fn validate_webhook_events(
    events: &[WebhookEventType],
) -> Result<Vec<WebhookEventType>, CoreError> {
    if events.contains(&WebhookEventType::Test) {
        return Err(invalid("events", "test is not a subscribable event"));
    }
    let set: BTreeSet<WebhookEventType> = events.iter().copied().collect();
    if set.is_empty() {
        return Err(invalid("events", "subscribe to at least one event"));
    }
    Ok(set.into_iter().collect())
}

/// Seals a `whsec_` secret for one endpoint of one tenant.
pub fn seal_webhook_secret(
    kek: &Kek,
    tenant: TenantId,
    endpoint: WebhookEndpointId,
    secret: &SecretString,
) -> Result<Vec<u8>, CoreError> {
    kek.seal(
        WEBHOOK_SECRET_PURPOSE,
        &webhook_aad(tenant, endpoint),
        secret.expose_secret().as_bytes(),
    )
    .map_err(|_| CoreError::Internal("webhook secret could not be sealed".into()))
}

fn open_one(
    kek: &Kek,
    endpoint: &WebhookEndpoint,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let undecryptable = || CoreError::Internal("webhook secret could not be decrypted".into());
    let plain = kek
        .open(
            WEBHOOK_SECRET_PURPOSE,
            &webhook_aad(endpoint.tenant_id, endpoint.id),
            sealed,
        )
        .map_err(|_| undecryptable())?;
    let text = std::str::from_utf8(&plain).map_err(|_| undecryptable())?;
    parse_webhook_secret(text).map_err(|_| undecryptable())
}

/// The HMAC keys that sign a delivery to `endpoint` at `now`: the current secret, then the
/// previous one while its rotation window is open. A secret sealed for another tenant or
/// endpoint does not open (`Internal`, without the value). Callers must not log or store them.
pub fn signing_keys(
    kek: &Kek,
    endpoint: &WebhookEndpoint,
    now: OffsetDateTime,
) -> Result<Vec<Zeroizing<Vec<u8>>>, CoreError> {
    let mut keys = vec![open_one(kek, endpoint, &endpoint.secret_enc)?];
    if let (Some(prev), Some(until)) = (
        &endpoint.previous_secret_enc,
        endpoint.previous_secret_expires_at,
    ) && until > now
    {
        keys.push(open_one(kek, endpoint, prev)?);
    }
    Ok(keys)
}

fn provided_or_generated(secret: Option<SecretString>) -> Result<SecretString, CoreError> {
    match secret {
        Some(s) => {
            parse_webhook_secret(s.expose_secret()).map_err(|_| {
                invalid(
                    "secret",
                    "must be whsec_ followed by base64 of 24 to 64 bytes",
                )
            })?;
            Ok(s)
        }
        None => Ok(SecretString::from(generate_webhook_secret().as_str())),
    }
}

/// Manages a tenant's webhook endpoints (module docs).
#[derive(Clone)]
pub struct WebhookService {
    pub storage: Arc<dyn Storage>,
    pub kek: Arc<Kek>,
    pub clock: Arc<dyn Clock>,
    /// The outbound destination policy (the web layer's `OutboundClient`).
    pub url_check: Arc<dyn WebhookUrlCheck>,
}

impl WebhookService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    async fn record(
        &self,
        endpoint: &WebhookEndpoint,
        actor: AuditActor,
        action: AuditAction,
        ctx: &RequestContext,
        extra: AuditDetails,
    ) -> Result<(), CoreError> {
        self.audit()
            .record(
                endpoint.tenant_id,
                actor,
                action,
                Some(endpoint.id.to_string()),
                AuditOutcome::Success,
                ctx,
                AuditDetails::webhook_endpoint(&endpoint.name).with(extra),
            )
            .await
    }

    fn conflict(e: StorageError) -> CoreError {
        match e {
            StorageError::Conflict(_) => {
                CoreError::Conflict("a webhook endpoint with this name already exists".into())
            }
            other => other.into(),
        }
    }

    /// Every endpoint of the tenant, in name order.
    pub async fn list(&self, tenant: TenantId) -> Result<Vec<WebhookEndpoint>, CoreError> {
        Ok(self.storage.webhooks().list_endpoints(tenant).await?)
    }

    /// The endpoint `id` of `tenant`; `NotFound` for another tenant's endpoint. The returned
    /// value holds only sealed secret bytes; callers expose `secret_configured`, never them.
    pub async fn get(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
    ) -> Result<WebhookEndpoint, CoreError> {
        self.storage
            .webhooks()
            .get_endpoint(tenant, id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Validates and creates an endpoint. The secret (provided or generated) is sealed before it
    /// is stored and returned here once. Audited as `webhook_endpoint_created`; a duplicate name
    /// is `Conflict`.
    pub async fn create(
        &self,
        tenant: TenantId,
        input: NewWebhookInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<EndpointWithSecret, CoreError> {
        validate_webhook_name(&input.name)?;
        validate_webhook_url(&input.url, self.url_check.as_ref())?;
        let events = validate_webhook_events(&input.events)?;
        let secret = provided_or_generated(input.secret)?;
        let id = WebhookEndpointId::new_v7();
        let new = NewWebhookEndpoint {
            id,
            name: input.name,
            url: input.url,
            events,
            enabled: input.enabled,
            secret_enc: seal_webhook_secret(&self.kek, tenant, id, &secret)?,
            created_at: truncate_to_ms(self.clock.now()),
        };
        let endpoint = self
            .storage
            .webhooks()
            .create_endpoint(tenant, &new)
            .await
            .map_err(Self::conflict)?;
        self.record(
            &endpoint,
            actor,
            AuditAction::WebhookEndpointCreated,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
        Ok(EndpointWithSecret { endpoint, secret })
    }

    /// Applies a partial update (name, URL, events, enabled; validated like create). Re-enabling
    /// clears the system's disabled reason. Audited as `webhook_endpoint_updated` with the
    /// changed field names.
    pub async fn update(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        mut update: WebhookEndpointUpdate,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<WebhookEndpoint, CoreError> {
        let mut fields: Vec<&'static str> = Vec::new();
        if let Some(name) = &update.name {
            validate_webhook_name(name)?;
            fields.push("name");
        }
        if let Some(url) = &update.url {
            validate_webhook_url(url, self.url_check.as_ref())?;
            fields.push("url");
        }
        if let Some(events) = &update.events {
            update.events = Some(validate_webhook_events(events)?);
            fields.push("events");
        }
        if update.enabled.is_some() {
            fields.push("enabled");
        }
        let endpoint = self
            .storage
            .webhooks()
            .update_endpoint(tenant, id, &update, truncate_to_ms(self.clock.now()))
            .await
            .map_err(Self::conflict)?
            .ok_or(CoreError::NotFound)?;
        self.record(
            &endpoint,
            actor,
            AuditAction::WebhookEndpointUpdated,
            ctx,
            AuditDetails::fields(&fields),
        )
        .await?;
        Ok(endpoint)
    }

    /// Generates a new secret (returned once); the current one keeps signing for
    /// [`WEBHOOK_ROTATION_GRACE`]. Audited as `webhook_secret_rotated`, never with a secret.
    pub async fn rotate_secret(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<EndpointWithSecret, CoreError> {
        self.rotate_to(tenant, id, None, actor, ctx).await
    }

    /// [`Self::rotate_secret`] to a caller-provided `whsec_` secret (declarative configuration):
    /// same grace period for the previous secret, same audit event.
    pub async fn set_secret(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        secret: SecretString,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<WebhookEndpoint, CoreError> {
        Ok(self
            .rotate_to(tenant, id, Some(secret), actor, ctx)
            .await?
            .endpoint)
    }

    async fn rotate_to(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        provided: Option<SecretString>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<EndpointWithSecret, CoreError> {
        // Existence first, so an unknown endpoint is NotFound before any sealing.
        self.get(tenant, id).await?;
        let secret = provided_or_generated(provided)?;
        let sealed = seal_webhook_secret(&self.kek, tenant, id, &secret)?;
        let now = truncate_to_ms(self.clock.now());
        if !self
            .storage
            .webhooks()
            .rotate_secret(tenant, id, &sealed, now + WEBHOOK_ROTATION_GRACE, now)
            .await?
        {
            return Err(CoreError::NotFound);
        }
        let endpoint = self.get(tenant, id).await?;
        self.record(
            &endpoint,
            actor,
            AuditAction::WebhookSecretRotated,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
        Ok(EndpointWithSecret { endpoint, secret })
    }

    /// Deletes the endpoint and its delivery log. Audited as `webhook_endpoint_deleted`.
    pub async fn delete(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let current = self.get(tenant, id).await?;
        if !self.storage.webhooks().delete_endpoint(tenant, id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            &current,
            actor,
            AuditAction::WebhookEndpointDeleted,
            ctx,
            AuditDetails::empty(),
        )
        .await
    }

    /// Queues the `test` event for the endpoint regardless of its subscriptions. Audited as
    /// `webhook_test_sent` with the delivery.
    pub async fn send_test(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<WebhookDelivery, CoreError> {
        let endpoint = self.get(tenant, id).await?;
        let now = truncate_to_ms(self.clock.now());
        // The payload names the tenant by id, like every lifecycle event (ids only).
        let event = test_event(&tenant.to_string(), now);
        let delivery = self
            .storage
            .webhooks()
            .enqueue_test(tenant, id, &event, now)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.record(
            &endpoint,
            actor,
            AuditAction::WebhookTestSent,
            ctx,
            AuditDetails::webhook_event(WebhookEventType::Test)
                .with(AuditDetails::webhook_delivery(delivery.id, 0, "queued")),
        )
        .await?;
        Ok(delivery)
    }

    /// Queues a new delivery (new id, fresh attempts) with the event of delivery `id`. Audited as
    /// `webhook_redelivered` with the original and the new delivery.
    pub async fn redeliver(
        &self,
        tenant: TenantId,
        id: WebhookDeliveryId,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<WebhookDelivery, CoreError> {
        let now = truncate_to_ms(self.clock.now());
        let delivery = self
            .storage
            .webhooks()
            .redeliver(tenant, id, now)
            .await?
            .ok_or(CoreError::NotFound)?;
        let endpoint = self.get(tenant, delivery.endpoint_id).await?;
        let extra = AuditDetails::webhook_event(delivery.event_type)
            .with(AuditDetails::webhook_delivery(delivery.id, 0, "queued"))
            .with(AuditDetails::reason("redelivery"));
        self.record(
            &endpoint,
            actor,
            AuditAction::WebhookRedelivered,
            ctx,
            extra,
        )
        .await?;
        Ok(delivery)
    }

    /// The endpoint's delivery log, newest first (management-API page rules).
    pub async fn deliveries(
        &self,
        tenant: TenantId,
        endpoint: WebhookEndpointId,
        page: PageRequest,
    ) -> Result<Page<WebhookDelivery>, CoreError> {
        self.get(tenant, endpoint).await?;
        Ok(self
            .storage
            .webhooks()
            .deliveries(tenant, endpoint, admin_page(page))
            .await?)
    }

    /// The HMAC keys that sign a delivery to `endpoint` now ([`signing_keys`]).
    pub fn signing_keys(
        &self,
        endpoint: &WebhookEndpoint,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, CoreError> {
        signing_keys(&self.kek, endpoint, self.clock.now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Policy(Result<(), UrlRefusal>);

    impl WebhookUrlCheck for Policy {
        fn check(&self, _: &Url) -> Result<(), UrlRefusal> {
            self.0
        }
    }

    fn field(e: CoreError) -> &'static str {
        match e {
            CoreError::Validation { field, .. } => field,
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    #[test]
    fn names_follow_the_key_syntax() {
        for ok in ["crm", "a", "billing-sync_2", &"x".repeat(64)] {
            validate_webhook_name(ok).unwrap();
        }
        for bad in ["", "-x", "_x", "CRM", "a b", "a.b", "é", &"x".repeat(65)] {
            assert_eq!(field(validate_webhook_name(bad).unwrap_err()), "name");
        }
    }

    #[test]
    fn urls_are_checked_by_the_destination_policy() {
        let allow = Policy(Ok(()));
        validate_webhook_url("https://hooks.example/x?y=1", &allow).unwrap();
        for bad in [
            "",
            "not a url",
            "https://hooks.example/x#frag",
            "/relative",
            "https://hooks.example/\nx",
        ] {
            assert_eq!(field(validate_webhook_url(bad, &allow).unwrap_err()), "url");
        }
        let long = format!("https://hooks.example/{}", "a".repeat(MAX_WEBHOOK_URL_LEN));
        assert_eq!(
            field(validate_webhook_url(&long, &allow).unwrap_err()),
            "url"
        );
        assert!(matches!(
            validate_webhook_url("https://10.0.0.1/", &Policy(Err(UrlRefusal::Blocked))),
            Err(CoreError::Validation { field: "url", message }) if message == "destination not allowed"
        ));
        assert!(matches!(
            validate_webhook_url("http://hooks.example/", &Policy(Err(UrlRefusal::Invalid))),
            Err(CoreError::Validation { field: "url", .. })
        ));
    }

    #[test]
    fn events_are_deduplicated_and_never_test() {
        use WebhookEventType as W;
        assert_eq!(
            validate_webhook_events(&[W::SessionCreated, W::UserCreated, W::SessionCreated])
                .unwrap(),
            vec![W::UserCreated, W::SessionCreated]
        );
        assert_eq!(field(validate_webhook_events(&[]).unwrap_err()), "events");
        assert_eq!(
            field(validate_webhook_events(&[W::UserCreated, W::Test]).unwrap_err()),
            "events"
        );
    }

    fn endpoint(kek: &Kek, secret: &SecretString) -> WebhookEndpoint {
        let tenant = TenantId::new_v7();
        let id = WebhookEndpointId::new_v7();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        WebhookEndpoint {
            id,
            tenant_id: tenant,
            name: "crm".into(),
            url: "https://hooks.example/x".into(),
            events: vec![WebhookEventType::UserCreated],
            enabled: true,
            secret_enc: seal_webhook_secret(kek, tenant, id, secret).unwrap(),
            previous_secret_enc: None,
            previous_secret_expires_at: None,
            disabled_reason: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn sealed_secret_opens_only_for_its_endpoint() {
        let kek = Kek::generate();
        let secret = SecretString::from(generate_webhook_secret().as_str());
        let mut e = endpoint(&kek, &secret);
        let sealed = &e.secret_enc;
        assert!(
            !sealed
                .windows(secret.expose_secret().len())
                .any(|w| w == secret.expose_secret().as_bytes()),
            "the stored bytes must not contain the secret"
        );
        let keys = signing_keys(&kek, &e, e.created_at).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].as_slice(),
            parse_webhook_secret(secret.expose_secret())
                .unwrap()
                .as_slice()
        );
        // Moved to another endpoint id (AAD mismatch): does not open.
        e.id = WebhookEndpointId::new_v7();
        assert!(matches!(
            signing_keys(&kek, &e, e.created_at),
            Err(CoreError::Internal(_))
        ));
        // Another KEK: does not open.
        let e = endpoint(&kek, &secret);
        assert!(signing_keys(&Kek::generate(), &e, e.created_at).is_err());
    }

    #[test]
    fn previous_secret_signs_only_inside_its_window() {
        let kek = Kek::generate();
        let current = SecretString::from(generate_webhook_secret().as_str());
        let previous = SecretString::from(generate_webhook_secret().as_str());
        let mut e = endpoint(&kek, &current);
        let until = e.created_at + WEBHOOK_ROTATION_GRACE;
        e.previous_secret_enc =
            Some(seal_webhook_secret(&kek, e.tenant_id, e.id, &previous).unwrap());
        e.previous_secret_expires_at = Some(until);
        assert_eq!(
            signing_keys(&kek, &e, until - time::Duration::SECOND)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(signing_keys(&kek, &e, until).unwrap().len(), 1);
    }

    #[test]
    fn provided_secrets_must_be_whsec() {
        provided_or_generated(Some(SecretString::from(generate_webhook_secret().as_str())))
            .unwrap();
        assert_eq!(
            field(provided_or_generated(Some(SecretString::from("hunter2"))).unwrap_err()),
            "secret"
        );
        let generated = provided_or_generated(None).unwrap();
        assert!(generated.expose_secret().starts_with("whsec_"));
    }
}
