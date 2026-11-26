//! `WebhookRepo` on SQLite: endpoints, the leased delivery queue, and the enqueue helper that
//! `AuditRepo::append` calls inside its own transaction.
//!
//! `events` is stored as a JSON array of the event types' wire names (`as_str()`), so the
//! subscription test in [`enqueue_for_event`] is a plain `json_each` lookup. Claims are single
//! statements on the single writer connection, so concurrent claimers never get the same row.

use std::collections::HashMap;

use anvil_core::model::{
    DeliveryStatus, NewWebhookEndpoint, Page, PageRequest, TenantId, WebhookDelivery,
    WebhookDeliveryId, WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEvent,
    WebhookEventType, WebhookResult,
};
use anvil_core::ports::{ClaimedWebhookDelivery, StorageError, WebhookRepo};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    from_json, i64_to_u32, into_page, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, opt_odt_to_ms,
    parse_enum, to_json,
};

/// `last_error` and `disabled_reason` recorded for a 410 Gone answer.
const GONE: &str = "gone";

#[derive(Debug, Clone)]
pub(crate) struct SqliteWebhooks {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct EndpointRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    name: String,
    url: String,
    events: String,
    enabled: bool,
    secret_enc: Vec<u8>,
    previous_secret_enc: Option<Vec<u8>>,
    previous_secret_expires_at: Option<i64>,
    disabled_reason: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<EndpointRow> for WebhookEndpoint {
    type Error = StorageError;

    fn try_from(r: EndpointRow) -> Result<Self, StorageError> {
        let names: Vec<String> = from_json(&r.events, "webhook_endpoint.events")?;
        let events = names
            .iter()
            .map(|n| parse_enum(n, WebhookEventType::parse, "webhook event type"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WebhookEndpoint {
            id: WebhookEndpointId(r.id),
            tenant_id: TenantId(r.tenant_id),
            name: r.name,
            url: r.url,
            events,
            enabled: r.enabled,
            secret_enc: r.secret_enc,
            previous_secret_enc: r.previous_secret_enc,
            previous_secret_expires_at: opt_ms_to_odt(r.previous_secret_expires_at)?,
            disabled_reason: r.disabled_reason,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

struct DeliveryRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    endpoint_id: uuid::Uuid,
    event_type: String,
    payload_json: String,
    attempts: i64,
    next_attempt_at: i64,
    status: String,
    last_http_status: Option<i64>,
    last_error: Option<String>,
    created_at: i64,
    completed_at: Option<i64>,
}

impl TryFrom<DeliveryRow> for WebhookDelivery {
    type Error = StorageError;

    fn try_from(r: DeliveryRow) -> Result<Self, StorageError> {
        Ok(WebhookDelivery {
            id: WebhookDeliveryId(r.id),
            tenant_id: TenantId(r.tenant_id),
            endpoint_id: WebhookEndpointId(r.endpoint_id),
            event_type: parse_enum(&r.event_type, WebhookEventType::parse, "webhook event type")?,
            payload_json: r.payload_json,
            attempts: i64_to_u32(r.attempts, "webhook_delivery.attempts")?,
            next_attempt_at: ms_to_odt(r.next_attempt_at)?,
            status: parse_enum(&r.status, DeliveryStatus::parse, "webhook delivery status")?,
            last_http_status: r
                .last_http_status
                .map(|s| {
                    u16::try_from(s).map_err(|_| {
                        StorageError::Corrupt(format!("webhook_delivery.last_http_status {s}"))
                    })
                })
                .transpose()?,
            last_error: r.last_error,
            created_at: ms_to_odt(r.created_at)?,
            completed_at: opt_ms_to_odt(r.completed_at)?,
        })
    }
}

/// Subscriptions → stored JSON array of wire names.
fn events_json(events: &[WebhookEventType]) -> Result<String, StorageError> {
    let names: Vec<&str> = events.iter().map(|e| e.as_str()).collect();
    to_json(&names, "webhook_endpoint.events")
}

/// Enqueues, on `conn` (the caller's transaction), one `Pending` delivery of `event` per enabled
/// endpoint of `tenant` subscribed to its type, each with a fresh id and
/// `created_at = next_attempt_at = at`. Endpoint ids are selected inside the same transaction.
pub(crate) async fn enqueue_for_event(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    event: &WebhookEvent,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    let event_type = event.event_type.as_str();
    let endpoints = sqlx::query_scalar!(
        r#"SELECT e.id AS "id!: uuid::Uuid" FROM webhook_endpoint e
            WHERE e.tenant_id = ?1 AND e.enabled
              AND EXISTS (SELECT 1 FROM json_each(e.events) j WHERE j.value = ?2)
            ORDER BY e.id"#,
        tenant.0,
        event_type,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(map_err)?;
    let at_ms = odt_to_ms(at);
    for endpoint in endpoints {
        let id = WebhookDeliveryId::new_v7();
        sqlx::query!(
            "INSERT INTO webhook_delivery
                 (id, tenant_id, endpoint_id, event_type, payload_json, attempts, next_attempt_at,
                  status, last_http_status, last_error, created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 'pending', NULL, NULL, ?6, NULL)",
            id.0,
            tenant.0,
            endpoint,
            event_type,
            event.payload_json,
            at_ms,
        )
        .execute(&mut *conn)
        .await
        .map_err(map_err)?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl WebhookRepo for SqliteWebhooks {
    async fn create_endpoint(
        &self,
        tenant: TenantId,
        endpoint: &NewWebhookEndpoint,
    ) -> Result<WebhookEndpoint, StorageError> {
        let events = events_json(&endpoint.events)?;
        let created_at = odt_to_ms(endpoint.created_at);
        sqlx::query!(
            "INSERT INTO webhook_endpoint
                 (id, tenant_id, name, url, events, enabled, secret_enc, previous_secret_enc,
                  previous_secret_expires_at, disabled_reason, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8, ?8)",
            endpoint.id.0,
            tenant.0,
            endpoint.name,
            endpoint.url,
            events,
            endpoint.enabled,
            endpoint.secret_enc,
            created_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(WebhookEndpoint {
            id: endpoint.id,
            tenant_id: tenant,
            name: endpoint.name.clone(),
            url: endpoint.url.clone(),
            events: endpoint.events.clone(),
            enabled: endpoint.enabled,
            secret_enc: endpoint.secret_enc.clone(),
            previous_secret_enc: None,
            previous_secret_expires_at: None,
            disabled_reason: None,
            created_at: endpoint.created_at,
            updated_at: endpoint.created_at,
        })
    }

    async fn get_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        sqlx::query_as!(
            EndpointRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      name AS "name!", url AS "url!", events AS "events!",
                      enabled AS "enabled!: bool", secret_enc AS "secret_enc!",
                      previous_secret_enc AS "previous_secret_enc?",
                      previous_secret_expires_at AS "previous_secret_expires_at?",
                      disabled_reason AS "disabled_reason?", created_at AS "created_at!",
                      updated_at AS "updated_at!"
                 FROM webhook_endpoint WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(WebhookEndpoint::try_from)
        .transpose()
    }

    async fn list_endpoints(&self, tenant: TenantId) -> Result<Vec<WebhookEndpoint>, StorageError> {
        sqlx::query_as!(
            EndpointRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      name AS "name!", url AS "url!", events AS "events!",
                      enabled AS "enabled!: bool", secret_enc AS "secret_enc!",
                      previous_secret_enc AS "previous_secret_enc?",
                      previous_secret_expires_at AS "previous_secret_expires_at?",
                      disabled_reason AS "disabled_reason?", created_at AS "created_at!",
                      updated_at AS "updated_at!"
                 FROM webhook_endpoint WHERE tenant_id = ?1
                ORDER BY name"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(WebhookEndpoint::try_from)
        .collect()
    }

    async fn update_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        update: &WebhookEndpointUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        let events = update.events.as_deref().map(events_json).transpose()?;
        let now_ms = odt_to_ms(now);
        // Re-enabling (`enabled = Some(true)`) clears the disabled reason.
        sqlx::query_as!(
            EndpointRow,
            r#"UPDATE webhook_endpoint
                  SET name = COALESCE(?3, name),
                      url = COALESCE(?4, url),
                      events = COALESCE(?5, events),
                      enabled = COALESCE(?6, enabled),
                      disabled_reason = CASE WHEN ?6 THEN NULL ELSE disabled_reason END,
                      updated_at = ?7
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      name AS "name!", url AS "url!", events AS "events!",
                      enabled AS "enabled!: bool", secret_enc AS "secret_enc!",
                      previous_secret_enc AS "previous_secret_enc?",
                      previous_secret_expires_at AS "previous_secret_expires_at?",
                      disabled_reason AS "disabled_reason?", created_at AS "created_at!",
                      updated_at AS "updated_at!""#,
            tenant.0,
            id.0,
            update.name,
            update.url,
            events,
            update.enabled,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(WebhookEndpoint::try_from)
        .transpose()
    }

    async fn rotate_secret(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        new_secret_enc: &[u8],
        previous_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let expires_ms = odt_to_ms(previous_expires_at);
        let now_ms = odt_to_ms(now);
        // Right-hand sides see the old row: the current secret becomes the previous one.
        let done = sqlx::query!(
            "UPDATE webhook_endpoint
                SET previous_secret_enc = secret_enc, previous_secret_expires_at = ?4,
                    secret_enc = ?3, updated_at = ?5
              WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
            new_secret_enc,
            expires_ms,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn disable_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE webhook_endpoint SET enabled = 0, disabled_reason = ?3, updated_at = ?4
              WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
            reason,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
    ) -> Result<bool, StorageError> {
        // One statement; the deliveries go with it by ON DELETE CASCADE.
        let done = sqlx::query!(
            "DELETE FROM webhook_endpoint WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn claim_due(
        &self,
        owner_lease_until: OffsetDateTime,
        now: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<ClaimedWebhookDelivery>, StorageError> {
        let now_ms = odt_to_ms(now);
        let lease_ms = odt_to_ms(owner_lease_until);
        let limit = i64::from(limit);
        // The lease and the endpoint read run in one transaction on the single writer
        // connection: no other claimer can interleave, and each endpoint is read as of the claim.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let rows = sqlx::query_as!(
            DeliveryRow,
            r#"UPDATE webhook_delivery SET next_attempt_at = ?1
                WHERE id IN (SELECT d.id FROM webhook_delivery d
                               JOIN webhook_endpoint e
                                 ON e.tenant_id = d.tenant_id AND e.id = d.endpoint_id
                              WHERE d.status = 'pending' AND d.next_attempt_at <= ?2
                                AND e.enabled
                              ORDER BY d.next_attempt_at, d.created_at, d.id
                              LIMIT ?3)
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      endpoint_id AS "endpoint_id!: uuid::Uuid", event_type AS "event_type!",
                      payload_json AS "payload_json!", attempts AS "attempts!",
                      next_attempt_at AS "next_attempt_at!", status AS "status!",
                      last_http_status AS "last_http_status?", last_error AS "last_error?",
                      created_at AS "created_at!", completed_at AS "completed_at?""#,
            lease_ms,
            now_ms,
            limit,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        let mut deliveries = rows
            .into_iter()
            .map(WebhookDelivery::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        // RETURNING order is unspecified: oldest first.
        deliveries.sort_by_key(|d| (d.created_at, d.id.0));

        let mut endpoints: HashMap<uuid::Uuid, WebhookEndpoint> = HashMap::new();
        for d in &deliveries {
            if endpoints.contains_key(&d.endpoint_id.0) {
                continue;
            }
            let row = sqlx::query_as!(
                EndpointRow,
                r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                          name AS "name!", url AS "url!", events AS "events!",
                          enabled AS "enabled!: bool", secret_enc AS "secret_enc!",
                          previous_secret_enc AS "previous_secret_enc?",
                          previous_secret_expires_at AS "previous_secret_expires_at?",
                          disabled_reason AS "disabled_reason?", created_at AS "created_at!",
                          updated_at AS "updated_at!"
                     FROM webhook_endpoint WHERE tenant_id = ?1 AND id = ?2"#,
                d.tenant_id.0,
                d.endpoint_id.0,
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(map_err)?;
            endpoints.insert(d.endpoint_id.0, WebhookEndpoint::try_from(row)?);
        }
        tx.commit().await.map_err(map_err)?;
        deliveries
            .into_iter()
            .map(|delivery| {
                let endpoint =
                    endpoints
                        .get(&delivery.endpoint_id.0)
                        .cloned()
                        .ok_or_else(|| {
                            StorageError::Corrupt("claimed delivery without endpoint".to_owned())
                        })?;
                Ok(ClaimedWebhookDelivery { delivery, endpoint })
            })
            .collect()
    }

    async fn complete(
        &self,
        id: WebhookDeliveryId,
        result: &WebhookResult,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let now_ms = odt_to_ms(now);
        let (status, next_attempt_at, http_status, error, completed_at, disable) = match result {
            WebhookResult::Delivered { http_status } => (
                DeliveryStatus::Delivered,
                None,
                Some(*http_status),
                None,
                Some(now_ms),
                false,
            ),
            WebhookResult::Retry {
                next_attempt_at,
                http_status,
                error_class,
            } => (
                DeliveryStatus::Pending,
                Some(*next_attempt_at),
                *http_status,
                Some(*error_class),
                None,
                false,
            ),
            WebhookResult::GiveUp {
                http_status,
                error_class,
            } => (
                DeliveryStatus::Failed,
                None,
                *http_status,
                Some(*error_class),
                Some(now_ms),
                false,
            ),
            WebhookResult::DisableEndpoint { http_status } => (
                DeliveryStatus::Failed,
                None,
                Some(*http_status),
                Some(GONE),
                Some(now_ms),
                true,
            ),
        };
        let status = status.as_str();
        let next_ms = opt_odt_to_ms(next_attempt_at);
        let http_status = http_status.map(i64::from);
        // Only a pending row changes: a completed delivery is final.
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let row = sqlx::query!(
            r#"UPDATE webhook_delivery
                  SET attempts = attempts + 1, status = ?2,
                      next_attempt_at = COALESCE(?3, next_attempt_at),
                      last_http_status = ?4, last_error = ?5, completed_at = ?6
                WHERE id = ?1 AND status = 'pending'
            RETURNING tenant_id AS "tenant_id!: uuid::Uuid",
                      endpoint_id AS "endpoint_id!: uuid::Uuid""#,
            id.0,
            status,
            next_ms,
            http_status,
            error,
            completed_at,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        let Some(row) = row else {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        };
        if disable {
            sqlx::query!(
                "UPDATE webhook_endpoint SET enabled = 0, disabled_reason = ?3, updated_at = ?4
                  WHERE tenant_id = ?1 AND id = ?2",
                row.tenant_id,
                row.endpoint_id,
                GONE,
                now_ms,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn deliveries(
        &self,
        tenant: TenantId,
        endpoint: WebhookEndpointId,
        page: PageRequest,
    ) -> Result<Page<WebhookDelivery>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            DeliveryRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      endpoint_id AS "endpoint_id!: uuid::Uuid", event_type AS "event_type!",
                      payload_json AS "payload_json!", attempts AS "attempts!",
                      next_attempt_at AS "next_attempt_at!", status AS "status!",
                      last_http_status AS "last_http_status?", last_error AS "last_error?",
                      created_at AS "created_at!", completed_at AS "completed_at?"
                 FROM webhook_delivery
                WHERE tenant_id = ?1 AND endpoint_id = ?2 AND (?3 IS NULL OR id < ?3)
                ORDER BY id DESC
                LIMIT ?4"#,
            tenant.0,
            endpoint.0,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(WebhookDelivery::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |d| d.id.0))
    }

    async fn redeliver(
        &self,
        tenant: TenantId,
        id: WebhookDeliveryId,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        let new_id = WebhookDeliveryId::new_v7();
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            DeliveryRow,
            r#"INSERT INTO webhook_delivery
                   (id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                    next_attempt_at, status, last_http_status, last_error, created_at,
                    completed_at)
               SELECT ?3, tenant_id, endpoint_id, event_type, payload_json, 0, ?4, 'pending',
                      NULL, NULL, ?4, NULL
                 FROM webhook_delivery WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      endpoint_id AS "endpoint_id!: uuid::Uuid", event_type AS "event_type!",
                      payload_json AS "payload_json!", attempts AS "attempts!",
                      next_attempt_at AS "next_attempt_at!", status AS "status!",
                      last_http_status AS "last_http_status?", last_error AS "last_error?",
                      created_at AS "created_at!", completed_at AS "completed_at?""#,
            tenant.0,
            id.0,
            new_id.0,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(WebhookDelivery::try_from)
        .transpose()
    }

    async fn enqueue_test(
        &self,
        tenant: TenantId,
        endpoint: WebhookEndpointId,
        event: &WebhookEvent,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        let new_id = WebhookDeliveryId::new_v7();
        let event_type = event.event_type.as_str();
        let now_ms = odt_to_ms(now);
        // Subscriptions are ignored on purpose (the console's "send test event").
        sqlx::query_as!(
            DeliveryRow,
            r#"INSERT INTO webhook_delivery
                   (id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                    next_attempt_at, status, last_http_status, last_error, created_at,
                    completed_at)
               SELECT ?3, tenant_id, id, ?4, ?5, 0, ?6, 'pending', NULL, NULL, ?6, NULL
                 FROM webhook_endpoint WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      endpoint_id AS "endpoint_id!: uuid::Uuid", event_type AS "event_type!",
                      payload_json AS "payload_json!", attempts AS "attempts!",
                      next_attempt_at AS "next_attempt_at!", status AS "status!",
                      last_http_status AS "last_http_status?", last_error AS "last_error?",
                      created_at AS "created_at!", completed_at AS "completed_at?""#,
            tenant.0,
            endpoint.0,
            new_id.0,
            event_type,
            event.payload_json,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(WebhookDelivery::try_from)
        .transpose()
    }
}
