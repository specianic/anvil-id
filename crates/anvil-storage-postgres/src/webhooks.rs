//! `WebhookRepo` on Postgres: per-tenant endpoints and the installation-wide delivery queue, plus
//! [`enqueue_for_event`], called by `AuditRepo::append` inside its transaction.
//!
//! Like the logout delivery queue, concurrent nodes claim disjoint rows with
//! `FOR UPDATE SKIP LOCKED`, and the claim moves each row's `next_attempt_at` to the lease end
//! before the row lock is released, so N stateless nodes never deliver the same row twice within
//! a lease.

use anvil_core::model::{
    DeliveryStatus, NewWebhookEndpoint, Page, PageRequest, TenantId, WebhookDelivery,
    WebhookDeliveryId, WebhookEndpoint, WebhookEndpointId, WebhookEndpointUpdate, WebhookEvent,
    WebhookEventType, WebhookResult,
};
use anvil_core::ports::{ClaimedWebhookDelivery, StorageError, WebhookRepo};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{enum_from, enum_names, enums_from, fetch_limit, into_page, map_err, to_u32};

/// `last_error` and `disabled_reason` written when an endpoint answers 410 Gone.
const GONE: &str = "gone";

#[derive(Debug, Clone)]
pub(crate) struct PgWebhooks {
    pub(crate) pool: PgPool,
}

struct EndpointRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    url: String,
    events: Vec<String>,
    enabled: bool,
    secret_enc: Vec<u8>,
    previous_secret_enc: Option<Vec<u8>>,
    previous_secret_expires_at: Option<OffsetDateTime>,
    disabled_reason: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl EndpointRow {
    fn into_model(self) -> Result<WebhookEndpoint, StorageError> {
        Ok(WebhookEndpoint {
            id: WebhookEndpointId(self.id),
            tenant_id: TenantId(self.tenant_id),
            name: self.name,
            url: self.url,
            events: enums_from(
                "webhook_endpoint.events",
                &self.events,
                WebhookEventType::parse,
            )?,
            enabled: self.enabled,
            secret_enc: self.secret_enc,
            previous_secret_enc: self.previous_secret_enc,
            previous_secret_expires_at: self.previous_secret_expires_at,
            disabled_reason: self.disabled_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct DeliveryRow {
    id: Uuid,
    tenant_id: Uuid,
    endpoint_id: Uuid,
    event_type: String,
    payload_json: String,
    attempts: i32,
    next_attempt_at: OffsetDateTime,
    status: String,
    last_http_status: Option<i32>,
    last_error: Option<String>,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
}

fn http_status(column: &str, value: Option<i32>) -> Result<Option<u16>, StorageError> {
    value
        .map(|v| {
            u16::try_from(v)
                .map_err(|_| StorageError::Corrupt(format!("{column}: out of range {v}")))
        })
        .transpose()
}

impl DeliveryRow {
    fn into_model(self) -> Result<WebhookDelivery, StorageError> {
        Ok(WebhookDelivery {
            id: WebhookDeliveryId(self.id),
            tenant_id: TenantId(self.tenant_id),
            endpoint_id: WebhookEndpointId(self.endpoint_id),
            event_type: enum_from(
                "webhook_delivery.event_type",
                &self.event_type,
                WebhookEventType::parse,
            )?,
            payload_json: self.payload_json,
            attempts: to_u32("webhook_delivery.attempts", self.attempts)?,
            next_attempt_at: self.next_attempt_at,
            status: enum_from(
                "webhook_delivery.status",
                &self.status,
                DeliveryStatus::parse,
            )?,
            last_http_status: http_status(
                "webhook_delivery.last_http_status",
                self.last_http_status,
            )?,
            last_error: self.last_error,
            created_at: self.created_at,
            completed_at: self.completed_at,
        })
    }
}

/// A claimed delivery joined with its endpoint (endpoint columns prefixed `e_`).
struct ClaimedRow {
    id: Uuid,
    tenant_id: Uuid,
    endpoint_id: Uuid,
    event_type: String,
    payload_json: String,
    attempts: i32,
    next_attempt_at: OffsetDateTime,
    status: String,
    last_http_status: Option<i32>,
    last_error: Option<String>,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
    e_name: String,
    e_url: String,
    e_events: Vec<String>,
    e_enabled: bool,
    e_secret_enc: Vec<u8>,
    e_previous_secret_enc: Option<Vec<u8>>,
    e_previous_secret_expires_at: Option<OffsetDateTime>,
    e_disabled_reason: Option<String>,
    e_created_at: OffsetDateTime,
    e_updated_at: OffsetDateTime,
}

impl ClaimedRow {
    fn into_model(self) -> Result<ClaimedWebhookDelivery, StorageError> {
        let endpoint = EndpointRow {
            id: self.endpoint_id,
            tenant_id: self.tenant_id,
            name: self.e_name,
            url: self.e_url,
            events: self.e_events,
            enabled: self.e_enabled,
            secret_enc: self.e_secret_enc,
            previous_secret_enc: self.e_previous_secret_enc,
            previous_secret_expires_at: self.e_previous_secret_expires_at,
            disabled_reason: self.e_disabled_reason,
            created_at: self.e_created_at,
            updated_at: self.e_updated_at,
        }
        .into_model()?;
        let delivery = DeliveryRow {
            id: self.id,
            tenant_id: self.tenant_id,
            endpoint_id: self.endpoint_id,
            event_type: self.event_type,
            payload_json: self.payload_json,
            attempts: self.attempts,
            next_attempt_at: self.next_attempt_at,
            status: self.status,
            last_http_status: self.last_http_status,
            last_error: self.last_error,
            created_at: self.created_at,
            completed_at: self.completed_at,
        }
        .into_model()?;
        Ok(ClaimedWebhookDelivery { delivery, endpoint })
    }
}

/// Enqueues `event` for every enabled endpoint of `tenant` subscribed to its type, on the
/// caller's transaction (module docs of `anvil_core::ports`, "Webhook enqueueing"). Each delivery
/// gets its own UUIDv7 id, generated here after the subscribed endpoints were selected in the same
/// transaction. Returns the number of deliveries queued.
pub(crate) async fn enqueue_for_event(
    conn: &mut sqlx::PgConnection,
    tenant: TenantId,
    event: &WebhookEvent,
    at: OffsetDateTime,
) -> Result<u64, StorageError> {
    let endpoints = sqlx::query_scalar!(
        "SELECT id FROM webhook_endpoint
          WHERE tenant_id = $1 AND enabled AND $2 = ANY (events)
          ORDER BY id",
        tenant.0,
        event.event_type.as_str(),
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(map_err)?;
    if endpoints.is_empty() {
        return Ok(0);
    }
    let ids: Vec<Uuid> = endpoints.iter().map(|_| Uuid::now_v7()).collect();
    let done = sqlx::query!(
        "INSERT INTO webhook_delivery
             (id, tenant_id, endpoint_id, event_type, payload_json, attempts, next_attempt_at,
              status, created_at)
         SELECT d.id, $3, d.endpoint_id, $4, $5, 0, $6, 'pending', $6
           FROM unnest($1::uuid[], $2::uuid[]) AS d (id, endpoint_id)",
        &ids,
        &endpoints,
        tenant.0,
        event.event_type.as_str(),
        event.payload_json,
        at,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    Ok(done.rows_affected())
}

#[async_trait::async_trait]
impl WebhookRepo for PgWebhooks {
    async fn create_endpoint(
        &self,
        tenant: TenantId,
        e: &NewWebhookEndpoint,
    ) -> Result<WebhookEndpoint, StorageError> {
        let events = enum_names(&e.events, WebhookEventType::as_str);
        sqlx::query!(
            "INSERT INTO webhook_endpoint
                 (id, tenant_id, name, url, events, enabled, secret_enc, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
            e.id.0,
            tenant.0,
            e.name,
            e.url,
            &events,
            e.enabled,
            e.secret_enc,
            e.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(WebhookEndpoint {
            id: e.id,
            tenant_id: tenant,
            name: e.name.clone(),
            url: e.url.clone(),
            events: e.events.clone(),
            enabled: e.enabled,
            secret_enc: e.secret_enc.clone(),
            previous_secret_enc: None,
            previous_secret_expires_at: None,
            disabled_reason: None,
            created_at: e.created_at,
            updated_at: e.created_at,
        })
    }

    async fn get_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        sqlx::query_as!(
            EndpointRow,
            "SELECT id, tenant_id, name, url, events, enabled, secret_enc, previous_secret_enc,
                    previous_secret_expires_at, disabled_reason, created_at, updated_at
               FROM webhook_endpoint
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(EndpointRow::into_model)
        .transpose()
    }

    async fn list_endpoints(&self, tenant: TenantId) -> Result<Vec<WebhookEndpoint>, StorageError> {
        sqlx::query_as!(
            EndpointRow,
            "SELECT id, tenant_id, name, url, events, enabled, secret_enc, previous_secret_enc,
                    previous_secret_expires_at, disabled_reason, created_at, updated_at
               FROM webhook_endpoint
              WHERE tenant_id = $1
              ORDER BY name COLLATE \"C\"",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(EndpointRow::into_model)
        .collect()
    }

    async fn update_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
        update: &WebhookEndpointUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookEndpoint>, StorageError> {
        let events = update
            .events
            .as_ref()
            .map(|e| enum_names(e, WebhookEventType::as_str));
        // Re-enabling clears the reason the system disabled the endpoint for.
        sqlx::query_as!(
            EndpointRow,
            "UPDATE webhook_endpoint
                SET name = COALESCE($3, name),
                    url = COALESCE($4, url),
                    events = COALESCE($5, events),
                    enabled = COALESCE($6, enabled),
                    disabled_reason = CASE WHEN $6 IS TRUE THEN NULL ELSE disabled_reason END,
                    updated_at = $7
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, name, url, events, enabled, secret_enc, previous_secret_enc,
                    previous_secret_expires_at, disabled_reason, created_at, updated_at",
            tenant.0,
            id.0,
            update.name,
            update.url,
            events.as_deref(),
            update.enabled,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(EndpointRow::into_model)
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
        // SET expressions see the row as it was before the update, so the current secret moves
        // into previous_secret_enc in the same statement.
        let done = sqlx::query!(
            "UPDATE webhook_endpoint
                SET previous_secret_enc = secret_enc,
                    previous_secret_expires_at = $4,
                    secret_enc = $3,
                    updated_at = $5
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
            new_secret_enc,
            previous_expires_at,
            now,
        )
        .execute(&self.pool)
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
        let done = sqlx::query!(
            "UPDATE webhook_endpoint SET enabled = false, disabled_reason = $3, updated_at = $4
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
            reason,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete_endpoint(
        &self,
        tenant: TenantId,
        id: WebhookEndpointId,
    ) -> Result<bool, StorageError> {
        // Deliveries go by the cascading composite foreign key, in this statement.
        let done = sqlx::query!(
            "DELETE FROM webhook_endpoint WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
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
        // FOR UPDATE OF d SKIP LOCKED: concurrent claimers lock disjoint due rows (the endpoint
        // rows are only read), and the lease moves each claimed row out of the due window before
        // its lock is released. The endpoint is returned as of this statement.
        let mut rows = sqlx::query_as!(
            ClaimedRow,
            "WITH claimed AS (
               UPDATE webhook_delivery
                  SET next_attempt_at = $1
                WHERE id IN (SELECT d.id
                               FROM webhook_delivery d
                               JOIN webhook_endpoint e
                                 ON e.tenant_id = d.tenant_id AND e.id = d.endpoint_id
                              WHERE d.status = 'pending' AND d.next_attempt_at <= $2
                                AND e.enabled
                              ORDER BY d.next_attempt_at, d.id
                              LIMIT $3
                                FOR UPDATE OF d SKIP LOCKED)
            RETURNING id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                      next_attempt_at, status, last_http_status, last_error, created_at,
                      completed_at)
             SELECT c.id AS \"id!\", c.tenant_id AS \"tenant_id!\",
                    c.endpoint_id AS \"endpoint_id!\", c.event_type AS \"event_type!\",
                    c.payload_json AS \"payload_json!\", c.attempts AS \"attempts!\",
                    c.next_attempt_at AS \"next_attempt_at!\", c.status AS \"status!\",
                    c.last_http_status, c.last_error, c.created_at AS \"created_at!\",
                    c.completed_at,
                    e.name AS \"e_name!\", e.url AS \"e_url!\", e.events AS \"e_events!\",
                    e.enabled AS \"e_enabled!\", e.secret_enc AS \"e_secret_enc!\",
                    e.previous_secret_enc AS e_previous_secret_enc,
                    e.previous_secret_expires_at AS e_previous_secret_expires_at,
                    e.disabled_reason AS e_disabled_reason,
                    e.created_at AS \"e_created_at!\", e.updated_at AS \"e_updated_at!\"
               FROM claimed c
               JOIN webhook_endpoint e ON e.tenant_id = c.tenant_id AND e.id = c.endpoint_id",
            owner_lease_until,
            now,
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        // Oldest first (the claim order); every claimed row now has the same lease end.
        rows.sort_by_key(|r| (r.created_at, r.id));
        rows.into_iter().map(ClaimedRow::into_model).collect()
    }

    async fn complete(
        &self,
        id: WebhookDeliveryId,
        result: &WebhookResult,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        // (status, next_attempt_at override, last_http_status, last_error, completed_at)
        let (status, next, http, error, completed_at) = match result {
            WebhookResult::Delivered { http_status } => (
                DeliveryStatus::Delivered,
                None,
                Some(*http_status),
                None,
                Some(now),
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
            ),
            WebhookResult::GiveUp {
                http_status,
                error_class,
            } => (
                DeliveryStatus::Failed,
                None,
                *http_status,
                Some(*error_class),
                Some(now),
            ),
            WebhookResult::DisableEndpoint { http_status } => (
                DeliveryStatus::Failed,
                None,
                Some(*http_status),
                Some(GONE),
                Some(now),
            ),
        };
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // Only a pending row changes: a completed delivery is final.
        let Some(row) = sqlx::query!(
            "UPDATE webhook_delivery
                SET attempts = attempts + 1,
                    status = $2,
                    next_attempt_at = COALESCE($3, next_attempt_at),
                    last_http_status = $4,
                    last_error = $5,
                    completed_at = $6
              WHERE id = $1 AND status = 'pending'
          RETURNING tenant_id, endpoint_id",
            id.0,
            status.as_str(),
            next,
            http.map(i32::from),
            error,
            completed_at,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        else {
            return Ok(false);
        };
        if matches!(result, WebhookResult::DisableEndpoint { .. }) {
            sqlx::query!(
                "UPDATE webhook_endpoint SET enabled = false, disabled_reason = $3, updated_at = $4
                  WHERE tenant_id = $1 AND id = $2",
                row.tenant_id,
                row.endpoint_id,
                GONE,
                now,
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
        let rows = sqlx::query_as!(
            DeliveryRow,
            "SELECT id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                    next_attempt_at, status, last_http_status, last_error, created_at,
                    completed_at
               FROM webhook_delivery
              WHERE tenant_id = $1 AND endpoint_id = $2 AND ($3::uuid IS NULL OR id < $3)
              ORDER BY id DESC
              LIMIT $4",
            tenant.0,
            endpoint.0,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(DeliveryRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |d| d.id.0))
    }

    async fn redeliver(
        &self,
        tenant: TenantId,
        id: WebhookDeliveryId,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        sqlx::query_as!(
            DeliveryRow,
            "INSERT INTO webhook_delivery
                 (id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                  next_attempt_at, status, created_at)
             SELECT $3, tenant_id, endpoint_id, event_type, payload_json, 0, $4, 'pending', $4
               FROM webhook_delivery
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                    next_attempt_at, status, last_http_status, last_error, created_at,
                    completed_at",
            tenant.0,
            id.0,
            Uuid::now_v7(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(DeliveryRow::into_model)
        .transpose()
    }

    async fn enqueue_test(
        &self,
        tenant: TenantId,
        endpoint: WebhookEndpointId,
        event: &WebhookEvent,
        now: OffsetDateTime,
    ) -> Result<Option<WebhookDelivery>, StorageError> {
        sqlx::query_as!(
            DeliveryRow,
            "INSERT INTO webhook_delivery
                 (id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                  next_attempt_at, status, created_at)
             SELECT $3, tenant_id, id, $4, $5, 0, $6, 'pending', $6
               FROM webhook_endpoint
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, endpoint_id, event_type, payload_json, attempts,
                    next_attempt_at, status, last_http_status, last_error, created_at,
                    completed_at",
            tenant.0,
            endpoint.0,
            Uuid::now_v7(),
            event.event_type.as_str(),
            event.payload_json,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(DeliveryRow::into_model)
        .transpose()
    }
}
