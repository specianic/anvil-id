//! `FlowRepo` on Postgres.

use anvil_core::model::{AuthRequestId, Flow, FlowId, FlowKind, NewFlow, TenantId};
use anvil_core::ports::{FlowRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::{enum_from, hash, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgFlows {
    pub(crate) pool: PgPool,
}

#[async_trait::async_trait]
impl FlowRepo for PgFlows {
    async fn create(&self, tenant: TenantId, flow: &NewFlow) -> Result<(), StorageError> {
        sqlx::query!(
            "INSERT INTO flow
                 (id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id,
                  created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            flow.id.0,
            tenant.0,
            flow.kind.as_str(),
            flow.state,
            flow.csrf_hash.as_bytes().as_slice(),
            flow.cookie_hash.as_bytes().as_slice(),
            flow.auth_request_id.map(|a| a.0),
            flow.created_at,
            flow.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: TenantId,
        id: FlowId,
        now: OffsetDateTime,
    ) -> Result<Option<Flow>, StorageError> {
        let row = sqlx::query!(
            "SELECT id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id,
                    created_at, expires_at
               FROM flow
              WHERE tenant_id = $1 AND id = $2 AND expires_at > $3",
            tenant.0,
            id.0,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(Flow {
                id: FlowId(r.id),
                tenant_id: TenantId(r.tenant_id),
                kind: enum_from("flow.kind", &r.kind, FlowKind::parse)?,
                state: r.state,
                csrf_hash: hash("flow.csrf_hash", &r.csrf_hash)?,
                cookie_hash: hash("flow.cookie_hash", &r.cookie_hash)?,
                auth_request_id: r.auth_request_id.map(AuthRequestId),
                created_at: r.created_at,
                expires_at: r.expires_at,
            })
        })
        .transpose()
    }

    async fn update_state(
        &self,
        tenant: TenantId,
        id: FlowId,
        state: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE flow SET state = $3
              WHERE tenant_id = $1 AND id = $2 AND expires_at > $4",
            tenant.0,
            id.0,
            state,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, id: FlowId) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM flow WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    // TRANSITIONAL(03-06): Phase 3 methods, implemented with the 0003 migration.
    async fn swap_state(
        &self,
        _tenant: TenantId,
        _id: FlowId,
        _expected: &str,
        _new: &str,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        crate::pending::unsupported("FlowRepo::swap_state")
    }
}
