//! `FlowRepo` on SQLite.

use anvil_core::model::{AuthRequestId, Flow, FlowId, FlowKind, NewFlow, TenantId};
use anvil_core::ports::{FlowRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{blob_to_hash, map_err, ms_to_odt, odt_to_ms, parse_enum};

#[derive(Debug, Clone)]
pub(crate) struct SqliteFlows {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

#[async_trait::async_trait]
impl FlowRepo for SqliteFlows {
    async fn create(&self, tenant: TenantId, flow: &NewFlow) -> Result<(), StorageError> {
        let kind = flow.kind.as_str();
        let csrf = flow.csrf_hash.as_bytes().as_slice();
        let cookie = flow.cookie_hash.as_bytes().as_slice();
        let auth_request_id = flow.auth_request_id.map(|a| a.0);
        let created_at = odt_to_ms(flow.created_at);
        let expires_at = odt_to_ms(flow.expires_at);
        sqlx::query!(
            "INSERT INTO flow
                 (id, tenant_id, kind, state, csrf_hash, cookie_hash, auth_request_id, created_at,
                  expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            flow.id.0,
            tenant.0,
            kind,
            flow.state,
            csrf,
            cookie,
            auth_request_id,
            created_at,
            expires_at,
        )
        .execute(&self.writer)
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
        let now_ms = odt_to_ms(now);
        let row = sqlx::query!(
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      kind AS "kind!", state AS "state!", csrf_hash AS "csrf_hash!",
                      cookie_hash AS "cookie_hash!",
                      auth_request_id AS "auth_request_id?: uuid::Uuid",
                      created_at AS "created_at!", expires_at AS "expires_at!"
                 FROM flow WHERE tenant_id = ?1 AND id = ?2 AND expires_at > ?3"#,
            tenant.0,
            id.0,
            now_ms,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(Flow {
                id: FlowId(r.id),
                tenant_id: TenantId(r.tenant_id),
                kind: parse_enum(&r.kind, FlowKind::parse, "flow kind")?,
                state: r.state,
                csrf_hash: blob_to_hash(&r.csrf_hash, "flow.csrf_hash")?,
                cookie_hash: blob_to_hash(&r.cookie_hash, "flow.cookie_hash")?,
                auth_request_id: r.auth_request_id.map(AuthRequestId),
                created_at: ms_to_odt(r.created_at)?,
                expires_at: ms_to_odt(r.expires_at)?,
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
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE flow SET state = ?3 WHERE tenant_id = ?1 AND id = ?2 AND expires_at > ?4",
            tenant.0,
            id.0,
            state,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, id: FlowId) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM flow WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
