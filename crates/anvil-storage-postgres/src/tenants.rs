//! `TenantRepo` on Postgres.

use anvil_core::model::{NewTenant, Page, PageRequest, Tenant, TenantId, TenantUpdate};
use anvil_core::ports::{StorageError, TenantRepo};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{fetch_limit, from_json, into_page, map_err, to_json};

#[derive(Debug, Clone)]
pub(crate) struct PgTenants {
    pub(crate) pool: PgPool,
}

pub(crate) struct TenantRow {
    pub(crate) id: Uuid,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) host: Option<String>,
    pub(crate) settings: serde_json::Value,
    pub(crate) created_at: OffsetDateTime,
}

impl TenantRow {
    pub(crate) fn into_model(self) -> Result<Tenant, StorageError> {
        Ok(Tenant {
            id: TenantId(self.id),
            slug: self.slug,
            display_name: self.display_name,
            host: self.host,
            settings: from_json("tenant.settings", self.settings)?,
            created_at: self.created_at,
        })
    }
}

/// Inserts a tenant on any executor (pool or transaction). The UNIQUE indexes on slug and host
/// decide conflicts; there is no pre-check.
pub(crate) async fn insert_tenant<'e, E>(exec: E, tenant: &NewTenant) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let settings = to_json("tenant.settings", &tenant.settings)?;
    sqlx::query!(
        "INSERT INTO tenant (id, slug, display_name, host, settings, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
        tenant.id.0,
        tenant.slug,
        tenant.display_name,
        tenant.host,
        settings,
        tenant.created_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

fn tenant_from_new(t: &NewTenant) -> Tenant {
    Tenant {
        id: t.id,
        slug: t.slug.clone(),
        display_name: t.display_name.clone(),
        host: t.host.clone(),
        settings: t.settings.clone(),
        created_at: t.created_at,
    }
}

#[async_trait::async_trait]
impl TenantRepo for PgTenants {
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError> {
        insert_tenant(&self.pool, tenant).await?;
        Ok(tenant_from_new(tenant))
    }

    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            "SELECT id, slug, display_name, host, settings, created_at FROM tenant WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(TenantRow::into_model)
        .transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            "SELECT id, slug, display_name, host, settings, created_at FROM tenant WHERE slug = $1",
            slug,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(TenantRow::into_model)
        .transpose()
    }

    async fn get_by_host(&self, host: &str) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            "SELECT id, slug, display_name, host, settings, created_at FROM tenant WHERE host = $1",
            host,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(TenantRow::into_model)
        .transpose()
    }

    async fn list(&self, page: PageRequest) -> Result<Page<Tenant>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            TenantRow,
            "SELECT id, slug, display_name, host, settings, created_at
               FROM tenant
              WHERE ($1::uuid IS NULL OR id > $1)
              ORDER BY id
              LIMIT $2",
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(TenantRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |t| t.id.0))
    }

    async fn update(
        &self,
        id: TenantId,
        update: &TenantUpdate,
    ) -> Result<Option<Tenant>, StorageError> {
        let settings = update
            .settings
            .as_ref()
            .map(|s| to_json("tenant.settings", s))
            .transpose()?;
        let (set_host, host) = match &update.host {
            Some(h) => (true, h.clone()),
            None => (false, None),
        };
        sqlx::query_as!(
            TenantRow,
            "UPDATE tenant
                SET display_name = COALESCE($2, display_name),
                    host = CASE WHEN $3 THEN $4 ELSE host END,
                    settings = COALESCE($5, settings)
              WHERE id = $1
          RETURNING id, slug, display_name, host, settings, created_at",
            id.0,
            update.display_name,
            set_host,
            host,
            settings,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(TenantRow::into_model)
        .transpose()
    }

    async fn delete(&self, id: TenantId) -> Result<bool, StorageError> {
        // ON DELETE CASCADE removes every row of the tenant.
        let done = sqlx::query!("DELETE FROM tenant WHERE id = $1", id.0)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
