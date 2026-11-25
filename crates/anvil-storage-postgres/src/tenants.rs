//! `TenantRepo` on Postgres.

use anvil_core::model::{NewTenant, Tenant, TenantId};
use anvil_core::ports::{StorageError, TenantRepo};
use sqlx::PgPool;

use crate::convert::map_err;

#[derive(Debug, Clone)]
pub(crate) struct PgTenants {
    pub(crate) pool: PgPool,
}

#[async_trait::async_trait]
impl TenantRepo for PgTenants {
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError> {
        // The UNIQUE index on slug decides conflicts; no pre-check.
        sqlx::query!(
            "INSERT INTO tenant (id, slug, display_name, created_at) VALUES ($1, $2, $3, $4)",
            tenant.id.0,
            tenant.slug,
            tenant.display_name,
            tenant.created_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(Tenant {
            id: tenant.id,
            slug: tenant.slug.clone(),
            display_name: tenant.display_name.clone(),
            created_at: tenant.created_at,
        })
    }

    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError> {
        let row = sqlx::query!(
            "SELECT id, slug, display_name, created_at FROM tenant WHERE id = $1",
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| Tenant {
            id: TenantId(r.id),
            slug: r.slug,
            display_name: r.display_name,
            created_at: r.created_at,
        }))
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError> {
        let row = sqlx::query!(
            "SELECT id, slug, display_name, created_at FROM tenant WHERE slug = $1",
            slug,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| Tenant {
            id: TenantId(r.id),
            slug: r.slug,
            display_name: r.display_name,
            created_at: r.created_at,
        }))
    }
}
