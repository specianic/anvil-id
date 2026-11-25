//! `TenantRepo` on SQLite.

use anvil_core::model::{NewTenant, Tenant, TenantId};
use anvil_core::ports::{StorageError, TenantRepo};
use sqlx::SqlitePool;

use crate::convert::{map_err, ms_to_odt, odt_to_ms};

#[derive(Debug, Clone)]
pub(crate) struct SqliteTenants {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

fn to_tenant(
    id: uuid::Uuid,
    slug: String,
    display_name: String,
    created_at: i64,
) -> Result<Tenant, StorageError> {
    Ok(Tenant {
        id: TenantId(id),
        slug,
        display_name,
        created_at: ms_to_odt(created_at)?,
    })
}

#[async_trait::async_trait]
impl TenantRepo for SqliteTenants {
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError> {
        let created_at = odt_to_ms(tenant.created_at);
        // The UNIQUE index on slug decides conflicts; no pre-check.
        sqlx::query!(
            "INSERT INTO tenant (id, slug, display_name, created_at) VALUES (?1, ?2, ?3, ?4)",
            tenant.id.0,
            tenant.slug,
            tenant.display_name,
            created_at,
        )
        .execute(&self.writer)
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
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      created_at AS "created_at!"
                 FROM tenant WHERE id = ?1"#,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| to_tenant(r.id, r.slug, r.display_name, r.created_at))
            .transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError> {
        let row = sqlx::query!(
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      created_at AS "created_at!"
                 FROM tenant WHERE slug = ?1"#,
            slug,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| to_tenant(r.id, r.slug, r.display_name, r.created_at))
            .transpose()
    }
}
