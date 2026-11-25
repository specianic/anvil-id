//! `TenantRepo` on SQLite.

use anvil_core::model::{NewTenant, Page, PageRequest, Tenant, TenantId, TenantUpdate};
use anvil_core::ports::{StorageError, TenantRepo};
use sqlx::{SqliteConnection, SqlitePool};

use crate::convert::{from_json, into_page, map_err, ms_to_odt, odt_to_ms, to_json};

#[derive(Debug, Clone)]
pub(crate) struct SqliteTenants {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

/// A tenant row as selected by every query below.
pub(crate) struct TenantRow {
    pub(crate) id: uuid::Uuid,
    pub(crate) slug: String,
    pub(crate) display_name: String,
    pub(crate) host: Option<String>,
    pub(crate) settings: String,
    pub(crate) created_at: i64,
}

impl TryFrom<TenantRow> for Tenant {
    type Error = StorageError;

    fn try_from(r: TenantRow) -> Result<Self, StorageError> {
        Ok(Tenant {
            id: TenantId(r.id),
            slug: r.slug,
            display_name: r.display_name,
            host: r.host,
            settings: from_json(&r.settings, "tenant.settings")?,
            created_at: ms_to_odt(r.created_at)?,
        })
    }
}

/// Inserts a tenant on `conn` (a pool connection or an open transaction). The unique indexes on
/// slug and host decide conflicts; no pre-check.
pub(crate) async fn insert_tenant(
    conn: &mut SqliteConnection,
    tenant: &NewTenant,
) -> Result<(), StorageError> {
    let settings = to_json(&tenant.settings, "tenant.settings")?;
    let created_at = odt_to_ms(tenant.created_at);
    sqlx::query!(
        "INSERT INTO tenant (id, slug, display_name, host, settings, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        tenant.id.0,
        tenant.slug,
        tenant.display_name,
        tenant.host,
        settings,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

fn created(tenant: &NewTenant) -> Tenant {
    Tenant {
        id: tenant.id,
        slug: tenant.slug.clone(),
        display_name: tenant.display_name.clone(),
        host: tenant.host.clone(),
        settings: tenant.settings.clone(),
        created_at: tenant.created_at,
    }
}

#[async_trait::async_trait]
impl TenantRepo for SqliteTenants {
    async fn create(&self, tenant: &NewTenant) -> Result<Tenant, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_tenant(&mut conn, tenant).await?;
        Ok(created(tenant))
    }

    async fn get(&self, id: TenantId) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      host AS "host?", settings AS "settings!", created_at AS "created_at!"
                 FROM tenant WHERE id = ?1"#,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Tenant::try_from)
        .transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      host AS "host?", settings AS "settings!", created_at AS "created_at!"
                 FROM tenant WHERE slug = ?1"#,
            slug,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Tenant::try_from)
        .transpose()
    }

    async fn get_by_host(&self, host: &str) -> Result<Option<Tenant>, StorageError> {
        sqlx::query_as!(
            TenantRow,
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      host AS "host?", settings AS "settings!", created_at AS "created_at!"
                 FROM tenant WHERE host = ?1"#,
            host,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Tenant::try_from)
        .transpose()
    }

    async fn list(&self, page: PageRequest) -> Result<Page<Tenant>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            TenantRow,
            r#"SELECT id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      host AS "host?", settings AS "settings!", created_at AS "created_at!"
                 FROM tenant
                WHERE ?1 IS NULL OR id > ?1
                ORDER BY id
                LIMIT ?2"#,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(Tenant::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |t| t.id.0))
    }

    async fn update(
        &self,
        id: TenantId,
        update: &TenantUpdate,
    ) -> Result<Option<Tenant>, StorageError> {
        let set_host = update.host.is_some();
        let host = update.host.clone().flatten();
        let settings = update
            .settings
            .as_ref()
            .map(|s| to_json(s, "tenant.settings"))
            .transpose()?;
        // One statement: a host conflict changes nothing.
        sqlx::query_as!(
            TenantRow,
            r#"UPDATE tenant
                  SET display_name = COALESCE(?2, display_name),
                      host = CASE WHEN ?3 THEN ?4 ELSE host END,
                      settings = COALESCE(?5, settings)
                WHERE id = ?1
            RETURNING id AS "id!: uuid::Uuid", slug AS "slug!", display_name AS "display_name!",
                      host AS "host?", settings AS "settings!", created_at AS "created_at!""#,
            id.0,
            update.display_name,
            set_host,
            host,
            settings,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(Tenant::try_from)
        .transpose()
    }

    async fn delete(&self, id: TenantId) -> Result<bool, StorageError> {
        // Every tenant-scoped table references tenant(id) ON DELETE CASCADE.
        let done = sqlx::query!("DELETE FROM tenant WHERE id = ?1", id.0)
            .execute(&self.writer)
            .await
            .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
