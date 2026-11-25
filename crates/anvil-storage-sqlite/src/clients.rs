//! `ClientRepo` on SQLite.

use anvil_core::model::{
    ApplicationType, Client, ClientAuthMethod, ClientId, ClientType, ClientUpdate, NewClient, Page,
    PageRequest, RevokeReason, SecretHash, TenantId,
};
use anvil_core::ports::{ClientRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    from_json, into_page, map_err, ms_to_odt, now_ms, odt_to_ms, opt_blob_to_hash, parse_enum,
    to_json,
};

#[derive(Debug, Clone)]
pub(crate) struct SqliteClients {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

pub(crate) struct ClientRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    client_id: String,
    name: String,
    client_type: String,
    application_type: String,
    auth_method: String,
    secret_hash: Option<Vec<u8>>,
    jwks: Option<String>,
    redirect_uris: String,
    grant_types: String,
    scopes: String,
    require_pkce: bool,
    created_at: i64,
    updated_at: i64,
}

impl TryFrom<ClientRow> for Client {
    type Error = StorageError;

    fn try_from(r: ClientRow) -> Result<Self, StorageError> {
        Ok(Client {
            id: ClientId(r.id),
            tenant_id: TenantId(r.tenant_id),
            client_id: r.client_id,
            name: r.name,
            client_type: parse_enum(&r.client_type, ClientType::parse, "client_type")?,
            application_type: parse_enum(
                &r.application_type,
                ApplicationType::parse,
                "application_type",
            )?,
            auth_method: parse_enum(&r.auth_method, ClientAuthMethod::parse, "auth_method")?,
            secret_hash: opt_blob_to_hash(r.secret_hash.as_deref(), "client.secret_hash")?,
            jwks: r.jwks,
            redirect_uris: from_json(&r.redirect_uris, "client.redirect_uris")?,
            grant_types: from_json(&r.grant_types, "client.grant_types")?,
            scopes: from_json(&r.scopes, "client.scopes")?,
            require_pkce: r.require_pkce,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

/// Inserts a client on `conn` and returns the stored record. `Conflict` on a duplicate
/// (tenant, client_id) or id.
pub(crate) async fn insert_client(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    client: &NewClient,
) -> Result<Client, StorageError> {
    let client_type = client.client_type.as_str();
    let application_type = client.application_type.as_str();
    let auth_method = client.auth_method.as_str();
    let secret_hash = client.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
    let redirect_uris = to_json(&client.redirect_uris, "client.redirect_uris")?;
    let grant_types = to_json(&client.grant_types, "client.grant_types")?;
    let scopes = to_json(&client.scopes, "client.scopes")?;
    let created_at = odt_to_ms(client.created_at);
    sqlx::query!(
        "INSERT INTO client
             (id, tenant_id, client_id, name, client_type, application_type, auth_method,
              secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce, created_at,
              updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)",
        client.id.0,
        tenant.0,
        client.client_id,
        client.name,
        client_type,
        application_type,
        auth_method,
        secret_hash,
        client.jwks,
        redirect_uris,
        grant_types,
        scopes,
        client.require_pkce,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(Client {
        id: client.id,
        tenant_id: tenant,
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        client_type: client.client_type,
        application_type: client.application_type,
        auth_method: client.auth_method,
        secret_hash: client.secret_hash,
        jwks: client.jwks.clone(),
        redirect_uris: client.redirect_uris.clone(),
        grant_types: client.grant_types.clone(),
        scopes: client.scopes.clone(),
        require_pkce: client.require_pkce,
        created_at: client.created_at,
        updated_at: client.created_at,
    })
}

#[async_trait::async_trait]
impl ClientRepo for SqliteClients {
    async fn create(&self, tenant: TenantId, client: &NewClient) -> Result<Client, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_client(&mut conn, tenant, client).await
    }

    async fn get(&self, tenant: TenantId, client_id: &str) -> Result<Option<Client>, StorageError> {
        sqlx::query_as!(
            ClientRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM client WHERE tenant_id = ?1 AND client_id = ?2"#,
            tenant.0,
            client_id,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Client::try_from)
        .transpose()
    }

    async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Client>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            ClientRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM client
                WHERE tenant_id = ?1 AND (?2 IS NULL OR id > ?2)
                ORDER BY id
                LIMIT ?3"#,
            tenant.0,
            page.after,
            fetch,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(Client::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |c| c.id.0))
    }

    async fn update(
        &self,
        tenant: TenantId,
        client_id: &str,
        update: &ClientUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<Client>, StorageError> {
        let redirect_uris = update
            .redirect_uris
            .as_ref()
            .map(|v| to_json(v, "client.redirect_uris"))
            .transpose()?;
        let grant_types = update
            .grant_types
            .as_ref()
            .map(|v| to_json(v, "client.grant_types"))
            .transpose()?;
        let scopes = update
            .scopes
            .as_ref()
            .map(|v| to_json(v, "client.scopes"))
            .transpose()?;
        let set_jwks = update.jwks.is_some();
        let jwks = update.jwks.clone().flatten();
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            ClientRow,
            r#"UPDATE client
                  SET name = COALESCE(?3, name),
                      redirect_uris = COALESCE(?4, redirect_uris),
                      grant_types = COALESCE(?5, grant_types),
                      scopes = COALESCE(?6, scopes),
                      require_pkce = COALESCE(?7, require_pkce),
                      jwks = CASE WHEN ?8 THEN ?9 ELSE jwks END,
                      updated_at = ?10
                WHERE tenant_id = ?1 AND client_id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!""#,
            tenant.0,
            client_id,
            update.name,
            redirect_uris,
            grant_types,
            scopes,
            update.require_pkce,
            set_jwks,
            jwks,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(Client::try_from)
        .transpose()
    }

    async fn set_secret_hash(
        &self,
        tenant: TenantId,
        client_id: &str,
        secret_hash: Option<SecretHash>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let hash = secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE client SET secret_hash = ?3, updated_at = ?4
              WHERE tenant_id = ?1 AND client_id = ?2",
            tenant.0,
            client_id,
            hash,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, client_id: &str) -> Result<bool, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "DELETE FROM client WHERE tenant_id = ?1 AND client_id = ?2",
            tenant.0,
            client_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        }
        let reason = RevokeReason::ClientDeleted.as_str();
        let revoked_at = odt_to_ms(now_ms());
        sqlx::query!(
            "UPDATE token_family SET revoked_at = ?3, revoked_reason = ?4
              WHERE tenant_id = ?1 AND client_id = ?2 AND revoked_at IS NULL",
            tenant.0,
            client_id,
            revoked_at,
            reason,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }
}
