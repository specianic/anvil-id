//! `ClientRepo` on Postgres.

use anvil_core::model::{
    ApplicationType, Client, ClientAuthMethod, ClientId, ClientType, ClientUpdate, ConsentMode,
    GrantType, NewClient, Page, PageRequest, RevokeReason, SecretHash, TenantId, TokenFormat,
};
use anvil_core::ports::{ClientRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{
    enum_from, enum_names, enums_from, fetch_limit, into_page, map_err, opt_hash,
};

#[derive(Debug, Clone)]
pub(crate) struct PgClients {
    pub(crate) pool: PgPool,
}

pub(crate) struct ClientRow {
    id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    name: String,
    client_type: String,
    application_type: String,
    auth_method: String,
    secret_hash: Option<Vec<u8>>,
    jwks: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scopes: Vec<String>,
    require_pkce: bool,
    token_format: String,
    consent_mode: String,
    id_token_signed_response_alg: Option<String>,
    can_introspect: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ClientRow {
    fn into_model(self) -> Result<Client, StorageError> {
        Ok(Client {
            id: ClientId(self.id),
            tenant_id: TenantId(self.tenant_id),
            client_id: self.client_id,
            name: self.name,
            client_type: enum_from("client.client_type", &self.client_type, ClientType::parse)?,
            application_type: enum_from(
                "client.application_type",
                &self.application_type,
                ApplicationType::parse,
            )?,
            auth_method: enum_from(
                "client.auth_method",
                &self.auth_method,
                ClientAuthMethod::parse,
            )?,
            secret_hash: opt_hash("client.secret_hash", self.secret_hash.as_deref())?,
            jwks: self.jwks,
            redirect_uris: self.redirect_uris,
            grant_types: enums_from("client.grant_types", &self.grant_types, GrantType::parse)?,
            scopes: self.scopes,
            require_pkce: self.require_pkce,
            token_format: enum_from(
                "client.token_format",
                &self.token_format,
                TokenFormat::parse,
            )?,
            consent_mode: enum_from(
                "client.consent_mode",
                &self.consent_mode,
                ConsentMode::parse,
            )?,
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            can_introspect: self.can_introspect,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The record a successful insert of `c` under `tenant` stores.
pub(crate) fn client_from_new(tenant: TenantId, c: &NewClient) -> Client {
    Client {
        id: c.id,
        tenant_id: tenant,
        client_id: c.client_id.clone(),
        name: c.name.clone(),
        client_type: c.client_type,
        application_type: c.application_type,
        auth_method: c.auth_method,
        secret_hash: c.secret_hash,
        jwks: c.jwks.clone(),
        redirect_uris: c.redirect_uris.clone(),
        grant_types: c.grant_types.clone(),
        scopes: c.scopes.clone(),
        require_pkce: c.require_pkce,
        token_format: c.token_format,
        consent_mode: c.consent_mode,
        id_token_signed_response_alg: c.id_token_signed_response_alg.clone(),
        can_introspect: c.can_introspect,
        created_at: c.created_at,
        updated_at: c.created_at,
    }
}

/// Inserts a client on any executor. `Conflict` on a duplicate (tenant, client_id).
pub(crate) async fn insert_client<'e, E>(
    exec: E,
    tenant: TenantId,
    c: &NewClient,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let secret_hash = c.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
    let grant_types = enum_names(&c.grant_types, GrantType::as_str);
    sqlx::query!(
        "INSERT INTO client
             (id, tenant_id, client_id, name, client_type, application_type, auth_method,
              secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
              token_format, consent_mode, id_token_signed_response_alg, can_introspect,
              created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 $18, $18)",
        c.id.0,
        tenant.0,
        c.client_id,
        c.name,
        c.client_type.as_str(),
        c.application_type.as_str(),
        c.auth_method.as_str(),
        secret_hash,
        c.jwks,
        &c.redirect_uris,
        &grant_types,
        &c.scopes,
        c.require_pkce,
        c.token_format.as_str(),
        c.consent_mode.as_str(),
        c.id_token_signed_response_alg,
        c.can_introspect,
        c.created_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl ClientRepo for PgClients {
    async fn create(&self, tenant: TenantId, client: &NewClient) -> Result<Client, StorageError> {
        insert_client(&self.pool, tenant, client).await?;
        Ok(client_from_new(tenant, client))
    }

    async fn get(&self, tenant: TenantId, client_id: &str) -> Result<Option<Client>, StorageError> {
        sqlx::query_as!(
            ClientRow,
            "SELECT id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at
               FROM client
              WHERE tenant_id = $1 AND client_id = $2",
            tenant.0,
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ClientRow::into_model)
        .transpose()
    }

    async fn list(
        &self,
        tenant: TenantId,
        page: PageRequest,
    ) -> Result<Page<Client>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            ClientRow,
            "SELECT id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at
               FROM client
              WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id > $2)
              ORDER BY id
              LIMIT $3",
            tenant.0,
            page.after,
            fetch_limit(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        let items = rows
            .into_iter()
            .map(ClientRow::into_model)
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
        let grant_types = update
            .grant_types
            .as_ref()
            .map(|g| enum_names(g, GrantType::as_str));
        let (set_jwks, jwks) = match &update.jwks {
            Some(j) => (true, j.clone()),
            None => (false, None),
        };
        let (set_alg, alg) = match &update.id_token_signed_response_alg {
            Some(a) => (true, a.clone()),
            None => (false, None),
        };
        sqlx::query_as!(
            ClientRow,
            "UPDATE client
                SET name = COALESCE($3, name),
                    redirect_uris = COALESCE($4, redirect_uris),
                    grant_types = COALESCE($5, grant_types),
                    scopes = COALESCE($6, scopes),
                    require_pkce = COALESCE($7, require_pkce),
                    jwks = CASE WHEN $8 THEN $9 ELSE jwks END,
                    token_format = COALESCE($11, token_format),
                    consent_mode = COALESCE($12, consent_mode),
                    id_token_signed_response_alg =
                      CASE WHEN $13 THEN $14 ELSE id_token_signed_response_alg END,
                    can_introspect = COALESCE($15, can_introspect),
                    updated_at = $10
              WHERE tenant_id = $1 AND client_id = $2
          RETURNING id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at",
            tenant.0,
            client_id,
            update.name,
            update.redirect_uris.as_deref(),
            grant_types.as_deref(),
            update.scopes.as_deref(),
            update.require_pkce,
            set_jwks,
            jwks,
            now,
            update.token_format.map(|f| f.as_str()),
            update.consent_mode.map(|m| m.as_str()),
            set_alg,
            alg,
            update.can_introspect,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ClientRow::into_model)
        .transpose()
    }

    async fn set_secret_hash(
        &self,
        tenant: TenantId,
        client_id: &str,
        secret_hash: Option<SecretHash>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let secret_hash = secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
        let done = sqlx::query!(
            "UPDATE client SET secret_hash = $3, updated_at = $4
              WHERE tenant_id = $1 AND client_id = $2",
            tenant.0,
            client_id,
            secret_hash,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn delete(&self, tenant: TenantId, client_id: &str) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let done = sqlx::query!(
            "DELETE FROM client WHERE tenant_id = $1 AND client_id = $2",
            tenant.0,
            client_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            return Ok(false);
        }
        // The port passes no timestamp here; use the database clock at the storage contract's
        // millisecond precision.
        sqlx::query!(
            "UPDATE token_family
                SET revoked_at = date_trunc('milliseconds', now()), revoked_reason = $3
              WHERE tenant_id = $1 AND client_id = $2 AND revoked_at IS NULL",
            tenant.0,
            client_id,
            RevokeReason::ClientDeleted.as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }
}
