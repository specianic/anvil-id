//! `ClientRepo` on Postgres.

use anvil_core::model::{
    ApplicationType, BrandingScope, Client, ClientAuthMethod, ClientId, ClientSource, ClientType,
    ClientUpdate, ConsentMode, GrantType, MfaPolicy, NewClient, Page, PageRequest, RevokeReason,
    SecretHash, TenantId, TokenFormat,
};
use anvil_core::ports::{ClientRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{
    enum_from, enum_names, enums_from, fetch_limit, from_json, into_page, map_err, opt_hash,
    to_json,
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
    post_logout_redirect_uris: serde_json::Value,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    allowed_resources: serde_json::Value,
    mfa_policy: Option<String>,
    registration_source: String,
    metadata_expires_at: Option<OffsetDateTime>,
    registration_access_token_hash: Option<Vec<u8>>,
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
            post_logout_redirect_uris: from_json(
                "client.post_logout_redirect_uris",
                self.post_logout_redirect_uris,
            )?,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            allowed_resources: from_json("client.allowed_resources", self.allowed_resources)?,
            mfa_policy: self
                .mfa_policy
                .as_deref()
                .map(|m| enum_from("client.mfa_policy", m, MfaPolicy::parse))
                .transpose()?,
            metadata_expires_at: self.metadata_expires_at,
            registration_access_token_hash: opt_hash(
                "client.registration_access_token_hash",
                self.registration_access_token_hash.as_deref(),
            )?,
            registration_source: enum_from(
                "client.registration_source",
                &self.registration_source,
                ClientSource::parse,
            )?,
            organization: anvil_core::model::OrgClientPolicy::Off,
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
        post_logout_redirect_uris: c.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: c.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: c.backchannel_logout_session_required,
        allowed_resources: c.allowed_resources.clone(),
        mfa_policy: c.mfa_policy,
        metadata_expires_at: c.metadata_expires_at,
        registration_access_token_hash: c.registration_access_token_hash,
        registration_source: c.registration_source,
        organization: c.organization,
    }
}

/// TRANSITIONAL(06-08): the client organization policy needs the 1.0 `client.organization`
/// column; any value but `off` is refused until 06-08 adds it, never silently dropped.
fn refuse_org_policy(
    policy: Option<anvil_core::model::OrgClientPolicy>,
) -> Result<(), StorageError> {
    if policy.is_some_and(|p| p != anvil_core::model::OrgClientPolicy::Off) {
        return Err(StorageError::Unsupported(
            "client organization policy (06-08)",
        ));
    }
    Ok(())
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
    refuse_org_policy(Some(c.organization))?;
    let post_logout = to_json(
        "client.post_logout_redirect_uris",
        &c.post_logout_redirect_uris,
    )?;
    let resources = to_json("client.allowed_resources", &c.allowed_resources)?;
    let secret_hash = c.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
    let grant_types = enum_names(&c.grant_types, GrantType::as_str);
    sqlx::query!(
        "INSERT INTO client
             (id, tenant_id, client_id, name, client_type, application_type, auth_method,
              secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
              token_format, consent_mode, id_token_signed_response_alg, can_introspect,
              created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
              backchannel_logout_session_required, allowed_resources, mfa_policy,
              registration_source, metadata_expires_at, registration_access_token_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                 $18, $18, $19, $20, $21, $22, $23, $24, $25, $26)",
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
        post_logout,
        c.backchannel_logout_uri,
        c.backchannel_logout_session_required,
        resources,
        c.mfa_policy.map(|m| m.as_str()),
        c.registration_source.as_str(),
        c.metadata_expires_at,
        c.registration_access_token_hash
            .as_ref()
            .map(|h| h.as_bytes().as_slice()),
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
                    created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy,
                    registration_source, metadata_expires_at, registration_access_token_hash
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
                    created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy,
                    registration_source, metadata_expires_at, registration_access_token_hash
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
        refuse_org_policy(update.organization)?;
        let post_logout = update
            .post_logout_redirect_uris
            .as_ref()
            .map(|u| to_json("client.post_logout_redirect_uris", u))
            .transpose()?;
        let resources = update
            .allowed_resources
            .as_ref()
            .map(|r| to_json("client.allowed_resources", r))
            .transpose()?;
        let (set_bc_uri, bc_uri) = match &update.backchannel_logout_uri {
            Some(u) => (true, u.clone()),
            None => (false, None),
        };
        let (set_mfa, mfa) = match update.mfa_policy {
            Some(m) => (true, m.map(|m| m.as_str())),
            None => (false, None),
        };
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
        let (set_expiry, expiry) = match update.metadata_expires_at {
            Some(e) => (true, e),
            None => (false, None),
        };
        let (set_rat, rat) = match &update.registration_access_token_hash {
            Some(h) => (true, h.as_ref().map(|h| h.as_bytes().to_vec())),
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
                    post_logout_redirect_uris = COALESCE($16, post_logout_redirect_uris),
                    backchannel_logout_uri =
                      CASE WHEN $17 THEN $18 ELSE backchannel_logout_uri END,
                    backchannel_logout_session_required =
                      COALESCE($19, backchannel_logout_session_required),
                    allowed_resources = COALESCE($20, allowed_resources),
                    mfa_policy = CASE WHEN $21 THEN $22 ELSE mfa_policy END,
                    metadata_expires_at = CASE WHEN $23 THEN $24 ELSE metadata_expires_at END,
                    registration_access_token_hash =
                      CASE WHEN $25 THEN $26 ELSE registration_access_token_hash END,
                    updated_at = $10
              WHERE tenant_id = $1 AND client_id = $2
          RETURNING id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy,
                    registration_source, metadata_expires_at, registration_access_token_hash",
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
            post_logout,
            set_bc_uri,
            bc_uri,
            update.backchannel_logout_session_required,
            resources,
            set_mfa,
            mfa,
            set_expiry,
            expiry,
            set_rat,
            rat,
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
        // The client's branding and preview draft go with it. Its logo becomes unreferenced
        // and is removed by the next `purge_expired`.
        let scope_key = BrandingScope::Client(client_id.to_owned()).scope_key();
        sqlx::query!(
            "DELETE FROM branding WHERE tenant_id = $1 AND scope_key = $2",
            tenant.0,
            scope_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        sqlx::query!(
            "DELETE FROM branding_draft WHERE tenant_id = $1 AND scope_key = $2",
            tenant.0,
            scope_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn upsert_cimd(
        &self,
        tenant: TenantId,
        c: &NewClient,
        metadata_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Client, StorageError> {
        refuse_org_policy(Some(c.organization))?;
        // One statement: insert, or replace the metadata of an existing CIMD client. The
        // conflict update only applies to CIMD rows; for a static or dynamic client holding the
        // `client_id` the WHERE fails, nothing changes and no row comes back (`Conflict`).
        let post_logout = to_json(
            "client.post_logout_redirect_uris",
            &c.post_logout_redirect_uris,
        )?;
        let resources = to_json("client.allowed_resources", &c.allowed_resources)?;
        let secret_hash = c.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
        let grant_types = enum_names(&c.grant_types, GrantType::as_str);
        let rat = c
            .registration_access_token_hash
            .as_ref()
            .map(|h| h.as_bytes().as_slice());
        sqlx::query_as!(
            ClientRow,
            "INSERT INTO client
                 (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                  secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                  token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                  created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                  backchannel_logout_session_required, allowed_resources, mfa_policy,
                  registration_source, metadata_expires_at, registration_access_token_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $18, $19, $20, $21, $22, $23, 'cimd', $24, $25)
             ON CONFLICT (tenant_id, client_id) DO UPDATE
                SET name = EXCLUDED.name,
                    client_type = EXCLUDED.client_type,
                    application_type = EXCLUDED.application_type,
                    auth_method = EXCLUDED.auth_method,
                    secret_hash = EXCLUDED.secret_hash,
                    jwks = EXCLUDED.jwks,
                    redirect_uris = EXCLUDED.redirect_uris,
                    grant_types = EXCLUDED.grant_types,
                    scopes = EXCLUDED.scopes,
                    require_pkce = EXCLUDED.require_pkce,
                    token_format = EXCLUDED.token_format,
                    consent_mode = EXCLUDED.consent_mode,
                    id_token_signed_response_alg = EXCLUDED.id_token_signed_response_alg,
                    can_introspect = EXCLUDED.can_introspect,
                    updated_at = EXCLUDED.updated_at,
                    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
                    backchannel_logout_uri = EXCLUDED.backchannel_logout_uri,
                    backchannel_logout_session_required =
                      EXCLUDED.backchannel_logout_session_required,
                    allowed_resources = EXCLUDED.allowed_resources,
                    mfa_policy = EXCLUDED.mfa_policy,
                    metadata_expires_at = EXCLUDED.metadata_expires_at,
                    registration_access_token_hash = EXCLUDED.registration_access_token_hash
              WHERE client.registration_source = 'cimd'
          RETURNING id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy,
                    registration_source, metadata_expires_at, registration_access_token_hash",
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
            now,
            post_logout,
            c.backchannel_logout_uri,
            c.backchannel_logout_session_required,
            resources,
            c.mfa_policy.map(|m| m.as_str()),
            metadata_expires_at,
            rat,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .ok_or_else(|| {
            StorageError::Conflict(
                "client_id is held by a registered (static or dynamic) client".to_owned(),
            )
        })?
        .into_model()
    }

    async fn get_by_registration_token(
        &self,
        tenant: TenantId,
        client_id: &str,
        token_hash: &SecretHash,
    ) -> Result<Option<Client>, StorageError> {
        sqlx::query_as!(
            ClientRow,
            "SELECT id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    token_format, consent_mode, id_token_signed_response_alg, can_introspect,
                    created_at, updated_at, post_logout_redirect_uris, backchannel_logout_uri,
                    backchannel_logout_session_required, allowed_resources, mfa_policy,
                    registration_source, metadata_expires_at, registration_access_token_hash
               FROM client
              WHERE tenant_id = $1 AND client_id = $2 AND registration_source = 'dynamic'
                AND registration_access_token_hash = $3",
            tenant.0,
            client_id,
            token_hash.as_bytes().as_slice(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(ClientRow::into_model)
        .transpose()
    }

    async fn set_registration_token(
        &self,
        tenant: TenantId,
        client_id: &str,
        token_hash: Option<&SecretHash>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE client SET registration_access_token_hash = $3, updated_at = $4
              WHERE tenant_id = $1 AND client_id = $2",
            tenant.0,
            client_id,
            token_hash.map(|h| h.as_bytes().as_slice()),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}

#[cfg(test)]
mod transitional_tests {
    use super::*;
    use anvil_core::model::OrgClientPolicy;

    #[test]
    fn non_default_org_policy_is_refused() {
        for p in [OrgClientPolicy::Optional, OrgClientPolicy::Required] {
            assert!(matches!(
                refuse_org_policy(Some(p)),
                Err(StorageError::Unsupported(_))
            ));
        }
        assert!(refuse_org_policy(Some(OrgClientPolicy::Off)).is_ok());
        assert!(refuse_org_policy(None).is_ok());
    }
}
