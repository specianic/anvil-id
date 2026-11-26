//! `ClientRepo` on SQLite.

use anvil_core::model::{
    ApplicationType, BrandingScope, Client, ClientAuthMethod, ClientId, ClientSource, ClientType,
    ClientUpdate, ConsentMode, MfaPolicy, NewClient, Page, PageRequest, RevokeReason, SecretHash,
    TenantId, TokenFormat,
};
use anvil_core::ports::{ClientRepo, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    from_json, into_page, map_err, ms_to_odt, now_ms, odt_to_ms, opt_blob_to_hash, opt_ms_to_odt,
    opt_odt_to_ms, parse_enum, to_json,
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
    token_format: String,
    consent_mode: String,
    id_token_signed_response_alg: Option<String>,
    can_introspect: bool,
    created_at: i64,
    updated_at: i64,
    post_logout_redirect_uris: String,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    allowed_resources: String,
    mfa_policy: Option<String>,
    registration_source: String,
    metadata_expires_at: Option<i64>,
    registration_access_token_hash: Option<Vec<u8>>,
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
            token_format: parse_enum(&r.token_format, TokenFormat::parse, "token_format")?,
            consent_mode: parse_enum(&r.consent_mode, ConsentMode::parse, "consent_mode")?,
            id_token_signed_response_alg: r.id_token_signed_response_alg,
            can_introspect: r.can_introspect,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
            post_logout_redirect_uris: from_json(
                &r.post_logout_redirect_uris,
                "client.post_logout_redirect_uris",
            )?,
            backchannel_logout_uri: r.backchannel_logout_uri,
            backchannel_logout_session_required: r.backchannel_logout_session_required,
            allowed_resources: from_json(&r.allowed_resources, "client.allowed_resources")?,
            mfa_policy: r
                .mfa_policy
                .as_deref()
                .map(|p| parse_enum(p, MfaPolicy::parse, "client.mfa_policy"))
                .transpose()?,
            registration_source: parse_enum(
                &r.registration_source,
                ClientSource::parse,
                "client.registration_source",
            )?,
            metadata_expires_at: opt_ms_to_odt(r.metadata_expires_at)?,
            registration_access_token_hash: opt_blob_to_hash(
                r.registration_access_token_hash.as_deref(),
                "client.registration_access_token_hash",
            )?,
            organization: anvil_core::model::OrgClientPolicy::Off,
        })
    }
}

/// TRANSITIONAL(06-07): the client organization policy needs the 1.0 `client.organization`
/// column; any value but `off` is refused until 06-07 adds it, never silently dropped.
fn refuse_org_policy(
    policy: Option<anvil_core::model::OrgClientPolicy>,
) -> Result<(), StorageError> {
    if policy.is_some_and(|p| p != anvil_core::model::OrgClientPolicy::Off) {
        return Err(StorageError::Unsupported(
            "client organization policy (06-07)",
        ));
    }
    Ok(())
}

/// Inserts a client on `conn` and returns the stored record. `Conflict` on a duplicate
/// (tenant, client_id) or id.
pub(crate) async fn insert_client(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    client: &NewClient,
) -> Result<Client, StorageError> {
    refuse_org_policy(Some(client.organization))?;
    let client_type = client.client_type.as_str();
    let application_type = client.application_type.as_str();
    let auth_method = client.auth_method.as_str();
    let secret_hash = client.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
    let redirect_uris = to_json(&client.redirect_uris, "client.redirect_uris")?;
    let grant_types = to_json(&client.grant_types, "client.grant_types")?;
    let scopes = to_json(&client.scopes, "client.scopes")?;
    let token_format = client.token_format.as_str();
    let consent_mode = client.consent_mode.as_str();
    let post_logout = to_json(
        &client.post_logout_redirect_uris,
        "client.post_logout_redirect_uris",
    )?;
    let allowed_resources = to_json(&client.allowed_resources, "client.allowed_resources")?;
    let mfa_policy = client.mfa_policy.map(|p| p.as_str());
    let created_at = odt_to_ms(client.created_at);
    let registration_source = client.registration_source.as_str();
    let metadata_expires_at = opt_odt_to_ms(client.metadata_expires_at);
    let registration_token = client
        .registration_access_token_hash
        .as_ref()
        .map(|h| h.as_bytes().as_slice());
    sqlx::query!(
        "INSERT INTO client
             (id, tenant_id, client_id, name, client_type, application_type, auth_method,
              secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce, created_at,
              updated_at, token_format, consent_mode, id_token_signed_response_alg,
              can_introspect, post_logout_redirect_uris, backchannel_logout_uri,
              backchannel_logout_session_required, allowed_resources, mfa_policy,
              registration_source, metadata_expires_at, registration_access_token_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14, ?15, ?16, ?17,
                 ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)",
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
        token_format,
        consent_mode,
        client.id_token_signed_response_alg,
        client.can_introspect,
        post_logout,
        client.backchannel_logout_uri,
        client.backchannel_logout_session_required,
        allowed_resources,
        mfa_policy,
        registration_source,
        metadata_expires_at,
        registration_token,
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
        token_format: client.token_format,
        consent_mode: client.consent_mode,
        id_token_signed_response_alg: client.id_token_signed_response_alg.clone(),
        can_introspect: client.can_introspect,
        created_at: client.created_at,
        updated_at: client.created_at,
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        allowed_resources: client.allowed_resources.clone(),
        mfa_policy: client.mfa_policy,
        registration_source: client.registration_source,
        metadata_expires_at: client.metadata_expires_at,
        registration_access_token_hash: client.registration_access_token_hash,
        organization: client.organization,
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
                      token_format AS "token_format!", consent_mode AS "consent_mode!",
                      id_token_signed_response_alg AS "id_token_signed_response_alg?",
                      can_introspect AS "can_introspect!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      post_logout_redirect_uris AS "post_logout_redirect_uris!",
                      backchannel_logout_uri AS "backchannel_logout_uri?",
                      backchannel_logout_session_required
                        AS "backchannel_logout_session_required!: bool",
                      allowed_resources AS "allowed_resources!",
                      mfa_policy AS "mfa_policy?",
                      registration_source AS "registration_source!",
                      metadata_expires_at AS "metadata_expires_at?",
                      registration_access_token_hash AS "registration_access_token_hash?"
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
                      token_format AS "token_format!", consent_mode AS "consent_mode!",
                      id_token_signed_response_alg AS "id_token_signed_response_alg?",
                      can_introspect AS "can_introspect!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      post_logout_redirect_uris AS "post_logout_redirect_uris!",
                      backchannel_logout_uri AS "backchannel_logout_uri?",
                      backchannel_logout_session_required
                        AS "backchannel_logout_session_required!: bool",
                      allowed_resources AS "allowed_resources!",
                      mfa_policy AS "mfa_policy?",
                      registration_source AS "registration_source!",
                      metadata_expires_at AS "metadata_expires_at?",
                      registration_access_token_hash AS "registration_access_token_hash?"
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
        refuse_org_policy(update.organization)?;
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
        let token_format = update.token_format.map(|f| f.as_str());
        let consent_mode = update.consent_mode.map(|m| m.as_str());
        let set_alg = update.id_token_signed_response_alg.is_some();
        let alg = update.id_token_signed_response_alg.clone().flatten();
        let post_logout = update
            .post_logout_redirect_uris
            .as_ref()
            .map(|v| to_json(v, "client.post_logout_redirect_uris"))
            .transpose()?;
        let set_bc_uri = update.backchannel_logout_uri.is_some();
        let bc_uri = update.backchannel_logout_uri.clone().flatten();
        let allowed_resources = update
            .allowed_resources
            .as_ref()
            .map(|v| to_json(v, "client.allowed_resources"))
            .transpose()?;
        let set_mfa = update.mfa_policy.is_some();
        let mfa_policy = update.mfa_policy.flatten().map(|p| p.as_str());
        let set_expiry = update.metadata_expires_at.is_some();
        let expiry = opt_odt_to_ms(update.metadata_expires_at.flatten());
        let set_reg_token = update.registration_access_token_hash.is_some();
        let reg_token = update
            .registration_access_token_hash
            .flatten()
            .map(|h| h.as_bytes().to_vec());
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
                      updated_at = ?10,
                      token_format = COALESCE(?11, token_format),
                      consent_mode = COALESCE(?12, consent_mode),
                      id_token_signed_response_alg =
                        CASE WHEN ?13 THEN ?14 ELSE id_token_signed_response_alg END,
                      can_introspect = COALESCE(?15, can_introspect),
                      post_logout_redirect_uris = COALESCE(?16, post_logout_redirect_uris),
                      backchannel_logout_uri =
                        CASE WHEN ?17 THEN ?18 ELSE backchannel_logout_uri END,
                      backchannel_logout_session_required =
                        COALESCE(?19, backchannel_logout_session_required),
                      allowed_resources = COALESCE(?20, allowed_resources),
                      mfa_policy = CASE WHEN ?21 THEN ?22 ELSE mfa_policy END,
                      metadata_expires_at =
                        CASE WHEN ?23 THEN ?24 ELSE metadata_expires_at END,
                      registration_access_token_hash =
                        CASE WHEN ?25 THEN ?26 ELSE registration_access_token_hash END
                WHERE tenant_id = ?1 AND client_id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      token_format AS "token_format!", consent_mode AS "consent_mode!",
                      id_token_signed_response_alg AS "id_token_signed_response_alg?",
                      can_introspect AS "can_introspect!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      post_logout_redirect_uris AS "post_logout_redirect_uris!",
                      backchannel_logout_uri AS "backchannel_logout_uri?",
                      backchannel_logout_session_required
                        AS "backchannel_logout_session_required!: bool",
                      allowed_resources AS "allowed_resources!",
                      mfa_policy AS "mfa_policy?",
                      registration_source AS "registration_source!",
                      metadata_expires_at AS "metadata_expires_at?",
                      registration_access_token_hash AS "registration_access_token_hash?""#,
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
            token_format,
            consent_mode,
            set_alg,
            alg,
            update.can_introspect,
            post_logout,
            set_bc_uri,
            bc_uri,
            update.backchannel_logout_session_required,
            allowed_resources,
            set_mfa,
            mfa_policy,
            set_expiry,
            expiry,
            set_reg_token,
            reg_token,
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
        // The client's branding goes with it; the draft lives in columns of the same row. Its
        // logo becomes unreferenced and is removed by the next `purge_expired`.
        let scope_key = BrandingScope::Client(client_id.to_owned()).scope_key();
        sqlx::query!(
            "DELETE FROM branding WHERE tenant_id = ?1 AND scope_key = ?2",
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
        client: &NewClient,
        metadata_expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Client, StorageError> {
        refuse_org_policy(Some(client.organization))?;
        let client_type = client.client_type.as_str();
        let application_type = client.application_type.as_str();
        let auth_method = client.auth_method.as_str();
        let secret_hash = client.secret_hash.as_ref().map(|h| h.as_bytes().as_slice());
        let redirect_uris = to_json(&client.redirect_uris, "client.redirect_uris")?;
        let grant_types = to_json(&client.grant_types, "client.grant_types")?;
        let scopes = to_json(&client.scopes, "client.scopes")?;
        let token_format = client.token_format.as_str();
        let consent_mode = client.consent_mode.as_str();
        let post_logout = to_json(
            &client.post_logout_redirect_uris,
            "client.post_logout_redirect_uris",
        )?;
        let allowed_resources = to_json(&client.allowed_resources, "client.allowed_resources")?;
        let mfa_policy = client.mfa_policy.map(|p| p.as_str());
        let registration_token = client
            .registration_access_token_hash
            .as_ref()
            .map(|h| h.as_bytes().as_slice());
        let expires_ms = odt_to_ms(metadata_expires_at);
        let now_ms = odt_to_ms(now);
        // One statement: insert, or replace the metadata of an existing CIMD client (row id,
        // client_id and created_at kept). The DO UPDATE's WHERE leaves a static or dynamic
        // client untouched; then no row is returned and the call is a Conflict.
        let row = sqlx::query_as!(
            ClientRow,
            r#"INSERT INTO client
                   (id, tenant_id, client_id, name, client_type, application_type, auth_method,
                    secret_hash, jwks, redirect_uris, grant_types, scopes, require_pkce,
                    created_at, updated_at, token_format, consent_mode,
                    id_token_signed_response_alg, can_introspect, post_logout_redirect_uris,
                    backchannel_logout_uri, backchannel_logout_session_required,
                    allowed_resources, mfa_policy, registration_source, metadata_expires_at,
                    registration_access_token_hash)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14, ?15,
                       ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, 'cimd', ?24, ?25)
               ON CONFLICT (tenant_id, client_id) DO UPDATE
                  SET name = excluded.name,
                      client_type = excluded.client_type,
                      application_type = excluded.application_type,
                      auth_method = excluded.auth_method,
                      secret_hash = excluded.secret_hash,
                      jwks = excluded.jwks,
                      redirect_uris = excluded.redirect_uris,
                      grant_types = excluded.grant_types,
                      scopes = excluded.scopes,
                      require_pkce = excluded.require_pkce,
                      updated_at = excluded.updated_at,
                      token_format = excluded.token_format,
                      consent_mode = excluded.consent_mode,
                      id_token_signed_response_alg = excluded.id_token_signed_response_alg,
                      can_introspect = excluded.can_introspect,
                      post_logout_redirect_uris = excluded.post_logout_redirect_uris,
                      backchannel_logout_uri = excluded.backchannel_logout_uri,
                      backchannel_logout_session_required =
                        excluded.backchannel_logout_session_required,
                      allowed_resources = excluded.allowed_resources,
                      mfa_policy = excluded.mfa_policy,
                      metadata_expires_at = excluded.metadata_expires_at,
                      registration_access_token_hash = excluded.registration_access_token_hash
                WHERE client.registration_source = 'cimd'
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      token_format AS "token_format!", consent_mode AS "consent_mode!",
                      id_token_signed_response_alg AS "id_token_signed_response_alg?",
                      can_introspect AS "can_introspect!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      post_logout_redirect_uris AS "post_logout_redirect_uris!",
                      backchannel_logout_uri AS "backchannel_logout_uri?",
                      backchannel_logout_session_required
                        AS "backchannel_logout_session_required!: bool",
                      allowed_resources AS "allowed_resources!",
                      mfa_policy AS "mfa_policy?",
                      registration_source AS "registration_source!",
                      metadata_expires_at AS "metadata_expires_at?",
                      registration_access_token_hash AS "registration_access_token_hash?""#,
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
            now_ms,
            token_format,
            consent_mode,
            client.id_token_signed_response_alg,
            client.can_introspect,
            post_logout,
            client.backchannel_logout_uri,
            client.backchannel_logout_session_required,
            allowed_resources,
            mfa_policy,
            expires_ms,
            registration_token,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?;
        match row {
            Some(row) => Client::try_from(row),
            None => Err(StorageError::Conflict(
                "client_id is held by a registered (non-CIMD) client".to_owned(),
            )),
        }
    }

    async fn get_by_registration_token(
        &self,
        tenant: TenantId,
        client_id: &str,
        token_hash: &SecretHash,
    ) -> Result<Option<Client>, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        sqlx::query_as!(
            ClientRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", name AS "name!", client_type AS "client_type!",
                      application_type AS "application_type!", auth_method AS "auth_method!",
                      secret_hash AS "secret_hash?", jwks AS "jwks?",
                      redirect_uris AS "redirect_uris!", grant_types AS "grant_types!",
                      scopes AS "scopes!", require_pkce AS "require_pkce!: bool",
                      token_format AS "token_format!", consent_mode AS "consent_mode!",
                      id_token_signed_response_alg AS "id_token_signed_response_alg?",
                      can_introspect AS "can_introspect!: bool",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      post_logout_redirect_uris AS "post_logout_redirect_uris!",
                      backchannel_logout_uri AS "backchannel_logout_uri?",
                      backchannel_logout_session_required
                        AS "backchannel_logout_session_required!: bool",
                      allowed_resources AS "allowed_resources!",
                      mfa_policy AS "mfa_policy?",
                      registration_source AS "registration_source!",
                      metadata_expires_at AS "metadata_expires_at?",
                      registration_access_token_hash AS "registration_access_token_hash?"
                 FROM client
                WHERE tenant_id = ?1 AND client_id = ?2 AND registration_source = 'dynamic'
                  AND registration_access_token_hash = ?3"#,
            tenant.0,
            client_id,
            hash,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Client::try_from)
        .transpose()
    }

    async fn set_registration_token(
        &self,
        tenant: TenantId,
        client_id: &str,
        token_hash: Option<&SecretHash>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let hash = token_hash.map(|h| h.as_bytes().as_slice());
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE client SET registration_access_token_hash = ?3, updated_at = ?4
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
