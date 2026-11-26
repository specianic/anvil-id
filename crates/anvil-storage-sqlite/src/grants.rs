//! `GrantRepo` on SQLite: authorization requests, codes, token families, refresh tokens and
//! replay guards.

use anvil_core::model::{
    AccessTokenRecord, AuthRequestId, AuthorizationCode, AuthorizationRequest, CodeHash,
    ConsentGrant, NewAccessToken, NewAuthorizationCode, NewAuthorizationRequest, NewConsent,
    NewRefreshToken, NewTokenFamily, OrgId, RefreshToken, ReplayKind, RevokeReason, SecretHash,
    SessionId, TenantId, TokenFamily, TokenFamilyId, UserId,
};
use anvil_core::ports::{ConsumeOutcome, GrantRepo, JtiOutcome, RotateOutcome, StorageError};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::consent;
use crate::convert::{
    blob_to_hash, from_json, map_err, ms_to_odt, odt_to_ms, opt_blob_to_hash, opt_from_json,
    opt_ms_to_odt, opt_odt_to_ms, parse_enum, to_json,
};
use crate::logout::record_rp_session;

#[derive(Debug, Clone)]
pub(crate) struct SqliteGrants {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct FamilyRow {
    id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    client_id: String,
    user_id: Option<uuid::Uuid>,
    scope: String,
    auth_time: Option<i64>,
    acr: Option<String>,
    amr: String,
    session_id: Option<uuid::Uuid>,
    claims: Option<String>,
    created_at: i64,
    absolute_expires_at: i64,
    revoked_at: Option<i64>,
    revoked_reason: Option<String>,
    resource: String,
    org_id: Option<uuid::Uuid>,
}

impl TryFrom<FamilyRow> for TokenFamily {
    type Error = StorageError;

    fn try_from(r: FamilyRow) -> Result<Self, StorageError> {
        Ok(TokenFamily {
            id: TokenFamilyId(r.id),
            tenant_id: TenantId(r.tenant_id),
            client_id: r.client_id,
            user_id: r.user_id.map(UserId),
            scope: r.scope,
            auth_time: opt_ms_to_odt(r.auth_time)?,
            acr: r.acr,
            amr: from_json(&r.amr, "token_family.amr")?,
            session_id: r.session_id.map(SessionId),
            claims: opt_from_json(r.claims.as_deref(), "token_family.claims")?,
            created_at: ms_to_odt(r.created_at)?,
            absolute_expires_at: ms_to_odt(r.absolute_expires_at)?,
            revoked_at: opt_ms_to_odt(r.revoked_at)?,
            revoked_reason: r
                .revoked_reason
                .as_deref()
                .map(|s| parse_enum(s, RevokeReason::parse, "revoked_reason"))
                .transpose()?,
            resource: from_json(&r.resource, "token_family.resource")?,
            org_id: r.org_id.map(OrgId),
        })
    }
}

/// Reads a family on `conn` (used inside transactions on the writer).
async fn family_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    id: uuid::Uuid,
) -> Result<Option<TokenFamily>, StorageError> {
    sqlx::query_as!(
        FamilyRow,
        r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                  client_id AS "client_id!", user_id AS "user_id?: uuid::Uuid", scope AS "scope!",
                  auth_time AS "auth_time?", acr AS "acr?", amr AS "amr!",
                  session_id AS "session_id?: uuid::Uuid", claims AS "claims?",
                  created_at AS "created_at!", absolute_expires_at AS "absolute_expires_at!",
                  revoked_at AS "revoked_at?", revoked_reason AS "revoked_reason?",
                  resource AS "resource!", org_id AS "org_id?: uuid::Uuid"
             FROM token_family WHERE tenant_id = ?1 AND id = ?2"#,
        tenant.0,
        id,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?
    .map(TokenFamily::try_from)
    .transpose()
}

/// Revokes a family on `conn` unless already revoked (the first time and reason are kept).
/// Returns whether the family exists in `tenant`.
async fn revoke_family_on(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    id: uuid::Uuid,
    reason: RevokeReason,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let reason = reason.as_str();
    let now_ms = odt_to_ms(now);
    sqlx::query!(
        "UPDATE token_family SET revoked_at = ?3, revoked_reason = ?4
          WHERE tenant_id = ?1 AND id = ?2 AND revoked_at IS NULL",
        tenant.0,
        id,
        now_ms,
        reason,
    )
    .execute(&mut *conn)
    .await
    .map_err(map_err)?;
    let row = sqlx::query!(
        r#"SELECT EXISTS(SELECT 1 FROM token_family WHERE tenant_id = ?1 AND id = ?2)
                  AS "exists!: bool""#,
        tenant.0,
        id,
    )
    .fetch_one(conn)
    .await
    .map_err(map_err)?;
    Ok(row.exists)
}

/// Inserts a token family on `conn`. `Conflict` on a duplicate id.
async fn insert_family(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    family: &NewTokenFamily,
) -> Result<(), StorageError> {
    let amr = to_json(&family.amr, "token_family.amr")?;
    let resource = to_json(&family.resource, "token_family.resource")?;
    let claims = family
        .claims
        .as_ref()
        .map(|c| to_json(c, "token_family.claims"))
        .transpose()?;
    let user = family.user_id.map(|u| u.0);
    let session = family.session_id.map(|s| s.0);
    let auth_time = opt_odt_to_ms(family.auth_time);
    let created_at = odt_to_ms(family.created_at);
    let absolute = odt_to_ms(family.absolute_expires_at);
    let org_id = family.org_id.map(|o| o.0);
    sqlx::query!(
        "INSERT INTO token_family
             (id, tenant_id, client_id, user_id, scope, auth_time, acr, amr, session_id,
              claims, created_at, absolute_expires_at, revoked_at, revoked_reason, resource,
              org_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL, ?13, ?14)",
        family.id.0,
        tenant.0,
        family.client_id,
        user,
        family.scope,
        auth_time,
        family.acr,
        amr,
        session,
        claims,
        created_at,
        absolute,
        resource,
        org_id,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Inserts a refresh token on `conn`. `Conflict` on a duplicate hash.
async fn insert_refresh(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    token: &NewRefreshToken,
) -> Result<(), StorageError> {
    let hash = token.token_hash.as_bytes().as_slice();
    let parent = token.parent_hash.as_ref().map(|h| h.as_bytes().as_slice());
    let created_at = odt_to_ms(token.created_at);
    let expires_at = odt_to_ms(token.expires_at);
    sqlx::query!(
        "INSERT INTO refresh_token
             (token_hash, tenant_id, family_id, parent_hash, scope, created_at, expires_at,
              consumed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        hash,
        tenant.0,
        token.family_id.0,
        parent,
        token.scope,
        created_at,
        expires_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl GrantRepo for SqliteGrants {
    async fn create_authorization_request(
        &self,
        tenant: TenantId,
        request: &NewAuthorizationRequest,
    ) -> Result<(), StorageError> {
        let params = to_json(&request.params, "authorization_request.params")?;
        let created_at = odt_to_ms(request.created_at);
        let expires_at = odt_to_ms(request.expires_at);
        sqlx::query!(
            "INSERT INTO authorization_request
                 (id, tenant_id, client_id, params, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            request.id.0,
            tenant.0,
            request.client_id,
            params,
            created_at,
            expires_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationRequest>, StorageError> {
        let now_ms = odt_to_ms(now);
        let row = sqlx::query!(
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      client_id AS "client_id!", params AS "params!",
                      created_at AS "created_at!", expires_at AS "expires_at!"
                 FROM authorization_request
                WHERE tenant_id = ?1 AND id = ?2 AND expires_at > ?3"#,
            tenant.0,
            id.0,
            now_ms,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(AuthorizationRequest {
                id: AuthRequestId(r.id),
                tenant_id: TenantId(r.tenant_id),
                client_id: r.client_id,
                params: from_json(&r.params, "authorization_request.params")?,
                created_at: ms_to_odt(r.created_at)?,
                expires_at: ms_to_odt(r.expires_at)?,
            })
        })
        .transpose()
    }

    async fn delete_authorization_request(
        &self,
        tenant: TenantId,
        id: AuthRequestId,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM authorization_request WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn create_code(
        &self,
        tenant: TenantId,
        code: &NewAuthorizationCode,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError> {
        if code.token_family_id != family.id {
            return Err(StorageError::Conflict(
                "authorization code token_family_id does not match the family".to_owned(),
            ));
        }
        let code_hash = code.code_hash.as_bytes().as_slice();
        let code_amr = to_json(&code.amr, "authorization_code.amr")?;
        let code_auth_time = odt_to_ms(code.auth_time);
        let code_expires_at = odt_to_ms(code.expires_at);
        let code_created_at = odt_to_ms(code.created_at);
        let code_resource = to_json(&code.resource, "authorization_code.resource")?;
        let code_org = code.org_id.map(|o| o.0);

        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Any error drops `tx` uncommitted: neither the family nor the code is stored.
        insert_family(&mut tx, tenant, family).await?;
        sqlx::query!(
            "INSERT INTO authorization_code
                 (code_hash, tenant_id, client_id, user_id, session_id, redirect_uri, scope, nonce,
                  code_challenge, auth_time, acr, amr, token_family_id, expires_at, consumed_at,
                  created_at, resource, org_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15,
                     ?16, ?17)",
            code_hash,
            tenant.0,
            code.client_id,
            code.user_id.0,
            code.session_id.0,
            code.redirect_uri,
            code.scope,
            code.nonce,
            code.code_challenge,
            code_auth_time,
            code.acr,
            code_amr,
            code.token_family_id.0,
            code_expires_at,
            code_created_at,
            code_resource,
            code_org,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        // The browser session signed in to this client (back-channel logout targets).
        record_rp_session(
            &mut tx,
            tenant,
            code.session_id,
            &code.client_id,
            &code.issuer,
            code.created_at,
        )
        .await?;
        tx.commit().await.map_err(map_err)
    }

    async fn consume_code(
        &self,
        tenant: TenantId,
        code_hash: &CodeHash,
        now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError> {
        let hash = code_hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);

        // The race is decided by this single statement on the single writer connection.
        let row = sqlx::query!(
            r#"UPDATE authorization_code
                  SET consumed_at = ?3
                WHERE tenant_id = ?1 AND code_hash = ?2
                  AND consumed_at IS NULL AND expires_at > ?3
            RETURNING code_hash       AS "code_hash!: Vec<u8>",
                      tenant_id       AS "tenant_id!: uuid::Uuid",
                      client_id       AS "client_id!",
                      user_id         AS "user_id!: uuid::Uuid",
                      session_id      AS "session_id!: uuid::Uuid",
                      redirect_uri    AS "redirect_uri!",
                      scope           AS "scope!",
                      nonce           AS "nonce?",
                      code_challenge  AS "code_challenge?",
                      auth_time       AS "auth_time!",
                      acr             AS "acr!",
                      amr             AS "amr!",
                      token_family_id AS "token_family_id!: uuid::Uuid",
                      expires_at      AS "expires_at!",
                      created_at      AS "created_at!",
                      resource        AS "resource!",
                      org_id          AS "org_id?: uuid::Uuid""#,
            tenant.0,
            hash,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?;

        if let Some(r) = row {
            return Ok(ConsumeOutcome::Consumed(AuthorizationCode {
                tenant_id: TenantId(r.tenant_id),
                code_hash: blob_to_hash(&r.code_hash, "authorization_code.code_hash")?,
                client_id: r.client_id,
                user_id: UserId(r.user_id),
                session_id: SessionId(r.session_id),
                redirect_uri: r.redirect_uri,
                scope: r.scope,
                nonce: r.nonce,
                code_challenge: r.code_challenge,
                auth_time: ms_to_odt(r.auth_time)?,
                acr: r.acr,
                amr: from_json(&r.amr, "authorization_code.amr")?,
                token_family_id: TokenFamilyId(r.token_family_id),
                expires_at: ms_to_odt(r.expires_at)?,
                created_at: ms_to_odt(r.created_at)?,
                resource: from_json(&r.resource, "authorization_code.resource")?,
                org_id: r.org_id.map(OrgId),
            }));
        }

        // Zero rows: classify the loser. This read does not decide anything, it only tells a
        // replay (already consumed) apart from unknown / expired / other tenant.
        let existing = sqlx::query!(
            r#"SELECT consumed_at     AS "consumed_at?",
                      token_family_id AS "token_family_id!: uuid::Uuid"
                 FROM authorization_code
                WHERE tenant_id = ?1 AND code_hash = ?2"#,
            tenant.0,
            hash,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?;

        Ok(match existing {
            Some(r) if r.consumed_at.is_some() => ConsumeOutcome::AlreadyConsumed {
                family_id: Some(TokenFamilyId(r.token_family_id)),
            },
            _ => ConsumeOutcome::NotFound,
        })
    }

    async fn get_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
    ) -> Result<Option<TokenFamily>, StorageError> {
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        family_on(&mut conn, tenant, id.0).await
    }

    async fn revoke_family(
        &self,
        tenant: TenantId,
        id: TokenFamilyId,
        reason: RevokeReason,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        revoke_family_on(&mut conn, tenant, id.0, reason, now).await
    }

    async fn create_refresh_token(
        &self,
        tenant: TenantId,
        token: &NewRefreshToken,
    ) -> Result<(), StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_refresh(&mut conn, tenant, token).await
    }

    async fn find_refresh_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(RefreshToken, TokenFamily)>, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        let row = sqlx::query!(
            r#"SELECT token_hash AS "token_hash!", tenant_id AS "tenant_id!: uuid::Uuid",
                      family_id AS "family_id!: uuid::Uuid", parent_hash AS "parent_hash?",
                      scope AS "scope!", created_at AS "created_at!", expires_at AS "expires_at!",
                      consumed_at AS "consumed_at?"
                 FROM refresh_token WHERE tenant_id = ?1 AND token_hash = ?2"#,
            tenant.0,
            hash,
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(map_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let token = RefreshToken {
            token_hash: blob_to_hash(&r.token_hash, "refresh_token.token_hash")?,
            tenant_id: TenantId(r.tenant_id),
            family_id: TokenFamilyId(r.family_id),
            parent_hash: opt_blob_to_hash(r.parent_hash.as_deref(), "refresh_token.parent_hash")?,
            scope: r.scope,
            created_at: ms_to_odt(r.created_at)?,
            expires_at: ms_to_odt(r.expires_at)?,
            consumed_at: opt_ms_to_odt(r.consumed_at)?,
        };
        let family = family_on(&mut conn, tenant, r.family_id)
            .await?
            .ok_or_else(|| {
                StorageError::Corrupt("refresh_token references a missing family".to_owned())
            })?;
        Ok(Some((token, family)))
    }

    async fn rotate_refresh(
        &self,
        tenant: TenantId,
        presented: &SecretHash,
        child: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<RotateOutcome, StorageError> {
        let hash = presented.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let mut tx = self.writer.begin().await.map_err(map_err)?;

        // The race is decided by this single statement: only an unconsumed, unexpired token of a
        // live family is consumed.
        let consumed = sqlx::query!(
            r#"UPDATE refresh_token SET consumed_at = ?3
                WHERE token_hash = ?1 AND tenant_id = ?2 AND consumed_at IS NULL
                  AND expires_at > ?3
                  AND family_id IN (SELECT id FROM token_family
                                     WHERE tenant_id = ?2 AND revoked_at IS NULL
                                       AND absolute_expires_at > ?3)
            RETURNING family_id AS "family_id!: uuid::Uuid""#,
            hash,
            tenant.0,
            now_ms,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;

        if let Some(r) = consumed {
            if child.family_id.0 != r.family_id {
                tx.rollback().await.map_err(map_err)?;
                return Err(StorageError::Conflict(
                    "refresh token child belongs to another family".to_owned(),
                ));
            }
            // Any error drops `tx` uncommitted, which also undoes the consumption.
            insert_refresh(&mut tx, tenant, child).await?;
            let family = family_on(&mut tx, tenant, r.family_id)
                .await?
                .ok_or_else(|| {
                    StorageError::Corrupt("refresh_token references a missing family".to_owned())
                })?;
            tx.commit().await.map_err(map_err)?;
            return Ok(RotateOutcome::Rotated(family));
        }

        let existing = sqlx::query!(
            r#"SELECT consumed_at AS "consumed_at?", family_id AS "family_id!: uuid::Uuid"
                 FROM refresh_token WHERE token_hash = ?1 AND tenant_id = ?2"#,
            hash,
            tenant.0,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        match existing {
            Some(r) if r.consumed_at.is_some() => {
                // Reuse of a consumed token: revoke the whole family (an earlier reason wins).
                revoke_family_on(
                    &mut tx,
                    tenant,
                    r.family_id,
                    RevokeReason::RefreshReuse,
                    now,
                )
                .await?;
                tx.commit().await.map_err(map_err)?;
                Ok(RotateOutcome::ReuseDetected {
                    family_id: TokenFamilyId(r.family_id),
                })
            }
            _ => {
                tx.rollback().await.map_err(map_err)?;
                Ok(RotateOutcome::NotFound)
            }
        }
    }

    async fn record_jti(
        &self,
        tenant: TenantId,
        kind: ReplayKind,
        hash: &SecretHash,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<JtiOutcome, StorageError> {
        let kind = kind.as_str();
        let value = hash.as_bytes().as_slice();
        let expires_ms = odt_to_ms(expires_at);
        let now_ms = odt_to_ms(now);
        // Insert, or take over an expired entry; an unexpired entry leaves 0 rows affected.
        let done = sqlx::query!(
            "INSERT INTO replay_guard (tenant_id, kind, value_hash, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (tenant_id, kind, value_hash)
             DO UPDATE SET expires_at = excluded.expires_at
                     WHERE replay_guard.expires_at <= ?5",
            tenant.0,
            kind,
            value,
            expires_ms,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(if done.rows_affected() == 1 {
            JtiOutcome::Recorded
        } else {
            JtiOutcome::Replayed
        })
    }

    async fn create_family(
        &self,
        tenant: TenantId,
        family: &NewTokenFamily,
    ) -> Result<(), StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        insert_family(&mut conn, tenant, family).await
    }

    async fn create_access_token(
        &self,
        tenant: TenantId,
        token: &NewAccessToken,
    ) -> Result<(), StorageError> {
        let hash = token.token_hash.as_bytes().as_slice();
        let resource = to_json(&token.resource, "access_token.resource")?;
        let family = token.family_id.map(|f| f.0);
        let user = token.user_id.map(|u| u.0);
        let created_at = odt_to_ms(token.created_at);
        let expires_at = odt_to_ms(token.expires_at);
        sqlx::query!(
            "INSERT INTO access_token
                 (token_hash, tenant_id, family_id, client_id, user_id, scope, created_at,
                  expires_at, revoked_at, resource)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)",
            hash,
            tenant.0,
            family,
            token.client_id,
            user,
            token.scope,
            created_at,
            expires_at,
            resource,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
    ) -> Result<Option<(AccessTokenRecord, Option<TokenFamily>)>, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        let mut conn = self.reader.acquire().await.map_err(map_err)?;
        let row = sqlx::query!(
            r#"SELECT token_hash AS "token_hash!", tenant_id AS "tenant_id!: uuid::Uuid",
                      family_id AS "family_id?: uuid::Uuid", client_id AS "client_id!",
                      user_id AS "user_id?: uuid::Uuid", scope AS "scope!",
                      created_at AS "created_at!", expires_at AS "expires_at!",
                      revoked_at AS "revoked_at?", resource AS "resource!"
                 FROM access_token WHERE tenant_id = ?1 AND token_hash = ?2"#,
            tenant.0,
            hash,
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(map_err)?;
        let Some(r) = row else {
            return Ok(None);
        };
        let record = AccessTokenRecord {
            token_hash: blob_to_hash(&r.token_hash, "access_token.token_hash")?,
            tenant_id: TenantId(r.tenant_id),
            family_id: r.family_id.map(TokenFamilyId),
            client_id: r.client_id,
            user_id: r.user_id.map(UserId),
            scope: r.scope,
            created_at: ms_to_odt(r.created_at)?,
            expires_at: ms_to_odt(r.expires_at)?,
            revoked_at: opt_ms_to_odt(r.revoked_at)?,
            resource: from_json(&r.resource, "access_token.resource")?,
        };
        let family = match r.family_id {
            Some(id) => Some(family_on(&mut conn, tenant, id).await?.ok_or_else(|| {
                StorageError::Corrupt("access_token references a missing family".to_owned())
            })?),
            None => None,
        };
        Ok(Some((record, family)))
    }

    async fn revoke_access_token(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let hash = token_hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE access_token SET revoked_at = ?3
              WHERE tenant_id = ?1 AND token_hash = ?2 AND revoked_at IS NULL",
            tenant.0,
            hash,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
    ) -> Result<Option<ConsentGrant>, StorageError> {
        consent::active(&self.reader, tenant, user, client_id).await
    }

    async fn list_consents(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<ConsentGrant>, StorageError> {
        consent::list_active(&self.reader, tenant, user).await
    }

    async fn upsert_consent(
        &self,
        tenant: TenantId,
        consent: &NewConsent,
        now: OffsetDateTime,
    ) -> Result<ConsentGrant, StorageError> {
        consent::upsert(&self.writer, tenant, consent, now).await
    }

    async fn revoke_consent(
        &self,
        tenant: TenantId,
        user: UserId,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        consent::revoke(&self.writer, tenant, user, client_id, now).await
    }
}
