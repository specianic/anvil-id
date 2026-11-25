//! `UserRepo` on Postgres: users, password credentials and self-service tokens. Passkey, TOTP
//! and recovery-code methods live in `credentials`.

use anvil_core::model::{
    CounterOutcome, CredentialId, CredentialSummary, NewEmail, NewPasskey, NewPasswordCredential,
    NewSelfServiceToken, NewTotp, NewUser, Page, PageRequest, PasskeyCredential,
    PasswordCredential, RecoveryCodeHash, RecoveryNotice, RevokeReason, SecretHash,
    SelfServiceKind, TenantId, TotpCredential, User, UserId, UserStatus, UserUpdate,
};
use anvil_core::ports::{StorageError, UserRepo};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{enum_from, fetch_limit, from_json, into_page, map_err, to_json};
use crate::credentials;
use crate::outbox::enqueue_email;

#[derive(Debug, Clone)]
pub(crate) struct PgUsers {
    pub(crate) pool: PgPool,
}

pub(crate) struct UserRow {
    id: Uuid,
    tenant_id: Uuid,
    email: String,
    email_verified: bool,
    username: Option<String>,
    claims: serde_json::Value,
    status: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_login_at: Option<OffsetDateTime>,
}

impl UserRow {
    pub(crate) fn into_model(self) -> Result<User, StorageError> {
        Ok(User {
            id: UserId(self.id),
            tenant_id: TenantId(self.tenant_id),
            email: self.email,
            email_verified: self.email_verified,
            username: self.username,
            claims: from_json("user.claims", self.claims)?,
            status: enum_from("user.status", &self.status, UserStatus::parse)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}

/// The record a successful insert of `u` under `tenant` stores.
pub(crate) fn user_from_new(tenant: TenantId, u: &NewUser) -> User {
    User {
        id: u.id,
        tenant_id: tenant,
        email: u.email.clone(),
        email_verified: u.email_verified,
        username: u.username.clone(),
        claims: u.claims.clone(),
        status: u.status,
        created_at: u.created_at,
        updated_at: u.created_at,
        last_login_at: None,
    }
}

/// Inserts a user on any executor. `Conflict` on a duplicate (tenant, email) or (tenant,
/// username).
pub(crate) async fn insert_user<'e, E>(
    exec: E,
    tenant: TenantId,
    u: &NewUser,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let claims = to_json("user.claims", &u.claims)?;
    sqlx::query!(
        "INSERT INTO \"user\"
             (id, tenant_id, email, email_verified, username, claims, status, created_at,
              updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
        u.id.0,
        tenant.0,
        u.email,
        u.email_verified,
        u.username,
        claims,
        u.status.as_str(),
        u.created_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Inserts the password credential of a user that exists in `tenant`.
pub(crate) async fn insert_password<'e, E>(
    exec: E,
    tenant: TenantId,
    user: UserId,
    p: &NewPasswordCredential,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO credential (id, tenant_id, user_id, kind, data, created_at, updated_at)
         VALUES ($5, $1, $2, 'password', $3, $4, $4)",
        tenant.0,
        user.0,
        p.phc,
        p.created_at,
        CredentialId::new_v7().0,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Inserts a self-service token on any executor. `Conflict` on a duplicate hash.
async fn insert_self_service_token<'e, E>(
    exec: E,
    tenant: TenantId,
    t: &NewSelfServiceToken,
) -> Result<(), StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO self_service_token
             (token_hash, tenant_id, kind, user_id, email, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        t.token_hash.as_bytes().as_slice(),
        tenant.0,
        t.kind.as_str(),
        t.user_id.0,
        t.email,
        t.created_at,
        t.expires_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl UserRepo for PgUsers {
    async fn create(
        &self,
        tenant: TenantId,
        user: &NewUser,
        password: Option<&NewPasswordCredential>,
        token: Option<&NewSelfServiceToken>,
        email: Option<&NewEmail>,
    ) -> Result<User, StorageError> {
        if let Some(t) = token {
            crate::pending::refuse_phase4_token_kind(t.kind)?;
        }
        // One transaction; any error drops `tx` and rolls everything back.
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        insert_user(&mut *tx, tenant, user).await?;
        if let Some(p) = password {
            insert_password(&mut *tx, tenant, user.id, p).await?;
        }
        if let Some(t) = token {
            insert_self_service_token(&mut *tx, tenant, t).await?;
        }
        if let Some(e) = email {
            enqueue_email(&mut *tx, tenant, e).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(user_from_new(tenant, user))
    }

    async fn get(&self, tenant: TenantId, id: UserId) -> Result<Option<User>, StorageError> {
        sqlx::query_as!(
            UserRow,
            "SELECT id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at
               FROM \"user\"
              WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(UserRow::into_model)
        .transpose()
    }

    async fn get_by_email(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<Option<User>, StorageError> {
        sqlx::query_as!(
            UserRow,
            "SELECT id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at
               FROM \"user\"
              WHERE tenant_id = $1 AND email = $2",
            tenant.0,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(UserRow::into_model)
        .transpose()
    }

    async fn list(&self, tenant: TenantId, page: PageRequest) -> Result<Page<User>, StorageError> {
        let limit = page.clamped_limit();
        let rows = sqlx::query_as!(
            UserRow,
            "SELECT id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at
               FROM \"user\"
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
            .map(UserRow::into_model)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(into_page(items, limit, |u| u.id.0))
    }

    async fn update(
        &self,
        tenant: TenantId,
        id: UserId,
        update: &UserUpdate,
        now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError> {
        let claims = update
            .claims
            .as_ref()
            .map(|c| to_json("user.claims", c))
            .transpose()?;
        let (set_username, username) = match &update.username {
            Some(u) => (true, u.clone()),
            None => (false, None),
        };
        let status = update.status.map(|s| s.as_str());
        // One statement: a unique violation leaves the row unchanged.
        sqlx::query_as!(
            UserRow,
            "UPDATE \"user\"
                SET email = COALESCE($3, email),
                    email_verified = COALESCE($4, email_verified),
                    username = CASE WHEN $5 THEN $6 ELSE username END,
                    claims = COALESCE($7, claims),
                    status = COALESCE($8, status),
                    updated_at = $9
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at",
            tenant.0,
            id.0,
            update.email,
            update.email_verified,
            set_username,
            username,
            claims,
            status,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(UserRow::into_model)
        .transpose()
    }

    async fn delete(&self, tenant: TenantId, id: UserId) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // Credentials, sessions and self-service tokens go by ON DELETE CASCADE.
        let done = sqlx::query!(
            "DELETE FROM \"user\" WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            id.0,
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
              WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            tenant.0,
            id.0,
            RevokeReason::UserDeleted.as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn password(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<PasswordCredential>, StorageError> {
        let row = sqlx::query!(
            "SELECT user_id, data, created_at, updated_at
               FROM credential
              WHERE tenant_id = $1 AND user_id = $2 AND kind = 'password'",
            tenant.0,
            user.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| PasswordCredential {
            user_id: UserId(r.user_id),
            phc: r.data,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn set_password(
        &self,
        tenant: TenantId,
        user: UserId,
        phc: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = upsert_password(&self.pool, tenant, user, phc, now).await?;
        Ok(done)
    }

    async fn record_login(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query!(
            "UPDATE \"user\" SET last_login_at = $3 WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            user.0,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn issue_self_service_token(
        &self,
        tenant: TenantId,
        token: &NewSelfServiceToken,
        email: Option<&NewEmail>,
    ) -> Result<(), StorageError> {
        crate::pending::refuse_phase4_token_kind(token.kind)?;
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        insert_self_service_token(&mut *tx, tenant, token).await?;
        if let Some(e) = email {
            enqueue_email(&mut *tx, tenant, e).await?;
        }
        tx.commit().await.map_err(map_err)
    }

    async fn complete_verification(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // Single conditional UPDATE: concurrent callers serialise on the row lock and only the
        // first sees `consumed_at IS NULL`.
        let Some(token) = sqlx::query!(
            "UPDATE self_service_token SET consumed_at = $3
              WHERE tenant_id = $1 AND token_hash = $2 AND kind = $4
                AND consumed_at IS NULL AND expires_at > $3
          RETURNING user_id, email",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
            SelfServiceKind::Verification.as_str(),
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        // Only verifies the address the token was sent to.
        let user = sqlx::query_as!(
            UserRow,
            "UPDATE \"user\" SET email_verified = TRUE, updated_at = $4
              WHERE tenant_id = $1 AND id = $2 AND email = $3
          RETURNING id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at",
            tenant.0,
            token.user_id,
            token.email,
            now,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        let Some(user) = user else {
            // The email changed since the token was issued: roll back, nothing changes.
            return Ok(None);
        };
        tx.commit().await.map_err(map_err)?;
        user.into_model().map(Some)
    }

    async fn complete_recovery(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        new_phc: &str,
        now: OffsetDateTime,
        notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        let kinds = [
            SelfServiceKind::Recovery.as_str().to_owned(),
            SelfServiceKind::Invitation.as_str().to_owned(),
        ];
        let Some(token) = sqlx::query!(
            "UPDATE self_service_token SET consumed_at = $3
              WHERE tenant_id = $1 AND token_hash = $2 AND kind = ANY($4)
                AND consumed_at IS NULL AND expires_at > $3
          RETURNING user_id, email",
            tenant.0,
            token_hash.as_bytes().as_slice(),
            now,
            &kinds[..],
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        let user_id = UserId(token.user_id);
        if !upsert_password(&mut *tx, tenant, user_id, new_phc, now).await? {
            return Ok(None);
        }
        let Some(user) = sqlx::query_as!(
            UserRow,
            "UPDATE \"user\" SET email_verified = TRUE, updated_at = $3
              WHERE tenant_id = $1 AND id = $2
          RETURNING id, tenant_id, email, email_verified, username, claims, status, created_at,
                    updated_at, last_login_at",
            tenant.0,
            user_id.0,
            now,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        sqlx::query!(
            "UPDATE browser_session SET revoked_at = $3
              WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            tenant.0,
            user_id.0,
            now,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        sqlx::query!(
            "UPDATE token_family SET revoked_at = $3, revoked_reason = $4
              WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL",
            tenant.0,
            user_id.0,
            now,
            RevokeReason::UserRecovery.as_str(),
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if let Some(notice) = notice {
            // The recipient is the address the consumed token was sent to.
            enqueue_email(&mut *tx, tenant, &notice.to_email(&token.email)).await?;
        }
        tx.commit().await.map_err(map_err)?;
        user.into_model().map(Some)
    }

    async fn list_credentials(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<CredentialSummary>, StorageError> {
        credentials::list_credentials(&self.pool, tenant, user).await
    }

    async fn create_passkey(
        &self,
        tenant: TenantId,
        user: UserId,
        passkey: &NewPasskey,
    ) -> Result<(), StorageError> {
        credentials::create_passkey(&self.pool, tenant, user, passkey).await
    }

    async fn passkeys(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<PasskeyCredential>, StorageError> {
        credentials::passkeys(&self.pool, tenant, user).await
    }

    async fn find_passkey(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, StorageError> {
        credentials::find_passkey(&self.pool, tenant, credential_id).await
    }

    async fn update_passkey(
        &self,
        tenant: TenantId,
        id: CredentialId,
        passkey_json: &str,
        counter: u32,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError> {
        credentials::update_passkey(&self.pool, tenant, id, passkey_json, counter, now).await
    }

    async fn totp(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<TotpCredential>, StorageError> {
        credentials::totp(&self.pool, tenant, user).await
    }

    async fn create_totp(
        &self,
        tenant: TenantId,
        user: UserId,
        totp: &NewTotp,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        credentials::create_totp(&self.pool, tenant, user, totp, codes, now).await
    }

    async fn advance_totp_step(
        &self,
        tenant: TenantId,
        user: UserId,
        step: u64,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError> {
        credentials::advance_totp_step(&self.pool, tenant, user, step, now).await
    }

    async fn delete_credential(
        &self,
        tenant: TenantId,
        user: UserId,
        id: CredentialId,
    ) -> Result<bool, StorageError> {
        credentials::delete_credential(&self.pool, tenant, user, id).await
    }

    async fn replace_recovery_codes(
        &self,
        tenant: TenantId,
        user: UserId,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        credentials::replace_recovery_codes(&self.pool, tenant, user, codes, now).await
    }

    async fn consume_recovery_code(
        &self,
        tenant: TenantId,
        user: UserId,
        hash: &RecoveryCodeHash,
        now: OffsetDateTime,
        notice: Option<&NewEmail>,
    ) -> Result<bool, StorageError> {
        credentials::consume_recovery_code(&self.pool, tenant, user, hash, now, notice).await
    }

    async fn recovery_codes_remaining(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<u32, StorageError> {
        credentials::recovery_codes_remaining(&self.pool, tenant, user).await
    }

    async fn complete_email_change(
        &self,
        _tenant: TenantId,
        _token_hash: &SecretHash,
        _now: OffsetDateTime,
        _notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError> {
        // TRANSITIONAL(04-05)
        crate::pending::complete_email_change_unsupported()
    }
}

/// Inserts or replaces the password of a user of `tenant`. `false` if the user does not exist
/// in the tenant.
async fn upsert_password<'e, E>(
    exec: E,
    tenant: TenantId,
    user: UserId,
    phc: &str,
    now: OffsetDateTime,
) -> Result<bool, StorageError>
where
    E: sqlx::PgExecutor<'e>,
{
    let done = sqlx::query!(
        "INSERT INTO credential (id, tenant_id, user_id, kind, data, created_at, updated_at)
         SELECT $5, $1, $2, 'password', $3, $4, $4
          WHERE EXISTS (SELECT 1 FROM \"user\" WHERE tenant_id = $1 AND id = $2)
         ON CONFLICT (tenant_id, user_id) WHERE kind = 'password'
         DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at",
        tenant.0,
        user.0,
        phc,
        now,
        CredentialId::new_v7().0,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(done.rows_affected() > 0)
}
