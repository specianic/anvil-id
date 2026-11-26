//! `UserRepo` on SQLite.

use anvil_core::model::{
    CounterOutcome, CredentialId, CredentialSummary, NewEmail, NewPasskey, NewPasswordCredential,
    NewSelfServiceToken, NewTotp, NewUser, Page, PageRequest, PasskeyCredential,
    PasswordCredential, RecoveryCodeHash, RecoveryNotice, RevokeReason, SecretHash,
    SelfServiceKind, TenantId, TotpCredential, User, UserId, UserStatus, UserUpdate,
};
use anvil_core::ports::{StorageError, UserRepo};
use sqlx::{SqliteConnection, SqlitePool};
use time::OffsetDateTime;

use crate::convert::{
    from_json, into_page, map_err, ms_to_odt, now_ms, odt_to_ms, opt_ms_to_odt, parse_enum, to_json,
};
use crate::credentials;
use crate::logout::enqueue_deliveries;
use crate::outbox::insert_email;

#[derive(Debug, Clone)]
pub(crate) struct SqliteUsers {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

/// Credential kind of password rows.
pub(crate) const PASSWORD_KIND: &str = "password";

pub(crate) struct UserRow {
    pub(crate) id: uuid::Uuid,
    pub(crate) tenant_id: uuid::Uuid,
    pub(crate) email: String,
    pub(crate) email_verified: bool,
    pub(crate) username: Option<String>,
    pub(crate) claims: String,
    pub(crate) status: String,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) last_login_at: Option<i64>,
}

impl TryFrom<UserRow> for User {
    type Error = StorageError;

    fn try_from(r: UserRow) -> Result<Self, StorageError> {
        Ok(User {
            id: UserId(r.id),
            tenant_id: TenantId(r.tenant_id),
            email: r.email,
            email_verified: r.email_verified,
            username: r.username,
            claims: from_json(&r.claims, "user.claims")?,
            status: parse_enum(&r.status, UserStatus::parse, "user status")?,
            created_at: ms_to_odt(r.created_at)?,
            updated_at: ms_to_odt(r.updated_at)?,
            last_login_at: opt_ms_to_odt(r.last_login_at)?,
        })
    }
}

/// Inserts a user on `conn` and returns the stored record. `Conflict` on a duplicate
/// (tenant, email), (tenant, username) or id.
pub(crate) async fn insert_user(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: &NewUser,
) -> Result<User, StorageError> {
    let claims = to_json(&user.claims, "user.claims")?;
    let status = user.status.as_str();
    let created_at = odt_to_ms(user.created_at);
    sqlx::query!(
        "INSERT INTO user
             (id, tenant_id, email, email_verified, username, claims, status, created_at,
              updated_at, last_login_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, NULL)",
        user.id.0,
        tenant.0,
        user.email,
        user.email_verified,
        user.username,
        claims,
        status,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(User {
        id: user.id,
        tenant_id: tenant,
        email: user.email.clone(),
        email_verified: user.email_verified,
        username: user.username.clone(),
        claims: user.claims.clone(),
        status: user.status,
        created_at: user.created_at,
        updated_at: user.created_at,
        last_login_at: None,
    })
}

/// Inserts the password credential of a just-created user on `conn`.
pub(crate) async fn insert_password(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    password: &NewPasswordCredential,
) -> Result<(), StorageError> {
    let id = CredentialId::new_v7();
    let created_at = odt_to_ms(password.created_at);
    sqlx::query!(
        "INSERT INTO credential (id, tenant_id, user_id, kind, secret, created_at, updated_at)
         VALUES (?6, ?1, ?2, ?3, ?4, ?5, ?5)",
        tenant.0,
        user.0,
        PASSWORD_KIND,
        password.phc,
        created_at,
        id.0,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}
/// Inserts a self-service token on `conn`. `Conflict` on a duplicate hash.
pub(crate) async fn insert_self_service_token(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    token: &NewSelfServiceToken,
) -> Result<(), StorageError> {
    let hash = token.token_hash.as_bytes().as_slice();
    let kind = token.kind.as_str();
    let created_at = odt_to_ms(token.created_at);
    let expires_at = odt_to_ms(token.expires_at);
    sqlx::query!(
        "INSERT INTO self_service_token
             (token_hash, tenant_id, kind, user_id, email, created_at, expires_at, consumed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)",
        hash,
        tenant.0,
        kind,
        token.user_id.0,
        token.email,
        created_at,
        expires_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

/// Revokes every unrevoked token family of `user` on `conn` (first reason is kept).
async fn revoke_user_families(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    reason: RevokeReason,
    now: OffsetDateTime,
) -> Result<(), StorageError> {
    let reason = reason.as_str();
    let now_ms = odt_to_ms(now);
    sqlx::query!(
        "UPDATE token_family SET revoked_at = ?3, revoked_reason = ?4
          WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
        tenant.0,
        user.0,
        now_ms,
        reason,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}

#[async_trait::async_trait]
impl UserRepo for SqliteUsers {
    async fn create(
        &self,
        tenant: TenantId,
        user: &NewUser,
        password: Option<&NewPasswordCredential>,
        token: Option<&NewSelfServiceToken>,
        email: Option<&NewEmail>,
    ) -> Result<User, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Any error drops `tx` uncommitted: nothing at all is persisted.
        let created = insert_user(&mut tx, tenant, user).await?;
        if let Some(password) = password {
            insert_password(&mut tx, tenant, user.id, password).await?;
        }
        if let Some(token) = token {
            insert_self_service_token(&mut tx, tenant, token).await?;
        }
        if let Some(email) = email {
            insert_email(&mut tx, tenant, email).await?;
        }
        tx.commit().await.map_err(map_err)?;
        Ok(created)
    }

    async fn get(&self, tenant: TenantId, id: UserId) -> Result<Option<User>, StorageError> {
        sqlx::query_as!(
            UserRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?"
                 FROM user WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            id.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(User::try_from)
        .transpose()
    }

    async fn get_by_email(
        &self,
        tenant: TenantId,
        email: &str,
    ) -> Result<Option<User>, StorageError> {
        sqlx::query_as!(
            UserRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?"
                 FROM user WHERE tenant_id = ?1 AND email = ?2"#,
            tenant.0,
            email,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(User::try_from)
        .transpose()
    }

    async fn list(&self, tenant: TenantId, page: PageRequest) -> Result<Page<User>, StorageError> {
        let limit = page.clamped_limit();
        let fetch = i64::from(limit) + 1;
        let rows = sqlx::query_as!(
            UserRow,
            r#"SELECT id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?"
                 FROM user
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
            .map(User::try_from)
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
        let set_username = update.username.is_some();
        let username = update.username.clone().flatten();
        let claims = update
            .claims
            .as_ref()
            .map(|c| to_json(c, "user.claims"))
            .transpose()?;
        let status = update.status.map(|s| s.as_str());
        let now_ms = odt_to_ms(now);
        // One statement: a conflicting email or username changes nothing.
        sqlx::query_as!(
            UserRow,
            r#"UPDATE user
                  SET email = COALESCE(?3, email),
                      email_verified = COALESCE(?4, email_verified),
                      username = CASE WHEN ?5 THEN ?6 ELSE username END,
                      claims = COALESCE(?7, claims),
                      status = COALESCE(?8, status),
                      updated_at = ?9
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?""#,
            tenant.0,
            id.0,
            update.email,
            update.email_verified,
            set_username,
            username,
            claims,
            status,
            now_ms,
        )
        .fetch_optional(&self.writer)
        .await
        .map_err(map_err)?
        .map(User::try_from)
        .transpose()
    }

    async fn delete(&self, tenant: TenantId, id: UserId) -> Result<bool, StorageError> {
        let now = now_ms();
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Log out the user's live sessions first: their RP sessions cascade away with the user,
        // the deliveries do not (logout_delivery has no foreign key to session or user).
        let sessions: Vec<uuid::Uuid> = sqlx::query_scalar!(
            r#"SELECT id AS "id!: uuid::Uuid" FROM browser_session
                WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
                ORDER BY id"#,
            tenant.0,
            id.0,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        enqueue_deliveries(&mut tx, tenant, id, &sessions, now).await?;
        // Credentials, sessions, identity links, self-service tokens and codes go by ON DELETE
        // CASCADE.
        let done = sqlx::query!(
            "DELETE FROM user WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            id.0,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        if done.rows_affected() == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Ok(false);
        }
        revoke_user_families(&mut tx, tenant, id, RevokeReason::UserDeleted, now).await?;
        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn password(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<PasswordCredential>, StorageError> {
        let row = sqlx::query!(
            r#"SELECT user_id AS "user_id!: uuid::Uuid", secret AS "secret!",
                      created_at AS "created_at!", updated_at AS "updated_at!"
                 FROM credential WHERE tenant_id = ?1 AND user_id = ?2 AND kind = ?3"#,
            tenant.0,
            user.0,
            PASSWORD_KIND,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(PasswordCredential {
                user_id: UserId(r.user_id),
                phc: r.secret,
                created_at: ms_to_odt(r.created_at)?,
                updated_at: ms_to_odt(r.updated_at)?,
            })
        })
        .transpose()
    }

    async fn set_password(
        &self,
        tenant: TenantId,
        user: UserId,
        phc: &str,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut conn = self.writer.acquire().await.map_err(map_err)?;
        upsert_password(&mut conn, tenant, user, phc, now).await
    }

    async fn record_login(
        &self,
        tenant: TenantId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let now_ms = odt_to_ms(now);
        sqlx::query!(
            "UPDATE user SET last_login_at = ?3 WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            user.0,
            now_ms,
        )
        .execute(&self.writer)
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
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        insert_self_service_token(&mut tx, tenant, token).await?;
        if let Some(email) = email {
            insert_email(&mut tx, tenant, email).await?;
        }
        tx.commit().await.map_err(map_err)
    }

    async fn complete_verification(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let Some((user_id, email)) = consume_self_service_token(
            &mut tx,
            tenant,
            token_hash,
            [SelfServiceKind::Verification; 2],
            now,
        )
        .await?
        else {
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        };
        let now_ms = odt_to_ms(now);
        let verified = sqlx::query_as!(
            UserRow,
            r#"UPDATE user SET email_verified = 1, updated_at = ?4
                WHERE tenant_id = ?1 AND id = ?2 AND email = ?3
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?""#,
            tenant.0,
            user_id,
            email,
            now_ms,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;
        match verified {
            Some(row) => {
                tx.commit().await.map_err(map_err)?;
                User::try_from(row).map(Some)
            }
            // The email changed since the token was issued: verify nothing, keep the token.
            None => {
                tx.rollback().await.map_err(map_err)?;
                Ok(None)
            }
        }
    }

    async fn complete_recovery(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        new_phc: &str,
        now: OffsetDateTime,
        notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let Some((user_id, token_email)) = consume_self_service_token(
            &mut tx,
            tenant,
            token_hash,
            [SelfServiceKind::Recovery, SelfServiceKind::Invitation],
            now,
        )
        .await?
        else {
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        };
        let user = UserId(user_id);
        let now_ms = odt_to_ms(now);
        // Any error below drops `tx` uncommitted, which also undoes the token consumption.
        if !upsert_password(&mut tx, tenant, user, new_phc, now).await? {
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        }
        let row = sqlx::query_as!(
            UserRow,
            r#"UPDATE user SET email_verified = 1, updated_at = ?3
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?""#,
            tenant.0,
            user.0,
            now_ms,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        let revoked: Vec<uuid::Uuid> = sqlx::query_scalar!(
            r#"UPDATE browser_session SET revoked_at = ?3
                WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL
            RETURNING id AS "id!: uuid::Uuid""#,
            tenant.0,
            user.0,
            now_ms,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(map_err)?;
        revoke_user_families(&mut tx, tenant, user, RevokeReason::UserRecovery, now).await?;
        enqueue_deliveries(&mut tx, tenant, user, &revoked, now).await?;
        if let Some(notice) = notice {
            // The recipient is the address the consumed token was sent to.
            insert_email(&mut tx, tenant, &notice.to_email(&token_email)).await?;
        }
        let recovered = User::try_from(row)?;
        tx.commit().await.map_err(map_err)?;
        Ok(Some(recovered))
    }

    async fn list_credentials(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<CredentialSummary>, StorageError> {
        credentials::list(&self.reader, tenant, user).await
    }

    async fn create_passkey(
        &self,
        tenant: TenantId,
        user: UserId,
        passkey: &NewPasskey,
    ) -> Result<(), StorageError> {
        credentials::create_passkey(&self.writer, tenant, user, passkey).await
    }

    async fn passkeys(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Vec<PasskeyCredential>, StorageError> {
        credentials::passkeys(&self.reader, tenant, user).await
    }

    async fn find_passkey(
        &self,
        tenant: TenantId,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, StorageError> {
        credentials::find_passkey(&self.reader, tenant, credential_id).await
    }

    async fn update_passkey(
        &self,
        tenant: TenantId,
        id: CredentialId,
        passkey_json: &str,
        counter: u32,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError> {
        credentials::update_passkey(&self.writer, tenant, id, passkey_json, counter, now).await
    }

    async fn totp(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<TotpCredential>, StorageError> {
        credentials::totp(&self.reader, tenant, user).await
    }

    async fn create_totp(
        &self,
        tenant: TenantId,
        user: UserId,
        totp: &NewTotp,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        credentials::create_totp(&self.writer, tenant, user, totp, codes, now).await
    }

    async fn advance_totp_step(
        &self,
        tenant: TenantId,
        user: UserId,
        step: u64,
        now: OffsetDateTime,
    ) -> Result<CounterOutcome, StorageError> {
        credentials::advance_totp_step(&self.writer, tenant, user, step, now).await
    }

    async fn delete_credential(
        &self,
        tenant: TenantId,
        user: UserId,
        id: CredentialId,
    ) -> Result<bool, StorageError> {
        credentials::delete(&self.writer, tenant, user, id).await
    }

    async fn replace_recovery_codes(
        &self,
        tenant: TenantId,
        user: UserId,
        codes: &[RecoveryCodeHash],
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        credentials::replace_recovery_codes(&self.writer, tenant, user, codes, now).await
    }

    async fn consume_recovery_code(
        &self,
        tenant: TenantId,
        user: UserId,
        hash: &RecoveryCodeHash,
        now: OffsetDateTime,
        notice: Option<&NewEmail>,
    ) -> Result<bool, StorageError> {
        credentials::consume_recovery_code(&self.writer, tenant, user, hash, now, notice).await
    }

    async fn recovery_codes_remaining(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<u32, StorageError> {
        credentials::recovery_codes_remaining(&self.reader, tenant, user).await
    }

    async fn complete_email_change(
        &self,
        tenant: TenantId,
        token_hash: &SecretHash,
        now: OffsetDateTime,
        notice: Option<&RecoveryNotice>,
    ) -> Result<Option<User>, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        let Some((user_id, new_email)) = consume_self_service_token(
            &mut tx,
            tenant,
            token_hash,
            [SelfServiceKind::EmailChange; 2],
            now,
        )
        .await?
        else {
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        };
        let Some(old_email) = sqlx::query_scalar!(
            r#"SELECT email AS "email!" FROM user WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            user_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?
        else {
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        };
        let now_ms = odt_to_ms(now);
        // A unique violation (another user holds the address) is `Conflict`; returning early
        // drops `tx` uncommitted, so the token stays unconsumed.
        let row = sqlx::query_as!(
            UserRow,
            r#"UPDATE user SET email = ?3, email_verified = 1, updated_at = ?4
                WHERE tenant_id = ?1 AND id = ?2
            RETURNING id AS "id!: uuid::Uuid", tenant_id AS "tenant_id!: uuid::Uuid",
                      email AS "email!", email_verified AS "email_verified!: bool",
                      username AS "username?", claims AS "claims!", status AS "status!",
                      created_at AS "created_at!", updated_at AS "updated_at!",
                      last_login_at AS "last_login_at?""#,
            tenant.0,
            user_id,
            new_email,
            now_ms,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        if let Some(notice) = notice {
            // The notice goes to the address before the change.
            insert_email(&mut tx, tenant, &notice.to_email(&old_email)).await?;
        }
        let changed = User::try_from(row)?;
        tx.commit().await.map_err(map_err)?;
        Ok(Some(changed))
    }

    async fn replace_password_if(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _expected: &str,
        _new_phc: &str,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "TRANSITIONAL(07-08): UserRepo::replace_password_if",
        ))
    }

    async fn pending_self_service_tokens(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<Vec<(anvil_core::model::SelfServiceKind, OffsetDateTime)>, StorageError> {
        Err(StorageError::Unsupported(
            "TRANSITIONAL(07-08): UserRepo::pending_self_service_tokens",
        ))
    }
}

/// Upserts the password credential of an existing user on `conn`. `false` if the user does not
/// exist in `tenant`.
async fn upsert_password(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    user: UserId,
    phc: &str,
    now: OffsetDateTime,
) -> Result<bool, StorageError> {
    let now_ms = odt_to_ms(now);
    let id = CredentialId::new_v7();
    // `WHERE` before `ON CONFLICT` resolves SQLite's INSERT ... SELECT upsert ambiguity. The
    // conflict target is the partial unique index of password rows (one per user).
    let done = sqlx::query!(
        "INSERT INTO credential (id, tenant_id, user_id, kind, secret, created_at, updated_at)
         SELECT ?6, tenant_id, id, ?3, ?4, ?5, ?5 FROM user WHERE tenant_id = ?1 AND id = ?2
         ON CONFLICT (tenant_id, user_id) WHERE kind = 'password'
         DO UPDATE SET secret = excluded.secret, updated_at = excluded.updated_at",
        tenant.0,
        user.0,
        PASSWORD_KIND,
        phc,
        now_ms,
        id.0,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(done.rows_affected() > 0)
}

/// Atomically consumes an unconsumed, unexpired self-service token of one of `kinds` on `conn`
/// (a single `UPDATE ... RETURNING`). Pass the same kind twice to accept only one. Returns the
/// token's user id and email.
async fn consume_self_service_token(
    conn: &mut SqliteConnection,
    tenant: TenantId,
    token_hash: &SecretHash,
    kinds: [SelfServiceKind; 2],
    now: OffsetDateTime,
) -> Result<Option<(uuid::Uuid, String)>, StorageError> {
    let hash = token_hash.as_bytes().as_slice();
    let now_ms = odt_to_ms(now);
    let [kind_a, kind_b] = kinds.map(|k| k.as_str());
    let row = sqlx::query!(
        r#"UPDATE self_service_token SET consumed_at = ?3
            WHERE token_hash = ?1 AND tenant_id = ?2 AND kind IN (?4, ?5)
              AND consumed_at IS NULL AND expires_at > ?3
        RETURNING user_id AS "user_id!: uuid::Uuid", email AS "email!""#,
        hash,
        tenant.0,
        now_ms,
        kind_a,
        kind_b,
    )
    .fetch_optional(conn)
    .await
    .map_err(map_err)?;
    Ok(row.map(|r| (r.user_id, r.email)))
}
