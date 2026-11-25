//! `UserRepo` on SQLite.

use anvil_core::model::{
    NewPasswordCredential, NewUser, TenantId, User, UserId, UserStatus,
};
use anvil_core::ports::StorageError;
use sqlx::SqliteConnection;

use crate::convert::{from_json, map_err, ms_to_odt, odt_to_ms, opt_ms_to_odt, parse_enum, to_json};

/// The only credential kind of 0.1.
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
    let created_at = odt_to_ms(password.created_at);
    sqlx::query!(
        "INSERT INTO credential (tenant_id, user_id, kind, secret, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        tenant.0,
        user.0,
        PASSWORD_KIND,
        password.phc,
        created_at,
    )
    .execute(conn)
    .await
    .map_err(map_err)?;
    Ok(())
}
