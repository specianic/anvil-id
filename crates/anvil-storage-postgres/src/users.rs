//! `UserRepo` on Postgres: users, password credentials and self-service tokens.

use anvil_core::model::{NewPasswordCredential, NewUser, TenantId, User, UserId};
use anvil_core::ports::StorageError;

use crate::convert::{map_err, to_json};

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
        "INSERT INTO credential (tenant_id, user_id, kind, data, created_at, updated_at)
         VALUES ($1, $2, 'password', $3, $4, $4)",
        tenant.0,
        user.0,
        p.phc,
        p.created_at,
    )
    .execute(exec)
    .await
    .map_err(map_err)?;
    Ok(())
}
