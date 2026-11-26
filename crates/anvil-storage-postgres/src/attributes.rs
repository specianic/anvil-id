//! `AttributeRepo` on Postgres: custom attribute definitions (natural key `(tenant_id, name)`) and
//! the per-user value object (`"user".attributes`, a jsonb object).

use anvil_core::model::{AttributeDefinition, ClaimRule, TenantId, UserId};
use anvil_core::ports::{AttributeRepo, StorageError};
use serde_json::{Map, Value};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::{map_err, opt_from_json, to_json};

#[derive(Debug, Clone)]
pub(crate) struct PgAttributes {
    pub(crate) pool: PgPool,
}

struct AttributeRow {
    name: String,
    schema: Value,
    required: bool,
    user_editable: bool,
    claim: Option<Value>,
    position: i64,
}

impl AttributeRow {
    fn into_model(self) -> Result<AttributeDefinition, StorageError> {
        Ok(AttributeDefinition {
            name: self.name,
            schema: self.schema,
            required: self.required,
            user_editable: self.user_editable,
            claim: opt_from_json::<ClaimRule>("attribute_definition.claim", self.claim)?,
            position: u32::try_from(self.position).map_err(|_| {
                StorageError::Corrupt(format!(
                    "attribute_definition.position: out of range {}",
                    self.position
                ))
            })?,
        })
    }
}

/// jsonb → attribute value object. Anything else is corrupt data.
fn values_from(value: Value) -> Result<Map<String, Value>, StorageError> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(StorageError::Corrupt(
            "user.attributes: not an object".to_owned(),
        )),
    }
}

#[async_trait::async_trait]
impl AttributeRepo for PgAttributes {
    async fn list(&self, tenant: TenantId) -> Result<Vec<AttributeDefinition>, StorageError> {
        sqlx::query_as!(
            AttributeRow,
            "SELECT name, schema, required, user_editable, claim, position
               FROM attribute_definition
              WHERE tenant_id = $1
              ORDER BY position, name COLLATE \"C\"",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(AttributeRow::into_model)
        .collect()
    }

    async fn get(
        &self,
        tenant: TenantId,
        name: &str,
    ) -> Result<Option<AttributeDefinition>, StorageError> {
        sqlx::query_as!(
            AttributeRow,
            "SELECT name, schema, required, user_editable, claim, position
               FROM attribute_definition
              WHERE tenant_id = $1 AND name = $2",
            tenant.0,
            name,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(AttributeRow::into_model)
        .transpose()
    }

    async fn upsert(
        &self,
        tenant: TenantId,
        d: &AttributeDefinition,
        now: OffsetDateTime,
    ) -> Result<AttributeDefinition, StorageError> {
        let claim = d
            .claim
            .as_ref()
            .map(|c| to_json("attribute_definition.claim", c))
            .transpose()?;
        sqlx::query_as!(
            AttributeRow,
            "INSERT INTO attribute_definition
                 (tenant_id, name, schema, required, user_editable, claim, position, created_at,
                  updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
             ON CONFLICT (tenant_id, name) DO UPDATE
                SET schema = EXCLUDED.schema,
                    required = EXCLUDED.required,
                    user_editable = EXCLUDED.user_editable,
                    claim = EXCLUDED.claim,
                    position = EXCLUDED.position,
                    updated_at = EXCLUDED.updated_at
          RETURNING name, schema, required, user_editable, claim, position",
            tenant.0,
            d.name,
            d.schema,
            d.required,
            d.user_editable,
            claim,
            i64::from(d.position),
            now,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?
        .into_model()
    }

    async fn delete(&self, tenant: TenantId, name: &str) -> Result<bool, StorageError> {
        // User values are deliberately left in place (a re-created definition sees them again).
        let done = sqlx::query!(
            "DELETE FROM attribute_definition WHERE tenant_id = $1 AND name = $2",
            tenant.0,
            name,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn user_values(
        &self,
        tenant: TenantId,
        user: UserId,
    ) -> Result<Option<Map<String, Value>>, StorageError> {
        sqlx::query_scalar!(
            "SELECT attributes FROM \"user\" WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            user.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(values_from)
        .transpose()
    }

    async fn set_user_values(
        &self,
        tenant: TenantId,
        user: UserId,
        values: &Map<String, Value>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "UPDATE \"user\" SET attributes = $3, updated_at = $4 WHERE tenant_id = $1 AND id = $2",
            tenant.0,
            user.0,
            Value::Object(values.clone()),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
