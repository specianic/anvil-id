//! `AttributeRepo` on SQLite: per-tenant attribute definitions and the per-user JSON object in
//! `user.attributes`.

use anvil_core::model::{AttributeDefinition, ClaimRule, TenantId, UserId};
use anvil_core::ports::{AttributeRepo, StorageError};
use serde_json::{Map, Value};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{from_json, i64_to_u32, map_err, odt_to_ms, opt_from_json, to_json};

#[derive(Debug, Clone)]
pub(crate) struct SqliteAttributes {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct DefinitionRow {
    name: String,
    schema: String,
    required: bool,
    user_editable: bool,
    claim: Option<String>,
    position: i64,
}

impl TryFrom<DefinitionRow> for AttributeDefinition {
    type Error = StorageError;

    fn try_from(r: DefinitionRow) -> Result<Self, StorageError> {
        Ok(AttributeDefinition {
            name: r.name,
            schema: from_json(&r.schema, "attribute_definition.schema")?,
            required: r.required,
            user_editable: r.user_editable,
            claim: opt_from_json::<ClaimRule>(r.claim.as_deref(), "attribute_definition.claim")?,
            position: i64_to_u32(r.position, "attribute_definition.position")?,
        })
    }
}

#[async_trait::async_trait]
impl AttributeRepo for SqliteAttributes {
    async fn list(&self, tenant: TenantId) -> Result<Vec<AttributeDefinition>, StorageError> {
        sqlx::query_as!(
            DefinitionRow,
            r#"SELECT name AS "name!", schema AS "schema!", required AS "required!: bool",
                      user_editable AS "user_editable!: bool", claim AS "claim?",
                      position AS "position!"
                 FROM attribute_definition WHERE tenant_id = ?1
                ORDER BY position, name"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(AttributeDefinition::try_from)
        .collect()
    }

    async fn get(
        &self,
        tenant: TenantId,
        name: &str,
    ) -> Result<Option<AttributeDefinition>, StorageError> {
        sqlx::query_as!(
            DefinitionRow,
            r#"SELECT name AS "name!", schema AS "schema!", required AS "required!: bool",
                      user_editable AS "user_editable!: bool", claim AS "claim?",
                      position AS "position!"
                 FROM attribute_definition WHERE tenant_id = ?1 AND name = ?2"#,
            tenant.0,
            name,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(AttributeDefinition::try_from)
        .transpose()
    }

    async fn upsert(
        &self,
        tenant: TenantId,
        definition: &AttributeDefinition,
        now: OffsetDateTime,
    ) -> Result<AttributeDefinition, StorageError> {
        let schema = to_json(&definition.schema, "attribute_definition.schema")?;
        let claim = definition
            .claim
            .as_ref()
            .map(|c| to_json(c, "attribute_definition.claim"))
            .transpose()?;
        let position = i64::from(definition.position);
        let now_ms = odt_to_ms(now);
        sqlx::query_as!(
            DefinitionRow,
            r#"INSERT INTO attribute_definition
                   (tenant_id, name, schema, required, user_editable, claim, position,
                    created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
               ON CONFLICT (tenant_id, name) DO UPDATE
                  SET schema = excluded.schema, required = excluded.required,
                      user_editable = excluded.user_editable, claim = excluded.claim,
                      position = excluded.position, updated_at = excluded.updated_at
            RETURNING name AS "name!", schema AS "schema!", required AS "required!: bool",
                      user_editable AS "user_editable!: bool", claim AS "claim?",
                      position AS "position!""#,
            tenant.0,
            definition.name,
            schema,
            definition.required,
            definition.user_editable,
            claim,
            position,
            now_ms,
        )
        .fetch_one(&self.writer)
        .await
        .map_err(map_err)
        .and_then(AttributeDefinition::try_from)
    }

    async fn delete(&self, tenant: TenantId, name: &str) -> Result<bool, StorageError> {
        // Stored user values are deliberately left alone.
        let done = sqlx::query!(
            "DELETE FROM attribute_definition WHERE tenant_id = ?1 AND name = ?2",
            tenant.0,
            name,
        )
        .execute(&self.writer)
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
            r#"SELECT attributes AS "attributes!" FROM user WHERE tenant_id = ?1 AND id = ?2"#,
            tenant.0,
            user.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(|text| from_json::<Map<String, Value>>(&text, "user.attributes"))
        .transpose()
    }

    async fn set_user_values(
        &self,
        tenant: TenantId,
        user: UserId,
        values: &Map<String, Value>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let attributes = to_json(values, "user.attributes")?;
        let now_ms = odt_to_ms(now);
        let done = sqlx::query!(
            "UPDATE user SET attributes = ?3, updated_at = ?4 WHERE tenant_id = ?1 AND id = ?2",
            tenant.0,
            user.0,
            attributes,
            now_ms,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
