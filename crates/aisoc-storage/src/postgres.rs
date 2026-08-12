//! PostgreSQL/SQLx primitives for the V4 control-plane storage boundary.
//!
//! The local append-only journal remains useful for edge durability and replay,
//! but PostgreSQL is the authoritative transactional plane for central state.

use std::time::Duration;

use sqlx::migrate::Migrator;
pub use sqlx::postgres::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::StorageError;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone, Copy)]
pub struct PostgresPoolConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
        }
    }
}

pub async fn connect_postgres(
    database_url: &str,
    config: PostgresPoolConfig,
) -> Result<PgPool, StorageError> {
    validate_database_url(database_url)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<(), StorageError> {
    ensure_native_migration_safe(pool).await?;
    MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn ensure_native_migration_safe(pool: &PgPool) -> Result<(), StorageError> {
    let legacy_schema: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public.alembic_version')::text")
            .fetch_one(pool)
            .await?;
    let native_schema: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations')::text")
            .fetch_one(pool)
            .await?;
    if legacy_schema.is_some() && native_schema.is_none() {
        return Err(StorageError::LegacySchemaDetected);
    }
    Ok(())
}

pub async fn healthcheck(pool: &PgPool) -> Result<(), StorageError> {
    let value: i32 = sqlx::query_scalar("SELECT 1").fetch_one(pool).await?;
    if value != 1 {
        return Err(StorageError::DatabaseInvariant);
    }
    Ok(())
}

fn validate_database_url(database_url: &str) -> Result<(), StorageError> {
    if database_url.len() > 4096
        || !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://"))
    {
        return Err(StorageError::InvalidDatabaseUrl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_postgres_database_urls() {
        assert!(matches!(
            validate_database_url("sqlite:///tmp/aisoc.db"),
            Err(StorageError::InvalidDatabaseUrl)
        ));
        assert!(validate_database_url("postgresql://aisoc@localhost/aisoc").is_ok());
    }
}
