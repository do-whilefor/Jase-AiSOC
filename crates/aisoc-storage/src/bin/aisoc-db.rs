#![forbid(unsafe_code)]

use aisoc_storage::postgres::{connect_postgres, healthcheck, migrate, PostgresPoolConfig};

const USAGE: &str = "usage: aisoc-db <migrate|health>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let command = args.next().ok_or(USAGE)?;
    if args.next().is_some() {
        return Err(USAGE.into());
    }
    let database_url = database_url_from_env()?;
    let pool = connect_postgres(&database_url, PostgresPoolConfig::default()).await?;

    match command.as_str() {
        "migrate" => {
            migrate(&pool).await?;
            healthcheck(&pool).await?;
            println!("aisoc-db: migrations applied and database healthy");
        }
        "health" => {
            healthcheck(&pool).await?;
            println!("aisoc-db: database healthy");
        }
        _ => return Err(USAGE.into()),
    }

    pool.close().await;
    Ok(())
}

fn database_url_from_env() -> Result<String, Box<dyn std::error::Error>> {
    for name in ["AISOC_DATABASE_URL", "DATABASE_URL"] {
        if let Ok(value) = std::env::var(name) {
            if !value.trim().is_empty() {
                return Ok(value);
            }
        }
    }
    Err("AISOC_DATABASE_URL is required".into())
}
