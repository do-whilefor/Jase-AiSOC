#![forbid(unsafe_code)]

pub mod central;
pub mod postgres;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use aisoc_core::sha256_hex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("append-only journal integrity check failed")]
    Integrity,
    #[error("append-only journal path is insecure")]
    InsecurePath,
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("database URL must use PostgreSQL and be bounded")]
    InvalidDatabaseUrl,
    #[error("database health invariant failed")]
    DatabaseInvariant,
    #[error("central repository idempotency or tenant invariant conflict")]
    DataConflict,
    #[error("numeric value exceeds PostgreSQL storage bounds")]
    NumericOverflow,
    #[error("agent identity is revoked in the central repository")]
    AgentRevoked,
    #[error("agent identity is bound to a different host in the central repository")]
    AgentBindingMismatch,
    #[error("legacy Alembic schema detected; use an explicit data migration before SQLx cutover")]
    LegacySchemaDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord<T> {
    previous_sha256: Option<String>,
    payload: T,
    record_sha256: String,
}

#[derive(Debug)]
pub struct AppendOnlyJsonl<T> {
    path: PathBuf,
    last_sha256: Option<String>,
    _marker: std::marker::PhantomData<T>,
}

impl<T> AppendOnlyJsonl<T>
where
    T: Serialize + DeserializeOwned + Clone,
{
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            let metadata = fs::symlink_metadata(parent)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(StorageError::InsecurePath);
            }
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_journal_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(&path)?;
            }
            Err(error) => return Err(error.into()),
        }
        // Verify that the path still resolves to the same regular file after open.
        let _ = open_verified(&path, false, true)?;
        let mut store = Self {
            path,
            last_sha256: None,
            _marker: std::marker::PhantomData,
        };
        store.verify()?;
        Ok(store)
    }

    pub fn append(&mut self, payload: T) -> Result<String, StorageError> {
        let material = serde_json::to_vec(&(self.last_sha256.as_deref(), &payload))?;
        let record_sha256 = sha256_hex(&material);
        let record = StoredRecord {
            previous_sha256: self.last_sha256.clone(),
            payload,
            record_sha256: record_sha256.clone(),
        };
        let mut file = open_verified(&self.path, true, false)?;
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        self.last_sha256 = Some(record_sha256.clone());
        Ok(record_sha256)
    }

    pub fn read_all(&self) -> Result<Vec<T>, StorageError> {
        let file = open_verified(&self.path, false, true)?;
        let mut values = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: StoredRecord<T> = serde_json::from_str(&line)?;
            values.push(record.payload);
        }
        Ok(values)
    }

    pub fn verify(&mut self) -> Result<(), StorageError> {
        let file = open_verified(&self.path, false, true)?;
        let mut previous: Option<String> = None;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: StoredRecord<T> = serde_json::from_str(&line)?;
            if record.previous_sha256 != previous {
                return Err(StorageError::Integrity);
            }
            let material = serde_json::to_vec(&(record.previous_sha256.as_deref(), &record.payload))?;
            if sha256_hex(&material) != record.record_sha256 {
                return Err(StorageError::Integrity);
            }
            previous = Some(record.record_sha256);
        }
        self.last_sha256 = previous;
        Ok(())
    }
}

fn validate_journal_metadata(metadata: &fs::Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::InsecurePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::InsecurePath);
        }
    }
    Ok(())
}

fn open_verified(path: &Path, append: bool, read: bool) -> Result<File, StorageError> {
    let before = fs::symlink_metadata(path)?;
    validate_journal_metadata(&before)?;
    let mut options = OpenOptions::new();
    options.append(append).read(read);
    let file = options.open(path)?;
    let opened = file.metadata()?;
    validate_journal_metadata(&opened)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(StorageError::InsecurePath);
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aisoc-storage-{label}-{}-{nonce}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn append_only_store_survives_reopen() {
        let path = temp_path("reopen");
        let mut store = AppendOnlyJsonl::<String>::open(&path).expect("open");
        store.append("one".to_owned()).expect("append");
        store.append("two".to_owned()).expect("append");
        drop(store);
        let reopened = AppendOnlyJsonl::<String>::open(&path).expect("reopen");
        assert_eq!(reopened.read_all().expect("read"), vec!["one", "two"]);
        fs::remove_file(path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_journal() {
        use std::os::unix::fs::symlink;
        let target = temp_path("target");
        let link = temp_path("link");
        fs::write(&target, b"").expect("target");
        fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("permissions");
        symlink(&target, &link).expect("symlink");
        assert!(matches!(
            AppendOnlyJsonl::<String>::open(&link),
            Err(StorageError::InsecurePath)
        ));
        fs::remove_file(link).expect("remove link");
        fs::remove_file(target).expect("remove target");
    }
}
