use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aisoc_core::sha256_hex;
use thiserror::Error;

const DEFAULT_MAX_RAW_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum RawSpoolError {
    #[error("raw evidence exceeds configured byte limit")]
    TooLarge,
    #[error("raw evidence spool I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("existing raw evidence object does not match its digest")]
    IntegrityMismatch,
}

#[derive(Debug, Clone)]
pub struct RawSpool {
    root: PathBuf,
    max_raw_bytes: usize,
}

impl RawSpool {
    pub fn open(root: impl AsRef<Path>, max_raw_bytes: Option<usize>) -> Result<Self, RawSpoolError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        set_private_dir(&root)?;
        Ok(Self {
            root,
            max_raw_bytes: max_raw_bytes.unwrap_or(DEFAULT_MAX_RAW_BYTES),
        })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<String, RawSpoolError> {
        if bytes.len() > self.max_raw_bytes {
            return Err(RawSpoolError::TooLarge);
        }
        let digest = sha256_hex(bytes);
        let path = self.root.join(format!("{digest}.raw"));
        match create_private_file(&path) {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_data()?;
                sync_directory(&self.root)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_bounded(&path, self.max_raw_bytes)?;
                if sha256_hex(&existing) != digest || existing != bytes {
                    return Err(RawSpoolError::IntegrityMismatch);
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(format!("agent://raw/{digest}"))
    }

    pub fn verify_ref(&self, raw_ref: &str) -> Result<bool, RawSpoolError> {
        let Some(digest) = raw_ref.strip_prefix("agent://raw/") else {
            return Ok(false);
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(false);
        }
        let bytes = match read_bounded(&self.root.join(format!("{digest}.raw")), self.max_raw_bytes) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(sha256_hex(&bytes) == digest)
    }
}

fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_bounded(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "raw spool object is unsafe or oversized",
        ));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "raw spool object changed while opening",
            ));
        }
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "raw spool object is oversized",
        ));
    }
    Ok(bytes)
}

fn set_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_data()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn raw_objects_are_content_addressed_and_idempotent() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("aisoc-raw-spool-{nonce}"));
        let spool = RawSpool::open(&root, Some(1024)).expect("spool");
        let first = spool.put(b"evidence").expect("put");
        let second = spool.put(b"evidence").expect("idempotent put");
        assert_eq!(first, second);
        assert!(spool.verify_ref(&first).expect("verify"));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
