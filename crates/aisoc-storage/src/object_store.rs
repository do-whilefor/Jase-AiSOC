//! Jase-AiSOC immutable raw-evidence object storage.
//!
//! The local backend is the authoritative Base/Standalone implementation. It
//! deliberately exposes opaque tenant-bound locators rather than arbitrary
//! paths or URLs, creates every object exactly once, and verifies integrity on
//! every read. Central/S3 adapters can implement the same contract later.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aisoc_core::{open_regular_file_nofollow, secure_compare, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const OBJECT_SUFFIX: &str = ".evidence";
const EVIDENCE_SCHEME: &str = "evidence://";

#[derive(Debug, Error)]
pub enum ObjectStoreError {
    #[error("raw evidence object I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid tenant identifier")]
    InvalidTenant,
    #[error("invalid or out-of-scope raw evidence reference")]
    InvalidReference,
    #[error("raw evidence object integrity check failed")]
    Integrity,
    #[error("raw evidence object path is insecure")]
    InsecurePath,
    #[error("raw evidence object exceeds the configured read bound")]
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMetadata {
    pub raw_ref: String,
    pub object_key: String,
    pub sha256: String,
    pub content_bytes: usize,
    pub media_type: String,
}

#[derive(Debug, Clone)]
pub struct LocalObjectStore {
    root: PathBuf,
}

impl LocalObjectStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ObjectStoreError> {
        let root = root.as_ref().to_path_buf();
        if !root.is_absolute() {
            return Err(ObjectStoreError::InsecurePath);
        }
        prepare_private_root(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(
        &self,
        tenant_id: &str,
        data: &[u8],
        media_type: &str,
    ) -> Result<ObjectMetadata, ObjectStoreError> {
        validate_tenant(tenant_id)?;
        if media_type.is_empty() || media_type.len() > 255 || !media_type.is_ascii() {
            return Err(ObjectStoreError::InvalidReference);
        }
        let digest = sha256_hex(data);
        if data.is_empty() {
            return Err(ObjectStoreError::InvalidReference);
        }
        let object_key = object_key(tenant_id, &digest);
        let destination = self.path_for_key(&object_key)?;

        match create_private_file(&destination) {
            Ok(mut file) => {
                if let Err(error) = file.write_all(data).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&destination);
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_verified_file(&destination, data.len())?;
                if !secure_compare(sha256_hex(&existing).as_bytes(), digest.as_bytes()) {
                    return Err(ObjectStoreError::Integrity);
                }
            }
            Err(error) => return Err(error.into()),
        }

        Ok(ObjectMetadata {
            raw_ref: format!("{EVIDENCE_SCHEME}{tenant_id}/{digest}"),
            object_key,
            sha256: digest,
            content_bytes: data.len(),
            media_type: media_type.to_owned(),
        })
    }

    pub fn get(
        &self,
        tenant_id: &str,
        raw_ref: &str,
        expected_sha256: &str,
        expected_bytes: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        validate_tenant(tenant_id)?;
        if expected_bytes > max_bytes {
            return Err(ObjectStoreError::TooLarge);
        }
        if !is_lower_sha256(expected_sha256) {
            return Err(ObjectStoreError::InvalidReference);
        }
        let digest = parse_raw_ref(tenant_id, raw_ref)?;
        if !secure_compare(digest.as_bytes(), expected_sha256.as_bytes()) {
            return Err(ObjectStoreError::Integrity);
        }
        let key = object_key(tenant_id, digest);
        let path = self.path_for_key(&key)?;
        let data = read_verified_file(&path, max_bytes)?;
        if data.len() != expected_bytes
            || !secure_compare(sha256_hex(&data).as_bytes(), expected_sha256.as_bytes())
        {
            return Err(ObjectStoreError::Integrity);
        }
        Ok(data)
    }

    pub fn get_by_key(
        &self,
        tenant_id: &str,
        key: &str,
        expected_sha256: &str,
        expected_bytes: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        validate_tenant(tenant_id)?;
        if expected_bytes > max_bytes {
            return Err(ObjectStoreError::TooLarge);
        }
        if !is_lower_sha256(expected_sha256)
            || key != object_key(tenant_id, expected_sha256)
        {
            return Err(ObjectStoreError::InvalidReference);
        }
        let path = self.path_for_key(key)?;
        let data = read_verified_file(&path, max_bytes)?;
        if data.len() != expected_bytes
            || !secure_compare(sha256_hex(&data).as_bytes(), expected_sha256.as_bytes())
        {
            return Err(ObjectStoreError::Integrity);
        }
        Ok(data)
    }

    pub fn get_by_ref(
        &self,
        tenant_id: &str,
        raw_ref: &str,
        expected_sha256: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ObjectStoreError> {
        validate_tenant(tenant_id)?;
        if !is_lower_sha256(expected_sha256) {
            return Err(ObjectStoreError::InvalidReference);
        }
        let digest = parse_raw_ref(tenant_id, raw_ref)?;
        if !secure_compare(digest.as_bytes(), expected_sha256.as_bytes()) {
            return Err(ObjectStoreError::Integrity);
        }
        let path = self.path_for_key(&object_key(tenant_id, digest))?;
        let data = read_verified_file(&path, max_bytes)?;
        if !secure_compare(sha256_hex(&data).as_bytes(), expected_sha256.as_bytes()) {
            return Err(ObjectStoreError::Integrity);
        }
        Ok(data)
    }

    pub fn metadata_for_ref(
        &self,
        tenant_id: &str,
        raw_ref: &str,
        expected_sha256: &str,
    ) -> Result<(String, usize), ObjectStoreError> {
        validate_tenant(tenant_id)?;
        if !is_lower_sha256(expected_sha256) {
            return Err(ObjectStoreError::InvalidReference);
        }
        let digest = parse_raw_ref(tenant_id, raw_ref)?;
        if !secure_compare(digest.as_bytes(), expected_sha256.as_bytes()) {
            return Err(ObjectStoreError::Integrity);
        }
        let key = object_key(tenant_id, digest);
        let path = self.path_for_key(&key)?;
        let metadata = fs::symlink_metadata(&path)?;
        validate_object_metadata(&metadata, usize::MAX)?;
        let file = open_regular_file_nofollow(&path, u64::MAX)?;
        let opened = file.metadata()?;
        validate_object_metadata(&opened, usize::MAX)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
                return Err(ObjectStoreError::InsecurePath);
            }
        }
        let content_bytes =
            usize::try_from(opened.len()).map_err(|_| ObjectStoreError::TooLarge)?;
        Ok((key, content_bytes))
    }

    pub fn verify_metadata(&self, metadata: &ObjectMetadata) -> Result<(), ObjectStoreError> {
        let expected_key = object_key(
            tenant_from_ref(&metadata.raw_ref)?,
            parse_unscoped_raw_ref(&metadata.raw_ref)?,
        );
        if metadata.object_key != expected_key {
            return Err(ObjectStoreError::Integrity);
        }
        let tenant_id = tenant_from_ref(&metadata.raw_ref)?;
        self.get(
            tenant_id,
            &metadata.raw_ref,
            &metadata.sha256,
            metadata.content_bytes,
            metadata.content_bytes,
        )?;
        Ok(())
    }

    fn path_for_key(&self, key: &str) -> Result<PathBuf, ObjectStoreError> {
        if key.is_empty()
            || key.starts_with('/')
            || key.contains('/')
            || key.contains('\\')
            || matches!(key, "." | "..")
        {
            return Err(ObjectStoreError::InvalidReference);
        }
        let destination = self.root.join(key);
        if !destination.starts_with(&self.root) {
            return Err(ObjectStoreError::InsecurePath);
        }
        Ok(destination)
    }
}

fn object_key(tenant_id: &str, digest: &str) -> String {
    format!("raw--{tenant_id}--{digest}{OBJECT_SUFFIX}")
}

fn parse_raw_ref<'a>(tenant_id: &str, raw_ref: &'a str) -> Result<&'a str, ObjectStoreError> {
    let prefix = format!("{EVIDENCE_SCHEME}{tenant_id}/");
    let digest = raw_ref
        .strip_prefix(&prefix)
        .ok_or(ObjectStoreError::InvalidReference)?;
    if !is_lower_sha256(digest) || digest.contains('/') {
        return Err(ObjectStoreError::InvalidReference);
    }
    Ok(digest)
}

fn parse_unscoped_raw_ref(raw_ref: &str) -> Result<&str, ObjectStoreError> {
    let remainder = raw_ref
        .strip_prefix(EVIDENCE_SCHEME)
        .ok_or(ObjectStoreError::InvalidReference)?;
    let (_, digest) = remainder
        .split_once('/')
        .ok_or(ObjectStoreError::InvalidReference)?;
    if !is_lower_sha256(digest) || digest.contains('/') {
        return Err(ObjectStoreError::InvalidReference);
    }
    Ok(digest)
}

fn tenant_from_ref(raw_ref: &str) -> Result<&str, ObjectStoreError> {
    let remainder = raw_ref
        .strip_prefix(EVIDENCE_SCHEME)
        .ok_or(ObjectStoreError::InvalidReference)?;
    let (tenant_id, _) = remainder
        .split_once('/')
        .ok_or(ObjectStoreError::InvalidReference)?;
    validate_tenant(tenant_id)?;
    Ok(tenant_id)
}

fn validate_tenant(value: &str) -> Result<(), ObjectStoreError> {
    let Some(rest) = value.strip_prefix("ten_") else {
        return Err(ObjectStoreError::InvalidTenant);
    };
    if rest.len() < 8
        || value.len() > 132
        || !rest.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(ObjectStoreError::InvalidTenant);
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn prepare_private_root(path: &Path) -> Result<(), ObjectStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ObjectStoreError::InsecurePath);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(ObjectStoreError::InsecurePath)?;
            let parent_metadata = fs::symlink_metadata(parent)?;
            if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
                return Err(ObjectStoreError::InsecurePath);
            }
            fs::create_dir(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    validate_directory_metadata(&metadata)
}

fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), ObjectStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ObjectStoreError::InsecurePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ObjectStoreError::InsecurePath);
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn read_verified_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ObjectStoreError> {
    let before = fs::symlink_metadata(path)?;
    validate_object_metadata(&before, max_bytes)?;
    let file = open_regular_file_nofollow(
        path,
        u64::try_from(max_bytes).unwrap_or(u64::MAX),
    )?;
    let opened = file.metadata()?;
    validate_object_metadata(&opened, max_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ObjectStoreError::InsecurePath);
        }
    }
    let after = fs::symlink_metadata(path)?;
    validate_object_metadata(&after, max_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != opened.dev() || after.ino() != opened.ino() {
            return Err(ObjectStoreError::InsecurePath);
        }
    }
    let opened_len = usize::try_from(opened.len()).map_err(|_| ObjectStoreError::TooLarge)?;
    if opened_len > max_bytes {
        return Err(ObjectStoreError::TooLarge);
    }
    let mut data = Vec::with_capacity(opened_len);
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bounded_reader = file.take(limit);
    bounded_reader.read_to_end(&mut data)?;
    if data.len() > max_bytes {
        return Err(ObjectStoreError::TooLarge);
    }
    let file = bounded_reader.into_inner();
    let final_metadata = file.metadata()?;
    validate_object_metadata(&final_metadata, max_bytes)?;
    if final_metadata.len() != opened.len() {
        return Err(ObjectStoreError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if final_metadata.dev() != opened.dev()
            || final_metadata.ino() != opened.ino()
            || final_metadata.mtime() != opened.mtime()
            || final_metadata.mtime_nsec() != opened.mtime_nsec()
            || final_metadata.ctime() != opened.ctime()
            || final_metadata.ctime_nsec() != opened.ctime_nsec()
        {
            return Err(ObjectStoreError::Integrity);
        }
    }
    Ok(data)
}

fn validate_object_metadata(
    metadata: &fs::Metadata,
    max_bytes: usize,
) -> Result<(), ObjectStoreError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ObjectStoreError::InsecurePath);
    }
    if metadata.len() > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
        return Err(ObjectStoreError::TooLarge);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(ObjectStoreError::InsecurePath);
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "jase-aisoc-object-store-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    #[test]
    fn object_is_immutable_tenant_bound_and_content_addressed() {
        let root = temp_root("roundtrip");
        let store = LocalObjectStore::open(&root).expect("open");
        let metadata = store
            .put("ten_12345678", b"immutable evidence", "application/json")
            .expect("put");
        assert_eq!(
            store
                .get(
                    "ten_12345678",
                    &metadata.raw_ref,
                    &metadata.sha256,
                    metadata.content_bytes,
                    1024,
                )
                .expect("get"),
            b"immutable evidence"
        );
        let replayed = store
            .put("ten_12345678", b"immutable evidence", "application/json")
            .expect("idempotent put");
        assert_eq!(metadata.object_key, replayed.object_key);
        assert!(matches!(
            store.get(
                "ten_foreign01",
                &metadata.raw_ref,
                &metadata.sha256,
                metadata.content_bytes,
                1024
            ),
            Err(ObjectStoreError::InvalidReference)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn read_rejects_tampering_and_symlink_objects() {
        let root = temp_root("tamper");
        let store = LocalObjectStore::open(&root).expect("open");
        let metadata = store
            .put("ten_12345678", b"original", "application/json")
            .expect("put");
        let path = root.join(&metadata.object_key);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        fs::write(&path, b"tampered").expect("tamper");
        assert!(matches!(
            store.get(
                "ten_12345678",
                &metadata.raw_ref,
                &metadata.sha256,
                metadata.content_bytes,
                1024
            ),
            Err(ObjectStoreError::Integrity)
        ));

        fs::remove_file(&path).expect("remove object");
        let decoy = root.join("decoy");
        fs::write(&decoy, b"original").expect("decoy");
        fs::set_permissions(&decoy, fs::Permissions::from_mode(0o600)).expect("decoy mode");
        symlink(&decoy, &path).expect("symlink");
        assert!(matches!(
            store.get(
                "ten_12345678",
                &metadata.raw_ref,
                &metadata.sha256,
                metadata.content_bytes,
                1024
            ),
            Err(ObjectStoreError::InsecurePath)
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn read_rejects_hardlinked_objects() {
        let root = temp_root("hardlink");
        let store = LocalObjectStore::open(&root).expect("open");
        let metadata = store
            .put("ten_12345678", b"original", "application/json")
            .expect("put");
        let path = root.join(&metadata.object_key);
        let second_link = root.join("second-link.evidence");
        fs::hard_link(&path, &second_link).expect("hard link");
        assert!(matches!(
            store.get(
                "ten_12345678",
                &metadata.raw_ref,
                &metadata.sha256,
                metadata.content_bytes,
                1024
            ),
            Err(ObjectStoreError::InsecurePath) | Err(ObjectStoreError::Io(_))
        ));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
