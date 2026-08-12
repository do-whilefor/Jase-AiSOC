use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const SHA256_BLOCK_BYTES: usize = 64;
const FILE_BUFFER_BYTES: usize = 64 * 1024;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_bytes(data))
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mut block_key = if key.len() > SHA256_BLOCK_BYTES {
        sha256_bytes(key).to_vec()
    } else {
        key.to_vec()
    };
    block_key.resize(SHA256_BLOCK_BYTES, 0);

    let mut ipad = [0x36_u8; SHA256_BLOCK_BYTES];
    let mut opad = [0x5c_u8; SHA256_BLOCK_BYTES];
    for (index, byte) in block_key.iter().enumerate() {
        ipad[index] ^= byte;
        opad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    hex::encode(outer.finalize())
}

pub fn secure_compare(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&lhs, &rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

pub fn open_regular_file_nofollow(path: &Path, max_bytes: u64) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file: File = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hash target must be a private single-link regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hash target exceeds the configured size limit",
        ));
    }
    Ok(file)
}

pub fn sha256_file(path: &Path, max_bytes: u64) -> io::Result<(String, u64)> {
    let mut file = open_regular_file_nofollow(path, max_bytes)?;
    let metadata = file.metadata()?;

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; FILE_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hash target grew beyond the configured size limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }

    let final_metadata = file.metadata()?;
    if final_metadata.len() != metadata.len()
        || final_metadata.mtime() != metadata.mtime()
        || final_metadata.mtime_nsec() != metadata.mtime_nsec()
        || final_metadata.ctime() != metadata.ctime()
        || final_metadata.ctime_nsec() != metadata.ctime_nsec()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hash target changed while it was being read",
        ));
    }

    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sha256_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn known_hmac_vector() {
        assert_eq!(
            hmac_sha256_hex(b"key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn comparison_requires_equal_content_and_length() {
        assert!(secure_compare(b"same", b"same"));
        assert!(!secure_compare(b"same", b"diff"));
        assert!(!secure_compare(b"same", b"same-longer"));
    }
}
