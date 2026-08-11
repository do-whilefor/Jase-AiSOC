#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("aisoc-core targets Linux only");

pub mod hashing;
pub mod ioc;
pub mod linux;
pub mod static_analysis;

pub use hashing::{hmac_sha256_hex, secure_compare, sha256_bytes, sha256_file, sha256_hex};
pub use ioc::{normalize_domain, normalize_ip, normalize_sha256, IocMatcher};
pub use linux::{
    probe_linux, CapabilityLevel, CapabilityReport, CgroupVersion, CollectorCapability,
    CollectorState, InitSystem, LinuxProbePaths, PackageManager, PlatformInfo, ProbeError,
};
pub use static_analysis::{ascii_strings, entropy, inspect_elf, ElfInfo};
