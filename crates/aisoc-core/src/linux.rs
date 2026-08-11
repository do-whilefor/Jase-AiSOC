use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_OS_RELEASE_BYTES: usize = 64 * 1024;
const MAX_PROBE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    Systemd,
    OpenRc,
    Runit,
    Other,
    Unknown,
}

impl InitSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "openrc",
            Self::Runit => "runit",
            Self::Other => "other",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
    Unknown,
}

impl CgroupVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Pacman,
    Apk,
    Unknown,
}

impl PackageManager {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Yum => "yum",
            Self::Zypper => "zypper",
            Self::Pacman => "pacman",
            Self::Apk => "apk",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorState {
    Enabled,
    Degraded,
    Failed,
}

impl CollectorState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLevel {
    L0,
    L1,
}

impl CapabilityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformInfo {
    pub distro_id: String,
    pub distro_like: Vec<String>,
    pub version_id: Option<String>,
    pub kernel_release: String,
    pub architecture: String,
    pub init_system: InitSystem,
    pub package_manager: PackageManager,
    pub btf_available: bool,
    pub cgroup_version: CgroupVersion,
    pub security_modules: Vec<String>,
    pub probe_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorCapability {
    pub name: &'static str,
    pub state: CollectorState,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub level: CapabilityLevel,
    pub platform: PlatformInfo,
    pub collectors: Vec<CollectorCapability>,
}

#[derive(Debug, Clone)]
pub struct LinuxProbePaths {
    pub os_release_candidates: Vec<PathBuf>,
    pub init_comm: PathBuf,
    pub btf_vmlinux: PathBuf,
    pub cgroup_v2_controllers: PathBuf,
    pub cgroup_v1_registry: PathBuf,
    pub lsm_list: PathBuf,
    pub journal_socket: PathBuf,
    pub auditctl_candidates: Vec<PathBuf>,
    pub apt_candidates: Vec<PathBuf>,
    pub dnf_candidates: Vec<PathBuf>,
    pub yum_candidates: Vec<PathBuf>,
    pub zypper_candidates: Vec<PathBuf>,
    pub pacman_candidates: Vec<PathBuf>,
    pub apk_candidates: Vec<PathBuf>,
}

impl Default for LinuxProbePaths {
    fn default() -> Self {
        Self {
            os_release_candidates: vec![
                PathBuf::from("/etc/os-release"),
                PathBuf::from("/usr/lib/os-release"),
            ],
            init_comm: PathBuf::from("/proc/1/comm"),
            btf_vmlinux: PathBuf::from("/sys/kernel/btf/vmlinux"),
            cgroup_v2_controllers: PathBuf::from("/sys/fs/cgroup/cgroup.controllers"),
            cgroup_v1_registry: PathBuf::from("/proc/cgroups"),
            lsm_list: PathBuf::from("/sys/kernel/security/lsm"),
            journal_socket: PathBuf::from("/run/systemd/journal/socket"),
            auditctl_candidates: vec![
                PathBuf::from("/sbin/auditctl"),
                PathBuf::from("/usr/sbin/auditctl"),
            ],
            apt_candidates: vec![PathBuf::from("/usr/bin/apt-get"), PathBuf::from("/usr/bin/apt")],
            dnf_candidates: vec![PathBuf::from("/usr/bin/dnf"), PathBuf::from("/bin/dnf")],
            yum_candidates: vec![PathBuf::from("/usr/bin/yum"), PathBuf::from("/bin/yum")],
            zypper_candidates: vec![PathBuf::from("/usr/bin/zypper")],
            pacman_candidates: vec![PathBuf::from("/usr/bin/pacman")],
            apk_candidates: vec![PathBuf::from("/sbin/apk"), PathBuf::from("/usr/sbin/apk")],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeError {
    message: String,
}

impl ProbeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProbeError {}

pub fn parse_os_release(value: &str) -> Result<BTreeMap<String, String>, ProbeError> {
    if value.len() > MAX_OS_RELEASE_BYTES {
        return Err(ProbeError::new("os-release exceeds the 64 KiB safety limit"));
    }
    if value.as_bytes().contains(&0) {
        return Err(ProbeError::new("os-release contains a NUL byte"));
    }

    let mut result = BTreeMap::new();
    for (index, raw_line) in value.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            return Err(ProbeError::new(format!(
                "invalid os-release assignment on line {line_number}"
            )));
        };
        if !valid_os_release_key(key) {
            return Err(ProbeError::new(format!(
                "invalid os-release assignment on line {line_number}"
            )));
        }
        if result.contains_key(key) {
            return Err(ProbeError::new(format!("duplicate os-release key: {key}")));
        }
        let parsed = parse_assignment_value(raw_value, line_number)?;
        result.insert(key.to_owned(), parsed);
    }
    Ok(result)
}

pub fn probe_linux(
    paths: &LinuxProbePaths,
    kernel_release: &str,
    architecture: &str,
) -> CapabilityReport {
    let mut warnings = Vec::new();
    let assignments = match read_first(
        &paths.os_release_candidates,
        "os-release",
        MAX_OS_RELEASE_BYTES,
        &mut warnings,
    ) {
        Some(value) => match parse_os_release(&value) {
            Ok(assignments) => assignments,
            Err(error) => {
                warnings.push(error.to_string());
                BTreeMap::new()
            }
        },
        None => BTreeMap::new(),
    };

    let distro_id = assignments
        .get("ID")
        .map(|value| value.to_ascii_lowercase())
        .filter(|value| valid_identifier(value))
        .unwrap_or_else(|| {
            warnings.push("os-release ID is missing or invalid".to_owned());
            "unknown".to_owned()
        });
    let distro_like = normalize_words(
        assignments.get("ID_LIKE").map(String::as_str).unwrap_or_default(),
        &mut warnings,
    );
    let version_id = assignments.get("VERSION_ID").cloned().and_then(|value| {
        if value.len() <= 64 {
            Some(value)
        } else {
            warnings.push("os-release VERSION_ID exceeds 64 characters".to_owned());
            None
        }
    });

    let init_text = read_text(
        &paths.init_comm,
        "init process name",
        MAX_PROBE_BYTES,
        &mut warnings,
    );
    let init_system = detect_init_system(init_text.as_deref());
    let cgroup_version = if path_exists(&paths.cgroup_v2_controllers) {
        CgroupVersion::V2
    } else if path_exists(&paths.cgroup_v1_registry) {
        CgroupVersion::V1
    } else {
        CgroupVersion::Unknown
    };
    let security_modules = read_text(
        &paths.lsm_list,
        "LSM list",
        MAX_PROBE_BYTES,
        &mut warnings,
    )
        .map(|value| normalize_modules(&value, &mut warnings))
        .unwrap_or_default();
    let package_manager = detect_package_manager(paths);

    let platform = PlatformInfo {
        distro_id,
        distro_like,
        version_id,
        kernel_release: bounded_fact(kernel_release, 128),
        architecture: bounded_fact(architecture, 64),
        init_system,
        package_manager,
        btf_available: path_exists(&paths.btf_vmlinux),
        cgroup_version,
        security_modules,
        probe_warnings: warnings,
    };

    let collectors = vec![
        journald_capability(paths, &platform),
        auditd_capability(paths),
        ebpf_capability(&platform),
    ];
    let level = if collectors.iter().any(|collector| {
        matches!(collector.name, "journald" | "auditd")
            && collector.state == CollectorState::Enabled
    }) {
        CapabilityLevel::L1
    } else {
        CapabilityLevel::L0
    };

    CapabilityReport {
        level,
        platform,
        collectors,
    }
}

fn parse_assignment_value(raw: &str, line_number: usize) -> Result<String, ProbeError> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    let first = value.as_bytes()[0];
    if first == b'\'' || first == b'"' {
        if value.len() < 2 || value.as_bytes()[value.len() - 1] != first {
            return Err(ProbeError::new(format!(
                "invalid os-release quoting on line {line_number}"
            )));
        }
        let inner = &value[1..value.len() - 1];
        if first == b'\'' {
            if inner.contains('\'') {
                return Err(ProbeError::new(format!(
                    "invalid os-release quoting on line {line_number}"
                )));
            }
            return Ok(inner.to_owned());
        }
        return parse_double_quoted(inner, line_number);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ProbeError::new(format!(
            "unquoted whitespace in os-release value on line {line_number}"
        )));
    }
    Ok(value.to_owned())
}

fn parse_double_quoted(value: &str, line_number: usize) -> Result<String, ProbeError> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            if character == '"' {
                return Err(ProbeError::new(format!(
                    "invalid os-release quoting on line {line_number}"
                )));
            }
            output.push(character);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(ProbeError::new(format!(
                "invalid os-release quoting on line {line_number}"
            )));
        };
        match escaped {
            '"' | '\\' | '$' | '`' => output.push(escaped),
            other => {
                output.push('\\');
                output.push(other);
            }
        }
    }
    Ok(output)
}

fn valid_os_release_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn normalize_words(value: &str, warnings: &mut Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut words = Vec::new();
    for word in value.split_whitespace().map(str::to_ascii_lowercase) {
        if !valid_identifier(&word) {
            warnings.push("os-release ID_LIKE contains an invalid identifier".to_owned());
            return Vec::new();
        }
        if seen.insert(word.clone()) {
            words.push(word);
        }
    }
    words
}

fn normalize_modules(value: &str, warnings: &mut Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut modules = Vec::new();
    for module in value.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        let normalized = module.to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.len() > 64
            || !normalized.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
        {
            warnings.push("LSM list contains an invalid module name".to_owned());
            return Vec::new();
        }
        if seen.insert(normalized.clone()) {
            modules.push(normalized);
        }
    }
    modules
}

fn read_first(
    candidates: &[PathBuf],
    label: &str,
    max_bytes: usize,
    warnings: &mut Vec<String>,
) -> Option<String> {
    for path in candidates {
        if path_exists(path) {
            return read_text(path, label, max_bytes, warnings);
        }
    }
    warnings.push(format!("{label} is unavailable"));
    None
}

fn read_text(
    path: &Path,
    label: &str,
    max_bytes: usize,
    warnings: &mut Vec<String>,
) -> Option<String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            warnings.push(format!("{label} could not be read: {:?}", error.kind()));
            return None;
        }
    };
    let mut data = Vec::with_capacity(max_bytes.saturating_add(1));
    let mut reader = file.take(max_bytes.saturating_add(1) as u64);
    if let Err(error) = reader.read_to_end(&mut data) {
        warnings.push(format!("{label} could not be read: {:?}", error.kind()));
        return None;
    }
    if data.len() > max_bytes {
        warnings.push(format!("{label} exceeds the {max_bytes} byte probe limit"));
        return None;
    }
    if data.contains(&0) {
        warnings.push(format!("{label} contains a NUL byte"));
        return None;
    }
    match String::from_utf8(data) {
        Ok(value) => Some(value.trim().to_owned()),
        Err(_) => {
            warnings.push(format!("{label} is not valid UTF-8"));
            None
        }
    }
}

fn detect_init_system(value: Option<&str>) -> InitSystem {
    match value.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
        "systemd" => InitSystem::Systemd,
        "openrc" | "openrc-init" => InitSystem::OpenRc,
        "runit" | "runsvdir" => InitSystem::Runit,
        "" => InitSystem::Unknown,
        _ => InitSystem::Other,
    }
}

fn detect_package_manager(paths: &LinuxProbePaths) -> PackageManager {
    if any_exists(&paths.apt_candidates) {
        PackageManager::Apt
    } else if any_exists(&paths.dnf_candidates) {
        PackageManager::Dnf
    } else if any_exists(&paths.yum_candidates) {
        PackageManager::Yum
    } else if any_exists(&paths.zypper_candidates) {
        PackageManager::Zypper
    } else if any_exists(&paths.pacman_candidates) {
        PackageManager::Pacman
    } else if any_exists(&paths.apk_candidates) {
        PackageManager::Apk
    } else {
        PackageManager::Unknown
    }
}

fn journald_capability(paths: &LinuxProbePaths, platform: &PlatformInfo) -> CollectorCapability {
    if path_exists(&paths.journal_socket) {
        return CollectorCapability {
            name: "journald",
            state: CollectorState::Enabled,
            last_error: None,
        };
    }
    if platform.init_system == InitSystem::Systemd {
        return CollectorCapability {
            name: "journald",
            state: CollectorState::Degraded,
            last_error: Some("systemd detected but the journald socket is unavailable".to_owned()),
        };
    }
    CollectorCapability {
        name: "journald",
        state: CollectorState::Failed,
        last_error: Some("journald is unavailable for the detected init system".to_owned()),
    }
}

fn auditd_capability(paths: &LinuxProbePaths) -> CollectorCapability {
    if any_exists(&paths.auditctl_candidates) {
        return CollectorCapability {
            name: "auditd",
            state: CollectorState::Degraded,
            last_error: Some(
                "auditctl is present but runtime access has not been verified".to_owned(),
            ),
        };
    }
    CollectorCapability {
        name: "auditd",
        state: CollectorState::Failed,
        last_error: Some("auditctl is unavailable".to_owned()),
    }
}

fn ebpf_capability(platform: &PlatformInfo) -> CollectorCapability {
    if platform.btf_available {
        return CollectorCapability {
            name: "ebpf",
            state: CollectorState::Degraded,
            last_error: Some(
                "BTF is available but eBPF load permissions and hooks are unverified".to_owned(),
            ),
        };
    }
    CollectorCapability {
        name: "ebpf",
        state: CollectorState::Failed,
        last_error: Some("kernel BTF is unavailable".to_owned()),
    }
}

fn bounded_fact(value: &str, max_length: usize) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "unknown".to_owned();
    }
    trimmed.chars().take(max_length).collect()
}

fn any_exists(paths: &[PathBuf]) -> bool {
    paths.iter().any(|path| path_exists(path))
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aisoc-linux-probe-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[test]
    fn parses_safe_os_release_without_evaluating_shell() {
        let parsed = parse_os_release(
            "ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=\"debian ubuntu\"\nNAME='Ubuntu'\n",
        )
        .expect("valid os-release");
        assert_eq!(parsed.get("ID").map(String::as_str), Some("ubuntu"));
        assert_eq!(parsed.get("VERSION_ID").map(String::as_str), Some("24.04"));
        assert_eq!(parsed.get("ID_LIKE").map(String::as_str), Some("debian ubuntu"));
    }

    #[test]
    fn rejects_unquoted_whitespace_and_duplicate_keys() {
        assert!(parse_os_release("ID=bad value\n").is_err());
        assert!(parse_os_release("ID=one\nID=two\n").is_err());
    }

    #[test]
    fn probes_injected_linux_tree_and_package_manager() {
        let root = temp_root();
        let etc = root.join("etc");
        let proc = root.join("proc");
        let sys = root.join("sys");
        let run = root.join("run");
        let usr_bin = root.join("usr/bin");
        for path in [&etc, &proc, &sys, &run, &usr_bin] {
            fs::create_dir_all(path).expect("mkdir");
        }
        fs::write(etc.join("os-release"), "ID=rocky\nID_LIKE=\"rhel fedora\"\nVERSION_ID=9.6\n")
            .expect("os-release");
        fs::write(proc.join("1-comm"), "systemd\n").expect("init");
        fs::write(usr_bin.join("dnf"), b"").expect("dnf");
        fs::write(run.join("journal-socket"), b"").expect("journal");
        fs::write(sys.join("btf-vmlinux"), b"").expect("btf");
        fs::write(proc.join("cgroups"), b"#subsys_name\n").expect("cgroups");
        fs::write(sys.join("lsm"), b"lockdown,capability,selinux\n").expect("lsm");

        let paths = LinuxProbePaths {
            os_release_candidates: vec![etc.join("os-release")],
            init_comm: proc.join("1-comm"),
            btf_vmlinux: sys.join("btf-vmlinux"),
            cgroup_v2_controllers: sys.join("cgroup-v2"),
            cgroup_v1_registry: proc.join("cgroups"),
            lsm_list: sys.join("lsm"),
            journal_socket: run.join("journal-socket"),
            auditctl_candidates: vec![root.join("auditctl")],
            apt_candidates: vec![root.join("apt")],
            dnf_candidates: vec![usr_bin.join("dnf")],
            yum_candidates: vec![root.join("yum")],
            zypper_candidates: vec![root.join("zypper")],
            pacman_candidates: vec![root.join("pacman")],
            apk_candidates: vec![root.join("apk")],
        };
        let report = probe_linux(&paths, "6.12.0", "x86_64");
        assert_eq!(report.platform.distro_id, "rocky");
        assert_eq!(report.platform.package_manager, PackageManager::Dnf);
        assert_eq!(report.platform.init_system, InitSystem::Systemd);
        assert_eq!(report.platform.cgroup_version, CgroupVersion::V1);
        assert_eq!(report.level, CapabilityLevel::L1);

        fs::remove_dir_all(root).expect("cleanup");
    }
}
