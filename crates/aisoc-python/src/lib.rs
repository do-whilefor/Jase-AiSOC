use aisoc_core::{
    ascii_strings as core_ascii_strings, entropy as core_entropy,
    hmac_sha256_hex as core_hmac_sha256_hex, inspect_elf as core_inspect_elf,
    probe_linux as core_probe_linux, secure_compare as core_secure_compare,
    sha256_bytes as core_sha256_bytes, sha256_file as core_sha256_file,
    sha256_hex as core_sha256_hex, IocMatcher as CoreIocMatcher, LinuxProbePaths,
};
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::path::Path;

#[pyfunction]
fn sha256_hex(data: &[u8]) -> String {
    core_sha256_hex(data)
}

#[pyfunction]
fn sha256_bytes<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new_bound(py, &core_sha256_bytes(data))
}

#[pyfunction]
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    core_hmac_sha256_hex(key, message)
}

#[pyfunction]
fn secure_compare(left: &[u8], right: &[u8]) -> bool {
    core_secure_compare(left, right)
}

#[pyfunction]
fn sha256_file(path: &str, max_bytes: u64) -> PyResult<(String, u64)> {
    if max_bytes == 0 {
        return Err(PyValueError::new_err("max_bytes must be positive"));
    }
    core_sha256_file(Path::new(path), max_bytes)
        .map_err(|error| PyOSError::new_err(error.to_string()))
}

#[pyfunction]
fn entropy(data: &[u8]) -> f64 {
    core_entropy(data)
}

#[pyfunction]
#[pyo3(signature = (data, minimum_length=4, max_strings=128, max_string_length=256))]
fn ascii_strings(
    data: &[u8],
    minimum_length: usize,
    max_strings: usize,
    max_string_length: usize,
) -> PyResult<Vec<String>> {
    if minimum_length == 0
        || max_strings == 0
        || max_string_length < minimum_length
        || max_string_length > 4096
        || max_strings > 4096
    {
        return Err(PyValueError::new_err("invalid ASCII string extraction bounds"));
    }
    Ok(core_ascii_strings(
        data,
        minimum_length,
        max_strings,
        max_string_length,
    ))
}

#[pyfunction]
fn inspect_elf(data: &[u8]) -> Option<(Option<String>, String, Vec<String>)> {
    core_inspect_elf(data).map(|info| {
        (
            info.architecture,
            info.format,
            info.warnings.into_iter().map(str::to_owned).collect(),
        )
    })
}

#[pyfunction]
fn probe_linux<'py>(
    py: Python<'py>,
    kernel_release: &str,
    architecture: &str,
) -> PyResult<Bound<'py, PyDict>> {
    let report = core_probe_linux(&LinuxProbePaths::default(), kernel_release, architecture);
    let platform = PyDict::new_bound(py);
    platform.set_item("distro_id", report.platform.distro_id)?;
    platform.set_item("distro_like", report.platform.distro_like)?;
    platform.set_item("version_id", report.platform.version_id)?;
    platform.set_item("kernel_release", report.platform.kernel_release)?;
    platform.set_item("architecture", report.platform.architecture)?;
    platform.set_item("init_system", report.platform.init_system.as_str())?;
    platform.set_item("package_manager", report.platform.package_manager.as_str())?;
    platform.set_item("btf_available", report.platform.btf_available)?;
    platform.set_item("cgroup_version", report.platform.cgroup_version.as_str())?;
    platform.set_item("security_modules", report.platform.security_modules)?;
    platform.set_item("probe_warnings", report.platform.probe_warnings)?;

    let collectors = PyList::empty_bound(py);
    for collector in report.collectors {
        let item = PyDict::new_bound(py);
        item.set_item("name", collector.name)?;
        item.set_item("state", collector.state.as_str())?;
        item.set_item("last_error", collector.last_error)?;
        collectors.append(item)?;
    }

    let result = PyDict::new_bound(py);
    result.set_item("level", report.level.as_str())?;
    result.set_item("platform", platform)?;
    result.set_item("collectors", collectors)?;
    Ok(result)
}

#[pyclass]
struct IocMatcher {
    inner: CoreIocMatcher,
}

#[pymethods]
impl IocMatcher {
    #[new]
    fn new(ips: Vec<String>, domains: Vec<String>, sha256: Vec<String>) -> PyResult<Self> {
        let inner = CoreIocMatcher::new(ips, domains, sha256)
            .map_err(PyValueError::new_err)?;
        Ok(Self { inner })
    }

    fn contains_ip(&self, value: &str) -> bool {
        self.inner.contains_ip(value)
    }

    fn contains_domain(&self, value: &str) -> bool {
        self.inner.contains_domain(value)
    }

    fn contains_sha256(&self, value: &str) -> bool {
        self.inner.contains_sha256(value)
    }
}

#[pyfunction]
fn version() -> &'static str {
    concat!("aisoc-rust ", env!("CARGO_PKG_VERSION"))
}

#[pymodule]
fn aisoc_rust(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(sha256_hex, module)?)?;
    module.add_function(wrap_pyfunction!(sha256_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(hmac_sha256_hex, module)?)?;
    module.add_function(wrap_pyfunction!(secure_compare, module)?)?;
    module.add_function(wrap_pyfunction!(sha256_file, module)?)?;
    module.add_function(wrap_pyfunction!(entropy, module)?)?;
    module.add_function(wrap_pyfunction!(ascii_strings, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_elf, module)?)?;
    module.add_function(wrap_pyfunction!(probe_linux, module)?)?;
    module.add_class::<IocMatcher>()?;
    module.add_function(wrap_pyfunction!(version, module)?)?;
    Ok(())
}
