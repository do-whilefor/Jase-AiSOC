use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Default)]
pub struct IocMatcher {
    ips: HashSet<String>,
    domains: HashSet<String>,
    sha256: HashSet<String>,
}

impl IocMatcher {
    pub fn new(
        ips: impl IntoIterator<Item = String>,
        domains: impl IntoIterator<Item = String>,
        sha256: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let ips = ips
            .into_iter()
            .map(|value| normalize_ip(&value))
            .collect::<Result<HashSet<_>, _>>()?;
        let domains = domains
            .into_iter()
            .map(|value| normalize_domain(&value))
            .collect::<Result<HashSet<_>, _>>()?;
        let sha256 = sha256
            .into_iter()
            .map(|value| normalize_sha256(&value))
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self {
            ips,
            domains,
            sha256,
        })
    }

    pub fn contains_ip(&self, value: &str) -> bool {
        normalize_ip(value)
            .map(|normalized| self.ips.contains(&normalized))
            .unwrap_or(false)
    }

    pub fn contains_domain(&self, value: &str) -> bool {
        normalize_domain(value)
            .map(|normalized| self.domains.contains(&normalized))
            .unwrap_or(false)
    }

    pub fn contains_sha256(&self, value: &str) -> bool {
        normalize_sha256(value)
            .map(|normalized| self.sha256.contains(&normalized))
            .unwrap_or(false)
    }
}

pub fn normalize_ip(value: &str) -> Result<String, String> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| "invalid IOC IP address".to_owned())
}

pub fn normalize_sha256(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid IOC SHA-256".to_owned());
    }
    Ok(normalized)
}

pub fn normalize_domain(value: &str) -> Result<String, String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 || !normalized.is_ascii() {
        return Err("invalid IOC domain".to_owned());
    }
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("invalid IOC domain".to_owned());
        }
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_normalizes_exact_indicators() {
        let matcher = IocMatcher::new(
            vec!["2001:0db8::1".to_owned(), "198.51.100.4".to_owned()],
            vec!["C2.Example.".to_owned()],
            vec!["A".repeat(64)],
        )
        .expect("matcher");
        assert!(matcher.contains_ip("2001:db8::1"));
        assert!(matcher.contains_domain("c2.example"));
        assert!(matcher.contains_sha256(&"a".repeat(64)));
        assert!(!matcher.contains_domain("sub.c2.example"));
    }

    #[test]
    fn invalid_indicators_are_rejected() {
        assert!(IocMatcher::new(vec!["999.1.1.1".to_owned()], vec![], vec![]).is_err());
        assert!(normalize_domain("bad..example").is_err());
        assert!(normalize_sha256("deadbeef").is_err());
    }
}
