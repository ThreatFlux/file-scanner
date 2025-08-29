//! Version parsing utilities

use anyhow::{anyhow, Result};
use std::cmp::Ordering;

/// Parsed semantic version
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre_release: Option<String>,
    pub build: Option<String>,
}

impl Version {
    /// Parse a version string
    pub fn parse(version: &str) -> Result<Self> {
        let version = version.trim_start_matches('v');

        // Split on + for build metadata
        let (version, build) = if let Some(pos) = version.find('+') {
            (&version[..pos], Some(version[pos + 1..].to_string()))
        } else {
            (version, None)
        };

        // Split on - for pre-release
        let (version, pre_release) = if let Some(pos) = version.find('-') {
            (&version[..pos], Some(version[pos + 1..].to_string()))
        } else {
            (version, None)
        };

        // Parse major.minor.patch
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() < 3 {
            return Err(anyhow!("Invalid version format: {}", version));
        }

        Ok(Version {
            major: parts[0].parse()?,
            minor: parts[1].parse()?,
            patch: parts[2].parse()?,
            pre_release,
            build,
        })
    }

    /// Check if this version satisfies a version specification
    pub fn satisfies(&self, spec: &str) -> bool {
        // Simple implementation - just checks basic operators
        if let Some(stripped) = spec.strip_prefix(">=") {
            if let Ok(other) = Version::parse(stripped) {
                return self >= &other;
            }
        } else if let Some(stripped) = spec.strip_prefix('>') {
            if let Ok(other) = Version::parse(stripped) {
                return self > &other;
            }
        } else if let Some(stripped) = spec.strip_prefix("<=") {
            if let Ok(other) = Version::parse(stripped) {
                return self <= &other;
            }
        } else if let Some(stripped) = spec.strip_prefix('<') {
            if let Ok(other) = Version::parse(stripped) {
                return self < &other;
            }
        } else if spec.starts_with('=') || spec.starts_with("==") {
            let v = spec.trim_start_matches('=');
            if let Ok(other) = Version::parse(v) {
                return self == &other;
            }
        }

        // Try exact match
        if let Ok(other) = Version::parse(spec) {
            return self == &other;
        }

        false
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minor.cmp(&other.minor) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.patch.cmp(&other.patch) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Pre-release versions have lower precedence
        match (&self.pre_release, &other.pre_release) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre_release.is_none());
        assert!(v.build.is_none());
    }

    #[test]
    fn test_parse_version_with_pre_release() {
        let v = Version::parse("1.2.3-beta.1").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.pre_release, Some("beta.1".to_string()));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.2.3").unwrap();
        let v2 = Version::parse("1.2.4").unwrap();
        assert!(v1 < v2);

        let v3 = Version::parse("2.0.0").unwrap();
        assert!(v2 < v3);
    }

    #[test]
    fn test_version_satisfies() {
        let v = Version::parse("1.2.3").unwrap();
        assert!(v.satisfies(">=1.0.0"));
        assert!(v.satisfies(">1.2.0"));
        assert!(v.satisfies("<=2.0.0"));
        assert!(v.satisfies("<1.3.0"));
        assert!(v.satisfies("=1.2.3"));
        assert!(v.satisfies("==1.2.3"));
    }
}
