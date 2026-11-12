use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};
use crate::package_scan::{edit_distance, AdvisoryDataInfo};

/// Python vulnerability database
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PythonVulnerabilityDatabase {
    pub vulnerabilities: HashMap<String, Vec<PackageVulnerability>>,
    pub last_updated: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageVulnerability {
    pub package_name: String,
    pub vulnerability: KnownVulnerability,
    pub affected_version_ranges: Vec<VersionRange>,
    pub patched_versions: Vec<String>,
    pub references: Vec<String>,
    pub disclosure_date: Option<String>,
    pub exploit_available: bool,
    pub malware_indicators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionRange {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub includes_min: bool,
    pub includes_max: bool,
}

/// Create a hardcoded vulnerability database for common Python vulnerabilities
pub fn create_python_vulnerability_database() -> PythonVulnerabilityDatabase {
    let mut vulnerabilities = HashMap::new();

    // Django vulnerabilities
    vulnerabilities.insert(
        "django".to_string(),
        vec![PackageVulnerability {
            package_name: "django".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2023-43665".to_string(),
                severity: VulnerabilitySeverity::High,
                description:
                    "Django Denial-of-Service vulnerability in django.utils.text.Truncator"
                        .to_string(),
                affected_versions: vec![
                    "< 3.2.22".to_string(),
                    "< 4.1.12".to_string(),
                    "< 4.2.6".to_string(),
                ],
                fixed_in: Some("3.2.22, 4.1.12, 4.2.6".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2023-10-04".to_string()),
            },
            affected_version_ranges: vec![
                VersionRange {
                    min_version: None,
                    max_version: Some("3.2.22".to_string()),
                    includes_min: true,
                    includes_max: false,
                },
                VersionRange {
                    min_version: Some("4.0.0".to_string()),
                    max_version: Some("4.1.12".to_string()),
                    includes_min: true,
                    includes_max: false,
                },
                VersionRange {
                    min_version: Some("4.2.0".to_string()),
                    max_version: Some("4.2.6".to_string()),
                    includes_min: true,
                    includes_max: false,
                },
            ],
            patched_versions: vec![
                "3.2.22".to_string(),
                "4.1.12".to_string(),
                "4.2.6".to_string(),
            ],
            references: vec![
                "https://www.djangoproject.com/weblog/2023/oct/04/security-releases/".to_string(),
            ],
            disclosure_date: Some("2023-10-04".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    // Flask vulnerabilities
    vulnerabilities.insert(
        "flask".to_string(),
        vec![
            PackageVulnerability {
                package_name: "flask".to_string(),
                vulnerability: KnownVulnerability {
                    cve_id: "CVE-2023-30861".to_string(),
                    severity: VulnerabilitySeverity::High,
                    description: "Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header".to_string(),
                    affected_versions: vec!["< 2.2.5".to_string(), "< 2.3.2".to_string()],
                    fixed_in: Some("2.2.5, 2.3.2".to_string()),
                    cvss_score: Some(7.5),
                    published_date: Some("2023-05-02".to_string()),
                },
                affected_version_ranges: vec![
                    VersionRange {
                        min_version: None,
                        max_version: Some("2.2.5".to_string()),
                        includes_min: true,
                        includes_max: false,
                    }
            ,VersionRange {
                min_version: Some("2.3.0".to_string()),
                max_version: Some("2.3.2".to_string()),
                includes_min: true,
                includes_max: false,
            },
                ],
                patched_versions: vec!["2.2.5".to_string(), "2.3.2".to_string()],
                references: vec!["https://github.com/pallets/flask/security/advisories/GHSA-m2qf-hxjv-5gpq".to_string()],
                disclosure_date: Some("2023-05-02".to_string()),
                exploit_available: false,
                malware_indicators: vec![],
            },
        ],
    );

    // Requests vulnerabilities
    vulnerabilities.insert(
        "requests".to_string(),
        vec![
            PackageVulnerability {
                package_name: "requests".to_string(),
                vulnerability: KnownVulnerability {
                    cve_id: "CVE-2023-32681".to_string(),
                    severity: VulnerabilitySeverity::Medium,
                    description: "Requests vulnerable to leaking Proxy-Authorization headers to destination servers".to_string(),
                    affected_versions: vec![">= 2.3.0, < 2.31.0".to_string()],
                    fixed_in: Some("2.31.0".to_string()),
                    cvss_score: Some(6.1),
                    published_date: Some("2023-05-26".to_string()),
                },
                affected_version_ranges: vec![
                    VersionRange {
                        min_version: Some("2.3.0".to_string()),
                        max_version: Some("2.31.0".to_string()),
                        includes_min: true,
                        includes_max: false,
                    },
                ],
                patched_versions: vec!["2.31.0".to_string()],
                references: vec!["https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q".to_string()],
                disclosure_date: Some("2023-05-26".to_string()),
                exploit_available: false,
                malware_indicators: vec![],
            },
        ],
    );

    // Pillow vulnerabilities
    vulnerabilities.insert(
        "pillow".to_string(),
        vec![PackageVulnerability {
            package_name: "pillow".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2023-44271".to_string(),
                severity: VulnerabilitySeverity::High,
                description:
                    "Pillow vulnerable to uncontrolled resource consumption when opening images"
                        .to_string(),
                affected_versions: vec!["< 10.0.1".to_string()],
                fixed_in: Some("10.0.1".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2023-10-03".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("10.0.1".to_string()),
                includes_min: true,
                includes_max: false,
            }],
            patched_versions: vec!["10.0.1".to_string()],
            references: vec![
                "https://github.com/python-pillow/Pillow/security/advisories/GHSA-j7hp-h8jx-5ppr"
                    .to_string(),
            ],
            disclosure_date: Some("2023-10-03".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    // PyYAML vulnerabilities
    vulnerabilities.insert(
        "pyyaml".to_string(),
        vec![
            PackageVulnerability {
                package_name: "pyyaml".to_string(),
                vulnerability: KnownVulnerability {
                    cve_id: "CVE-2020-14343".to_string(),
                    severity: VulnerabilitySeverity::Critical,
                    description: "PyYAML vulnerable to arbitrary code execution when processing untrusted YAML files".to_string(),
                    affected_versions: vec!["< 5.4".to_string()],
                    fixed_in: Some("5.4".to_string()),
                    cvss_score: Some(9.8),
                    published_date: Some("2020-07-21".to_string()),
                },
                affected_version_ranges: vec![
                    VersionRange {
                        min_version: None,
                        max_version: Some("5.4".to_string()),
                        includes_min: true,
                        includes_max: false,
                    },
                ],
                patched_versions: vec!["5.4".to_string()],
                references: vec!["https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation".to_string()],
                disclosure_date: Some("2020-07-21".to_string()),
                exploit_available: true,
                malware_indicators: vec![],
            },
        ],
    );

    // NumPy vulnerabilities
    vulnerabilities.insert(
        "numpy".to_string(),
        vec![PackageVulnerability {
            package_name: "numpy".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2021-41495".to_string(),
                severity: VulnerabilitySeverity::Medium,
                description: "NumPy vulnerable to NULL pointer dereference".to_string(),
                affected_versions: vec!["< 1.22.0".to_string()],
                fixed_in: Some("1.22.0".to_string()),
                cvss_score: Some(5.5),
                published_date: Some("2021-12-17".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("1.22.0".to_string()),
                includes_min: true,
                includes_max: false,
            }],
            patched_versions: vec!["1.22.0".to_string()],
            references: vec!["https://github.com/numpy/numpy/issues/19000".to_string()],
            disclosure_date: Some("2021-12-17".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    // urllib3 vulnerabilities
    vulnerabilities.insert(
        "urllib3".to_string(),
        vec![PackageVulnerability {
            package_name: "urllib3".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2023-43804".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "urllib3 vulnerable to Cookie request header leakage".to_string(),
                affected_versions: vec!["< 1.26.17".to_string(), "< 2.0.5".to_string()],
                fixed_in: Some("1.26.17, 2.0.5".to_string()),
                cvss_score: Some(8.1),
                published_date: Some("2023-10-04".to_string()),
            },
            affected_version_ranges: vec![
                VersionRange {
                    min_version: None,
                    max_version: Some("1.26.17".to_string()),
                    includes_min: true,
                    includes_max: false,
                },
                VersionRange {
                    min_version: Some("2.0.0".to_string()),
                    max_version: Some("2.0.5".to_string()),
                    includes_min: true,
                    includes_max: false,
                },
            ],
            patched_versions: vec!["1.26.17".to_string(), "2.0.5".to_string()],
            references: vec![
                "https://github.com/urllib3/urllib3/security/advisories/GHSA-v845-jxx5-vc9f"
                    .to_string(),
            ],
            disclosure_date: Some("2023-10-04".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    PythonVulnerabilityDatabase {
        vulnerabilities,
        last_updated: "2025-01-06".to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Normalise a PyPI project name (PEP 503): lower case, runs of `-`, `_` and
/// `.` become one `-`.
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut separator = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            separator = true;
        } else {
            if separator && !out.is_empty() {
                out.push('-');
            }
            separator = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// Check if a package has known vulnerabilities at an exact version.
///
/// The name is normalised (`PyYAML`, `pyyaml` and `Py_YAML` are one project).
/// `version` must be a concrete PEP 440 version; a specifier such as `>=2.0` is
/// not a version, use [`check_dependency_spec`]. Operators in front of a
/// version (`==2.9.1`) are tolerated.
pub fn check_package_vulnerabilities(package_name: &str, version: &str) -> Vec<KnownVulnerability> {
    let version = version
        .trim()
        .trim_start_matches("===")
        .trim_start_matches("==");
    let Some(parsed) = Pep440::parse(version) else {
        return vec![];
    };
    static DB: OnceLock<PythonVulnerabilityDatabase> = OnceLock::new();
    let db = DB.get_or_init(create_python_vulnerability_database);
    let name = normalize_name(package_name);
    let mut found: Vec<KnownVulnerability> = db
        .vulnerabilities
        .get(&name)
        .into_iter()
        .flatten()
        .filter(|vuln| {
            vuln.affected_version_ranges
                .iter()
                .any(|range| range_contains(range, &parsed))
        })
        .map(|vuln| vuln.vulnerability.clone())
        .collect();
    if get_known_malicious_versions()
        .iter()
        .any(|(n, v)| normalize_name(n) == name && Pep440::parse(v).as_ref() == Some(&parsed))
    {
        found.push(compromised_release(package_name, version));
    }
    found
}

/// The entry reported for a release that was published with malicious code.
fn compromised_release(name: &str, version: &str) -> KnownVulnerability {
    KnownVulnerability {
        cve_id: "KNOWN-COMPROMISED-RELEASE".to_string(),
        severity: VulnerabilitySeverity::Critical,
        description: format!(
            "{name} {version} is a release that was published with malicious code (hijacked or trojaned). Do not install it."
        ),
        affected_versions: vec![version.to_string()],
        fixed_in: None,
        cvss_score: None,
        published_date: None,
    }
}

/// What the offline table says about one requirement.
#[derive(Debug, Clone, Default)]
pub struct SpecCheck {
    /// Advisories that apply to the exact pinned (or resolved) version.
    pub vulnerabilities: Vec<KnownVulnerability>,
    /// Advisories whose affected range contains the lowest version the
    /// specifier admits; the installed version may be newer.
    pub range_floor_matches: Vec<KnownVulnerability>,
    /// The exact version the check used, if there was one.
    pub version_used: Option<String>,
}

/// Check a requirement's specifier (`==2.9.1`, `>=9.5.0,<10`, `(==2.5.0)`, or
/// empty). An unpinned requirement is unknown, not vulnerable. `resolved` is a
/// version a lock file pins and wins over the specifier.
pub fn check_dependency_spec(name: &str, specifier: &str, resolved: Option<&str>) -> SpecCheck {
    if let Some(version) = resolved.and_then(Pep440::parse) {
        return SpecCheck {
            vulnerabilities: check_package_vulnerabilities(name, resolved.unwrap_or_default()),
            range_floor_matches: vec![],
            version_used: Some(version.to_string()),
        };
    }
    match classify_specifier(specifier) {
        SpecKind::Pinned(version) => {
            let text = version.to_string();
            SpecCheck {
                vulnerabilities: check_package_vulnerabilities(name, &text),
                range_floor_matches: vec![],
                version_used: Some(text),
            }
        }
        SpecKind::Floor(version) => SpecCheck {
            vulnerabilities: vec![],
            range_floor_matches: check_package_vulnerabilities(name, &version.to_string()),
            version_used: None,
        },
        SpecKind::Unknown => SpecCheck::default(),
    }
}

/// What a specifier pins down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecKind {
    /// `==X` or `===X` without a wildcard.
    Pinned(Pep440),
    /// A lower bound (`>=`, `>`, `~=`, `==X.*`) and nothing exact.
    Floor(Pep440),
    /// No specifier, or one with no usable lower bound.
    Unknown,
}

/// Classify a requirement's version specifier.
pub fn classify_specifier(specifier: &str) -> SpecKind {
    let cleaned: String = specifier
        .split(';')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !matches!(c, '(' | ')') && !c.is_whitespace())
        .collect();
    if cleaned.is_empty() || cleaned == "*" {
        return SpecKind::Unknown;
    }
    let clauses: Vec<&str> = cleaned.split(',').filter(|c| !c.is_empty()).collect();
    if let [single] = clauses.as_slice() {
        for op in ["===", "=="] {
            if let Some(rest) = single.strip_prefix(op) {
                if !rest.contains('*') {
                    return Pep440::parse(rest).map_or(SpecKind::Unknown, SpecKind::Pinned);
                }
            }
        }
    }
    let mut floor: Option<Pep440> = None;
    for clause in clauses {
        let lower = ["~=", ">=", "==", ">"].iter().find_map(|op| {
            clause
                .strip_prefix(op)
                .map(|rest| rest.trim_end_matches(".*"))
        });
        if let Some(version) = lower.and_then(Pep440::parse) {
            floor = Some(match floor {
                Some(current) => current.max(version),
                None => version,
            });
        }
    }
    floor.map_or(SpecKind::Unknown, SpecKind::Floor)
}

fn range_contains(range: &VersionRange, version: &Pep440) -> bool {
    if let Some(min) = range.min_version.as_deref() {
        let Some(min) = Pep440::parse(min) else {
            return false;
        };
        let ok = if range.includes_min {
            version >= &min
        } else {
            version > &min
        };
        if !ok {
            return false;
        }
    }
    if let Some(max) = range.max_version.as_deref() {
        let Some(max) = Pep440::parse(max) else {
            return false;
        };
        let ok = if range.includes_max {
            version <= &max
        } else {
            version < &max
        };
        if !ok {
            return false;
        }
    }
    true
}

/// A PEP 440 version with its ordering: epoch, release (trailing zeros
/// ignored), pre-release (`a`, `b`, `rc`), post-release, dev release and local
/// label. `1.0.dev1 < 1.0a1 < 1.0rc1 < 1.0 < 1.0.post1`, and `2.30.0 < 2.5.0`
/// is false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440 {
    /// Epoch (`1!2.0`), default 0.
    pub epoch: u64,
    /// Release numbers, trailing zeros removed.
    pub release: Vec<u64>,
    /// Pre-release: rank (0 a, 1 b, 2 rc) and number.
    pub pre: Option<(u8, u64)>,
    /// Post-release number.
    pub post: Option<u64>,
    /// Dev-release number.
    pub dev: Option<u64>,
    /// Local version label (after `+`).
    pub local: Option<String>,
}

/// Ordering key of a [`Pep440`].
type SortKey<'a> = (
    u64,
    &'a [u64],
    (i8, u8, u64),
    (i8, u64),
    (i8, u64),
    Option<&'a str>,
);

impl Pep440 {
    /// Parse a version string; `None` for anything PEP 440 does not allow.
    pub fn parse(text: &str) -> Option<Self> {
        let lower = text.trim().to_ascii_lowercase();
        let text = lower.strip_prefix('v').unwrap_or(&lower);
        let (public, local) = match text.split_once('+') {
            Some((public, local)) => (public, Some(local.to_string())),
            None => (text, None),
        };
        let (epoch, rest) = match public.split_once('!') {
            Some((epoch, rest)) => (epoch.parse().ok()?, rest),
            None => (0, public),
        };
        let release_end = rest
            .char_indices()
            .find(|&(_, c)| !(c.is_ascii_digit() || c == '.'))
            .map_or(rest.len(), |(i, _)| i);
        let (release_text, mut tail) = rest.split_at(release_end);
        let release_text = release_text.trim_end_matches('.');
        if release_text.is_empty() {
            return None;
        }
        let mut release = Vec::new();
        for part in release_text.split('.') {
            release.push(part.parse::<u64>().ok()?);
        }
        while release.len() > 1 && release.last() == Some(&0) {
            release.pop();
        }
        let mut pre = None;
        let mut post = None;
        let mut dev = None;
        // Separators `.`, `-` and `_` are optional between the parts.
        let strip_sep = |s: &str| s.trim_start_matches(['.', '-', '_']).to_string();
        let mut tail_owned = strip_sep(tail);
        tail = &tail_owned;
        let mut remaining = tail.to_string();
        while !remaining.is_empty() {
            let (kind, after) = if let Some(rest) =
                ["alpha", "beta", "preview", "pre", "rc", "a", "b", "c"]
                    .iter()
                    .find_map(|k| remaining.strip_prefix(k).map(|r| (*k, r)))
            {
                (rest.0, rest.1.to_string())
            } else if let Some(r) = remaining.strip_prefix("post") {
                ("post", r.to_string())
            } else if let Some(r) = remaining.strip_prefix("rev") {
                ("post", r.to_string())
            } else if let Some(r) = remaining.strip_prefix("dev") {
                ("dev", r.to_string())
            } else if let Some(r) = remaining.strip_prefix('r') {
                ("post", r.to_string())
            } else if remaining.chars().all(|c| c.is_ascii_digit()) {
                // "1.0-1" is post release 1
                post = Some(remaining.parse().ok()?);
                break;
            } else {
                return None;
            };
            let after = strip_sep(&after);
            let digits_end = after
                .char_indices()
                .find(|&(_, c)| !c.is_ascii_digit())
                .map_or(after.len(), |(i, _)| i);
            let number: u64 = if digits_end == 0 {
                0
            } else {
                after[..digits_end].parse().ok()?
            };
            match kind {
                "a" | "alpha" => pre = Some((0, number)),
                "b" | "beta" => pre = Some((1, number)),
                "c" | "rc" | "pre" | "preview" => pre = Some((2, number)),
                "post" => post = Some(number),
                _ => dev = Some(number),
            }
            tail_owned = strip_sep(&after[digits_end..]);
            remaining = tail_owned.clone();
        }
        Some(Self {
            epoch,
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    fn sort_key(&self) -> SortKey<'_> {
        // A dev release of a final or post release sorts before its pre-releases.
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => (-1, 0, 0),
            (None, _, _) => (1, 0, 0),
            (Some((rank, n)), _, _) => (0, rank, n),
        };
        let post = self.post.map_or((-1, 0), |n| (0, n));
        let dev = self.dev.map_or((1, 0), |n| (0, n));
        (
            self.epoch,
            self.release.as_slice(),
            pre,
            post,
            dev,
            self.local.as_deref(),
        )
    }
}

impl PartialOrd for Pep440 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl std::fmt::Display for Pep440 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.epoch != 0 {
            write!(f, "{}!", self.epoch)?;
        }
        let release: Vec<String> = self.release.iter().map(u64::to_string).collect();
        write!(f, "{}", release.join("."))?;
        if let Some((rank, n)) = self.pre {
            write!(f, "{}{n}", ["a", "b", "rc"][rank as usize])?;
        }
        if let Some(n) = self.post {
            write!(f, ".post{n}")?;
        }
        if let Some(n) = self.dev {
            write!(f, ".dev{n}")?;
        }
        if let Some(local) = &self.local {
            write!(f, "+{local}")?;
        }
        Ok(())
    }
}

/// Where the advisory data behind [`check_package_vulnerabilities`] comes from.
pub fn advisory_data_info() -> AdvisoryDataInfo {
    let db = create_python_vulnerability_database();
    let advisory_count = db.vulnerabilities.values().map(Vec::len).sum();
    let newest = db
        .vulnerabilities
        .values()
        .flatten()
        .filter_map(|v| v.vulnerability.published_date.clone())
        .max()
        .unwrap_or_default();
    AdvisoryDataInfo {
        source: "small built-in table compiled into file-scanner; nothing is fetched".to_string(),
        last_updated: db.last_updated,
        newest_advisory: newest,
        package_count: db.vulnerabilities.len(),
        advisory_count,
        offline: true,
        coverage_note: "An empty vulnerability list means the package is not in this table, not that it has no known vulnerabilities. Run `pip-audit` or query OSV for full coverage."
            .to_string(),
    }
}

/// Get a list of known malicious package patterns
pub fn get_malicious_patterns() -> Vec<MaliciousPackagePattern> {
    vec![
        MaliciousPackagePattern {
            pattern_name: "Setup.py code execution".to_string(),
            description: "Package executes code during installation via setup.py".to_string(),
            indicators: vec![
                "exec\\(".to_string(),
                "eval\\(".to_string(),
                "subprocess\\.".to_string(),
                "os\\.system".to_string(),
                "__import__".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Obfuscated code".to_string(),
            description: "Package contains obfuscated or encoded code".to_string(),
            indicators: vec![
                "base64\\.b64decode".to_string(),
                "codecs\\.decode".to_string(),
                "compile\\(.*exec".to_string(),
                "\\\\x[0-9a-fA-F]{2}".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Network backdoor".to_string(),
            description: "Package creates network connections for backdoor access".to_string(),
            indicators: vec![
                "socket\\.socket".to_string(),
                "requests\\.get.*http".to_string(),
                "urllib.*urlopen".to_string(),
                "paramiko".to_string(),
                "reverse.*shell".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Credential theft".to_string(),
            description: "Package attempts to steal credentials or sensitive data".to_string(),
            indicators: vec![
                "os\\.environ".to_string(),
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gitconfig".to_string(),
                "keyring".to_string(),
                "password".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Cryptocurrency mining".to_string(),
            description: "Package contains cryptocurrency mining code".to_string(),
            indicators: vec![
                "stratum".to_string(),
                "mining".to_string(),
                "monero".to_string(),
                "bitcoin".to_string(),
                "hashrate".to_string(),
                "xmrig".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "File system manipulation".to_string(),
            description: "Package performs suspicious file system operations".to_string(),
            indicators: vec![
                "shutil\\.rmtree".to_string(),
                "os\\.remove".to_string(),
                "/etc/passwd".to_string(),
                "site-packages".to_string(),
                "__pycache__".to_string(),
            ],
            severity: "High".to_string(),
        },
    ]
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousPackagePattern {
    pub pattern_name: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub severity: String,
}

/// Names of packages that are malicious at every version.
///
/// Legitimate packages never belong here: an entry labels the package Critical.
/// Compromised releases of legitimate packages go in [`get_known_malicious_versions`].
pub fn get_known_malicious_packages() -> Vec<&'static str> {
    vec![
        // Known malicious packages from PyPI
        "colourama",        // Typosquatting colorama
        "python3-dateutil", // Typosquatting python-dateutil
        "jeIlyfish",        // Typosquatting jellyfish (capital I instead of l)
        "python-sqlite",
        "mock-utils",
        "py-util",
        "setup-tools", // Typosquatting setuptools
        "python-mysql",
        "python-mongo",
        "python-openssl",
        "python-crypt",
        "python-crypto",
        "python-yaml",
        "urllib", // Should be urllib3
        "requests-hub",
        "request", // Should be requests
        "python-pandas",
        "opencv",      // Should be opencv-python
        "django-rest", // Should be djangorestframework
        "flask-rest",
        "matplotlib-pyplot",
        // Malicious packages removed from PyPI
        "apidev-coop",
        "bzip",
        "crypt",
        "django-server",
        "pwd",
        "setup-tools",
        "telnet",
        "urlib3", // Typosquatting urllib3
        "urllib-requests",
        // Packages with backdoors
        "ssh-decorate",
        "coloramma",
        "python-dateutils",
    ]
}

/// Compromised releases of otherwise legitimate packages: `(normalised name, version)`.
pub fn get_known_malicious_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        // Hijacked 2022-05 (ctx) and 2024-12 (ultralytics, cryptominer in a release build).
        ("ctx", "0.1.2"),
        ("ultralytics", "8.3.41"),
        ("ultralytics", "8.3.42"),
        ("ultralytics", "8.3.45"),
        ("ultralytics", "8.3.46"),
    ]
}

/// Check if a package name is suspiciously similar to a popular package.
///
/// The name is normalised first (PEP 503: case and `-_.` runs). A name that is
/// itself on the list is never reported. Names within edit distance 1 (a
/// transposition counts as 1) are reported; distance 2 only when both names
/// have at least eight characters.
pub fn check_typosquatting_similarity(package_name: &str) -> Option<Vec<String>> {
    let package_name = normalize_name(package_name);
    let package_name = package_name.as_str();
    let popular_packages = vec![
        "setuptools",
        "pip",
        "wheel",
        "six",
        "urllib3",
        "certifi",
        "idna",
        "charset-normalizer",
        "pyyaml",
        "packaging",
        "attrs",
        "aiohttp",
        "httpx",
        "uvicorn",
        "gunicorn",
        "werkzeug",
        "markupsafe",
        "itsdangerous",
        "psycopg2",
        "lxml",
        "openpyxl",
        "pyjwt",
        "python-dateutil",
        "pytz",
        "oauthlib",
        "numpy",
        "pandas",
        "requests",
        "matplotlib",
        "scipy",
        "scikit-learn",
        "tensorflow",
        "torch",
        "django",
        "flask",
        "pytest",
        "pillow",
        "sqlalchemy",
        "beautifulsoup4",
        "selenium",
        "opencv-python",
        "keras",
        "nltk",
        "spacy",
        "plotly",
        "seaborn",
        "networkx",
        "sympy",
        "scrapy",
        "kivy",
        "pygame",
        "pydantic",
        "fastapi",
        "celery",
        "airflow",
        "jupyter",
        "notebook",
        "ipython",
        "colorama",
        "tqdm",
        "click",
        "boto3",
        "pymongo",
        "redis",
        "elasticsearch",
        "kafka-python",
        "pyspark",
        "dask",
        "ray",
        "cryptography",
        "paramiko",
        "fabric",
        "ansible",
        "salt",
        "pytest",
        "nose",
        "mock",
        "faker",
        "factory-boy",
        "hypothesis",
        "black",
        "flake8",
        "pylint",
        "mypy",
        "isort",
        "bandit",
        "sphinx",
        "mkdocs",
        "docutils",
        "jinja2",
        "mako",
        "chameleon",
    ];

    // `attr` and `boto` are real projects one edit away from attrs and boto3.
    if package_name.is_empty()
        || package_name.len() > 214
        || matches!(package_name, "attr" | "boto")
        || popular_packages.contains(&package_name)
    {
        return None;
    }
    let mut similar_packages = vec![];

    for popular in &popular_packages {
        if package_name.len() >= 4
            && popular.len() >= 4
            && package_name.len().abs_diff(popular.len()) <= 2
        {
            let distance = edit_distance(package_name, popular);
            let allowed = if package_name.len().min(popular.len()) >= 8 {
                2
            } else {
                1
            };
            if distance > 0 && distance <= allowed {
                similar_packages.push(popular.to_string());
            }
        }

        // Check for common typosquatting patterns
        if package_name.starts_with(popular) && package_name.len() > popular.len() {
            let suffix = &package_name[popular.len()..];
            if matches!(
                suffix,
                "-dev" | "-test" | "-py" | "-python" | "2" | "3" | "-lib"
            ) || suffix.is_empty()
            {
                similar_packages.push(format!("{popular} (suspicious suffix: {suffix})"));
            }
        }

        // Check for prefix patterns
        if package_name.ends_with(popular) && package_name.len() > popular.len() {
            let prefix = &package_name[..package_name.len() - popular.len()];
            if matches!(prefix, "python-" | "py-" | "lib-") {
                similar_packages.push(format!("{popular} (suspicious prefix: {prefix})"));
            }
        }
    }

    similar_packages.sort();
    similar_packages.dedup();
    if similar_packages.is_empty() {
        None
    } else {
        Some(similar_packages)
    }
}
