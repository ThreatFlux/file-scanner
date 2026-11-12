use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::package_scan::{edit_distance, AdvisoryDataInfo};

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};

/// NPM vulnerability database
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmVulnerabilityDatabase {
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

/// Create a hardcoded vulnerability database for common npm vulnerabilities
pub fn create_npm_vulnerability_database() -> NpmVulnerabilityDatabase {
    let mut vulnerabilities = HashMap::new();

    // Event-stream malware incident
    vulnerabilities.insert(
        "event-stream".to_string(),
        vec![PackageVulnerability {
            package_name: "event-stream".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "NPM-MALWARE-2018-001".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description: "Malicious code injection that steals cryptocurrency wallets"
                    .to_string(),
                affected_versions: vec!["3.3.6".to_string()],
                fixed_in: Some("4.0.0".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2018-11-26".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("3.3.6".to_string()),
                max_version: Some("3.3.6".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["4.0.0".to_string()],
            references: vec![
                "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident"
                    .to_string(),
            ],
            disclosure_date: Some("2018-11-26".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "flatmap-stream".to_string(),
                "cryptocurrency wallet theft".to_string(),
            ],
        }],
    );

    // ua-parser-js crypto mining malware
    vulnerabilities.insert(
        "ua-parser-js".to_string(),
        vec![PackageVulnerability {
            package_name: "ua-parser-js".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2021-41265".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description:
                    "Compromised versions contain crypto mining and password stealing malware"
                        .to_string(),
                affected_versions: vec![
                    "0.7.29".to_string(),
                    "0.8.0".to_string(),
                    "1.0.0".to_string(),
                ],
                fixed_in: Some("0.7.30".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2021-10-22".to_string()),
            },
            affected_version_ranges: vec![
                VersionRange {
                    min_version: Some("0.7.29".to_string()),
                    max_version: Some("0.7.29".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
                VersionRange {
                    min_version: Some("0.8.0".to_string()),
                    max_version: Some("0.8.0".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
                VersionRange {
                    min_version: Some("1.0.0".to_string()),
                    max_version: Some("1.0.0".to_string()),
                    includes_min: true,
                    includes_max: true,
                },
            ],
            patched_versions: vec![
                "0.7.30".to_string(),
                "0.8.1".to_string(),
                "1.0.1".to_string(),
            ],
            references: vec!["https://github.com/faisalman/ua-parser-js/issues/536".to_string()],
            disclosure_date: Some("2021-10-22".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "crypto mining".to_string(),
                "password stealer".to_string(),
                "jsextension".to_string(),
            ],
        }],
    );

    // node-ipc malware protest-ware
    vulnerabilities.insert(
        "node-ipc".to_string(),
        vec![PackageVulnerability {
            package_name: "node-ipc".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2022-23812".to_string(),
                severity: VulnerabilitySeverity::Critical,
                description:
                    "Malicious code that overwrites files with specific geographic IP addresses"
                        .to_string(),
                affected_versions: vec!["10.1.1".to_string(), "10.1.2".to_string()],
                fixed_in: Some("10.1.3".to_string()),
                cvss_score: Some(9.8),
                published_date: Some("2022-03-16".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("10.1.1".to_string()),
                max_version: Some("10.1.2".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["10.1.3".to_string()],
            references: vec!["https://snyk.io/vuln/SNYK-JS-NODEIPC-2426370".to_string()],
            disclosure_date: Some("2022-03-16".to_string()),
            exploit_available: true,
            malware_indicators: vec![
                "protestware".to_string(),
                "file overwrite".to_string(),
                "geo-targeted".to_string(),
            ],
        }],
    );

    // colors and faker protest-ware
    vulnerabilities.insert(
        "colors".to_string(),
        vec![PackageVulnerability {
            package_name: "colors".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "GHSA-2pr3-vjfc-gx2g".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Infinite loop causing Denial of Service".to_string(),
                affected_versions: vec![
                    "1.4.1".to_string(),
                    "1.4.2".to_string(),
                    "1.4.44-liberty-2".to_string(),
                ],
                fixed_in: Some("1.4.0".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2022-01-08".to_string()),
            },
            affected_version_ranges: ["1.4.1", "1.4.2", "1.4.44-liberty-2"]
                .iter()
                .map(|v| VersionRange {
                    min_version: Some((*v).to_string()),
                    max_version: Some((*v).to_string()),
                    includes_min: true,
                    includes_max: true,
                })
                .collect(),
            patched_versions: vec!["1.4.0".to_string()],
            references: vec!["https://github.com/advisories/GHSA-2pr3-vjfc-gx2g".to_string()],
            disclosure_date: Some("2022-01-08".to_string()),
            exploit_available: true,
            malware_indicators: vec!["infinite loop".to_string(), "protestware".to_string()],
        }],
    );

    // lodash vulnerability
    vulnerabilities.insert(
        "lodash".to_string(),
        vec![PackageVulnerability {
            package_name: "lodash".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2019-10744".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Prototype pollution vulnerability in defaultsDeep function"
                    .to_string(),
                affected_versions: vec!["< 4.17.12".to_string()],
                fixed_in: Some("4.17.12".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2019-07-26".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("4.17.11".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["4.17.12".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-10744".to_string()],
            disclosure_date: Some("2019-07-26".to_string()),
            exploit_available: true,
            malware_indicators: vec![],
        }],
    );

    // minimist vulnerability
    vulnerabilities.insert(
        "minimist".to_string(),
        vec![PackageVulnerability {
            package_name: "minimist".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "CVE-2020-7598".to_string(),
                severity: VulnerabilitySeverity::Medium,
                description:
                    "Prototype pollution vulnerability allowing modification of Object prototype"
                        .to_string(),
                affected_versions: vec!["< 1.2.2".to_string()],
                fixed_in: Some("1.2.2".to_string()),
                cvss_score: Some(5.3),
                published_date: Some("2020-03-11".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("1.2.1".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["1.2.2".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-7598".to_string()],
            disclosure_date: Some("2020-03-11".to_string()),
            exploit_available: false,
            malware_indicators: vec![],
        }],
    );

    NpmVulnerabilityDatabase {
        vulnerabilities,
        last_updated: "2025-01-06".to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Check if a package has known vulnerabilities at an exact version.
///
/// `version` must be a concrete version (`4.17.4`, `1.0.0-rc.1`). A range
/// such as `^1.2.0` is not a version: use [`check_dependency_spec`].
pub fn check_package_vulnerabilities(package_name: &str, version: &str) -> Vec<KnownVulnerability> {
    let Some(parsed) = SemVer::parse(version) else {
        return vec![];
    };
    let mut found: Vec<KnownVulnerability> = advisories_for(package_name)
        .into_iter()
        .filter(|vuln| {
            vuln.affected_version_ranges
                .iter()
                .any(|r| range_contains(r, &parsed))
        })
        .map(|vuln| vuln.vulnerability)
        .collect();
    let lower = package_name.to_ascii_lowercase();
    let normalized = parsed.to_string();
    if found.is_empty()
        && get_known_malicious_versions()
            .iter()
            .any(|(n, v)| *n == lower && *v == normalized)
    {
        found.push(KnownVulnerability {
            cve_id: "KNOWN-COMPROMISED-RELEASE".to_string(),
            severity: VulnerabilitySeverity::Critical,
            description: format!(
                "{package_name} {version} is a release that was published with malicious code (hijacked or trojaned). Do not install it."
            ),
            affected_versions: vec![version.to_string()],
            fixed_in: None,
            cvss_score: None,
            published_date: None,
        });
    }
    found
}

fn advisories_for(package_name: &str) -> Vec<PackageVulnerability> {
    static DB: OnceLock<NpmVulnerabilityDatabase> = OnceLock::new();
    DB.get_or_init(create_npm_vulnerability_database)
        .vulnerabilities
        .get(&package_name.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

/// What the offline table says about one dependency declaration.
#[derive(Debug, Clone, Default)]
pub struct SpecCheck {
    /// Advisories that apply to the exact version (declared or resolved).
    pub vulnerabilities: Vec<KnownVulnerability>,
    /// Advisories whose affected range contains the lowest version the
    /// declared range admits. The installed version may be newer and
    /// unaffected; a lock file settles it.
    pub range_floor_matches: Vec<KnownVulnerability>,
    /// The exact version the check used, if there was one.
    pub version_used: Option<String>,
}

/// Check a `package.json` dependency declaration.
///
/// `resolved` is the version a lock file pins, when there is one; it wins over
/// the declared spec. Otherwise an exact spec (`1.2.3`, `=1.2.3`) is checked
/// as that version, and a range is checked at its lowest admitted version and
/// reported separately in [`SpecCheck::range_floor_matches`]. Git, file, URL,
/// tag and alias specs cannot be judged and give an empty result.
pub fn check_dependency_spec(name: &str, spec: &str, resolved: Option<&str>) -> SpecCheck {
    if let Some(version) = resolved.and_then(SemVer::parse) {
        return SpecCheck {
            vulnerabilities: check_package_vulnerabilities(name, &version.to_string()),
            range_floor_matches: vec![],
            version_used: Some(version.to_string()),
        };
    }
    match classify_spec(spec) {
        SpecKind::Exact(version) => SpecCheck {
            vulnerabilities: check_package_vulnerabilities(name, &version.to_string()),
            range_floor_matches: vec![],
            version_used: Some(version.to_string()),
        },
        SpecKind::Range { floor } => SpecCheck {
            vulnerabilities: vec![],
            range_floor_matches: check_package_vulnerabilities(name, &floor.to_string()),
            version_used: None,
        },
        SpecKind::Unknown => SpecCheck::default(),
    }
}

/// What a dependency spec pins down.
#[derive(Debug, Clone, PartialEq)]
pub enum SpecKind {
    /// One exact version.
    Exact(SemVer),
    /// A range; `floor` is the lowest version it admits.
    Range {
        /// Lowest admitted version.
        floor: SemVer,
    },
    /// A tag, URL, git or file spec, or an unparseable string.
    Unknown,
}

/// Classify an npm dependency spec.
pub fn classify_spec(spec: &str) -> SpecKind {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" || spec.eq_ignore_ascii_case("latest") {
        return SpecKind::Range {
            floor: SemVer::new(0, 0, 0),
        };
    }
    if spec.contains("://")
        || spec.starts_with("git")
        || spec.starts_with("file:")
        || spec.starts_with("link:")
        || spec.starts_with("npm:")
        || spec.starts_with("github:")
        || spec.starts_with("workspace:")
        || (spec.contains('/') && !spec.contains(' '))
    {
        return SpecKind::Unknown;
    }
    let bare = spec.strip_prefix('=').unwrap_or(spec).trim();
    let bare = bare.strip_prefix('v').unwrap_or(bare);
    if let Some(version) = SemVer::parse(bare) {
        return SpecKind::Exact(version);
    }
    match range_floor(spec) {
        Some(floor) => SpecKind::Range { floor },
        None => SpecKind::Unknown,
    }
}

/// Lowest version a semver range admits (an approximation good enough to ask
/// "could this range install an affected version"). Handles `^`, `~`, `>=`,
/// `>`, `<`, `<=`, `=`, x-ranges, hyphen ranges and `||`.
pub fn range_floor(range: &str) -> Option<SemVer> {
    let mut best: Option<SemVer> = None;
    for set in range.split("||") {
        let tokens: Vec<&str> = set.split_whitespace().collect();
        if tokens.is_empty() {
            return Some(SemVer::new(0, 0, 0));
        }
        let mut floor = SemVer::new(0, 0, 0);
        let mut understood = false;
        let mut i = 0;
        while i < tokens.len() {
            let token = tokens[i];
            if i + 2 < tokens.len() && tokens[i + 1] == "-" {
                // hyphen range "1.2.3 - 2.3.4"
                if let Some(low) = parse_partial(token) {
                    floor = floor.max(low);
                    understood = true;
                }
                i += 3;
                continue;
            }
            let (op, rest) = split_operator(token);
            // "> 1.2.3" written with a space
            let (rest, advance) = if rest.is_empty() && i + 1 < tokens.len() {
                (tokens[i + 1], 2)
            } else {
                (rest, 1)
            };
            if let Some(version) = parse_partial(rest) {
                understood = true;
                match op {
                    "<" | "<=" => {}
                    ">" => {
                        let mut v = version;
                        v.patch = v.patch.saturating_add(1);
                        v.pre.clear();
                        floor = floor.max(v);
                    }
                    _ => floor = floor.max(version),
                }
            }
            i += advance;
        }
        if !understood {
            return None;
        }
        best = Some(best.map_or(floor.clone(), |b| b.min(floor)));
    }
    best
}

fn split_operator(token: &str) -> (&str, &str) {
    for op in [">=", "<=", ">", "<", "=", "^", "~"] {
        if let Some(rest) = token.strip_prefix(op) {
            return (op, rest.trim_start_matches('v'));
        }
    }
    ("", token.trim_start_matches('v'))
}

/// `1`, `1.2`, `1.x`, `1.2.*`, `1.2.3-rc.1` as the lowest full version.
fn parse_partial(text: &str) -> Option<SemVer> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(version) = SemVer::parse(text) {
        return Some(version);
    }
    let mut parts = [0u64; 3];
    let mut seen = 0;
    for (i, part) in text.split('.').enumerate() {
        if i > 2 {
            return None;
        }
        if matches!(part, "x" | "X" | "*") {
            break;
        }
        parts[i] = part.parse().ok()?;
        seen += 1;
    }
    if seen == 0 && !matches!(text.chars().next(), Some('x' | 'X' | '*')) {
        return None;
    }
    Some(SemVer::new(parts[0], parts[1], parts[2]))
}

fn range_contains(range: &VersionRange, version: &SemVer) -> bool {
    if let Some(min) = range.min_version.as_deref() {
        let Some(min) = SemVer::parse(min) else {
            return false;
        };
        let ok = if range.includes_min {
            *version >= min
        } else {
            *version > min
        };
        if !ok {
            return false;
        }
    }
    if let Some(max) = range.max_version.as_deref() {
        let Some(max) = SemVer::parse(max) else {
            return false;
        };
        let ok = if range.includes_max {
            *version <= max
        } else {
            *version < max
        };
        if !ok {
            return false;
        }
    }
    true
}

/// A semantic version (<https://semver.org>) with its precedence order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
    /// Pre-release identifiers, empty for a release.
    pub pre: Vec<PreId>,
}

/// One dot-separated pre-release identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreId {
    /// Numeric identifiers compare as numbers and sort below alphanumeric ones.
    Num(u64),
    /// Alphanumeric identifiers compare in ASCII order.
    Alpha(String),
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Num(a), Self::Num(b)) => a.cmp(b),
            (Self::Num(_), Self::Alpha(_)) => std::cmp::Ordering::Less,
            (Self::Alpha(_), Self::Num(_)) => std::cmp::Ordering::Greater,
            (Self::Alpha(a), Self::Alpha(b)) => a.cmp(b),
        }
    }
}

impl SemVer {
    /// A release version.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: Vec::new(),
        }
    }

    /// Parse `1.2.3`, `v1.2.3`, `1.2.3-rc.1`, `1.2.3+build` (build metadata is
    /// ignored). Anything that is not a full three-part version gives `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let text = text.split('+').next()?;
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let mut numbers = core.split('.');
        let major = numbers.next()?.parse().ok()?;
        let minor = numbers.next()?.parse().ok()?;
        let patch = numbers.next()?.parse().ok()?;
        if numbers.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => {
                if pre.is_empty() {
                    return None;
                }
                pre.split('.')
                    .map(|id| {
                        id.parse::<u64>()
                            .map_or_else(|_| PreId::Alpha(id.to_string()), PreId::Num)
                    })
                    .collect()
            }
        };
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            let ids: Vec<String> = self
                .pre
                .iter()
                .map(|id| match id {
                    PreId::Num(n) => n.to_string(),
                    PreId::Alpha(a) => a.clone(),
                })
                .collect();
            write!(f, "-{}", ids.join("."))?;
        }
        Ok(())
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

/// Where the advisory data behind [`check_package_vulnerabilities`] comes from.
pub fn advisory_data_info() -> AdvisoryDataInfo {
    let db = create_npm_vulnerability_database();
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
        coverage_note: "An empty vulnerability list means the package is not in this table, not that it has no known vulnerabilities. Run `npm audit` or query OSV for full coverage."
            .to_string(),
    }
}

/// Comprehensive malicious patterns database with real-world threat intelligence
pub fn get_malicious_patterns() -> Vec<MaliciousPackagePattern> {
    vec![
        // Supply Chain Attack Patterns (High Priority)
        MaliciousPackagePattern {
            pattern_name: "Install script with external download".to_string(),
            description: "Package downloads and executes external code during installation"
                .to_string(),
            indicators: vec![
                r"curl.*http.*\|.*exec".to_string(),
                "wget.*http.*exec".to_string(),
                "fetch.*http.*eval".to_string(),
                "postinstall.*download".to_string(),
                "preinstall.*curl".to_string(),
                "install.*remote.*script".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Obfuscated code execution".to_string(),
            description: "Package contains heavily obfuscated code that executes dynamically"
                .to_string(),
            indicators: vec![
                r"eval\s*\(".to_string(),
                r"Function\s*\(".to_string(),
                r"atob\s*\(".to_string(),
                r#"Buffer\.from\([^,]+,\s*['"]base64"#.to_string(),
                "\\\\x[0-9a-fA-F]+".to_string(),
                "String\\.fromCharCode".to_string(),
                "unescape\\(".to_string(),
                "setTimeout.*eval".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Environment variable exfiltration".to_string(),
            description: "Package attempts to read and send environment variables".to_string(),
            indicators: vec![
                "process\\.env.*http".to_string(),
                "process\\.env.*fetch".to_string(),
                "process\\.env.*request".to_string(),
                "Object\\.keys\\(process\\.env\\)".to_string(),
                "JSON\\.stringify\\(process\\.env\\)".to_string(),
                "process\\.env\\..*TOKEN".to_string(),
                "process\\.env\\..*SECRET".to_string(),
                "process\\.env\\..*API_KEY".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // Cryptocurrency & Financial Attacks
        MaliciousPackagePattern {
            pattern_name: "Cryptocurrency theft".to_string(),
            description: "Package contains patterns associated with cryptocurrency wallet theft"
                .to_string(),
            indicators: vec![
                "wallet\\.dat".to_string(),
                "bitcoin.*core".to_string(),
                "ethereum.*keystore".to_string(),
                "private.*key".to_string(),
                "seed.*phrase".to_string(),
                "mnemonic.*phrase".to_string(),
                "electrum".to_string(),
                "metamask".to_string(),
                "exodus".to_string(),
                "coinbase".to_string(),
                "[13][a-km-zA-HJ-NP-Z1-9]{25,34}".to_string(), // Bitcoin address
                "0x[a-fA-F0-9]{40}".to_string(),               // Ethereum address
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Cryptocurrency mining".to_string(),
            description: "Package contains cryptocurrency mining code".to_string(),
            indicators: vec![
                "stratum\\+tcp".to_string(),
                "cryptonight".to_string(),
                "coinhive".to_string(),
                "crypto-loot".to_string(),
                "mining.*pool".to_string(),
                "hashrate".to_string(),
                "xmrig".to_string(),
                "cpuminer".to_string(),
                "monero.*miner".to_string(),
                "WebAssembly.*mining".to_string(),
            ],
            severity: "High".to_string(),
        },
        // Network & Communication Attacks
        MaliciousPackagePattern {
            pattern_name: "Reverse shell".to_string(),
            description: "Package attempts to establish reverse shell connection".to_string(),
            indicators: vec![
                "nc.*-e".to_string(),
                "bash.*-i".to_string(),
                "/dev/tcp".to_string(),
                "socket.*connect".to_string(),
                "telnet.*bash".to_string(),
                "socat.*exec".to_string(),
                "powershell.*-c".to_string(),
                "cmd\\.exe.*reverse".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Suspicious network activity".to_string(),
            description: "Package makes unexpected network connections".to_string(),
            indicators: vec![
                r"https?://\d+\.\d+\.\d+\.\d+".to_string(), // IP addresses
                "pastebin\\.com".to_string(),
                "ngrok\\.io".to_string(),
                "webhook".to_string(),
                "discord\\.com/api/webhooks".to_string(),
                "telegram\\.org/bot".to_string(),
                "bit\\.ly".to_string(),
                "tinyurl\\.com".to_string(),
                "raw\\.githubusercontent\\.com".to_string(),
                "transfer\\.sh".to_string(),
                "file\\.io".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Command and control".to_string(),
            description: "Package establishes command and control communication".to_string(),
            indicators: vec![
                "c2\\..*\\.com".to_string(),
                "cmd\\..*\\.org".to_string(),
                "setInterval.*http".to_string(),
                "WebSocket.*onmessage.*eval".to_string(),
                "eval.*response".to_string(),
                "exec.*response".to_string(),
                "periodic.*beacon".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // Data Theft & Exfiltration
        MaliciousPackagePattern {
            pattern_name: "File system enumeration".to_string(),
            description: "Package attempts to enumerate sensitive files".to_string(),
            indicators: vec![
                "\\.ssh/id_rsa".to_string(),
                "\\.aws/credentials".to_string(),
                "\\.npmrc".to_string(),
                "\\.env".to_string(),
                "config\\.json".to_string(),
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "readdir.*recursive".to_string(),
                "glob\\(.*secrets".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Browser data theft".to_string(),
            description: "Package attempts to steal browser data".to_string(),
            indicators: vec![
                "Local Storage".to_string(),
                "Session Storage".to_string(),
                "document\\.cookie".to_string(),
                "Chrome.*passwords".to_string(),
                "Firefox.*passwords".to_string(),
                "History.*file".to_string(),
                "Cookies.*database".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // System Manipulation
        MaliciousPackagePattern {
            pattern_name: "Registry manipulation".to_string(),
            description: "Package manipulates Windows registry".to_string(),
            indicators: vec![
                "HKEY_CURRENT_USER".to_string(),
                "HKEY_LOCAL_MACHINE".to_string(),
                "reg\\.exe.*add".to_string(),
                "regedit.*import".to_string(),
                "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run".to_string(),
                "winreg.*OpenKey".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Persistence mechanisms".to_string(),
            description: "Package establishes persistence on the system".to_string(),
            indicators: vec![
                "crontab.*-l".to_string(),
                "startup.*folder".to_string(),
                "autostart".to_string(),
                "/etc/rc\\.local".to_string(),
                "systemd.*service".to_string(),
                "launchd.*plist".to_string(),
                "pm2.*startup".to_string(),
                "Windows.*Task.*Scheduler".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Process injection".to_string(),
            description: "Package attempts process injection or manipulation".to_string(),
            indicators: vec![
                "ptrace".to_string(),
                "CreateRemoteThread".to_string(),
                "VirtualAllocEx".to_string(),
                "WriteProcessMemory".to_string(),
                "SetWindowsHookEx".to_string(),
                "DLL.*injection".to_string(),
                "code.*injection".to_string(),
                "process.*hollowing".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // Anti-Analysis & Evasion
        MaliciousPackagePattern {
            pattern_name: "Anti-debugging".to_string(),
            description: "Package contains anti-debugging techniques".to_string(),
            indicators: vec![
                "debugger".to_string(),
                "IsDebuggerPresent".to_string(),
                "CheckRemoteDebuggerPresent".to_string(),
                "timing.*attack".to_string(),
                "performance\\.now.*diff".to_string(),
                "Date\\.now.*diff".to_string(),
                "setInterval.*debugger".to_string(),
            ],
            severity: "Medium".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Sandbox evasion".to_string(),
            description: "Package attempts to evade sandbox analysis".to_string(),
            indicators: vec![
                "VirtualBox".to_string(),
                "VMware".to_string(),
                "qemu".to_string(),
                "sandboxie".to_string(),
                "sleep.*random".to_string(),
                "setTimeout.*random".to_string(),
                "user.*interaction".to_string(),
                "mouse.*click".to_string(),
            ],
            severity: "Medium".to_string(),
        },
        // Malware Delivery
        MaliciousPackagePattern {
            pattern_name: "Malware download".to_string(),
            description: "Package downloads and executes malware".to_string(),
            indicators: vec![
                "\\.exe.*download".to_string(),
                "\\.bat.*download".to_string(),
                "\\.ps1.*download".to_string(),
                "\\.sh.*download".to_string(),
                "wget.*http.*exec".to_string(),
                "curl.*http.*exec".to_string(),
                "invoke.*webrequest".to_string(),
                "downloadstring.*invoke".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Fileless malware".to_string(),
            description: "Package uses fileless malware techniques".to_string(),
            indicators: vec![
                "powershell.*-enc".to_string(),
                "powershell.*-encodedcommand".to_string(),
                "invoke.*expression".to_string(),
                "bypass.*executionpolicy".to_string(),
                "hidden.*windowstyle".to_string(),
                "memory.*only.*execution".to_string(),
                "reflective.*loading".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // Data Destruction
        MaliciousPackagePattern {
            pattern_name: "Data destruction".to_string(),
            description: "Package may destroy or corrupt data".to_string(),
            indicators: vec![
                "rm.*-rf.*/$".to_string(),
                "del.*\\*.*force".to_string(),
                "format.*c:".to_string(),
                "shred.*-vfz".to_string(),
                "dd.*if=/dev/zero".to_string(),
                "crypto.*encrypt.*ransom".to_string(),
                "ransomware".to_string(),
                "wipe.*disk".to_string(),
            ],
            severity: "Critical".to_string(),
        },
        // Information Gathering
        MaliciousPackagePattern {
            pattern_name: "System reconnaissance".to_string(),
            description: "Package gathers system information".to_string(),
            indicators: vec![
                "uname.*-a".to_string(),
                "systeminfo".to_string(),
                "whoami".to_string(),
                "ipconfig".to_string(),
                "ifconfig".to_string(),
                "netstat.*-an".to_string(),
                "ps.*aux".to_string(),
                "tasklist".to_string(),
                "os\\.platform".to_string(),
                "process\\.arch".to_string(),
            ],
            severity: "Medium".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Network reconnaissance".to_string(),
            description: "Package performs network reconnaissance".to_string(),
            indicators: vec![
                "nmap".to_string(),
                "ping.*-c.*subnet".to_string(),
                "port.*scan".to_string(),
                "network.*discovery".to_string(),
                "arp.*-a".to_string(),
                "nslookup.*internal".to_string(),
                "dig.*@.*internal".to_string(),
                "traceroute".to_string(),
            ],
            severity: "Medium".to_string(),
        },
        // Supply Chain Specific
        MaliciousPackagePattern {
            pattern_name: "Dependency confusion".to_string(),
            description: "Package may be part of dependency confusion attack".to_string(),
            indicators: vec![
                "internal-".to_string(),
                "company-".to_string(),
                "corp-".to_string(),
                "private-".to_string(),
                "@internal/".to_string(),
                "@company/".to_string(),
                "test-.*-internal".to_string(),
                "@[a-zA-Z]+/(internal|private|corp)".to_string(),
            ],
            severity: "High".to_string(),
        },
        MaliciousPackagePattern {
            pattern_name: "Typosquatting indicators".to_string(),
            description: "Package shows signs of typosquatting attack".to_string(),
            indicators: vec![
                ".*-official$".to_string(),
                ".*-secure$".to_string(),
                ".*-fixed$".to_string(),
                ".*-updated$".to_string(),
                ".*-new$".to_string(),
                ".*-latest$".to_string(),
                ".*2$".to_string(),
                ".*js$".to_string(),
                "real-.*".to_string(),
                "original-.*".to_string(),
                "better-.*".to_string(),
            ],
            severity: "Medium".to_string(),
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
/// Entries are bare names. Legitimate packages never belong here (an entry labels
/// the package Critical); a compromised release of a legitimate package goes in
/// [`get_known_malicious_versions`] instead.
pub fn get_known_malicious_packages() -> Vec<&'static str> {
    vec![
        // Known malicious packages
        "flatmap-stream",
        "crossenv",
        "cross-env.js",
        "d3.js",
        "fabric-js",
        "ffmpeg.js",
        "gruntcli",
        "http-proxy.js",
        "jquery.js",
        "mongose",
        "mssql.js",
        "mssql-node",
        "node-fabric",
        "node-opensl",
        "node-openssl",
        "node-tkinter",
        "nodecaffe",
        "nodefabric",
        "nodeffmpeg",
        "nodemailer-js",
        "noderequest",
        "nodesass",
        "nodesqlite",
        "opencv.js",
        "openssl.js",
        "proxy.js",
        "shadowsock",
        "sqlite.js",
        "sqliter",
        // Recent supply chain attacks (2021-2024)
        // Cryptocurrency miners
        "electron-native-notify",
        "getcookies",
        "http-server-upload",
        "nodetest199",
        "nodesass",
        "discordi.js",
        "discord-selfbot",
        "bitcoin-miner",
        "crypto-miner-script",
        "mine-bitcoin",
        "monero-miner",
        // Data exfiltration packages
        "discord-token-grabber",
        "browser-password-stealer",
        "keylogger-node",
        "steal-password",
        "grab-discord-tokens",
        "password-harvester",
        // Backdoor packages
        "remote-access-tool",
        "reverse-shell-js",
        "backdoor-service",
        "shell-access",
        "cmd-executor",
        "system-backdoor",
        // Package confusion attacks
        "internal-tool",
        "company-utils",
        "corp-logger",
        "private-config",
        "internal-auth",
        "dev-tools-internal",
        // Typosquatting attempts (popular packages)
        "reakt",               // react
        "reactt",              // react
        "react-js",            // react
        "babelcli",            // babel-cli
        "expresss",            // express
        "expres",              // express
        "express-js",          // express
        "lodaash",             // lodash
        "lod4sh",              // lodash
        "lodash-js",           // lodash
        "axiooss",             // axios
        "axios-js",            // axios
        "momentt",             // moment
        "moment-js",           // moment
        "webpackk",            // webpack
        "web-pack",            // webpack
        "eslintrc",            // eslint
        "es-lint",             // eslint
        "typescriptt",         // typescript
        "type-script",         // typescript
        "vue-js",              // vue
        "vue2",                // vue
        "angularr",            // angular
        "angular-js",          // angular
        "jquerry",             // jquery
        "j-query",             // jquery
        "jquery-js",           // jquery
        "underscorejs",        // underscore
        "underscore-js",       // underscore
        "backbonejs",          // backbone
        "backbone-js",         // backbone
        "require-js",          // require
        "gruntjs",             // grunt
        "grunt-js",            // grunt
        "gulpjs",              // gulp
        "gulp-js",             // gulp
        "bowerr",              // bower
        "bower-js",            // bower
        "yarn-js",             // yarn
        "npm-js",              // npm
        "npmjs",               // npm
        "nodemon-js",          // nodemon
        "node-mon",            // nodemon
        "expresss-generator",  // express-generator
        "create-react-app-js", // create-react-app
        "prettier-js",         // prettier
        "eslint-js",           // eslint
        "webpack-cli-js",      // webpack-cli
    ]
}

/// Compromised releases of otherwise legitimate packages: `(name, version)`.
pub fn get_known_malicious_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("event-stream", "3.3.6"),
        ("eslint-scope", "3.7.2"),
        ("node-ipc", "9.2.2"),
        ("node-ipc", "10.1.1"),
        ("node-ipc", "10.1.2"),
        ("colors", "1.4.1"),
        ("colors", "1.4.2"),
        ("faker", "6.6.6"),
        ("ua-parser-js", "0.7.29"),
        ("ua-parser-js", "0.8.0"),
        ("ua-parser-js", "1.0.0"),
        ("coa", "2.0.3"),
        ("coa", "2.0.4"),
        ("rc", "1.2.9"),
        ("rc", "1.3.0"),
    ]
}

/// Typosquatting check against the popular-package list.
///
/// The name is lower-cased first. A name that is itself on the list is never
/// reported (so `express` is not a typosquat of `cypress`), and neither is a
/// scoped name. Names within edit distance 1 (a transposition counts as 1) are
/// reported; distance 2 only when both names have at least eight characters.
pub fn check_typosquatting_similarity(package_name: &str) -> Option<Vec<String>> {
    let name = package_name.trim().to_ascii_lowercase();
    // npm names are at most 214 characters: anything longer is not compared.
    if name.is_empty() || name.starts_with('@') || name.len() > 214 {
        return None;
    }
    // Real projects whose names sit one edit away from another popular package.
    if matches!(name.as_str(), "pathe") {
        return None;
    }
    let popular_packages = get_top_npm_packages();
    if popular_packages.contains(&name.as_str()) {
        return None;
    }
    let mut similar_packages = vec![];

    for popular in &popular_packages {
        if name.len() >= 4 && popular.len() >= 4 && name.len().abs_diff(popular.len()) <= 2 {
            let distance = edit_distance(&name, popular);
            let allowed = if name.len().min(popular.len()) >= 8 {
                2
            } else {
                1
            };
            if distance > 0 && distance <= allowed {
                similar_packages.push(format!("{popular} (distance: {distance})"));
            }
        }

        // Common typosquatting patterns
        if name.starts_with(popular) && name.len() > popular.len() {
            let suffix = &name[popular.len()..];
            if matches!(
                suffix,
                "-dev"
                    | "-test"
                    | ".js"
                    | "-js"
                    | "2"
                    | "-official"
                    | "-latest"
                    | "-new"
                    | "-updated"
                    | "-fixed"
                    | "-secure"
                    | "-safe"
                    | "-tool"
                    | "-lib"
                    | "1"
                    | "3"
                    | "4"
                    | "5"
            ) {
                similar_packages.push(format!("{popular} (suspicious suffix: {suffix})"));
            }
        }

        // Prefix patterns
        if name.ends_with(popular) && name.len() > popular.len() {
            let prefix = &name[..name.len() - popular.len()];
            if matches!(
                prefix,
                "new-"
                    | "updated-"
                    | "fixed-"
                    | "secure-"
                    | "safe-"
                    | "official-"
                    | "real-"
                    | "original-"
                    | "better-"
                    | "super-"
            ) {
                similar_packages.push(format!("{popular} (suspicious prefix: {prefix})"));
            }
        }
    }

    // Remove duplicates
    similar_packages.sort();
    similar_packages.dedup();

    if similar_packages.is_empty() {
        None
    } else {
        Some(similar_packages)
    }
}

/// Get top 100+ most popular npm packages for typosquatting detection
fn get_top_npm_packages() -> Vec<&'static str> {
    vec![
        "preact",
        "svelte",
        "next",
        "zod",
        "js-yaml",
        "core-js",
        "lodash-es",
        "express-session",
        "ws",
        "ms",
        "semver",
        "vitest",
        "tslib",
        // Top 50 most downloaded packages
        "react",
        "lodash",
        "express",
        "axios",
        "moment",
        "webpack",
        "babel-core",
        "eslint",
        "typescript",
        "vue",
        "angular",
        "jquery",
        "underscore",
        "backbone",
        "grunt",
        "gulp",
        "bower",
        "yarn",
        "npm",
        "nodemon",
        "prettier",
        "jest",
        "mocha",
        "chai",
        "sinon",
        "helmet",
        "cors",
        "body-parser",
        "cookie-parser",
        "multer",
        "passport",
        "bcrypt",
        "jsonwebtoken",
        "mongoose",
        "sequelize",
        "redis",
        "socket.io",
        "validator",
        "request",
        "chalk",
        "commander",
        "yargs",
        "inquirer",
        "ora",
        "boxen",
        "figlet",
        "colors",
        "debug",
        "util",
        "path",
        // Popular React ecosystem
        "react-dom",
        "react-router",
        "react-router-dom",
        "create-react-app",
        "react-scripts",
        "react-dev-utils",
        "prop-types",
        "react-helmet",
        "react-hook-form",
        "redux",
        "react-redux",
        "redux-thunk",
        "redux-saga",
        "reselect",
        "immutable",
        "styled-components",
        "emotion",
        "material-ui",
        // Popular Vue ecosystem
        "vue-router",
        "vuex",
        "vue-cli",
        "nuxt",
        "vue-loader",
        "vue-template-compiler",
        // Popular Angular ecosystem
        "@angular/core",
        "@angular/common",
        "@angular/forms",
        "@angular/router",
        "@angular/cli",
        "rxjs",
        "zone.js",
        // Build tools and bundlers
        "webpack-cli",
        "webpack-dev-server",
        "babel-loader",
        "css-loader",
        "style-loader",
        "file-loader",
        "html-webpack-plugin",
        "mini-css-extract-plugin",
        "rollup",
        "parcel",
        "vite",
        "esbuild",
        "swc",
        // Testing frameworks
        "cypress",
        "puppeteer",
        "playwright",
        "selenium-webdriver",
        "supertest",
        "karma",
        "jasmine",
        "ava",
        "tape",
        // Development tools
        "nodemon",
        "concurrently",
        "cross-env",
        "rimraf",
        "mkdirp",
        "glob",
        "minimist",
        "dotenv",
        "config",
        "helmet",
        "morgan",
        "compression",
        // Database and ORM
        "mysql",
        "pg",
        "sqlite3",
        "mongodb",
        "mysql2",
        "typeorm",
        "prisma",
        "knex",
        "bookshelf",
        // Utility libraries
        "moment",
        "date-fns",
        "luxon",
        "ramda",
        "immutable",
        "faker",
        "uuid",
        "crypto-js",
        "base64-js",
        "btoa",
        "atob",
        "qs",
        "querystring",
        "url-parse",
        // HTTP clients
        "node-fetch",
        "got",
        "superagent",
        "isomorphic-fetch",
        // File system utilities
        "fs-extra",
        "graceful-fs",
        "chokidar",
        "watch",
        "recursive-readdir",
        // CLI utilities
        "meow",
        "cac",
        "caporal",
        "oclif",
        "vorpal",
        "blessed",
        "ink",
        // Logging
        "winston",
        "pino",
        "bunyan",
        "log4js",
        "signale",
        // Process management
        "pm2",
        "forever",
        "cluster",
        "throng",
        // Security
        "helmet",
        "csrf",
        "express-rate-limit",
        "express-validator",
        "joi",
        "ajv",
        "sanitize-html",
        "xss",
        "dompurify",
    ]
}
