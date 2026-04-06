use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};

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
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("3.2.21".to_string()),
                includes_min: true,
                includes_max: true,
            }],
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
                        max_version: Some("2.2.4".to_string()),
                        includes_min: true,
                        includes_max: true,
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
                    affected_versions: vec!["< 2.31.0".to_string()],
                    fixed_in: Some("2.31.0".to_string()),
                    cvss_score: Some(6.1),
                    published_date: Some("2023-05-26".to_string()),
                },
                affected_version_ranges: vec![
                    VersionRange {
                        min_version: None,
                        max_version: Some("2.30.0".to_string()),
                        includes_min: true,
                        includes_max: true,
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
                max_version: Some("10.0.0".to_string()),
                includes_min: true,
                includes_max: true,
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
                        max_version: Some("5.3.1".to_string()),
                        includes_min: true,
                        includes_max: true,
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
                max_version: Some("1.21.5".to_string()),
                includes_min: true,
                includes_max: true,
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
            affected_version_ranges: vec![VersionRange {
                min_version: None,
                max_version: Some("1.26.16".to_string()),
                includes_min: true,
                includes_max: true,
            }],
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

    // Malicious package patterns
    vulnerabilities.insert(
        "PATTERN-TYPOSQUATTING".to_string(),
        vec![PackageVulnerability {
            package_name: "PATTERN-TYPOSQUATTING".to_string(),
            vulnerability: KnownVulnerability {
                cve_id: "PATTERN-001".to_string(),
                severity: VulnerabilitySeverity::High,
                description:
                    "Typosquatting attack pattern - packages with names similar to popular packages"
                        .to_string(),
                affected_versions: vec!["*".to_string()],
                fixed_in: None,
                cvss_score: Some(8.0),
                published_date: None,
            },
            affected_version_ranges: vec![],
            patched_versions: vec![],
            references: vec![],
            disclosure_date: None,
            exploit_available: true,
            malware_indicators: vec!["typosquatting".to_string(), "similar name".to_string()],
        }],
    );

    PythonVulnerabilityDatabase {
        vulnerabilities,
        last_updated: "2025-01-06".to_string(),
        version: "1.0.0".to_string(),
    }
}

/// Check if a package has known vulnerabilities
pub fn check_package_vulnerabilities(package_name: &str, version: &str) -> Vec<KnownVulnerability> {
    let db = create_python_vulnerability_database();
    let mut found_vulnerabilities = vec![];

    if let Some(package_vulns) = db.vulnerabilities.get(package_name) {
        for vuln in package_vulns {
            if is_version_affected(version, &vuln.affected_version_ranges) {
                found_vulnerabilities.push(vuln.vulnerability.clone());
            }
        }
    }

    found_vulnerabilities
}

/// Check if a version is within the affected ranges
fn is_version_affected(version: &str, ranges: &[VersionRange]) -> bool {
    // Simple version check - in production, use a proper semver library

    // Extract just the version number if it has operators
    let version_num = if version.starts_with(">=")
        || version.starts_with("<=")
        || version.starts_with("~=")
        || version.starts_with("!=")
        || version.starts_with("==")
    {
        &version[2..]
    } else if version.starts_with(">") || version.starts_with("<") {
        &version[1..]
    } else {
        version
    }
    .trim();

    for range in ranges {
        // If specific versions are listed, check exact match
        if let (Some(min), Some(max)) = (&range.min_version, &range.max_version) {
            if min == max && version_num == min {
                return true;
            }

            // Simple comparison for ranges
            if version_num >= min.as_str() && version_num <= max.as_str() {
                return true;
            }
        } else if let Some(max) = &range.max_version {
            if version_num <= max.as_str() {
                return true;
            }
        }

        // Pre-release versions need special handling
        if version_num.contains("dev") || version_num.contains("rc") || version_num.contains("beta")
        {
            return true; // Conservative approach
        }
    }

    false
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

/// Known malicious Python packages list
pub fn get_known_malicious_packages() -> Vec<&'static str> {
    vec![
        // Known malicious packages from PyPI
        "colourama",        // Typosquatting colorama
        "python3-dateutil", // Typosquatting python-dateutil
        "jeIlyfish",        // Typosquatting jellyfish (capital I instead of l)
        "python-sqlite",
        "mock-utils",
        "py-util",
        "pypistats",
        "setup-tools", // Typosquatting setuptools
        "python-mysql",
        "python-mongo",
        "python-openssl",
        "python-crypt",
        "python-crypto",
        "python-jwt",
        "python-yaml",
        "urllib", // Should be urllib3
        "requests-hub",
        "request",       // Should be requests
        "beautifulsoup", // Should be beautifulsoup4
        "python-pandas",
        "pytorch", // Should be torch
        "tensorflow-gpu",
        "opencv",      // Should be opencv-python
        "django-rest", // Should be djangorestframework
        "flask-rest",
        "matplotlib-pyplot",
        "sklearn", // Should be scikit-learn
        "python-nmap",
        "crypto", // Should be pycrypto or cryptography
        "python-binance",
        "python-telegram",
        "python-whatsapp",
        // Malicious packages removed from PyPI
        "acquisition",
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

/// Check if a package name is suspiciously similar to a popular package
pub fn check_typosquatting_similarity(package_name: &str) -> Option<Vec<String>> {
    let popular_packages = vec![
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

    let mut similar_packages = vec![];

    for popular in &popular_packages {
        let distance = levenshtein_distance(package_name, popular);
        if distance > 0 && distance <= 2 {
            similar_packages.push(popular.to_string());
        }

        // Check for common typosquatting patterns
        if package_name.starts_with(popular) && package_name.len() > popular.len() {
            let suffix = &package_name[popular.len()..];
            if matches!(
                suffix,
                "-dev" | "-test" | "-py" | "-python" | "2" | "3" | "-lib"
            ) || suffix.is_empty()
            {
                similar_packages.push(format!("{} (suspicious suffix: {})", popular, suffix));
            }
        }

        // Check for prefix patterns
        if package_name.ends_with(popular) && package_name.len() > popular.len() {
            let prefix = &package_name[..package_name.len() - popular.len()];
            if matches!(prefix, "python-" | "py-" | "lib-") {
                similar_packages.push(format!("{} (suspicious prefix: {})", popular, prefix));
            }
        }
    }

    if similar_packages.is_empty() {
        None
    } else {
        Some(similar_packages)
    }
}

fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();
    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    for (j, cell) in matrix[0].iter_mut().enumerate().take(len2 + 1) {
        *cell = j;
    }

    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(matrix[i][j + 1] + 1, matrix[i + 1][j] + 1),
                matrix[i][j] + cost,
            );
        }
    }

    matrix[len1][len2]
}
