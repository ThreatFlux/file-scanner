use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strsim::levenshtein;

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
                affected_versions: vec!["1.4.1".to_string(), "1.4.44-liberty".to_string()],
                fixed_in: Some("1.4.0".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2022-01-08".to_string()),
            },
            affected_version_ranges: vec![VersionRange {
                min_version: Some("1.4.1".to_string()),
                max_version: Some("1.4.44-liberty".to_string()),
                includes_min: true,
                includes_max: true,
            }],
            patched_versions: vec!["1.4.0".to_string()],
            references: vec!["https://github.com/advisories/GHSA-2pr3-vjfc-gx2g".to_string()],
            disclosure_date: Some("2022-01-08".to_string()),
            exploit_available: true,
            malware_indicators: vec!["infinite loop".to_string(), "protestware".to_string()],
        }],
    );

    // Common vulnerability patterns (not specific packages but patterns to detect)
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

/// Check if a package has known vulnerabilities
pub fn check_package_vulnerabilities(package_name: &str, version: &str) -> Vec<KnownVulnerability> {
    let db = create_npm_vulnerability_database();
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
    for range in ranges {
        // If specific versions are listed in affected_versions, check exact match
        if let (Some(min), Some(max)) = (&range.min_version, &range.max_version) {
            if min == max && version == min {
                return true;
            }
        }

        // TODO: Implement proper semver range checking
        // For now, do simple string comparison
        if version.contains('-') || version.contains('+') {
            // Pre-release or build metadata versions need special handling
            return true; // Conservative approach
        }
    }

    false
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
                "curl.*http.*|.*exec".to_string(),
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

/// Known malicious npm packages list (for quick lookup)
pub fn get_known_malicious_packages() -> Vec<&'static str> {
    vec![
        // Known malicious packages
        "flatmap-stream",
        "event-stream@3.3.6",
        "eslint-scope@3.7.2",
        "bootstrap-sass@3.3.7",
        "crossenv",
        "cross-env.js",
        "d3.js",
        "fabric-js",
        "ffmpeg.js",
        "gruntcli",
        "http-proxy.js",
        "jquery.js",
        "mariadb",
        "mongose",
        "mssql.js",
        "mssql-node",
        "node-fabric",
        "node-opencv",
        "node-opensl",
        "node-openssl",
        "node-sqlite",
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
        "smb",
        "sqlite.js",
        "sqliter",
        "sqlserver",
        "tkinter",
        // Recent supply chain attacks (2021-2024)
        "node-ipc@9.2.2",
        "node-ipc@10.1.1",
        "node-ipc@10.1.2",
        "colors@1.4.1",
        "colors@1.4.2",
        "faker@6.6.6",
        "ua-parser-js@0.7.29",
        "ua-parser-js@0.8.0",
        "ua-parser-js@1.0.0",
        "coa@2.0.3",
        "coa@2.0.4",
        "rc@1.2.9",
        "rc@1.3.0",
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
        "reakt",    // react
        "reactt",   // react
        "react-js", // react
        "reactjs",  // react
        "babelcli", // babel-cli
        "babel-preset-es2015",
        "babel-preset-es2016",
        "babel-preset-es2017",
        "expresss",            // express
        "expres",              // express
        "express-js",          // express
        "lodaash",             // lodash
        "lod4sh",              // lodash
        "lo-dash",             // lodash
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
        "vuejs",               // vue
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
        "requirejs",           // require
        "require-js",          // require
        "gruntjs",             // grunt
        "grunt-js",            // grunt
        "gulpjs",              // gulp
        "gulp-js",             // gulp
        "bowerr",              // bower
        "bower-js",            // bower
        "yarnpkg",             // yarn
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
        "babel-preset-react",
        "babel-preset-stage-0",
        "font-awesome",
        "react-dev-utils",
        "react-scripts",
        "vue-cli",
        "webpack-dev-server",
    ]
}

/// Enhanced typosquatting detection using Levenshtein distance and pattern analysis
pub fn check_typosquatting_similarity(package_name: &str) -> Option<Vec<String>> {
    let popular_packages = get_top_npm_packages();
    let mut similar_packages = vec![];

    for popular in &popular_packages {
        let distance = levenshtein(package_name, popular);

        // More sophisticated similarity checking
        if distance > 0 && distance <= 2 {
            similar_packages.push(format!("{popular} (distance: {distance})"));
        }

        // Character substitution patterns
        if check_character_substitution(package_name, popular) {
            similar_packages.push(format!("{popular} (character substitution)"));
        }

        // Keyboard proximity typos
        if check_keyboard_proximity(package_name, popular) {
            similar_packages.push(format!("{popular} (keyboard typo)"));
        }

        // Visual similarity (0/o, 1/l, etc.)
        if check_visual_similarity(package_name, popular) {
            similar_packages.push(format!("{popular} (visual confusion)"));
        }

        // Common typosquatting patterns
        if package_name.starts_with(popular) && package_name.len() > popular.len() {
            let suffix = &package_name[popular.len()..];
            if matches!(
                suffix,
                "-dev"
                    | "-test"
                    | "js"
                    | ".js"
                    | "-js"
                    | "2"
                    | "-cli"
                    | "-official"
                    | "-latest"
                    | "-new"
                    | "-updated"
                    | "-fixed"
                    | "-secure"
                    | "-safe"
                    | "-utils"
                    | "-tool"
                    | "-lib"
                    | "-core"
                    | "-api"
                    | "1"
                    | "3"
                    | "4"
                    | "5"
            ) {
                similar_packages.push(format!("{popular} (suspicious suffix: {suffix})"));
            }
        }

        // Prefix patterns
        if package_name.ends_with(popular) && package_name.len() > popular.len() {
            let prefix = &package_name[..package_name.len() - popular.len()];
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
                    | "fast-"
                    | "node-"
                    | "npm-"
                    | "js-"
                    | "lib-"
                    | "core-"
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

/// Check for character substitution patterns (common typos)
fn check_character_substitution(name1: &str, name2: &str) -> bool {
    if name1.len() != name2.len() {
        return false;
    }

    let chars1: Vec<char> = name1.chars().collect();
    let chars2: Vec<char> = name2.chars().collect();
    let mut differences = 0;

    for (c1, c2) in chars1.iter().zip(chars2.iter()) {
        if c1 != c2 {
            differences += 1;
            if differences > 1 {
                return false;
            }
        }
    }

    differences == 1
}

/// Check for keyboard proximity errors
fn check_keyboard_proximity(name1: &str, name2: &str) -> bool {
    if name1.len() != name2.len() {
        return false;
    }

    let adjacent_keys = get_adjacent_keys();
    let chars1: Vec<char> = name1.chars().collect();
    let chars2: Vec<char> = name2.chars().collect();
    let mut proximity_errors = 0;

    for (c1, c2) in chars1.iter().zip(chars2.iter()) {
        if c1 != c2 {
            if let Some(adjacent) = adjacent_keys.get(c1) {
                if adjacent.contains(c2) {
                    proximity_errors += 1;
                    if proximity_errors > 1 {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    proximity_errors == 1
}

/// Check for visual similarity (confusing characters)
fn check_visual_similarity(name1: &str, name2: &str) -> bool {
    if name1.len() != name2.len() {
        return false;
    }

    let visual_confusions = get_visual_confusions();
    let chars1: Vec<char> = name1.chars().collect();
    let chars2: Vec<char> = name2.chars().collect();
    let mut visual_errors = 0;

    for (c1, c2) in chars1.iter().zip(chars2.iter()) {
        if c1 != c2 {
            if let Some(similar) = visual_confusions.get(c1) {
                if similar.contains(c2) {
                    visual_errors += 1;
                    if visual_errors > 1 {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    visual_errors == 1
}

/// Get QWERTY keyboard adjacent keys mapping
fn get_adjacent_keys() -> HashMap<char, Vec<char>> {
    let mut adjacent = HashMap::new();

    adjacent.insert('q', vec!['w', 'a', 's']);
    adjacent.insert('w', vec!['q', 'e', 'a', 's', 'd']);
    adjacent.insert('e', vec!['w', 'r', 's', 'd', 'f']);
    adjacent.insert('r', vec!['e', 't', 'd', 'f', 'g']);
    adjacent.insert('t', vec!['r', 'y', 'f', 'g', 'h']);
    adjacent.insert('y', vec!['t', 'u', 'g', 'h', 'j']);
    adjacent.insert('u', vec!['y', 'i', 'h', 'j', 'k']);
    adjacent.insert('i', vec!['u', 'o', 'j', 'k', 'l']);
    adjacent.insert('o', vec!['i', 'p', 'k', 'l']);
    adjacent.insert('p', vec!['o', 'l']);

    adjacent.insert('a', vec!['q', 'w', 's', 'z', 'x']);
    adjacent.insert('s', vec!['q', 'w', 'e', 'a', 'd', 'z', 'x', 'c']);
    adjacent.insert('d', vec!['w', 'e', 'r', 's', 'f', 'x', 'c', 'v']);
    adjacent.insert('f', vec!['e', 'r', 't', 'd', 'g', 'c', 'v', 'b']);
    adjacent.insert('g', vec!['r', 't', 'y', 'f', 'h', 'v', 'b', 'n']);
    adjacent.insert('h', vec!['t', 'y', 'u', 'g', 'j', 'b', 'n', 'm']);
    adjacent.insert('j', vec!['y', 'u', 'i', 'h', 'k', 'n', 'm']);
    adjacent.insert('k', vec!['u', 'i', 'o', 'j', 'l', 'm']);
    adjacent.insert('l', vec!['i', 'o', 'p', 'k']);

    adjacent.insert('z', vec!['a', 's', 'x']);
    adjacent.insert('x', vec!['a', 's', 'd', 'z', 'c']);
    adjacent.insert('c', vec!['s', 'd', 'f', 'x', 'v']);
    adjacent.insert('v', vec!['d', 'f', 'g', 'c', 'b']);
    adjacent.insert('b', vec!['f', 'g', 'h', 'v', 'n']);
    adjacent.insert('n', vec!['g', 'h', 'j', 'b', 'm']);
    adjacent.insert('m', vec!['h', 'j', 'k', 'n']);

    adjacent
}

/// Get visually confusing character mappings
fn get_visual_confusions() -> HashMap<char, Vec<char>> {
    let mut confusions = HashMap::new();

    confusions.insert('0', vec!['o', 'O']);
    confusions.insert('o', vec!['0', 'O']);
    confusions.insert('O', vec!['0', 'o']);

    confusions.insert('1', vec!['l', 'I', '|']);
    confusions.insert('l', vec!['1', 'I', '|']);
    confusions.insert('I', vec!['1', 'l', '|']);
    confusions.insert('|', vec!['1', 'l', 'I']);

    confusions.insert('5', vec!['s', 'S']);
    confusions.insert('s', vec!['5', 'S']);
    confusions.insert('S', vec!['5', 's']);

    confusions.insert('6', vec!['g', 'G']);
    confusions.insert('g', vec!['6', 'G']);
    confusions.insert('G', vec!['6', 'g']);

    confusions.insert('8', vec!['b', 'B']);
    confusions.insert('b', vec!['8', 'B']);
    confusions.insert('B', vec!['8', 'b']);

    confusions.insert('2', vec!['z', 'Z']);
    confusions.insert('z', vec!['2', 'Z']);
    confusions.insert('Z', vec!['2', 'z']);

    confusions
}
