use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};
use crate::npm_vuln_db::{
    check_package_vulnerabilities, check_typosquatting_similarity, get_known_malicious_packages,
    get_malicious_patterns,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmPackageAnalysis {
    pub package_info: PackageJsonInfo,
    pub dependencies: NpmDependencyAnalysis,
    pub security_analysis: NpmSecurityAnalysis,
    pub malicious_indicators: MaliciousPackageIndicators,
    pub files_analysis: Vec<NpmFileAnalysis>,
    pub scripts_analysis: ScriptsAnalysis,
    pub maintainer_analysis: MaintainerAnalysis,
    pub quality_metrics: PackageQualityMetrics,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageJsonInfo {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub main: Option<String>,
    pub author: Option<AuthorInfo>,
    pub license: Option<String>,
    pub repository: Option<RepositoryInfo>,
    pub keywords: Vec<String>,
    pub homepage: Option<String>,
    pub bugs: Option<String>,
    pub engines: Option<HashMap<String, String>>,
    pub os: Option<Vec<String>>,
    pub cpu: Option<Vec<String>>,
    pub private: bool,
    pub publish_config: Option<HashMap<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RepositoryInfo {
    pub repo_type: String,
    pub url: String,
    pub directory: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmDependencyAnalysis {
    pub dependencies: HashMap<String, DependencyDetails>,
    pub dev_dependencies: HashMap<String, DependencyDetails>,
    pub peer_dependencies: HashMap<String, DependencyDetails>,
    pub optional_dependencies: HashMap<String, DependencyDetails>,
    pub bundled_dependencies: Vec<String>,
    pub dependency_count: usize,
    pub total_transitive_count: Option<usize>,
    pub vulnerability_summary: VulnerabilitySummary,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyDetails {
    pub version_spec: String,
    pub resolved_version: Option<String>,
    pub is_local: bool,
    pub is_git: bool,
    pub is_url: bool,
    pub vulnerabilities: Vec<KnownVulnerability>,
    pub license: Option<String>,
    pub deprecated: bool,
    pub deprecation_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilitySummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_count: usize,
    pub vulnerable_packages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmSecurityAnalysis {
    pub has_preinstall_script: bool,
    pub has_postinstall_script: bool,
    pub has_install_script: bool,
    pub suspicious_scripts: Vec<SuspiciousScript>,
    pub network_access_patterns: Vec<NetworkAccessPattern>,
    pub file_system_access: Vec<FileSystemAccess>,
    pub process_execution: Vec<ProcessExecution>,
    pub obfuscation_detected: bool,
    pub crypto_mining_indicators: bool,
    pub data_exfiltration_risk: bool,
    pub supply_chain_risk_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspiciousScript {
    pub script_name: String,
    pub script_content: String,
    pub risk_indicators: Vec<String>,
    pub obfuscation_level: ObfuscationLevel,
    pub external_commands: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ObfuscationLevel {
    None,
    Low,
    Medium,
    High,
    Extreme,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkAccessPattern {
    pub url: String,
    pub protocol: String,
    pub is_suspicious: bool,
    pub reputation_score: Option<f32>,
    pub found_in: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileSystemAccess {
    pub path: String,
    pub operation: String,
    pub is_suspicious: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessExecution {
    pub command: String,
    pub arguments: Vec<String>,
    pub is_suspicious: bool,
    pub risk_level: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousPackageIndicators {
    pub typosquatting_risk: TyposquattingAnalysis,
    pub dependency_confusion_risk: bool,
    pub known_malicious_patterns: Vec<MaliciousPattern>,
    pub suspicious_maintainer_activity: bool,
    pub code_injection_patterns: Vec<CodeInjectionPattern>,
    pub backdoor_indicators: Vec<BackdoorIndicator>,
    pub overall_risk_score: f32,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TyposquattingAnalysis {
    pub is_potential_typosquatting: bool,
    pub similar_packages: Vec<SimilarPackage>,
    pub name_distance: Option<u32>,
    pub suspicious_name_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimilarPackage {
    pub name: String,
    pub download_count: Option<u64>,
    pub similarity_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousPattern {
    pub pattern_type: String,
    pub description: String,
    pub found_in: String,
    pub severity: String,
    pub evidence: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodeInjectionPattern {
    pub injection_type: String,
    pub location: String,
    pub code_snippet: String,
    pub risk_level: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackdoorIndicator {
    pub indicator_type: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NpmFileAnalysis {
    pub file_path: String,
    pub file_type: String,
    pub size: u64,
    pub entropy: f32,
    pub suspicious_content: Vec<String>,
    pub hidden_functionality: bool,
    pub malicious_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScriptsAnalysis {
    pub script_hooks: HashMap<String, String>,
    pub custom_scripts: HashMap<String, String>,
    pub dangerous_commands: Vec<DangerousCommand>,
    pub external_downloads: Vec<String>,
    pub shell_injection_risk: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DangerousCommand {
    pub command: String,
    pub script_name: String,
    pub risk_reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerAnalysis {
    pub maintainers: Vec<MaintainerInfo>,
    pub contributors: Vec<ContributorInfo>,
    pub ownership_changes: Vec<OwnershipChange>,
    pub suspicious_activity: Vec<String>,
    pub trust_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerInfo {
    pub name: String,
    pub email: Option<String>,
    pub npm_username: Option<String>,
    pub first_publish_date: Option<String>,
    pub package_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContributorInfo {
    pub name: String,
    pub commit_count: Option<u32>,
    pub first_contribution: Option<String>,
    pub last_contribution: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OwnershipChange {
    pub date: String,
    pub previous_owner: String,
    pub new_owner: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageQualityMetrics {
    pub has_readme: bool,
    pub has_changelog: bool,
    pub has_tests: bool,
    pub has_ci_config: bool,
    pub documentation_score: f32,
    pub maintenance_score: f32,
    pub popularity_score: f32,
    pub overall_quality_score: f32,
}

/// Main entry point for npm package analysis
pub fn analyze_npm_package(path: &Path) -> Result<NpmPackageAnalysis> {
    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("tgz") {
        analyze_npm_tarball(path)
    } else if path.is_dir() {
        analyze_npm_directory(path)
    } else {
        anyhow::bail!("Path must be either a .tgz file or a directory containing package.json")
    }
}

/// Analyze an npm package from a tarball
fn analyze_npm_tarball(tarball_path: &Path) -> Result<NpmPackageAnalysis> {
    let file = File::open(tarball_path).context("Failed to open tarball")?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut package_json_content = None;
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();

        if path.ends_with("package.json") && package_json_content.is_none() {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            package_json_content = Some(content);
        }

        // Collect file information
        files.push(NpmFileAnalysis {
            file_path: path.clone(),
            file_type: detect_file_type(&path),
            size: entry.size(),
            entropy: 0.0, // TODO: Calculate entropy
            suspicious_content: vec![],
            hidden_functionality: false,
            malicious_patterns: vec![],
        });
    }

    let package_json =
        package_json_content.ok_or_else(|| anyhow::anyhow!("No package.json found in tarball"))?;

    analyze_package_json(&package_json, files)
}

/// Analyze an npm package from a directory
fn analyze_npm_directory(dir_path: &Path) -> Result<NpmPackageAnalysis> {
    let package_json_path = dir_path.join("package.json");
    if !package_json_path.exists() {
        anyhow::bail!("No package.json found in directory");
    }

    let package_json_content =
        std::fs::read_to_string(&package_json_path).context("Failed to read package.json")?;

    // TODO: Scan directory for files
    let files = vec![];

    analyze_package_json(&package_json_content, files)
}

/// Parse and analyze package.json content
fn analyze_package_json(
    package_json: &str,
    files: Vec<NpmFileAnalysis>,
) -> Result<NpmPackageAnalysis> {
    let parsed: Value =
        serde_json::from_str(package_json).context("Failed to parse package.json")?;

    let package_info = extract_package_info(&parsed)?;
    let dependencies = analyze_dependencies(&parsed)?;
    let scripts_analysis = analyze_scripts(&parsed)?;
    let security_analysis = perform_security_analysis(&parsed, &scripts_analysis, &files)?;
    let malicious_indicators =
        detect_malicious_indicators(&package_info, &dependencies, &security_analysis)?;
    let maintainer_analysis = analyze_maintainers(&parsed)?;
    let quality_metrics = calculate_quality_metrics(&parsed, &files)?;

    Ok(NpmPackageAnalysis {
        package_info,
        dependencies,
        security_analysis,
        malicious_indicators,
        files_analysis: files,
        scripts_analysis,
        maintainer_analysis,
        quality_metrics,
    })
}

/// Extract basic package information from package.json
fn extract_package_info(package_json: &Value) -> Result<PackageJsonInfo> {
    let obj = package_json
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

    Ok(PackageJsonInfo {
        name: obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing package name"))?
            .to_string(),
        version: obj
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing package version"))?
            .to_string(),
        description: obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from),
        main: obj.get("main").and_then(|v| v.as_str()).map(String::from),
        author: extract_author_info(obj.get("author")),
        license: obj
            .get("license")
            .and_then(|v| v.as_str())
            .map(String::from),
        repository: extract_repository_info(obj.get("repository")),
        keywords: obj
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        homepage: obj
            .get("homepage")
            .and_then(|v| v.as_str())
            .map(String::from),
        bugs: obj.get("bugs").and_then(|v| v.as_str()).map(String::from),
        engines: obj.get("engines").and_then(|v| v.as_object()).map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        }),
        os: obj.get("os").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        }),
        cpu: obj.get("cpu").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        }),
        private: obj
            .get("private")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        publish_config: obj
            .get("publishConfig")
            .and_then(|v| v.as_object())
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
    })
}

fn extract_author_info(author_value: Option<&Value>) -> Option<AuthorInfo> {
    author_value.map(|v| {
        if let Some(s) = v.as_str() {
            // Parse author string format: "Name <email> (url)"
            AuthorInfo {
                name: Some(s.split('<').next().unwrap_or(s).trim().to_string()),
                email: None,
                url: None,
            }
        } else if let Some(obj) = v.as_object() {
            AuthorInfo {
                name: obj.get("name").and_then(|v| v.as_str()).map(String::from),
                email: obj.get("email").and_then(|v| v.as_str()).map(String::from),
                url: obj.get("url").and_then(|v| v.as_str()).map(String::from),
            }
        } else {
            AuthorInfo {
                name: None,
                email: None,
                url: None,
            }
        }
    })
}

fn extract_repository_info(repo_value: Option<&Value>) -> Option<RepositoryInfo> {
    repo_value.and_then(|v| {
        if let Some(s) = v.as_str() {
            Some(RepositoryInfo {
                repo_type: "git".to_string(),
                url: s.to_string(),
                directory: None,
            })
        } else {
            v.as_object().map(|obj| RepositoryInfo {
                repo_type: obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("git")
                    .to_string(),
                url: obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                directory: obj
                    .get("directory")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            })
        }
    })
}

fn analyze_dependencies(package_json: &Value) -> Result<NpmDependencyAnalysis> {
    let obj = package_json
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

    let _all_deps: HashMap<String, DependencyDetails> = HashMap::new();
    // Extract different dependency types
    let dependencies = extract_dependency_map(obj.get("dependencies"));
    let dev_dependencies = extract_dependency_map(obj.get("devDependencies"));
    let peer_dependencies = extract_dependency_map(obj.get("peerDependencies"));
    let optional_dependencies = extract_dependency_map(obj.get("optionalDependencies"));
    let bundled_dependencies = extract_bundled_dependencies(
        obj.get("bundledDependencies")
            .or_else(|| obj.get("bundleDependencies")),
    );

    let dependency_count = dependencies.len()
        + dev_dependencies.len()
        + peer_dependencies.len()
        + optional_dependencies.len();

    // Calculate vulnerability summary
    let mut vulnerability_summary = VulnerabilitySummary {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        total_count: 0,
        vulnerable_packages: vec![],
    };

    // Count vulnerabilities across all dependency types
    for (name, details) in dependencies
        .iter()
        .chain(dev_dependencies.iter())
        .chain(peer_dependencies.iter())
        .chain(optional_dependencies.iter())
    {
        if !details.vulnerabilities.is_empty() {
            vulnerability_summary.vulnerable_packages.push(name.clone());
            vulnerability_summary.total_count += details.vulnerabilities.len();

            for vuln in &details.vulnerabilities {
                match vuln.severity {
                    VulnerabilitySeverity::Critical => vulnerability_summary.critical_count += 1,
                    VulnerabilitySeverity::High => vulnerability_summary.high_count += 1,
                    VulnerabilitySeverity::Medium => vulnerability_summary.medium_count += 1,
                    VulnerabilitySeverity::Low => vulnerability_summary.low_count += 1,
                    VulnerabilitySeverity::None => {}
                }
            }
        }
    }

    Ok(NpmDependencyAnalysis {
        dependencies,
        dev_dependencies,
        peer_dependencies,
        optional_dependencies,
        bundled_dependencies,
        dependency_count,
        total_transitive_count: None, // TODO: Calculate from lock file
        vulnerability_summary,
    })
}

fn extract_dependency_map(deps_value: Option<&Value>) -> HashMap<String, DependencyDetails> {
    deps_value
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(name, version)| {
                    let version_str = version.as_str().unwrap_or("");

                    // Check for vulnerabilities
                    let vulnerabilities =
                        if !version_str.starts_with("file:") && !version_str.starts_with("http") {
                            // Extract version number from version spec (simple approach)
                            let version_num = extract_version_number(version_str);
                            check_package_vulnerabilities(name, &version_num)
                        } else {
                            vec![]
                        };

                    let details = DependencyDetails {
                        version_spec: version_str.to_string(),
                        resolved_version: None,
                        is_local: version_str.starts_with("file:"),
                        is_git: version_str.contains("git") || version_str.contains("github"),
                        is_url: version_str.starts_with("http"),
                        vulnerabilities,
                        license: None,
                        deprecated: false,
                        deprecation_reason: None,
                    };
                    (name.clone(), details)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_version_number(version_spec: &str) -> String {
    // Simple extraction - in production use a proper semver parser
    version_spec
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches('>')
        .trim_start_matches('<')
        .trim_start_matches('=')
        .trim()
        .to_string()
}

fn extract_bundled_dependencies(bundled_value: Option<&Value>) -> Vec<String> {
    bundled_value
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn analyze_scripts(package_json: &Value) -> Result<ScriptsAnalysis> {
    let scripts: HashMap<String, String> = package_json
        .get("scripts")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();

    let mut script_hooks = HashMap::new();
    let mut custom_scripts = HashMap::new();
    let mut dangerous_commands = vec![];
    let mut external_downloads = vec![];
    let mut shell_injection_risk = false;

    for (name, content) in &scripts {
        // Categorize scripts
        if is_npm_hook(name) {
            script_hooks.insert(name.clone(), content.clone());
        } else {
            custom_scripts.insert(name.clone(), content.clone());
        }

        // Check for dangerous patterns
        if let Some(dangerous) = check_dangerous_command(content) {
            dangerous_commands.push(DangerousCommand {
                command: content.clone(),
                script_name: name.clone(),
                risk_reason: dangerous,
            });
        }

        // Check for external downloads
        if content.contains("curl") || content.contains("wget") || content.contains("fetch") {
            external_downloads.push(content.clone());
        }

        // Check for shell injection
        if content.contains('$') || content.contains('`') || content.contains("eval") {
            shell_injection_risk = true;
        }
    }

    Ok(ScriptsAnalysis {
        script_hooks,
        custom_scripts,
        dangerous_commands,
        external_downloads,
        shell_injection_risk,
    })
}

fn is_npm_hook(script_name: &str) -> bool {
    matches!(
        script_name,
        "preinstall"
            | "install"
            | "postinstall"
            | "preuninstall"
            | "uninstall"
            | "postuninstall"
            | "prepublish"
            | "prepare"
            | "prepublishOnly"
            | "prepack"
            | "postpack"
            | "publish"
            | "postpublish"
            | "preversion"
            | "version"
            | "postversion"
            | "preshrinkwrap"
            | "shrinkwrap"
            | "postshrinkwrap"
            | "pretest"
            | "test"
            | "posttest"
            | "prestop"
            | "stop"
            | "poststop"
            | "prestart"
            | "start"
            | "poststart"
            | "prerestart"
            | "restart"
            | "postrestart"
    )
}

fn check_dangerous_command(command: &str) -> Option<String> {
    let dangerous_patterns = [
        ("rm -rf", "Recursive file deletion"),
        ("sudo", "Elevated privileges"),
        ("chmod 777", "Overly permissive file permissions"),
        ("nc ", "Netcat network tool"),
        ("telnet", "Unencrypted network communication"),
        ("/dev/tcp", "Bash network redirection"),
        ("base64 -d", "Base64 decoding (possible obfuscation)"),
        ("eval", "Dynamic code execution"),
        ("exec", "Process execution"),
        ("spawn", "Process spawning"),
    ];

    for (pattern, reason) in &dangerous_patterns {
        if command.contains(pattern) {
            return Some(reason.to_string());
        }
    }

    None
}

fn perform_security_analysis(
    package_json: &Value,
    scripts: &ScriptsAnalysis,
    _files: &[NpmFileAnalysis],
) -> Result<NpmSecurityAnalysis> {
    let has_preinstall_script = scripts.script_hooks.contains_key("preinstall");
    let has_postinstall_script = scripts.script_hooks.contains_key("postinstall");
    let has_install_script = scripts.script_hooks.contains_key("install");

    let suspicious_scripts = analyze_suspicious_scripts(scripts);
    let network_access_patterns = detect_network_patterns(scripts, _files);
    let file_system_access = detect_filesystem_patterns(scripts, _files);
    let process_execution = detect_process_execution(scripts, _files);

    let obfuscation_detected = detect_obfuscation(scripts, _files);
    let crypto_mining_indicators = detect_crypto_mining(scripts, _files);
    let data_exfiltration_risk = detect_data_exfiltration(&network_access_patterns);

    let supply_chain_risk_score =
        calculate_supply_chain_risk(package_json, scripts, &network_access_patterns);

    Ok(NpmSecurityAnalysis {
        has_preinstall_script,
        has_postinstall_script,
        has_install_script,
        suspicious_scripts,
        network_access_patterns,
        file_system_access,
        process_execution,
        obfuscation_detected,
        crypto_mining_indicators,
        data_exfiltration_risk,
        supply_chain_risk_score,
    })
}

fn analyze_suspicious_scripts(scripts: &ScriptsAnalysis) -> Vec<SuspiciousScript> {
    let mut suspicious = vec![];

    for (name, content) in &scripts.script_hooks {
        let mut risk_indicators = vec![];
        let obfuscation_level = detect_script_obfuscation(content);

        // Check for suspicious patterns
        if content.contains("eval") || content.contains("Function(") {
            risk_indicators.push("Dynamic code execution".to_string());
        }
        if content.contains("base64") {
            risk_indicators.push("Base64 encoding/decoding".to_string());
        }
        if content.contains("\\x") || content.contains("\\u") {
            risk_indicators.push("Hex or unicode escape sequences".to_string());
        }
        if content.len() > 1000 && content.chars().filter(|c| c.is_whitespace()).count() < 10 {
            risk_indicators.push("Minified/obfuscated code".to_string());
        }

        let external_commands = extract_external_commands(content);

        if !risk_indicators.is_empty() || !external_commands.is_empty() {
            suspicious.push(SuspiciousScript {
                script_name: name.clone(),
                script_content: content.clone(),
                risk_indicators,
                obfuscation_level,
                external_commands,
            });
        }
    }

    suspicious
}

fn detect_script_obfuscation(script: &str) -> ObfuscationLevel {
    let mut score = 0;

    // Check various obfuscation indicators
    if script.contains("eval") {
        score += 2;
    }
    if script.contains("atob") || script.contains("btoa") {
        score += 2;
    }
    if script.contains("\\x") || script.contains("\\u") {
        score += 1;
    }
    if script.contains("fromCharCode") {
        score += 2;
    }
    if script.contains("String.prototype") {
        score += 1;
    }
    if script.len() > 500 && script.matches(' ').count() < 10 {
        score += 3;
    }

    // Check for suspicious variable names
    let suspicious_vars = regex::Regex::new(r"\b[a-zA-Z_]\w{0,2}\b").unwrap();
    if suspicious_vars.find_iter(script).count() > 20 {
        score += 2;
    }

    match score {
        0 => ObfuscationLevel::None,
        1..=2 => ObfuscationLevel::Low,
        3..=5 => ObfuscationLevel::Medium,
        6..=8 => ObfuscationLevel::High,
        _ => ObfuscationLevel::Extreme,
    }
}

fn extract_external_commands(script: &str) -> Vec<String> {
    let mut commands = vec![];

    let command_patterns = [
        r"(?:^|\s)(curl|wget|fetch|nc|netcat|telnet|ssh|scp)\s+[^\s]+",
        r"(?:^|\s)(node|npm|npx|yarn|pnpm)\s+[^\s]+",
        r"(?:^|\s)(python|python3|pip|pip3)\s+[^\s]+",
        r"(?:^|\s)(sh|bash|zsh|cmd|powershell)\s+[^\s]+",
    ];

    for pattern in &command_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for mat in re.find_iter(script) {
                commands.push(mat.as_str().trim().to_string());
            }
        }
    }

    commands
}

fn detect_network_patterns(
    scripts: &ScriptsAnalysis,
    _files: &[NpmFileAnalysis],
) -> Vec<NetworkAccessPattern> {
    let mut patterns = vec![];

    // URL regex pattern
    let url_re = regex::Regex::new(r#"https?://[^\s"']+"#).unwrap();

    // Check scripts
    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for mat in url_re.find_iter(content) {
            let url = mat.as_str().to_string();
            patterns.push(NetworkAccessPattern {
                url: url.clone(),
                protocol: if url.starts_with("https") {
                    "https"
                } else {
                    "http"
                }
                .to_string(),
                is_suspicious: is_suspicious_url(&url),
                reputation_score: None, // TODO: Implement reputation checking
                found_in: format!("script:{name}"),
            });
        }
    }

    // TODO: Also check file contents for URLs

    patterns
}

fn is_suspicious_url(url: &str) -> bool {
    let suspicious_patterns = [
        "pastebin.com",
        "bit.ly",
        "tinyurl.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        "transfer.sh",
        "file.io",
        "temp.sh",
        "ngrok.io",
    ];

    suspicious_patterns
        .iter()
        .any(|pattern| url.contains(pattern))
}

fn detect_filesystem_patterns(
    scripts: &ScriptsAnalysis,
    _files: &[NpmFileAnalysis],
) -> Vec<FileSystemAccess> {
    let mut accesses = vec![];

    let fs_patterns = [
        (r#"fs\.\w+\s*\(['"]([^'"]+)"#, "Node.js fs operation"),
        (r#"require\s*\(\s*['"]fs['"]\s*\)"#, "fs module import"),
        (
            r"writeFile|readFile|mkdir|rmdir|unlink",
            "File system operation",
        ),
        (r"/etc/passwd|/etc/shadow|~/.ssh", "Sensitive file access"),
        (r"process\.env|\.env", "Environment variable access"),
    ];

    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for (pattern, operation) in &fs_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(content) {
                    accesses.push(FileSystemAccess {
                        path: name.clone(),
                        operation: operation.to_string(),
                        is_suspicious: true,
                        reason: Some("Detected in script".to_string()),
                    });
                }
            }
        }
    }

    accesses
}

fn detect_process_execution(
    scripts: &ScriptsAnalysis,
    _files: &[NpmFileAnalysis],
) -> Vec<ProcessExecution> {
    let mut executions = vec![];

    let exec_patterns = [
        (r"child_process|exec|spawn|fork", "high"),
        (r#"require\s*\(\s*['"]child_process"#, "high"),
        (r"process\.kill|process\.exit", "medium"),
        (r"`[^`]+`", "medium"),     // Backticks
        (r"\$\([^)]+\)", "medium"), // Command substitution
    ];

    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for (pattern, risk) in &exec_patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(content) {
                    executions.push(ProcessExecution {
                        command: name.clone(),
                        arguments: vec![],
                        is_suspicious: true,
                        risk_level: risk.to_string(),
                    });
                }
            }
        }
    }

    executions
}

fn detect_obfuscation(scripts: &ScriptsAnalysis, _files: &[NpmFileAnalysis]) -> bool {
    // Check scripts for obfuscation
    for (_, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        if matches!(
            detect_script_obfuscation(content),
            ObfuscationLevel::High | ObfuscationLevel::Extreme
        ) {
            return true;
        }
    }

    // TODO: Check files for obfuscation
    false
}

fn detect_crypto_mining(scripts: &ScriptsAnalysis, _files: &[NpmFileAnalysis]) -> bool {
    let mining_indicators = [
        "stratum+tcp://",
        "cryptonight",
        "coinhive",
        "crypto-loot",
        "coin-hive",
        "miner",
        "monero",
        "bitcoin",
        "ethereum",
        "mining",
        "hashrate",
    ];

    for (_, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        let content_lower = content.to_lowercase();
        if mining_indicators
            .iter()
            .any(|indicator| content_lower.contains(indicator))
        {
            return true;
        }
    }

    false
}

fn detect_data_exfiltration(network_patterns: &[NetworkAccessPattern]) -> bool {
    // Check for suspicious data exfiltration patterns
    network_patterns.iter().any(|pattern| {
        pattern.is_suspicious
            || pattern.url.contains("webhook")
            || pattern.url.contains("discord.com/api/webhooks")
            || pattern.url.contains("telegram.org/bot")
    })
}

fn calculate_supply_chain_risk(
    _package_json: &Value,
    scripts: &ScriptsAnalysis,
    network_patterns: &[NetworkAccessPattern],
) -> f32 {
    let mut risk_score: f32 = 0.0;

    // Installation scripts are high risk
    if scripts.script_hooks.contains_key("preinstall") {
        risk_score += 20.0;
    }
    if scripts.script_hooks.contains_key("postinstall") {
        risk_score += 20.0;
    }
    if scripts.script_hooks.contains_key("install") {
        risk_score += 15.0;
    }

    // Network access in scripts
    if !network_patterns.is_empty() {
        risk_score += 10.0;
    }
    if network_patterns.iter().any(|p| p.is_suspicious) {
        risk_score += 20.0;
    }

    // Shell injection risk
    if scripts.shell_injection_risk {
        risk_score += 15.0;
    }

    // External downloads
    if !scripts.external_downloads.is_empty() {
        risk_score += 10.0;
    }

    risk_score.min(100.0)
}

fn detect_malicious_indicators(
    package_info: &PackageJsonInfo,
    dependencies: &NpmDependencyAnalysis,
    security: &NpmSecurityAnalysis,
) -> Result<MaliciousPackageIndicators> {
    let typosquatting_risk = analyze_typosquatting(&package_info.name);
    let dependency_confusion_risk = check_dependency_confusion(package_info, dependencies);
    let known_malicious_patterns = detect_known_malicious_patterns(package_info, security);
    let suspicious_maintainer_activity = false; // TODO: Implement
    let code_injection_patterns = detect_code_injection_patterns(security);
    let backdoor_indicators = detect_backdoor_indicators(security);

    let mut overall_risk_score = 0.0;

    if typosquatting_risk.is_potential_typosquatting {
        overall_risk_score += 30.0;
    }
    if dependency_confusion_risk {
        overall_risk_score += 25.0;
    }
    if !known_malicious_patterns.is_empty() {
        overall_risk_score += 40.0;
    }
    if !code_injection_patterns.is_empty() {
        overall_risk_score += 35.0;
    }
    if !backdoor_indicators.is_empty() {
        overall_risk_score += 45.0;
    }

    overall_risk_score = security
        .supply_chain_risk_score
        .mul_add(0.5, overall_risk_score);

    let risk_level = match overall_risk_score {
        x if x >= 80.0 => RiskLevel::Critical,
        x if x >= 60.0 => RiskLevel::High,
        x if x >= 40.0 => RiskLevel::Medium,
        x if x >= 20.0 => RiskLevel::Low,
        _ => RiskLevel::Safe,
    };

    Ok(MaliciousPackageIndicators {
        typosquatting_risk,
        dependency_confusion_risk,
        known_malicious_patterns,
        suspicious_maintainer_activity,
        code_injection_patterns,
        backdoor_indicators,
        overall_risk_score: overall_risk_score.min(100.0),
        risk_level,
    })
}

fn analyze_typosquatting(package_name: &str) -> TyposquattingAnalysis {
    let mut is_potential_typosquatting = false;
    let mut similar_packages = vec![];
    let mut suspicious_name_patterns = vec![];

    // Check for common typosquatting patterns
    let typo_patterns = [
        (r"-dev$", "Ends with -dev"),
        (r"-test$", "Ends with -test"),
        (r"^test-", "Starts with test-"),
        (r"\d+$", "Ends with numbers"),
        (r"[0-9]{2,}", "Contains multiple digits"),
        (r"(.)\1{2,}", "Repeated characters"),
    ];

    for (pattern, description) in &typo_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(package_name) {
                suspicious_name_patterns.push(description.to_string());
            }
        }
    }

    // Use the vulnerability database to check for typosquatting
    if let Some(similar) = check_typosquatting_similarity(package_name) {
        is_potential_typosquatting = true;
        for sim_name in similar {
            similar_packages.push(SimilarPackage {
                name: sim_name,
                download_count: None,  // TODO: Fetch from npm registry
                similarity_score: 0.8, // Default high similarity
            });
        }
    }

    // Check if it's in the known malicious packages list
    if get_known_malicious_packages().contains(&package_name) {
        is_potential_typosquatting = true;
        suspicious_name_patterns.push("Known malicious package".to_string());
    }

    TyposquattingAnalysis {
        is_potential_typosquatting,
        similar_packages,
        name_distance: None,
        suspicious_name_patterns,
    }
}

fn check_dependency_confusion(
    package_info: &PackageJsonInfo,
    _dependencies: &NpmDependencyAnalysis,
) -> bool {
    // Check if package appears to be targeting internal/private packages
    if package_info.private {
        return false;
    }

    // Check for patterns indicating dependency confusion attack
    let internal_patterns = [
        r"^@[a-z]+/internal-",
        r"^@[a-z]+/private-",
        r"-internal$",
        r"-private$",
        r"^corp-",
        r"^company-",
    ];

    for pattern in &internal_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(&package_info.name) {
                return true;
            }
        }
    }

    false
}

fn detect_known_malicious_patterns(
    package_info: &PackageJsonInfo,
    security: &NpmSecurityAnalysis,
) -> Vec<MaliciousPattern> {
    let mut patterns = vec![];

    // Check for known malicious patterns from database
    let db_patterns = get_malicious_patterns();

    // Check scripts for malicious patterns
    for script in &security.suspicious_scripts {
        for db_pattern in &db_patterns {
            for indicator in &db_pattern.indicators {
                if let Ok(re) = regex::Regex::new(indicator) {
                    if re.is_match(&script.script_content) {
                        patterns.push(MaliciousPattern {
                            pattern_type: db_pattern.pattern_name.clone(),
                            description: db_pattern.description.clone(),
                            found_in: script.script_name.clone(),
                            severity: db_pattern.severity.clone(),
                            evidence: format!("Pattern '{indicator}' found"),
                        });
                    }
                }
            }
        }
    }

    // Check if package is in known malicious list
    if get_known_malicious_packages().contains(&package_info.name.as_str()) {
        patterns.push(MaliciousPattern {
            pattern_type: "Known malicious package".to_string(),
            description: "This package is in the known malicious packages list".to_string(),
            found_in: "package name".to_string(),
            severity: "Critical".to_string(),
            evidence: package_info.name.clone(),
        });
    }

    // Check for known malicious patterns
    if security.has_preinstall_script && security.has_postinstall_script {
        patterns.push(MaliciousPattern {
            pattern_type: "Multiple install hooks".to_string(),
            description: "Package uses multiple installation hooks which is suspicious".to_string(),
            found_in: "package.json".to_string(),
            severity: "High".to_string(),
            evidence: "preinstall and postinstall scripts present".to_string(),
        });
    }

    if security.crypto_mining_indicators {
        patterns.push(MaliciousPattern {
            pattern_type: "Crypto mining".to_string(),
            description: "Package contains crypto mining indicators".to_string(),
            found_in: "scripts".to_string(),
            severity: "Critical".to_string(),
            evidence: "Mining-related keywords detected".to_string(),
        });
    }

    if security.data_exfiltration_risk {
        patterns.push(MaliciousPattern {
            pattern_type: "Data exfiltration".to_string(),
            description: "Package may exfiltrate data to external servers".to_string(),
            found_in: "scripts".to_string(),
            severity: "Critical".to_string(),
            evidence: "Suspicious network patterns detected".to_string(),
        });
    }

    patterns
}

fn detect_code_injection_patterns(security: &NpmSecurityAnalysis) -> Vec<CodeInjectionPattern> {
    let mut patterns = vec![];

    for script in &security.suspicious_scripts {
        if script
            .risk_indicators
            .iter()
            .any(|r| r.contains("Dynamic code execution"))
        {
            patterns.push(CodeInjectionPattern {
                injection_type: "Dynamic code execution".to_string(),
                location: script.script_name.clone(),
                code_snippet: script.script_content.chars().take(100).collect(),
                risk_level: "High".to_string(),
            });
        }
    }

    patterns
}

fn detect_backdoor_indicators(security: &NpmSecurityAnalysis) -> Vec<BackdoorIndicator> {
    let mut indicators = vec![];

    // Check for reverse shell patterns
    let reverse_shell_patterns = ["nc -e", "bash -i", "/dev/tcp", "telnet", "socat"];

    for pattern in &reverse_shell_patterns {
        for script in &security.suspicious_scripts {
            if script.script_content.contains(pattern) {
                indicators.push(BackdoorIndicator {
                    indicator_type: "Reverse shell".to_string(),
                    description: format!("Possible reverse shell using {pattern}"),
                    evidence: vec![script.script_name.clone()],
                    confidence: 0.8,
                });
            }
        }
    }

    indicators
}

fn analyze_maintainers(package_json: &Value) -> Result<MaintainerAnalysis> {
    let maintainers = package_json
        .get("maintainers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_object().map(|obj| MaintainerInfo {
                        name: obj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        email: obj.get("email").and_then(|e| e.as_str()).map(String::from),
                        npm_username: None,
                        first_publish_date: None,
                        package_count: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(MaintainerAnalysis {
        maintainers,
        contributors: vec![],
        ownership_changes: vec![],
        suspicious_activity: vec![],
        trust_score: 50.0, // Default neutral score
    })
}

fn calculate_quality_metrics(
    package_json: &Value,
    _files: &[NpmFileAnalysis],
) -> Result<PackageQualityMetrics> {
    let has_readme = _files
        .iter()
        .any(|f| f.file_path.to_lowercase().contains("readme"));
    let has_changelog = _files.iter().any(|f| {
        let path = f.file_path.to_lowercase();
        path.contains("changelog") || path.contains("history")
    });
    let has_tests = _files
        .iter()
        .any(|f| f.file_path.contains("test") || f.file_path.contains("spec"));
    let has_ci_config = _files.iter().any(|f| {
        f.file_path.contains(".travis")
            || f.file_path.contains(".github/workflows")
            || f.file_path.contains(".circleci")
    });

    let mut documentation_score = 0.0;
    if has_readme {
        documentation_score += 40.0;
    }
    if has_changelog {
        documentation_score += 20.0;
    }
    if package_json.get("description").is_some() {
        documentation_score += 20.0;
    }
    if package_json
        .get("keywords")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
    {
        documentation_score += 20.0;
    }

    let maintenance_score =
        if has_tests { 50.0 } else { 0.0 } + if has_ci_config { 50.0 } else { 0.0 };

    let overall_quality_score = f32::midpoint(documentation_score, maintenance_score);

    Ok(PackageQualityMetrics {
        has_readme,
        has_changelog,
        has_tests,
        has_ci_config,
        documentation_score,
        maintenance_score,
        popularity_score: 0.0, // TODO: Fetch from npm registry
        overall_quality_score,
    })
}

fn detect_file_type(path: &str) -> String {
    let extension = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    match extension {
        "js" => "JavaScript",
        "ts" => "TypeScript",
        "json" => "JSON",
        "md" => "Markdown",
        "txt" => "Text",
        "yml" | "yaml" => "YAML",
        _ => "Unknown",
    }
    .to_string()
}
