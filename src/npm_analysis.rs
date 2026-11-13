use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};
use crate::npm_vuln_db::{
    advisory_data_info, check_dependency_spec, check_package_vulnerabilities,
    check_typosquatting_similarity, get_known_malicious_packages, get_known_malicious_versions,
    get_malicious_patterns, is_known_malicious_release,
};
use crate::package_scan::{
    self, language_of, scan_source, sort_findings, source_findings_score, AdvisoryDataInfo,
    ContainerKind, InputInfo, LoadedPackage, Selector, SourceFinding,
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
    /// Suspicious constructs found in source files, worst first, with file and line.
    #[serde(default)]
    pub source_findings: Vec<SourceFinding>,
    /// What was read of the input and how much of it was scanned.
    #[serde(default)]
    pub input: InputInfo,
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
    /// Every package a lock file pins (direct and transitive), when there is a lock file.
    #[serde(default)]
    pub locked_packages: Vec<LockedPackage>,
    /// Advisories that apply to the analysed package itself.
    #[serde(default)]
    pub package_vulnerabilities: Vec<KnownVulnerability>,
    /// Where the advisory data comes from; an empty list is not a clean bill of health.
    #[serde(default)]
    pub vulnerability_db: AdvisoryDataInfo,
}

/// One entry of a lock file.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub dev: bool,
    pub vulnerabilities: Vec<KnownVulnerability>,
    /// This release is one the built-in table marks as malicious.
    #[serde(default)]
    pub known_malicious_release: bool,
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
    /// Advisories whose affected range contains the lowest version the declared
    /// range admits (ids). The installed version may be newer; a lock file settles it.
    #[serde(default)]
    pub range_floor_advisories: Vec<String>,
    /// The pinned or exact version is a release the built-in table marks as malicious.
    #[serde(default)]
    pub known_malicious_release: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilitySummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_count: usize,
    pub vulnerable_packages: Vec<String>,
    /// Dependencies whose declared range could install an affected version (not counted above).
    #[serde(default)]
    pub unresolved_range_hits: Vec<String>,
    /// `name@version` of every dependency (direct or locked) that is a release the
    /// built-in table marks as malicious. These are malware, not ordinary advisories.
    #[serde(default)]
    pub malicious_releases: Vec<String>,
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
    /// What the score is made of.
    #[serde(default)]
    pub risk_reasons: Vec<String>,
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
    /// The file's content was read and scanned (false for files past the scan limits).
    #[serde(default)]
    pub source_scanned: bool,
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

fn is_manifest(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    parts.len() <= 2
        && matches!(
            parts[parts.len() - 1],
            "package.json" | "package-lock.json" | "npm-shrinkwrap.json"
        )
}

fn is_source(path: &str) -> bool {
    language_of(path).is_some()
}

const SELECTOR: Selector = Selector {
    is_manifest,
    is_source,
};

/// Findings and URLs from scanning the source files.
#[derive(Default)]
struct SourceScan {
    findings: Vec<SourceFinding>,
    /// (url, file, line)
    urls: Vec<(String, String, usize)>,
    /// Files an install hook runs (`node scripts/setup.js`): package path to the
    /// hook's name. Their code runs at install time, so findings in them weigh
    /// like findings in the hook itself.
    install_files: HashMap<String, String>,
}

/// Cap on findings kept per package.
const MAX_FINDINGS: usize = 2000;

/// Main entry point for npm package analysis.
///
/// `path` is a gzip tarball (`.tgz`, `.tar.gz`, detected by content), a
/// directory, a `package.json`, or a lock file (`package-lock.json`,
/// `npm-shrinkwrap.json`) used as a dependency list. Registry names are not
/// supported: nothing is downloaded.
pub fn analyze_npm_package(path: &Path) -> Result<NpmPackageAnalysis> {
    if path.is_dir() {
        return analyze_npm_directory(path);
    }
    if !path.is_file() {
        anyhow::bail!("Path must be an npm tarball, package.json, package-lock.json or a directory containing package.json");
    }
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name == "package.json" {
        let directory = path
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        return analyze_npm_directory(directory);
    }
    if file_name == "package-lock.json" || file_name == "npm-shrinkwrap.json" {
        let text = package_scan::read_dependency_list(path)?;
        return analyze_lock_text(&text, file_name);
    }
    match package_scan::sniff(path)? {
        Some(kind @ (ContainerKind::TarGz | ContainerKind::Tar)) => {
            let loaded = package_scan::load(path, kind, &SELECTOR)?;
            analyze_loaded(&loaded, "tarball")
        }
        Some(ContainerKind::Zip) => anyhow::bail!(
            "This is a zip archive. npm packages are gzip tarballs: pass the .tgz that `npm pack` produces, an unpacked package directory, or a package.json."
        ),
        _ => anyhow::bail!(
            "Not an npm package: the file is not a gzip tarball (.tgz or .tar.gz), a package.json or a package-lock.json. Pass the .tgz that `npm pack` produces, an unpacked package directory, or a lock file."
        ),
    }
}

/// Analyze an npm package from a directory
fn analyze_npm_directory(dir_path: &Path) -> Result<NpmPackageAnalysis> {
    let has_manifest = dir_path.join("package.json").is_file();
    if !has_manifest {
        for lock in ["package-lock.json", "npm-shrinkwrap.json"] {
            let lock_path = dir_path.join(lock);
            if lock_path.is_file() {
                let text = package_scan::read_dependency_list(&lock_path)?;
                return analyze_lock_text(&text, lock);
            }
        }
        anyhow::bail!(
            "No package.json found in {} (and no package-lock.json). Pass the package directory, or the .tgz from `npm pack`.",
            dir_path.display()
        );
    }
    let loaded = package_scan::load(dir_path, ContainerKind::Directory, &SELECTOR)?;
    analyze_loaded(&loaded, "directory")
}

fn analyze_loaded(loaded: &LoadedPackage, kind: &str) -> Result<NpmPackageAnalysis> {
    let tarball = matches!(loaded.container, ContainerKind::TarGz | ContainerKind::Tar);
    let Some(manifest) =
        package_scan::root_manifest(&loaded.files, "package.json", "package", tarball)
    else {
        let nested: Vec<&str> = loaded
            .files
            .iter()
            .filter(|f| f.path.ends_with("package.json"))
            .map(|f| f.path.as_str())
            .take(3)
            .collect();
        let mut hint = if nested.is_empty() {
            String::new()
        } else {
            format!(" Only nested manifests exist: {}.", nested.join(", "))
        };
        if loaded.listing_truncated {
            hint.push_str(
                " The archive listing stopped at a limit (more than 64 MiB of long-name or PAX headers, or too many entries); a package.json may lie beyond it, so nothing was analysed.",
            );
        }
        anyhow::bail!(
            "No package.json found at the root of the package (expected package/package.json or package.json).{hint}"
        );
    };
    let manifest_path = manifest.path.clone();
    let manifest_text = loaded.text(&manifest_path).with_context(|| {
        if manifest.size > package_scan::MAX_MANIFEST_BYTES as u64 {
            format!(
                "{manifest_path} was not read: it is {} bytes, over the {} byte manifest limit",
                manifest.size,
                package_scan::MAX_MANIFEST_BYTES
            )
        } else {
            format!("{manifest_path} could not be read from the package (it may have been removed or be unreadable)")
        }
    })?;
    let root_dir = manifest_path
        .rsplit_once('/')
        .map_or("", |(dir, _)| dir)
        .to_string();
    let join = |name: &str| {
        if root_dir.is_empty() {
            name.to_string()
        } else {
            format!("{root_dir}/{name}")
        }
    };
    let lock = ["package-lock.json", "npm-shrinkwrap.json"]
        .iter()
        .find_map(|name| loaded.text(&join(name)))
        .and_then(|text| parse_lock(&text));

    let mut files = Vec::with_capacity(loaded.files.len());
    let mut scan = SourceScan::default();
    for file in &loaded.files {
        let mut analysis = NpmFileAnalysis {
            file_path: file.display_path().to_string(),
            file_type: detect_file_type(file.display_path()),
            size: file.size,
            entropy: 0.0,
            suspicious_content: vec![],
            hidden_functionality: false,
            malicious_patterns: vec![],
            source_scanned: false,
        };
        if let (Some(lang), Some(bytes)) = (language_of(&file.path), file.content.as_deref()) {
            let result = scan_source(lang, file.display_path(), bytes);
            analysis.source_scanned = true;
            analysis.entropy = result.entropy;
            analysis.hidden_functionality = result.obfuscation_score > 0.5
                || result.findings.iter().any(|f| f.severity == "Critical");
            analysis.suspicious_content = result
                .findings
                .iter()
                .map(|f| format!("line {}: {}", f.line, f.rule))
                .collect();
            let mut patterns: Vec<String> = result
                .findings
                .iter()
                .filter(|f| package_scan::severity_rank(&f.severity) >= 3)
                .map(|f| f.rule.clone())
                .collect();
            patterns.sort();
            patterns.dedup();
            analysis.malicious_patterns = patterns;
            for (url, line) in result.suspicious_urls {
                scan.urls.push((url, file.display_path().to_string(), line));
            }
            if scan.findings.len() < MAX_FINDINGS {
                scan.findings.extend(result.findings);
            }
        }
        files.push(analysis);
    }
    scan.findings.truncate(MAX_FINDINGS);
    sort_findings(&mut scan.findings);

    let mut input = InputInfo::from_loaded(kind, loaded, Some(&manifest_path));
    let unsafe_findings = package_scan::unsafe_entry_findings(loaded);
    if !unsafe_findings.is_empty() {
        scan.findings.extend(unsafe_findings);
        sort_findings(&mut scan.findings);
    }
    if let Some(note) = package_scan::unsafe_entry_note(loaded) {
        input.notes.push(note);
    }
    let competing = if tarball {
        package_scan::competing_manifests(&loaded.files, "package.json", &manifest_path)
    } else {
        vec![]
    };
    if !competing.is_empty() {
        let list = competing.join(", ");
        input.notes.push(format!(
            "The package holds more than one package.json ({list}). Analysed: {manifest_path}, the one npm install would use{}",
            " (the last entry under a top-level folder wins; root-level files are dropped)"
        ));
        scan.findings.push(SourceFinding {
            rule: "Several package.json files".to_string(),
            category: "package-structure".to_string(),
            severity: "High".to_string(),
            file: manifest_path.clone(),
            line: 1,
            evidence: format!(
                "also present: {}",
                list.chars().take(120).collect::<String>()
            ),
            in_comment: false,
        });
        sort_findings(&mut scan.findings);
    }
    analyze_package_json(
        &manifest_text,
        files,
        scan,
        lock.as_ref(),
        input,
        Some(&manifest_path),
    )
}

/// A lock file read as a dependency list.
struct ParsedLock {
    name: Option<String>,
    version: Option<String>,
    root_dependencies: Option<Value>,
    root_dev_dependencies: Option<Value>,
    packages: Vec<LockedPackage>,
    /// Version of each top-level `node_modules/<name>`.
    top_level: HashMap<String, String>,
}

const MAX_LOCKED: usize = 20_000;

fn parse_lock(text: &str) -> Option<ParsedLock> {
    let value: Value = serde_json::from_str(text).ok()?;
    let mut lock = ParsedLock {
        name: value.get("name").and_then(Value::as_str).map(String::from),
        version: value
            .get("version")
            .and_then(Value::as_str)
            .map(String::from),
        root_dependencies: None,
        root_dev_dependencies: None,
        packages: vec![],
        top_level: HashMap::new(),
    };
    let mut seen = std::collections::HashSet::new();
    let mut push = |lock: &mut ParsedLock, name: &str, version: &str, dev: bool| {
        if lock.packages.len() < MAX_LOCKED && seen.insert((name.to_string(), version.to_string()))
        {
            lock.packages.push(LockedPackage {
                name: name.to_string(),
                version: version.to_string(),
                dev,
                vulnerabilities: check_dependency_spec(name, version, Some(version))
                    .vulnerabilities,
                known_malicious_release: is_known_malicious_release(name, version),
            });
        }
    };
    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages {
            if key.is_empty() {
                lock.root_dependencies = entry.get("dependencies").cloned();
                lock.root_dev_dependencies = entry.get("devDependencies").cloned();
                if lock.name.is_none() {
                    lock.name = entry.get("name").and_then(Value::as_str).map(String::from);
                }
                if lock.version.is_none() {
                    lock.version = entry
                        .get("version")
                        .and_then(Value::as_str)
                        .map(String::from);
                }
                continue;
            }
            if entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let derived = key.rsplit("node_modules/").next().unwrap_or(key);
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(derived)
                .to_string();
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false);
            if *key == format!("node_modules/{derived}") && lock.top_level.len() < MAX_LOCKED {
                lock.top_level
                    .insert(derived.to_string(), version.to_string());
            }
            push(&mut lock, &name, version, dev);
        }
    } else {
        let dependencies = value.get("dependencies").and_then(Value::as_object)?;
        fn walk(
            deps: &serde_json::Map<String, Value>,
            top: bool,
            lock: &mut ParsedLock,
            push: &mut dyn FnMut(&mut ParsedLock, &str, &str, bool),
        ) {
            for (name, entry) in deps {
                if let Some(version) = entry.get("version").and_then(Value::as_str) {
                    let dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false);
                    if top && lock.top_level.len() < MAX_LOCKED {
                        lock.top_level.insert(name.clone(), version.to_string());
                    }
                    push(lock, name, version, dev);
                }
                if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                    walk(nested, false, lock, push);
                }
            }
        }
        walk(dependencies, true, &mut lock, &mut push);
    }
    Some(lock)
}

/// The first [`MAX_LOCKED`] entries of a dependency map.
fn take_entries(map: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    map.iter()
        .take(MAX_LOCKED)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A lock file as the only input: a dependency list, no source to scan.
fn analyze_lock_text(text: &str, file_name: &str) -> Result<NpmPackageAnalysis> {
    let lock = parse_lock(text).with_context(|| {
        format!("{file_name} is not a readable npm lock file (expected lockfileVersion 1, 2 or 3 JSON with `packages` or `dependencies`)")
    })?;
    let mut dependencies = serde_json::Map::new();
    let mut dev_dependencies = serde_json::Map::new();
    if let Some(Value::Object(map)) = &lock.root_dependencies {
        dependencies = take_entries(map);
    }
    if let Some(Value::Object(map)) = &lock.root_dev_dependencies {
        dev_dependencies = take_entries(map);
    }
    if dependencies.is_empty() && dev_dependencies.is_empty() {
        let dev_set: std::collections::HashSet<(&str, &str)> = lock
            .packages
            .iter()
            .filter(|p| p.dev)
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        for (name, version) in &lock.top_level {
            let dev = dev_set.contains(&(name.as_str(), version.as_str()));
            let target = if dev {
                &mut dev_dependencies
            } else {
                &mut dependencies
            };
            target.insert(name.clone(), Value::String(version.clone()));
        }
    }
    let manifest = serde_json::json!({
        "name": lock.name.clone().unwrap_or_else(|| "(lock file)".to_string()),
        "version": lock.version.clone().unwrap_or_else(|| "0.0.0".to_string()),
        "dependencies": dependencies,
        "devDependencies": dev_dependencies,
    });
    let input = InputInfo::dependency_list(
        "lockfile",
        &format!("{file_name} is a dependency list: no source files were scanned and the package name was not judged"),
    );
    analyze_package_json(
        &manifest.to_string(),
        vec![],
        SourceScan::default(),
        Some(&lock),
        input,
        None,
    )
}

/// Parse and analyze package.json content
fn analyze_package_json(
    package_json: &str,
    files: Vec<NpmFileAnalysis>,
    scan: SourceScan,
    lock: Option<&ParsedLock>,
    mut input: InputInfo,
    manifest_path: Option<&str>,
) -> Result<NpmPackageAnalysis> {
    // A lock file read as a manifest has no package of its own to judge.
    let judge_name = manifest_path.is_some();
    let mut scan = scan;
    let parsed: Value =
        serde_json::from_str(package_json).context("Failed to parse package.json")?;
    if let Some(manifest_path) = manifest_path {
        scan_install_scripts(&parsed, manifest_path, &mut scan, &mut input.notes);
    }

    let package_info = extract_package_info(&parsed)?;
    let dependencies = analyze_dependencies(&parsed, lock, &package_info)?;
    let mut scripts_analysis = analyze_scripts(&parsed)?;
    add_install_file_findings(&mut scripts_analysis, &scan);
    let security_analysis = perform_security_analysis(&parsed, &scripts_analysis, &scan)?;
    let mut malicious_indicators = detect_malicious_indicators(
        &package_info,
        &dependencies,
        &security_analysis,
        &scan.findings,
        &scan.install_files,
        judge_name,
    )?;
    apply_input_floor(&mut malicious_indicators, &input, &dependencies);
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
        source_findings: scan.findings,
        input,
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

fn analyze_dependencies(
    package_json: &Value,
    lock: Option<&ParsedLock>,
    package_info: &PackageJsonInfo,
) -> Result<NpmDependencyAnalysis> {
    let obj = package_json
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

    let top_level = lock.map(|l| &l.top_level);
    // Extract different dependency types
    let dependencies = extract_dependency_map(obj.get("dependencies"), top_level);
    let dev_dependencies = extract_dependency_map(obj.get("devDependencies"), top_level);
    let peer_dependencies = extract_dependency_map(obj.get("peerDependencies"), top_level);
    let optional_dependencies = extract_dependency_map(obj.get("optionalDependencies"), top_level);
    let bundled_dependencies = extract_bundled_dependencies(
        obj.get("bundledDependencies")
            .or_else(|| obj.get("bundleDependencies")),
    );

    let dependency_count = dependencies.len()
        + dev_dependencies.len()
        + peer_dependencies.len()
        + optional_dependencies.len();

    let mut vulnerability_summary = VulnerabilitySummary {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        total_count: 0,
        vulnerable_packages: vec![],
        unresolved_range_hits: vec![],
        malicious_releases: vec![],
    };
    let mut tally = |name: &str, vulns: &[KnownVulnerability]| {
        if vulns.is_empty() {
            return;
        }
        vulnerability_summary
            .vulnerable_packages
            .push(name.to_string());
        vulnerability_summary.total_count += vulns.len();
        for vuln in vulns {
            match vuln.severity {
                VulnerabilitySeverity::Critical => vulnerability_summary.critical_count += 1,
                VulnerabilitySeverity::High => vulnerability_summary.high_count += 1,
                VulnerabilitySeverity::Medium => vulnerability_summary.medium_count += 1,
                VulnerabilitySeverity::Low => vulnerability_summary.low_count += 1,
                VulnerabilitySeverity::None => {}
            }
        }
    };

    // Direct dependencies of every kind.
    let mut direct_names = std::collections::HashSet::new();
    let mut declared: Vec<(&String, &DependencyDetails)> = dependencies
        .iter()
        .chain(dev_dependencies.iter())
        .chain(peer_dependencies.iter())
        .chain(optional_dependencies.iter())
        .collect();
    declared.sort_by(|a, b| a.0.cmp(b.0));
    let mut unresolved = vec![];
    let mut malicious_releases: Vec<String> = vec![];
    for (name, details) in declared {
        direct_names.insert(name.clone());
        if details.known_malicious_release {
            let version = details
                .resolved_version
                .as_deref()
                .unwrap_or(details.version_spec.as_str());
            malicious_releases.push(format!(
                "{name}@{}",
                version.trim().trim_start_matches(['=', 'v'])
            ));
        }
        tally(name, &details.vulnerabilities);
        if !details.range_floor_advisories.is_empty() {
            unresolved.push(name.clone());
        }
    }
    // Transitive packages a lock file pins.
    let locked_packages = lock.map(|l| l.packages.clone()).unwrap_or_default();
    for package in &locked_packages {
        if !direct_names.contains(&package.name) {
            if package.known_malicious_release {
                malicious_releases.push(format!("{}@{}", package.name, package.version));
            }
            tally(
                &format!("{}@{}", package.name, package.version),
                &package.vulnerabilities,
            );
        }
    }
    unresolved.sort();
    unresolved.dedup();
    vulnerability_summary.unresolved_range_hits = unresolved;
    malicious_releases.sort();
    malicious_releases.dedup();
    vulnerability_summary.malicious_releases = malicious_releases;

    let package_vulnerabilities =
        check_package_vulnerabilities(&package_info.name, &package_info.version);

    Ok(NpmDependencyAnalysis {
        dependencies,
        dev_dependencies,
        peer_dependencies,
        optional_dependencies,
        bundled_dependencies,
        dependency_count,
        total_transitive_count: lock.map(|l| l.packages.len()),
        vulnerability_summary,
        locked_packages,
        package_vulnerabilities,
        vulnerability_db: advisory_data_info(),
    })
}

fn extract_dependency_map(
    deps_value: Option<&Value>,
    resolved: Option<&HashMap<String, String>>,
) -> HashMap<String, DependencyDetails> {
    deps_value
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(name, version)| {
                    let version_str = version.as_str().unwrap_or("");
                    let locked = resolved.and_then(|map| map.get(name)).map(String::as_str);
                    let check = check_dependency_spec(name, version_str, locked);
                    let known_malicious_release = check
                        .version_used
                        .as_deref()
                        .is_some_and(|v| is_known_malicious_release(name, v));

                    let details = DependencyDetails {
                        version_spec: version_str.to_string(),
                        resolved_version: locked.map(String::from),
                        is_local: version_str.starts_with("file:"),
                        is_git: version_str.contains("git") || version_str.contains("github"),
                        is_url: version_str.starts_with("http"),
                        vulnerabilities: check.vulnerabilities,
                        license: None,
                        deprecated: false,
                        deprecation_reason: None,
                        range_floor_advisories: check
                            .range_floor_matches
                            .into_iter()
                            .map(|v| v.cve_id)
                            .collect(),
                        known_malicious_release,
                    };
                    (name.clone(), details)
                })
                .collect()
        })
        .unwrap_or_default()
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
    let (scripts, _) = scripts_of(package_json);

    let mut script_hooks = HashMap::new();
    let mut custom_scripts = HashMap::new();
    let mut dangerous_commands = vec![];
    let mut external_downloads = vec![];
    let mut shell_injection_risk = false;

    for (name, content) in &scripts {
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
        if download_regex().is_match(content) {
            external_downloads.push(content.clone());
        }

        // Check for shell injection
        if content.contains('$') || content.contains('`') || eval_word_regex().is_match(content) {
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

/// A file an install hook runs is install-time code: its High and Critical
/// findings count as dangerous commands of that hook, and a download in it as an
/// external download.
fn add_install_file_findings(scripts: &mut ScriptsAnalysis, scan: &SourceScan) {
    let mut files: Vec<(&String, &String)> = scan.install_files.iter().collect();
    files.sort();
    for (file, hook) in files {
        let Some(worst) = scan
            .findings
            .iter()
            .filter(|f| {
                &f.file == file
                    && (package_scan::severity_rank(&f.severity) >= 3
                        || f.category == "obfuscation")
                    && !f.in_comment
            })
            .max_by_key(|f| package_scan::severity_rank(&f.severity))
        else {
            continue;
        };
        let command = scripts.script_hooks.get(hook).cloned().unwrap_or_default();
        scripts.dangerous_commands.push(DangerousCommand {
            command: command.clone(),
            script_name: hook.clone(),
            risk_reason: format!(
                "runs {file}, which contains {} ({}:{})",
                worst.rule, worst.file, worst.line
            ),
        });
        if scan
            .findings
            .iter()
            .any(|f| &f.file == file && f.category == "download-exec" && !f.in_comment)
            && !scripts.external_downloads.contains(&command)
        {
            scripts.external_downloads.push(command);
        }
    }
}

fn download_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\b(curl|wget)\b").expect("download regex"))
}

fn eval_word_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\beval\b").expect("eval regex"))
}

/// Scripts npm runs by itself when the package is installed.
const INSTALL_HOOKS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
];

/// Most scripts of one package.json that are analysed.
const MAX_SCRIPTS: usize = 500;

fn is_npm_hook(script_name: &str) -> bool {
    INSTALL_HOOKS.contains(&script_name)
}

/// Scripts of a package.json in analysis order: install hooks first, then the
/// rest by name, at most [`MAX_SCRIPTS`]. Returns how many were left out.
fn scripts_of(package_json: &Value) -> (Vec<(String, String)>, usize) {
    let mut scripts: Vec<(String, String)> = package_json
        .get("scripts")
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();
    scripts.sort_by(|a, b| (!is_npm_hook(&a.0), &a.0).cmp(&(!is_npm_hook(&b.0), &b.0)));
    let left_out = scripts.len().saturating_sub(MAX_SCRIPTS);
    scripts.truncate(MAX_SCRIPTS);
    (scripts, left_out)
}

fn node_eval_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"\bnode(js)?\b[^\n]*\s(-e|--eval|-p|--print)\b").expect("node -e regex")
    })
}

/// Run the install-time scripts through the source rules: `curl ... | sh` in a
/// `postinstall` is the textbook install-time attack and is rated like the same
/// line in a source file. Findings carry `<manifest>#scripts.<name>` as file.
fn scan_install_scripts(
    package_json: &Value,
    manifest_path: &str,
    scan: &mut SourceScan,
    notes: &mut Vec<String>,
) {
    let (scripts, left_out) = scripts_of(package_json);
    if left_out > 0 {
        notes.push(format!(
            "package.json has {} scripts; only the first {MAX_SCRIPTS} (install hooks first) were analysed",
            scripts.len() + left_out
        ));
    }
    let mut added = false;
    let root_dir = manifest_path.rsplit_once('/').map_or("", |(dir, _)| dir);
    for (name, text) in scripts.iter().filter(|(name, _)| is_npm_hook(name)) {
        for file in hook_files(text) {
            let full = if root_dir.is_empty() {
                file
            } else {
                format!("{root_dir}/{file}")
            };
            scan.install_files
                .entry(full)
                .or_insert_with(|| name.clone());
        }
        // The whole text: package.json is already capped, and padding must not hide the tail.
        let bytes = text.as_bytes();
        let mut langs = vec![package_scan::Lang::Shell];
        if node_eval_regex().is_match(text) {
            langs.push(package_scan::Lang::Js);
        }
        for lang in langs {
            let mut result = scan_source(lang, "package.json", bytes);
            for finding in &mut result.findings {
                finding.file = format!("{manifest_path}#scripts.{name}");
                if !scan.findings.iter().any(|f| {
                    f.file == finding.file && f.rule == finding.rule && f.line == finding.line
                }) {
                    scan.findings.push(finding.clone());
                    added = true;
                }
            }
            for (url, line) in result.suspicious_urls {
                scan.urls
                    .push((url, format!("{manifest_path}#scripts.{name}"), line));
            }
        }
    }
    if added {
        sort_findings(&mut scan.findings);
    }
}

/// Interpreters whose first non-option argument is a file they run.
const SCRIPT_RUNNERS: &[&str] = &[
    "node", "nodejs", "sh", "bash", "zsh", "dash", "python", "python2", "python3", "ts-node",
    "tsx", "bun", "deno",
];

/// Files in the package that an install hook's command runs: `node scripts/setup.js`,
/// `sh ./install.sh`, `python3 setup_hook.py` or a direct `./scripts/run.sh`, also
/// when joined with `&&`, `||`, `;` or `|`. Paths are relative to the package root,
/// without `./`; a path that leaves the package or is absolute is dropped.
fn hook_files(command: &str) -> Vec<String> {
    /// Join `path` onto the directory `base` (package-relative parts); `None`
    /// when the result leaves the package.
    fn resolve(base: &[String], path: &str) -> Option<Vec<String>> {
        if path.starts_with('/') {
            return None;
        }
        let mut parts: Vec<String> = base.to_vec();
        for part in path.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                other => parts.push(other.to_string()),
            }
        }
        Some(parts)
    }
    let mut files: Vec<String> = Vec::new();
    // The directory a `cd` moved to; `None` once it left the package.
    let mut cwd: Option<Vec<String>> = Some(Vec::new());
    for segment in command.split(['&', '|', ';', '\n']) {
        let mut tokens: Vec<&str> = segment
            .split_whitespace()
            .map(|t| t.trim_matches(['"', '\'']))
            .collect();
        // `NAME=value node file.js`
        while tokens.first().is_some_and(|t| {
            t.split_once('=').is_some_and(|(name, _)| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        }) {
            tokens.remove(0);
        }
        let Some(first) = tokens.first() else {
            continue;
        };
        if *first == "cd" {
            cwd = match (&cwd, tokens.get(1)) {
                (Some(base), Some(dir)) => resolve(base, dir),
                _ => None,
            };
            continue;
        }
        let Some(base) = cwd.as_ref() else {
            continue;
        };
        let runner = first.rsplit('/').next().unwrap_or(first);
        let candidate = if SCRIPT_RUNNERS.contains(&runner) {
            let mut iter = tokens[1..].iter();
            let mut found = None;
            while let Some(token) = iter.next() {
                if matches!(*token, "-e" | "--eval" | "-p" | "--print" | "-c") {
                    break;
                }
                if matches!(*token, "-r" | "--require" | "--import" | "--loader") {
                    iter.next();
                    continue;
                }
                if token.starts_with('-') {
                    continue;
                }
                found = Some(*token);
                break;
            }
            found
        } else if first.contains('/') {
            Some(*first)
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let Some(parts) = resolve(base, candidate) else {
            continue;
        };
        if parts.is_empty() {
            continue;
        }
        let path = parts.join("/");
        let last = parts.last().map_or("", String::as_str);
        let lower = last.to_ascii_lowercase();
        let paths: Vec<String> = if lower.contains('.') {
            if ["js", "mjs", "cjs", "ts", "sh", "py"]
                .iter()
                .any(|ext| lower.ends_with(&format!(".{ext}")))
            {
                vec![path]
            } else {
                continue;
            }
        } else {
            // `node scripts/setup` and `node scripts`: what node would load.
            vec![
                format!("{path}.js"),
                format!("{path}.cjs"),
                format!("{path}.mjs"),
                format!("{path}/index.js"),
            ]
        };
        for path in paths {
            if !files.contains(&path) {
                files.push(path);
            }
        }
    }
    files
}

fn dangerous_command_rules() -> &'static Vec<(regex::Regex, &'static str)> {
    static RULES: std::sync::OnceLock<Vec<(regex::Regex, &'static str)>> =
        std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        [
            (
                r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r",
                "Recursive file deletion",
            ),
            (r"\bsudo\b", "Elevated privileges"),
            (
                r"\bchmod\s+(-R\s+)?777\b",
                "Overly permissive file permissions",
            ),
            (r"\b(nc|ncat|netcat)\s", "Netcat network tool"),
            (r"\btelnet\b", "Unencrypted network communication"),
            (r"/dev/tcp", "Bash network redirection"),
            (
                r"\bbase64\s+(-d|--decode)\b",
                "Base64 decoding (possible obfuscation)",
            ),
            (r"\beval\b", "Dynamic code execution"),
            (r"\bexec\b", "Process execution"),
            (r"\bspawn\b", "Process spawning"),
        ]
        .iter()
        .map(|(pattern, reason)| (regex::Regex::new(pattern).expect("dangerous rule"), *reason))
        .collect()
    })
}

fn check_dangerous_command(command: &str) -> Option<String> {
    // A download that is run is the first thing to say about a script.
    let text = command.as_bytes();
    let scan = scan_source(package_scan::Lang::Shell, "package.json", text);
    if let Some(finding) = scan.findings.iter().find(|f| f.category == "download-exec") {
        return Some(format!("{} (download and run)", finding.rule));
    }
    dangerous_command_rules()
        .iter()
        .find(|(re, _)| re.is_match(command))
        .map(|(_, reason)| (*reason).to_string())
}

fn perform_security_analysis(
    package_json: &Value,
    scripts: &ScriptsAnalysis,
    scan: &SourceScan,
) -> Result<NpmSecurityAnalysis> {
    let has_preinstall_script = scripts.script_hooks.contains_key("preinstall");
    let has_postinstall_script = scripts.script_hooks.contains_key("postinstall");
    let has_install_script = scripts.script_hooks.contains_key("install");

    let suspicious_scripts = analyze_suspicious_scripts(scripts);
    let mut network_access_patterns = detect_network_patterns(scripts);
    // A URL mentioned in a source file is not evidence of exfiltration: only
    // script URLs and High exfiltration findings (below) decide that.
    let script_network_patterns = network_access_patterns.clone();
    for (url, file, line) in &scan.urls {
        if network_access_patterns.len() >= 100 {
            break;
        }
        network_access_patterns.push(NetworkAccessPattern {
            url: url.clone(),
            protocol: if url.starts_with("https") {
                "https"
            } else {
                "http"
            }
            .to_string(),
            is_suspicious: true,
            reputation_score: None,
            found_in: format!("file:{file}:{line}"),
        });
    }
    let file_system_access = detect_filesystem_patterns(scripts);
    let mut process_execution = detect_process_execution(scripts);
    for finding in scan
        .findings
        .iter()
        .filter(|f| f.category == "process-exec")
        .take(50)
    {
        process_execution.push(ProcessExecution {
            command: format!("{}:{}", finding.file, finding.line),
            arguments: vec![finding.evidence.clone()],
            is_suspicious: true,
            risk_level: finding.severity.to_lowercase(),
        });
    }

    // An obfuscation finding of High severity (an eval of a decoded payload) is
    // the signal by itself; Medium ones count when there are two.
    let obfuscation_detected = detect_obfuscation(scripts)
        || scan
            .findings
            .iter()
            .any(|f| f.category == "obfuscation" && f.severity != "Medium" && !f.in_comment)
        || scan
            .findings
            .iter()
            .filter(|f| f.category == "obfuscation")
            .count()
            >= 2;
    let crypto_mining_indicators =
        detect_crypto_mining(scripts) || scan.findings.iter().any(|f| f.category == "cryptomining");
    let data_exfiltration_risk = detect_data_exfiltration(&script_network_patterns)
        || scan
            .findings
            .iter()
            .any(|f| f.category == "exfiltration" && f.severity != "Medium");

    let supply_chain_risk_score =
        calculate_supply_chain_risk(package_json, scripts, &script_network_patterns);

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
    static SHORT_NAMES: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
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
    let suspicious_vars = SHORT_NAMES
        .get_or_init(|| regex::Regex::new(r"\b[a-zA-Z_]\w{0,2}\b").expect("short names"));
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
    static PATTERNS: std::sync::OnceLock<Vec<regex::Regex>> = std::sync::OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            r"(?:^|\s)(curl|wget|fetch|nc|netcat|telnet|ssh|scp)\s+[^\s]+",
            r"(?:^|\s)(node|npm|npx|yarn|pnpm)\s+[^\s]+",
            r"(?:^|\s)(python|python3|pip|pip3)\s+[^\s]+",
            r"(?:^|\s)(sh|bash|zsh|cmd|powershell)\s+[^\s]+",
        ]
        .iter()
        .map(|p| regex::Regex::new(p).expect("command pattern"))
        .collect()
    });
    let mut commands = vec![];
    for re in patterns {
        for mat in re.find_iter(script).take(20) {
            commands.push(mat.as_str().trim().to_string());
        }
    }
    commands
}

fn detect_network_patterns(scripts: &ScriptsAnalysis) -> Vec<NetworkAccessPattern> {
    static URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let mut patterns = vec![];

    let url_re = URL.get_or_init(|| regex::Regex::new(r#"https?://[^\s"']+"#).expect("url"));

    // Check scripts
    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for mat in url_re.find_iter(content).take(50) {
            let url = mat.as_str().to_string();
            // A raw-file or gist URL in a script that runs at install is a staging
            // download; in a benchmark or build script it is ordinary. Hosts that
            // exist to receive stolen data count wherever they appear.
            let suspicious = package_scan::is_suspicious_url(&url)
                || (is_suspicious_url(&url) && is_npm_hook(name));
            patterns.push(NetworkAccessPattern {
                url: url.clone(),
                protocol: if url.starts_with("https") {
                    "https"
                } else {
                    "http"
                }
                .to_string(),
                is_suspicious: suspicious,
                reputation_score: None, // no reputation source is available offline
                found_in: format!("script:{name}"),
            });
        }
    }

    patterns
}

fn is_suspicious_url(url: &str) -> bool {
    if package_scan::is_suspicious_url(url) {
        return true;
    }
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

fn detect_filesystem_patterns(scripts: &ScriptsAnalysis) -> Vec<FileSystemAccess> {
    static PATTERNS: std::sync::OnceLock<Vec<(regex::Regex, &'static str)>> =
        std::sync::OnceLock::new();
    let fs_patterns = PATTERNS.get_or_init(|| {
        [
            (r#"fs\.\w+\s*\(['"]([^'"]+)"#, "Node.js fs operation"),
            (r#"require\s*\(\s*['"]fs['"]\s*\)"#, "fs module import"),
            (
                r"writeFile|readFile|mkdir|rmdir|unlink",
                "File system operation",
            ),
            (r"/etc/passwd|/etc/shadow|~/.ssh", "Sensitive file access"),
            (r"process\.env|\.env", "Environment variable access"),
        ]
        .iter()
        .map(|(p, o)| (regex::Regex::new(p).expect("fs pattern"), *o))
        .collect()
    });
    let mut accesses = vec![];

    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for (re, operation) in fs_patterns {
            if re.is_match(content) {
                accesses.push(FileSystemAccess {
                    path: name.clone(),
                    operation: (*operation).to_string(),
                    is_suspicious: true,
                    reason: Some("Detected in script".to_string()),
                });
            }
        }
    }

    accesses
}

fn detect_process_execution(scripts: &ScriptsAnalysis) -> Vec<ProcessExecution> {
    static PATTERNS: std::sync::OnceLock<Vec<(regex::Regex, &'static str)>> =
        std::sync::OnceLock::new();
    let exec_patterns = PATTERNS.get_or_init(|| {
        [
            (r"child_process|\bexec\b|\bspawn\b|\bfork\b", "high"),
            (r#"require\s*\(\s*['"]child_process"#, "high"),
            (r"process\.kill|process\.exit", "medium"),
            (r"`[^`]+`", "medium"),     // Backticks
            (r"\$\([^)]+\)", "medium"), // Command substitution
        ]
        .iter()
        .map(|(p, r)| (regex::Regex::new(p).expect("exec pattern"), *r))
        .collect()
    });
    let mut executions = vec![];

    for (name, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        for (re, risk) in exec_patterns {
            if re.is_match(content) {
                executions.push(ProcessExecution {
                    command: name.clone(),
                    arguments: vec![],
                    is_suspicious: true,
                    risk_level: (*risk).to_string(),
                });
            }
        }
    }

    executions
}

fn detect_obfuscation(scripts: &ScriptsAnalysis) -> bool {
    // Check scripts for obfuscation
    for (_, content) in scripts.script_hooks.iter().chain(&scripts.custom_scripts) {
        if matches!(
            detect_script_obfuscation(content),
            ObfuscationLevel::High | ObfuscationLevel::Extreme
        ) {
            return true;
        }
    }

    false
}

fn detect_crypto_mining(scripts: &ScriptsAnalysis) -> bool {
    // Strong indicators only: the words "miner", "bitcoin" or "ethereum" appear in
    // ordinary script and file names (examiner, ethereum.config.js).
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)(stratum\+(tcp|ssl|tls)://|\bcryptonight\b|\bcoin-?hive\b|\bcrypto-?loot\b|\bxmrig\b|\bminerd\b|\bcpuminer\b|\bminexmr\b)",
        )
        .expect("mining regex")
    });
    scripts
        .script_hooks
        .values()
        .chain(scripts.custom_scripts.values())
        .any(|content| re.is_match(content))
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

/// Raise the rating of an input that was not read in full (see
/// `package_scan::input_floor`).
fn apply_input_floor(
    indicators: &mut MaliciousPackageIndicators,
    input: &InputInfo,
    dependencies: &NpmDependencyAnalysis,
) {
    let has_advisory = dependencies.vulnerability_summary.total_count > 0
        || !dependencies.package_vulnerabilities.is_empty();
    if let Some((floor, reason)) = package_scan::input_floor(input, has_advisory) {
        if indicators.overall_risk_score < floor {
            indicators.overall_risk_score = floor;
            indicators.risk_level = match package_scan::level_for_score(floor) {
                "Medium" => RiskLevel::Medium,
                _ => RiskLevel::Low,
            };
        }
        indicators.risk_reasons.push(reason);
    }
}

/// Advisory counts of the dependencies that are not known malicious releases:
/// (total, critical, high, medium). Mirrors how the summary tallies direct and
/// locked packages.
fn ordinary_advisory_counts(dependencies: &NpmDependencyAnalysis) -> (usize, usize, usize, usize) {
    let mut counts = (0usize, 0usize, 0usize, 0usize);
    let mut add = |vulns: &[KnownVulnerability]| {
        for vuln in vulns {
            counts.0 += 1;
            match vuln.severity {
                VulnerabilitySeverity::Critical => counts.1 += 1,
                VulnerabilitySeverity::High => counts.2 += 1,
                VulnerabilitySeverity::Medium => counts.3 += 1,
                _ => {}
            }
        }
    };
    let mut direct = std::collections::HashSet::new();
    for (name, details) in dependencies
        .dependencies
        .iter()
        .chain(&dependencies.dev_dependencies)
        .chain(&dependencies.peer_dependencies)
        .chain(&dependencies.optional_dependencies)
    {
        direct.insert(name.as_str());
        if !details.known_malicious_release {
            add(&details.vulnerabilities);
        }
    }
    for package in &dependencies.locked_packages {
        if !direct.contains(package.name.as_str()) && !package.known_malicious_release {
            add(&package.vulnerabilities);
        }
    }
    counts
}

/// Points the dependency vulnerability counts add to the risk score.
fn vulnerability_points(critical: usize, high: usize, medium: usize) -> f32 {
    if critical > 0 {
        40.0
    } else if high > 0 || medium > 0 {
        20.0
    } else {
        0.0
    }
}

fn detect_malicious_indicators(
    package_info: &PackageJsonInfo,
    dependencies: &NpmDependencyAnalysis,
    security: &NpmSecurityAnalysis,
    findings: &[SourceFinding],
    install_files: &HashMap<String, String>,
    judge_name: bool,
) -> Result<MaliciousPackageIndicators> {
    let typosquatting_risk = if judge_name {
        analyze_typosquatting(&package_info.name)
    } else {
        TyposquattingAnalysis {
            is_potential_typosquatting: false,
            similar_packages: vec![],
            name_distance: None,
            suspicious_name_patterns: vec![],
        }
    };
    let dependency_confusion_risk =
        judge_name && check_dependency_confusion(package_info, dependencies);
    let known_malicious_patterns = if judge_name {
        detect_known_malicious_patterns(package_info, security, findings)
    } else {
        vec![]
    };
    let suspicious_maintainer_activity = false; // needs registry data; this tool is offline
    let code_injection_patterns = detect_code_injection_patterns(security, findings);
    let backdoor_indicators = detect_backdoor_indicators(security, findings);

    let mut overall_risk_score = 0.0;
    let mut reasons: Vec<String> = vec![];

    if typosquatting_risk.is_potential_typosquatting {
        overall_risk_score += 30.0;
        reasons.push("package name resembles a popular package or a known malicious name".into());
    }
    if dependency_confusion_risk {
        overall_risk_score += 25.0;
        reasons.push("package name looks like an internal package (dependency confusion)".into());
    }
    if !known_malicious_patterns.is_empty() {
        overall_risk_score += 40.0;
        reasons.push(format!(
            "{} known-malicious pattern(s): {}",
            known_malicious_patterns.len(),
            known_malicious_patterns
                .iter()
                .map(|p| p.pattern_type.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !code_injection_patterns.is_empty() {
        overall_risk_score += 35.0;
        reasons.push("dynamic code execution of decoded or dynamic content".into());
    }
    if !backdoor_indicators.is_empty() {
        overall_risk_score += 45.0;
        reasons.push("backdoor / reverse shell indicators".into());
    }

    let source_points = source_findings_score(findings);
    if source_points > 0.0 {
        overall_risk_score += source_points;
        reasons.push(format!(
            "{} finding(s) in source files (see section findings)",
            findings.len()
        ));
    }

    // The same behaviour is worse in a script npm runs on install: nobody has
    // to import the code for it to run.
    // A file a hook runs that is obfuscated (obfuscator names, an escaped or
    // char-code string blob) counts too: nobody hides ordinary code that way.
    let mut hook_obfuscation = false;
    if let Some(hit) = findings.iter().find(|f| {
        (f.file.contains("#scripts.") || install_files.contains_key(&f.file))
            && (package_scan::severity_rank(&f.severity) >= 3
                || (install_files.contains_key(&f.file) && f.category == "obfuscation"))
            && !f.in_comment
    }) {
        hook_obfuscation = package_scan::severity_rank(&hit.severity) < 3;
        overall_risk_score += 20.0;
        let place = match install_files.get(&hit.file) {
            Some(hook) => format!("{hook} runs {}", hit.file),
            None => hit.file.rsplit('#').next().unwrap_or("scripts").to_string(),
        };
        reasons.push(format!(
            "an install-time script runs suspicious code: {} ({place})",
            hit.rule
        ));
    }

    let summary = &dependencies.vulnerability_summary;
    let malicious_dependencies = !summary.malicious_releases.is_empty();
    if malicious_dependencies {
        reasons.push(format!(
            "depends on {} known malicious release(s): {}",
            summary.malicious_releases.len(),
            summary
                .malicious_releases
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    // The advisories of a malicious release are part of the malware finding above;
    // the ordinary advisory counts are the rest.
    let (other_total, other_critical, other_high, _other_medium) =
        ordinary_advisory_counts(dependencies);
    // The points come from the full counts, as for any advisory: a malicious
    // release adds at least what a Critical advisory does. Only the wording
    // of the reason leaves the malware entries out.
    let dep_points = vulnerability_points(
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
    );
    if dep_points > 0.0 {
        overall_risk_score += dep_points;
        let (total, critical, high) = if malicious_dependencies {
            (other_total, other_critical, other_high)
        } else {
            (
                summary.total_count,
                summary.critical_count,
                summary.high_count,
            )
        };
        if total > 0 {
            reasons.push(format!(
                "{total} known vulnerability(ies) in dependencies ({critical} critical, {high} high)"
            ));
        }
    }
    let own_critical = dependencies
        .package_vulnerabilities
        .iter()
        .filter(|v| matches!(v.severity, VulnerabilitySeverity::Critical))
        .count();
    if !dependencies.package_vulnerabilities.is_empty() {
        overall_risk_score += if own_critical > 0 { 40.0 } else { 20.0 };
        reasons.push(format!(
            "this package version has {} known advisory(ies)",
            dependencies.package_vulnerabilities.len()
        ));
    }

    if security.supply_chain_risk_score > 0.0 {
        reasons.push(format!(
            "install scripts / network use in scripts (supply chain score {:.0})",
            security.supply_chain_risk_score
        ));
    }
    overall_risk_score = security
        .supply_chain_risk_score
        .mul_add(0.5, overall_risk_score);

    // High and Critical need a High or Critical reason: a known-bad name or
    // release, a strong finding, a backdoor, or an advisory on this package or
    // a dependency. Soft signals alone (a name that resembles another, Medium
    // findings, install hooks) stop at Medium.
    let strong_evidence = !known_malicious_patterns.is_empty()
        || hook_obfuscation
        || !backdoor_indicators.is_empty()
        || !code_injection_patterns.is_empty()
        || findings
            .iter()
            .any(|f| package_scan::severity_rank(&f.severity) >= 3)
        || !dependencies.package_vulnerabilities.is_empty()
        || summary.critical_count + summary.high_count > 0
        || security.supply_chain_risk_score >= 50.0;
    if known_malicious_patterns.iter().any(|p| {
        matches!(
            p.pattern_type.as_str(),
            "Known malicious package" | "Known malicious release"
        )
    }) {
        // A known-bad name or release is Critical on its own.
        overall_risk_score = overall_risk_score.max(80.0);
    }
    if hook_obfuscation {
        overall_risk_score = overall_risk_score.max(60.0);
    }
    if malicious_dependencies {
        // Depending on a hijacked or trojaned release is a supply-chain compromise,
        // not an ordinary advisory: at least High.
        overall_risk_score = overall_risk_score.max(70.0);
    }
    if !strong_evidence && !malicious_dependencies {
        overall_risk_score = overall_risk_score.min(59.0);
    }
    if typosquatting_risk.is_potential_typosquatting {
        // The name is flagged as imitating another: the level must match the flag.
        overall_risk_score = overall_risk_score.max(40.0);
    }

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
        risk_reasons: reasons,
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

fn first_finding<'a>(findings: &'a [SourceFinding], category: &str) -> Option<&'a SourceFinding> {
    findings.iter().find(|f| f.category == category)
}

fn detect_known_malicious_patterns(
    package_info: &PackageJsonInfo,
    security: &NpmSecurityAnalysis,
    findings: &[SourceFinding],
) -> Vec<MaliciousPattern> {
    let mut patterns = vec![];

    // Check for known malicious patterns from database
    let db_patterns = get_malicious_patterns();

    // Check scripts for malicious patterns
    for script in &security.suspicious_scripts {
        for db_pattern in &db_patterns {
            // Name-shaped patterns (typosquat suffixes, internal prefixes) are
            // judged against the package name elsewhere, not against script text.
            if matches!(
                db_pattern.pattern_name.as_str(),
                "Typosquatting indicators" | "Dependency confusion"
            ) {
                continue;
            }
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

    // Check if package is in the known malicious lists: bare names, or name and version.
    let name = package_info.name.to_ascii_lowercase();
    if get_known_malicious_packages().contains(&name.as_str()) {
        patterns.push(MaliciousPattern {
            pattern_type: "Known malicious package".to_string(),
            description: "This package name is in the known malicious packages list".to_string(),
            found_in: "package name".to_string(),
            severity: "Critical".to_string(),
            evidence: package_info.name.clone(),
        });
    }
    if get_known_malicious_versions()
        .iter()
        .any(|(n, v)| *n == name && *v == package_info.version)
    {
        patterns.push(MaliciousPattern {
            pattern_type: "Known malicious release".to_string(),
            description: "This exact version is a known compromised release".to_string(),
            found_in: "package name and version".to_string(),
            severity: "Critical".to_string(),
            evidence: format!("{}@{}", package_info.name, package_info.version),
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
        let hit = first_finding(findings, "cryptomining");
        patterns.push(MaliciousPattern {
            pattern_type: "Crypto mining".to_string(),
            description: "Package contains crypto mining indicators".to_string(),
            found_in: hit.map_or_else(
                || "scripts".to_string(),
                |f| format!("{}:{}", f.file, f.line),
            ),
            severity: "Critical".to_string(),
            evidence: hit.map_or_else(
                || "Mining-related keywords detected".to_string(),
                |f| f.evidence.clone(),
            ),
        });
    }

    if security.data_exfiltration_risk {
        let hit = first_finding(findings, "exfiltration");
        patterns.push(MaliciousPattern {
            pattern_type: "Data exfiltration".to_string(),
            description: "Package may exfiltrate data to external servers".to_string(),
            found_in: hit.map_or_else(
                || "scripts".to_string(),
                |f| format!("{}:{}", f.file, f.line),
            ),
            severity: "Critical".to_string(),
            evidence: hit.map_or_else(
                || "Suspicious network patterns detected".to_string(),
                |f| f.evidence.clone(),
            ),
        });
    }

    patterns
}

fn detect_code_injection_patterns(
    security: &NpmSecurityAnalysis,
    findings: &[SourceFinding],
) -> Vec<CodeInjectionPattern> {
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
    // Only evaluation of decoded payloads counts here; plain eval is a Medium finding.
    for finding in findings
        .iter()
        .filter(|f| {
            f.rule == "Eval of decoded payload"
                || f.rule == "Decoded payload passed to process execution"
        })
        .take(20)
    {
        patterns.push(CodeInjectionPattern {
            injection_type: finding.rule.clone(),
            location: format!("{}:{}", finding.file, finding.line),
            code_snippet: finding.evidence.clone(),
            risk_level: finding.severity.clone(),
        });
    }

    patterns
}

fn detect_backdoor_indicators(
    security: &NpmSecurityAnalysis,
    findings: &[SourceFinding],
) -> Vec<BackdoorIndicator> {
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
    for finding in findings
        .iter()
        .filter(|f| f.category == "backdoor")
        .take(20)
    {
        indicators.push(BackdoorIndicator {
            indicator_type: finding.rule.clone(),
            description: format!("{} at {}:{}", finding.rule, finding.file, finding.line),
            evidence: vec![finding.evidence.clone()],
            confidence: 0.9,
        });
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
        "js" | "mjs" | "cjs" | "jsx" => "JavaScript",
        "ts" | "tsx" | "mts" | "cts" => "TypeScript",
        "sh" | "bash" => "Shell",
        "py" => "Python",
        "json" => "JSON",
        "md" => "Markdown",
        "txt" => "Text",
        "yml" | "yaml" => "YAML",
        _ => "Unknown",
    }
    .to_string()
}
