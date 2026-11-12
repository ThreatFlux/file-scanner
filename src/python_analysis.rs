use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};
use crate::package_scan::{
    self, language_of, scan_source, sort_findings, source_findings_score, AdvisoryDataInfo,
    ContainerKind, InputInfo, LoadedPackage, Selector, SourceFinding,
};
use crate::python_vuln_db::{
    advisory_data_info, check_dependency_spec, check_package_vulnerabilities,
    check_typosquatting_similarity, classify_specifier, get_known_malicious_packages,
    get_known_malicious_versions, normalize_name, SpecKind,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PythonPackageAnalysis {
    pub package_info: PackageInfo,
    pub dependencies: PythonDependencyAnalysis,
    pub security_analysis: PythonSecurityAnalysis,
    pub malicious_indicators: MaliciousPackageIndicators,
    pub files_analysis: Vec<PythonFileAnalysis>,
    pub setup_analysis: SetupAnalysis,
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
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub author_email: Option<String>,
    pub maintainer: Option<String>,
    pub maintainer_email: Option<String>,
    pub license: Option<String>,
    pub url: Option<String>,
    pub project_urls: HashMap<String, String>,
    pub keywords: Vec<String>,
    pub classifiers: Vec<String>,
    pub python_requires: Option<String>,
    pub package_format: PackageFormat,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PackageFormat {
    Wheel,
    SourceDistribution,
    EggInfo,
    Directory,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PythonDependencyAnalysis {
    pub install_requires: HashMap<String, DependencyDetails>,
    pub extras_require: HashMap<String, HashMap<String, DependencyDetails>>,
    pub setup_requires: HashMap<String, DependencyDetails>,
    pub tests_require: HashMap<String, DependencyDetails>,
    pub dependency_count: usize,
    pub vulnerability_summary: VulnerabilitySummary,
    /// Packages a lock file (poetry.lock) pins, when there is one.
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyDetails {
    pub version_spec: String,
    pub is_pinned: bool,
    pub is_url: bool,
    pub is_git: bool,
    pub vulnerabilities: Vec<KnownVulnerability>,
    pub deprecated: bool,
    /// Version a lock file pins, when there is one.
    #[serde(default)]
    pub resolved_version: Option<String>,
    /// Advisories whose affected range contains the lowest version the
    /// specifier admits (ids). The installed version may be newer.
    #[serde(default)]
    pub range_floor_advisories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilitySummary {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_count: usize,
    pub vulnerable_packages: Vec<String>,
    /// Requirements whose specifier could install an affected version (not counted above).
    #[serde(default)]
    pub unresolved_range_hits: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PythonSecurityAnalysis {
    pub has_setup_script: bool,
    pub has_install_script: bool,
    pub has_post_install: bool,
    pub suspicious_imports: Vec<SuspiciousImport>,
    pub network_access_patterns: Vec<NetworkAccessPattern>,
    pub file_system_access: Vec<FileSystemAccess>,
    pub process_execution: Vec<ProcessExecution>,
    pub obfuscation_detected: bool,
    pub crypto_mining_indicators: bool,
    pub data_exfiltration_risk: bool,
    pub backdoor_indicators: Vec<BackdoorIndicator>,
    pub supply_chain_risk_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspiciousImport {
    pub module_name: String,
    pub risk_level: String,
    pub reason: String,
    pub found_in: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkAccessPattern {
    pub url: String,
    pub protocol: String,
    pub is_suspicious: bool,
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
pub struct BackdoorIndicator {
    pub indicator_type: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaliciousPackageIndicators {
    pub typosquatting_risk: TyposquattingAnalysis,
    pub dependency_confusion_risk: bool,
    pub known_malicious_patterns: Vec<MaliciousPattern>,
    pub suspicious_maintainer_activity: bool,
    pub code_injection_patterns: Vec<CodeInjectionPattern>,
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
    pub suspicious_name_patterns: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SimilarPackage {
    pub name: String,
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PythonFileAnalysis {
    pub file_path: String,
    pub file_type: String,
    pub size: u64,
    pub suspicious_content: Vec<String>,
    pub imports: Vec<String>,
    pub obfuscation_score: f32,
    /// The file's content was read and scanned (false for files past the scan limits).
    #[serde(default)]
    pub source_scanned: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetupAnalysis {
    pub setup_type: SetupType,
    pub setup_commands: Vec<SetupCommand>,
    pub custom_commands: HashMap<String, String>,
    pub dangerous_operations: Vec<DangerousOperation>,
    pub external_downloads: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SetupType {
    SetupPy,
    PyProjectToml,
    SetupCfg,
    Mixed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetupCommand {
    pub command_name: String,
    pub command_class: String,
    pub is_suspicious: bool,
    pub risk_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DangerousOperation {
    pub operation: String,
    pub location: String,
    pub risk_reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerAnalysis {
    pub maintainers: Vec<MaintainerInfo>,
    pub upload_history: Vec<UploadEvent>,
    pub suspicious_activity: Vec<String>,
    pub trust_score: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintainerInfo {
    pub name: String,
    pub email: Option<String>,
    pub first_upload: Option<String>,
    pub package_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadEvent {
    pub version: String,
    pub upload_date: Option<String>,
    pub uploader: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageQualityMetrics {
    pub has_readme: bool,
    pub has_changelog: bool,
    pub has_tests: bool,
    pub has_ci_config: bool,
    pub has_type_hints: bool,
    pub documentation_score: f32,
    pub code_quality_score: f32,
    pub overall_quality_score: f32,
}

fn is_manifest(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let name = parts[parts.len() - 1];
    if parts.len() == 2 && parts[0].ends_with(".dist-info") && name == "METADATA" {
        return true;
    }
    parts.len() <= 2
        && matches!(
            name,
            "setup.py"
                | "setup.cfg"
                | "pyproject.toml"
                | "PKG-INFO"
                | "requirements.txt"
                | "poetry.lock"
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
}

const MAX_FINDINGS: usize = 2000;

/// Main entry point for Python package analysis.
///
/// `path` is a wheel, an sdist or any zip or tar archive (detected by content,
/// not by extension), a directory, a `setup.py` / `pyproject.toml` /
/// `setup.cfg` (its directory), or a dependency list (`requirements.txt`,
/// `poetry.lock`). Registry names are not supported: nothing is downloaded.
pub fn analyze_python_package(path: &Path) -> Result<PythonPackageAnalysis> {
    if path.is_dir() {
        return analyze_python_directory(path);
    }
    if !path.is_file() {
        anyhow::bail!("Path must be either a Python package file or a directory");
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let lower = file_name.to_ascii_lowercase();
    if matches!(lower.as_str(), "setup.py" | "setup.cfg" | "pyproject.toml") {
        let directory = path
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        return analyze_python_directory(directory);
    }
    if lower == "poetry.lock" {
        let text = package_scan::read_dependency_list(path)?;
        return analyze_poetry_lock(&text);
    }
    if lower.starts_with("requirements") && lower.ends_with(".txt") {
        let text = package_scan::read_dependency_list(path)?;
        return analyze_requirements_text(&text, &file_name);
    }
    match package_scan::sniff(path)? {
        Some(kind @ (ContainerKind::TarGz | ContainerKind::Tar | ContainerKind::Zip)) => {
            let loaded = package_scan::load(path, kind, &SELECTOR)?;
            let label = if kind == ContainerKind::Zip { "zip" } else { "sdist" };
            analyze_loaded(&loaded, label)
        }
        _ => anyhow::bail!(
            "Unsupported file type: not a wheel, zip, tar or gzip archive, requirements.txt or poetry.lock. Pass a .whl, .tar.gz, .tgz or .zip archive, a source directory, or a dependency list."
        ),
    }
}

/// Analyze a Python directory
fn analyze_python_directory(dir_path: &Path) -> Result<PythonPackageAnalysis> {
    let has_metadata = ["setup.py", "setup.cfg", "pyproject.toml"]
        .iter()
        .any(|name| dir_path.join(name).is_file());
    if !has_metadata {
        if dir_path.join("poetry.lock").is_file() {
            let text = package_scan::read_dependency_list(&dir_path.join("poetry.lock"))?;
            return analyze_poetry_lock(&text);
        }
        if dir_path.join("requirements.txt").is_file() {
            let text = package_scan::read_dependency_list(&dir_path.join("requirements.txt"))?;
            return analyze_requirements_text(&text, "requirements.txt");
        }
        anyhow::bail!(
            "No setup.py, setup.cfg, pyproject.toml, requirements.txt or poetry.lock found in {}. Pass the package directory, a wheel or sdist, or a requirements file.",
            dir_path.display()
        );
    }
    let loaded = package_scan::load(dir_path, ContainerKind::Directory, &SELECTOR)?;
    analyze_loaded(&loaded, "directory")
}

/// The directory prefix the package metadata lives in: `""` or `top`.
fn sdist_root(loaded: &LoadedPackage) -> Option<String> {
    let names = ["setup.py", "pyproject.toml", "setup.cfg", "PKG-INFO"];
    // When every file sits under one top-level directory, that is the root.
    let mut tops = loaded
        .files
        .iter()
        .map(|f| f.path.split_once('/').map(|(top, _)| top));
    let common_top = match tops.next() {
        Some(Some(first)) if tops.all(|t| t == Some(first)) => Some(first.to_string()),
        _ => None,
    };
    let has = |root: &str| {
        names.iter().any(|name| {
            let path = if root.is_empty() {
                (*name).to_string()
            } else {
                format!("{root}/{name}")
            };
            loaded.file(&path).is_some_and(|f| f.content.is_some())
        })
    };
    if let Some(top) = &common_top {
        if has(top) {
            return Some(top.clone());
        }
    }
    if has("") {
        return Some(String::new());
    }
    let mut candidates: Vec<String> = loaded
        .files
        .iter()
        .filter_map(|f| {
            let parts: Vec<&str> = f.path.split('/').collect();
            (parts.len() == 2 && names.contains(&parts[1])).then(|| parts[0].to_string())
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next()
}

fn analyze_loaded(loaded: &LoadedPackage, kind: &str) -> Result<PythonPackageAnalysis> {
    let mut files = Vec::with_capacity(loaded.files.len());
    let mut scan = SourceScan::default();
    for file in &loaded.files {
        let mut analysis = PythonFileAnalysis {
            file_path: file.path.clone(),
            file_type: detect_python_file_type(&file.path),
            size: file.size,
            suspicious_content: vec![],
            imports: vec![],
            obfuscation_score: 0.0,
            source_scanned: false,
        };
        if let (Some(lang), Some(bytes)) = (language_of(&file.path), file.content.as_deref()) {
            let result = scan_source(lang, &file.path, bytes);
            analysis.source_scanned = true;
            analysis.obfuscation_score = result.obfuscation_score;
            analysis.imports = result.imports;
            analysis.suspicious_content = result
                .findings
                .iter()
                .map(|f| format!("line {}: {}", f.line, f.rule))
                .collect();
            for (url, line) in result.suspicious_urls {
                scan.urls.push((url, file.path.clone(), line));
            }
            if scan.findings.len() < MAX_FINDINGS {
                scan.findings.extend(result.findings);
            }
        }
        files.push(analysis);
    }
    scan.findings.truncate(MAX_FINDINGS);
    sort_findings(&mut scan.findings);

    // A wheel: <name>-<version>.dist-info/METADATA at the top level.
    let wheel_metadata = loaded
        .files
        .iter()
        .filter(|f| {
            let parts: Vec<&str> = f.path.split('/').collect();
            parts.len() == 2 && parts[0].ends_with(".dist-info") && parts[1] == "METADATA"
        })
        .map(|f| f.path.clone())
        .min();
    if let Some(path) = wheel_metadata {
        let metadata = loaded
            .text(&path)
            .context("METADATA was not read (larger than the manifest limit)")?;
        let mut input = InputInfo::from_loaded(
            if kind == "zip" { "wheel" } else { kind },
            loaded,
            Some(&path),
        );
        let other_dist_infos: std::collections::BTreeSet<String> = loaded
            .files
            .iter()
            .filter_map(|f| f.path.split_once('/'))
            .filter(|(dir, name)| dir.ends_with(".dist-info") && *name == "METADATA")
            .map(|(dir, _)| dir.to_string())
            .filter(|dir| !path.starts_with(&format!("{dir}/")))
            .collect();
        if !other_dist_infos.is_empty() {
            let list = other_dist_infos.into_iter().collect::<Vec<_>>().join(", ");
            input.notes.push(format!(
                "The wheel holds more than one .dist-info directory (also {list}); pip rejects such wheels. Analysed {path}."
            ));
            scan.findings.push(SourceFinding {
                rule: "Several .dist-info directories".to_string(),
                category: "package-structure".to_string(),
                severity: "High".to_string(),
                file: path.clone(),
                line: 1,
                evidence: format!(
                    "also present: {}",
                    list.chars().take(120).collect::<String>()
                ),
            });
            sort_findings(&mut scan.findings);
        }
        return analyze_package_with_metadata(&metadata, files, scan, input);
    }

    let root = sdist_root(loaded).context(
        "No package metadata found at the root of the archive (expected setup.py, setup.cfg, pyproject.toml or PKG-INFO next to the top-level directory, or <name>.dist-info/METADATA for a wheel)",
    )?;
    let at = |name: &str| {
        let path = if root.is_empty() {
            name.to_string()
        } else {
            format!("{root}/{name}")
        };
        loaded.text(&path).map(|text| (path, text))
    };
    let setup_py = at("setup.py");
    let setup_cfg = at("setup.cfg");
    let pyproject = at("pyproject.toml");
    let pkg_info = at("PKG-INFO");
    let manifest = setup_py
        .as_ref()
        .or(pyproject.as_ref())
        .or(setup_cfg.as_ref())
        .or(pkg_info.as_ref())
        .map(|(path, _)| path.clone());
    let lock = at("poetry.lock").map(|(_, text)| parse_poetry_lock(&text));
    let input = InputInfo::from_loaded(kind, loaded, manifest.as_deref());
    let format = if kind == "directory" {
        PackageFormat::Directory
    } else {
        PackageFormat::SourceDistribution
    };
    analyze_package_with_files(
        setup_py.map(|(_, t)| t),
        setup_cfg.map(|(_, t)| t),
        pyproject.map(|(_, t)| t),
        pkg_info.map(|(_, t)| t),
        files,
        format,
        scan,
        lock.as_ref(),
        input,
    )
}

/// Analyze package with metadata content (for wheel packages)
fn analyze_package_with_metadata(
    metadata: &str,
    files: Vec<PythonFileAnalysis>,
    scan: SourceScan,
    input: InputInfo,
) -> Result<PythonPackageAnalysis> {
    let package_info = parse_wheel_metadata(metadata)?;
    let mut dependencies = analyze_dependencies_from_metadata(metadata)?;
    finish_dependencies(&mut dependencies, &package_info, None);
    let setup_analysis = SetupAnalysis {
        setup_type: SetupType::PyProjectToml,
        setup_commands: vec![],
        custom_commands: HashMap::new(),
        dangerous_operations: vec![],
        external_downloads: vec![],
    };

    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &files, &setup_analysis, &scan)?;
    let malicious_indicators = detect_malicious_indicators(
        &package_info,
        &dependencies,
        &security_analysis,
        &scan.findings,
        true,
    )?;
    let maintainer_analysis = analyze_maintainers(&package_info)?;
    let quality_metrics = calculate_quality_metrics(&files)?;

    Ok(PythonPackageAnalysis {
        package_info,
        dependencies,
        security_analysis,
        malicious_indicators,
        files_analysis: files,
        setup_analysis,
        maintainer_analysis,
        quality_metrics,
        source_findings: scan.findings,
        input,
    })
}

/// Analyze package with various setup files
#[allow(clippy::too_many_arguments)]
fn analyze_package_with_files(
    setup_py: Option<String>,
    setup_cfg: Option<String>,
    pyproject_toml: Option<String>,
    pkg_info: Option<String>,
    files: Vec<PythonFileAnalysis>,
    format: PackageFormat,
    scan: SourceScan,
    lock: Option<&ParsedLock>,
    input: InputInfo,
) -> Result<PythonPackageAnalysis> {
    // Extract package info from available sources
    let mut package_info = if let Some(ref content) = pyproject_toml {
        parse_pyproject_toml(content)?
    } else if let Some(ref content) = setup_py {
        parse_setup_py(content)?
    } else if let Some(ref content) = setup_cfg {
        parse_setup_cfg(content)?
    } else if let Some(ref content) = pkg_info {
        parse_pkg_info(content)?
    } else {
        anyhow::bail!("No package metadata found")
    };
    package_info.package_format = format;
    // A pyproject.toml without a [project] name (setuptools via setup.py) falls back to setup.py.
    if package_info.name.is_empty() {
        if let Some(ref content) = setup_py {
            let fallback = parse_setup_py(content)?;
            if !fallback.name.is_empty() {
                package_info.name = fallback.name;
                if package_info.version.is_empty() {
                    package_info.version = fallback.version;
                }
            }
        }
    }

    // Analyze dependencies
    let mut dependencies = analyze_dependencies(&setup_py, &setup_cfg, &pyproject_toml, lock)?;
    finish_dependencies(&mut dependencies, &package_info, lock);

    // Analyze setup scripts
    let setup_analysis = analyze_setup_scripts(&setup_py, &setup_cfg, &pyproject_toml)?;

    // Perform security analysis
    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &files, &setup_analysis, &scan)?;

    // Detect malicious indicators
    let malicious_indicators = detect_malicious_indicators(
        &package_info,
        &dependencies,
        &security_analysis,
        &scan.findings,
        true,
    )?;

    // Analyze maintainers
    let maintainer_analysis = analyze_maintainers(&package_info)?;

    // Calculate quality metrics
    let quality_metrics = calculate_quality_metrics(&files)?;

    Ok(PythonPackageAnalysis {
        package_info,
        dependencies,
        security_analysis,
        malicious_indicators,
        files_analysis: files,
        setup_analysis,
        maintainer_analysis,
        quality_metrics,
        source_findings: scan.findings,
        input,
    })
}

/// A lock file read as a dependency list.
struct ParsedLock {
    packages: Vec<LockedPackage>,
    /// Version of each package by normalised name.
    by_name: HashMap<String, String>,
}

const MAX_LOCKED: usize = 20_000;

fn parse_poetry_lock(text: &str) -> ParsedLock {
    let mut packages = Vec::new();
    let mut by_name = HashMap::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut dev = false;
    let mut in_package = false;
    let mut flush = |name: &mut Option<String>, version: &mut Option<String>, dev: &mut bool| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            if packages.len() < MAX_LOCKED {
                by_name.insert(normalize_name(&n), v.clone());
                packages.push(LockedPackage {
                    vulnerabilities: check_package_vulnerabilities(&n, &v),
                    name: n,
                    version: v,
                    dev: *dev,
                });
            }
        }
        *dev = false;
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut dev);
            in_package = true;
        } else if line.starts_with('[') {
            // [package.dependencies] and friends belong to the current package.
            if !line.starts_with("[package") {
                in_package = false;
            }
        } else if in_package {
            if let Some(rest) = line.strip_prefix("name = ") {
                if name.is_none() {
                    name = Some(rest.trim_matches('"').to_string());
                }
            } else if let Some(rest) = line.strip_prefix("version = ") {
                if version.is_none() {
                    version = Some(rest.trim_matches('"').to_string());
                }
            } else if line.starts_with("category = \"dev\"") {
                dev = true;
            } else if let Some(rest) = line.strip_prefix("groups = ") {
                dev = !rest.contains("\"main\"");
            }
        }
    }
    flush(&mut name, &mut version, &mut dev);
    ParsedLock { packages, by_name }
}

fn dependency_details(
    name: &str,
    raw: &str,
    specifier: &str,
    resolved: Option<&str>,
) -> DependencyDetails {
    let check = check_dependency_spec(name, specifier, resolved);
    DependencyDetails {
        version_spec: specifier.to_string(),
        is_pinned: matches!(classify_specifier(specifier), SpecKind::Pinned(_)),
        is_url: raw.starts_with("http") || raw.contains(" @ http"),
        is_git: raw.contains("git+"),
        vulnerabilities: check.vulnerabilities,
        deprecated: false,
        resolved_version: resolved.map(String::from),
        range_floor_advisories: check
            .range_floor_matches
            .into_iter()
            .map(|v| v.cve_id)
            .collect(),
    }
}

/// Fill in what depends on the whole dependency set: lock file entries, the
/// package's own advisories, the advisory-data provenance and the summary.
fn finish_dependencies(
    dependencies: &mut PythonDependencyAnalysis,
    package_info: &PackageInfo,
    lock: Option<&ParsedLock>,
) {
    dependencies.package_vulnerabilities =
        check_package_vulnerabilities(&package_info.name, &package_info.version);
    dependencies.vulnerability_db = advisory_data_info();
    if let Some(lock) = lock {
        dependencies.locked_packages = lock.packages.clone();
    }
    let mut summary = calculate_vulnerability_summary(&dependencies.install_requires);
    for (name, details) in dependencies
        .setup_requires
        .iter()
        .chain(dependencies.tests_require.iter())
    {
        tally_dependency(&mut summary, name, details);
    }
    let direct: std::collections::HashSet<String> = dependencies
        .install_requires
        .keys()
        .chain(dependencies.setup_requires.keys())
        .chain(dependencies.tests_require.keys())
        .map(|n| normalize_name(n))
        .collect();
    for package in &dependencies.locked_packages {
        if !direct.contains(&normalize_name(&package.name)) && !package.vulnerabilities.is_empty() {
            tally_vulns(
                &mut summary,
                &format!("{}=={}", package.name, package.version),
                &package.vulnerabilities,
            );
        }
    }
    summary.vulnerable_packages.sort();
    summary.unresolved_range_hits.sort();
    summary.unresolved_range_hits.dedup();
    dependencies.vulnerability_summary = summary;
}

fn tally_vulns(summary: &mut VulnerabilitySummary, name: &str, vulns: &[KnownVulnerability]) {
    if vulns.is_empty() {
        return;
    }
    summary.vulnerable_packages.push(name.to_string());
    summary.total_count += vulns.len();
    for vuln in vulns {
        match vuln.severity {
            VulnerabilitySeverity::Critical => summary.critical_count += 1,
            VulnerabilitySeverity::High => summary.high_count += 1,
            VulnerabilitySeverity::Medium => summary.medium_count += 1,
            VulnerabilitySeverity::Low => summary.low_count += 1,
            VulnerabilitySeverity::None => {}
        }
    }
}

fn tally_dependency(summary: &mut VulnerabilitySummary, name: &str, details: &DependencyDetails) {
    tally_vulns(summary, name, &details.vulnerabilities);
    if !details.range_floor_advisories.is_empty() {
        summary.unresolved_range_hits.push(name.to_string());
    }
}

/// A poetry.lock as the only input: a dependency list, no source to scan.
fn analyze_poetry_lock(text: &str) -> Result<PythonPackageAnalysis> {
    let lock = parse_poetry_lock(text);
    if lock.packages.is_empty() {
        anyhow::bail!(
            "poetry.lock has no [[package]] entries; it is not a readable poetry lock file"
        );
    }
    let mut install_requires = HashMap::new();
    let mut tests_require = HashMap::new();
    for package in &lock.packages {
        let spec = format!("=={}", package.version);
        let details = dependency_details(&package.name, &package.name, &spec, None);
        if package.dev {
            tests_require.insert(package.name.clone(), details);
        } else {
            install_requires.insert(package.name.clone(), details);
        }
    }
    let input = InputInfo::dependency_list(
        "lockfile",
        "poetry.lock is a dependency list: no source files were scanned and the package name was not judged",
    );
    dependency_list_analysis(
        "(poetry.lock)",
        install_requires,
        tests_require,
        Some(&lock),
        input,
    )
}

/// A requirements file as the only input.
fn analyze_requirements_text(text: &str, file_name: &str) -> Result<PythonPackageAnalysis> {
    let mut install_requires = HashMap::new();
    let mut joined = String::new();
    let mut capped = false;
    for raw in text.lines() {
        if install_requires.len() >= package_scan::MAX_DEPENDENCY_ENTRIES {
            capped = true;
            break;
        }
        let line = raw.trim_end();
        if let Some(stripped) = line.strip_suffix('\\') {
            joined.push_str(stripped);
            joined.push(' ');
            continue;
        }
        joined.push_str(line);
        let entry = std::mem::take(&mut joined);
        let entry = entry.split(" #").next().unwrap_or("").trim().to_string();
        if entry.is_empty() || entry.starts_with('#') || entry.starts_with('-') {
            continue;
        }
        // Drop per-requirement options such as `--hash=sha256:...`.
        let requirement = entry.split(" --").next().unwrap_or("").trim();
        if requirement.is_empty() {
            continue;
        }
        let (name, specifier) = parse_dependency_spec(requirement);
        if name.is_empty() {
            continue;
        }
        let details = dependency_details(&name, requirement, &specifier, None);
        install_requires.insert(name, details);
    }
    if install_requires.is_empty() {
        anyhow::bail!("{file_name} lists no requirements");
    }
    let mut input = InputInfo::dependency_list(
        "requirements",
        &format!("{file_name} is a dependency list: no source files were scanned and the package name was not judged"),
    );
    if capped {
        input.notes.push(format!(
            "Only the first {} requirements were analysed; the rest of {file_name} was not read.",
            package_scan::MAX_DEPENDENCY_ENTRIES
        ));
    }
    dependency_list_analysis(
        &format!("({file_name})"),
        install_requires,
        HashMap::new(),
        None,
        input,
    )
}

fn dependency_list_analysis(
    label: &str,
    install_requires: HashMap<String, DependencyDetails>,
    tests_require: HashMap<String, DependencyDetails>,
    lock: Option<&ParsedLock>,
    input: InputInfo,
) -> Result<PythonPackageAnalysis> {
    let package_info = PackageInfo {
        name: label.to_string(),
        version: String::new(),
        description: None,
        author: None,
        author_email: None,
        maintainer: None,
        maintainer_email: None,
        license: None,
        url: None,
        project_urls: HashMap::new(),
        keywords: vec![],
        classifiers: vec![],
        python_requires: None,
        package_format: PackageFormat::Directory,
    };
    let dependency_count = install_requires.len() + tests_require.len();
    let mut dependencies = PythonDependencyAnalysis {
        install_requires,
        extras_require: HashMap::new(),
        setup_requires: HashMap::new(),
        tests_require,
        dependency_count,
        vulnerability_summary: VulnerabilitySummary {
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            total_count: 0,
            vulnerable_packages: vec![],
            unresolved_range_hits: vec![],
        },
        locked_packages: vec![],
        package_vulnerabilities: vec![],
        vulnerability_db: AdvisoryDataInfo::default(),
    };
    finish_dependencies(&mut dependencies, &package_info, lock);
    let setup_analysis = SetupAnalysis {
        setup_type: SetupType::PyProjectToml,
        setup_commands: vec![],
        custom_commands: HashMap::new(),
        dangerous_operations: vec![],
        external_downloads: vec![],
    };
    let scan = SourceScan::default();
    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &[], &setup_analysis, &scan)?;
    let malicious_indicators =
        detect_malicious_indicators(&package_info, &dependencies, &security_analysis, &[], false)?;
    let maintainer_analysis = analyze_maintainers(&package_info)?;
    let quality_metrics = calculate_quality_metrics(&[])?;
    Ok(PythonPackageAnalysis {
        package_info,
        dependencies,
        security_analysis,
        malicious_indicators,
        files_analysis: vec![],
        setup_analysis,
        maintainer_analysis,
        quality_metrics,
        source_findings: vec![],
        input,
    })
}

/// The header block of a METADATA / PKG-INFO file (up to the first blank line).
fn metadata_headers(metadata: &str) -> &str {
    let end = metadata
        .find("\n\n")
        .into_iter()
        .chain(metadata.find("\r\n\r\n"))
        .min()
        .unwrap_or(metadata.len());
    &metadata[..end]
}

/// Parse wheel METADATA file
fn parse_wheel_metadata(metadata: &str) -> Result<PackageInfo> {
    let mut name = String::new();
    let mut version = String::new();
    let mut description = None;
    let mut author = None;
    let mut author_email = None;
    let mut maintainer = None;
    let mut maintainer_email = None;
    let mut license = None;
    let mut url = None;
    let mut keywords = vec![];
    let mut classifiers = vec![];
    let mut python_requires = None;
    let mut project_urls = HashMap::new();

    // Only the header block: a long description after the blank line may contain "Name: ...".
    for line in metadata_headers(metadata).lines() {
        if let Some((key, value)) = line.split_once(": ") {
            match key {
                "Name" => name = value.to_string(),
                "Version" => version = value.to_string(),
                "Summary" => description = Some(value.to_string()),
                "Author" => author = Some(value.to_string()),
                "Author-email" => author_email = Some(value.to_string()),
                "Maintainer" => maintainer = Some(value.to_string()),
                "Maintainer-email" => maintainer_email = Some(value.to_string()),
                "License" => license = Some(value.to_string()),
                "Home-page" => url = Some(value.to_string()),
                "Keywords" => keywords = value.split(',').map(|s| s.trim().to_string()).collect(),
                "Classifier" => classifiers.push(value.to_string()),
                "Requires-Python" => python_requires = Some(value.to_string()),
                "Project-URL" => {
                    if let Some((url_name, url_value)) = value.split_once(", ") {
                        project_urls.insert(url_name.to_string(), url_value.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    Ok(PackageInfo {
        name,
        version,
        description,
        author,
        author_email,
        maintainer,
        maintainer_email,
        license,
        url,
        project_urls,
        keywords,
        classifiers,
        python_requires,
        package_format: PackageFormat::Wheel,
    })
}

/// Parse pyproject.toml
fn parse_pyproject_toml(content: &str) -> Result<PackageInfo> {
    // Simple parsing - in production, use a TOML parser
    let mut name = String::new();
    let mut version = String::new();
    let mut description = None;
    let author = None;
    let license = None;

    for line in content.lines() {
        if line.contains("name =") {
            if let Some(value) = extract_quoted_value(line) {
                name = value;
            }
        } else if line.contains("version =") {
            if let Some(value) = extract_quoted_value(line) {
                version = value;
            }
        } else if line.contains("description =") {
            if let Some(value) = extract_quoted_value(line) {
                description = Some(value);
            }
        }
    }

    Ok(PackageInfo {
        name,
        version,
        description,
        author,
        author_email: None,
        maintainer: None,
        maintainer_email: None,
        license,
        url: None,
        project_urls: HashMap::new(),
        keywords: vec![],
        classifiers: vec![],
        python_requires: None,
        package_format: PackageFormat::Directory,
    })
}

/// Parse setup.py
fn parse_setup_py(content: &str) -> Result<PackageInfo> {
    // Extract package info from setup() call
    let mut name = String::new();
    let mut version = String::new();
    let mut description = None;
    let mut author = None;
    let mut author_email = None;
    let mut license = None;
    let mut url = None;

    // Simple regex-based extraction
    if let Some(cap) = regex::Regex::new(r#"name\s*=\s*["']([^"']+)["']"#)?.captures(content) {
        name = cap[1].to_string();
    }
    if let Some(cap) = regex::Regex::new(r#"version\s*=\s*["']([^"']+)["']"#)?.captures(content) {
        version = cap[1].to_string();
    }
    if let Some(cap) = regex::Regex::new(r#"description\s*=\s*["']([^"']+)["']"#)?.captures(content)
    {
        description = Some(cap[1].to_string());
    }
    if let Some(cap) = regex::Regex::new(r#"author\s*=\s*["']([^"']+)["']"#)?.captures(content) {
        author = Some(cap[1].to_string());
    }
    if let Some(cap) =
        regex::Regex::new(r#"author_email\s*=\s*["']([^"']+)["']"#)?.captures(content)
    {
        author_email = Some(cap[1].to_string());
    }
    if let Some(cap) = regex::Regex::new(r#"license\s*=\s*["']([^"']+)["']"#)?.captures(content) {
        license = Some(cap[1].to_string());
    }
    if let Some(cap) = regex::Regex::new(r#"url\s*=\s*["']([^"']+)["']"#)?.captures(content) {
        url = Some(cap[1].to_string());
    }

    // Extract keywords - handle list format
    let mut keywords = vec![];
    if let Some(keywords_list) = extract_list_from_setup_py(content, "keywords") {
        keywords = keywords_list;
    }

    Ok(PackageInfo {
        name,
        version,
        description,
        author,
        author_email,
        maintainer: None,
        maintainer_email: None,
        license,
        url,
        project_urls: HashMap::new(),
        keywords,
        classifiers: vec![],
        python_requires: None,
        package_format: PackageFormat::SourceDistribution,
    })
}

/// Parse setup.cfg
fn parse_setup_cfg(content: &str) -> Result<PackageInfo> {
    // Simple INI-style parsing
    let mut name = String::new();
    let mut version = String::new();
    let mut description = None;
    let mut author = None;
    let mut author_email = None;
    let mut license = None;
    let mut url = None;

    let mut in_metadata = false;

    for line in content.lines() {
        if line.trim() == "[metadata]" {
            in_metadata = true;
            continue;
        }
        if line.starts_with('[') {
            in_metadata = false;
        }

        if in_metadata {
            if let Some((key, value)) = line.split_once(" = ") {
                match key.trim() {
                    "name" => name = value.trim().to_string(),
                    "version" => version = value.trim().to_string(),
                    "description" => description = Some(value.trim().to_string()),
                    "author" => author = Some(value.trim().to_string()),
                    "author_email" => author_email = Some(value.trim().to_string()),
                    "license" => license = Some(value.trim().to_string()),
                    "url" => url = Some(value.trim().to_string()),
                    _ => {}
                }
            }
        }
    }

    Ok(PackageInfo {
        name,
        version,
        description,
        author,
        author_email,
        maintainer: None,
        maintainer_email: None,
        license,
        url,
        project_urls: HashMap::new(),
        keywords: vec![],
        classifiers: vec![],
        python_requires: None,
        package_format: PackageFormat::SourceDistribution,
    })
}

/// Parse PKG-INFO
fn parse_pkg_info(content: &str) -> Result<PackageInfo> {
    parse_wheel_metadata(content) // PKG-INFO has similar format to METADATA
}

/// Analyze dependencies from metadata
fn analyze_dependencies_from_metadata(metadata: &str) -> Result<PythonDependencyAnalysis> {
    let mut install_requires = HashMap::new();

    // Parse Requires-Dist entries
    for line in metadata_headers(metadata).lines() {
        if line.starts_with("Requires-Dist: ") {
            let dep_spec = line.trim_start_matches("Requires-Dist: ");

            // Skip dependencies with environment markers for extras
            if dep_spec.contains("; extra ==") || dep_spec.contains(";extra==") {
                continue;
            }

            let (name, version_spec) = parse_dependency_spec(dep_spec);
            if name.is_empty() {
                continue;
            }
            let details = dependency_details(&name, dep_spec, &version_spec, None);
            install_requires.insert(name, details);
        }
    }

    let dependency_count = install_requires.len();
    let vulnerability_summary = calculate_vulnerability_summary(&install_requires);

    Ok(PythonDependencyAnalysis {
        install_requires,
        extras_require: HashMap::new(),
        setup_requires: HashMap::new(),
        tests_require: HashMap::new(),
        dependency_count,
        vulnerability_summary,
        locked_packages: vec![],
        package_vulnerabilities: vec![],
        vulnerability_db: AdvisoryDataInfo::default(),
    })
}

/// Analyze dependencies from various setup files
fn analyze_dependencies(
    setup_py: &Option<String>,
    setup_cfg: &Option<String>,
    pyproject_toml: &Option<String>,
    lock: Option<&ParsedLock>,
) -> Result<PythonDependencyAnalysis> {
    let mut install_requires = HashMap::new();
    let mut extras_require = HashMap::new();
    let setup_requires = HashMap::new();
    let tests_require = HashMap::new();

    // Extract from setup.py
    if let Some(content) = setup_py {
        extract_setup_py_dependencies(content, &mut install_requires, &mut extras_require)?;
    }

    // Extract from setup.cfg
    if let Some(content) = setup_cfg {
        extract_setup_cfg_dependencies(content, &mut install_requires)?;
    }

    // Extract from pyproject.toml
    if let Some(content) = pyproject_toml {
        extract_pyproject_dependencies(content, &mut install_requires)?;
    }

    // A lock file settles which version a requirement resolves to.
    if let Some(lock) = lock {
        for (name, details) in &mut install_requires {
            if let Some(version) = lock.by_name.get(&normalize_name(name)) {
                *details = dependency_details(
                    name,
                    &details.version_spec,
                    &details.version_spec.clone(),
                    Some(version),
                );
            }
        }
    }

    let dependency_count = install_requires.len()
        + extras_require
            .values()
            .map(std::collections::HashMap::len)
            .sum::<usize>();

    let vulnerability_summary = calculate_vulnerability_summary(&install_requires);

    Ok(PythonDependencyAnalysis {
        install_requires,
        extras_require,
        setup_requires,
        tests_require,
        dependency_count,
        vulnerability_summary,
        locked_packages: vec![],
        package_vulnerabilities: vec![],
        vulnerability_db: AdvisoryDataInfo::default(),
    })
}

/// Extract dependencies from setup.py
fn extract_setup_py_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
    _extras_require: &mut HashMap<String, HashMap<String, DependencyDetails>>,
) -> Result<()> {
    // Extract install_requires
    if let Some(deps) = extract_list_from_setup_py(content, "install_requires") {
        for dep in deps {
            let (name, version_spec) = parse_dependency_spec(&dep);
            if name.is_empty() {
                continue;
            }
            let details = dependency_details(&name, &dep, &version_spec, None);
            install_requires.insert(name, details);
        }
    }

    Ok(())
}

/// Extract a list from setup.py
fn extract_list_from_setup_py(content: &str, field_name: &str) -> Option<Vec<String>> {
    // Simple regex to extract list contents
    let pattern = format!(r"{field_name}\s*=\s*\[([\s\S]*?)\]");
    if let Ok(re) = regex::Regex::new(&pattern) {
        if let Some(cap) = re.captures(content) {
            let list_content = &cap[1];
            return Some(
                list_content
                    .split(',')
                    .filter_map(|s| {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.trim_matches(|c| c == '"' || c == '\'').to_string())
                        }
                    })
                    .collect(),
            );
        }
    }
    None
}

/// Extract dependencies from setup.cfg
fn extract_setup_cfg_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
) -> Result<()> {
    let mut in_options = false;
    let mut in_install_requires = false;

    for line in content.lines() {
        if line.trim() == "[options]" {
            in_options = true;
            continue;
        }
        if line.starts_with('[') {
            in_options = false;
            in_install_requires = false;
        }

        if in_options && line.trim() == "install_requires =" {
            in_install_requires = true;
            continue;
        }

        if in_install_requires && !line.starts_with(' ') && !line.starts_with('\t') {
            in_install_requires = false;
        }

        if in_install_requires && !line.trim().is_empty() {
            let dep = line.trim();
            let (name, version_spec) = parse_dependency_spec(dep);
            if name.is_empty() {
                continue;
            }
            let details = dependency_details(&name, dep, &version_spec, None);
            install_requires.insert(name, details);
        }
    }

    Ok(())
}

/// Extract dependencies from pyproject.toml
fn extract_pyproject_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
) -> Result<()> {
    // Simple extraction - in production use a TOML parser
    let mut in_dependencies = false;
    let mut in_project_deps = false;
    let mut in_deps_list = false;

    for line in content.lines() {
        // Handle [tool.poetry.dependencies] section (key-value format)
        if line.contains("[tool.poetry.dependencies]") {
            in_dependencies = true;
            in_project_deps = false;
            in_deps_list = false;
            continue;
        }

        // Handle [project] section
        if line.contains("[project]") {
            in_project_deps = true;
            in_dependencies = false;
            in_deps_list = false;
            continue;
        }

        // Handle dependencies list in [project] section
        if in_project_deps && line.trim() == "dependencies = [" {
            in_deps_list = true;
            continue;
        }

        // End of section
        if line.starts_with('[') {
            in_dependencies = false;
            in_project_deps = false;
            in_deps_list = false;
        }

        // End of dependencies list
        if in_deps_list && line.contains(']') {
            in_deps_list = false;
        }

        // Parse dependencies in [project] dependencies list format
        if in_deps_list && line.trim().starts_with('"') {
            let dep_spec = line.trim().trim_matches('"').trim_matches(',');
            let (name, version_spec) = parse_dependency_spec(dep_spec);
            if name.is_empty() {
                continue;
            }
            let details = dependency_details(&name, dep_spec, &version_spec, None);
            install_requires.insert(name, details);
        }
        // Parse dependencies in [tool.poetry.dependencies] format
        else if in_dependencies && line.contains('=') {
            if let Some((name, version)) = line.split_once('=') {
                let name = name.trim().trim_matches('"');
                if name == "python" {
                    continue; // Skip python version requirement
                }
                // Poetry: "^1.2" is a caret range; a bare "1.2.3" is exact.
                let raw_spec = version.trim().trim_matches('"');
                let specifier = poetry_specifier(raw_spec);
                let details = dependency_details(name, raw_spec, &specifier, None);
                install_requires.insert(name.to_string(), details);
            }
        }
    }

    Ok(())
}

/// Turn a Poetry version constraint into a PEP 440 specifier: `^1.2.3` and
/// `~1.2.3` become `>=1.2.3`, a bare `1.2.3` becomes `==1.2.3`, `*` stays `*`.
fn poetry_specifier(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() || raw == "*" {
        return "*".to_string();
    }
    if let Some(rest) = raw.strip_prefix('^').or_else(|| raw.strip_prefix('~')) {
        if raw.starts_with("~=") {
            return raw.to_string();
        }
        return format!(">={rest}");
    }
    if raw.starts_with(['=', '<', '>', '!']) || raw.contains(',') {
        return raw.replace(' ', "");
    }
    if raw.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return format!("=={raw}");
    }
    "*".to_string()
}

/// Parse a requirement into `(name, specifier)`.
///
/// Handles `name==1.0`, `name>=1.0,<2`, `name[extra]>=1`, the parenthesised
/// METADATA form `name (==1.0)`, environment markers after `;` and direct
/// references `name @ url`. The specifier is `*` when there is none.
fn parse_dependency_spec(spec: &str) -> (String, String) {
    let spec = spec.split(';').next().unwrap_or("").trim();
    if let Some((name, _url)) = spec.split_once(" @ ") {
        return (strip_extras(name.trim()), "*".to_string());
    }
    let cleaned: String = spec.chars().filter(|c| !matches!(c, '(' | ')')).collect();
    let cleaned = strip_extras(cleaned.trim());
    match cleaned.find(['=', '<', '>', '!', '~']) {
        Some(index) => (
            cleaned[..index].trim().to_string(),
            cleaned[index..].replace(' ', ""),
        ),
        // `name 1.0` is not valid, but `name (1.0)` style leftovers keep the name only.
        None => (
            cleaned.split_whitespace().next().unwrap_or("").to_string(),
            "*".to_string(),
        ),
    }
}

fn strip_extras(spec: &str) -> String {
    match (spec.find('['), spec.find(']')) {
        (Some(start), Some(end)) if end > start => {
            format!("{}{}", &spec[..start], &spec[end + 1..])
        }
        _ => spec.to_string(),
    }
}

/// Calculate vulnerability summary
fn calculate_vulnerability_summary(
    dependencies: &HashMap<String, DependencyDetails>,
) -> VulnerabilitySummary {
    let mut summary = VulnerabilitySummary {
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        total_count: 0,
        vulnerable_packages: vec![],
        unresolved_range_hits: vec![],
    };
    let mut names: Vec<&String> = dependencies.keys().collect();
    names.sort();
    for name in names {
        tally_dependency(&mut summary, name, &dependencies[name]);
    }
    summary
}

/// Analyze setup scripts
fn analyze_setup_scripts(
    setup_py: &Option<String>,
    _setup_cfg: &Option<String>,
    _pyproject_toml: &Option<String>,
) -> Result<SetupAnalysis> {
    let mut setup_type = SetupType::PyProjectToml;
    let mut setup_commands = vec![];
    let mut custom_commands = HashMap::new();
    let mut dangerous_operations = vec![];
    let mut external_downloads = vec![];

    if let Some(content) = setup_py {
        setup_type = SetupType::SetupPy;

        // Check for custom commands
        if content.contains("cmdclass") {
            setup_commands.push(SetupCommand {
                command_name: "custom".to_string(),
                command_class: "Custom command detected".to_string(),
                is_suspicious: true,
                risk_reason: Some("Custom setup commands can execute arbitrary code".to_string()),
            });

            // Also add to custom_commands map
            custom_commands.insert(
                "cmdclass".to_string(),
                "Custom commands detected".to_string(),
            );
        }

        // Check for imports that indicate dangerous operations
        let dangerous_imports = [
            ("subprocess", "Process execution"),
            ("os.system", "System command execution"),
            ("urllib", "Network access"),
            ("requests", "HTTP requests"),
            ("socket", "Network socket access"),
            ("base64", "Base64 encoding/decoding"),
            ("exec", "Dynamic code execution"),
            ("eval", "Code evaluation"),
            ("compile", "Code compilation"),
            ("__import__", "Dynamic import"),
        ];

        for (import, reason) in &dangerous_imports {
            if content.contains(import) {
                dangerous_operations.push(DangerousOperation {
                    operation: import.to_string(),
                    location: "setup.py".to_string(),
                    risk_reason: reason.to_string(),
                });
            }
        }

        // Check for external downloads
        if content.contains("urlopen")
            || content.contains("requests.get")
            || content.contains("wget")
        {
            external_downloads.push("External download detected in setup.py".to_string());
        }
    }

    Ok(SetupAnalysis {
        setup_type,
        setup_commands,
        custom_commands,
        dangerous_operations,
        external_downloads,
    })
}

/// Perform security analysis
fn perform_security_analysis(
    package_info: &PackageInfo,
    dependencies: &PythonDependencyAnalysis,
    files: &[PythonFileAnalysis],
    setup_analysis: &SetupAnalysis,
    scan: &SourceScan,
) -> Result<PythonSecurityAnalysis> {
    let has_setup_script = matches!(setup_analysis.setup_type, SetupType::SetupPy);
    let has_install_script = !setup_analysis.setup_commands.is_empty();
    let has_post_install = setup_analysis
        .setup_commands
        .iter()
        .any(|cmd| cmd.command_name.contains("install"));

    let suspicious_imports = detect_suspicious_imports(files, setup_analysis);
    let mut network_access_patterns = detect_network_patterns(files, setup_analysis);
    // A URL mentioned in a source file is not evidence of exfiltration.
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
            found_in: format!("file:{file}:{line}"),
        });
    }
    let file_system_access = detect_filesystem_patterns(files, setup_analysis);
    let mut process_execution = detect_process_execution(files, setup_analysis);
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
            risk_level: finding.severity.clone(),
        });
    }

    // Check for obfuscation in files and setup script
    let mut obfuscation_detected = detect_obfuscation(files);
    if !obfuscation_detected && matches!(setup_analysis.setup_type, SetupType::SetupPy) {
        // Also check setup.py content if we have it
        for op in &setup_analysis.dangerous_operations {
            if op.operation == "base64"
                || op.operation == "exec"
                || op.operation == "eval"
                || op.operation == "__import__"
                || op.operation == "compile"
            {
                obfuscation_detected = true;
                break;
            }
        }
    }

    let crypto_mining_indicators = scan.findings.iter().any(|f| f.category == "cryptomining");
    let data_exfiltration_risk = detect_data_exfiltration(&script_network_patterns)
        || scan
            .findings
            .iter()
            .any(|f| f.category == "exfiltration" && f.severity != "Medium");
    let mut backdoor_indicators = detect_backdoor_indicators(files, &process_execution);
    for finding in scan
        .findings
        .iter()
        .filter(|f| f.category == "backdoor")
        .take(20)
    {
        backdoor_indicators.push(BackdoorIndicator {
            indicator_type: finding.rule.clone(),
            description: format!("{} at {}:{}", finding.rule, finding.file, finding.line),
            evidence: vec![finding.evidence.clone()],
            confidence: 0.9,
        });
    }

    let supply_chain_risk_score = calculate_supply_chain_risk(
        package_info,
        dependencies,
        setup_analysis,
        &script_network_patterns,
    );

    Ok(PythonSecurityAnalysis {
        has_setup_script,
        has_install_script,
        has_post_install,
        suspicious_imports,
        network_access_patterns,
        file_system_access,
        process_execution,
        obfuscation_detected,
        crypto_mining_indicators,
        data_exfiltration_risk,
        backdoor_indicators,
        supply_chain_risk_score,
    })
}

/// Detect suspicious imports
fn detect_suspicious_imports(
    _files: &[PythonFileAnalysis],
    setup_analysis: &SetupAnalysis,
) -> Vec<SuspiciousImport> {
    let mut imports = vec![];

    // Check setup.py dangerous operations
    for op in &setup_analysis.dangerous_operations {
        imports.push(SuspiciousImport {
            module_name: op.operation.clone(),
            risk_level: "High".to_string(),
            reason: op.risk_reason.clone(),
            found_in: op.location.clone(),
        });
    }

    imports
}

/// Detect network patterns
fn detect_network_patterns(
    _files: &[PythonFileAnalysis],
    setup_analysis: &SetupAnalysis,
) -> Vec<NetworkAccessPattern> {
    let mut patterns = vec![];

    // Check for external downloads in setup
    for download in &setup_analysis.external_downloads {
        patterns.push(NetworkAccessPattern {
            url: "unknown".to_string(),
            protocol: "http/https".to_string(),
            is_suspicious: true,
            found_in: download.clone(),
        });
    }

    patterns
}

/// Detect filesystem patterns
const fn detect_filesystem_patterns(
    _files: &[PythonFileAnalysis],
    _setup_analysis: &SetupAnalysis,
) -> Vec<FileSystemAccess> {
    vec![] // TODO: Implement
}

/// Detect process execution
fn detect_process_execution(
    _files: &[PythonFileAnalysis],
    setup_analysis: &SetupAnalysis,
) -> Vec<ProcessExecution> {
    let mut executions = vec![];

    // Check for process execution in setup
    for op in &setup_analysis.dangerous_operations {
        if op.operation.contains("subprocess") || op.operation.contains("os.system") {
            executions.push(ProcessExecution {
                command: op.operation.clone(),
                arguments: vec![],
                is_suspicious: true,
                risk_level: "High".to_string(),
            });
        }
    }

    executions
}

/// Detect obfuscation
fn detect_obfuscation(files: &[PythonFileAnalysis]) -> bool {
    // Check if any file has suspicious content suggesting obfuscation
    files.iter().any(|f| f.obfuscation_score > 0.5)
}

/// Detect obfuscation in setup content
fn detect_obfuscation_in_content(content: &str) -> bool {
    // Check for various obfuscation patterns
    let obfuscation_patterns = [
        r"base64\.b64decode",
        r"codecs\.decode.*hex",
        r"exec\s*\(",
        r"eval\s*\(",
        r"compile\s*\(",
        r"__import__",
        r"chr\s*\(\s*\d+\s*\)",
        r"\\x[0-9a-fA-F]{2}",
        r"lambda\s*:.*\(\s*\)",
    ];

    for pattern in &obfuscation_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(content) {
                return true;
            }
        }
    }

    // Check for string concatenation obfuscation (many single char strings)
    if let Ok(re) = regex::Regex::new(r"'[^']'\s*\+\s*'[^']'") {
        let matches = re.find_iter(content).count();
        if matches > 3 {
            return true;
        }
    }

    false
}

/// Detect data exfiltration
fn detect_data_exfiltration(network_patterns: &[NetworkAccessPattern]) -> bool {
    network_patterns.iter().any(|p| p.is_suspicious)
}

/// Detect backdoor indicators
fn detect_backdoor_indicators(
    _files: &[PythonFileAnalysis],
    process_execution: &[ProcessExecution],
) -> Vec<BackdoorIndicator> {
    let mut indicators = vec![];

    if !process_execution.is_empty() && process_execution.iter().any(|p| p.risk_level == "High") {
        indicators.push(BackdoorIndicator {
            indicator_type: "Process execution".to_string(),
            description: "Package executes external processes".to_string(),
            evidence: process_execution
                .iter()
                .map(|p| p.command.clone())
                .collect(),
            confidence: 0.7,
        });
    }

    indicators
}

/// Calculate supply chain risk
fn calculate_supply_chain_risk(
    _package_info: &PackageInfo,
    dependencies: &PythonDependencyAnalysis,
    setup_analysis: &SetupAnalysis,
    network_patterns: &[NetworkAccessPattern],
) -> f32 {
    let mut risk_score: f32 = 0.0;

    // Setup script risks
    if matches!(setup_analysis.setup_type, SetupType::SetupPy) {
        risk_score += 10.0;
    }
    if !setup_analysis.setup_commands.is_empty() {
        risk_score += 15.0;
    }
    if !setup_analysis.dangerous_operations.is_empty() {
        risk_score += 20.0;
    }
    if !setup_analysis.external_downloads.is_empty() {
        risk_score += 25.0;
    }

    // Dependency risks
    if dependencies.vulnerability_summary.critical_count > 0 {
        risk_score += 20.0;
    }
    if dependencies.vulnerability_summary.high_count > 0 {
        risk_score += 15.0;
    }

    // Network risks
    if !network_patterns.is_empty() {
        risk_score += 10.0;
    }

    risk_score.min(100.0)
}

/// Points the dependency vulnerability counts add to the risk score.
fn vulnerability_points(critical: usize, high: usize, medium: usize) -> f32 {
    if critical > 0 {
        40.0
    } else if high > 0 {
        20.0
    } else if medium > 0 {
        5.0
    } else {
        0.0
    }
}

/// Detect malicious indicators
fn detect_malicious_indicators(
    package_info: &PackageInfo,
    dependencies: &PythonDependencyAnalysis,
    security: &PythonSecurityAnalysis,
    findings: &[SourceFinding],
    judge_name: bool,
) -> Result<MaliciousPackageIndicators> {
    let typosquatting_risk = if judge_name {
        analyze_typosquatting(&package_info.name)
    } else {
        TyposquattingAnalysis {
            is_potential_typosquatting: false,
            similar_packages: vec![],
            suspicious_name_patterns: vec![],
        }
    };
    let dependency_confusion_risk = judge_name && check_dependency_confusion(package_info);
    let known_malicious_patterns = if judge_name {
        detect_known_malicious_patterns(package_info, security, findings)
    } else {
        vec![]
    };
    let suspicious_maintainer_activity = false; // needs registry data; this tool is offline
    let code_injection_patterns = detect_code_injection_patterns(security, findings);

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
        reasons.push("dynamic code execution of decoded content".into());
    }

    let source_points = source_findings_score(findings);
    if source_points > 0.0 {
        overall_risk_score += source_points;
        reasons.push(format!(
            "{} finding(s) in source files (see section findings)",
            findings.len()
        ));
    }

    let summary = &dependencies.vulnerability_summary;
    let dep_points = vulnerability_points(
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
    );
    if dep_points > 0.0 {
        overall_risk_score += dep_points;
        reasons.push(format!(
            "{} known vulnerability(ies) in dependencies ({} critical, {} high)",
            summary.total_count, summary.critical_count, summary.high_count
        ));
    }
    if !dependencies.package_vulnerabilities.is_empty() {
        let critical = dependencies
            .package_vulnerabilities
            .iter()
            .any(|v| matches!(v.severity, VulnerabilitySeverity::Critical));
        overall_risk_score += if critical { 40.0 } else { 20.0 };
        reasons.push(format!(
            "this package version has {} known advisory(ies)",
            dependencies.package_vulnerabilities.len()
        ));
    }
    if security.supply_chain_risk_score > 0.0 {
        let what = if security.has_setup_script || security.has_install_script {
            "setup script / network use"
        } else {
            "advisories in dependencies / network use"
        };
        reasons.push(format!(
            "{what} (supply chain score {:.0})",
            security.supply_chain_risk_score
        ));
    }

    overall_risk_score = security
        .supply_chain_risk_score
        .mul_add(0.5, overall_risk_score);

    // High and Critical need a High or Critical reason; soft signals alone
    // (a name that resembles another, Medium findings) stop at Medium.
    let strong_evidence = !known_malicious_patterns.is_empty()
        || !code_injection_patterns.is_empty()
        || !security.backdoor_indicators.is_empty()
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
    if !strong_evidence {
        overall_risk_score = overall_risk_score.min(59.0);
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
        overall_risk_score: overall_risk_score.min(100.0),
        risk_level,
        risk_reasons: reasons,
    })
}

/// Analyze typosquatting
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
    ];

    for (pattern, description) in &typo_patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if re.is_match(package_name) {
                suspicious_name_patterns.push(description.to_string());
            }
        }
    }

    // Check similarity to popular packages
    if let Some(similar) = check_typosquatting_similarity(package_name) {
        is_potential_typosquatting = true;
        for sim_name in similar {
            similar_packages.push(SimilarPackage {
                name: sim_name,
                similarity_score: 0.8,
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
        suspicious_name_patterns,
    }
}

/// Check dependency confusion
fn check_dependency_confusion(package_info: &PackageInfo) -> bool {
    // Check for patterns indicating dependency confusion attack
    let internal_patterns = [
        r"^internal-",
        r"^private-",
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

/// Detect known malicious patterns
fn detect_known_malicious_patterns(
    package_info: &PackageInfo,
    security: &PythonSecurityAnalysis,
    findings: &[SourceFinding],
) -> Vec<MaliciousPattern> {
    let mut patterns = vec![];

    // Check if package is in the known malicious lists (names are PEP 503 normalised).
    let name = normalize_name(&package_info.name);
    if get_known_malicious_packages()
        .iter()
        .any(|known| normalize_name(known) == name)
    {
        patterns.push(MaliciousPattern {
            pattern_type: "Known malicious package".to_string(),
            description: "This package name is in the known malicious packages list".to_string(),
            found_in: "package name".to_string(),
            severity: "Critical".to_string(),
            evidence: package_info.name.clone(),
        });
    }
    if let Some(version) = crate::python_vuln_db::Pep440::parse(&package_info.version) {
        if get_known_malicious_versions().iter().any(|(n, v)| {
            *n == name && crate::python_vuln_db::Pep440::parse(v).as_ref() == Some(&version)
        }) {
            patterns.push(MaliciousPattern {
                pattern_type: "Known malicious release".to_string(),
                description: "This exact version is a known compromised release".to_string(),
                found_in: "package name and version".to_string(),
                severity: "Critical".to_string(),
                evidence: format!("{}=={}", package_info.name, package_info.version),
            });
        }
    }

    // Check for suspicious setup scripts
    if security.has_setup_script && security.has_install_script {
        patterns.push(MaliciousPattern {
            pattern_type: "Multiple install hooks".to_string(),
            description: "Package uses setup.py with install commands".to_string(),
            found_in: "setup.py".to_string(),
            severity: "High".to_string(),
            evidence: "setup.py with install hooks".to_string(),
        });
    }

    if security.crypto_mining_indicators {
        let hit = findings.iter().find(|f| f.category == "cryptomining");
        patterns.push(MaliciousPattern {
            pattern_type: "Crypto mining".to_string(),
            description: "Package contains crypto mining indicators".to_string(),
            found_in: hit.map_or_else(
                || "package files".to_string(),
                |f| format!("{}:{}", f.file, f.line),
            ),
            severity: "Critical".to_string(),
            evidence: hit.map_or_else(
                || "Mining-related code detected".to_string(),
                |f| f.evidence.clone(),
            ),
        });
    }

    if security.data_exfiltration_risk {
        let hit = findings.iter().find(|f| f.category == "exfiltration");
        patterns.push(MaliciousPattern {
            pattern_type: "Data exfiltration".to_string(),
            description: "Package may exfiltrate data to external servers".to_string(),
            found_in: hit.map_or_else(
                || "package files".to_string(),
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

/// Detect code injection patterns
fn detect_code_injection_patterns(
    security: &PythonSecurityAnalysis,
    findings: &[SourceFinding],
) -> Vec<CodeInjectionPattern> {
    let mut patterns = vec![];

    for import in &security.suspicious_imports {
        if import.module_name.contains("exec") || import.module_name.contains("eval") {
            patterns.push(CodeInjectionPattern {
                injection_type: "Dynamic code execution".to_string(),
                location: import.found_in.clone(),
                code_snippet: import.module_name.clone(),
                risk_level: "High".to_string(),
            });
        }
    }
    for finding in findings
        .iter()
        .filter(|f| f.rule == "Exec of decoded payload")
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

/// Analyze maintainers
fn analyze_maintainers(package_info: &PackageInfo) -> Result<MaintainerAnalysis> {
    let mut maintainers = vec![];

    if let Some(author) = &package_info.author {
        maintainers.push(MaintainerInfo {
            name: author.clone(),
            email: package_info.author_email.clone(),
            first_upload: None,
            package_count: None,
        });
    }

    if let Some(maintainer) = &package_info.maintainer {
        maintainers.push(MaintainerInfo {
            name: maintainer.clone(),
            email: package_info.maintainer_email.clone(),
            first_upload: None,
            package_count: None,
        });
    }

    Ok(MaintainerAnalysis {
        maintainers,
        upload_history: vec![],
        suspicious_activity: vec![],
        trust_score: 50.0, // Default neutral score
    })
}

/// Calculate quality metrics
fn calculate_quality_metrics(files: &[PythonFileAnalysis]) -> Result<PackageQualityMetrics> {
    let has_readme = files.iter().any(|f| {
        let name = f.file_path.to_lowercase();
        name.contains("readme")
    });

    let has_changelog = files.iter().any(|f| {
        let name = f.file_path.to_lowercase();
        name.contains("changelog") || name.contains("history")
    });

    let has_tests = files
        .iter()
        .any(|f| f.file_path.contains("test") || f.file_path.contains("spec"));

    let has_ci_config = files.iter().any(|f| {
        f.file_path.contains(".travis")
            || f.file_path.contains(".github/workflows")
            || f.file_path.contains(".circleci")
            || f.file_path.contains("tox.ini")
    });

    let has_type_hints = files
        .iter()
        .any(|f| f.file_path.ends_with(".pyi") || f.file_path.contains("py.typed"));

    let documentation_score = if has_readme { 40.0 } else { 0.0 }
        + if has_changelog { 20.0 } else { 0.0 }
        + if has_type_hints { 20.0 } else { 0.0 }
        + 20.0; // Base score for having package metadata

    let code_quality_score =
        if has_tests { 50.0 } else { 0.0 } + if has_ci_config { 50.0 } else { 0.0 };

    let overall_quality_score = f32::midpoint(documentation_score, code_quality_score);

    Ok(PackageQualityMetrics {
        has_readme,
        has_changelog,
        has_tests,
        has_ci_config,
        has_type_hints,
        documentation_score,
        code_quality_score,
        overall_quality_score,
    })
}

/// Detect Python file type
fn detect_python_file_type(path: &str) -> String {
    let path_lower = path.to_lowercase();

    if path_lower.ends_with("setup.py") {
        "Setup Script".to_string()
    } else if path_lower.ends_with("__init__.py") {
        "Init File".to_string()
    } else if path_lower.contains("test_") && path_lower.ends_with(".py") {
        "Test File".to_string()
    } else if path_lower.ends_with(".py") {
        if path_lower.contains("module") {
            "Python Module".to_string()
        } else {
            "Python source".to_string()
        }
    } else if path_lower.ends_with(".pyi") {
        "Python stub".to_string()
    } else if path_lower.ends_with(".pyc") {
        "Compiled Python".to_string()
    } else if path_lower.ends_with(".pyo") {
        "Python optimized bytecode".to_string()
    } else if path_lower.ends_with(".pyd") {
        "Python extension".to_string()
    } else if path_lower.ends_with(".so") {
        "Shared library".to_string()
    } else if path_lower.ends_with("requirements.txt") || path_lower.ends_with("requirements.in") {
        "Requirements".to_string()
    } else if path_lower.ends_with(".cfg")
        || path_lower.ends_with(".ini")
        || path_lower.ends_with(".toml")
    {
        "Config".to_string()
    } else if path_lower.ends_with(".md")
        || path_lower.ends_with(".rst")
        || path_lower.ends_with(".txt")
    {
        "Documentation".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Extract quoted value from a line
fn extract_quoted_value(line: &str) -> Option<String> {
    // Extract value between quotes
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start + 1..].find('"') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    if let Some(start) = line.find('\'') {
        if let Some(end) = line[start + 1..].find('\'') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    None
}
