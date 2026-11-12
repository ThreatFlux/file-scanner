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
    /// Dependencies (direct or locked) that are a known malicious release or package
    /// according to the built-in table: malware, not an ordinary advisory.
    #[serde(default)]
    pub malicious_releases: Vec<String>,
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
            file_path: file.display_path().to_string(),
            file_type: detect_python_file_type(file.display_path()),
            size: file.size,
            suspicious_content: vec![],
            imports: vec![],
            obfuscation_score: 0.0,
            source_scanned: false,
        };
        if let (Some(lang), Some(bytes)) = (language_of(&file.path), file.content.as_deref()) {
            let result = scan_source(lang, file.display_path(), bytes);
            analysis.source_scanned = true;
            analysis.obfuscation_score = result.obfuscation_score;
            analysis.imports = result.imports;
            analysis.suspicious_content = result
                .findings
                .iter()
                .map(|f| format!("line {}: {}", f.line, f.rule))
                .collect();
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
    let unsafe_findings = package_scan::unsafe_entry_findings(loaded);
    scan.findings.extend(unsafe_findings);
    sort_findings(&mut scan.findings);
    let unsafe_note = package_scan::unsafe_entry_note(loaded);

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
        input.notes.extend(unsafe_note.clone());
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
                in_comment: false,
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
    let mut input = InputInfo::from_loaded(kind, loaded, manifest.as_deref());
    input.notes.extend(unsafe_note);
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
    let mut malicious_indicators = detect_malicious_indicators(
        &package_info,
        &dependencies,
        &security_analysis,
        &scan.findings,
        true,
    )?;
    apply_input_floor(&mut malicious_indicators, &input, &dependencies);
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
    mut input: InputInfo,
) -> Result<PythonPackageAnalysis> {
    if let Some(ref content) = setup_py {
        let unread = manifest::parse_setup_py(content).unread();
        if !unread.is_empty() {
            input.notes.push(format!(
                "setup.py computes {} at run time; the value was not read, so the name, version or dependencies it would give are missing.",
                unread.join(", ")
            ));
        }
    }
    // Package identity: PKG-INFO (what the build recorded) first, then the source
    // manifests; each fills only what is still empty, so a field is never taken
    // from a table or call that does not own it.
    let mut candidates: Vec<PackageInfo> = Vec::new();
    if let Some(ref content) = pkg_info {
        candidates.push(parse_pkg_info(content)?);
    }
    if let Some(ref content) = pyproject_toml {
        candidates.push(parse_pyproject_toml(content)?);
    }
    if let Some(ref content) = setup_py {
        candidates.push(parse_setup_py(content)?);
    }
    if let Some(ref content) = setup_cfg {
        candidates.push(parse_setup_cfg(content)?);
    }
    let mut candidates = candidates.into_iter();
    let Some(mut package_info) = candidates.next() else {
        anyhow::bail!("No package metadata found")
    };
    for other in candidates {
        if package_info.name.is_empty() {
            package_info.name = other.name.clone();
        }
        if package_info.version.is_empty() {
            package_info.version = other.version.clone();
        }
        package_info.description = package_info.description.take().or(other.description);
        package_info.author = package_info.author.take().or(other.author);
        package_info.author_email = package_info.author_email.take().or(other.author_email);
        package_info.license = package_info.license.take().or(other.license);
        package_info.url = package_info.url.take().or(other.url);
        package_info.python_requires = package_info
            .python_requires
            .take()
            .or(other.python_requires);
        if package_info.keywords.is_empty() {
            package_info.keywords = other.keywords;
        }
        if package_info.classifiers.is_empty() {
            package_info.classifiers = other.classifiers;
        }
    }
    package_info.package_format = format;

    // Analyze dependencies
    let mut dependencies =
        analyze_dependencies(&setup_py, &setup_cfg, &pyproject_toml, &pkg_info, lock)?;
    finish_dependencies(&mut dependencies, &package_info, lock);

    // Analyze setup scripts
    let setup_analysis = analyze_setup_scripts(&setup_py, &scan);

    // Perform security analysis
    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &files, &setup_analysis, &scan)?;

    // Detect malicious indicators
    let mut malicious_indicators = detect_malicious_indicators(
        &package_info,
        &dependencies,
        &security_analysis,
        &scan.findings,
        true,
    )?;
    apply_input_floor(&mut malicious_indicators, &input, &dependencies);

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
                    vulnerabilities: check_dependency_spec(&n, "", Some(&v)).vulnerabilities,
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
    summary.malicious_releases.sort();
    summary.malicious_releases.dedup();
    summary.unresolved_range_hits.sort();
    summary.unresolved_range_hits.dedup();
    dependencies.vulnerability_summary = summary;
}

/// An advisory entry the built-in table writes for a release or package that is malware.
fn is_malware_entry(vuln: &KnownVulnerability) -> bool {
    matches!(
        vuln.cve_id.as_str(),
        "KNOWN-COMPROMISED-RELEASE" | "KNOWN-MALICIOUS-PACKAGE"
    )
}

fn tally_vulns(summary: &mut VulnerabilitySummary, name: &str, vulns: &[KnownVulnerability]) {
    if vulns.is_empty() {
        return;
    }
    if vulns.iter().any(is_malware_entry) {
        summary.malicious_releases.push(name.to_string());
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

/// True for a requirement that is a URL, a VCS reference, an archive or a path.
fn is_direct_reference(requirement: &str) -> bool {
    let lower = requirement.to_ascii_lowercase();
    let first = lower.split_whitespace().next().unwrap_or("");
    first.contains("://")
        || first.starts_with("git+")
        || first.starts_with("file:")
        || first.starts_with("./")
        || first.starts_with("../")
        || first.starts_with('/')
        || first.starts_with('~')
        || (!lower.contains(" @ ")
            && (first.ends_with(".whl") || first.ends_with(".tar.gz") || first.ends_with(".zip")))
}

/// Replace `user:password@` in URLs by `***@`.
fn redact_credentials(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        out.push_str(&rest[..at + 3]);
        rest = &rest[at + 3..];
        let end = rest.find(['/', ' ']).unwrap_or(rest.len());
        if let Some(userinfo) = rest[..end].rfind('@') {
            out.push_str("***@");
            rest = &rest[userinfo + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// Say what a requirements-file option line does that this analysis does not follow.
fn note_requirements_option(line: &str, notes: &mut Vec<String>, unread: &mut usize) {
    *unread += 1;
    if notes.len() >= 20 {
        return;
    }
    // Credentials in an index URL are not repeated.
    let redacted = redact_credentials(line);
    let line = redacted.as_str();
    let mut parts = line.splitn(2, [' ', '=']);
    let option = parts.next().unwrap_or("");
    let value = parts.next().unwrap_or("").trim();
    let text = match option {
        "-r" | "--requirement" => format!(
            "`{line}` includes another requirements file that was not read: its pins are not analysed. Analyse {value} on its own."
        ),
        "-c" | "--constraint" => format!(
            "`{line}` names a constraints file that was not read: it may pin or limit versions."
        ),
        "-e" | "--editable" => format!(
            "`{line}` is an editable install from a path or VCS URL; it was not analysed."
        ),
        "-i" | "--index-url" => format!(
            "`{line}` replaces the package index: every requirement here is resolved from that server."
        ),
        "--extra-index-url" => format!(
            "`{line}` adds a second package index. pip takes the highest version from any index, so an internal package name can be taken over from here (dependency confusion)."
        ),
        "-f" | "--find-links" => format!(
            "`{line}` adds a location to look for archives; it was not examined."
        ),
        _ => format!("option line `{line}` is not followed by this analysis."),
    };
    notes.push(text);
}

/// A requirements file as the only input.
fn analyze_requirements_text(text: &str, file_name: &str) -> Result<PythonPackageAnalysis> {
    let mut install_requires = HashMap::new();
    let mut joined = String::new();
    let mut capped = false;
    let mut notes: Vec<String> = Vec::new();
    let mut unread_options = 0usize;
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
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if entry.starts_with('-') {
            note_requirements_option(&entry, &mut notes, &mut unread_options);
            continue;
        }
        // Drop per-requirement options such as `--hash=sha256:...`.
        let requirement = entry.split(" --").next().unwrap_or("").trim();
        if requirement.is_empty() {
            continue;
        }
        if is_direct_reference(requirement) {
            // A URL or a path installs whatever is there: not a name, not a version.
            install_requires.insert(
                redact_credentials(requirement),
                DependencyDetails {
                    version_spec: "direct reference".to_string(),
                    is_pinned: false,
                    is_url: true,
                    is_git: requirement.starts_with("git+"),
                    vulnerabilities: vec![],
                    deprecated: false,
                    resolved_version: None,
                    range_floor_advisories: vec![],
                },
            );
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
    if unread_options > notes.len() {
        notes.push(format!(
            "{} more option lines are not described here.",
            unread_options - notes.len()
        ));
    }
    input.notes.extend(notes);
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
            malicious_releases: vec![],
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
    let mut malicious_indicators =
        detect_malicious_indicators(&package_info, &dependencies, &security_analysis, &[], false)?;
    apply_input_floor(&mut malicious_indicators, &input, &dependencies);
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

fn empty_info(format: PackageFormat) -> PackageInfo {
    PackageInfo {
        name: String::new(),
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
        package_format: format,
    }
}

/// `Name <email>` as Poetry writes authors.
fn split_name_email(text: &str) -> (String, Option<String>) {
    match (text.find('<'), text.rfind('>')) {
        (Some(start), Some(end)) if end > start => (
            text[..start].trim().to_string(),
            Some(text[start + 1..end].trim().to_string()),
        ),
        _ => (text.trim().to_string(), None),
    }
}

/// Names and emails of a PEP 621 `authors` / `maintainers` array of tables.
fn people(value: Option<&manifest::Toml>) -> (Option<String>, Option<String>) {
    let mut names = Vec::new();
    let mut emails = Vec::new();
    for person in value.and_then(manifest::Toml::as_array).unwrap_or(&[]) {
        if let Some(name) = person.get("name").and_then(manifest::Toml::as_str) {
            names.push(name.to_string());
        } else if let Some(text) = person.as_str() {
            let (name, email) = split_name_email(text);
            names.push(name);
            emails.extend(email);
            continue;
        }
        if let Some(email) = person.get("email").and_then(manifest::Toml::as_str) {
            emails.push(email.to_string());
        }
    }
    let join = |items: Vec<String>| (!items.is_empty()).then(|| items.join(", "));
    (join(names), join(emails))
}

/// Parse pyproject.toml: the `[project]` table (PEP 621), else `[tool.poetry]`.
/// Only keys of those tables count; a `name = ` under `[tool.black]` or an
/// author's name is not the package's.
fn parse_pyproject_toml(content: &str) -> Result<PackageInfo> {
    let doc = manifest::parse_toml(content);
    let mut info = empty_info(PackageFormat::Directory);
    let text = |table: &manifest::Toml, key: &str| {
        table
            .get(key)
            .and_then(manifest::Toml::as_str)
            .map(String::from)
    };
    if let Some(project) = doc.get("project") {
        info.name = text(project, "name").unwrap_or_default();
        info.version = text(project, "version").unwrap_or_default();
        info.description = text(project, "description");
        info.python_requires = text(project, "requires-python");
        info.license = text(project, "license").or_else(|| {
            project
                .at(&["license", "text"])
                .and_then(manifest::Toml::as_str)
                .map(String::from)
        });
        let (author, author_email) = people(project.get("authors"));
        info.author = author;
        info.author_email = author_email;
        let (maintainer, maintainer_email) = people(project.get("maintainers"));
        info.maintainer = maintainer;
        info.maintainer_email = maintainer_email;
        info.keywords = project
            .get("keywords")
            .map(manifest::Toml::strings)
            .unwrap_or_default();
        info.classifiers = project
            .get("classifiers")
            .map(manifest::Toml::strings)
            .unwrap_or_default();
        if let Some(urls) = project.get("urls").and_then(manifest::Toml::as_table) {
            for (key, value) in urls {
                if let Some(url) = value.as_str() {
                    info.project_urls.insert(key.clone(), url.to_string());
                }
            }
        }
        info.url = info
            .project_urls
            .iter()
            .find(|(k, _)| matches!(k.to_ascii_lowercase().as_str(), "homepage" | "home"))
            .map(|(_, v)| v.clone());
    }
    if info.name.is_empty() {
        if let Some(poetry) = doc.at(&["tool", "poetry"]) {
            info.name = text(poetry, "name").unwrap_or_default();
            info.version = text(poetry, "version").unwrap_or_default();
            info.description = text(poetry, "description");
            info.license = text(poetry, "license");
            info.url = text(poetry, "homepage");
            info.keywords = poetry
                .get("keywords")
                .map(manifest::Toml::strings)
                .unwrap_or_default();
            info.classifiers = poetry
                .get("classifiers")
                .map(manifest::Toml::strings)
                .unwrap_or_default();
            let authors = poetry
                .get("authors")
                .map(manifest::Toml::strings)
                .unwrap_or_default();
            if let Some(first) = authors.first() {
                let (name, email) = split_name_email(first);
                info.author = Some(name);
                info.author_email = email;
            }
            info.python_requires = poetry
                .at(&["dependencies", "python"])
                .and_then(manifest::Toml::as_str)
                .map(String::from);
        }
    }
    Ok(info)
}

/// Parse setup.py: the keyword arguments of its `setup()` call, with simple
/// `NAME = '...'` constants resolved. Arguments computed at run time stay empty.
fn parse_setup_py(content: &str) -> Result<PackageInfo> {
    let args = manifest::parse_setup_py(content);
    let mut info = empty_info(PackageFormat::SourceDistribution);
    info.name = args.string("name").unwrap_or_default();
    info.version = args.string("version").unwrap_or_default();
    info.description = args.string("description");
    info.author = args.string("author");
    info.author_email = args.string("author_email");
    info.maintainer = args.string("maintainer");
    info.maintainer_email = args.string("maintainer_email");
    info.license = args.string("license");
    info.url = args.string("url");
    info.python_requires = args.string("python_requires");
    info.keywords = match args.strings("keywords") {
        Some(list) if list.len() == 1 && list[0].contains(',') => {
            list[0].split(',').map(|k| k.trim().to_string()).collect()
        }
        Some(list) => list,
        None => vec![],
    };
    info.classifiers = args.strings("classifiers").unwrap_or_default();
    Ok(info)
}

/// Parse setup.cfg: its `[metadata]` section.
fn parse_setup_cfg(content: &str) -> Result<PackageInfo> {
    let ini = manifest::parse_ini(content);
    let get = |key: &str| {
        ini.get("metadata", key)
            .map(str::trim)
            .filter(|v| !v.is_empty() && !v.starts_with("attr:") && !v.starts_with("file:"))
            .map(String::from)
    };
    let mut info = empty_info(PackageFormat::SourceDistribution);
    info.name = get("name").unwrap_or_default();
    info.version = get("version").unwrap_or_default();
    info.description = get("description").or_else(|| get("summary"));
    info.author = get("author");
    info.author_email = get("author_email").or_else(|| get("author-email"));
    info.maintainer = get("maintainer");
    info.maintainer_email = get("maintainer_email");
    info.license = get("license");
    info.url = get("url").or_else(|| get("home_page"));
    info.python_requires = ini.get("options", "python_requires").map(String::from);
    info.keywords = get("keywords")
        .map(|k| {
            k.split([',', '\n'])
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect()
        })
        .unwrap_or_default();
    info.classifiers = ini
        .get("metadata", "classifiers")
        .map(|c| {
            c.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok(info)
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
    pkg_info: &Option<String>,
    lock: Option<&ParsedLock>,
) -> Result<PythonDependencyAnalysis> {
    let mut install_requires = HashMap::new();
    let extras_require = HashMap::new();
    let mut setup_requires = HashMap::new();
    let mut tests_require = HashMap::new();

    // Extract from setup.py
    if let Some(content) = setup_py {
        extract_setup_py_dependencies(
            content,
            &mut install_requires,
            &mut setup_requires,
            &mut tests_require,
        );
    }

    // Extract from setup.cfg
    if let Some(content) = setup_cfg {
        extract_setup_cfg_dependencies(content, &mut install_requires);
    }

    // Extract from pyproject.toml
    if let Some(content) = pyproject_toml {
        extract_pyproject_dependencies(content, &mut install_requires);
    }

    // An sdist's PKG-INFO lists what the build produced (setup.py may compute it).
    if let Some(content) = pkg_info {
        for (name, details) in analyze_dependencies_from_metadata(content)?.install_requires {
            install_requires.entry(name).or_insert(details);
        }
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
        + setup_requires.len()
        + tests_require.len()
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

/// Add one requirement string to a dependency map.
fn add_requirement(map: &mut HashMap<String, DependencyDetails>, requirement: &str) {
    if map.len() >= package_scan::MAX_DEPENDENCY_ENTRIES {
        return;
    }
    let requirement = requirement.trim();
    let (name, version_spec) = parse_dependency_spec(requirement);
    if name.is_empty() {
        return;
    }
    let details = dependency_details(&name, requirement, &version_spec, None);
    map.insert(name, details);
}

/// Extract dependencies from setup.py's `install_requires`, `setup_requires`
/// and `tests_require` arguments.
fn extract_setup_py_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
    setup_requires: &mut HashMap<String, DependencyDetails>,
    tests_require: &mut HashMap<String, DependencyDetails>,
) {
    let args = manifest::parse_setup_py(content);
    for (key, target) in [
        ("install_requires", install_requires),
        ("setup_requires", setup_requires),
        ("tests_require", tests_require),
    ] {
        for requirement in args.strings(key).unwrap_or_default() {
            add_requirement(target, &requirement);
        }
    }
}

/// Extract dependencies from setup.cfg
fn extract_setup_cfg_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
) {
    let ini = manifest::parse_ini(content);
    if let Some(list) = ini.get("options", "install_requires") {
        for line in list.lines() {
            // A line that is not a requirement (`file:`, `attr:`, a comment) names nothing.
            if !line.starts_with("file:") && !line.starts_with("attr:") {
                add_requirement(install_requires, line);
            }
        }
    }
}

/// Extract dependencies from pyproject.toml: `[project] dependencies` (PEP 621)
/// and `[tool.poetry.dependencies]`.
fn extract_pyproject_dependencies(
    content: &str,
    install_requires: &mut HashMap<String, DependencyDetails>,
) {
    let doc = manifest::parse_toml(content);
    if let Some(list) = doc.at(&["project", "dependencies"]) {
        for requirement in list.strings() {
            add_requirement(install_requires, &requirement);
        }
    }
    if let Some(table) = doc
        .at(&["tool", "poetry", "dependencies"])
        .and_then(manifest::Toml::as_table)
    {
        for (name, value) in table.iter().take(package_scan::MAX_DEPENDENCY_ENTRIES) {
            if name == "python" {
                continue;
            }
            // A constraint is a string, an inline table (`{ version = "^1", extras = [..] }`)
            // or an array of such tables for markers.
            let first = value.as_array().and_then(|a| a.first()).unwrap_or(value);
            let raw = match first {
                manifest::Toml::Str(s) => s.clone(),
                table => table
                    .get("version")
                    .and_then(manifest::Toml::as_str)
                    .map(String::from)
                    .unwrap_or_default(),
            };
            let (is_git, is_url) = (
                first.get("git").is_some(),
                first.get("url").is_some() || first.get("path").is_some(),
            );
            let specifier = poetry_specifier(&raw);
            let mut details = dependency_details(name, &raw, &specifier, None);
            details.is_git |= is_git;
            details.is_url |= is_url;
            install_requires.insert(name.clone(), details);
        }
    }
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
        malicious_releases: vec![],
    };
    let mut names: Vec<&String> = dependencies.keys().collect();
    names.sort();
    for name in names {
        tally_dependency(&mut summary, name, &dependencies[name]);
    }
    summary
}

/// Analyze setup scripts
/// True for a finding in the package's own top-level `setup.py`.
fn is_setup_py_finding(finding: &SourceFinding) -> bool {
    finding.file == "setup.py"
        || (finding.file.ends_with("/setup.py") && finding.file.matches('/').count() == 1)
}

/// What the setup script does, from the scan findings on `setup.py` (token
/// aware, with line numbers) and its `setup()` arguments. Words that merely
/// appear in text ("executable", "evaluate") are not operations.
fn analyze_setup_scripts(setup_py: &Option<String>, scan: &SourceScan) -> SetupAnalysis {
    let mut setup_type = SetupType::PyProjectToml;
    let mut setup_commands = vec![];
    let mut custom_commands = HashMap::new();
    let mut dangerous_operations = vec![];
    let mut external_downloads = vec![];

    if let Some(content) = setup_py {
        setup_type = SetupType::SetupPy;

        // `cmdclass` replaces build or install steps with the package's own code:
        // worth knowing, and common in packages that build C extensions.
        if manifest::parse_setup_py(content).has("cmdclass") {
            setup_commands.push(SetupCommand {
                command_name: "cmdclass".to_string(),
                command_class: "Custom build or install command classes".to_string(),
                is_suspicious: false,
                risk_reason: None,
            });
            custom_commands.insert(
                "cmdclass".to_string(),
                "setup() passes cmdclass: the package's own code runs as part of building or installing it".to_string(),
            );
        }

        for finding in scan.findings.iter().filter(|f| is_setup_py_finding(f)) {
            if finding.rule == "Network access in setup.py" {
                if external_downloads.len() < 20 {
                    external_downloads.push(format!(
                        "{} at {}:{}",
                        finding.rule, finding.file, finding.line
                    ));
                }
            } else if dangerous_operations.len() < 40 {
                dangerous_operations.push(DangerousOperation {
                    operation: finding.rule.clone(),
                    location: format!("{}:{}", finding.file, finding.line),
                    risk_reason: format!("{}: {}", finding.severity, finding.evidence),
                });
            }
        }
    }

    SetupAnalysis {
        setup_type,
        setup_commands,
        custom_commands,
        dangerous_operations,
        external_downloads,
    }
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
    let mut process_execution: Vec<ProcessExecution> = Vec::new();
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

    // Obfuscation: a file that looks packed, or an exec of decoded content in the setup script.
    let obfuscation_detected = detect_obfuscation(files)
        || scan.findings.iter().any(|f| {
            f.category == "obfuscation"
                && !f.in_comment
                && (is_setup_py_finding(f) || f.severity != "Medium")
        });

    let crypto_mining_indicators = scan.findings.iter().any(|f| f.category == "cryptomining");
    // A download in setup.py is listed under network patterns; only an exfiltration
    // finding (an endpoint that receives data, environment sent out) counts here.
    let data_exfiltration_risk = scan
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

/// Modules whose import in `setup.py` is worth listing (informational).
const NOTABLE_SETUP_IMPORTS: &[(&str, &str)] = &[
    ("subprocess", "Process execution"),
    ("socket", "Network socket access"),
    ("urllib", "Network access"),
    ("urllib2", "Network access"),
    ("requests", "HTTP requests"),
    ("httpx", "HTTP requests"),
    ("base64", "Base64 encoding/decoding"),
    ("marshal", "Bytecode loading"),
    ("ctypes", "Foreign function calls"),
    ("pty", "Pseudo-terminal control"),
];

/// The operations found in `setup.py` and the notable modules it imports, as
/// suspicious-import rows. An import alone is listed as Low: it is a pointer
/// for the reader, not evidence.
fn detect_suspicious_imports(
    files: &[PythonFileAnalysis],
    setup_analysis: &SetupAnalysis,
) -> Vec<SuspiciousImport> {
    let mut rows: Vec<SuspiciousImport> = Vec::new();
    if let Some(setup) = files.iter().find(|f| {
        f.file_path == "setup.py"
            || (f.file_path.ends_with("/setup.py") && f.file_path.matches('/').count() == 1)
    }) {
        for (module, reason) in NOTABLE_SETUP_IMPORTS {
            if setup.imports.iter().any(|i| i == module) {
                rows.push(SuspiciousImport {
                    module_name: (*module).to_string(),
                    risk_level: "Low".to_string(),
                    reason: format!("{reason}: imported by setup.py"),
                    found_in: setup.file_path.clone(),
                });
            }
        }
    }
    rows.extend(setup_analysis.dangerous_operations.iter().map(|op| {
        SuspiciousImport {
            module_name: op.operation.clone(),
            risk_level: op
                .risk_reason
                .split_once(':')
                .map_or("Medium", |(severity, _)| severity)
                .to_string(),
            reason: op.risk_reason.clone(),
            found_in: op.location.clone(),
        }
    }));
    rows
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

/// Paths whose code does not run when the package is used: tests, docs, examples.
fn is_non_runtime_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    lower.split('/').any(|part| {
        matches!(
            part,
            "tests" | "test" | "testing" | "docs" | "doc" | "examples" | "example" | "benchmarks"
        )
    }) || name.starts_with("test_")
        || name == "conftest.py"
        || name.ends_with("_test.py")
}

/// Detect obfuscation
fn detect_obfuscation(files: &[PythonFileAnalysis]) -> bool {
    // Check if any file has suspicious content suggesting obfuscation
    files.iter().any(|f| f.obfuscation_score > 0.5)
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
        risk_score += 5.0;
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

/// Raise the rating of an input that was not read in full (see
/// `package_scan::input_floor`).
fn apply_input_floor(
    indicators: &mut MaliciousPackageIndicators,
    input: &InputInfo,
    dependencies: &PythonDependencyAnalysis,
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

/// Advisory counts of the dependencies that are not malware entries:
/// (total, critical, high, medium).
fn ordinary_advisory_counts(
    dependencies: &PythonDependencyAnalysis,
) -> (usize, usize, usize, usize) {
    let mut counts = (0usize, 0usize, 0usize, 0usize);
    let mut add = |vulns: &[KnownVulnerability]| {
        for vuln in vulns.iter().filter(|v| !is_malware_entry(v)) {
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
        .install_requires
        .iter()
        .chain(&dependencies.setup_requires)
        .chain(&dependencies.tests_require)
    {
        direct.insert(normalize_name(name));
        add(&details.vulnerabilities);
    }
    for package in &dependencies.locked_packages {
        if !direct.contains(&normalize_name(&package.name)) {
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
    let code_injection_patterns = detect_code_injection_patterns(findings);

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

    // Medium and Low findings in tests, docs and examples (an `exec` in a test
    // fixture) are listed but do not raise the score of the package.
    let weighed: Vec<SourceFinding> = findings
        .iter()
        .filter(|f| package_scan::severity_rank(&f.severity) >= 3 || !is_non_runtime_path(&f.file))
        .cloned()
        .collect();
    let source_points = source_findings_score(&weighed);
    if source_points > 0.0 {
        overall_risk_score += source_points;
        reasons.push(format!(
            "{} finding(s) in source files (see section findings)",
            weighed.len()
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
    // The advisories of a malicious release are part of the malware finding above.
    let (other_total, other_critical, other_high, _other_medium) =
        ordinary_advisory_counts(dependencies);
    // Points use the full counts (a malicious release adds at least a Critical
    // advisory's weight); only the reason's wording leaves the malware out.
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
fn detect_code_injection_patterns(findings: &[SourceFinding]) -> Vec<CodeInjectionPattern> {
    let mut patterns = vec![];

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

mod manifest {
    //! Readers for Python package manifests: a TOML reader for `pyproject.toml`
    //! (the `toml` crate is not a dependency of this crate and may not be added
    //! here), a reader for the `setup()` call of `setup.py`, and an INI reader for
    //! `setup.cfg`. All of them are tolerant: input they cannot understand yields
    //! fewer fields, never a wrong one.

    use std::collections::BTreeMap;

    // ---------------------------------------------------------------------------
    // TOML
    // ---------------------------------------------------------------------------

    /// A TOML value; dates, numbers and booleans are kept as their text.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Toml {
        Str(String),
        Array(Vec<Toml>),
        Table(BTreeMap<String, Toml>),
        Other(String),
    }

    impl Toml {
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Self::Str(s) => Some(s),
                _ => None,
            }
        }

        pub fn as_array(&self) -> Option<&[Toml]> {
            match self {
                Self::Array(a) => Some(a),
                _ => None,
            }
        }

        pub fn as_table(&self) -> Option<&BTreeMap<String, Toml>> {
            match self {
                Self::Table(t) => Some(t),
                _ => None,
            }
        }

        pub fn get(&self, key: &str) -> Option<&Toml> {
            self.as_table()?.get(key)
        }

        /// Follow a path of table keys.
        pub fn at(&self, path: &[&str]) -> Option<&Toml> {
            let mut current = self;
            for key in path {
                current = current.get(key)?;
            }
            Some(current)
        }

        /// The strings of an array, skipping other values.
        pub fn strings(&self) -> Vec<String> {
            self.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    const MAX_TOML_DEPTH: usize = 32;
    /// Most dotted parts in one key or table header. A deeper key is skipped, so a
    /// hostile file cannot build a value that overflows the stack when it is dropped.
    const MAX_TOML_KEY_PARTS: usize = 16;

    struct Parser<'a> {
        text: &'a str,
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Parser<'a> {
        const fn new(text: &'a str) -> Self {
            Self {
                text,
                bytes: text.as_bytes(),
                pos: 0,
            }
        }

        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }

        fn starts_with(&self, s: &str) -> bool {
            self.bytes[self.pos..].starts_with(s.as_bytes())
        }

        fn skip_inline_space(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
                self.pos += 1;
            }
        }

        fn skip_comment(&mut self) {
            if self.peek() == Some(b'#') {
                while !matches!(self.peek(), None | Some(b'\n')) {
                    self.pos += 1;
                }
            }
        }

        /// Whitespace, newlines and comments.
        fn skip_blank(&mut self) {
            loop {
                self.skip_inline_space();
                match self.peek() {
                    Some(b'\n') => self.pos += 1,
                    Some(b'#') => self.skip_comment(),
                    _ => break,
                }
            }
        }

        fn skip_line(&mut self) {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.pos += 1;
            }
        }

        fn parse_string(&mut self) -> Option<String> {
            let quote = self.peek()?;
            if quote != b'"' && quote != b'\'' {
                return None;
            }
            let triple = self.starts_with(&String::from_utf8(vec![quote; 3]).ok()?);
            let basic = quote == b'"';
            self.pos += if triple { 3 } else { 1 };
            if triple && self.peek() == Some(b'\r') {
                self.pos += 1;
            }
            if triple && self.peek() == Some(b'\n') {
                self.pos += 1;
            }
            let mut out = String::new();
            loop {
                let byte = self.peek()?;
                if byte == quote {
                    if !triple {
                        self.pos += 1;
                        return Some(out);
                    }
                    if self.starts_with(&String::from_utf8(vec![quote; 3]).ok()?) {
                        self.pos += 3;
                        // Up to two more quotes belong to the string.
                        while self.peek() == Some(quote) {
                            out.push(quote as char);
                            self.pos += 1;
                        }
                        return Some(out);
                    }
                }
                if byte == b'\n' && !triple {
                    return None;
                }
                if byte == b'\\' && basic {
                    self.pos += 1;
                    let escaped = self.peek()?;
                    self.pos += 1;
                    match escaped {
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'u' | b'U' => {
                            let len = if escaped == b'u' { 4 } else { 8 };
                            let hex = self.text.get(self.pos..self.pos + len)?;
                            out.push(u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)?);
                            self.pos += len;
                        }
                        b'\n' | b' ' | b'\t' | b'\r' if triple => {
                            // Line-ending backslash: drop the whitespace that follows.
                            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                                self.pos += 1;
                            }
                        }
                        _ => return None,
                    }
                    continue;
                }
                // Copy one whole UTF-8 character.
                let start = self.pos;
                self.pos += 1;
                while self.pos < self.bytes.len() && !self.text.is_char_boundary(self.pos) {
                    self.pos += 1;
                }
                out.push_str(&self.text[start..self.pos]);
            }
        }

        fn parse_key(&mut self) -> Option<Vec<String>> {
            let mut parts = Vec::new();
            loop {
                if parts.len() >= MAX_TOML_KEY_PARTS {
                    // No real manifest nests this deep; the line is skipped.
                    return None;
                }
                self.skip_inline_space();
                match self.peek()? {
                    b'"' | b'\'' => parts.push(self.parse_string()?),
                    b if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' => {
                        let start = self.pos;
                        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                        {
                            self.pos += 1;
                        }
                        parts.push(self.text[start..self.pos].to_string());
                    }
                    _ => return None,
                }
                self.skip_inline_space();
                if self.peek() == Some(b'.') {
                    self.pos += 1;
                } else {
                    return Some(parts);
                }
            }
        }

        fn parse_value(&mut self, depth: usize) -> Option<Toml> {
            if depth > MAX_TOML_DEPTH {
                return None;
            }
            self.skip_inline_space();
            match self.peek()? {
                b'"' | b'\'' => self.parse_string().map(Toml::Str),
                b'[' => {
                    self.pos += 1;
                    let mut items = Vec::new();
                    loop {
                        self.skip_blank();
                        match self.peek()? {
                            b']' => {
                                self.pos += 1;
                                return Some(Toml::Array(items));
                            }
                            b',' => self.pos += 1,
                            _ => items.push(self.parse_value(depth + 1)?),
                        }
                    }
                }
                b'{' => {
                    self.pos += 1;
                    let mut table = BTreeMap::new();
                    loop {
                        self.skip_blank();
                        match self.peek()? {
                            b'}' => {
                                self.pos += 1;
                                return Some(Toml::Table(table));
                            }
                            b',' => self.pos += 1,
                            _ => {
                                let key = self.parse_key()?;
                                self.skip_inline_space();
                                if self.peek()? != b'=' {
                                    return None;
                                }
                                self.pos += 1;
                                let value = self.parse_value(depth + 1)?;
                                insert_dotted(&mut table, &key, value);
                            }
                        }
                    }
                }
                _ => {
                    let start = self.pos;
                    while !matches!(self.peek(), None | Some(b',' | b']' | b'}' | b'\n' | b'#')) {
                        self.pos += 1;
                    }
                    let raw = self.text[start..self.pos].trim();
                    (!raw.is_empty()).then(|| Toml::Other(raw.to_string()))
                }
            }
        }
    }

    fn insert_dotted(table: &mut BTreeMap<String, Toml>, key: &[String], value: Toml) {
        let Some((last, parents)) = key.split_last() else {
            return;
        };
        let target = table_at(table, parents);
        target.insert(last.clone(), value);
    }

    /// The table at `path`, created on the way. An array of tables is entered at
    /// its last element.
    fn table_at<'a>(
        root: &'a mut BTreeMap<String, Toml>,
        path: &[String],
    ) -> &'a mut BTreeMap<String, Toml> {
        let mut current = root;
        for segment in path.iter().take(MAX_TOML_KEY_PARTS) {
            let entry = current
                .entry(segment.clone())
                .or_insert_with(|| Toml::Table(BTreeMap::new()));
            if !matches!(entry, Toml::Table(_) | Toml::Array(_)) {
                *entry = Toml::Table(BTreeMap::new());
            }
            if let Toml::Array(items) = entry {
                if !matches!(items.last(), Some(Toml::Table(_))) {
                    items.push(Toml::Table(BTreeMap::new()));
                }
            }
            current = match entry {
                Toml::Table(t) => t,
                Toml::Array(items) => match items.last_mut() {
                    Some(Toml::Table(t)) => t,
                    _ => unreachable!("an array of tables ends in a table"),
                },
                _ => unreachable!("entry was made a table or array above"),
            };
        }
        current
    }

    /// Read TOML text. Lines that are not valid TOML are skipped; the rest is kept.
    pub fn parse_toml(text: &str) -> Toml {
        let mut parser = Parser::new(text);
        let mut root: BTreeMap<String, Toml> = BTreeMap::new();
        let mut current: Vec<String> = Vec::new();
        loop {
            parser.skip_blank();
            let Some(byte) = parser.peek() else { break };
            if byte == b'[' {
                let array = parser.starts_with("[[");
                parser.pos += if array { 2 } else { 1 };
                let Some(path) = parser.parse_key() else {
                    parser.skip_line();
                    continue;
                };
                parser.skip_inline_space();
                let closer = if array { "]]" } else { "]" };
                if !parser.starts_with(closer) {
                    parser.skip_line();
                    continue;
                }
                parser.pos += closer.len();
                if array {
                    let (last, parents) = path.split_last().expect("key has a part");
                    let parent = table_at(&mut root, parents);
                    let entry = parent
                        .entry(last.clone())
                        .or_insert_with(|| Toml::Array(Vec::new()));
                    if let Toml::Array(items) = entry {
                        items.push(Toml::Table(BTreeMap::new()));
                    } else {
                        *entry = Toml::Array(vec![Toml::Table(BTreeMap::new())]);
                    }
                } else {
                    table_at(&mut root, &path);
                }
                current = path;
            } else if let Some(key) = parser.parse_key() {
                parser.skip_inline_space();
                if parser.peek() != Some(b'=') {
                    parser.skip_line();
                    continue;
                }
                parser.pos += 1;
                match parser.parse_value(0) {
                    Some(value) => {
                        let table = table_at(&mut root, &current);
                        insert_dotted(table, &key, value);
                    }
                    None => parser.skip_line(),
                }
            } else {
                parser.skip_line();
            }
        }
        Toml::Table(root)
    }

    // ---------------------------------------------------------------------------
    // setup.py
    // ---------------------------------------------------------------------------

    /// A value read from a `setup()` argument.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Py {
        Str(String),
        List(Vec<Py>),
        Unknown,
    }

    /// The keyword arguments of the `setup(...)` call.
    #[derive(Debug, Default)]
    pub struct SetupArgs {
        /// A `setup(` call was found.
        pub found: bool,
        /// The call passes `**something`, whose keys are known only at run time.
        pub kwargs: bool,
        args: BTreeMap<String, Py>,
    }

    impl SetupArgs {
        /// Identity and dependency arguments that are computed at run time and
        /// could not be read, plus `**kwargs` when the call uses it.
        pub fn unread(&self) -> Vec<String> {
            let mut out: Vec<String> = [
                "name",
                "version",
                "install_requires",
                "setup_requires",
                "tests_require",
            ]
            .iter()
            .filter(|k| matches!(self.args.get(**k), Some(Py::Unknown)))
            .map(|k| (*k).to_string())
            .collect();
            if self.kwargs {
                out.push("**kwargs".to_string());
            }
            out
        }

        pub fn has(&self, key: &str) -> bool {
            self.args.contains_key(key)
        }

        /// A string argument, when it is a plain string (or a constant that is).
        pub fn string(&self, key: &str) -> Option<String> {
            match self.args.get(key)? {
                Py::Str(s) => Some(s.clone()),
                _ => None,
            }
        }

        /// A list argument: the string items that could be read. A single string
        /// is split by lines, as setuptools does.
        pub fn strings(&self, key: &str) -> Option<Vec<String>> {
            match self.args.get(key)? {
                Py::List(items) => Some(
                    items
                        .iter()
                        .filter_map(|i| match i {
                            Py::Str(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect(),
                ),
                Py::Str(s) => Some(
                    s.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(String::from)
                        .collect(),
                ),
                Py::Unknown => None,
            }
        }
    }

    const MAX_SETUP_CALL_BYTES: usize = 256 * 1024;
    /// Most `setup` look-alikes examined before giving up.
    const MAX_SETUP_CANDIDATES: usize = 200;
    const MAX_CONSTANTS: usize = 500;
    const MAX_EXPR_DEPTH: usize = 16;

    /// Index just past the end of the string literal that starts at `start`.
    fn string_end(text: &str, start: usize) -> usize {
        let bytes = text.as_bytes();
        let quote = bytes[start];
        let triple = bytes[start..].starts_with(&[quote, quote, quote]);
        let mut i = start + if triple { 3 } else { 1 };
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b if b == quote => {
                    if !triple {
                        return i + 1;
                    }
                    if bytes[i..].starts_with(&[quote, quote, quote]) {
                        return i + 3;
                    }
                    i += 1;
                }
                b'\n' if !triple => return i,
                _ => i += 1,
            }
        }
        bytes.len()
    }

    /// Split `text` at top-level occurrences of `sep` (outside strings, comments
    /// and brackets).
    fn split_top(text: &str, sep: u8) -> Vec<&str> {
        let bytes = text.as_bytes();
        let mut parts = Vec::new();
        let mut depth = 0i32;
        let mut start = 0;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' | b'\'' => {
                    i = string_end(text, i);
                    continue;
                }
                b'#' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b if b == sep && depth == 0 => {
                    parts.push(&text[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
            i += 1;
        }
        parts.push(&text[start..]);
        parts
    }

    /// The text between the bracket at `open` and its match, and the index after it.
    fn balanced(text: &str, open: usize) -> Option<(&str, usize)> {
        let bytes = text.as_bytes();
        let mut depth = 0i32;
        let mut i = open;
        while i < bytes.len() && i - open < MAX_SETUP_CALL_BYTES {
            match bytes[i] {
                b'"' | b'\'' => {
                    i = string_end(text, i);
                    continue;
                }
                b'#' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((&text[open + 1..i], i + 1));
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
    }

    fn is_string_prefix(text: &str) -> usize {
        // r, u, b, R, U, B and combinations, directly before a quote; f-strings are not literals.
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len()
            && i < 2
            && matches!(bytes[i], b'r' | b'R' | b'u' | b'U' | b'b' | b'B')
        {
            i += 1;
        }
        if matches!(bytes.get(i), Some(b'"' | b'\'')) {
            i
        } else {
            usize::MAX
        }
    }

    fn unescape(body: &str, raw: bool) -> String {
        if raw || !body.contains('\\') {
            return body.to_string();
        }
        let mut out = String::new();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\n') | None => {}
                Some(other) => out.push(other),
            }
        }
        out
    }

    fn eval_py(expr: &str, constants: &BTreeMap<String, Py>, depth: usize) -> Py {
        if depth > MAX_EXPR_DEPTH {
            return Py::Unknown;
        }
        let expr = strip_comments(expr);
        let expr = expr.trim();
        if expr.is_empty() {
            return Py::Unknown;
        }
        let terms = split_top(expr, b'+');
        if terms.len() > 1 {
            let values: Vec<Py> = terms
                .iter()
                .map(|t| eval_py(t, constants, depth + 1))
                .collect();
            if values.iter().all(|v| matches!(v, Py::Str(_))) {
                return Py::Str(
                    values
                        .iter()
                        .filter_map(|v| match v {
                            Py::Str(s) => Some(s.as_str()),
                            _ => None,
                        })
                        .collect(),
                );
            }
            if values.iter().all(|v| matches!(v, Py::List(_))) {
                return Py::List(
                    values
                        .into_iter()
                        .flat_map(|v| match v {
                            Py::List(items) => items,
                            _ => vec![],
                        })
                        .collect(),
                );
            }
            return Py::Unknown;
        }
        let prefix = is_string_prefix(expr);
        if prefix != usize::MAX {
            // One or more adjacent string literals.
            let mut out = String::new();
            let mut rest = expr;
            while !rest.is_empty() {
                let prefix = is_string_prefix(rest);
                if prefix == usize::MAX {
                    return Py::Unknown;
                }
                let raw = rest[..prefix].contains(['r', 'R']);
                let end = string_end(rest, prefix);
                let literal = &rest[prefix..end];
                let quote = literal.as_bytes()[0];
                let triple = literal.as_bytes().starts_with(&[quote, quote, quote]);
                let cut = if triple { 3 } else { 1 };
                if literal.len() < cut * 2 || !literal.as_bytes().ends_with(&[quote]) {
                    return Py::Unknown;
                }
                out.push_str(&unescape(&literal[cut..literal.len() - cut], raw));
                rest = rest[end..].trim_start();
            }
            return Py::Str(out);
        }
        let first = expr.as_bytes()[0];
        if first == b'[' || first == b'(' {
            let Some((inner, end)) = balanced(expr, 0) else {
                return Py::Unknown;
            };
            if !expr[end..].trim().is_empty() {
                return Py::Unknown;
            }
            let items = split_top(inner, b',');
            if first == b'(' && items.len() == 1 {
                return eval_py(items[0], constants, depth + 1);
            }
            let inner_trim = inner.trim();
            if inner_trim.contains(" for ") && split_top(inner, b',').len() == 1 {
                return Py::Unknown;
            }
            return Py::List(
                items
                    .iter()
                    .filter(|i| !i.trim().is_empty())
                    .map(|i| eval_py(i, constants, depth + 1))
                    .collect(),
            );
        }
        if expr.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return constants.get(expr).cloned().unwrap_or(Py::Unknown);
        }
        Py::Unknown
    }

    /// The expression that starts at `start`: to the end of the line, or further
    /// while brackets or a string are open.
    fn expression_at(text: &str, start: usize) -> &str {
        let bytes = text.as_bytes();
        let mut depth = 0i32;
        let mut i = start;
        while i < bytes.len() && i - start < MAX_SETUP_CALL_BYTES {
            match bytes[i] {
                b'"' | b'\'' => {
                    i = string_end(text, i);
                    continue;
                }
                b'#' => {
                    if depth <= 0 {
                        break;
                    }
                    // Inside brackets a comment ends at the line end and the list goes on.
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b'\\' if bytes.get(i + 1) == Some(&b'\n') => i += 1,
                b'\n' if depth <= 0 => break,
                _ => {}
            }
            i += 1;
        }
        let mut end = i.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[start..end]
    }

    /// `text` without its `#` comments (outside strings).
    fn strip_comments(text: &str) -> std::borrow::Cow<'_, str> {
        if !text.contains('#') {
            return std::borrow::Cow::Borrowed(text);
        }
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        let mut copied = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'"' | b'\'' => {
                    i = string_end(text, i).min(bytes.len());
                }
                b'#' => {
                    out.push_str(&text[copied..i]);
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    copied = i;
                }
                _ => i += 1,
            }
        }
        out.push_str(&text[copied..]);
        std::borrow::Cow::Owned(out)
    }

    fn constants_of(content: &str) -> BTreeMap<String, Py> {
        let mut constants = BTreeMap::new();
        let mut offset = 0usize;
        let mut evaluated = 0usize;
        for line in content.split_inclusive('\n') {
            let line_start = offset;
            offset += line.len();
            let first = line.as_bytes().first().copied().unwrap_or(b' ');
            if !(first.is_ascii_alphabetic() || first == b'_') {
                continue;
            }
            let name_end = line
                .bytes()
                .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
                .unwrap_or(line.len());
            let after = line[name_end..].trim_start();
            let Some(rhs) = after.strip_prefix('=') else {
                continue;
            };
            if rhs.starts_with('=') {
                continue;
            }
            evaluated += 1;
            if evaluated > MAX_CONSTANTS {
                break;
            }
            let expr_start = line_start + (line.len() - rhs.len());
            let value = eval_py(expression_at(content, expr_start), &constants, 0);
            if constants.len() < MAX_CONSTANTS {
                constants.insert(line[..name_end].to_string(), value);
            }
        }
        constants
    }

    /// Read the keyword arguments of the first real `setup(...)` call.
    pub fn parse_setup_py(content: &str) -> SetupArgs {
        let Some(open) = find_setup_call(content) else {
            return SetupArgs::default();
        };
        let Some((inner, _)) = balanced(content, open) else {
            return SetupArgs::default();
        };
        let constants = constants_of(content);
        let mut args = BTreeMap::new();
        let mut kwargs = false;
        for item in split_top(inner, b',') {
            let item = strip_comments(item);
            let item = item.trim();
            if item.starts_with("**") {
                kwargs = true;
                continue;
            }
            let name_end = item
                .bytes()
                .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
                .unwrap_or(item.len());
            if name_end == 0 {
                continue;
            }
            let Some(value) = item[name_end..].trim_start().strip_prefix('=') else {
                continue;
            };
            if value.starts_with('=') {
                continue;
            }
            args.insert(item[..name_end].to_string(), eval_py(value, &constants, 0));
        }
        SetupArgs {
            found: true,
            kwargs,
            args,
        }
    }

    /// Index of the `(` of the first `setup(` call that is not a definition, a
    /// method call or inside a comment.
    fn find_setup_call(content: &str) -> Option<usize> {
        let bytes = content.as_bytes();
        let mut search = 0usize;
        let mut candidates = 0usize;
        while let Some(found) = content[search..].find("setup") {
            candidates += 1;
            if candidates > MAX_SETUP_CANDIDATES {
                return None;
            }
            let at = search + found;
            search = at + 5;
            let before = if at == 0 { b' ' } else { bytes[at - 1] };
            let qualified = before == b'.'
                && (content[..at].ends_with("setuptools.") || content[..at].ends_with("core."));
            if (before.is_ascii_alphanumeric() || before == b'_' || before == b'.') && !qualified {
                continue;
            }
            let after = content[at + 5..].trim_start();
            if !after.starts_with('(') {
                continue;
            }
            let line_start = content[..at].rfind('\n').map_or(0, |i| i + 1);
            let prefix = &content[line_start..at];
            if prefix.contains('#') || prefix.trim_start().starts_with("def ") {
                continue;
            }
            return Some(content.len() - after.len());
        }
        None
    }

    // ---------------------------------------------------------------------------
    // setup.cfg
    // ---------------------------------------------------------------------------

    /// An INI file: section name to (key, value) pairs. A value that continues on
    /// indented lines is joined with newlines.
    #[derive(Debug, Default)]
    pub struct Ini {
        sections: Vec<(String, Vec<(String, String)>)>,
    }

    impl Ini {
        pub fn get(&self, section: &str, key: &str) -> Option<&str> {
            self.sections
                .iter()
                .filter(|(name, _)| name == section)
                .flat_map(|(_, pairs)| pairs.iter())
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    pub fn parse_ini(text: &str) -> Ini {
        let mut ini = Ini::default();
        for raw in text.lines() {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let indented = raw.starts_with([' ', '\t']);
            if !indented && trimmed.starts_with('[') && trimmed.ends_with(']') {
                ini.sections
                    .push((trimmed[1..trimmed.len() - 1].trim().to_string(), vec![]));
                continue;
            }
            let Some((_, pairs)) = ini.sections.last_mut() else {
                continue;
            };
            if indented {
                if let Some((_, value)) = pairs.last_mut() {
                    value.push('\n');
                    value.push_str(trimmed);
                }
                continue;
            }
            if let Some((key, value)) = trimmed.split_once(['=', ':']) {
                pairs.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
        ini
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::manifest::{parse_ini, parse_setup_py, parse_toml, Toml};

    #[test]
    fn toml_tables_arrays_and_comments() {
        let doc = parse_toml(
            "a = 1 # c\n[t]\nname = \"x\\\"y\"\nlist = [\n 'a', # one\n \"b\",\n]\ninline = { k = \"v\", n = [1, 2] }\n[[t.rows]]\nid = 1\n[[t.rows]]\nid = 2\n[t.sub.deep]\nz = '''multi\nline'''\n",
        );
        assert_eq!(doc.at(&["t", "name"]).and_then(Toml::as_str), Some("x\"y"));
        assert_eq!(doc.at(&["t", "list"]).unwrap().strings(), vec!["a", "b"]);
        assert_eq!(
            doc.at(&["t", "inline", "k"]).and_then(Toml::as_str),
            Some("v")
        );
        assert_eq!(
            doc.at(&["t", "rows"])
                .and_then(Toml::as_array)
                .map(<[Toml]>::len),
            Some(2)
        );
        assert_eq!(
            doc.at(&["t", "sub", "deep", "z"]).and_then(Toml::as_str),
            Some("multi\nline")
        );
    }

    #[test]
    fn toml_garbage_is_skipped_not_fatal() {
        let doc =
            parse_toml("= = =\n[unclosed\nname = \"kept\"\n[x]\nv = \"ok\"\n\u{0}\u{1}\n[[[\n");
        assert_eq!(doc.at(&["x", "v"]).and_then(Toml::as_str), Some("ok"));
        // Deeply nested arrays stop at the depth limit instead of overflowing the stack.
        let nested = format!("a = {}", "[".repeat(10_000));
        let _ = parse_toml(&nested);
    }

    #[test]
    fn setup_py_constants_concatenation_and_unknowns() {
        let args = parse_setup_py(
            "NAME = 'a' 'b'\nVER = '1.' + '2'\nREQ = ['x==1']\nsetup(name=NAME, version=VER,\n  install_requires=REQ + ['y>=2'],  # c\n  long_description=open('R').read(), keywords='a, b')\n",
        );
        assert!(args.found);
        assert_eq!(args.string("name").as_deref(), Some("ab"));
        assert_eq!(args.string("version").as_deref(), Some("1.2"));
        assert_eq!(
            args.strings("install_requires").unwrap(),
            vec!["x==1", "y>=2"]
        );
        assert_eq!(args.string("long_description"), None);
        assert!(!parse_setup_py("def setup(self):\n    pass\n# setup(name='x')\n").found);
        assert!(parse_setup_py("import setuptools\nsetuptools.setup(name='q')\n").found);
    }

    #[test]
    fn ini_values_continue_on_indented_lines() {
        let ini =
            parse_ini("[metadata]\nname=pkg\n[options]\ninstall_requires =\n    a==1\n    b\n");
        assert_eq!(ini.get("metadata", "name"), Some("pkg"));
        assert_eq!(ini.get("options", "install_requires"), Some("\na==1\nb"));
    }
}
