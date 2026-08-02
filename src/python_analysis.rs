use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;
use zip::ZipArchive;

use crate::dependency_analysis::{KnownVulnerability, VulnerabilitySeverity};
use crate::python_vuln_db::{
    check_package_vulnerabilities, check_typosquatting_similarity, get_known_malicious_packages,
    get_malicious_patterns,
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyDetails {
    pub version_spec: String,
    pub is_pinned: bool,
    pub is_url: bool,
    pub is_git: bool,
    pub vulnerabilities: Vec<KnownVulnerability>,
    pub deprecated: bool,
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

/// Main entry point for Python package analysis
pub fn analyze_python_package(path: &Path) -> Result<PythonPackageAnalysis> {
    if path.is_file() {
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        match extension {
            "whl" => analyze_wheel_package(path),
            "gz" => analyze_tar_package(path),
            "zip" => analyze_zip_package(path),
            _ => anyhow::bail!("Unsupported file type. Expected .whl, .tar.gz, or .zip"),
        }
    } else if path.is_dir() {
        analyze_python_directory(path)
    } else {
        anyhow::bail!("Path must be either a Python package file or a directory")
    }
}

/// Analyze a wheel package
fn analyze_wheel_package(wheel_path: &Path) -> Result<PythonPackageAnalysis> {
    let file = File::open(wheel_path).context("Failed to open wheel file")?;
    let mut zip = ZipArchive::new(file).context("Failed to read wheel as zip")?;

    let mut metadata_content = None;
    let mut files = Vec::new();

    // Extract metadata and collect files
    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();

        if name.ends_with("/METADATA") {
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            metadata_content = Some(content);
        }

        files.push(PythonFileAnalysis {
            file_path: name.clone(),
            file_type: detect_python_file_type(&name),
            size: file.size(),
            suspicious_content: vec![],
            imports: vec![],
            obfuscation_score: 0.0,
        });
    }

    let metadata = metadata_content.ok_or_else(|| anyhow::anyhow!("No METADATA found in wheel"))?;

    analyze_package_with_metadata(&metadata, files, PackageFormat::Wheel)
}

/// Analyze a tar.gz package
fn analyze_tar_package(tar_path: &Path) -> Result<PythonPackageAnalysis> {
    let file = File::open(tar_path).context("Failed to open tar.gz file")?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut setup_py_content = None;
    let mut setup_cfg_content = None;
    let mut pyproject_toml_content = None;
    let mut pkg_info_content = None;
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().to_string();

        if path.ends_with("setup.py") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            setup_py_content = Some(content);
        } else if path.ends_with("setup.cfg") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            setup_cfg_content = Some(content);
        } else if path.ends_with("pyproject.toml") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            pyproject_toml_content = Some(content);
        } else if path.ends_with("PKG-INFO") {
            let mut content = String::new();
            entry.read_to_string(&mut content)?;
            pkg_info_content = Some(content);
        }

        files.push(PythonFileAnalysis {
            file_path: path.clone(),
            file_type: detect_python_file_type(&path),
            size: entry.size(),
            suspicious_content: vec![],
            imports: vec![],
            obfuscation_score: 0.0,
        });
    }

    analyze_package_with_files(
        setup_py_content,
        setup_cfg_content,
        pyproject_toml_content,
        pkg_info_content,
        files,
        PackageFormat::SourceDistribution,
    )
}

/// Analyze a zip package
fn analyze_zip_package(zip_path: &Path) -> Result<PythonPackageAnalysis> {
    let file = File::open(zip_path).context("Failed to open zip file")?;
    let mut zip = ZipArchive::new(file).context("Failed to read zip")?;

    let mut setup_py_content = None;
    let mut files = Vec::new();

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let name = file.name().to_string();

        if name.ends_with("setup.py") {
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            setup_py_content = Some(content);
        }

        files.push(PythonFileAnalysis {
            file_path: name.clone(),
            file_type: detect_python_file_type(&name),
            size: file.size(),
            suspicious_content: vec![],
            imports: vec![],
            obfuscation_score: 0.0,
        });
    }

    analyze_package_with_files(
        setup_py_content,
        None,
        None,
        None,
        files,
        PackageFormat::SourceDistribution,
    )
}

/// Analyze a Python directory
fn analyze_python_directory(dir_path: &Path) -> Result<PythonPackageAnalysis> {
    let setup_py_path = dir_path.join("setup.py");
    let setup_cfg_path = dir_path.join("setup.cfg");
    let pyproject_toml_path = dir_path.join("pyproject.toml");

    let setup_py_content = if setup_py_path.exists() {
        Some(std::fs::read_to_string(&setup_py_path)?)
    } else {
        None
    };

    let setup_cfg_content = if setup_cfg_path.exists() {
        Some(std::fs::read_to_string(&setup_cfg_path)?)
    } else {
        None
    };

    let pyproject_toml_content = if pyproject_toml_path.exists() {
        Some(std::fs::read_to_string(&pyproject_toml_path)?)
    } else {
        None
    };

    if setup_py_content.is_none() && setup_cfg_content.is_none() && pyproject_toml_content.is_none()
    {
        anyhow::bail!("No setup.py, setup.cfg, or pyproject.toml found in directory");
    }

    // Scan directory for Python files
    let mut files = vec![];
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                files.push(PythonFileAnalysis {
                    file_path: file_name,
                    file_type: detect_python_file_type(&path.to_string_lossy()),
                    size: entry.metadata().map_or(0, |m| m.len()),
                    suspicious_content: vec![],
                    imports: vec![],
                    obfuscation_score: 0.0,
                });
            }
        }

        // Also recursively check common subdirectories
        for subdir in &["tests", ".github", ".circleci"] {
            let subdir_path = dir_path.join(subdir);
            if subdir_path.is_dir() {
                scan_directory_recursive(&subdir_path, &mut files, subdir)?;
            }
        }
    }

    analyze_package_with_files(
        setup_py_content,
        setup_cfg_content,
        pyproject_toml_content,
        None,
        files,
        PackageFormat::Directory,
    )
}

/// Analyze package with metadata content (for wheel packages)
fn analyze_package_with_metadata(
    metadata: &str,
    files: Vec<PythonFileAnalysis>,
    _format: PackageFormat,
) -> Result<PythonPackageAnalysis> {
    let package_info = parse_wheel_metadata(metadata)?;
    let dependencies = analyze_dependencies_from_metadata(metadata)?;
    let setup_analysis = SetupAnalysis {
        setup_type: SetupType::PyProjectToml,
        setup_commands: vec![],
        custom_commands: HashMap::new(),
        dangerous_operations: vec![],
        external_downloads: vec![],
    };

    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &files, &setup_analysis)?;
    let malicious_indicators =
        detect_malicious_indicators(&package_info, &dependencies, &security_analysis)?;
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
    })
}

/// Analyze package with various setup files
fn analyze_package_with_files(
    setup_py: Option<String>,
    setup_cfg: Option<String>,
    pyproject_toml: Option<String>,
    pkg_info: Option<String>,
    files: Vec<PythonFileAnalysis>,
    _format: PackageFormat,
) -> Result<PythonPackageAnalysis> {
    // Extract package info from available sources
    let package_info = if let Some(ref content) = pyproject_toml {
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

    // Analyze dependencies
    let dependencies = analyze_dependencies(&setup_py, &setup_cfg, &pyproject_toml)?;

    // Analyze setup scripts
    let setup_analysis = analyze_setup_scripts(&setup_py, &setup_cfg, &pyproject_toml)?;

    // Perform security analysis
    let security_analysis =
        perform_security_analysis(&package_info, &dependencies, &files, &setup_analysis)?;

    // Detect malicious indicators
    let malicious_indicators =
        detect_malicious_indicators(&package_info, &dependencies, &security_analysis)?;

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
    })
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

    for line in metadata.lines() {
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
    for line in metadata.lines() {
        if line.starts_with("Requires-Dist: ") {
            let dep_spec = line.trim_start_matches("Requires-Dist: ");

            // Skip dependencies with environment markers for extras
            if dep_spec.contains("; extra ==") || dep_spec.contains(";extra==") {
                continue;
            }

            let (name, version_spec) = parse_dependency_spec(dep_spec);

            let vulnerabilities = check_package_vulnerabilities(&name, &version_spec);

            install_requires.insert(
                name,
                DependencyDetails {
                    version_spec,
                    is_pinned: false, // TODO: Check if version is pinned
                    is_url: false,
                    is_git: false,
                    vulnerabilities,
                    deprecated: false,
                },
            );
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
    })
}

/// Analyze dependencies from various setup files
fn analyze_dependencies(
    setup_py: &Option<String>,
    setup_cfg: &Option<String>,
    pyproject_toml: &Option<String>,
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
            let vulnerabilities = check_package_vulnerabilities(&name, &version_spec);

            install_requires.insert(
                name,
                DependencyDetails {
                    version_spec: version_spec.clone(),
                    is_pinned: version_spec.contains("=="),
                    is_url: dep.starts_with("http"),
                    is_git: dep.contains("git+"),
                    vulnerabilities,
                    deprecated: false,
                },
            );
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
            let vulnerabilities = check_package_vulnerabilities(&name, &version_spec);

            install_requires.insert(
                name,
                DependencyDetails {
                    version_spec: version_spec.clone(),
                    is_pinned: version_spec.contains("=="),
                    is_url: dep.starts_with("http"),
                    is_git: dep.contains("git+"),
                    vulnerabilities,
                    deprecated: false,
                },
            );
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
            let vulnerabilities = check_package_vulnerabilities(&name, &version_spec);

            install_requires.insert(
                name,
                DependencyDetails {
                    version_spec,
                    is_pinned: false,
                    is_url: false,
                    is_git: false,
                    vulnerabilities,
                    deprecated: false,
                },
            );
        }
        // Parse dependencies in [tool.poetry.dependencies] format
        else if in_dependencies && line.contains('=') {
            if let Some((name, version)) = line.split_once('=') {
                let name = name.trim().trim_matches('"');
                if name == "python" {
                    continue; // Skip python version requirement
                }
                let version_spec = version.trim().trim_matches('"').trim_matches('^');
                let vulnerabilities = check_package_vulnerabilities(name, version_spec);

                install_requires.insert(
                    name.to_string(),
                    DependencyDetails {
                        version_spec: version_spec.to_string(),
                        is_pinned: version_spec.contains("=="),
                        is_url: false,
                        is_git: false,
                        vulnerabilities,
                        deprecated: false,
                    },
                );
            }
        }
    }

    Ok(())
}

/// Parse dependency specification
fn parse_dependency_spec(spec: &str) -> (String, String) {
    // Handle various formats: package==1.0, package>=1.0, package[extra]>=1.0
    let spec = spec.trim();

    // Remove extras
    let spec_no_extras = if let Some(idx) = spec.find('[') {
        if let Some(end_idx) = spec.find(']') {
            format!("{}{}", &spec[..idx], &spec[end_idx + 1..])
        } else {
            spec.to_string()
        }
    } else {
        spec.to_string()
    };

    // Find version specifier
    for op in &["==", ">=", "<=", ">", "<", "~=", "!="] {
        if let Some(idx) = spec_no_extras.find(op) {
            let name = spec_no_extras[..idx].trim();
            let version = spec_no_extras[idx..].trim();
            return (name.to_string(), version.to_string());
        }
    }

    // No version specifier
    (spec_no_extras.trim().to_string(), "*".to_string())
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
    };

    for (name, details) in dependencies {
        if !details.vulnerabilities.is_empty() {
            summary.vulnerable_packages.push(name.clone());
            summary.total_count += details.vulnerabilities.len();

            for vuln in &details.vulnerabilities {
                match vuln.severity {
                    VulnerabilitySeverity::Critical => summary.critical_count += 1,
                    VulnerabilitySeverity::High => summary.high_count += 1,
                    VulnerabilitySeverity::Medium => summary.medium_count += 1,
                    VulnerabilitySeverity::Low => summary.low_count += 1,
                    VulnerabilitySeverity::None => {}
                }
            }
        }
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
) -> Result<PythonSecurityAnalysis> {
    let has_setup_script = matches!(setup_analysis.setup_type, SetupType::SetupPy);
    let has_install_script = !setup_analysis.setup_commands.is_empty();
    let has_post_install = setup_analysis
        .setup_commands
        .iter()
        .any(|cmd| cmd.command_name.contains("install"));

    let suspicious_imports = detect_suspicious_imports(files, setup_analysis);
    let network_access_patterns = detect_network_patterns(files, setup_analysis);
    let file_system_access = detect_filesystem_patterns(files, setup_analysis);
    let process_execution = detect_process_execution(files, setup_analysis);

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

    let crypto_mining_indicators = detect_crypto_mining(files, &suspicious_imports);
    let data_exfiltration_risk = detect_data_exfiltration(&network_access_patterns);
    let backdoor_indicators = detect_backdoor_indicators(files, &process_execution);

    let supply_chain_risk_score = calculate_supply_chain_risk(
        package_info,
        dependencies,
        setup_analysis,
        &network_access_patterns,
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

/// Detect crypto mining
const fn detect_crypto_mining(
    _files: &[PythonFileAnalysis],
    _imports: &[SuspiciousImport],
) -> bool {
    false // TODO: Implement
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

    if !process_execution.is_empty() {
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

/// Detect malicious indicators
fn detect_malicious_indicators(
    package_info: &PackageInfo,
    _dependencies: &PythonDependencyAnalysis,
    security: &PythonSecurityAnalysis,
) -> Result<MaliciousPackageIndicators> {
    let typosquatting_risk = analyze_typosquatting(&package_info.name);
    let dependency_confusion_risk = check_dependency_confusion(package_info);
    let known_malicious_patterns = detect_known_malicious_patterns(package_info, security);
    let suspicious_maintainer_activity = false; // TODO: Implement
    let code_injection_patterns = detect_code_injection_patterns(security);

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
        overall_risk_score: overall_risk_score.min(100.0),
        risk_level,
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
) -> Vec<MaliciousPattern> {
    let mut patterns = vec![];

    // Check for known malicious patterns from database
    let _db_patterns = get_malicious_patterns();

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
        patterns.push(MaliciousPattern {
            pattern_type: "Crypto mining".to_string(),
            description: "Package contains crypto mining indicators".to_string(),
            found_in: "package files".to_string(),
            severity: "Critical".to_string(),
            evidence: "Mining-related code detected".to_string(),
        });
    }

    patterns
}

/// Detect code injection patterns
fn detect_code_injection_patterns(security: &PythonSecurityAnalysis) -> Vec<CodeInjectionPattern> {
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

/// Recursively scan directory for Python files
fn scan_directory_recursive(
    dir_path: &Path,
    files: &mut Vec<PythonFileAnalysis>,
    prefix: &str,
) -> Result<()> {
    if let Ok(entries) = std::fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let file_name = format!(
                    "{}/{}",
                    prefix,
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("")
                );

                files.push(PythonFileAnalysis {
                    file_path: file_name,
                    file_type: detect_python_file_type(&path.to_string_lossy()),
                    size: entry.metadata().map_or(0, |m| m.len()),
                    suspicious_content: vec![],
                    imports: vec![],
                    obfuscation_score: 0.0,
                });
            } else if path.is_dir() {
                let subdir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let new_prefix = format!("{prefix}/{subdir_name}");
                scan_directory_recursive(&path, files, &new_prefix)?;
            }
        }
    }
    Ok(())
}
