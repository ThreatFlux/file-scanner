use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::function_analysis::SymbolTable;
use crate::strings::ExtractedStrings;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAnalysisResult {
    pub dependencies: Vec<DependencyInfo>,
    pub dependency_graph: DependencyGraph,
    pub security_assessment: SecurityAssessment,
    pub license_summary: LicenseSummary,
    pub analysis_stats: DependencyAnalysisStats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub library_type: LibraryType,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub vulnerabilities: Vec<KnownVulnerability>,
    pub license: Option<LicenseInfo>,
    pub source: DependencySource,
    pub is_system_library: bool,
    pub imported_functions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LibraryType {
    StaticLibrary,
    DynamicLibrary,
    SystemLibrary,
    RuntimeLibrary,
    Framework,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum DependencySource {
    Import,          // From import table
    DynamicLink,     // From dynamic section
    StaticLink,      // Linked statically
    StringReference, // Found in strings
    RuntimeLoad,     // dlopen/LoadLibrary
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KnownVulnerability {
    pub cve_id: String,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_in: Option<String>,
    pub cvss_score: Option<f32>,
    pub published_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseInfo {
    pub license_type: String,
    pub license_family: LicenseFamily,
    pub is_oss: bool,
    pub is_copyleft: bool,
    pub is_commercial_friendly: bool,
    pub attribution_required: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum LicenseFamily {
    MIT,
    Apache,
    GPL,
    LGPL,
    BSD,
    Proprietary,
    PublicDomain,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyGraph {
    pub direct_dependencies: Vec<String>,
    pub transitive_dependencies: HashMap<String, Vec<String>>,
    pub dependency_tree: HashMap<String, Vec<String>>,
    pub dependency_depth: usize,
    pub total_dependencies: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityAssessment {
    pub vulnerable_dependencies: Vec<VulnerableDependency>,
    pub total_vulnerabilities: usize,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub outdated_dependencies: Vec<OutdatedDependency>,
    pub security_score: f32, // 0-100
    pub risk_level: SecurityRiskLevel,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerableDependency {
    pub dependency_name: String,
    pub current_version: Option<String>,
    pub vulnerabilities: Vec<String>, // CVE IDs
    pub highest_severity: VulnerabilitySeverity,
    pub recommended_action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutdatedDependency {
    pub dependency_name: String,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub versions_behind: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SecurityRiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseSummary {
    pub licenses_found: Vec<String>,
    pub license_conflicts: Vec<LicenseConflict>,
    pub copyleft_dependencies: Vec<String>,
    pub proprietary_dependencies: Vec<String>,
    pub compliance_issues: Vec<ComplianceIssue>,
    pub is_commercial_use_safe: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseConflict {
    pub dependency1: String,
    pub license1: String,
    pub dependency2: String,
    pub license2: String,
    pub conflict_reason: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ComplianceIssue {
    pub dependency: String,
    pub issue_type: ComplianceIssueType,
    pub description: String,
    pub severity: ComplianceSeverity,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ComplianceIssueType {
    MissingLicense,
    IncompatibleLicense,
    AttributionRequired,
    SourceCodeRequired,
    PatentConcern,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ComplianceSeverity {
    Blocking,
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyAnalysisStats {
    pub analysis_duration_ms: u64,
    pub total_dependencies_found: usize,
    pub libraries_analyzed: usize,
    pub vulnerabilities_checked: usize,
    pub licenses_identified: usize,
}

pub struct DependencyAnalyzer {
    vulnerability_db: VulnerabilityDatabase,
    license_detector: LicenseDetector,
}

struct VulnerabilityDatabase {
    known_vulnerabilities: HashMap<String, Vec<KnownVulnerability>>,
}

struct LicenseDetector {
    license_patterns: HashMap<String, Regex>,
}

impl DependencyAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            vulnerability_db: VulnerabilityDatabase::new(),
            license_detector: LicenseDetector::new(),
        };

        analyzer.load_vulnerability_database();
        analyzer
    }

    fn load_vulnerability_database(&mut self) {
        // Load known vulnerabilities for common libraries
        // In a real implementation, this would connect to NVD or other CVE databases

        // Example: OpenSSL vulnerabilities
        self.vulnerability_db.add_vulnerability(
            "openssl",
            KnownVulnerability {
                cve_id: "CVE-2014-0160".to_string(), // Heartbleed
                severity: VulnerabilitySeverity::Critical,
                description: "Heartbleed - allows remote attackers to obtain sensitive information"
                    .to_string(),
                affected_versions: vec![
                    "1.0.1".to_string(),
                    "1.0.1a".to_string(),
                    "1.0.1b".to_string(),
                    "1.0.1c".to_string(),
                    "1.0.1d".to_string(),
                    "1.0.1e".to_string(),
                    "1.0.1f".to_string(),
                ],
                fixed_in: Some("1.0.1g".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2014-04-07".to_string()),
            },
        );

        // Log4j vulnerability
        self.vulnerability_db.add_vulnerability(
            "log4j",
            KnownVulnerability {
                cve_id: "CVE-2021-44228".to_string(), // Log4Shell
                severity: VulnerabilitySeverity::Critical,
                description: "Log4Shell - Remote code execution vulnerability".to_string(),
                affected_versions: vec![
                    "2.0".to_string(),
                    "2.1".to_string(),
                    "2.2".to_string(),
                    "2.3".to_string(),
                    "2.4".to_string(),
                    "2.5".to_string(),
                    "2.6".to_string(),
                    "2.7".to_string(),
                    "2.8".to_string(),
                    "2.9".to_string(),
                    "2.10".to_string(),
                    "2.11".to_string(),
                    "2.12".to_string(),
                    "2.13".to_string(),
                    "2.14".to_string(),
                ],
                fixed_in: Some("2.15.0".to_string()),
                cvss_score: Some(10.0),
                published_date: Some("2021-12-10".to_string()),
            },
        );

        // zlib vulnerability
        self.vulnerability_db.add_vulnerability(
            "zlib",
            KnownVulnerability {
                cve_id: "CVE-2018-25032".to_string(),
                severity: VulnerabilitySeverity::High,
                description: "Memory corruption vulnerability".to_string(),
                affected_versions: vec!["1.2.11".to_string()],
                fixed_in: Some("1.2.12".to_string()),
                cvss_score: Some(7.5),
                published_date: Some("2022-03-25".to_string()),
            },
        );
    }

    pub fn analyze(
        &self,
        _path: &Path,
        symbol_table: &SymbolTable,
        extracted_strings: Option<&ExtractedStrings>,
    ) -> Result<DependencyAnalysisResult> {
        let start_time = std::time::Instant::now();
        let mut dependencies = Vec::new();
        let mut dependency_names = HashSet::new();

        // Analyze imports from symbol table
        for import in &symbol_table.imports {
            let dep_name = self.extract_library_name(&import.name);
            dependency_names.insert(dep_name.clone());

            let version = self.extract_version(&import.name, extracted_strings);
            let vulnerabilities = self
                .vulnerability_db
                .check_vulnerabilities(&dep_name, version.as_deref());
            let license = self.detect_license(&dep_name, extracted_strings);

            dependencies.push(DependencyInfo {
                name: dep_name,
                version,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities,
                license,
                source: DependencySource::Import,
                is_system_library: self.is_system_library(&import.name),
                imported_functions: vec![import.name.clone()],
            });
        }

        // Check for additional dependencies in strings
        if let Some(strings) = extracted_strings {
            self.analyze_string_dependencies(&mut dependencies, &mut dependency_names, strings)?;
        }

        // Build dependency graph
        let dependency_graph = self.build_dependency_graph(&dependencies);

        // Perform security assessment
        let security_assessment = self.assess_security(&dependencies);

        // Generate license summary
        let license_summary = self.summarize_licenses(&dependencies, extracted_strings);

        let duration = start_time.elapsed().as_millis() as u64;
        let total_vulnerabilities = security_assessment.total_vulnerabilities;
        let licenses_count = license_summary.licenses_found.len();

        Ok(DependencyAnalysisResult {
            dependencies,
            dependency_graph,
            security_assessment,
            license_summary,
            analysis_stats: DependencyAnalysisStats {
                analysis_duration_ms: duration,
                total_dependencies_found: dependency_names.len(),
                libraries_analyzed: dependency_names.len(),
                vulnerabilities_checked: total_vulnerabilities,
                licenses_identified: licenses_count,
            },
        })
    }

    fn extract_library_name(&self, import_name: &str) -> String {
        // Extract library name from function import
        // e.g., "printf@GLIBC_2.2.5" -> "glibc"
        if let Some(at_pos) = import_name.find('@') {
            let lib_part = &import_name[at_pos + 1..];
            if let Some(underscore_pos) = lib_part.find('_') {
                return lib_part[..underscore_pos].to_lowercase();
            }
            return lib_part.to_lowercase();
        }

        // Handle Windows-style imports (e.g., "kernel32.dll")
        if import_name.ends_with(".dll") {
            return import_name[..import_name.len() - 4].to_lowercase();
        }

        // Handle lib prefix (e.g., "libssl.so.1.1" -> "ssl")
        if import_name.starts_with("lib") && import_name.contains(".so") {
            if let Some(dot_pos) = import_name[3..].find('.') {
                return import_name[3..3 + dot_pos].to_string();
            }
        }

        import_name.to_lowercase()
    }

    fn extract_version(
        &self,
        import_name: &str,
        strings: Option<&ExtractedStrings>,
    ) -> Option<String> {
        // Try to extract version from import name
        let version_regex = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;

        if let Some(captures) = version_regex.captures(import_name) {
            return captures.get(1).map(|m| m.as_str().to_string());
        }

        // Search in strings for version information
        if let Some(strings) = strings {
            for string in &strings.ascii_strings {
                if string.contains("version") || string.contains("Version") {
                    if let Some(captures) = version_regex.captures(string) {
                        return captures.get(1).map(|m| m.as_str().to_string());
                    }
                }
            }
        }

        None
    }

    fn analyze_string_dependencies(
        &self,
        dependencies: &mut Vec<DependencyInfo>,
        dependency_names: &mut HashSet<String>,
        strings: &ExtractedStrings,
    ) -> Result<()> {
        // Look for library references in strings
        let lib_patterns = vec![
            r"lib(\w+)\.so(?:\.\d+)*",
            r"(\w+)\.dll",
            r"(\w+)\.dylib",
            r"lib(\w+)\.a",
        ];

        for pattern in lib_patterns {
            let regex = Regex::new(pattern)?;

            for string in &strings.ascii_strings {
                if let Some(captures) = regex.captures(string) {
                    if let Some(lib_name) = captures.get(1) {
                        let name = lib_name.as_str().to_lowercase();

                        if !dependency_names.contains(&name) && !self.is_common_file(&name) {
                            dependency_names.insert(name.clone());

                            let version = self.extract_version(string, Some(strings));
                            let vulnerabilities = self
                                .vulnerability_db
                                .check_vulnerabilities(&name, version.as_deref());
                            let license = self.detect_license(&name, Some(strings));

                            dependencies.push(DependencyInfo {
                                name,
                                version,
                                library_type: LibraryType::DynamicLibrary,
                                path: Some(string.clone()),
                                hash: None,
                                vulnerabilities,
                                license,
                                source: DependencySource::StringReference,
                                is_system_library: false,
                                imported_functions: Vec::new(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_system_library(&self, name: &str) -> bool {
        let system_libs = vec![
            "kernel32",
            "user32",
            "advapi32",
            "ntdll",
            "msvcrt", // Windows
            "libc",
            "libm",
            "libpthread",
            "libdl",
            "ld-linux", // Linux
            "libSystem",
            "libobjc",
            "CoreFoundation", // macOS
        ];

        let lower_name = name.to_lowercase();
        system_libs
            .iter()
            .any(|&lib| lower_name.contains(&lib.to_lowercase()))
    }

    fn is_common_file(&self, name: &str) -> bool {
        // Filter out common non-library files
        let common_files = ["config", "data", "cache", "tmp", "log", "pid"];
        common_files.iter().any(|&file| name.contains(file))
    }

    fn detect_license(
        &self,
        lib_name: &str,
        strings: Option<&ExtractedStrings>,
    ) -> Option<LicenseInfo> {
        // Simple license detection based on library name and strings
        let license = match lib_name {
            "openssl" => Some(("Apache-2.0", LicenseFamily::Apache)),
            "zlib" => Some(("Zlib", LicenseFamily::BSD)),
            "sqlite" => Some(("Public Domain", LicenseFamily::PublicDomain)),
            "boost" => Some(("BSL-1.0", LicenseFamily::BSD)),
            _ => None,
        };

        if let Some((license_type, family)) = license {
            return Some(LicenseInfo {
                license_type: license_type.to_string(),
                license_family: family.clone(),
                is_oss: true,
                is_copyleft: matches!(family, LicenseFamily::GPL | LicenseFamily::LGPL),
                is_commercial_friendly: !matches!(family, LicenseFamily::GPL),
                attribution_required: matches!(
                    family,
                    LicenseFamily::MIT | LicenseFamily::BSD | LicenseFamily::Apache
                ),
            });
        }

        // Try to detect license from strings
        if let Some(strings) = strings {
            self.license_detector.detect_from_strings(strings)
        } else {
            None
        }
    }

    fn build_dependency_graph(&self, dependencies: &[DependencyInfo]) -> DependencyGraph {
        let mut direct_deps = Vec::new();
        let mut dependency_tree = HashMap::new();

        for dep in dependencies {
            if dep.source == DependencySource::Import {
                direct_deps.push(dep.name.clone());
            }

            // Simple tree - in reality would need to analyze actual dependencies
            dependency_tree.insert(dep.name.clone(), Vec::new());
        }

        DependencyGraph {
            direct_dependencies: direct_deps,
            transitive_dependencies: HashMap::new(),
            dependency_tree,
            dependency_depth: 1,
            total_dependencies: dependencies.len(),
        }
    }

    fn assess_security(&self, dependencies: &[DependencyInfo]) -> SecurityAssessment {
        let mut vulnerable_deps = Vec::new();
        let mut total_vulns = 0;
        let mut critical_vulns = 0;
        let mut high_vulns = 0;

        for dep in dependencies {
            if !dep.vulnerabilities.is_empty() {
                let highest_severity = dep
                    .vulnerabilities
                    .iter()
                    .map(|v| &v.severity)
                    .max_by_key(|s| match s {
                        VulnerabilitySeverity::Critical => 4,
                        VulnerabilitySeverity::High => 3,
                        VulnerabilitySeverity::Medium => 2,
                        VulnerabilitySeverity::Low => 1,
                        VulnerabilitySeverity::None => 0,
                    })
                    .cloned()
                    .unwrap_or(VulnerabilitySeverity::None);

                vulnerable_deps.push(VulnerableDependency {
                    dependency_name: dep.name.clone(),
                    current_version: dep.version.clone(),
                    vulnerabilities: dep
                        .vulnerabilities
                        .iter()
                        .map(|v| v.cve_id.clone())
                        .collect(),
                    highest_severity: highest_severity.clone(),
                    recommended_action: self.get_recommended_action(&dep.name, &highest_severity),
                });

                total_vulns += dep.vulnerabilities.len();
                for vuln in &dep.vulnerabilities {
                    match vuln.severity {
                        VulnerabilitySeverity::Critical => critical_vulns += 1,
                        VulnerabilitySeverity::High => high_vulns += 1,
                        _ => {}
                    }
                }
            }
        }

        let security_score =
            self.calculate_security_score(dependencies, critical_vulns, high_vulns);
        let risk_level = self.determine_risk_level(security_score, critical_vulns);

        let mut recommendations = Vec::new();
        if critical_vulns > 0 {
            recommendations.push(
                "URGENT: Critical vulnerabilities found. Update affected dependencies immediately."
                    .to_string(),
            );
        }
        if high_vulns > 0 {
            recommendations.push(
                "High severity vulnerabilities detected. Plan updates within 24 hours.".to_string(),
            );
        }
        if vulnerable_deps.is_empty() {
            recommendations.push("No known vulnerabilities detected in dependencies.".to_string());
        }

        SecurityAssessment {
            vulnerable_dependencies: vulnerable_deps,
            total_vulnerabilities: total_vulns,
            critical_vulnerabilities: critical_vulns,
            high_vulnerabilities: high_vulns,
            outdated_dependencies: Vec::new(), // Would need version database
            security_score,
            risk_level,
            recommendations,
        }
    }

    fn get_recommended_action(&self, lib_name: &str, severity: &VulnerabilitySeverity) -> String {
        match severity {
            VulnerabilitySeverity::Critical => {
                format!(
                    "Immediately update {} to the latest patched version",
                    lib_name
                )
            }
            VulnerabilitySeverity::High => {
                format!("Update {} as soon as possible", lib_name)
            }
            VulnerabilitySeverity::Medium => {
                format!("Plan to update {} in your next release", lib_name)
            }
            _ => format!("Monitor {} for updates", lib_name),
        }
    }

    fn calculate_security_score(
        &self,
        dependencies: &[DependencyInfo],
        critical: usize,
        high: usize,
    ) -> f32 {
        if dependencies.is_empty() {
            return 100.0;
        }

        let vuln_deps = dependencies
            .iter()
            .filter(|d| !d.vulnerabilities.is_empty())
            .count();
        let vuln_ratio = vuln_deps as f32 / dependencies.len() as f32;

        let mut score = 100.0;
        score -= critical as f32 * 20.0;
        score -= high as f32 * 10.0;
        score -= vuln_ratio * 30.0;

        score.max(0.0)
    }

    fn determine_risk_level(&self, score: f32, critical_vulns: usize) -> SecurityRiskLevel {
        if critical_vulns > 0 || score < 30.0 {
            SecurityRiskLevel::Critical
        } else if score < 50.0 {
            SecurityRiskLevel::High
        } else if score < 70.0 {
            SecurityRiskLevel::Medium
        } else if score < 90.0 {
            SecurityRiskLevel::Low
        } else {
            SecurityRiskLevel::Minimal
        }
    }

    fn summarize_licenses(
        &self,
        dependencies: &[DependencyInfo],
        extracted_strings: Option<&ExtractedStrings>,
    ) -> LicenseSummary {
        let mut licenses_found = HashSet::new();
        let mut copyleft_deps = Vec::new();
        let mut proprietary_deps = Vec::new();
        let mut compliance_issues = Vec::new();

        // First, collect licenses from dependencies
        for dep in dependencies {
            if let Some(license) = &dep.license {
                licenses_found.insert(license.license_type.clone());

                if license.is_copyleft {
                    copyleft_deps.push(dep.name.clone());
                }

                if matches!(license.license_family, LicenseFamily::Proprietary) {
                    proprietary_deps.push(dep.name.clone());
                }

                // Check for missing attribution
                if license.attribution_required && dep.is_system_library {
                    compliance_issues.push(ComplianceIssue {
                        dependency: dep.name.clone(),
                        issue_type: ComplianceIssueType::AttributionRequired,
                        description: "Attribution required for this dependency".to_string(),
                        severity: ComplianceSeverity::Medium,
                    });
                }
            } else if !dep.is_system_library {
                compliance_issues.push(ComplianceIssue {
                    dependency: dep.name.clone(),
                    issue_type: ComplianceIssueType::MissingLicense,
                    description: "No license information found".to_string(),
                    severity: ComplianceSeverity::High,
                });
            }
        }

        // Also check for licenses directly in strings if provided
        if let Some(strings) = extracted_strings {
            self.detect_all_licenses_in_strings(strings, &mut licenses_found, &mut copyleft_deps);
        }

        let is_commercial_safe = copyleft_deps.is_empty() && proprietary_deps.is_empty();

        LicenseSummary {
            licenses_found: licenses_found.into_iter().collect(),
            license_conflicts: Vec::new(), // Would need more sophisticated analysis
            copyleft_dependencies: copyleft_deps,
            proprietary_dependencies: proprietary_deps,
            compliance_issues,
            is_commercial_use_safe: is_commercial_safe,
        }
    }

    fn detect_all_licenses_in_strings(
        &self,
        strings: &ExtractedStrings,
        licenses_found: &mut HashSet<String>,
        copyleft_deps: &mut Vec<String>,
    ) {
        // Check all strings against all license patterns
        for string in &strings.ascii_strings {
            for (license_type, pattern) in &self.license_detector.license_patterns {
                if pattern.is_match(string) {
                    licenses_found.insert(license_type.clone());

                    // Check if this is a copyleft license
                    let family = match license_type.as_str() {
                        "GPL-3.0" => LicenseFamily::GPL,
                        _ => continue, // Only GPL is copyleft in our current patterns
                    };

                    if matches!(family, LicenseFamily::GPL | LicenseFamily::LGPL) {
                        // Add a generic "string-detected" entry for copyleft licenses found in strings
                        let dep_name =
                            format!("license-in-strings-{}", license_type.to_lowercase());
                        if !copyleft_deps.contains(&dep_name) {
                            copyleft_deps.push(dep_name);
                        }
                    }
                }
            }
        }
    }
}

impl VulnerabilityDatabase {
    fn new() -> Self {
        Self {
            known_vulnerabilities: HashMap::new(),
        }
    }

    fn add_vulnerability(&mut self, library: &str, vulnerability: KnownVulnerability) {
        self.known_vulnerabilities
            .entry(library.to_string())
            .or_insert_with(Vec::new)
            .push(vulnerability);
    }

    fn check_vulnerabilities(
        &self,
        library: &str,
        version: Option<&str>,
    ) -> Vec<KnownVulnerability> {
        if let Some(vulns) = self.known_vulnerabilities.get(library) {
            if let Some(ver) = version {
                vulns
                    .iter()
                    .filter(|v| v.affected_versions.contains(&ver.to_string()))
                    .cloned()
                    .collect()
            } else {
                // If no version info, return all vulnerabilities for awareness
                vulns.clone()
            }
        } else {
            Vec::new()
        }
    }
}

impl LicenseDetector {
    fn new() -> Self {
        let mut patterns = HashMap::new();

        // Common license patterns
        patterns.insert("MIT".to_string(), Regex::new(r"(?i)mit\s+license").unwrap());
        patterns.insert(
            "Apache-2.0".to_string(),
            Regex::new(r"(?i)apache\s+license.*2\.0").unwrap(),
        );
        patterns.insert(
            "GPL-3.0".to_string(),
            Regex::new(r"(?i)gnu\s+general\s+public\s+license.*3").unwrap(),
        );
        patterns.insert(
            "BSD-3-Clause".to_string(),
            Regex::new(r"(?i)bsd\s+3-clause").unwrap(),
        );

        Self {
            license_patterns: patterns,
        }
    }

    fn detect_from_strings(&self, strings: &ExtractedStrings) -> Option<LicenseInfo> {
        for string in &strings.ascii_strings {
            for (license_type, pattern) in &self.license_patterns {
                if pattern.is_match(string) {
                    let family = match license_type.as_str() {
                        "MIT" => LicenseFamily::MIT,
                        "Apache-2.0" => LicenseFamily::Apache,
                        "GPL-3.0" => LicenseFamily::GPL,
                        "BSD-3-Clause" => LicenseFamily::BSD,
                        _ => LicenseFamily::Unknown,
                    };

                    return Some(LicenseInfo {
                        license_type: license_type.clone(),
                        license_family: family.clone(),
                        is_oss: true,
                        is_copyleft: matches!(family, LicenseFamily::GPL | LicenseFamily::LGPL),
                        is_commercial_friendly: !matches!(family, LicenseFamily::GPL),
                        attribution_required: true,
                    });
                }
            }
        }

        None
    }
}

pub fn analyze_dependencies(
    path: &Path,
    symbol_table: &SymbolTable,
    extracted_strings: Option<&ExtractedStrings>,
) -> Result<DependencyAnalysisResult> {
    let analyzer = DependencyAnalyzer::new();
    analyzer.analyze(path, symbol_table, extracted_strings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_analysis::{FunctionInfo, FunctionType, ImportInfo, SymbolCounts};

    fn create_test_symbol_table() -> SymbolTable {
        SymbolTable {
            functions: vec![FunctionInfo {
                name: "main".to_string(),
                address: 0x4000,
                size: 100,
                function_type: FunctionType::Local,
                calling_convention: None,
                parameters: vec![],
                is_entry_point: true,
                is_exported: false,
                is_imported: false,
            }],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![
                ImportInfo {
                    name: "printf@GLIBC_2.2.5".to_string(),
                    address: Some(0x1000),
                    library: Some("libc.so.6".to_string()),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "malloc@GLIBC_2.2.5".to_string(),
                    address: Some(0x1004),
                    library: Some("libc.so.6".to_string()),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "SSL_connect".to_string(),
                    address: Some(0x2000),
                    library: Some("libssl.so.1.1".to_string()),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "kernel32.dll".to_string(),
                    address: Some(0x3000),
                    library: Some("kernel32.dll".to_string()),
                    ordinal: None,
                    is_delayed: false,
                },
            ],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 1,
                local_functions: 1,
                imported_functions: 4,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        }
    }

    fn create_test_extracted_strings() -> ExtractedStrings {
        use crate::strings::InterestingString;

        ExtractedStrings {
            total_count: 11,
            unique_count: 11,
            ascii_strings: vec![
                "libssl.so.1.1".to_string(),
                "openssl version 1.0.1f".to_string(),
                "MIT License".to_string(),
                "log4j version 2.14".to_string(),
                "GNU General Public License version 3".to_string(),
                "Apache License 2.0".to_string(),
                "libconfig.so".to_string(),
                "libzlib.so.1.2.11".to_string(),
                "test.dll".to_string(),
                "libboost.a".to_string(),
                "sqlite3.dylib".to_string(),
            ],
            unicode_strings: vec![],
            interesting_strings: vec![InterestingString {
                category: "library".to_string(),
                value: "libssl.so.1.1".to_string(),
                offset: 100,
            }],
        }
    }

    #[test]
    fn test_dependency_analyzer_new() {
        let analyzer = DependencyAnalyzer::new();

        // Check that vulnerability database is populated
        assert!(!analyzer.vulnerability_db.known_vulnerabilities.is_empty());
        assert!(analyzer
            .vulnerability_db
            .known_vulnerabilities
            .contains_key("openssl"));
        assert!(analyzer
            .vulnerability_db
            .known_vulnerabilities
            .contains_key("log4j"));
        assert!(analyzer
            .vulnerability_db
            .known_vulnerabilities
            .contains_key("zlib"));
    }

    #[test]
    fn test_extract_library_name() {
        let analyzer = DependencyAnalyzer::new();

        // Test GLIBC versioned imports
        assert_eq!(analyzer.extract_library_name("printf@GLIBC_2.2.5"), "glibc");
        assert_eq!(analyzer.extract_library_name("malloc@LIBC_2.17"), "libc");

        // Test Windows DLL imports
        assert_eq!(analyzer.extract_library_name("kernel32.dll"), "kernel32");
        assert_eq!(analyzer.extract_library_name("USER32.dll"), "user32");

        // Test shared library format
        assert_eq!(analyzer.extract_library_name("libssl.so.1.1"), "ssl");
        assert_eq!(analyzer.extract_library_name("libcrypto.so"), "crypto");

        // Test plain function names
        assert_eq!(
            analyzer.extract_library_name("some_function"),
            "some_function"
        );
        assert_eq!(analyzer.extract_library_name("UPPERCASE"), "uppercase");
    }

    #[test]
    fn test_extract_version() {
        let analyzer = DependencyAnalyzer::new();
        let strings = create_test_extracted_strings();

        // Test version extraction from import name
        assert_eq!(
            analyzer.extract_version("printf@GLIBC_2.2.5", None),
            Some("2.2.5".to_string())
        );
        assert_eq!(
            analyzer.extract_version("libssl.so.1.1.0", None),
            Some("1.1.0".to_string())
        );

        // Test version extraction from strings that contain "version"
        // The function looks for any string containing "version" and extracts the first version pattern
        let any_version = analyzer.extract_version("any_lib", Some(&strings));
        assert!(any_version.is_some()); // Should find "1.0.1" from "openssl version 1.0.1f" (first match)

        // Test no version found
        assert_eq!(analyzer.extract_version("unknown_lib", None), None);

        // Test with strings that don't contain "version"
        let no_version_strings = ExtractedStrings {
            total_count: 1,
            unique_count: 1,
            ascii_strings: vec!["just a regular string".to_string()],
            unicode_strings: vec![],
            interesting_strings: vec![],
        };
        assert_eq!(
            analyzer.extract_version("no_version", Some(&no_version_strings)),
            None
        );
    }

    #[test]
    fn test_is_system_library() {
        let analyzer = DependencyAnalyzer::new();

        // Test Windows system libraries
        assert!(analyzer.is_system_library("kernel32.dll"));
        assert!(analyzer.is_system_library("KERNEL32"));
        assert!(analyzer.is_system_library("user32"));
        assert!(analyzer.is_system_library("ntdll"));
        assert!(analyzer.is_system_library("msvcrt"));

        // Test Linux system libraries
        assert!(analyzer.is_system_library("libc.so.6"));
        assert!(analyzer.is_system_library("libm"));
        assert!(analyzer.is_system_library("libpthread"));
        assert!(analyzer.is_system_library("ld-linux"));

        // Test macOS system libraries
        assert!(analyzer.is_system_library("libSystem"));
        assert!(analyzer.is_system_library("CoreFoundation"));

        // Test non-system libraries
        assert!(!analyzer.is_system_library("libssl"));
        assert!(!analyzer.is_system_library("custom_lib"));
    }

    #[test]
    fn test_is_common_file() {
        let analyzer = DependencyAnalyzer::new();

        // Test common file patterns
        assert!(analyzer.is_common_file("config"));
        assert!(analyzer.is_common_file("data_file"));
        assert!(analyzer.is_common_file("cache_dir"));
        assert!(analyzer.is_common_file("tmp_storage"));
        assert!(analyzer.is_common_file("log_file"));
        assert!(analyzer.is_common_file("pid_file"));

        // Test non-common files
        assert!(!analyzer.is_common_file("libssl"));
        assert!(!analyzer.is_common_file("important"));
    }

    #[test]
    fn test_detect_license() {
        let analyzer = DependencyAnalyzer::new();
        let strings = create_test_extracted_strings();

        // Test known library licenses
        let openssl_license = analyzer.detect_license("openssl", None);
        assert!(openssl_license.is_some());
        let license = openssl_license.unwrap();
        assert_eq!(license.license_type, "Apache-2.0");
        assert!(matches!(license.license_family, LicenseFamily::Apache));
        assert!(license.is_oss);
        assert!(!license.is_copyleft);
        assert!(license.is_commercial_friendly);

        let zlib_license = analyzer.detect_license("zlib", None);
        assert!(zlib_license.is_some());
        let license = zlib_license.unwrap();
        assert_eq!(license.license_type, "Zlib");
        assert!(matches!(license.license_family, LicenseFamily::BSD));

        let sqlite_license = analyzer.detect_license("sqlite", None);
        assert!(sqlite_license.is_some());
        let license = sqlite_license.unwrap();
        assert_eq!(license.license_type, "Public Domain");
        assert!(matches!(
            license.license_family,
            LicenseFamily::PublicDomain
        ));

        // Test license detection from strings
        let mit_license = analyzer.detect_license("unknown", Some(&strings));
        assert!(mit_license.is_some());
        let license = mit_license.unwrap();
        assert_eq!(license.license_type, "MIT");
        assert!(matches!(license.license_family, LicenseFamily::MIT));

        // Test unknown license
        let unknown_license = analyzer.detect_license("unknown_lib", None);
        assert!(unknown_license.is_none());
    }

    #[test]
    fn test_vulnerability_database() {
        let mut db = VulnerabilityDatabase::new();

        // Test adding vulnerability
        let vuln = KnownVulnerability {
            cve_id: "CVE-2023-1234".to_string(),
            severity: VulnerabilitySeverity::High,
            description: "Test vulnerability".to_string(),
            affected_versions: vec!["1.0.0".to_string(), "1.0.1".to_string()],
            fixed_in: Some("1.0.2".to_string()),
            cvss_score: Some(7.5),
            published_date: Some("2023-01-01".to_string()),
        };

        db.add_vulnerability("testlib", vuln.clone());

        // Test checking vulnerabilities with version
        let vulns = db.check_vulnerabilities("testlib", Some("1.0.0"));
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve_id, "CVE-2023-1234");

        // Test checking vulnerabilities without version
        let vulns = db.check_vulnerabilities("testlib", None);
        assert_eq!(vulns.len(), 1);

        // Test non-vulnerable version
        let vulns = db.check_vulnerabilities("testlib", Some("1.0.2"));
        assert_eq!(vulns.len(), 0);

        // Test unknown library
        let vulns = db.check_vulnerabilities("unknown", Some("1.0.0"));
        assert_eq!(vulns.len(), 0);
    }

    #[test]
    fn test_license_detector() {
        let detector = LicenseDetector::new();
        let strings = create_test_extracted_strings();

        // Test license detection from strings
        let license = detector.detect_from_strings(&strings);
        assert!(license.is_some());
        let license = license.unwrap();
        assert_eq!(license.license_type, "MIT");
        assert!(matches!(license.license_family, LicenseFamily::MIT));
        assert!(license.is_oss);
        assert!(!license.is_copyleft);
        assert!(license.is_commercial_friendly);
        assert!(license.attribution_required);

        // Test with strings containing no license information
        let empty_strings = ExtractedStrings {
            total_count: 1,
            unique_count: 1,
            ascii_strings: vec!["no license info here".to_string()],
            unicode_strings: vec![],
            interesting_strings: vec![],
        };

        let license = detector.detect_from_strings(&empty_strings);
        assert!(license.is_none());
    }

    #[test]
    fn test_analyze_string_dependencies() {
        let analyzer = DependencyAnalyzer::new();
        let strings = create_test_extracted_strings();
        let mut dependencies = Vec::new();
        let mut dependency_names = HashSet::new();

        let result = analyzer.analyze_string_dependencies(
            &mut dependencies,
            &mut dependency_names,
            &strings,
        );
        assert!(result.is_ok());

        // Check that dependencies were found
        assert!(!dependencies.is_empty());

        // Check for specific libraries found in strings
        let dep_names: Vec<&String> = dependencies.iter().map(|d| &d.name).collect();
        assert!(dep_names.contains(&&"ssl".to_string()));
        assert!(dep_names.contains(&&"zlib".to_string()));
        assert!(dep_names.contains(&&"boost".to_string()));

        // Check that config was filtered out (common file)
        assert!(!dep_names.contains(&&"config".to_string()));

        // Verify dependency properties
        let ssl_dep = dependencies.iter().find(|d| d.name == "ssl").unwrap();
        assert_eq!(ssl_dep.source, DependencySource::StringReference);
        assert!(!ssl_dep.is_system_library);
        assert!(ssl_dep.path.is_some());
    }

    #[test]
    fn test_build_dependency_graph() {
        let analyzer = DependencyAnalyzer::new();
        let dependencies = vec![
            DependencyInfo {
                name: "glibc".to_string(),
                version: Some("2.2.5".to_string()),
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: None,
                source: DependencySource::Import,
                is_system_library: true,
                imported_functions: vec!["printf".to_string()],
            },
            DependencyInfo {
                name: "ssl".to_string(),
                version: Some("1.1".to_string()),
                library_type: LibraryType::DynamicLibrary,
                path: Some("libssl.so.1.1".to_string()),
                hash: None,
                vulnerabilities: vec![],
                license: None,
                source: DependencySource::StringReference,
                is_system_library: false,
                imported_functions: vec![],
            },
        ];

        let graph = analyzer.build_dependency_graph(&dependencies);

        assert_eq!(graph.direct_dependencies.len(), 1);
        assert!(graph.direct_dependencies.contains(&"glibc".to_string()));
        assert_eq!(graph.total_dependencies, 2);
        assert_eq!(graph.dependency_depth, 1);
        assert!(graph.dependency_tree.contains_key("glibc"));
        assert!(graph.dependency_tree.contains_key("ssl"));
    }

    #[test]
    fn test_assess_security() {
        let analyzer = DependencyAnalyzer::new();

        // Create dependencies with vulnerabilities
        let vuln = KnownVulnerability {
            cve_id: "CVE-2014-0160".to_string(),
            severity: VulnerabilitySeverity::Critical,
            description: "Heartbleed".to_string(),
            affected_versions: vec!["1.0.1f".to_string()],
            fixed_in: Some("1.0.1g".to_string()),
            cvss_score: Some(7.5),
            published_date: Some("2014-04-07".to_string()),
        };

        let dependencies = vec![
            DependencyInfo {
                name: "openssl".to_string(),
                version: Some("1.0.1f".to_string()),
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![vuln],
                license: None,
                source: DependencySource::Import,
                is_system_library: false,
                imported_functions: vec![],
            },
            DependencyInfo {
                name: "safe_lib".to_string(),
                version: Some("2.0.0".to_string()),
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: None,
                source: DependencySource::Import,
                is_system_library: false,
                imported_functions: vec![],
            },
        ];

        let assessment = analyzer.assess_security(&dependencies);

        assert_eq!(assessment.vulnerable_dependencies.len(), 1);
        assert_eq!(assessment.total_vulnerabilities, 1);
        assert_eq!(assessment.critical_vulnerabilities, 1);
        assert_eq!(assessment.high_vulnerabilities, 0);
        assert!(matches!(assessment.risk_level, SecurityRiskLevel::Critical));
        assert!(assessment.security_score < 100.0);
        assert!(!assessment.recommendations.is_empty());

        let vuln_dep = &assessment.vulnerable_dependencies[0];
        assert_eq!(vuln_dep.dependency_name, "openssl");
        assert_eq!(vuln_dep.vulnerabilities, vec!["CVE-2014-0160"]);
        assert!(matches!(
            vuln_dep.highest_severity,
            VulnerabilitySeverity::Critical
        ));
    }

    #[test]
    fn test_get_recommended_action() {
        let analyzer = DependencyAnalyzer::new();

        let critical_action =
            analyzer.get_recommended_action("testlib", &VulnerabilitySeverity::Critical);
        assert!(critical_action.contains("Immediately update"));

        let high_action = analyzer.get_recommended_action("testlib", &VulnerabilitySeverity::High);
        assert!(high_action.contains("as soon as possible"));

        let medium_action =
            analyzer.get_recommended_action("testlib", &VulnerabilitySeverity::Medium);
        assert!(medium_action.contains("next release"));

        let low_action = analyzer.get_recommended_action("testlib", &VulnerabilitySeverity::Low);
        assert!(low_action.contains("Monitor"));
    }

    #[test]
    fn test_calculate_security_score() {
        let analyzer = DependencyAnalyzer::new();

        // Test with no dependencies
        let score = analyzer.calculate_security_score(&[], 0, 0);
        assert_eq!(score, 100.0);

        // Test with safe dependencies
        let safe_deps = vec![DependencyInfo {
            name: "safe".to_string(),
            version: None,
            library_type: LibraryType::DynamicLibrary,
            path: None,
            hash: None,
            vulnerabilities: vec![],
            license: None,
            source: DependencySource::Import,
            is_system_library: false,
            imported_functions: vec![],
        }];
        let score = analyzer.calculate_security_score(&safe_deps, 0, 0);
        assert_eq!(score, 100.0);

        // Test with critical vulnerabilities
        let score = analyzer.calculate_security_score(&safe_deps, 2, 0);
        assert_eq!(score, 60.0); // 100 - 2*20

        // Test with high vulnerabilities
        let score = analyzer.calculate_security_score(&safe_deps, 0, 3);
        assert_eq!(score, 70.0); // 100 - 3*10

        // Test score doesn't go below 0
        let score = analyzer.calculate_security_score(&safe_deps, 10, 10);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_determine_risk_level() {
        let analyzer = DependencyAnalyzer::new();

        assert!(matches!(
            analyzer.determine_risk_level(95.0, 0),
            SecurityRiskLevel::Minimal
        ));
        assert!(matches!(
            analyzer.determine_risk_level(75.0, 0),
            SecurityRiskLevel::Low
        ));
        assert!(matches!(
            analyzer.determine_risk_level(55.0, 0),
            SecurityRiskLevel::Medium
        ));
        assert!(matches!(
            analyzer.determine_risk_level(35.0, 0),
            SecurityRiskLevel::High
        ));
        assert!(matches!(
            analyzer.determine_risk_level(15.0, 0),
            SecurityRiskLevel::Critical
        ));
        assert!(matches!(
            analyzer.determine_risk_level(95.0, 1),
            SecurityRiskLevel::Critical
        ));
    }

    #[test]
    fn test_summarize_licenses() {
        let analyzer = DependencyAnalyzer::new();

        let mit_license = LicenseInfo {
            license_type: "MIT".to_string(),
            license_family: LicenseFamily::MIT,
            is_oss: true,
            is_copyleft: false,
            is_commercial_friendly: true,
            attribution_required: true,
        };

        let gpl_license = LicenseInfo {
            license_type: "GPL-3.0".to_string(),
            license_family: LicenseFamily::GPL,
            is_oss: true,
            is_copyleft: true,
            is_commercial_friendly: false,
            attribution_required: true,
        };

        let proprietary_license = LicenseInfo {
            license_type: "Proprietary".to_string(),
            license_family: LicenseFamily::Proprietary,
            is_oss: false,
            is_copyleft: false,
            is_commercial_friendly: false,
            attribution_required: false,
        };

        let dependencies = vec![
            DependencyInfo {
                name: "mit_lib".to_string(),
                version: None,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: Some(mit_license),
                source: DependencySource::Import,
                is_system_library: true,
                imported_functions: vec![],
            },
            DependencyInfo {
                name: "gpl_lib".to_string(),
                version: None,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: Some(gpl_license),
                source: DependencySource::Import,
                is_system_library: false,
                imported_functions: vec![],
            },
            DependencyInfo {
                name: "prop_lib".to_string(),
                version: None,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: Some(proprietary_license),
                source: DependencySource::Import,
                is_system_library: false,
                imported_functions: vec![],
            },
            DependencyInfo {
                name: "no_license".to_string(),
                version: None,
                library_type: LibraryType::DynamicLibrary,
                path: None,
                hash: None,
                vulnerabilities: vec![],
                license: None,
                source: DependencySource::Import,
                is_system_library: false,
                imported_functions: vec![],
            },
        ];

        let summary = analyzer.summarize_licenses(&dependencies, None);

        assert_eq!(summary.licenses_found.len(), 3);
        assert!(summary.licenses_found.contains(&"MIT".to_string()));
        assert!(summary.licenses_found.contains(&"GPL-3.0".to_string()));
        assert!(summary.licenses_found.contains(&"Proprietary".to_string()));

        assert_eq!(summary.copyleft_dependencies.len(), 1);
        assert!(summary
            .copyleft_dependencies
            .contains(&"gpl_lib".to_string()));

        assert_eq!(summary.proprietary_dependencies.len(), 1);
        assert!(summary
            .proprietary_dependencies
            .contains(&"prop_lib".to_string()));

        assert!(!summary.is_commercial_use_safe);

        // Check compliance issues
        assert!(!summary.compliance_issues.is_empty());
        let attribution_issue = summary
            .compliance_issues
            .iter()
            .find(|issue| matches!(issue.issue_type, ComplianceIssueType::AttributionRequired));
        assert!(attribution_issue.is_some());

        let missing_license_issue = summary
            .compliance_issues
            .iter()
            .find(|issue| matches!(issue.issue_type, ComplianceIssueType::MissingLicense));
        assert!(missing_license_issue.is_some());
    }

    #[test]
    fn test_full_analyze() {
        let symbol_table = create_test_symbol_table();
        let strings = create_test_extracted_strings();
        let path = Path::new("/test/binary");

        let analyzer = DependencyAnalyzer::new();
        let result = analyzer.analyze(&path, &symbol_table, Some(&strings));

        assert!(result.is_ok());
        let analysis = result.unwrap();

        // Check that analysis completed
        assert!(!analysis.dependencies.is_empty());
        assert!(analysis.analysis_stats.analysis_duration_ms > 0);
        assert!(analysis.analysis_stats.total_dependencies_found > 0);

        // Check that dependencies from both imports and strings were found
        let dep_names: Vec<&String> = analysis.dependencies.iter().map(|d| &d.name).collect();
        assert!(dep_names.contains(&&"glibc".to_string())); // from imports
        assert!(dep_names.contains(&&"ssl".to_string())); // from strings

        // Check security assessment
        assert!(analysis.security_assessment.security_score >= 0.0);
        assert!(analysis.security_assessment.security_score <= 100.0);

        // Check license summary
        assert!(!analysis.license_summary.licenses_found.is_empty());
    }

    #[test]
    fn test_analyze_dependencies_function() {
        let symbol_table = create_test_symbol_table();
        let strings = create_test_extracted_strings();
        let path = Path::new("/test/binary");

        let result = analyze_dependencies(&path, &symbol_table, Some(&strings));
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(!analysis.dependencies.is_empty());
        assert!(analysis.analysis_stats.analysis_duration_ms > 0);
    }

    #[test]
    fn test_serialization() {
        // Test that all data structures can be serialized/deserialized
        let vuln = KnownVulnerability {
            cve_id: "CVE-2023-1234".to_string(),
            severity: VulnerabilitySeverity::High,
            description: "Test vulnerability".to_string(),
            affected_versions: vec!["1.0.0".to_string()],
            fixed_in: Some("1.0.1".to_string()),
            cvss_score: Some(7.5),
            published_date: Some("2023-01-01".to_string()),
        };

        let license = LicenseInfo {
            license_type: "MIT".to_string(),
            license_family: LicenseFamily::MIT,
            is_oss: true,
            is_copyleft: false,
            is_commercial_friendly: true,
            attribution_required: true,
        };

        let dependency = DependencyInfo {
            name: "test_lib".to_string(),
            version: Some("1.0.0".to_string()),
            library_type: LibraryType::DynamicLibrary,
            path: Some("/path/to/lib".to_string()),
            hash: Some("abc123".to_string()),
            vulnerabilities: vec![vuln],
            license: Some(license),
            source: DependencySource::Import,
            is_system_library: false,
            imported_functions: vec!["func1".to_string()],
        };

        // Test JSON serialization
        let json = serde_json::to_string(&dependency);
        assert!(json.is_ok());

        let deserialized: Result<DependencyInfo, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());

        let dep = deserialized.unwrap();
        assert_eq!(dep.name, "test_lib");
        assert_eq!(dep.version, Some("1.0.0".to_string()));
        assert!(matches!(dep.library_type, LibraryType::DynamicLibrary));
        assert_eq!(dep.source, DependencySource::Import);
    }

    #[test]
    fn test_edge_cases() {
        let analyzer = DependencyAnalyzer::new();

        // Test with empty symbol table
        let empty_symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let result = analyzer.analyze(Path::new("/test"), &empty_symbol_table, None);
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert!(analysis.dependencies.is_empty());
        assert_eq!(analysis.security_assessment.total_vulnerabilities, 0);
        assert_eq!(analysis.security_assessment.security_score, 100.0);

        // Test with malformed import names
        let malformed_symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![
                ImportInfo {
                    name: "".to_string(),
                    address: None,
                    library: None,
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "@".to_string(),
                    address: None,
                    library: None,
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: ".dll".to_string(),
                    address: None,
                    library: None,
                    ordinal: None,
                    is_delayed: false,
                },
            ],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 3,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let result = analyzer.analyze(Path::new("/test"), &malformed_symbol_table, None);
        assert!(result.is_ok());

        // Test with empty strings
        let empty_strings = ExtractedStrings {
            total_count: 0,
            unique_count: 0,
            ascii_strings: vec![],
            unicode_strings: vec![],
            interesting_strings: vec![],
        };

        let result = analyzer.analyze(
            Path::new("/test"),
            &empty_symbol_table,
            Some(&empty_strings),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_vulnerability_severity_ordering() {
        // Test that severity comparison works correctly

        let critical = VulnerabilitySeverity::Critical;
        let _high = VulnerabilitySeverity::High;
        let medium = VulnerabilitySeverity::Medium;
        let low = VulnerabilitySeverity::Low;
        let _none = VulnerabilitySeverity::None;

        // Create vulnerabilities with different severities
        let vulnerabilities = vec![
            KnownVulnerability {
                cve_id: "CVE-1".to_string(),
                severity: low.clone(),
                description: "Low".to_string(),
                affected_versions: vec![],
                fixed_in: None,
                cvss_score: None,
                published_date: None,
            },
            KnownVulnerability {
                cve_id: "CVE-2".to_string(),
                severity: critical.clone(),
                description: "Critical".to_string(),
                affected_versions: vec![],
                fixed_in: None,
                cvss_score: None,
                published_date: None,
            },
            KnownVulnerability {
                cve_id: "CVE-3".to_string(),
                severity: medium.clone(),
                description: "Medium".to_string(),
                affected_versions: vec![],
                fixed_in: None,
                cvss_score: None,
                published_date: None,
            },
        ];

        // Find the highest severity
        let highest = vulnerabilities
            .iter()
            .map(|v| &v.severity)
            .max_by_key(|s| match s {
                VulnerabilitySeverity::Critical => 4,
                VulnerabilitySeverity::High => 3,
                VulnerabilitySeverity::Medium => 2,
                VulnerabilitySeverity::Low => 1,
                VulnerabilitySeverity::None => 0,
            });

        assert!(highest.is_some());
        assert!(matches!(highest.unwrap(), VulnerabilitySeverity::Critical));
    }
}
