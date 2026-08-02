//! Java package analyzer

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use zip::ZipArchive;

use crate::core::dependency::VulnerabilitySummary;
use crate::core::{
    AnalysisResult, Dependency, DependencyAnalysis, DependencyType, MaliciousPattern,
    PackageAnalyzer, PackageInfo, PackageMetadata, PatternMatcher, RiskAssessment, RiskCalculator,
    Vulnerability,
};
use crate::utils::typosquatting::TyposquattingDetector;
use crate::vulnerability_db::VulnerabilityDatabase;

/// Java package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaPackage {
    pub metadata: PackageMetadata,
    pub archive_type: JavaArchiveType,
    pub main_class: Option<String>,
    pub manifest_attributes: HashMap<String, String>,
    pub is_signed: bool,
    pub android_info: Option<AndroidInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JavaArchiveType {
    Jar,
    War,
    Ear,
    Apk,
    Aar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidInfo {
    pub package_name: String,
    pub version_code: Option<u32>,
    pub permissions: Vec<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
}

impl PackageInfo for JavaPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "java"
    }

    fn custom_attributes(&self) -> HashMap<String, serde_json::Value> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "archive_type".to_string(),
            serde_json::json!(self.archive_type),
        );
        attrs.insert("main_class".to_string(), serde_json::json!(self.main_class));
        attrs.insert("is_signed".to_string(), serde_json::json!(self.is_signed));
        if let Some(android) = &self.android_info {
            attrs.insert("android_info".to_string(), serde_json::json!(android));
        }
        attrs
    }
}

/// Java analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaAnalysisResult {
    pub package: JavaPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub security_analysis: JavaSecurityAnalysis,
}

impl AnalysisResult for JavaAnalysisResult {
    fn package_info(&self) -> &dyn PackageInfo {
        &self.package
    }

    fn risk_assessment(&self) -> &RiskAssessment {
        &self.risk_assessment
    }

    fn dependency_analysis(&self) -> &DependencyAnalysis {
        &self.dependency_analysis
    }

    fn vulnerabilities(&self) -> &[Vulnerability] {
        &self.vulnerabilities
    }

    fn malicious_patterns(&self) -> &[MaliciousPattern] {
        &self.malicious_patterns
    }

    fn to_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(self)?)
    }
}

/// Java-specific security analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JavaSecurityAnalysis {
    pub uses_reflection: bool,
    pub uses_jni: bool,
    pub has_native_libraries: bool,
    pub dangerous_permissions: Vec<String>,
    pub suspicious_apis: Vec<String>,
    pub certificate_issues: Vec<String>,
}

/// Java package analyzer
pub struct JavaAnalyzer {
    vuln_db: Box<dyn VulnerabilityDatabase>,
    pattern_matcher: PatternMatcher,
    _typo_detector: TyposquattingDetector,
}

impl JavaAnalyzer {
    /// Create a new Java analyzer
    pub fn new() -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_java_database()?,
            pattern_matcher: PatternMatcher::new()?,
            _typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Create analyzer with custom database path
    pub fn with_db_path(db_path: &Path) -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_java_database_with_path(db_path)?,
            pattern_matcher: PatternMatcher::new()?,
            _typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Detect archive type from file extension
    fn detect_archive_type(&self, path: &Path) -> JavaArchiveType {
        match path.extension().and_then(|e| e.to_str()) {
            Some("jar") => JavaArchiveType::Jar,
            Some("war") => JavaArchiveType::War,
            Some("ear") => JavaArchiveType::Ear,
            Some("apk") => JavaArchiveType::Apk,
            Some("aar") => JavaArchiveType::Aar,
            _ => JavaArchiveType::Jar, // Default
        }
    }

    /// Parse Java archive
    async fn parse_archive(&self, path: &Path) -> Result<JavaPackage> {
        let file = tokio::fs::File::open(path).await?;
        let file = file.into_std().await;
        let mut archive = ZipArchive::new(file)?;

        let archive_type = self.detect_archive_type(path);
        let mut manifest_attributes = HashMap::new();
        let mut main_class = None;
        let mut is_signed = false;
        let android_info = None;

        // Read manifest
        if let Ok(mut manifest_file) = archive.by_name("META-INF/MANIFEST.MF") {
            let mut content = String::new();
            std::io::Read::read_to_string(&mut manifest_file, &mut content)?;

            for line in content.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim();
                    let value = value.trim();
                    manifest_attributes.insert(key.to_string(), value.to_string());

                    if key == "Main-Class" {
                        main_class = Some(value.to_string());
                    }
                }
            }
        }

        // Check if signed
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name();
            if name.starts_with("META-INF/")
                && (name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".EC"))
            {
                is_signed = true;
                break;
            }
        }

        // Extract metadata
        let metadata = PackageMetadata {
            name: path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            version: manifest_attributes
                .get("Implementation-Version")
                .or_else(|| manifest_attributes.get("Bundle-Version"))
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            description: manifest_attributes
                .get("Bundle-Description")
                .or_else(|| manifest_attributes.get("Implementation-Title"))
                .cloned(),
            author: manifest_attributes
                .get("Implementation-Vendor")
                .or_else(|| manifest_attributes.get("Bundle-Vendor"))
                .cloned(),
            license: manifest_attributes.get("Bundle-License").cloned(),
            homepage: manifest_attributes.get("Bundle-DocURL").cloned(),
            repository: None,
            keywords: vec![],
            publish_date: None,
        };

        Ok(JavaPackage {
            metadata,
            archive_type,
            main_class,
            manifest_attributes,
            is_signed,
            android_info,
        })
    }

    /// Parse Maven project metadata from pom.xml
    async fn parse_project(&self, path: &Path) -> Result<JavaPackage> {
        let pom_path = path.join("pom.xml");
        let content = tokio::fs::read_to_string(&pom_path).await?;
        let artifact_id =
            extract_xml_text(&content, "artifactId").unwrap_or_else(|| "unknown".to_string());
        let version =
            extract_xml_text(&content, "version").unwrap_or_else(|| "unknown".to_string());
        let group_id = extract_xml_text(&content, "groupId");

        Ok(JavaPackage {
            metadata: PackageMetadata {
                name: artifact_id,
                version,
                description: None,
                author: group_id,
                license: None,
                homepage: None,
                repository: None,
                keywords: Vec::new(),
                publish_date: None,
            },
            archive_type: JavaArchiveType::Jar,
            main_class: None,
            manifest_attributes: HashMap::new(),
            is_signed: false,
            android_info: None,
        })
    }

    /// Analyze dependencies (from pom.xml or gradle files if present)
    async fn analyze_dependencies(&self, path: &Path) -> Result<DependencyAnalysis> {
        let mut analysis = DependencyAnalysis::default();
        if !path.is_dir() || !path.join("pom.xml").exists() {
            return Ok(analysis);
        }

        let content = tokio::fs::read_to_string(path.join("pom.xml")).await?;
        let dependency_re = regex::Regex::new(r"(?s)<dependency>\s*(.*?)\s*</dependency>")?;
        for dependency in dependency_re.captures_iter(&content) {
            let Some(block) = dependency.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(artifact_id) = extract_xml_text(block, "artifactId") else {
                continue;
            };
            let version = extract_xml_text(block, "version").unwrap_or_else(|| "*".to_string());
            let vulnerabilities = self
                .vuln_db
                .check_package(&artifact_id, &version, "java")
                .await?;

            analysis.dependency_tree.push(Dependency {
                name: artifact_id.clone(),
                version_spec: version,
                resolved_version: None,
                dependency_type: DependencyType::Runtime,
                is_direct: true,
                is_dev: false,
                vulnerabilities,
                license: None,
                dependencies: Vec::new(),
            });
            analysis.direct_dependencies += 1;
        }

        analysis.total_dependencies = analysis.dependency_tree.len();
        summarize_dependency_vulnerabilities(
            &mut analysis.vulnerability_summary,
            &analysis.dependency_tree,
        );

        Ok(analysis)
    }

    /// Analyze security aspects
    fn analyze_security(
        &self,
        archive: &mut ZipArchive<std::fs::File>,
    ) -> Result<JavaSecurityAnalysis> {
        let mut analysis = JavaSecurityAnalysis {
            uses_reflection: false,
            uses_jni: false,
            has_native_libraries: false,
            dangerous_permissions: vec![],
            suspicious_apis: vec![],
            certificate_issues: vec![],
        };

        // Check for native libraries
        for i in 0..archive.len() {
            let file = archive.by_index(i)?;
            let name = file.name();

            if name.ends_with(".so") || name.ends_with(".dll") || name.ends_with(".dylib") {
                analysis.has_native_libraries = true;
            }

            // TODO: Parse class files to detect reflection and suspicious API usage
        }

        Ok(analysis)
    }
}

fn summarize_dependency_vulnerabilities(
    summary: &mut VulnerabilitySummary,
    dependencies: &[Dependency],
) {
    for dependency in dependencies {
        for vulnerability in &dependency.vulnerabilities {
            summary.total_vulnerabilities += 1;
            match vulnerability.severity {
                crate::core::VulnerabilitySeverity::Critical => summary.critical_count += 1,
                crate::core::VulnerabilitySeverity::High => summary.high_count += 1,
                crate::core::VulnerabilitySeverity::Medium => summary.medium_count += 1,
                crate::core::VulnerabilitySeverity::Low => summary.low_count += 1,
                crate::core::VulnerabilitySeverity::None => {}
            }
            if !summary.vulnerable_dependencies.contains(&dependency.name) {
                summary
                    .vulnerable_dependencies
                    .push(dependency.name.clone());
            }
        }
    }
}

#[async_trait]
impl PackageAnalyzer for JavaAnalyzer {
    type Package = JavaPackage;
    type Analysis = JavaAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        let package = if path.is_dir() {
            self.parse_project(path).await?
        } else {
            self.parse_archive(path).await?
        };
        let dependency_analysis = self.analyze_dependencies(path).await?;

        let security_analysis = if path.is_dir() {
            JavaSecurityAnalysis::default()
        } else {
            let file = std::fs::File::open(path)?;
            let mut archive = ZipArchive::new(file)?;
            self.analyze_security(&mut archive)?
        };

        // Check for malicious patterns in manifest
        let manifest_content = serde_json::to_string(&package.manifest_attributes)?;
        let malicious_patterns = self
            .pattern_matcher
            .scan(&manifest_content, Some("MANIFEST.MF"));

        // Collect all vulnerabilities
        let mut vulnerabilities = vec![];
        for dep in &dependency_analysis.dependency_tree {
            vulnerabilities.extend(dep.vulnerabilities.clone());
        }

        // Calculate risk assessment
        let risk_calculator = RiskCalculator::new();
        let supply_chain_score = if security_analysis.has_native_libraries {
            30.0
        } else {
            0.0
        };

        let risk_score = risk_calculator.calculate(
            &vulnerabilities,
            &malicious_patterns,
            false, // TODO: Check typosquatting for Java packages
            supply_chain_score,
            50.0, // Default maintenance score
        );

        let risk_assessment = RiskAssessment {
            risk_score: risk_score.clone(),
            summary: format!(
                "Java archive '{}' has {} risk",
                package.metadata.name, risk_score.risk_level
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerabilities_present: !vulnerabilities.is_empty(),
                malicious_code_detected: !malicious_patterns.is_empty(),
                supply_chain_risks: security_analysis.has_native_libraries,
                actively_maintained: true,
                trusted_publisher: package.is_signed,
                security_practices_score: if package.is_signed { 70.0 } else { 30.0 },
            },
        };

        Ok(JavaAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            vulnerabilities,
            malicious_patterns,
            security_analysis,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("pom.xml").exists() || path.join("build.gradle").exists()
        } else {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| matches!(ext, "jar" | "war" | "ear" | "apk" | "aar"))
                .unwrap_or(false)
        }
    }

    fn name(&self) -> &str {
        "Java Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["jar", "war", "ear", "apk", "aar"]
    }
}

fn extract_xml_text(content: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"(?s)<{tag}>\s*([^<]+)\s*</{tag}>");
    regex::Regex::new(&pattern)
        .ok()?
        .captures(content)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
}
