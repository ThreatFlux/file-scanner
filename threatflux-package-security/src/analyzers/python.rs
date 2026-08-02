//! Python package analyzer

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::core::{
    AnalysisResult, Dependency, DependencyAnalysis, DependencyType, MaliciousPattern,
    PackageAnalyzer, PackageInfo, PackageMetadata, PatternCategory, PatternMatcher,
    PatternSeverity, RiskAssessment, RiskCalculator, Vulnerability,
};
use crate::utils::typosquatting::TyposquattingDetector;
use crate::vulnerability_db::VulnerabilityDatabase;

/// Python package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonPackage {
    pub metadata: PackageMetadata,
    pub package_format: PackageFormat,
    pub python_requires: Option<String>,
    pub classifiers: Vec<String>,
    pub project_urls: HashMap<String, String>,
    pub maintainer: Option<String>,
    pub maintainer_email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageFormat {
    Wheel,
    SourceDistribution,
    EggInfo,
    Directory,
}

impl PackageInfo for PythonPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "python"
    }

    fn custom_attributes(&self) -> HashMap<String, serde_json::Value> {
        let mut attrs = HashMap::new();
        attrs.insert(
            "package_format".to_string(),
            serde_json::json!(self.package_format),
        );
        attrs.insert(
            "python_requires".to_string(),
            serde_json::json!(self.python_requires),
        );
        attrs.insert(
            "classifiers".to_string(),
            serde_json::json!(self.classifiers),
        );
        attrs.insert(
            "project_urls".to_string(),
            serde_json::json!(self.project_urls),
        );
        attrs
    }
}

/// Python analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonAnalysisResult {
    pub package: PythonPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub setup_analysis: SetupAnalysis,
    pub typosquatting_risk: Option<TyposquattingRisk>,
}

impl AnalysisResult for PythonAnalysisResult {
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

/// Python setup.py analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupAnalysis {
    pub has_setup_py: bool,
    pub has_custom_commands: bool,
    pub dangerous_operations: Vec<String>,
    pub external_downloads: Vec<String>,
    pub code_execution_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRisk {
    pub is_likely_typosquatting: bool,
    pub similar_packages: Vec<String>,
    pub confidence: f32,
}

/// Python package analyzer
pub struct PythonAnalyzer {
    vuln_db: Box<dyn VulnerabilityDatabase>,
    pattern_matcher: PatternMatcher,
    typo_detector: TyposquattingDetector,
}

impl PythonAnalyzer {
    /// Create a new Python analyzer
    pub fn new() -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_python_database()?,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Create analyzer with custom database path
    pub fn with_db_path(db_path: &Path) -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_python_database_with_path(db_path)?,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Parse setup.py or pyproject.toml
    async fn parse_package_metadata(&self, path: &Path) -> Result<PythonPackage> {
        let (metadata, format) = if path.is_dir() {
            // Check for different Python project files
            if path.join("setup.py").exists() {
                let content = tokio::fs::read_to_string(path.join("setup.py")).await?;
                (self.parse_setup_py(&content)?, PackageFormat::Directory)
            } else if path.join("pyproject.toml").exists() {
                let content = tokio::fs::read_to_string(path.join("pyproject.toml")).await?;
                (
                    self.parse_pyproject_toml(&content)?,
                    PackageFormat::Directory,
                )
            } else if path.join("setup.cfg").exists() {
                let content = tokio::fs::read_to_string(path.join("setup.cfg")).await?;
                (self.parse_setup_cfg(&content)?, PackageFormat::Directory)
            } else {
                return Err(anyhow::anyhow!("No Python package files found"));
            }
        } else {
            // TODO: Handle .whl, .tar.gz archives
            return Err(anyhow::anyhow!("Archive extraction not yet implemented"));
        };

        Ok(PythonPackage {
            metadata,
            package_format: format,
            python_requires: None, // TODO: Extract from metadata
            classifiers: vec![],
            project_urls: HashMap::new(),
            maintainer: None,
            maintainer_email: None,
        })
    }

    /// Parse setup.py file
    fn parse_setup_py(&self, content: &str) -> Result<PackageMetadata> {
        // Simple regex-based extraction
        let name = self.extract_setup_field(content, "name")?;
        let version = self.extract_setup_field(content, "version")?;

        Ok(PackageMetadata {
            name,
            version,
            description: self.extract_setup_field(content, "description").ok(),
            author: self.extract_setup_field(content, "author").ok(),
            license: self.extract_setup_field(content, "license").ok(),
            homepage: self.extract_setup_field(content, "url").ok(),
            repository: None,
            keywords: vec![], // TODO: Parse keywords list
            publish_date: None,
        })
    }

    /// Parse pyproject.toml file
    fn parse_pyproject_toml(&self, content: &str) -> Result<PackageMetadata> {
        let toml_value: toml::Value = toml::from_str(content)?;

        let project = toml_value
            .get("project")
            .ok_or_else(|| anyhow::anyhow!("No [project] section in pyproject.toml"))?;

        Ok(PackageMetadata {
            name: project
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing project name"))?
                .to_string(),
            version: project
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing project version"))?
                .to_string(),
            description: project
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from),
            author: None, // TODO: Parse authors array
            license: project
                .get("license")
                .and_then(|v| v.as_str())
                .map(String::from),
            homepage: project
                .get("homepage")
                .and_then(|v| v.as_str())
                .map(String::from),
            repository: None,
            keywords: project
                .get("keywords")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            publish_date: None,
        })
    }

    /// Parse setup.cfg file
    fn parse_setup_cfg(&self, content: &str) -> Result<PackageMetadata> {
        // Simple INI-style parsing
        let mut metadata = PackageMetadata {
            name: String::new(),
            version: String::new(),
            description: None,
            author: None,
            license: None,
            homepage: None,
            repository: None,
            keywords: vec![],
            publish_date: None,
        };

        let mut in_metadata_section = false;

        for line in content.lines() {
            if line.trim() == "[metadata]" {
                in_metadata_section = true;
                continue;
            }
            if line.starts_with('[') {
                in_metadata_section = false;
            }

            if in_metadata_section {
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();

                    match key {
                        "name" => metadata.name = value.to_string(),
                        "version" => metadata.version = value.to_string(),
                        "description" => metadata.description = Some(value.to_string()),
                        "author" => metadata.author = Some(value.to_string()),
                        "license" => metadata.license = Some(value.to_string()),
                        "url" => metadata.homepage = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        if metadata.name.is_empty() || metadata.version.is_empty() {
            return Err(anyhow::anyhow!("Missing required metadata in setup.cfg"));
        }

        Ok(metadata)
    }

    /// Extract field from setup.py using regex
    fn extract_setup_field(&self, content: &str, field: &str) -> Result<String> {
        let pattern = format!(r#"{}\s*=\s*["']([^"']+)["']"#, field);
        let re = regex::Regex::new(&pattern)?;

        re.captures(content)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| anyhow::anyhow!("Field '{}' not found", field))
    }

    /// Analyze setup.py for dangerous operations
    fn analyze_setup(&self, content: &str) -> SetupAnalysis {
        let mut analysis = SetupAnalysis {
            has_setup_py: true,
            has_custom_commands: false,
            dangerous_operations: vec![],
            external_downloads: vec![],
            code_execution_risk: false,
        };

        // Check for custom commands
        if content.contains("cmdclass") {
            analysis.has_custom_commands = true;
            analysis
                .dangerous_operations
                .push("Custom setup commands detected".to_string());
        }

        // Check for dangerous operations
        let dangerous_patterns = [
            ("subprocess", "Process execution"),
            ("os.system", "System command execution"),
            ("exec", "Dynamic code execution"),
            ("eval", "Code evaluation"),
            ("__import__", "Dynamic imports"),
            ("urllib", "Network access"),
            ("requests", "HTTP requests"),
        ];

        for (pattern, description) in &dangerous_patterns {
            if content.contains(pattern) {
                analysis.dangerous_operations.push(description.to_string());
                analysis.code_execution_risk = true;
            }
        }

        // Check for external downloads
        if content.contains("urlopen") || content.contains("requests.get") {
            analysis
                .external_downloads
                .push("External download detected".to_string());
        }

        analysis
    }

    /// Analyze dependencies
    async fn analyze_dependencies(&self, path: &Path) -> Result<DependencyAnalysis> {
        let mut analysis = DependencyAnalysis::default();

        // Try to find requirements
        let requirements = if path.join("requirements.txt").exists() {
            tokio::fs::read_to_string(path.join("requirements.txt")).await?
        } else if path.join("setup.py").exists() {
            // TODO: Extract from setup.py install_requires
            String::new()
        } else if path.join("pyproject.toml").exists() {
            // TODO: Extract from pyproject.toml dependencies
            String::new()
        } else {
            String::new()
        };

        // Parse requirements
        for line in requirements.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Simple parsing - split on operators
            let (name, version_spec) = if let Some(pos) = line.find("==") {
                (&line[..pos], &line[pos..])
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], &line[pos..])
            } else if let Some(pos) = line.find("~=") {
                (&line[..pos], &line[pos..])
            } else {
                (line, "*")
            };

            let vulns = self
                .vuln_db
                .check_package(name, version_spec, "python")
                .await?;

            let dependency = Dependency {
                name: name.to_string(),
                version_spec: version_spec.to_string(),
                resolved_version: None,
                dependency_type: DependencyType::Runtime,
                is_direct: true,
                is_dev: false,
                vulnerabilities: vulns,
                license: None,
                dependencies: vec![],
            };

            analysis.dependency_tree.push(dependency);
            analysis.direct_dependencies += 1;
        }

        analysis.total_dependencies = analysis.dependency_tree.len();

        // Calculate vulnerability summary
        for dep in &analysis.dependency_tree {
            for vuln in &dep.vulnerabilities {
                analysis.vulnerability_summary.total_vulnerabilities += 1;
                match vuln.severity {
                    crate::core::VulnerabilitySeverity::Critical => {
                        analysis.vulnerability_summary.critical_count += 1;
                    }
                    crate::core::VulnerabilitySeverity::High => {
                        analysis.vulnerability_summary.high_count += 1;
                    }
                    crate::core::VulnerabilitySeverity::Medium => {
                        analysis.vulnerability_summary.medium_count += 1;
                    }
                    crate::core::VulnerabilitySeverity::Low => {
                        analysis.vulnerability_summary.low_count += 1;
                    }
                    _ => {}
                }
            }
        }

        Ok(analysis)
    }
}

#[async_trait]
impl PackageAnalyzer for PythonAnalyzer {
    type Package = PythonPackage;
    type Analysis = PythonAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        let package = self.parse_package_metadata(path).await?;
        let dependency_analysis = self.analyze_dependencies(path).await?;

        // Analyze setup.py if present
        let setup_analysis = if path.join("setup.py").exists() {
            let content = tokio::fs::read_to_string(path.join("setup.py")).await?;
            self.analyze_setup(&content)
        } else {
            SetupAnalysis {
                has_setup_py: false,
                has_custom_commands: false,
                dangerous_operations: vec![],
                external_downloads: vec![],
                code_execution_risk: false,
            }
        };

        // Check for malicious patterns
        let mut all_content = String::new();
        if path.join("setup.py").exists() {
            all_content.push_str(&tokio::fs::read_to_string(path.join("setup.py")).await?);
        }
        let mut malicious_patterns = self.pattern_matcher.scan(&all_content, Some("setup.py"));
        for operation in &setup_analysis.dangerous_operations {
            malicious_patterns.push(MaliciousPattern {
                pattern_id: format!("PY_SETUP_{}", operation.replace(' ', "_").to_uppercase()),
                pattern_name: "Suspicious Python setup operation".to_string(),
                description: if operation.contains("Network") {
                    "Network access detected in setup.py via urllib or requests".to_string()
                } else {
                    format!("{operation} detected in setup.py")
                },
                category: if operation.contains("Network") || operation.contains("HTTP") {
                    PatternCategory::NetworkAccess
                } else {
                    PatternCategory::CodeExecution
                },
                severity: PatternSeverity::High,
                indicators: vec![operation.clone()],
                regex_patterns: vec![],
                file_patterns: vec!["setup.py".to_string()],
                evidence: setup_analysis.external_downloads.clone(),
            });
        }

        // Check typosquatting
        let typosquatting_risk = if self.typo_detector.is_typosquatting(&package.metadata.name) {
            Some(TyposquattingRisk {
                is_likely_typosquatting: true,
                similar_packages: self.typo_detector.find_similar(&package.metadata.name),
                confidence: 0.8,
            })
        } else {
            None
        };

        // Collect all vulnerabilities
        let mut vulnerabilities = vec![];
        for dep in &dependency_analysis.dependency_tree {
            vulnerabilities.extend(dep.vulnerabilities.clone());
        }

        // Calculate risk assessment
        let risk_calculator = RiskCalculator::new();
        let supply_chain_score = if setup_analysis.code_execution_risk {
            50.0
        } else {
            0.0
        };

        let risk_score = risk_calculator.calculate(
            &vulnerabilities,
            &malicious_patterns,
            typosquatting_risk.is_some(),
            supply_chain_score,
            50.0, // Default maintenance score
        );

        let risk_assessment = RiskAssessment {
            risk_score: risk_score.clone(),
            summary: format!(
                "Python package '{}' has {} risk with {} vulnerabilities",
                package.metadata.name,
                risk_score.risk_level,
                vulnerabilities.len()
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerabilities_present: !vulnerabilities.is_empty(),
                malicious_code_detected: !malicious_patterns.is_empty(),
                supply_chain_risks: setup_analysis.code_execution_risk,
                actively_maintained: true,
                trusted_publisher: false,
                security_practices_score: 50.0,
            },
        };

        Ok(PythonAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            vulnerabilities,
            malicious_patterns,
            setup_analysis,
            typosquatting_risk,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("setup.py").exists()
                || path.join("pyproject.toml").exists()
                || path.join("setup.cfg").exists()
        } else {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| matches!(ext, "whl" | "egg" | "gz" | "zip"))
                .unwrap_or(false)
        }
    }

    fn name(&self) -> &str {
        "Python Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["whl", "egg", "tar.gz", "zip"]
    }
}
