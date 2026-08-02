//! NPM package analyzer

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

use crate::core::{
    AnalysisResult, Dependency, DependencyAnalysis, DependencyType, MaliciousPattern,
    PackageAnalyzer, PackageInfo, PackageMetadata, PatternCategory, PatternMatcher,
    PatternSeverity, RiskAssessment, RiskCalculator, Vulnerability,
};
use crate::utils::typosquatting::TyposquattingDetector;
use crate::vulnerability_db::VulnerabilityDatabase;

/// NPM package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmPackage {
    pub metadata: PackageMetadata,
    pub main: Option<String>,
    pub scripts: HashMap<String, String>,
    pub engines: HashMap<String, String>,
    pub files: Vec<String>,
    pub private: bool,
}

impl PackageInfo for NpmPackage {
    fn metadata(&self) -> &PackageMetadata {
        &self.metadata
    }

    fn package_type(&self) -> &str {
        "npm"
    }

    fn custom_attributes(&self) -> HashMap<String, serde_json::Value> {
        let mut attrs = HashMap::new();
        attrs.insert("main".to_string(), serde_json::json!(self.main));
        attrs.insert("scripts".to_string(), serde_json::json!(self.scripts));
        attrs.insert("engines".to_string(), serde_json::json!(self.engines));
        attrs.insert("private".to_string(), serde_json::json!(self.private));
        attrs
    }
}

/// NPM analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmAnalysisResult {
    pub package: NpmPackage,
    pub risk_assessment: RiskAssessment,
    pub dependency_analysis: DependencyAnalysis,
    pub vulnerabilities: Vec<Vulnerability>,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub scripts_analysis: ScriptsAnalysis,
    pub typosquatting_risk: Option<TyposquattingRisk>,
}

impl AnalysisResult for NpmAnalysisResult {
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

/// NPM-specific scripts analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptsAnalysis {
    pub has_install_scripts: bool,
    pub suspicious_scripts: Vec<SuspiciousScript>,
    pub external_downloads: Vec<String>,
    pub shell_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousScript {
    pub script_name: String,
    pub reason: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRisk {
    pub is_likely_typosquatting: bool,
    pub similar_packages: Vec<String>,
    pub confidence: f32,
}

/// NPM package analyzer
pub struct NpmAnalyzer {
    vuln_db: Box<dyn VulnerabilityDatabase>,
    pattern_matcher: PatternMatcher,
    typo_detector: TyposquattingDetector,
}

impl NpmAnalyzer {
    /// Create a new NPM analyzer
    pub fn new() -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_npm_database()?,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Create analyzer with custom database path
    pub fn with_db_path(db_path: &Path) -> Result<Self> {
        Ok(Self {
            vuln_db: crate::vulnerability_db::create_npm_database_with_path(db_path)?,
            pattern_matcher: PatternMatcher::new()?,
            typo_detector: TyposquattingDetector::new(),
        })
    }

    /// Parse package.json file
    async fn parse_package_json(&self, content: &str) -> Result<NpmPackage> {
        let json: Value = serde_json::from_str(content).context("Failed to parse package.json")?;

        let obj = json
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("package.json is not an object"))?;

        let metadata = PackageMetadata {
            name: obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            version: obj
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string(),
            description: obj
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from),
            author: obj.get("author").and_then(|v| v.as_str()).map(String::from),
            license: obj
                .get("license")
                .and_then(|v| v.as_str())
                .map(String::from),
            homepage: obj
                .get("homepage")
                .and_then(|v| v.as_str())
                .map(String::from),
            repository: obj.get("repository").and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if let Some(obj) = v.as_object() {
                    obj.get("url").and_then(|u| u.as_str()).map(String::from)
                } else {
                    None
                }
            }),
            keywords: obj
                .get("keywords")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            publish_date: None,
        };

        let scripts = obj
            .get("scripts")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let engines = obj
            .get("engines")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let files = obj
            .get("files")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(NpmPackage {
            metadata,
            main: obj.get("main").and_then(|v| v.as_str()).map(String::from),
            scripts,
            engines,
            files,
            private: obj
                .get("private")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        })
    }

    /// Analyze dependencies
    async fn analyze_dependencies(&self, package_json: &Value) -> Result<DependencyAnalysis> {
        let mut analysis = DependencyAnalysis::default();
        let obj = package_json.as_object().unwrap();

        // Parse different dependency types
        let dep_types = [
            ("dependencies", DependencyType::Runtime),
            ("devDependencies", DependencyType::Development),
            ("peerDependencies", DependencyType::Peer),
            ("optionalDependencies", DependencyType::Optional),
        ];

        for (field, dep_type) in &dep_types {
            if let Some(deps) = obj.get(*field).and_then(|v| v.as_object()) {
                for (name, version_spec) in deps {
                    let version_str = version_spec.as_str().unwrap_or("*");

                    // Check for vulnerabilities
                    let vulns = self.vuln_db.check_package(name, version_str, "npm").await?;

                    let dependency = Dependency {
                        name: name.clone(),
                        version_spec: version_str.to_string(),
                        resolved_version: None,
                        dependency_type: dep_type.clone(),
                        is_direct: true,
                        is_dev: matches!(dep_type, DependencyType::Development),
                        vulnerabilities: vulns,
                        license: None,
                        dependencies: vec![], // TODO: Parse lock file for transitive deps
                    };

                    analysis.dependency_tree.push(dependency);
                    analysis.direct_dependencies += 1;
                }
            }
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

                if !analysis
                    .vulnerability_summary
                    .vulnerable_dependencies
                    .contains(&dep.name)
                {
                    analysis
                        .vulnerability_summary
                        .vulnerable_dependencies
                        .push(dep.name.clone());
                }
            }
        }

        Ok(analysis)
    }

    /// Analyze scripts for suspicious patterns
    fn analyze_scripts(&self, scripts: &HashMap<String, String>) -> ScriptsAnalysis {
        let mut analysis = ScriptsAnalysis {
            has_install_scripts: false,
            suspicious_scripts: vec![],
            external_downloads: vec![],
            shell_commands: vec![],
        };

        let install_hooks = ["preinstall", "install", "postinstall", "prepare"];

        for (name, content) in scripts {
            // Check for install scripts
            if install_hooks.contains(&name.as_str()) {
                analysis.has_install_scripts = true;
            }

            // Check for external downloads
            if content.contains("curl") || content.contains("wget") {
                analysis.external_downloads.push(content.clone());
                analysis.suspicious_scripts.push(SuspiciousScript {
                    script_name: name.clone(),
                    reason: "Downloads external content".to_string(),
                    risk_level: "High".to_string(),
                });
            }

            // Check for shell commands
            if content.contains("sh") || content.contains("bash") || content.contains("exec") {
                analysis.shell_commands.push(content.clone());
            }

            // Check for suspicious patterns
            if content.contains("eval") || content.contains("Function(") {
                analysis.suspicious_scripts.push(SuspiciousScript {
                    script_name: name.clone(),
                    reason: "Dynamic code execution".to_string(),
                    risk_level: "Critical".to_string(),
                });
            }
        }

        analysis
    }
}

#[async_trait]
impl PackageAnalyzer for NpmAnalyzer {
    type Package = NpmPackage;
    type Analysis = NpmAnalysisResult;

    async fn analyze(&self, path: &Path) -> Result<Self::Analysis> {
        let package_json_path = if path.is_dir() {
            path.join("package.json")
        } else {
            // TODO: Handle .tgz archives
            return Err(anyhow::anyhow!("Archive extraction not yet implemented"));
        };

        let content = tokio::fs::read_to_string(&package_json_path)
            .await
            .context("Failed to read package.json")?;

        let package = self.parse_package_json(&content).await?;
        let json_value: Value = serde_json::from_str(&content)?;
        let dependency_analysis = self.analyze_dependencies(&json_value).await?;

        // Analyze scripts
        let scripts_analysis = self.analyze_scripts(&package.scripts);

        // Check for malicious patterns
        let mut malicious_patterns = self.pattern_matcher.scan(&content, Some("package.json"));
        for suspicious_script in &scripts_analysis.suspicious_scripts {
            let is_external_download = suspicious_script.reason.contains("Downloads");
            malicious_patterns.push(MaliciousPattern {
                pattern_id: format!("NPM_SCRIPT_{}", suspicious_script.script_name),
                pattern_name: format!("Suspicious npm {} script", suspicious_script.script_name),
                description: if is_external_download {
                    format!(
                        "Remote execution/download behavior detected in npm {} script via curl or wget",
                        suspicious_script.script_name
                    )
                } else {
                    format!(
                        "{} detected in npm {} script",
                        suspicious_script.reason, suspicious_script.script_name
                    )
                },
                category: if is_external_download {
                    PatternCategory::NetworkAccess
                } else {
                    PatternCategory::CodeExecution
                },
                severity: if suspicious_script.risk_level == "Critical" {
                    PatternSeverity::Critical
                } else {
                    PatternSeverity::High
                },
                indicators: vec![suspicious_script.reason.clone()],
                regex_patterns: vec![],
                file_patterns: vec!["package.json".to_string()],
                evidence: scripts_analysis.external_downloads.clone(),
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
        let supply_chain_score = if scripts_analysis.has_install_scripts {
            40.0
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
                "NPM package '{}' has {} risk with {} vulnerabilities and {} malicious patterns",
                package.metadata.name,
                risk_score.risk_level,
                vulnerabilities.len(),
                malicious_patterns.len()
            ),
            detailed_findings: vec![],
            recommendations: vec![],
            security_posture: crate::core::SecurityPosture {
                vulnerabilities_present: !vulnerabilities.is_empty(),
                malicious_code_detected: !malicious_patterns.is_empty(),
                supply_chain_risks: scripts_analysis.has_install_scripts,
                actively_maintained: true, // TODO: Check actual maintenance
                trusted_publisher: false,  // TODO: Check publisher trust
                security_practices_score: 50.0,
            },
        };

        Ok(NpmAnalysisResult {
            package,
            risk_assessment,
            dependency_analysis,
            vulnerabilities,
            malicious_patterns,
            scripts_analysis,
            typosquatting_risk,
        })
    }

    fn can_analyze(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("package.json").exists()
        } else {
            path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "tgz" || ext == "gz")
                .unwrap_or(false)
        }
    }

    fn name(&self) -> &str {
        "NPM Package Analyzer"
    }

    fn supported_extensions(&self) -> Vec<&str> {
        vec!["tgz", "tar.gz"]
    }
}
