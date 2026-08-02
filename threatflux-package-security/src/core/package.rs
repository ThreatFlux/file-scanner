//! Core package traits and structures

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use super::{DependencyAnalysis, MaliciousPattern, RiskAssessment, Vulnerability};

/// Supported package ecosystems.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PackageType {
    Npm,
    Python,
    Java,
    Unknown,
}

impl fmt::Display for PackageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Npm => f.write_str("npm"),
            Self::Python => f.write_str("python"),
            Self::Java => f.write_str("java"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

/// Basic package information common to all package types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub license: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub keywords: Vec<String>,
    pub publish_date: Option<String>,
}

/// Package-specific information trait
pub trait PackageInfo: Send + Sync {
    /// Get basic metadata
    fn metadata(&self) -> &PackageMetadata;

    /// Get package name
    fn name(&self) -> &str {
        &self.metadata().name
    }

    /// Get package version
    fn version(&self) -> &str {
        &self.metadata().version
    }

    /// Get package type identifier
    fn package_type(&self) -> &str;

    /// Get custom attributes specific to this package type
    fn custom_attributes(&self) -> HashMap<String, serde_json::Value>;
}

/// Analysis result trait
pub trait AnalysisResult: Send + Sync {
    /// Get the package info
    fn package_info(&self) -> &dyn PackageInfo;

    /// Get risk assessment
    fn risk_assessment(&self) -> &RiskAssessment;

    /// Get dependency analysis
    fn dependency_analysis(&self) -> &DependencyAnalysis;

    /// Get detected vulnerabilities
    fn vulnerabilities(&self) -> &[Vulnerability];

    /// Get detected malicious patterns
    fn malicious_patterns(&self) -> &[MaliciousPattern];

    /// Get overall risk level
    fn overall_risk_level(&self) -> super::RiskLevel {
        let mut level = self.risk_assessment().risk_score.risk_level;
        if !self.vulnerabilities().is_empty() {
            level = level.max(super::RiskLevel::Low);
        }
        if !self.malicious_patterns().is_empty() {
            level = level.max(super::RiskLevel::High);
        }
        if self.supply_chain_risk_score() >= 60.0 {
            level = level.max(super::RiskLevel::High);
        } else if self.supply_chain_risk_score() >= 30.0 {
            level = level.max(super::RiskLevel::Medium);
        }
        level
    }

    /// Get detected malicious indicators
    fn malicious_indicators(&self) -> &[MaliciousPattern] {
        self.malicious_patterns()
    }

    /// Get typosquatting risk summary
    fn typosquatting_risk(&self) -> TyposquattingRiskSummary {
        let score = self
            .risk_assessment()
            .risk_score
            .components
            .get("typosquatting")
            .copied()
            .unwrap_or(0.0);
        let is_potential = score > 0.0;
        let similar_packages = if is_potential {
            self.risk_assessment()
                .risk_score
                .factors
                .iter()
                .filter(|factor| {
                    matches!(factor.category, super::risk::RiskCategory::Typosquatting)
                })
                .flat_map(|factor| factor.evidence.clone())
                .collect()
        } else {
            Vec::new()
        };

        TyposquattingRiskSummary {
            is_potential,
            similar_packages,
            confidence: (score / 100.0).clamp(0.0, 1.0),
        }
    }

    /// Get supply-chain risk score
    fn supply_chain_risk_score(&self) -> f32 {
        let scored_component = self
            .risk_assessment()
            .risk_score
            .components
            .get("supply_chain")
            .copied()
            .unwrap_or(0.0);
        let dependency_score =
            (self.dependency_analysis().total_dependencies as f32 * 5.0).min(100.0);

        scored_component.max(dependency_score)
    }

    /// Get package quality metrics
    fn quality_metrics(&self) -> QualityMetricsSummary {
        let metadata = self.package_info().metadata();
        let attrs = self.package_info().custom_attributes();
        let scripts = attrs.get("scripts").and_then(serde_json::Value::as_object);

        let documentation_signals = [
            metadata.description.as_ref().is_some_and(|v| !v.is_empty()),
            metadata.homepage.as_ref().is_some_and(|v| !v.is_empty()),
            metadata.repository.as_ref().is_some_and(|v| !v.is_empty()),
            !metadata.keywords.is_empty(),
        ];
        let documentation_score = documentation_signals
            .iter()
            .filter(|has_signal| **has_signal)
            .count() as f32
            / documentation_signals.len() as f32;

        let has_tests = scripts.is_some_and(|scripts| {
            scripts.keys().any(|key| key.contains("test"))
                || scripts
                    .values()
                    .filter_map(serde_json::Value::as_str)
                    .any(|value| value.contains("test") || value.contains("mocha"))
        });
        let has_ci_cd = metadata.repository.as_ref().is_some_and(|v| !v.is_empty())
            || scripts.is_some_and(|scripts| {
                scripts
                    .keys()
                    .any(|key| key.contains("ci") || key.contains("lint"))
            });

        QualityMetricsSummary {
            documentation_score,
            has_tests,
            has_ci_cd,
        }
    }

    /// Convert to JSON representation
    fn to_json(&self) -> Result<serde_json::Value>;
}

/// Typosquatting risk summary shared across analyzer result types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TyposquattingRiskSummary {
    pub is_potential: bool,
    pub similar_packages: Vec<String>,
    pub confidence: f32,
}

impl TyposquattingRiskSummary {
    pub fn is_potential_typosquatting(&self) -> bool {
        self.is_potential
    }

    pub fn similar_packages(&self) -> &[String] {
        &self.similar_packages
    }

    pub fn confidence(&self) -> f32 {
        self.confidence
    }
}

/// Package quality metrics shared across analyzer result types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetricsSummary {
    pub documentation_score: f32,
    pub has_tests: bool,
    pub has_ci_cd: bool,
}

impl QualityMetricsSummary {
    pub fn documentation_score(&self) -> f32 {
        self.documentation_score
    }

    pub fn has_tests(&self) -> bool {
        self.has_tests
    }

    pub fn has_ci_cd(&self) -> bool {
        self.has_ci_cd
    }
}

/// Package analyzer trait
#[async_trait]
pub trait PackageAnalyzer: Send + Sync {
    /// The specific package type this analyzer handles
    type Package: PackageInfo;

    /// The analysis result type
    type Analysis: AnalysisResult;

    /// Analyze a package from the given path
    async fn analyze(&self, path: &Path) -> Result<Self::Analysis>;

    /// Check if this analyzer can handle the given path
    fn can_analyze(&self, path: &Path) -> bool;

    /// Get analyzer name
    fn name(&self) -> &str;

    /// Get supported file extensions
    fn supported_extensions(&self) -> Vec<&str>;
}

/// Common package analysis options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Enable deep dependency analysis
    pub analyze_dependencies: bool,

    /// Check against vulnerability databases
    pub check_vulnerabilities: bool,

    /// Scan for malicious patterns
    pub scan_malicious_patterns: bool,

    /// Enable typosquatting detection
    pub detect_typosquatting: bool,

    /// Maximum dependency depth to analyze
    pub max_dependency_depth: usize,

    /// Timeout for analysis in seconds
    pub timeout_seconds: u64,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            analyze_dependencies: true,
            check_vulnerabilities: true,
            scan_malicious_patterns: true,
            detect_typosquatting: true,
            max_dependency_depth: 5,
            timeout_seconds: 300,
        }
    }
}
