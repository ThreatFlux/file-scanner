//! Risk assessment and scoring framework

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use super::{MaliciousPattern, Vulnerability};

/// Risk level categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Convert from numeric risk score
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 80.0 => Self::Critical,
            s if s >= 60.0 => Self::High,
            s if s >= 40.0 => Self::Medium,
            s if s >= 20.0 => Self::Low,
            _ => Self::Safe,
        }
    }

    /// Get color representation for UI
    pub fn color(&self) -> &'static str {
        match self {
            Self::Critical => "#FF0000", // Red
            Self::High => "#FF6600",     // Orange
            Self::Medium => "#FFCC00",   // Yellow
            Self::Low => "#99CC00",      // Light Green
            Self::Safe => "#00CC00",     // Green
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safe => write!(f, "Safe"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Risk score with detailed breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub total_score: f32,
    pub risk_level: RiskLevel,
    pub components: HashMap<String, f32>,
    pub factors: Vec<RiskFactor>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub category: RiskCategory,
    pub description: String,
    pub severity: RiskLevel,
    pub score_contribution: f32,
    pub evidence: Vec<String>,
    pub mitigation: Option<String>,
}

/// Risk categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskCategory {
    Vulnerability,
    MaliciousCode,
    Typosquatting,
    SupplyChain,
    Maintenance,
    License,
    Privacy,
    Quality,
}

/// Complete risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_score: RiskScore,
    pub summary: String,
    pub detailed_findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    pub security_posture: SecurityPosture,
}

/// Security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_type: FindingType,
    pub severity: RiskLevel,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub affected_components: Vec<String>,
}

/// Finding types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    Vulnerability,
    MaliciousPattern,
    SuspiciousActivity,
    PolicyViolation,
    QualityIssue,
}

/// Recommendation for addressing risks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub action: String,
    pub reason: String,
    pub effort: EffortLevel,
    pub impact: ImpactLevel,
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Effort required for remediation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EffortLevel {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Impact of remediation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
}

/// Overall security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    pub vulnerabilities_present: bool,
    pub malicious_code_detected: bool,
    pub supply_chain_risks: bool,
    pub actively_maintained: bool,
    pub trusted_publisher: bool,
    pub security_practices_score: f32,
}

/// Risk calculator
pub struct RiskCalculator {
    weights: HashMap<RiskCategory, f32>,
}

impl RiskCalculator {
    /// Create a new risk calculator with default weights
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert(RiskCategory::Vulnerability, 1.0);
        weights.insert(RiskCategory::MaliciousCode, 2.0);
        weights.insert(RiskCategory::Typosquatting, 1.5);
        weights.insert(RiskCategory::SupplyChain, 1.2);
        weights.insert(RiskCategory::Maintenance, 0.5);
        weights.insert(RiskCategory::License, 0.3);
        weights.insert(RiskCategory::Privacy, 0.8);
        weights.insert(RiskCategory::Quality, 0.4);

        Self { weights }
    }

    /// Calculate risk score from various inputs
    pub fn calculate(
        &self,
        vulnerabilities: &[Vulnerability],
        malicious_patterns: &[MaliciousPattern],
        is_typosquatting: bool,
        supply_chain_score: f32,
        _maintenance_score: f32,
    ) -> RiskScore {
        let mut components = HashMap::new();
        let mut factors = Vec::new();

        // Vulnerability score
        let vuln_score = self.calculate_vulnerability_score(vulnerabilities);
        if vuln_score > 0.0 {
            components.insert("vulnerabilities".to_string(), vuln_score);
            factors.push(RiskFactor {
                category: RiskCategory::Vulnerability,
                description: format!("{} vulnerabilities found", vulnerabilities.len()),
                severity: RiskLevel::from_score(vuln_score),
                score_contribution: vuln_score * self.weights[&RiskCategory::Vulnerability],
                evidence: vulnerabilities
                    .iter()
                    .map(|v| format!("{}: {}", v.id, v.title))
                    .collect(),
                mitigation: Some("Update to patched versions".to_string()),
            });
        }

        // Malicious code score
        let malicious_score = self.calculate_malicious_score(malicious_patterns);
        if malicious_score > 0.0 {
            components.insert("malicious_code".to_string(), malicious_score);
            factors.push(RiskFactor {
                category: RiskCategory::MaliciousCode,
                description: format!("{} malicious patterns detected", malicious_patterns.len()),
                severity: RiskLevel::Critical,
                score_contribution: malicious_score * self.weights[&RiskCategory::MaliciousCode],
                evidence: malicious_patterns
                    .iter()
                    .map(|p| p.pattern_name.clone())
                    .collect(),
                mitigation: Some("Remove package immediately".to_string()),
            });
        }

        // Typosquatting
        if is_typosquatting {
            let typo_score = 60.0;
            components.insert("typosquatting".to_string(), typo_score);
            factors.push(RiskFactor {
                category: RiskCategory::Typosquatting,
                description: "Package name is suspiciously similar to popular package".to_string(),
                severity: RiskLevel::High,
                score_contribution: typo_score * self.weights[&RiskCategory::Typosquatting],
                evidence: vec!["Name similarity detected".to_string()],
                mitigation: Some("Verify correct package name".to_string()),
            });
        }

        // Supply chain
        if supply_chain_score > 20.0 {
            components.insert("supply_chain".to_string(), supply_chain_score);
            factors.push(RiskFactor {
                category: RiskCategory::SupplyChain,
                description: "Supply chain risks detected".to_string(),
                severity: RiskLevel::from_score(supply_chain_score),
                score_contribution: supply_chain_score * self.weights[&RiskCategory::SupplyChain],
                evidence: vec!["Installation scripts present".to_string()],
                mitigation: Some("Review installation scripts".to_string()),
            });
        }

        // Calculate total
        let total_score: f32 = components
            .values()
            .zip(components.keys().map(|k| match k.as_str() {
                "vulnerabilities" => self.weights[&RiskCategory::Vulnerability],
                "malicious_code" => self.weights[&RiskCategory::MaliciousCode],
                "typosquatting" => self.weights[&RiskCategory::Typosquatting],
                "supply_chain" => self.weights[&RiskCategory::SupplyChain],
                _ => 1.0,
            }))
            .map(|(score, weight)| score * weight)
            .sum::<f32>()
            .min(100.0);

        RiskScore {
            total_score,
            risk_level: RiskLevel::from_score(total_score),
            components,
            factors,
        }
    }

    fn calculate_vulnerability_score(&self, vulnerabilities: &[Vulnerability]) -> f32 {
        vulnerabilities
            .iter()
            .map(|v| v.severity.weight())
            .sum::<f32>()
            .min(100.0)
    }

    fn calculate_malicious_score(&self, patterns: &[MaliciousPattern]) -> f32 {
        if patterns.is_empty() {
            0.0
        } else {
            // Any malicious pattern is critical
            95.0
        }
    }
}

impl Default for RiskCalculator {
    fn default() -> Self {
        Self::new()
    }
}
