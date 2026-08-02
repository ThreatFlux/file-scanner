//! Core traits and structures for package security analysis

pub mod dependency;
pub mod package;
pub mod patterns;
pub mod risk;
pub mod vulnerability;

pub use dependency::{Dependency, DependencyAnalysis, DependencyType};
pub use package::{
    AnalysisResult, PackageAnalyzer, PackageInfo, PackageMetadata, PackageType,
    QualityMetricsSummary, TyposquattingRiskSummary,
};
pub use patterns::{
    MaliciousPattern, PatternCategory, PatternDatabase, PatternMatcher, PatternSeverity,
};
pub use risk::{RiskAssessment, RiskCalculator, RiskLevel, RiskScore, SecurityPosture};
pub use vulnerability::{
    DatabaseStatistics, UpdateResult, Vulnerability, VulnerabilityDatabase, VulnerabilitySeverity,
};
