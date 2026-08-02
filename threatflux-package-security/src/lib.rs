//! ThreatFlux Package Security Library
//!
//! A unified framework for analyzing package security across multiple package managers
//! including npm, Python (PyPI), Java (Maven), and more.

pub mod analyzers;
pub mod core;
pub mod utils;
pub mod vulnerability_db;

pub use core::{
    AnalysisResult, MaliciousPattern, PackageAnalyzer, PackageInfo, PackageType,
    QualityMetricsSummary, RiskLevel, RiskScore, TyposquattingRiskSummary, Vulnerability,
    VulnerabilitySeverity,
};

pub use analyzers::{java::JavaAnalyzer, npm::NpmAnalyzer, python::PythonAnalyzer};

pub use vulnerability_db::VulnerabilityDatabase;

pub type SecurityAnalysisResult = Box<dyn AnalysisResult>;
pub type VulnerabilityInfo = Vulnerability;

use anyhow::Result;
use std::path::Path;

/// Main entry point for package security analysis
pub struct PackageSecurityAnalyzer {
    npm_analyzer: NpmAnalyzer,
    python_analyzer: PythonAnalyzer,
    java_analyzer: JavaAnalyzer,
}

impl PackageSecurityAnalyzer {
    /// Create a new package security analyzer with default settings
    pub fn new() -> Result<Self> {
        Ok(Self {
            npm_analyzer: NpmAnalyzer::new()?,
            python_analyzer: PythonAnalyzer::new()?,
            java_analyzer: JavaAnalyzer::new()?,
        })
    }

    /// Create analyzer with custom vulnerability database path
    pub fn with_db_path(db_path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            npm_analyzer: NpmAnalyzer::with_db_path(db_path.as_ref())?,
            python_analyzer: PythonAnalyzer::with_db_path(db_path.as_ref())?,
            java_analyzer: JavaAnalyzer::with_db_path(db_path.as_ref())?,
        })
    }

    /// Analyze a package file or directory
    pub async fn analyze(&self, path: impl AsRef<Path>) -> Result<Box<dyn AnalysisResult>> {
        let path = path.as_ref();

        // Detect package type based on file extension or contents
        if self.is_npm_package(path) {
            Ok(Box::new(self.npm_analyzer.analyze(path).await?))
        } else if self.is_python_package(path) {
            Ok(Box::new(self.python_analyzer.analyze(path).await?))
        } else if self.is_java_package(path) {
            Ok(Box::new(self.java_analyzer.analyze(path).await?))
        } else {
            anyhow::bail!("Unknown package type for path: {}", path.display())
        }
    }

    /// Check if path is an npm package
    fn is_npm_package(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("package.json").exists()
        } else if let Some(ext) = path.extension() {
            ext == "tgz" || (ext == "gz" && path.to_string_lossy().contains("npm"))
        } else {
            false
        }
    }

    /// Check if path is a Python package
    fn is_python_package(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("setup.py").exists()
                || path.join("pyproject.toml").exists()
                || path.join("setup.cfg").exists()
        } else if let Some(ext) = path.extension() {
            ext == "whl"
                || ext == "egg"
                || (ext == "gz" && path.to_string_lossy().contains(".tar.gz"))
                || (ext == "zip" && !self.is_java_package(path))
        } else {
            false
        }
    }

    /// Check if path is a Java package
    fn is_java_package(&self, path: &Path) -> bool {
        if path.is_dir() {
            path.join("pom.xml").exists() || path.join("build.gradle").exists()
        } else if let Some(ext) = path.extension() {
            matches!(
                ext.to_str(),
                Some("jar") | Some("war") | Some("ear") | Some("apk") | Some("aar")
            )
        } else {
            false
        }
    }
}

impl Default for PackageSecurityAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create default analyzer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_detection() {
        let analyzer = PackageSecurityAnalyzer::new().unwrap();

        assert!(analyzer.is_npm_package(Path::new("package.tgz")));
        assert!(analyzer.is_python_package(Path::new("package.whl")));
        assert!(analyzer.is_java_package(Path::new("app.jar")));
    }
}
