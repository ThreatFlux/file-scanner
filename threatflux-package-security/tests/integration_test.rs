//! Integration tests for ThreatFlux Package Security

use std::fs;
use tempfile::TempDir;
use threatflux_package_security::PackageSecurityAnalyzer;

#[tokio::test]
async fn test_npm_package_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let package_json = r#"{
        "name": "test-package",
        "version": "1.0.0",
        "description": "Test package",
        "dependencies": {
            "lodash": "4.17.10"
        }
    }"#;

    fs::write(temp_dir.path().join("package.json"), package_json).unwrap();

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "npm");
    assert!(!result.vulnerabilities().is_empty());
}

#[tokio::test]
async fn test_python_package_analysis() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py = r#"
from setuptools import setup

setup(
    name="test-package",
    version="1.0.0",
    description="Test package",
    install_requires=["django<3.2"]
)
"#;

    fs::write(temp_dir.path().join("setup.py"), setup_py).unwrap();

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "python");
}

#[test]
fn test_risk_level_ordering() {
    use threatflux_package_security::RiskLevel;

    assert!(RiskLevel::Safe < RiskLevel::Low);
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}
