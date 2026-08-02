#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::field_reassign_with_default,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::ignore_without_reason,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::ref_option,
    clippy::redundant_clone,
    clippy::redundant_pattern_matching,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_debug_formatting,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm,
    clippy::ignored_unit_patterns
)]

use anyhow::Result;
use file_scanner::npm_analysis::{analyze_npm_package, RiskLevel};
use file_scanner::npm_vuln_db::{check_package_vulnerabilities, check_typosquatting_similarity};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Helper function to create a test npm package
fn create_test_npm_package(temp_dir: &Path, name: &str, version: &str, deps: &str) -> Result<()> {
    let package_json = format!(
        r#"{{
  "name": "{name}",
  "version": "{version}",
  "description": "A test package",
  "main": "index.js",
  "scripts": {{
    "test": "echo \"Test\""
  }},
  "keywords": ["test"],
  "author": "test@example.com",
  "license": "MIT",
  "dependencies": {deps}
}}"#
    );

    fs::write(temp_dir.join("package.json"), package_json)?;
    fs::write(
        temp_dir.join("index.js"),
        "// Test file\nmodule.exports = {};",
    )?;

    Ok(())
}

#[test]
fn test_analyze_basic_npm_package() -> Result<()> {
    let temp_dir = TempDir::new()?;
    create_test_npm_package(
        temp_dir.path(),
        "test-package",
        "1.0.0",
        r#"{ "express": "^4.18.0" }"#,
    )?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Basic package info
    assert_eq!(analysis.package_info.name, "test-package");
    assert_eq!(analysis.package_info.version, "1.0.0");
    assert_eq!(analysis.package_info.license, Some("MIT".to_string()));

    // Dependencies
    assert!(analysis.dependencies.dependencies.contains_key("express"));
    assert_eq!(analysis.dependencies.dependency_count, 1);

    // Security analysis - should be clean
    assert!(!analysis.security_analysis.has_preinstall_script);
    assert!(!analysis.security_analysis.has_postinstall_script);

    Ok(())
}

#[test]
fn test_analyze_npm_package_missing_package_json() {
    let temp_dir = TempDir::new().unwrap();

    // Don't create package.json
    let result = analyze_npm_package(temp_dir.path());

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("package.json"));
}

#[test]
fn test_analyze_npm_package_invalid_json() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create invalid JSON
    fs::write(temp_dir.path().join("package.json"), "{ invalid json")?;

    let result = analyze_npm_package(temp_dir.path());

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_npm_vulnerability_detection() {
    // Test known vulnerable packages
    let vulns = check_package_vulnerabilities("event-stream", "3.3.6");
    assert!(!vulns.is_empty());
    assert_eq!(vulns[0].cve_id, "NPM-MALWARE-2018-001");

    let vulns = check_package_vulnerabilities("ua-parser-js", "0.7.29");
    assert!(!vulns.is_empty());
    assert_eq!(vulns[0].cve_id, "CVE-2021-41265");

    // Test safe versions
    let vulns = check_package_vulnerabilities("event-stream", "4.0.0");
    assert!(vulns.is_empty());
}

#[test]
fn test_npm_typosquatting_detection() {
    // Test exact typosquatting
    let similar = check_typosquatting_similarity("expres");
    assert!(similar.is_some());
    let similar_packages = similar.unwrap();
    assert!(similar_packages.iter().any(|s| s.contains("express")));

    let similar = check_typosquatting_similarity("lod-ash");
    assert!(similar.is_some());
    let similar_packages = similar.unwrap();
    assert!(similar_packages.iter().any(|s| s.contains("lodash")));

    // Test legitimate package
    let similar = check_typosquatting_similarity("my-unique-package-name");
    assert!(similar.is_none());
}

#[test]
fn test_analyze_npm_package_with_scripts() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let package_json = r#"{
  "name": "scripts-test",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "echo 'preinstall'",
    "postinstall": "echo 'postinstall'",
    "test": "echo 'test'"
  }
}"#;

    fs::write(temp_dir.path().join("package.json"), package_json)?;
    fs::write(temp_dir.path().join("index.js"), "module.exports = {};")?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Should detect install scripts
    assert!(analysis.security_analysis.has_preinstall_script);
    assert!(analysis.security_analysis.has_postinstall_script);

    Ok(())
}

#[test]
fn test_analyze_npm_package_with_dependencies() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let package_json = r#"{
  "name": "deps-test",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#;

    fs::write(temp_dir.path().join("package.json"), package_json)?;
    fs::write(temp_dir.path().join("index.js"), "module.exports = {};")?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Check dependencies
    assert_eq!(analysis.dependencies.dependencies.len(), 2);
    assert_eq!(analysis.dependencies.dev_dependencies.len(), 1);
    assert!(analysis.dependencies.dependencies.contains_key("express"));
    assert!(analysis.dependencies.dependencies.contains_key("lodash"));
    assert!(analysis.dependencies.dev_dependencies.contains_key("jest"));

    Ok(())
}

#[test]
fn test_analyze_npm_package_typosquatting_name() -> Result<()> {
    let temp_dir = TempDir::new()?;

    create_test_npm_package(
        temp_dir.path(),
        "expres", // Typo of "express"
        "1.0.0",
        "{}",
    )?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Should detect typosquatting
    assert!(
        analysis
            .malicious_indicators
            .typosquatting_risk
            .is_potential_typosquatting
    );
    assert!(!analysis
        .malicious_indicators
        .typosquatting_risk
        .similar_packages
        .is_empty());

    Ok(())
}

#[test]
fn test_analyze_npm_package_author_info() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let package_json = r#"{
  "name": "author-test",
  "version": "1.0.0",
  "author": {
    "name": "Test Author",
    "email": "test@example.com",
    "url": "https://example.com"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/test/package"
  }
}"#;

    fs::write(temp_dir.path().join("package.json"), package_json)?;
    fs::write(temp_dir.path().join("index.js"), "module.exports = {};")?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Check author info
    assert!(analysis.package_info.author.is_some());
    let author = analysis.package_info.author.as_ref().unwrap();
    assert_eq!(author.name, Some("Test Author".to_string()));
    assert_eq!(author.email, Some("test@example.com".to_string()));

    // Check repository info
    assert!(analysis.package_info.repository.is_some());
    let repo = analysis.package_info.repository.as_ref().unwrap();
    assert_eq!(repo.repo_type, "git");

    Ok(())
}

#[test]
fn test_analyze_npm_package_quality_metrics() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let package_json = r#"{
  "name": "quality-test",
  "version": "1.0.0",
  "description": "Test package",
  "keywords": ["test", "quality"],
  "license": "MIT"
}"#;

    fs::write(temp_dir.path().join("package.json"), package_json)?;
    fs::write(temp_dir.path().join("index.js"), "module.exports = {};")?;
    fs::write(temp_dir.path().join("README.md"), "# Test Package")?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Basic quality checks
    assert_eq!(analysis.package_info.name, "quality-test");
    assert!(analysis.package_info.description.is_some());
    assert!(!analysis.package_info.keywords.is_empty());

    // Quality metrics exist
    assert!(analysis.quality_metrics.documentation_score >= 0.0);
    assert!(analysis.quality_metrics.overall_quality_score >= 0.0);

    Ok(())
}

#[test]
fn test_analyze_npm_package_risk_levels() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // Create a simple safe package
    create_test_npm_package(temp_dir.path(), "safe-package", "1.0.0", "{}")?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Should have a defined risk level
    match analysis.malicious_indicators.risk_level {
        RiskLevel::Critical => assert!(analysis.malicious_indicators.overall_risk_score >= 80.0),
        RiskLevel::High => assert!(analysis.malicious_indicators.overall_risk_score >= 60.0),
        RiskLevel::Medium => assert!(analysis.malicious_indicators.overall_risk_score >= 40.0),
        RiskLevel::Low => assert!(analysis.malicious_indicators.overall_risk_score >= 20.0),
        RiskLevel::Safe => assert!(analysis.malicious_indicators.overall_risk_score < 20.0),
    }

    Ok(())
}

// Test vulnerable package detection from npm_vuln_db
#[test]
fn test_known_vulnerable_packages() {
    // Event-stream malware
    let vulns = check_package_vulnerabilities("event-stream", "3.3.6");
    assert_eq!(vulns.len(), 1);
    assert!(matches!(
        vulns[0].severity,
        file_scanner::dependency_analysis::VulnerabilitySeverity::Critical
    ));

    // UA-parser-js crypto mining
    let vulns = check_package_vulnerabilities("ua-parser-js", "0.7.29");
    assert_eq!(vulns.len(), 1);
    assert!(matches!(
        vulns[0].severity,
        file_scanner::dependency_analysis::VulnerabilitySeverity::Critical
    ));

    // Node-ipc protestware - test with a version that has special characters to trigger the check
    let vulns = check_package_vulnerabilities("node-ipc", "10.1.1-rc");
    assert!(!vulns.is_empty());

    // Colors protestware - test with a version that has special characters to trigger the check
    let vulns = check_package_vulnerabilities("colors", "1.4.1-beta");
    assert!(!vulns.is_empty());
}

// Test typosquatting patterns
#[test]
fn test_typosquatting_patterns() {
    // Common typos
    assert!(check_typosquatting_similarity("expres").is_some());
    assert!(check_typosquatting_similarity("axois").is_some());
    assert!(check_typosquatting_similarity("reakt").is_some());
    assert!(check_typosquatting_similarity("mooment").is_some());

    // Suffix patterns
    assert!(check_typosquatting_similarity("express-js").is_some());
    assert!(check_typosquatting_similarity("react-js").is_some());

    // Legitimate names
    assert!(check_typosquatting_similarity("totally-unique-name-xyz").is_none());
}

// Integration test with multiple features
#[test]
fn test_comprehensive_npm_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;

    let package_json = r#"{
  "name": "comprehensive-test",
  "version": "1.0.0",
  "description": "Comprehensive test package",
  "main": "index.js",
  "scripts": {
    "test": "jest",
    "build": "webpack"
  },
  "keywords": ["test", "comprehensive"],
  "author": {
    "name": "Test Author",
    "email": "test@example.com"
  },
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jest": "^29.5.0"
  }
}"#;

    fs::write(temp_dir.path().join("package.json"), package_json)?;
    fs::write(
        temp_dir.path().join("index.js"),
        r"
const express = require('express');
const _ = require('lodash');

const app = express();
module.exports = app;
",
    )?;
    fs::write(
        temp_dir.path().join("README.md"),
        "# Comprehensive Test Package",
    )?;

    let analysis = analyze_npm_package(temp_dir.path())?;

    // Comprehensive checks
    assert_eq!(analysis.package_info.name, "comprehensive-test");
    assert!(analysis.package_info.author.is_some());
    assert_eq!(analysis.dependencies.dependencies.len(), 2);
    assert_eq!(analysis.dependencies.dev_dependencies.len(), 1);

    // Should have reasonable risk level for a normal package
    assert!(matches!(
        analysis.malicious_indicators.risk_level,
        RiskLevel::Low | RiskLevel::Safe | RiskLevel::Medium
    ));

    Ok(())
}
