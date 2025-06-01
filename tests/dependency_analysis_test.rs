use file_scanner::dependency_analysis::*;
use file_scanner::function_analysis::{ImportInfo, SymbolCounts, SymbolTable};
use file_scanner::strings::ExtractedStrings;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[cfg(test)]
mod dependency_analysis_tests {
    use super::*;

    // Helper function to create test symbol table
    fn create_test_symbol_table() -> SymbolTable {
        SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![
                ImportInfo {
                    name: "printf@GLIBC_2.2.5".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "malloc@GLIBC_2.2.5".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x1010),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "SSL_CTX_new@OPENSSL_1.0.0".to_string(),
                    library: Some("libssl.so.1.0.0".to_string()),
                    address: Some(0x1020),
                    ordinal: None,
                    is_delayed: false,
                },
            ],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 3,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        }
    }

    // Helper function to create test extracted strings
    fn create_test_strings() -> ExtractedStrings {
        ExtractedStrings {
            total_count: 7,
            unique_count: 7,
            ascii_strings: vec![
                "libcrypto.so.1.1".to_string(),
                "libz.so.1.2.11".to_string(),
                "log4j-core-2.14.0.jar".to_string(),
                "MIT License".to_string(),
                "Apache License Version 2.0".to_string(),
                "version 1.0.1f".to_string(),
                "OpenSSL 1.0.1e".to_string(),
            ],
            unicode_strings: vec![],
            interesting_strings: vec![],
        }
    }

    fn create_test_binary() -> Vec<u8> {
        // Create a minimal binary that can be analyzed
        vec![0x7f, 0x45, 0x4c, 0x46] // ELF magic
    }

    #[test]
    fn test_basic_dependency_analysis() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&create_test_binary()).unwrap();
        file.flush().unwrap();

        let symbol_table = create_test_symbol_table();
        let strings = create_test_strings();

        let result = analyze_dependencies(file.path(), &symbol_table, Some(&strings));

        match result {
            Ok(analysis) => {
                assert!(analysis.dependencies.len() >= 3);
                assert!(analysis
                    .dependencies
                    .iter()
                    .any(|d| d.name.contains("glibc") || d.name.contains("libc")));
                assert!(analysis
                    .dependencies
                    .iter()
                    .any(|d| d.name.contains("openssl") || d.name.contains("ssl")));
            }
            Err(e) => panic!("Analysis failed: {}", e),
        }
    }

    #[test]
    fn test_vulnerability_detection() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&create_test_binary()).unwrap();
        file.flush().unwrap();

        let mut symbol_table = create_test_symbol_table();

        // Add vulnerable OpenSSL version
        symbol_table.imports.push(ImportInfo {
            name: "SSL_read@OPENSSL_1.0.1e".to_string(),
            library: Some("libssl.so.1.0.1".to_string()),
            address: Some(0x1030),
            ordinal: None,
            is_delayed: false,
        });

        let strings = ExtractedStrings {
            total_count: 1,
            unique_count: 1,
            ascii_strings: vec!["OpenSSL 1.0.1e".to_string()],
            unicode_strings: vec![],
            interesting_strings: vec![],
        };

        let result = analyze_dependencies(file.path(), &symbol_table, Some(&strings));

        match result {
            Ok(analysis) => {
                // Check if vulnerabilities were detected
                let has_vulnerable_deps = analysis
                    .dependencies
                    .iter()
                    .any(|d| !d.vulnerabilities.is_empty());

                assert!(
                    has_vulnerable_deps || analysis.security_assessment.total_vulnerabilities > 0
                );
            }
            Err(e) => panic!("Analysis failed: {}", e),
        }
    }

    #[test]
    fn test_license_detection_in_strings() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&create_test_binary()).unwrap();
        file.flush().unwrap();

        let symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let strings = ExtractedStrings {
            total_count: 4,
            unique_count: 4,
            ascii_strings: vec![
                "MIT License".to_string(),
                "Apache License Version 2.0".to_string(),
                "GNU General Public License version 3".to_string(),
                "BSD 3-Clause License".to_string(),
            ],
            unicode_strings: vec![],
            interesting_strings: vec![],
        };

        let result = analyze_dependencies(file.path(), &symbol_table, Some(&strings));

        match result {
            Ok(analysis) => {
                // Check that licenses were found
                assert!(!analysis.license_summary.licenses_found.is_empty());
            }
            Err(e) => panic!("Analysis failed: {}", e),
        }
    }

    #[test]
    fn test_empty_analysis() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&create_test_binary()).unwrap();
        file.flush().unwrap();

        let symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 0,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let result = analyze_dependencies(file.path(), &symbol_table, None);

        match result {
            Ok(analysis) => {
                assert_eq!(analysis.dependencies.len(), 0);
                assert_eq!(analysis.security_assessment.total_vulnerabilities, 0);
                assert_eq!(analysis.security_assessment.security_score, 100.0);
            }
            Err(e) => panic!("Analysis failed: {}", e),
        }
    }

    #[test]
    fn test_dependency_info_structure() {
        let dep = DependencyInfo {
            name: "test-lib".to_string(),
            version: Some("1.0.0".to_string()),
            library_type: LibraryType::DynamicLibrary,
            path: Some("/usr/lib/test-lib.so".to_string()),
            hash: Some("abcdef123456".to_string()),
            vulnerabilities: vec![],
            license: None,
            source: DependencySource::Import,
            is_system_library: false,
            imported_functions: vec!["func1".to_string(), "func2".to_string()],
        };

        assert_eq!(dep.name, "test-lib");
        assert_eq!(dep.version.unwrap(), "1.0.0");
        assert!(matches!(dep.library_type, LibraryType::DynamicLibrary));
        assert!(matches!(dep.source, DependencySource::Import));
        assert_eq!(dep.imported_functions.len(), 2);
    }

    #[test]
    fn test_vulnerability_structure() {
        let vuln = KnownVulnerability {
            cve_id: "CVE-2021-12345".to_string(),
            severity: VulnerabilitySeverity::High,
            description: "Test vulnerability".to_string(),
            affected_versions: vec!["1.0.0".to_string(), "1.0.1".to_string()],
            fixed_in: Some("1.0.2".to_string()),
            cvss_score: Some(7.5),
            published_date: Some("2021-01-01".to_string()),
        };

        assert_eq!(vuln.cve_id, "CVE-2021-12345");
        assert!(matches!(vuln.severity, VulnerabilitySeverity::High));
        assert_eq!(vuln.affected_versions.len(), 2);
        assert!(vuln.fixed_in.is_some());
        assert!(vuln.cvss_score.is_some());
    }

    #[test]
    fn test_license_info_structure() {
        let license = LicenseInfo {
            license_type: "MIT".to_string(),
            license_family: LicenseFamily::MIT,
            is_oss: true,
            is_copyleft: false,
            is_commercial_friendly: true,
            attribution_required: true,
        };

        assert_eq!(license.license_type, "MIT");
        assert!(matches!(license.license_family, LicenseFamily::MIT));
        assert!(license.is_oss);
        assert!(!license.is_copyleft);
        assert!(license.is_commercial_friendly);
        assert!(license.attribution_required);
    }

    #[test]
    fn test_security_assessment_structure() {
        let assessment = SecurityAssessment {
            vulnerable_dependencies: vec![VulnerableDependency {
                dependency_name: "vulnerable-lib".to_string(),
                current_version: Some("1.0.0".to_string()),
                vulnerabilities: vec!["CVE-2021-12345".to_string()],
                highest_severity: VulnerabilitySeverity::Critical,
                recommended_action: "Update immediately".to_string(),
            }],
            total_vulnerabilities: 1,
            critical_vulnerabilities: 1,
            high_vulnerabilities: 0,
            outdated_dependencies: vec![],
            security_score: 30.0,
            risk_level: SecurityRiskLevel::Critical,
            recommendations: vec!["Update vulnerable-lib immediately".to_string()],
        };

        assert_eq!(assessment.total_vulnerabilities, 1);
        assert_eq!(assessment.critical_vulnerabilities, 1);
        assert_eq!(assessment.vulnerable_dependencies.len(), 1);
        assert!(matches!(assessment.risk_level, SecurityRiskLevel::Critical));
        assert!(!assessment.recommendations.is_empty());
    }

    #[test]
    fn test_license_summary_structure() {
        let summary = LicenseSummary {
            licenses_found: vec!["MIT".to_string(), "Apache-2.0".to_string()],
            license_conflicts: vec![],
            copyleft_dependencies: vec![],
            proprietary_dependencies: vec![],
            compliance_issues: vec![ComplianceIssue {
                dependency: "unknown-lib".to_string(),
                issue_type: ComplianceIssueType::MissingLicense,
                description: "No license information found".to_string(),
                severity: ComplianceSeverity::High,
            }],
            is_commercial_use_safe: true,
        };

        assert_eq!(summary.licenses_found.len(), 2);
        assert!(summary.license_conflicts.is_empty());
        assert!(summary.copyleft_dependencies.is_empty());
        assert_eq!(summary.compliance_issues.len(), 1);
        assert!(summary.is_commercial_use_safe);
    }

    #[test]
    fn test_dependency_graph_structure() {
        let graph = DependencyGraph {
            direct_dependencies: vec!["lib1".to_string(), "lib2".to_string()],
            transitive_dependencies: HashMap::new(),
            dependency_tree: HashMap::new(),
            dependency_depth: 2,
            total_dependencies: 5,
        };

        assert_eq!(graph.direct_dependencies.len(), 2);
        assert_eq!(graph.dependency_depth, 2);
        assert_eq!(graph.total_dependencies, 5);
    }

    #[test]
    fn test_library_types() {
        let types = vec![
            LibraryType::StaticLibrary,
            LibraryType::DynamicLibrary,
            LibraryType::SystemLibrary,
            LibraryType::RuntimeLibrary,
            LibraryType::Framework,
        ];

        for lt in types {
            match lt {
                LibraryType::StaticLibrary => assert!(true),
                LibraryType::DynamicLibrary => assert!(true),
                LibraryType::SystemLibrary => assert!(true),
                LibraryType::RuntimeLibrary => assert!(true),
                LibraryType::Framework => assert!(true),
            }
        }
    }

    #[test]
    fn test_dependency_sources() {
        let sources = vec![
            DependencySource::Import,
            DependencySource::DynamicLink,
            DependencySource::StaticLink,
            DependencySource::StringReference,
            DependencySource::RuntimeLoad,
        ];

        for source in sources {
            match source {
                DependencySource::Import => assert!(true),
                DependencySource::DynamicLink => assert!(true),
                DependencySource::StaticLink => assert!(true),
                DependencySource::StringReference => assert!(true),
                DependencySource::RuntimeLoad => assert!(true),
            }
        }
    }

    #[test]
    fn test_vulnerability_severities() {
        let severities = vec![
            VulnerabilitySeverity::Critical,
            VulnerabilitySeverity::High,
            VulnerabilitySeverity::Medium,
            VulnerabilitySeverity::Low,
            VulnerabilitySeverity::None,
        ];

        for severity in severities {
            match severity {
                VulnerabilitySeverity::Critical => assert!(true),
                VulnerabilitySeverity::High => assert!(true),
                VulnerabilitySeverity::Medium => assert!(true),
                VulnerabilitySeverity::Low => assert!(true),
                VulnerabilitySeverity::None => assert!(true),
            }
        }
    }

    #[test]
    fn test_security_risk_levels() {
        let levels = vec![
            SecurityRiskLevel::Critical,
            SecurityRiskLevel::High,
            SecurityRiskLevel::Medium,
            SecurityRiskLevel::Low,
            SecurityRiskLevel::Minimal,
        ];

        for level in levels {
            match level {
                SecurityRiskLevel::Critical => assert!(true),
                SecurityRiskLevel::High => assert!(true),
                SecurityRiskLevel::Medium => assert!(true),
                SecurityRiskLevel::Low => assert!(true),
                SecurityRiskLevel::Minimal => assert!(true),
            }
        }
    }

    #[test]
    fn test_compliance_issue_types() {
        let types = vec![
            ComplianceIssueType::MissingLicense,
            ComplianceIssueType::IncompatibleLicense,
            ComplianceIssueType::AttributionRequired,
            ComplianceIssueType::SourceCodeRequired,
            ComplianceIssueType::PatentConcern,
        ];

        for issue_type in types {
            match issue_type {
                ComplianceIssueType::MissingLicense => assert!(true),
                ComplianceIssueType::IncompatibleLicense => assert!(true),
                ComplianceIssueType::AttributionRequired => assert!(true),
                ComplianceIssueType::SourceCodeRequired => assert!(true),
                ComplianceIssueType::PatentConcern => assert!(true),
            }
        }
    }

    #[test]
    fn test_license_families() {
        let families = vec![
            LicenseFamily::MIT,
            LicenseFamily::Apache,
            LicenseFamily::GPL,
            LicenseFamily::LGPL,
            LicenseFamily::BSD,
            LicenseFamily::Proprietary,
            LicenseFamily::PublicDomain,
            LicenseFamily::Unknown,
        ];

        for family in families {
            match family {
                LicenseFamily::MIT => assert!(true),
                LicenseFamily::Apache => assert!(true),
                LicenseFamily::GPL => assert!(true),
                LicenseFamily::LGPL => assert!(true),
                LicenseFamily::BSD => assert!(true),
                LicenseFamily::Proprietary => assert!(true),
                LicenseFamily::PublicDomain => assert!(true),
                LicenseFamily::Unknown => assert!(true),
            }
        }
    }

    #[test]
    fn test_analysis_with_multiple_dependencies() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&create_test_binary()).unwrap();
        file.flush().unwrap();

        let symbol_table = SymbolTable {
            functions: vec![],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![
                ImportInfo {
                    name: "printf@GLIBC_2.2.5".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x1000),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "malloc@GLIBC_2.2.5".to_string(),
                    library: Some("libc.so.6".to_string()),
                    address: Some(0x1010),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "SSL_CTX_new@OPENSSL_1.0.0".to_string(),
                    library: Some("libssl.so.1.0.0".to_string()),
                    address: Some(0x1020),
                    ordinal: None,
                    is_delayed: false,
                },
                ImportInfo {
                    name: "EVP_sha256".to_string(),
                    library: Some("libcrypto.so.1.1".to_string()),
                    address: Some(0x1030),
                    ordinal: None,
                    is_delayed: false,
                },
            ],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 0,
                local_functions: 0,
                imported_functions: 4,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let result = analyze_dependencies(file.path(), &symbol_table, None);

        match result {
            Ok(analysis) => {
                assert!(analysis.dependencies.len() >= 3);
                assert!(analysis.dependency_graph.total_dependencies >= 3);
                assert!(!analysis.dependency_graph.direct_dependencies.is_empty());
            }
            Err(e) => panic!("Analysis failed: {}", e),
        }
    }
}
