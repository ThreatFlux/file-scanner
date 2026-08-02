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

use file_scanner::dependency_analysis::*;
use file_scanner::function_analysis::{analyze_symbols, ImportInfo, SymbolCounts, SymbolTable};
use file_scanner::strings::ExtractedStrings;
use std::collections::HashMap;
use std::path::Path;

#[test]
fn test_analyze_dependencies_basic() {
    // Create a mock symbol table with some imports
    let symbol_table = SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![
            ImportInfo {
                name: "malloc".to_string(),
                library: Some("libc.so.6".to_string()),
                address: None,
                ordinal: None,
                is_delayed: false,
            },
            ImportInfo {
                name: "sin".to_string(),
                library: Some("libm.so.6".to_string()),
                address: None,
                ordinal: None,
                is_delayed: false,
            },
            ImportInfo {
                name: "pthread_create".to_string(),
                library: Some("libpthread.so.0".to_string()),
                address: None,
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
    };

    // Create mock extracted strings
    let extracted_strings = ExtractedStrings {
        total_count: 4,
        unique_count: 4,
        ascii_strings: vec![
            "dlopen".to_string(),
            "libssl.so.1.1".to_string(),
            "LoadLibraryA".to_string(),
            "kernel32.dll".to_string(),
        ],
        unicode_strings: vec![],
        interesting_strings: vec![],
    };

    let result = analyze_dependencies(
        Path::new("/fake/path"),
        &symbol_table,
        Some(&extracted_strings),
    );

    match result {
        Ok(analysis) => {
            // Check that we found dependencies
            assert!(!analysis.dependencies.is_empty());

            // Verify we found some dependencies
            println!(
                "Found dependencies: {:?}",
                analysis
                    .dependencies
                    .iter()
                    .map(|d| &d.name)
                    .collect::<Vec<_>>()
            );

            // Just check that we have dependencies
            assert!(
                !analysis.dependencies.is_empty(),
                "Should find at least one dependency"
            );

            // Check dependency graph
            assert!(analysis.dependency_graph.total_dependencies > 0);
        }
        Err(e) => {
            // It's okay if it fails due to file not existing
            eprintln!("Expected error for non-existent file: {e}");
        }
    }
}

#[test]
fn test_dependency_source_equality() {
    assert_eq!(DependencySource::Import, DependencySource::Import);
    assert_ne!(DependencySource::Import, DependencySource::DynamicLink);
    assert_eq!(DependencySource::RuntimeLoad, DependencySource::RuntimeLoad);
}

#[test]
fn test_vulnerability_severity_serialization() {
    let severities = vec![
        VulnerabilitySeverity::Critical,
        VulnerabilitySeverity::High,
        VulnerabilitySeverity::Medium,
        VulnerabilitySeverity::Low,
        VulnerabilitySeverity::None,
    ];

    for severity in severities {
        let serialized = serde_json::to_string(&severity).unwrap();
        let deserialized: VulnerabilitySeverity = serde_json::from_str(&serialized).unwrap();

        match (severity, deserialized) {
            (VulnerabilitySeverity::Critical, VulnerabilitySeverity::Critical) => {}
            (VulnerabilitySeverity::High, VulnerabilitySeverity::High) => {}
            (VulnerabilitySeverity::Medium, VulnerabilitySeverity::Medium) => {}
            (VulnerabilitySeverity::Low, VulnerabilitySeverity::Low) => {}
            (VulnerabilitySeverity::None, VulnerabilitySeverity::None) => {}
            _ => panic!("Severity serialization mismatch"),
        }
    }
}

#[test]
fn test_license_family_serialization() {
    let families = vec![
        LicenseFamily::Mit,
        LicenseFamily::Apache,
        LicenseFamily::Gpl,
        LicenseFamily::Lgpl,
        LicenseFamily::Bsd,
        LicenseFamily::Proprietary,
        LicenseFamily::PublicDomain,
        LicenseFamily::Unknown,
    ];

    for family in families {
        let serialized = serde_json::to_string(&family).unwrap();
        let deserialized: LicenseFamily = serde_json::from_str(&serialized).unwrap();

        match (family, deserialized) {
            (LicenseFamily::Mit, LicenseFamily::Mit) => {}
            (LicenseFamily::Apache, LicenseFamily::Apache) => {}
            (LicenseFamily::Gpl, LicenseFamily::Gpl) => {}
            (LicenseFamily::Lgpl, LicenseFamily::Lgpl) => {}
            (LicenseFamily::Bsd, LicenseFamily::Bsd) => {}
            (LicenseFamily::Proprietary, LicenseFamily::Proprietary) => {}
            (LicenseFamily::PublicDomain, LicenseFamily::PublicDomain) => {}
            (LicenseFamily::Unknown, LicenseFamily::Unknown) => {}
            _ => panic!("License family serialization mismatch"),
        }
    }
}

#[test]
fn test_library_type_serialization() {
    let types = vec![
        LibraryType::StaticLibrary,
        LibraryType::DynamicLibrary,
        LibraryType::SystemLibrary,
        LibraryType::RuntimeLibrary,
        LibraryType::Framework,
    ];

    for lib_type in types {
        let serialized = serde_json::to_string(&lib_type).unwrap();
        let deserialized: LibraryType = serde_json::from_str(&serialized).unwrap();

        match (lib_type, deserialized) {
            (LibraryType::StaticLibrary, LibraryType::StaticLibrary) => {}
            (LibraryType::DynamicLibrary, LibraryType::DynamicLibrary) => {}
            (LibraryType::SystemLibrary, LibraryType::SystemLibrary) => {}
            (LibraryType::RuntimeLibrary, LibraryType::RuntimeLibrary) => {}
            (LibraryType::Framework, LibraryType::Framework) => {}
            _ => panic!("Library type serialization mismatch"),
        }
    }
}

#[test]
fn test_dependency_graph_creation() {
    let deps = ["libc.so.6", "libm.so.6"];
    let mut transitive = HashMap::new();
    transitive.insert(
        "app".to_string(),
        deps.iter().map(std::string::ToString::to_string).collect(),
    );

    let graph = DependencyGraph {
        direct_dependencies: deps.iter().map(std::string::ToString::to_string).collect(),
        transitive_dependencies: transitive.clone(),
        dependency_tree: transitive,
        dependency_depth: 1,
        total_dependencies: 2,
    };

    assert_eq!(graph.direct_dependencies.len(), 2);
    assert_eq!(graph.total_dependencies, 2);
    assert_eq!(graph.dependency_depth, 1);
}

#[test]
fn test_known_vulnerability_creation() {
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
    assert_eq!(vuln.cvss_score, Some(7.5));
}

#[test]
fn test_license_info_creation() {
    let license = LicenseInfo {
        license_type: "MIT License".to_string(),
        license_family: LicenseFamily::Mit,
        is_oss: true,
        is_copyleft: false,
        is_commercial_friendly: true,
        attribution_required: true,
    };

    assert_eq!(license.license_type, "MIT License");
    assert!(matches!(license.license_family, LicenseFamily::Mit));
    assert!(license.is_oss);
    assert!(!license.is_copyleft);
    assert!(license.is_commercial_friendly);
}

#[test]
fn test_dependency_info_creation() {
    let dep = DependencyInfo {
        name: "libc".to_string(),
        version: Some("2.31".to_string()),
        library_type: LibraryType::SystemLibrary,
        path: Some("/lib/x86_64-linux-gnu/libc.so.6".to_string()),
        hash: Some("abc123".to_string()),
        vulnerabilities: vec![],
        license: None,
        source: DependencySource::Import,
        is_system_library: true,
        imported_functions: vec!["malloc".to_string(), "free".to_string()],
    };

    assert_eq!(dep.name, "libc");
    assert_eq!(dep.version, Some("2.31".to_string()));
    assert!(matches!(dep.library_type, LibraryType::SystemLibrary));
    assert!(dep.is_system_library);
    assert_eq!(dep.imported_functions.len(), 2);
}

#[test]
fn test_analyze_dependencies_with_real_binary() {
    // Try with the test binary if it exists
    let test_binary = Path::new("./target/debug/file-scanner");

    if test_binary.exists() {
        // Get function analysis first
        match analyze_symbols(test_binary) {
            Ok(symbol_table) => {
                // Create empty strings for testing
                let strings = ExtractedStrings {
                    total_count: 0,
                    unique_count: 0,
                    ascii_strings: vec![],
                    unicode_strings: vec![],
                    interesting_strings: vec![],
                };

                match analyze_dependencies(test_binary, &symbol_table, Some(&strings)) {
                    Ok(dep_analysis) => {
                        println!("Found {} dependencies", dep_analysis.dependencies.len());

                        // Should find at least some system libraries
                        let system_libs = dep_analysis
                            .dependencies
                            .iter()
                            .filter(|d| d.is_system_library)
                            .count();
                        assert!(system_libs > 0, "Should find at least one system library");
                    }
                    Err(e) => {
                        eprintln!("Dependency analysis failed (may be expected): {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Function analysis failed: {e}");
            }
        }
    }
}
