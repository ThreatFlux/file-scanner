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

use file_scanner::rar_analysis::*;
use std::fs::File;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

#[test]
fn test_rar_v4_detection() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    temp_file.write_all(&[0u8; 512]).unwrap(); // Add some content
    temp_file.flush().unwrap();

    assert!(is_rar_file(temp_file.path()));

    let analysis = analyze_rar(temp_file.path()).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::Rar));
    assert_eq!(analysis.metadata.created_by, Some("RAR 4.x".to_string()));
}

#[test]
fn test_rar_v5_detection() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x01\x00").unwrap();
    temp_file.write_all(&[0u8; 512]).unwrap(); // Add some content
    temp_file.flush().unwrap();

    assert!(is_rar_file(temp_file.path()));

    let analysis = analyze_rar(temp_file.path()).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::Rar));
    assert_eq!(analysis.metadata.created_by, Some("RAR 5.x".to_string()));
}

#[test]
fn test_invalid_rar_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"This is not a RAR file").unwrap();
    temp_file.flush().unwrap();

    assert!(!is_rar_file(temp_file.path()));

    let result = analyze_rar(temp_file.path());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Not a valid RAR file"));
}

#[test]
fn test_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();

    assert!(!is_rar_file(temp_file.path()));

    let result = analyze_rar(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_suspicious_rar_filenames() {
    let temp_dir = TempDir::new().unwrap();

    // Test various suspicious filenames
    let suspicious_names = vec![
        "software_crack.rar",
        "keygen_2024.rar",
        "game_patch.rar",
        "windows_activator.rar",
    ];

    for name in suspicious_names {
        let path = temp_dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(b"Rar!\x1a\x07\x00").unwrap();
        file.write_all(&[0u8; 100]).unwrap();

        let analysis = analyze_rar(&path).unwrap();
        assert!(analysis.suspicious_indicators.has_suspicious_names);
        assert!(!analysis
            .suspicious_indicators
            .suspicious_patterns
            .is_empty());
        assert!(analysis.suspicious_indicators.risk_score > 0);
    }
}

#[test]
fn test_normal_rar_filename() {
    let temp_dir = TempDir::new().unwrap();
    let normal_path = temp_dir.path().join("documents.rar");

    let mut file = File::create(&normal_path).unwrap();
    file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    file.write_all(&[0u8; 1000]).unwrap();

    let analysis = analyze_rar(&normal_path).unwrap();
    assert!(!analysis.suspicious_indicators.has_suspicious_names);
    assert!(analysis
        .suspicious_indicators
        .suspicious_patterns
        .is_empty());
}

#[test]
fn test_potential_rar_bomb() {
    let mut temp_file = NamedTempFile::new().unwrap();
    // Create a very small RAR file (potential bomb indicator)
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    temp_file.write_all(&[0u8; 50]).unwrap(); // Total size < 1000 bytes
    temp_file.flush().unwrap();

    let analysis = analyze_rar(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.risk_score >= 20);
}

#[test]
fn test_encrypted_rar_detection() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    // Add header with encryption flag
    temp_file.write_all(&[0x73, 0x80, 0x00]).unwrap(); // Block with encryption flag
    temp_file.write_all(&[0u8; 512]).unwrap();
    temp_file.flush().unwrap();

    let analysis = analyze_rar(temp_file.path()).unwrap();
    assert!(analysis.metadata.has_encryption);
}

#[test]
fn test_rar_metadata_structure() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    temp_file.write_all(&[0u8; 2048]).unwrap();
    temp_file.flush().unwrap();

    let analysis = analyze_rar(temp_file.path()).unwrap();

    // Check metadata fields
    assert_eq!(analysis.metadata.total_entries, 0); // Not parsed in basic impl
    assert_eq!(analysis.metadata.total_size_compressed, 2055); // Header + data
    assert_eq!(analysis.metadata.compression_ratio, 0.0);
    assert!(!analysis.metadata.has_password);
    assert!(analysis.metadata.comment.is_none());
    assert!(analysis.metadata.creation_date.is_none());
}

#[test]
fn test_risk_level_calculation() {
    // Test different risk scenarios
    let temp_dir = TempDir::new().unwrap();

    // High risk: suspicious name + small size
    let high_risk_path = temp_dir.path().join("crack.rar");
    let mut file = File::create(&high_risk_path).unwrap();
    file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    file.write_all(&[0u8; 50]).unwrap(); // Small file

    let analysis = analyze_rar(&high_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::High | RiskLevel::Medium
    ));

    // Low risk: normal name and size
    let low_risk_path = temp_dir.path().join("archive.rar");
    let mut file = File::create(&low_risk_path).unwrap();
    file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    file.write_all(&[0u8; 5000]).unwrap(); // Normal size

    let analysis = analyze_rar(&low_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low
    ));
}

#[test]
fn test_rar_serialization() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    temp_file.write_all(&[0u8; 1024]).unwrap();
    temp_file.flush().unwrap();

    let analysis = analyze_rar(temp_file.path()).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

    assert!(matches!(deserialized.archive_type, ArchiveType::Rar));
    assert_eq!(
        deserialized.metadata.created_by,
        analysis.metadata.created_by
    );
}

#[test]
fn test_multiple_rar_versions() {
    // Test that we can handle different RAR versions
    let versions = vec![
        (b"Rar!\x1a\x07\x00".to_vec(), "RAR 4.x"),
        (b"Rar!\x1a\x07\x01\x00".to_vec(), "RAR 5.x"),
    ];

    for (signature, expected_version) in versions {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&signature).unwrap();
        temp_file.write_all(&[0u8; 256]).unwrap();
        temp_file.flush().unwrap();

        let analysis = analyze_rar(temp_file.path()).unwrap();
        assert_eq!(
            analysis.metadata.created_by,
            Some(expected_version.to_string())
        );
    }
}

// Integration test with archive_analysis types
use file_scanner::archive_analysis::{ArchiveAnalysis, ArchiveType, RiskLevel};

#[test]
fn test_rar_analysis_integration() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"Rar!\x1a\x07\x00").unwrap();
    temp_file.write_all(&[0u8; 1024]).unwrap();
    temp_file.flush().unwrap();

    let analysis = analyze_rar(temp_file.path()).unwrap();

    // Verify it returns proper ArchiveAnalysis structure
    assert!(matches!(analysis.archive_type, ArchiveType::Rar));
    assert!(analysis.entries.is_empty()); // Basic implementation doesn't parse entries
    assert!(analysis.nested_archives.is_empty());

    // Check security analysis
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low | RiskLevel::Medium | RiskLevel::High
    ));
    assert!(analysis.security_analysis.malicious_patterns.is_empty());
    assert!(analysis.security_analysis.suspicious_files.is_empty());
}
