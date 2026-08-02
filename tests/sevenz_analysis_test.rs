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

use file_scanner::sevenz_analysis::*;
use tempfile::{NamedTempFile, TempDir};

const SEVENZ_SIGNATURE: &[u8] = b"7z\xBC\xAF\x27\x1C";

#[test]
fn test_7z_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 512]); // Add some content
    std::fs::write(temp_file.path(), &content).unwrap();

    assert!(is_7z_file(temp_file.path()));

    let analysis = analyze_7z(temp_file.path()).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::SevenZip));
    assert_eq!(analysis.metadata.created_by, Some("7-Zip".to_string()));
}

#[test]
fn test_invalid_7z_file() {
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), b"This is not a 7z file").unwrap();

    assert!(!is_7z_file(temp_file.path()));

    let result = analyze_7z(temp_file.path());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Not a valid 7z file"));
}

#[test]
fn test_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();

    assert!(!is_7z_file(temp_file.path()));

    let result = analyze_7z(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_suspicious_7z_filenames() {
    let temp_dir = TempDir::new().unwrap();

    // Test various suspicious filenames
    let suspicious_names = vec![
        "software_crack.7z",
        "keygen_2024.7z",
        "game_patch.7z",
        "windows_activator.7z",
        "trojan_payload.7z",
        "virus_sample.7z",
        "malware_kit.7z",
    ];

    for name in suspicious_names {
        let path = temp_dir.path().join(name);
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 100]);
        std::fs::write(&path, &content).unwrap();

        let analysis = analyze_7z(&path).unwrap();
        assert!(analysis.suspicious_indicators.has_suspicious_names);
        assert!(!analysis
            .suspicious_indicators
            .suspicious_patterns
            .is_empty());
        assert!(analysis.suspicious_indicators.risk_score > 0);
    }
}

#[test]
fn test_normal_7z_filename() {
    let temp_dir = TempDir::new().unwrap();
    let normal_path = temp_dir.path().join("documents.7z");

    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 1000]);
    std::fs::write(&normal_path, &content).unwrap();

    let analysis = analyze_7z(&normal_path).unwrap();
    assert!(!analysis.suspicious_indicators.has_suspicious_names);
    assert!(analysis
        .suspicious_indicators
        .suspicious_patterns
        .is_empty());
}

#[test]
fn test_potential_7z_bomb() {
    let temp_file = NamedTempFile::new().unwrap();
    // Create a very small 7z file (potential bomb indicator)
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 50]); // Total size < 1000 bytes
    std::fs::write(temp_file.path(), &content).unwrap();

    let analysis = analyze_7z(temp_file.path()).unwrap();
    assert!(analysis.suspicious_indicators.risk_score >= 25);
}

#[test]
fn test_encrypted_7z_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    // Add header with encryption indicators
    content.extend_from_slice(&[0x06, 0x01, 0x00]); // Encryption method indicators
    content.extend_from_slice(&[0u8; 512]);
    std::fs::write(temp_file.path(), &content).unwrap();

    let analysis = analyze_7z(temp_file.path()).unwrap();
    assert!(analysis.metadata.has_encryption);
}

#[test]
fn test_password_protected_filename() {
    let temp_dir = TempDir::new().unwrap();

    let password_files = vec![
        "password_protected.7z",
        "encrypted_backup.7z",
        "secret_encrypted.7z",
    ];

    for name in password_files {
        let path = temp_dir.path().join(name);
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 1000]);
        std::fs::write(&path, &content).unwrap();

        let analysis = analyze_7z(&path).unwrap();
        assert!(analysis.suspicious_indicators.risk_score >= 15); // Password indicator bonus
    }
}

#[test]
fn test_7z_metadata_structure() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 2048]);
    std::fs::write(temp_file.path(), &content).unwrap();

    let analysis = analyze_7z(temp_file.path()).unwrap();

    // Check metadata fields
    assert_eq!(analysis.metadata.total_entries, 0); // Not parsed in basic impl
    assert_eq!(analysis.metadata.total_size_compressed, 2054); // Signature + data
    assert_eq!(analysis.metadata.compression_ratio, 0.0);
    assert!(!analysis.metadata.has_password);
    assert!(analysis.metadata.comment.is_none());
    assert!(analysis.metadata.creation_date.is_none());
    assert_eq!(analysis.metadata.created_by, Some("7-Zip".to_string()));
}

#[test]
fn test_risk_level_calculation() {
    let temp_dir = TempDir::new().unwrap();

    // Critical risk: suspicious name + small size + password hint
    let critical_path = temp_dir.path().join("virus_encrypted.7z");
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 50]); // Small file
    std::fs::write(&critical_path, &content).unwrap();

    let analysis = analyze_7z(&critical_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Critical | RiskLevel::High
    ));

    // Low risk: normal name and size
    let low_risk_path = temp_dir.path().join("backup.7z");
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 5000]); // Normal size
    std::fs::write(&low_risk_path, &content).unwrap();

    let analysis = analyze_7z(&low_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low
    ));
}

#[test]
fn test_7z_serialization() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 1024]);
    std::fs::write(temp_file.path(), &content).unwrap();

    let analysis = analyze_7z(temp_file.path()).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

    assert!(matches!(deserialized.archive_type, ArchiveType::SevenZip));
    assert_eq!(
        deserialized.metadata.created_by,
        analysis.metadata.created_by
    );
}

#[test]
fn test_comprehensive_suspicious_patterns() {
    let temp_dir = TempDir::new().unwrap();

    // Test edge case combinations
    let edge_cases = vec![
        ("CRACK.7Z", true),           // Uppercase
        ("my_keygen_tool.7z", true),  // Embedded keyword
        ("backdoor123.7z", true),     // With numbers
        ("exploit-kit.7z", true),     // With hyphens
        ("clean_archive.7z", false),  // Clean name
        ("project_backup.7z", false), // Normal backup
    ];

    for (filename, should_be_suspicious) in edge_cases {
        let path = temp_dir.path().join(filename);
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 1000]);
        std::fs::write(&path, &content).unwrap();

        let analysis = analyze_7z(&path).unwrap();
        assert_eq!(
            analysis.suspicious_indicators.has_suspicious_names, should_be_suspicious,
            "Failed for filename: {filename}"
        );
    }
}

// Integration test with archive_analysis types
use file_scanner::archive_analysis::{ArchiveAnalysis, ArchiveType, RiskLevel};

#[test]
fn test_7z_analysis_integration() {
    let temp_file = NamedTempFile::new().unwrap();
    let mut content = Vec::from(SEVENZ_SIGNATURE);
    content.extend_from_slice(&[0u8; 1024]);
    std::fs::write(temp_file.path(), &content).unwrap();

    let analysis = analyze_7z(temp_file.path()).unwrap();

    // Verify it returns proper ArchiveAnalysis structure
    assert!(matches!(analysis.archive_type, ArchiveType::SevenZip));
    assert!(analysis.entries.is_empty()); // Basic implementation doesn't parse entries
    assert!(analysis.nested_archives.is_empty());

    // Check security analysis
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low | RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
    ));
    assert!(analysis.security_analysis.malicious_patterns.is_empty());
    assert!(analysis.security_analysis.suspicious_files.is_empty());
}

#[test]
fn test_short_file_handling() {
    let temp_file = NamedTempFile::new().unwrap();
    // File too short to be a valid 7z
    std::fs::write(temp_file.path(), b"7z").unwrap();

    assert!(!is_7z_file(temp_file.path()));

    let result = analyze_7z(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_exact_signature_match() {
    let temp_file = NamedTempFile::new().unwrap();
    // Test with exact signature only
    std::fs::write(temp_file.path(), SEVENZ_SIGNATURE).unwrap();

    assert!(is_7z_file(temp_file.path()));

    let analysis = analyze_7z(temp_file.path()).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::SevenZip));
}
