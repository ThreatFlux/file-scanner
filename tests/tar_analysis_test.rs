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

use file_scanner::tar_analysis::*;
use tempfile::{NamedTempFile, TempDir};

// Helper function to create a minimal valid TAR archive
fn create_test_tar() -> Vec<u8> {
    let mut tar = vec![0u8; 2560]; // 5 blocks: header + data + padding + end

    // Create file entry "hello.txt" with content "Hello World!"
    tar[0..9].copy_from_slice(b"hello.txt");
    tar[100..108].copy_from_slice(b"0000644 "); // Mode (octal)
    tar[108..116].copy_from_slice(b"0001000 "); // UID
    tar[116..124].copy_from_slice(b"0001000 "); // GID
    tar[124..135].copy_from_slice(b"00000000014"); // Size: 12 bytes
    tar[136..147].copy_from_slice(b"14174607250"); // Mtime
    tar[156] = b'0'; // Regular file
    tar[257..262].copy_from_slice(b"ustar"); // Magic
    tar[263..265].copy_from_slice(b"00"); // Version

    // Calculate checksum
    let mut checksum = 0u32;
    for (i, &byte) in tar[0..512].iter().enumerate() {
        if (148..156).contains(&i) {
            checksum += u32::from(b' '); // Checksum field treated as spaces
        } else {
            checksum += u32::from(byte);
        }
    }
    let checksum_str = format!("{checksum:06o}\0 ");
    tar[148..156].copy_from_slice(checksum_str.as_bytes());

    // Add file content in next block
    tar[512..524].copy_from_slice(b"Hello World!");

    tar
}

// Helper to create gzip compressed data
fn create_gzip_header() -> Vec<u8> {
    vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]
}

// Helper to create bzip2 compressed data
fn create_bzip2_header() -> Vec<u8> {
    vec![0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
}

// Helper to create xz compressed data
fn create_xz_header() -> Vec<u8> {
    vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6]
}

#[test]
fn test_plain_tar_detection() {
    let tar_data = create_test_tar();
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &tar_data).unwrap();

    assert!(is_tar_file(temp_file.path()));

    let analysis = analyze_tar(temp_file.path()).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::Tar));
    assert_eq!(analysis.metadata.total_entries, 1);
    assert!(analysis
        .metadata
        .created_by
        .unwrap()
        .contains("uncompressed"));
}

#[test]
fn test_tar_gz_detection() {
    let temp_dir = TempDir::new().unwrap();
    let tar_gz_path = temp_dir.path().join("archive.tar.gz");

    let mut data = create_gzip_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tar_gz_path, &data).unwrap();

    assert!(is_tar_file(&tar_gz_path));

    let analysis = analyze_tar(&tar_gz_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarGz));
    assert!(analysis.metadata.created_by.unwrap().contains("gzip"));
}

#[test]
fn test_tar_bz2_detection() {
    let temp_dir = TempDir::new().unwrap();
    let tar_bz2_path = temp_dir.path().join("archive.tar.bz2");

    let mut data = create_bzip2_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tar_bz2_path, &data).unwrap();

    assert!(is_tar_file(&tar_bz2_path));

    let analysis = analyze_tar(&tar_bz2_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarBz2));
    assert!(analysis.metadata.created_by.unwrap().contains("bzip2"));
}

#[test]
fn test_tar_xz_detection() {
    let temp_dir = TempDir::new().unwrap();
    let tar_xz_path = temp_dir.path().join("archive.tar.xz");

    let mut data = create_xz_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tar_xz_path, &data).unwrap();

    assert!(is_tar_file(&tar_xz_path));

    let analysis = analyze_tar(&tar_xz_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarXz));
    assert!(analysis.metadata.created_by.unwrap().contains("xz"));
}

#[test]
fn test_tgz_extension() {
    let temp_dir = TempDir::new().unwrap();
    let tgz_path = temp_dir.path().join("archive.tgz");

    let mut data = create_gzip_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tgz_path, &data).unwrap();

    let analysis = analyze_tar(&tgz_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarGz));
}

#[test]
fn test_tbz2_extension() {
    let temp_dir = TempDir::new().unwrap();
    let tbz2_path = temp_dir.path().join("archive.tbz2");

    let mut data = create_bzip2_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tbz2_path, &data).unwrap();

    let analysis = analyze_tar(&tbz2_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarBz2));
}

#[test]
fn test_txz_extension() {
    let temp_dir = TempDir::new().unwrap();
    let txz_path = temp_dir.path().join("archive.txz");

    let mut data = create_xz_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&txz_path, &data).unwrap();

    let analysis = analyze_tar(&txz_path).unwrap();
    assert!(matches!(analysis.archive_type, ArchiveType::TarXz));
}

#[test]
fn test_invalid_tar_file() {
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), b"This is not a TAR file").unwrap();

    assert!(!is_tar_file(temp_file.path()));

    let result = analyze_tar(temp_file.path());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Not a valid TAR file"));
}

#[test]
fn test_empty_file() {
    let temp_file = NamedTempFile::new().unwrap();

    assert!(!is_tar_file(temp_file.path()));

    let result = analyze_tar(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_suspicious_tar_filenames() {
    let temp_dir = TempDir::new().unwrap();

    let suspicious_names = vec![
        "malware_crack.tar",
        "keygen_tool.tar.gz",
        "exploit_kit.tar.bz2",
        "trojan_payload.tar.xz",
        "virus_samples.tgz",
        "backdoor_tools.tbz2",
        "rootkit_source.tar",
    ];

    for name in suspicious_names {
        let path = temp_dir.path().join(name);
        let tar_data = create_test_tar();
        std::fs::write(&path, &tar_data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        assert!(analysis.suspicious_indicators.has_suspicious_names);
        assert!(!analysis
            .suspicious_indicators
            .suspicious_patterns
            .is_empty());
        assert!(analysis.suspicious_indicators.risk_score > 0);
    }
}

#[test]
fn test_normal_tar_filenames() {
    let temp_dir = TempDir::new().unwrap();

    let normal_names = vec![
        "documents.tar",
        "source_code.tar.gz",
        "backup_files.tar.bz2",
        "project_archive.tar.xz",
        "data_export.tgz",
    ];

    for name in normal_names {
        let path = temp_dir.path().join(name);
        let tar_data = create_test_tar();
        std::fs::write(&path, &tar_data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        assert!(!analysis.suspicious_indicators.has_suspicious_names);
        assert!(analysis
            .suspicious_indicators
            .suspicious_patterns
            .is_empty());
    }
}

#[test]
fn test_package_manager_tar_safety() {
    let temp_dir = TempDir::new().unwrap();

    let package_names = vec![
        ("safe-package-1.0.tar.xz", {
            let mut data = create_xz_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
        ("pkg-tools-2.1.tar.gz", {
            let mut data = create_gzip_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
        ("libpackage-dev.tar.bz2", {
            let mut data = create_bzip2_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
    ];

    for (name, data) in package_names {
        let path = temp_dir.path().join(name);
        std::fs::write(&path, &data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        // Package manager files should have reduced risk
        assert!(
            analysis.suspicious_indicators.risk_score < 20,
            "Risk score {} >= 20 for package {}",
            analysis.suspicious_indicators.risk_score,
            name
        );
    }
}

#[test]
fn test_source_code_tar_safety() {
    let temp_dir = TempDir::new().unwrap();

    let source_names = vec![
        "project-src.tar.gz",
        "source_backup.tar.bz2",
        "dev_archive.tar.xz",
        "code_backup.tgz",
    ];

    for name in source_names {
        let path = temp_dir.path().join(name);
        let tar_data = create_test_tar();
        std::fs::write(&path, &tar_data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        // Source/backup files should have reduced risk
        assert!(analysis.suspicious_indicators.risk_score < 15);
    }
}

#[test]
fn test_potential_tar_bomb() {
    let temp_file = NamedTempFile::new().unwrap();
    // Create a very small TAR file (potential bomb indicator)
    let small_tar = vec![0u8; 100]; // Much smaller than normal TAR
    std::fs::write(temp_file.path(), &small_tar).unwrap();

    if let Ok(analysis) = analyze_tar(temp_file.path()) {
        assert!(analysis.suspicious_indicators.risk_score >= 20);
    }
}

#[test]
fn test_tar_metadata_structure() {
    let tar_data = create_test_tar();
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &tar_data).unwrap();

    let analysis = analyze_tar(temp_file.path()).unwrap();

    // Check metadata fields
    assert_eq!(analysis.metadata.total_entries, 1);
    assert_eq!(
        analysis.metadata.total_size_compressed,
        tar_data.len() as u64
    );
    assert_eq!(analysis.metadata.compression_ratio, 0.0); // Uncompressed TAR
    assert!(!analysis.metadata.has_encryption); // TAR doesn't support encryption
    assert!(!analysis.metadata.has_password);
    assert!(analysis.metadata.comment.is_none());
    assert!(analysis.metadata.created_by.is_some());
    assert!(analysis.metadata.creation_date.is_none());
}

#[test]
fn test_compressed_tar_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let tar_gz_path = temp_dir.path().join("test.tar.gz");

    let mut data = create_gzip_header();
    data.extend_from_slice(&create_test_tar());
    std::fs::write(&tar_gz_path, &data).unwrap();

    let analysis = analyze_tar(&tar_gz_path).unwrap();

    assert!(matches!(analysis.archive_type, ArchiveType::TarGz));
    assert_eq!(analysis.metadata.compression_ratio, 0.7); // Estimated compression
    assert!(analysis.metadata.created_by.unwrap().contains("gzip"));
}

#[test]
fn test_risk_level_calculation() {
    let temp_dir = TempDir::new().unwrap();

    // High risk: suspicious name
    let high_risk_path = temp_dir.path().join("exploit_malware.tar");
    let tar_data = create_test_tar();
    std::fs::write(&high_risk_path, &tar_data).unwrap();

    let analysis = analyze_tar(&high_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::High | RiskLevel::Medium
    ));

    // Low risk: normal name
    let low_risk_path = temp_dir.path().join("documents.tar");
    std::fs::write(&low_risk_path, &tar_data).unwrap();

    let analysis = analyze_tar(&low_risk_path).unwrap();
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low
    ));
}

#[test]
fn test_tar_serialization() {
    let tar_data = create_test_tar();
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &tar_data).unwrap();

    let analysis = analyze_tar(temp_file.path()).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

    assert!(matches!(deserialized.archive_type, ArchiveType::Tar));
    assert_eq!(
        deserialized.metadata.created_by,
        analysis.metadata.created_by
    );
    assert_eq!(
        deserialized.metadata.total_entries,
        analysis.metadata.total_entries
    );
}

#[test]
fn test_multiple_tar_variants() {
    let temp_dir = TempDir::new().unwrap();

    // Test all TAR variants
    let variants = vec![
        ("test.tar", ArchiveType::Tar, create_test_tar()),
        ("test.tar.gz", ArchiveType::TarGz, {
            let mut data = create_gzip_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
        ("test.tar.bz2", ArchiveType::TarBz2, {
            let mut data = create_bzip2_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
        ("test.tar.xz", ArchiveType::TarXz, {
            let mut data = create_xz_header();
            data.extend_from_slice(&create_test_tar());
            data
        }),
    ];

    for (filename, _expected_type, data) in variants {
        let path = temp_dir.path().join(filename);
        std::fs::write(&path, &data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        match (filename, &analysis.archive_type) {
            ("test.tar", ArchiveType::Tar) => {}
            ("test.tar.gz", ArchiveType::TarGz) => {}
            ("test.tar.bz2", ArchiveType::TarBz2) => {}
            ("test.tar.xz", ArchiveType::TarXz) => {}
            _ => panic!(
                "Unexpected archive type for {}: {:?}",
                filename, analysis.archive_type
            ),
        }
    }
}

// Integration test with archive_analysis types
use file_scanner::archive_analysis::{ArchiveAnalysis, ArchiveType, RiskLevel};

#[test]
fn test_tar_analysis_integration() {
    let tar_data = create_test_tar();
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &tar_data).unwrap();

    let analysis = analyze_tar(temp_file.path()).unwrap();

    // Verify it returns proper ArchiveAnalysis structure
    assert!(matches!(analysis.archive_type, ArchiveType::Tar));
    assert!(analysis.entries.is_empty()); // Basic implementation doesn't parse entries
    assert!(analysis.nested_archives.is_empty());

    // Check security analysis structure
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low | RiskLevel::Medium | RiskLevel::High
    ));
    assert!(analysis.security_analysis.malicious_patterns.is_empty());
    assert!(analysis.security_analysis.suspicious_files.is_empty());
    assert!(analysis.security_analysis.path_traversal_risks.is_empty());
}

#[test]
fn test_edge_case_filenames() {
    let temp_dir = TempDir::new().unwrap();

    // Test case sensitivity and edge cases
    let edge_cases = vec![
        ("CRACK.TAR", true),              // Uppercase
        ("my_keygen_tool.tar", true),     // Embedded keyword
        ("backdoor123.tar.gz", true),     // With numbers
        ("exploit-kit.tar.bz2", true),    // With hyphens
        ("clean_archive.tar", false),     // Clean name
        ("project_backup.tar.xz", false), // Normal backup
    ];

    for (filename, should_be_suspicious) in edge_cases {
        let path = temp_dir.path().join(filename);
        let tar_data = create_test_tar();
        std::fs::write(&path, &tar_data).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        assert_eq!(
            analysis.suspicious_indicators.has_suspicious_names, should_be_suspicious,
            "Failed for filename: {filename}"
        );
    }
}
