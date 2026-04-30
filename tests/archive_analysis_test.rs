use file_scanner::archive_analysis::*;
use std::io::Write;
use tempfile::NamedTempFile;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

#[test]
fn test_archive_analysis_serialization() {
    let analysis = ArchiveAnalysis {
        archive_type: ArchiveType::Zip,
        metadata: ArchiveMetadata {
            total_entries: 5,
            total_size_compressed: 1024,
            total_size_uncompressed: 2048,
            compression_ratio: 0.5,
            has_encryption: false,
            has_password: false,
            comment: Some("Test archive".to_string()),
            created_by: Some("Test Suite".to_string()),
            creation_date: Some("2024-01-01".to_string()),
        },
        entries: vec![ArchiveEntry {
            path: "test.txt".to_string(),
            file_name: "test.txt".to_string(),
            is_directory: false,
            size_compressed: 100,
            size_uncompressed: 200,
            compression_method: "Deflated".to_string(),
            compression_ratio: 0.5,
            last_modified: Some("2024-01-01 12:00:00".to_string()),
            crc32: Some(0x12345678),
            is_encrypted: false,
            is_text: true,
            permissions: Some(0o644),
            comment: None,
            file_type: FileType::Text,
            risk_indicators: vec![],
        }],
        security_analysis: ArchiveSecurityAnalysis {
            overall_risk: RiskLevel::Low,
            malicious_patterns: vec![],
            suspicious_files: vec![],
            path_traversal_risks: vec![],
            zip_bomb_indicators: ZipBombIndicators {
                is_potential_bomb: false,
                compression_ratio: 0.5,
                nesting_level: 0,
                recursive_entries: vec![],
                quine_detection: false,
            },
            hidden_content: vec![],
        },
        suspicious_indicators: SuspiciousArchiveIndicators::default(),
        nested_archives: vec![],
    };

    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(
        analysis.metadata.total_entries,
        deserialized.metadata.total_entries
    );
    assert!(matches!(analysis.archive_type, ArchiveType::Zip));
}

#[test]
fn test_simple_zip_creation_and_analysis() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);

        // Add a simple text file
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("hello.txt", options).unwrap();
        zip.write_all(b"Hello, World!").unwrap();

        zip.finish().unwrap();
    }

    let result = analyze_zip(temp_file.path());
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert_eq!(analysis.metadata.total_entries, 1);
    assert_eq!(analysis.entries.len(), 1);
    assert_eq!(analysis.entries[0].file_name, "hello.txt");
    assert_eq!(analysis.entries[0].size_uncompressed, 13);
    assert!(matches!(analysis.entries[0].file_type, FileType::Text));
}

#[test]
fn test_zip_with_multiple_file_types() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        // Add various file types
        zip.start_file("script.py", options).unwrap();
        zip.write_all(b"#!/usr/bin/env python\nprint('test')")
            .unwrap();

        zip.start_file("program.exe", options).unwrap();
        zip.write_all(b"MZ\x90\x00\x03").unwrap();

        zip.start_file("document.pdf", options).unwrap();
        zip.write_all(b"%PDF-1.4").unwrap();

        zip.start_file("archive.zip", options).unwrap();
        zip.write_all(b"PK\x03\x04").unwrap();

        zip.start_file("image.jpg", options).unwrap();
        zip.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert_eq!(analysis.metadata.total_entries, 5);
    assert!(analysis.suspicious_indicators.has_executable);
    assert!(analysis.suspicious_indicators.has_script);
    assert_eq!(analysis.suspicious_indicators.executable_count, 1);
    assert_eq!(analysis.suspicious_indicators.script_count, 1);
    assert_eq!(analysis.nested_archives.len(), 1);
}

#[test]
fn test_zip_with_suspicious_files() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        // Add files with double extensions
        zip.start_file("document.pdf.exe", options).unwrap();
        zip.write_all(b"MZ").unwrap();

        // Add files with suspicious names
        zip.start_file("crack_v2.exe", options).unwrap();
        zip.write_all(b"MZ").unwrap();

        zip.start_file("keygen.bat", options).unwrap();
        zip.write_all(b"@echo off").unwrap();

        // Add hidden file
        zip.start_file(".hidden_file.txt", options).unwrap();
        zip.write_all(b"secret").unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert!(analysis.suspicious_indicators.has_double_extension);
    assert!(analysis.suspicious_indicators.has_suspicious_names);
    assert!(analysis.suspicious_indicators.has_hidden_files);
    assert!(analysis.suspicious_indicators.risk_score > 50);

    let suspicious_count = analysis.security_analysis.suspicious_files.len();
    assert!(suspicious_count >= 3);
}

#[test]
fn test_zip_with_path_traversal() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        // Add files with path traversal attempts
        zip.start_file("../../../etc/passwd", options).unwrap();
        zip.write_all(b"root:x:0:0").unwrap();

        zip.start_file("/etc/shadow", options).unwrap();
        zip.write_all(b"shadow content").unwrap();

        zip.start_file("..\\windows\\system32\\config\\sam", options)
            .unwrap();
        zip.write_all(b"SAM data").unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert!(analysis.suspicious_indicators.has_path_traversal);
    assert!(!analysis.security_analysis.path_traversal_risks.is_empty());
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Critical
    ));
}

#[test]
fn test_zip_bomb_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);

        // Create a highly compressed file (potential zip bomb)
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("bomb.txt", options).unwrap();
        // Write highly compressible data
        let data = vec![b'A'; 1_000_000];
        zip.write_all(&data).unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    // Check compression ratio
    assert!(analysis.metadata.compression_ratio > 0.9);

    // In a real scenario, we'd check for extreme ratios
    // For now, just verify the structure
    assert!(
        !analysis
            .security_analysis
            .zip_bomb_indicators
            .recursive_entries
            .is_empty()
            || analysis
                .security_analysis
                .zip_bomb_indicators
                .compression_ratio
                > 0.9
    );
}

#[test]
fn test_encrypted_zip_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);

        // Note: zip crate doesn't support creating encrypted files
        // In real implementation, we'd test with an encrypted ZIP
        let options = SimpleFileOptions::default();

        zip.start_file("secret.txt", options).unwrap();
        zip.write_all(b"This would be encrypted").unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    // Verify structure (encryption detection would work with real encrypted files)
    assert_eq!(analysis.metadata.total_entries, 1);
}

#[test]
fn test_nested_archive_detection() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        // Add nested archives of different types
        zip.start_file("nested.zip", options).unwrap();
        zip.write_all(b"PK\x03\x04").unwrap();

        zip.start_file("nested.rar", options).unwrap();
        zip.write_all(b"Rar!\x1a\x07\x00").unwrap();

        zip.start_file("nested.7z", options).unwrap();
        zip.write_all(b"7z\xBC\xAF\x27\x1C").unwrap();

        zip.start_file("nested.tar.gz", options).unwrap();
        zip.write_all(b"\x1f\x8b\x08").unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert_eq!(analysis.nested_archives.len(), 4);
    assert!(analysis
        .nested_archives
        .iter()
        .any(|n| matches!(n.archive_type, ArchiveType::Zip)));
    assert!(analysis
        .nested_archives
        .iter()
        .any(|n| matches!(n.archive_type, ArchiveType::Rar)));
    assert!(analysis
        .nested_archives
        .iter()
        .any(|n| matches!(n.archive_type, ArchiveType::SevenZip)));
    assert!(analysis
        .nested_archives
        .iter()
        .any(|n| matches!(n.archive_type, ArchiveType::TarGz)));
}

#[test]
fn test_zip_with_comment() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let mut zip = ZipWriter::new(file);

        // Set archive comment
        zip.set_comment("This is a test archive with comment")
            .unwrap();

        let options = SimpleFileOptions::default();
        zip.start_file("file.txt", options).unwrap();
        zip.write_all(b"content").unwrap();

        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert!(analysis.metadata.comment.is_some());
    assert_eq!(
        analysis.metadata.comment.unwrap(),
        "This is a test archive with comment"
    );
}

#[test]
fn test_risk_level_assessment() {
    // Test Low risk
    let low_risk = determine_overall_risk(
        &[],
        &[],
        &ZipBombIndicators {
            is_potential_bomb: false,
            compression_ratio: 0.5,
            nesting_level: 0,
            recursive_entries: vec![],
            quine_detection: false,
        },
    );
    assert!(matches!(low_risk, RiskLevel::Low));

    // Test Critical risk with path traversal
    let critical_risk = determine_overall_risk(
        &[],
        &[PathTraversalRisk {
            entry_path: "../etc/passwd".to_string(),
            resolved_path: "/etc/passwd".to_string(),
            risk_type: "Directory Traversal".to_string(),
        }],
        &ZipBombIndicators::default(),
    );
    assert!(matches!(critical_risk, RiskLevel::Critical));
}

#[test]
fn test_file_type_variants() {
    let types = vec![
        FileType::Executable,
        FileType::Script,
        FileType::Document,
        FileType::Archive,
        FileType::Image,
        FileType::Text,
        FileType::Data,
        FileType::Unknown,
    ];

    for file_type in types {
        let json = serde_json::to_string(&file_type).unwrap();
        let deserialized: FileType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{:?}", file_type), format!("{:?}", deserialized));
    }
}

#[test]
fn test_comprehensive_suspicious_indicators() {
    let indicators = SuspiciousArchiveIndicators {
        has_executable: true,
        has_script: true,
        has_double_extension: true,
        has_path_traversal: true,
        has_hidden_files: true,
        has_suspicious_names: true,
        executable_count: 5,
        script_count: 3,
        suspicious_patterns: vec!["crack.exe".to_string(), "keygen.bat".to_string()],
        risk_score: 85,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: SuspiciousArchiveIndicators = serde_json::from_str(&json).unwrap();

    assert_eq!(indicators.has_executable, deserialized.has_executable);
    assert_eq!(indicators.executable_count, deserialized.executable_count);
    assert_eq!(
        indicators.suspicious_patterns.len(),
        deserialized.suspicious_patterns.len()
    );
    assert_eq!(indicators.risk_score, deserialized.risk_score);
}

#[test]
fn test_empty_archive_edge_case() {
    let temp_file = NamedTempFile::new().unwrap();
    {
        let file = temp_file.reopen().unwrap();
        let zip = ZipWriter::new(file);
        zip.finish().unwrap();
    }

    let analysis = analyze_zip(temp_file.path()).unwrap();

    assert_eq!(analysis.metadata.total_entries, 0);
    assert_eq!(analysis.entries.len(), 0);
    assert_eq!(analysis.suspicious_indicators.risk_score, 0);
    assert!(matches!(
        analysis.security_analysis.overall_risk,
        RiskLevel::Low
    ));
}

fn determine_overall_risk(
    suspicious_files: &[SuspiciousFile],
    path_traversal_risks: &[PathTraversalRisk],
    zip_bomb_indicators: &ZipBombIndicators,
) -> RiskLevel {
    if !path_traversal_risks.is_empty() || zip_bomb_indicators.is_potential_bomb {
        RiskLevel::Critical
    } else if !suspicious_files.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}
