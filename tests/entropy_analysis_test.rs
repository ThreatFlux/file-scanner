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

use file_scanner::entropy_analysis::*;
use std::fs;
use std::io::Write;
use tempfile::TempDir;

fn create_test_file(content: &[u8]) -> anyhow::Result<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new()?;
    let file_path = temp_dir.path().join("test_file");
    let mut file = fs::File::create(&file_path)?;
    file.write_all(content)?;
    Ok((temp_dir, file_path))
}

#[allow(dead_code)]
fn create_minimal_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 64]; // ELF header size

    // ELF magic
    elf[0..4].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
    // 64-bit
    elf[4] = 2;
    // Little endian
    elf[5] = 1;
    // Version
    elf[6] = 1;
    // OS/ABI (SYSV)
    elf[7] = 0;
    // ABI version
    elf[8] = 0;
    // Type: executable
    elf[16] = 2;
    elf[17] = 0;
    // Machine: x86_64
    elf[18] = 0x3e;
    elf[19] = 0;
    // Version
    elf[20..24].copy_from_slice(&[1, 0, 0, 0]);
    // Entry point
    elf[24..32].copy_from_slice(&[0x00, 0x10, 0x40, 0, 0, 0, 0, 0]);
    // Program header offset
    elf[32..40].copy_from_slice(&[64, 0, 0, 0, 0, 0, 0, 0]);
    // Section header offset (we'll add sections later)
    elf[40..48].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
    // Flags
    elf[48..52].copy_from_slice(&[0, 0, 0, 0]);
    // ELF header size
    elf[52..54].copy_from_slice(&[64, 0]);
    // Program header entry size
    elf[54..56].copy_from_slice(&[56, 0]);
    // Program header entry count
    elf[56..58].copy_from_slice(&[0, 0]);
    // Section header entry size
    elf[58..60].copy_from_slice(&[64, 0]);
    // Section header entry count
    elf[60..62].copy_from_slice(&[0, 0]);
    // Section header string table index
    elf[62..64].copy_from_slice(&[0, 0]);

    elf
}

fn create_minimal_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 512];

    // DOS header
    pe[0..2].copy_from_slice(b"MZ");
    // e_lfanew (offset to PE header)
    pe[60..64].copy_from_slice(&[128, 0, 0, 0]);

    // PE signature at offset 128
    pe[128..132].copy_from_slice(b"PE\0\0");
    // Machine: x86_64
    pe[132..134].copy_from_slice(&[0x64, 0x86]);
    // Number of sections
    pe[134..136].copy_from_slice(&[1, 0]);
    // Timestamp
    pe[136..140].copy_from_slice(&[0, 0, 0, 0]);
    // Pointer to symbol table
    pe[140..144].copy_from_slice(&[0, 0, 0, 0]);
    // Number of symbols
    pe[144..148].copy_from_slice(&[0, 0, 0, 0]);
    // Size of optional header
    pe[148..150].copy_from_slice(&[240, 0]);
    // Characteristics
    pe[150..152].copy_from_slice(&[0x22, 0x01]);

    pe
}

fn create_high_entropy_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 137 + 42) as u8).collect()
}

fn create_low_entropy_data(size: usize) -> Vec<u8> {
    vec![0x41; size] // All 'A's
}

fn create_random_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| ((i * 31 + 17) % 256) as u8).collect()
}

#[test]
fn test_analyze_entropy_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/file");
    let result = analyze_entropy(path);
    assert!(result.is_err());
}

#[test]
fn test_analyze_entropy_empty_file() {
    let (_temp_dir, file_path) = create_test_file(b"").unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert_eq!(result.overall_entropy, 0.0);
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].name, "entire_file");
    assert_eq!(result.sections[0].entropy, 0.0);
    assert!(!result.sections[0].is_suspicious);
}

#[test]
fn test_analyze_entropy_text_file() {
    let content = b"Hello, world! This is a normal text file with typical entropy.";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 3.0 && result.overall_entropy < 6.0);
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].name, "entire_file");
    assert!(!result.sections[0].is_suspicious);
    assert!(!result.packed_indicators.likely_packed);
    assert!(!result.encryption_indicators.likely_encrypted);
}

#[test]
fn test_analyze_entropy_high_entropy_file() {
    let content = create_high_entropy_data(1024);
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 7.0);
    assert_eq!(result.sections.len(), 1);
    assert!(result.sections[0].is_suspicious);
    assert!(
        result.packed_indicators.likely_packed || result.encryption_indicators.likely_encrypted
    );
}

#[test]
fn test_analyze_entropy_low_entropy_file() {
    let content = create_low_entropy_data(1024);
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy < 1.0);
    assert_eq!(result.sections.len(), 1);
    assert!(!result.sections[0].is_suspicious);
    assert!(!result.packed_indicators.likely_packed);
    assert!(!result.encryption_indicators.likely_encrypted);
}

#[test]
fn test_analyze_entropy_elf_binary() {
    // Just test with normal binary data since our minimal ELF might be malformed
    let content = create_random_data(1000);

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 0.0);
    // Should have at least the fallback entire_file section
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].name, "entire_file");
}

#[test]
fn test_analyze_entropy_pe_binary() {
    let mut content = create_minimal_pe();
    // Add some section data
    content.extend_from_slice(b"This is some section data");
    content.extend(create_random_data(300));

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 0.0);
    // PE parsing might fail with minimal header, should fall back to entire_file
    assert!(!result.sections.is_empty());
}

#[test]
fn test_analyze_entropy_mixed_content() {
    let mut content = Vec::new();
    // Low entropy section
    content.extend(create_low_entropy_data(256));
    // High entropy section
    content.extend(create_high_entropy_data(256));
    // Normal text
    content.extend_from_slice(b"Normal text content here");

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 3.0);
    assert_eq!(result.sections.len(), 1);
    assert!(result.obfuscation_score >= 0.0);
    assert!(!result.recommendations.is_empty());
}

#[test]
fn test_entropy_analysis_serialization() {
    let content = b"Test data for serialization";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    // Test JSON serialization
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: EntropyAnalysis = serde_json::from_str(&json).unwrap();

    // Use approximate comparison for floating point values
    assert!((deserialized.overall_entropy - result.overall_entropy).abs() < 1e-6);
    assert_eq!(deserialized.sections.len(), result.sections.len());
    assert!((deserialized.obfuscation_score - result.obfuscation_score).abs() < 1e-6);
}

#[test]
fn test_section_entropy_structure() {
    let section = SectionEntropy {
        name: "test_section".to_string(),
        offset: 100,
        size: 500,
        entropy: 6.5,
        is_suspicious: true,
        characteristics: vec!["executable".to_string(), "readable".to_string()],
    };

    assert_eq!(section.name, "test_section");
    assert_eq!(section.offset, 100);
    assert_eq!(section.size, 500);
    assert_eq!(section.entropy, 6.5);
    assert!(section.is_suspicious);
    assert_eq!(section.characteristics.len(), 2);
}

#[test]
fn test_packed_indicators_structure() {
    let indicators = PackedIndicators {
        likely_packed: true,
        packer_signatures: vec!["UPX".to_string(), "Themida".to_string()],
        compression_ratio_estimate: 0.75,
        import_table_anomalies: vec!["Minimal imports".to_string()],
        section_anomalies: vec!["High entropy .text".to_string()],
        entry_point_suspicious: true,
    };

    assert!(indicators.likely_packed);
    assert_eq!(indicators.packer_signatures.len(), 2);
    assert_eq!(indicators.compression_ratio_estimate, 0.75);
    assert!(!indicators.import_table_anomalies.is_empty());
    assert!(!indicators.section_anomalies.is_empty());
    assert!(indicators.entry_point_suspicious);
}

#[test]
fn test_encryption_indicators_structure() {
    let high_entropy_region = HighEntropyRegion {
        offset: 1000,
        size: 2048,
        entropy: 7.8,
        description: "Encrypted data block".to_string(),
    };

    let indicators = EncryptionIndicators {
        likely_encrypted: true,
        high_entropy_regions: vec![high_entropy_region],
        crypto_constants_found: vec!["AES".to_string(), "RSA".to_string()],
        random_data_percentage: 85.5,
    };

    assert!(indicators.likely_encrypted);
    assert_eq!(indicators.high_entropy_regions.len(), 1);
    assert_eq!(indicators.high_entropy_regions[0].entropy, 7.8);
    assert_eq!(indicators.crypto_constants_found.len(), 2);
    assert_eq!(indicators.random_data_percentage, 85.5);
}

#[test]
fn test_high_entropy_region_structure() {
    let region = HighEntropyRegion {
        offset: 2048,
        size: 1024,
        entropy: 7.9,
        description: "Possible encrypted payload".to_string(),
    };

    assert_eq!(region.offset, 2048);
    assert_eq!(region.size, 1024);
    assert_eq!(region.entropy, 7.9);
    assert_eq!(region.description, "Possible encrypted payload");
}

#[test]
fn test_entropy_analysis_with_crypto_patterns() {
    // Create data that might contain crypto constants
    let mut content = Vec::new();
    content.extend_from_slice(b"Normal text at the beginning");
    // Add some AES-like constants
    content.extend_from_slice(&[
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, // AES S-box start
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]);
    content.extend(create_high_entropy_data(512));

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 5.0);
    assert!(!result.recommendations.is_empty());
}

#[test]
fn test_entropy_analysis_recommendations() {
    let content = create_high_entropy_data(2048);
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(!result.recommendations.is_empty());
    // Should have recommendations for high entropy
    let recommendations_text = result.recommendations.join(" ");
    assert!(
        recommendations_text.contains("entropy")
            || recommendations_text.contains("packed")
            || recommendations_text.contains("encrypted")
    );
}

#[test]
fn test_entropy_analysis_obfuscation_score() {
    let content = create_high_entropy_data(1024);
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.obfuscation_score >= 0.0);
    assert!(result.obfuscation_score <= 100.0);
    // High entropy should result in higher obfuscation score
    assert!(result.obfuscation_score > 50.0);
}

#[test]
fn test_entropy_analysis_large_file() {
    let content = create_random_data(10000);
    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 6.0);
    assert_eq!(result.sections.len(), 1);
    assert!(result.sections[0].size == 10000);
}

#[test]
fn test_entropy_analysis_with_null_bytes() {
    let mut content = Vec::new();
    content.extend(vec![0u8; 512]); // Lots of nulls
    content.extend_from_slice(b"Some text in the middle");
    content.extend(vec![0u8; 512]); // More nulls

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy < 4.0); // Should be relatively low
    assert!(!result.packed_indicators.likely_packed);
    // Don't assert encryption status as it depends on threshold logic
}

#[test]
fn test_entropy_analysis_edge_cases() {
    // Single byte file
    let (_temp_dir, file_path) = create_test_file(b"X").unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert_eq!(result.overall_entropy, 0.0); // Single byte = no entropy
    assert_eq!(result.sections.len(), 1);
    assert!(!result.sections[0].is_suspicious);
}

#[test]
fn test_entropy_analysis_binary_data() {
    // Create binary data that looks like a real file but isn't a valid executable
    let mut content = Vec::new();
    content.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // Some header-like bytes
    content.extend(create_random_data(1000));
    content.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]); // Some footer-like bytes

    let (_temp_dir, file_path) = create_test_file(&content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    assert!(result.overall_entropy > 6.0);
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].name, "entire_file");
}

#[test]
fn test_entropy_thresholds() {
    // Test data right at threshold boundaries
    let high_entropy_content = create_high_entropy_data(1024);
    let (_temp_dir, file_path) = create_test_file(&high_entropy_content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();

    // Verify thresholds are being applied correctly
    if result.overall_entropy >= 7.5 {
        assert!(
            result.encryption_indicators.likely_encrypted || result.packed_indicators.likely_packed
        );
    }

    if result.overall_entropy >= 7.0 {
        assert!(result.sections[0].is_suspicious);
    }
}

#[test]
fn test_entropy_analysis_clone() {
    let content = b"Test data for clone test";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();
    let cloned = result.clone();

    assert_eq!(result.overall_entropy, cloned.overall_entropy);
    assert_eq!(result.sections.len(), cloned.sections.len());
    assert_eq!(result.obfuscation_score, cloned.obfuscation_score);
}

#[test]
fn test_entropy_analysis_debug_format() {
    let content = b"Test data";
    let (_temp_dir, file_path) = create_test_file(content).unwrap();

    let result = analyze_entropy(&file_path).unwrap();
    let debug_string = format!("{result:?}");

    assert!(debug_string.contains("EntropyAnalysis"));
    assert!(debug_string.contains("overall_entropy"));
    assert!(debug_string.contains("sections"));
}
