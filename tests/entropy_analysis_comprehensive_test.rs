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
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_entropy_analysis_struct_serialization() {
    // Test all EntropyAnalysis fields with comprehensive data
    let analysis = EntropyAnalysis {
        overall_entropy: 7.85,
        sections: vec![
            SectionEntropy {
                name: ".text".to_string(),
                offset: 0x1000,
                size: 2048,
                entropy: 6.45,
                is_suspicious: false,
                characteristics: vec!["executable".to_string()],
            },
            SectionEntropy {
                name: ".data".to_string(),
                offset: 0x2000,
                size: 1024,
                entropy: 3.22,
                is_suspicious: false,
                characteristics: vec!["writable".to_string()],
            },
            SectionEntropy {
                name: "packed_section".to_string(),
                offset: 0x3000,
                size: 4096,
                entropy: 7.95,
                is_suspicious: true,
                characteristics: vec!["executable".to_string(), "writable".to_string()],
            },
        ],
        packed_indicators: PackedIndicators {
            likely_packed: true,
            packer_signatures: vec!["UPX".to_string(), "MPRESS".to_string()],
            compression_ratio_estimate: 0.85,
            import_table_anomalies: vec!["Unusually small import table".to_string()],
            section_anomalies: vec![
                "Section packed_section is both writable and executable".to_string()
            ],
            entry_point_suspicious: true,
        },
        encryption_indicators: EncryptionIndicators {
            likely_encrypted: true,
            high_entropy_regions: vec![HighEntropyRegion {
                offset: 0x3000,
                size: 4096,
                entropy: 7.95,
                description: "Section packed_section has encryption-level entropy".to_string(),
            }],
            crypto_constants_found: vec!["AES S-box".to_string(), "SHA-256 constant".to_string()],
            random_data_percentage: 0.92,
        },
        obfuscation_score: 87.5,
        recommendations: vec![
            "Binary appears to be packed. Consider unpacking before analysis.".to_string(),
            "Detected packer: UPX, MPRESS. Use appropriate unpacking tool.".to_string(),
            "Binary contains encrypted/obfuscated regions.".to_string(),
            "Very high percentage of non-printable data suggests strong encryption.".to_string(),
            "Section 'packed_section' has suspicious entropy (7.95). Investigate further."
                .to_string(),
            "Entry point is in an unusual section. May indicate runtime unpacking.".to_string(),
        ],
    };

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: EntropyAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(analysis.overall_entropy, deserialized.overall_entropy);
    assert_eq!(analysis.sections.len(), deserialized.sections.len());
    assert_eq!(
        analysis.packed_indicators.likely_packed,
        deserialized.packed_indicators.likely_packed
    );
    assert_eq!(
        analysis.encryption_indicators.likely_encrypted,
        deserialized.encryption_indicators.likely_encrypted
    );
    assert_eq!(analysis.obfuscation_score, deserialized.obfuscation_score);
    assert_eq!(
        analysis.recommendations.len(),
        deserialized.recommendations.len()
    );

    // Test YAML serialization
    let yaml = serde_yaml::to_string(&analysis).unwrap();
    let deserialized_yaml: EntropyAnalysis = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(analysis.overall_entropy, deserialized_yaml.overall_entropy);
    assert_eq!(analysis.sections.len(), deserialized_yaml.sections.len());
}

#[test]
fn test_section_entropy_comprehensive() {
    let section = SectionEntropy {
        name: "comprehensive_test_section".to_string(),
        offset: 0xDEADBEEF,
        size: 0x12345678,
        entropy: 5.67,
        is_suspicious: true,
        characteristics: vec![
            "executable".to_string(),
            "writable".to_string(),
            "test_characteristic".to_string(),
        ],
    };

    let json = serde_json::to_string(&section).unwrap();
    let deserialized: SectionEntropy = serde_json::from_str(&json).unwrap();

    assert_eq!(section.name, deserialized.name);
    assert_eq!(section.offset, deserialized.offset);
    assert_eq!(section.size, deserialized.size);
    assert_eq!(section.entropy, deserialized.entropy);
    assert_eq!(section.is_suspicious, deserialized.is_suspicious);
    assert_eq!(section.characteristics, deserialized.characteristics);
}

#[test]
fn test_packed_indicators_comprehensive() {
    let indicators = PackedIndicators {
        likely_packed: true,
        packer_signatures: vec![
            "UPX".to_string(),
            "MPRESS".to_string(),
            "Petite".to_string(),
            "PECompact".to_string(),
            "ASPack".to_string(),
            "FSG".to_string(),
            "PECrypt".to_string(),
        ],
        compression_ratio_estimate: 0.73,
        import_table_anomalies: vec![
            "Unusually small import table".to_string(),
            "Missing common imports".to_string(),
            "Suspicious import patterns".to_string(),
        ],
        section_anomalies: vec![
            "Suspicious section name: ''".to_string(),
            "Section test_section is both writable and executable".to_string(),
            "Section packed has high entropy (7.90) for executable code".to_string(),
        ],
        entry_point_suspicious: true,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: PackedIndicators = serde_json::from_str(&json).unwrap();

    assert_eq!(indicators.likely_packed, deserialized.likely_packed);
    assert_eq!(indicators.packer_signatures, deserialized.packer_signatures);
    assert_eq!(
        indicators.compression_ratio_estimate,
        deserialized.compression_ratio_estimate
    );
    assert_eq!(
        indicators.import_table_anomalies,
        deserialized.import_table_anomalies
    );
    assert_eq!(indicators.section_anomalies, deserialized.section_anomalies);
    assert_eq!(
        indicators.entry_point_suspicious,
        deserialized.entry_point_suspicious
    );
}

#[test]
fn test_encryption_indicators_comprehensive() {
    let indicators = EncryptionIndicators {
        likely_encrypted: true,
        high_entropy_regions: vec![
            HighEntropyRegion {
                offset: 0x1000,
                size: 4096,
                entropy: 7.85,
                description: "High entropy region 1".to_string(),
            },
            HighEntropyRegion {
                offset: 0x5000,
                size: 8192,
                entropy: 7.92,
                description: "High entropy region 2".to_string(),
            },
        ],
        crypto_constants_found: vec![
            "AES S-box".to_string(),
            "SHA-256 constant".to_string(),
            "Possible RC4 init".to_string(),
            "MD5 constant".to_string(),
        ],
        random_data_percentage: 0.88,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: EncryptionIndicators = serde_json::from_str(&json).unwrap();

    assert_eq!(indicators.likely_encrypted, deserialized.likely_encrypted);
    assert_eq!(
        indicators.high_entropy_regions.len(),
        deserialized.high_entropy_regions.len()
    );
    assert_eq!(
        indicators.crypto_constants_found,
        deserialized.crypto_constants_found
    );
    assert_eq!(
        indicators.random_data_percentage,
        deserialized.random_data_percentage
    );
}

#[test]
fn test_high_entropy_region_serialization() {
    let region = HighEntropyRegion {
        offset: 0xCAFEBABE,
        size: 0x1337,
        entropy: 7.999,
        description: "Ultra high entropy test region with comprehensive data".to_string(),
    };

    let json = serde_json::to_string(&region).unwrap();
    let deserialized: HighEntropyRegion = serde_json::from_str(&json).unwrap();

    assert_eq!(region.offset, deserialized.offset);
    assert_eq!(region.size, deserialized.size);
    assert_eq!(region.entropy, deserialized.entropy);
    assert_eq!(region.description, deserialized.description);
}

#[test]
fn test_analyze_entropy_with_text_file() {
    // Test with a regular text file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .write_all(b"This is a normal text file with regular entropy patterns.")
        .unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(result.overall_entropy > 0.0);
    assert!(result.overall_entropy < 7.0); // Text should have moderate entropy
    assert_eq!(result.sections.len(), 1); // Should fall back to single section
    assert_eq!(result.sections[0].name, "entire_file");
    assert!(!result.packed_indicators.likely_packed);
    assert!(!result.encryption_indicators.likely_encrypted);
    assert!(result.obfuscation_score < 50.0);
    assert!(!result.recommendations.is_empty());
}

#[test]
fn test_analyze_entropy_with_high_entropy_data() {
    // Test with high-entropy (random-like) data
    let mut temp_file = NamedTempFile::new().unwrap();
    let high_entropy_data: Vec<u8> = (0..=255).cycle().take(2048).collect();
    temp_file.write_all(&high_entropy_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(result.overall_entropy > 7.8); // Should be very high entropy
    assert_eq!(result.sections.len(), 1);
    assert!(result.sections[0].is_suspicious); // High entropy should be suspicious
    assert!(result.obfuscation_score > 30.0); // Should have elevated obfuscation score
}

#[test]
fn test_analyze_entropy_with_low_entropy_data() {
    // Test with low-entropy (repetitive) data
    let mut temp_file = NamedTempFile::new().unwrap();
    let low_entropy_data = vec![0x41; 1000]; // All 'A' characters
    temp_file.write_all(&low_entropy_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(result.overall_entropy < 1.0); // Should be very low entropy
    assert_eq!(result.sections.len(), 1);
    assert!(!result.sections[0].is_suspicious); // Low entropy shouldn't be suspicious
    assert!(!result.packed_indicators.likely_packed);
    assert!(!result.encryption_indicators.likely_encrypted);
    assert!(result.obfuscation_score < 20.0);
}

#[test]
fn test_analyze_entropy_with_mixed_data() {
    // Test with mixed entropy data (text + high entropy)
    let mut temp_file = NamedTempFile::new().unwrap();
    let mut mixed_data = b"Normal text content at the beginning.".to_vec();
    let high_entropy_suffix: Vec<u8> = (0..=255).cycle().take(1024).collect();
    mixed_data.extend_from_slice(&high_entropy_suffix);
    temp_file.write_all(&mixed_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    // Should have moderate overall entropy due to mixing
    assert!(result.overall_entropy > 3.0);
    assert!(result.overall_entropy < 8.0);
    assert_eq!(result.sections.len(), 1);
}

#[test]
fn test_analyze_entropy_with_crypto_constants() {
    // Test with data containing crypto constants
    let mut temp_file = NamedTempFile::new().unwrap();
    let mut crypto_data = Vec::new();

    // Add AES S-box beginning
    crypto_data.extend_from_slice(&[0x63, 0x7c, 0x77, 0x7b, 0xf2]);
    // Add SHA-256 constant
    crypto_data.extend_from_slice(&[0x67, 0xe6, 0x09, 0x6a]);
    // Add MD5 constant
    crypto_data.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    // Add RC4 init pattern
    crypto_data.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    // Pad with more data
    crypto_data.extend_from_slice(&vec![0x55; 1000]);

    temp_file.write_all(&crypto_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    // Should detect crypto constants
    assert!(!result
        .encryption_indicators
        .crypto_constants_found
        .is_empty());
    assert!(result.encryption_indicators.likely_encrypted);
    assert!(result.obfuscation_score > 20.0);
}

#[test]
fn test_analyze_entropy_with_packer_signatures() {
    // Test with data containing packer signatures
    let packer_signatures = vec![
        (b"UPX0".to_vec(), "UPX"),
        (b"UPX1".to_vec(), "UPX"),
        (b"UPX!".to_vec(), "UPX"),
        (b"MPRESS1".to_vec(), "MPRESS"),
        (b"MPRESS2".to_vec(), "MPRESS"),
        (b".petite".to_vec(), "Petite"),
        (b"PECompact".to_vec(), "PECompact"),
        (b"ASPack".to_vec(), "ASPack"),
        (b"FSG!".to_vec(), "FSG"),
        (b"PEC2".to_vec(), "PECrypt"),
    ];

    for (signature, expected_name) in packer_signatures {
        let mut temp_file = NamedTempFile::new().unwrap();
        let mut data = vec![0x00; 100];
        data.extend_from_slice(&signature);
        data.extend_from_slice(&vec![0x55; 500]);
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_entropy(temp_file.path()).unwrap();

        // Should detect the packer signature
        assert!(
            result
                .packed_indicators
                .packer_signatures
                .contains(&expected_name.to_string()),
            "Failed to detect packer signature: {expected_name}"
        );
        assert!(result.packed_indicators.likely_packed);
    }
}

#[test]
fn test_analyze_entropy_with_binary_like_data() {
    // Test with binary-like data that might trigger binary parsing
    let mut temp_file = NamedTempFile::new().unwrap();
    let mut binary_data = vec![];

    // Add some binary-like patterns
    binary_data.extend_from_slice(&[0x7f, 0x45, 0x4c, 0x46]); // ELF magic-like
    binary_data.extend_from_slice(&[0x4d, 0x5a]); // PE magic-like
    binary_data.extend_from_slice(&[0x00; 100]); // Padding
    binary_data.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]); // Mach-O magic-like
    binary_data.extend_from_slice(&[0x55; 200]); // More data

    temp_file.write_all(&binary_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    // Should always succeed, even if it falls back to entire_file analysis
    assert!(result.overall_entropy >= 0.0);
    assert!(!result.sections.is_empty());
    assert_eq!(result.sections[0].size, binary_data.len() as u64);
}

#[test]
fn test_analyze_entropy_with_structured_data() {
    // Test with structured data that has different entropy characteristics
    let mut temp_file = NamedTempFile::new().unwrap();
    let mut structured_data = vec![];

    // Header-like section (low entropy)
    structured_data.extend_from_slice(&[0x00; 64]);

    // Data section (medium entropy)
    for i in 0..256 {
        structured_data.push((i % 64) as u8);
    }

    // Code-like section (medium-high entropy)
    for i in 0..512 {
        structured_data.push(((i * 17) % 256) as u8);
    }

    // Footer (low entropy)
    structured_data.extend_from_slice(&[0xFF; 32]);

    temp_file.write_all(&structured_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(result.overall_entropy >= 0.0);
    assert!(!result.sections.is_empty());
    assert_eq!(result.sections[0].size, structured_data.len() as u64);

    // Should have moderate to high entropy due to mixed content with some patterns
    assert!(result.overall_entropy > 2.0);
    assert!(result.overall_entropy < 8.0);
}

#[test]
fn test_analyze_entropy_error_cases() {
    // Test with nonexistent file
    let result = analyze_entropy(Path::new("/absolutely/nonexistent/file/path"));
    assert!(result.is_err());

    // Test with empty file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();
    assert_eq!(result.overall_entropy, 0.0);
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].name, "entire_file");
    assert_eq!(result.sections[0].size, 0);
}

#[test]
fn test_entropy_analysis_edge_cases() {
    // Test with single byte file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&[0x42]).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();
    assert_eq!(result.overall_entropy, 0.0); // Single repeated byte = 0 entropy
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].size, 1);

    // Test with two different bytes
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&[0x00, 0xFF]).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();
    assert_eq!(result.overall_entropy, 1.0); // Two equally probable bytes = 1 bit entropy
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].size, 2);
}

#[test]
fn test_entropy_thresholds_and_scoring() {
    // Test different entropy levels against thresholds
    let test_cases = vec![
        (vec![0x00; 1000], false), // Low entropy - not suspicious
        (vec![0x42; 1000], false), // Low entropy - not suspicious
        ((0..=255).cycle().take(1000).collect::<Vec<u8>>(), true), // High entropy - suspicious
    ];

    for (data, should_be_suspicious) in test_cases {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_entropy(temp_file.path()).unwrap();

        if should_be_suspicious {
            assert!(result.sections[0].is_suspicious);
        } else {
            assert!(!result.sections[0].is_suspicious);
        }

        // Note: packed/encrypted detection depends on more than just entropy
        // but this tests the threshold logic
    }
}

#[test]
fn test_recommendation_generation() {
    // Test that recommendations are generated appropriately
    let mut temp_file = NamedTempFile::new().unwrap();

    // Create data that should trigger multiple recommendations
    let mut complex_data = Vec::new();

    // Add packer signature
    complex_data.extend_from_slice(b"UPX0");
    // Add crypto constants
    complex_data.extend_from_slice(&[0x63, 0x7c, 0x77, 0x7b, 0xf2]); // AES S-box
                                                                     // Add high entropy data
    complex_data.extend_from_slice(&(0..=255).cycle().take(1000).collect::<Vec<u8>>());

    temp_file.write_all(&complex_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(!result.recommendations.is_empty());

    // Should have multiple recommendations due to packing and encryption indicators
    let recommendations_text = result.recommendations.join(" ");
    if result.packed_indicators.likely_packed {
        assert!(recommendations_text.contains("packed") || recommendations_text.contains("packer"));
    }
    if result.encryption_indicators.likely_encrypted {
        assert!(
            recommendations_text.contains("encrypted")
                || recommendations_text.contains("obfuscated")
        );
    }
}

#[test]
fn test_serialization_formats_comprehensive() {
    // Create a comprehensive entropy analysis result
    let analysis = EntropyAnalysis {
        overall_entropy: 6.75,
        sections: vec![SectionEntropy {
            name: "test_section".to_string(),
            offset: 0x1000,
            size: 2048,
            entropy: 5.5,
            is_suspicious: false,
            characteristics: vec!["executable".to_string()],
        }],
        packed_indicators: PackedIndicators {
            likely_packed: false,
            packer_signatures: vec![],
            compression_ratio_estimate: 0.2,
            import_table_anomalies: vec![],
            section_anomalies: vec![],
            entry_point_suspicious: false,
        },
        encryption_indicators: EncryptionIndicators {
            likely_encrypted: false,
            high_entropy_regions: vec![],
            crypto_constants_found: vec![],
            random_data_percentage: 0.3,
        },
        obfuscation_score: 25.0,
        recommendations: vec![
            "No significant obfuscation detected. Standard analysis should be effective."
                .to_string(),
        ],
    };

    // Test JSON pretty printing
    let json_pretty = serde_json::to_string_pretty(&analysis).unwrap();
    assert!(json_pretty.contains("overall_entropy"));
    assert!(json_pretty.contains("6.75"));

    // Test JSON compact
    let json_compact = serde_json::to_string(&analysis).unwrap();
    assert!(json_compact.len() < json_pretty.len());

    // Test YAML
    let yaml = serde_yaml::to_string(&analysis).unwrap();
    assert!(yaml.contains("overall_entropy"));
    assert!(yaml.contains("test_section"));

    // Test round-trip consistency
    let json_roundtrip: EntropyAnalysis = serde_json::from_str(&json_compact).unwrap();
    let yaml_roundtrip: EntropyAnalysis = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(analysis.overall_entropy, json_roundtrip.overall_entropy);
    assert_eq!(analysis.overall_entropy, yaml_roundtrip.overall_entropy);
    assert_eq!(analysis.sections.len(), json_roundtrip.sections.len());
    assert_eq!(analysis.sections.len(), yaml_roundtrip.sections.len());
}

#[test]
fn test_large_file_handling() {
    // Test with a larger file to ensure performance characteristics
    let mut temp_file = NamedTempFile::new().unwrap();

    // Create 10KB of mixed data
    let mut large_data = Vec::new();
    for i in 0..10240 {
        large_data.push((i % 256) as u8);
    }

    temp_file.write_all(&large_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_entropy(temp_file.path()).unwrap();

    assert!(result.overall_entropy > 7.5); // Should be high due to pattern
    assert_eq!(result.sections.len(), 1);
    assert_eq!(result.sections[0].size, 10240);
    assert!(result.sections[0].is_suspicious); // High entropy should be flagged
}
