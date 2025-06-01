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
fn test_extract_rule_name() {
    let test_cases = vec![
        (
            "rule test_rule : suspicious {",
            Some("test_rule".to_string()),
        ),
        (
            "rule malware_family : trojan malware {",
            Some("malware_family".to_string()),
        ),
        ("rule simple_rule {", Some("simple_rule".to_string())),
        ("invalid rule format", None),
        (
            "rule  spaced_name  : tag {",
            Some("spaced_name".to_string()),
        ),
    ];

    for (input, expected) in test_cases {
        let result = extract_rule_name(input);
        assert_eq!(result, expected);
    }
}

#[test]
fn test_extract_tags_from_rule() {
    let test_cases = vec![
        (
            "rule test : tag1 tag2 {",
            vec!["tag1".to_string(), "tag2".to_string()],
        ),
        ("rule test : single_tag {", vec!["single_tag".to_string()]),
        ("rule test {", vec![]),
        ("rule test : {", vec![]),
        (
            "rule test : tag1  tag2   tag3 {",
            vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
        ),
    ];

    for (input, expected) in test_cases {
        let result = extract_tags_from_rule(input);
        assert_eq!(result, expected);
    }
}

#[test]
fn test_extract_metadata_from_rule() {
    let rule_text = r#"
rule test_rule : suspicious {
    meta:
        description = "Test rule for analysis"
        author = "Security Team"
        severity = "high"
    strings:
        $test = "test"
    condition:
        $test
}"#;

    let metadata = extract_metadata_from_rule(rule_text);
    assert_eq!(metadata.len(), 3);
    assert_eq!(
        metadata.get("description").unwrap(),
        "Test rule for analysis"
    );
    assert_eq!(metadata.get("author").unwrap(), "Security Team");
    assert_eq!(metadata.get("severity").unwrap(), "high");
}

#[test]
fn test_contains_string() {
    let data = b"This is test data with VirtualAlloc function call";

    assert!(contains_string(data, "VirtualAlloc"));
    assert!(contains_string(data, "test"));
    assert!(contains_string(data, "This"));
    assert!(!contains_string(data, "NotPresent"));
    assert!(!contains_string(data, "virtualalloc")); // Case sensitive
}

#[test]
fn test_should_include_match_suspicious_apis() {
    let rule_match = YaraMatch {
        rule_identifier: "suspicious_api_calls".to_string(),
        tags: vec![],
        metadata: HashMap::new(),
    };

    // Test with sufficient API calls
    let data_with_apis = b"VirtualAlloc\0WriteProcessMemory\0CreateRemoteThread\0";
    assert!(should_include_match(&rule_match, data_with_apis));

    // Test with insufficient API calls
    let data_insufficient = b"VirtualAlloc\0WriteProcessMemory\0";
    assert!(!should_include_match(&rule_match, data_insufficient));
}

#[test]
fn test_should_include_match_crypto() {
    let rule_match = YaraMatch {
        rule_identifier: "crypto_operations".to_string(),
        tags: vec![],
        metadata: HashMap::new(),
    };

    // Test with AES
    let data_with_aes = b"AES encryption";
    assert!(should_include_match(&rule_match, data_with_aes));

    // Test with RSA
    let data_with_rsa = b"RSA key pair";
    assert!(should_include_match(&rule_match, data_with_rsa));

    // Test with base64
    let data_with_b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    assert!(should_include_match(&rule_match, data_with_b64));

    // Test without crypto
    let data_without_crypto = b"No cryptographic content here";
    assert!(!should_include_match(&rule_match, data_without_crypto));
}

#[test]
fn test_should_include_match_network() {
    let rule_match = YaraMatch {
        rule_identifier: "network_communication".to_string(),
        tags: vec![],
        metadata: HashMap::new(),
    };

    // Test with HTTP
    let data_with_http = b"http://example.com";
    assert!(should_include_match(&rule_match, data_with_http));

    // Test with HTTPS
    let data_with_https = b"https://secure.com";
    assert!(should_include_match(&rule_match, data_with_https));

    // Test with socket
    let data_with_socket = b"socket connection";
    assert!(should_include_match(&rule_match, data_with_socket));

    // Test without network indicators
    let data_without_network = b"No network content";
    assert!(!should_include_match(&rule_match, data_without_network));
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
