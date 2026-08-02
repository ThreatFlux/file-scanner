//! Tests for threat detection types and data structures

use std::collections::HashMap;
use std::time::Duration;
use threatflux_threat_detection::types::*;

#[test]
fn test_threat_level_ordering() {
    assert!(ThreatLevel::Clean < ThreatLevel::Suspicious);
    assert!(ThreatLevel::Suspicious < ThreatLevel::Malicious);
    assert!(ThreatLevel::Malicious < ThreatLevel::Critical);
}

#[test]
fn test_threat_level_display() {
    assert_eq!(ThreatLevel::Clean.to_string(), "Clean");
    assert_eq!(ThreatLevel::Suspicious.to_string(), "Suspicious");
    assert_eq!(ThreatLevel::Malicious.to_string(), "Malicious");
    assert_eq!(ThreatLevel::Critical.to_string(), "Critical");
}

#[test]
fn test_threat_level_default() {
    assert_eq!(ThreatLevel::default(), ThreatLevel::Clean);
}

#[test]
fn test_threat_classification_equality() {
    assert_eq!(ThreatClassification::Trojan, ThreatClassification::Trojan);
    assert_ne!(ThreatClassification::Trojan, ThreatClassification::Virus);

    let other1 = ThreatClassification::Other("Custom".to_string());
    let other2 = ThreatClassification::Other("Custom".to_string());
    let other3 = ThreatClassification::Other("Different".to_string());

    assert_eq!(other1, other2);
    assert_ne!(other1, other3);
}

#[test]
fn test_threat_classification_display() {
    assert_eq!(ThreatClassification::Trojan.to_string(), "Trojan");
    assert_eq!(ThreatClassification::Virus.to_string(), "Virus");
    assert_eq!(ThreatClassification::Worm.to_string(), "Worm");
    assert_eq!(ThreatClassification::Rootkit.to_string(), "Rootkit");
    assert_eq!(ThreatClassification::Adware.to_string(), "Adware");
    assert_eq!(ThreatClassification::Spyware.to_string(), "Spyware");
    assert_eq!(ThreatClassification::Ransomware.to_string(), "Ransomware");
    assert_eq!(ThreatClassification::Apt.to_string(), "APT");
    assert_eq!(ThreatClassification::Pua.to_string(), "PUA");
    assert_eq!(ThreatClassification::Banker.to_string(), "Banker");
    assert_eq!(ThreatClassification::Downloader.to_string(), "Downloader");
    assert_eq!(ThreatClassification::Backdoor.to_string(), "Backdoor");
    assert_eq!(ThreatClassification::Exploit.to_string(), "Exploit");
    assert_eq!(ThreatClassification::Cryptominer.to_string(), "Cryptominer");
    assert_eq!(ThreatClassification::InfoStealer.to_string(), "InfoStealer");
    assert_eq!(ThreatClassification::Botnet.to_string(), "Botnet");
    assert_eq!(ThreatClassification::WebShell.to_string(), "WebShell");
    assert_eq!(ThreatClassification::Keylogger.to_string(), "Keylogger");
    assert_eq!(
        ThreatClassification::ScreenCapture.to_string(),
        "ScreenCapture"
    );
    assert_eq!(
        ThreatClassification::RemoteAccess.to_string(),
        "RemoteAccess"
    );
    assert_eq!(
        ThreatClassification::Other("Custom".to_string()).to_string(),
        "Custom"
    );
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_severity_display() {
    assert_eq!(Severity::Low.to_string(), "Low");
    assert_eq!(Severity::Medium.to_string(), "Medium");
    assert_eq!(Severity::High.to_string(), "High");
    assert_eq!(Severity::Critical.to_string(), "Critical");
}

#[test]
fn test_severity_default() {
    assert_eq!(Severity::default(), Severity::Low);
}

#[test]
fn test_yara_match_construction() {
    let mut metadata = HashMap::new();
    metadata.insert("author".to_string(), "Test Author".to_string());
    metadata.insert("description".to_string(), "Test rule".to_string());

    let string_match = StringMatch {
        identifier: "$test_string".to_string(),
        offset: 1024,
        length: 12,
        value: Some("Hello World!".to_string()),
    };

    let yara_match = YaraMatch {
        rule_identifier: "test_rule".to_string(),
        tags: vec!["malware".to_string(), "trojan".to_string()],
        metadata,
        strings: vec![string_match],
    };

    assert_eq!(yara_match.rule_identifier, "test_rule");
    assert_eq!(yara_match.tags.len(), 2);
    assert!(yara_match.tags.contains(&"malware".to_string()));
    assert!(yara_match.tags.contains(&"trojan".to_string()));
    assert_eq!(yara_match.metadata.len(), 2);
    assert_eq!(yara_match.strings.len(), 1);
    assert_eq!(yara_match.strings[0].identifier, "$test_string");
    assert_eq!(yara_match.strings[0].offset, 1024);
    assert_eq!(yara_match.strings[0].length, 12);
    assert_eq!(
        yara_match.strings[0].value,
        Some("Hello World!".to_string())
    );
}

#[test]
fn test_string_match_construction() {
    let string_match = StringMatch {
        identifier: "$hex_pattern".to_string(),
        offset: 2048,
        length: 8,
        value: None, // Binary data, not printable
    };

    assert_eq!(string_match.identifier, "$hex_pattern");
    assert_eq!(string_match.offset, 2048);
    assert_eq!(string_match.length, 8);
    assert!(string_match.value.is_none());
}

#[test]
fn test_threat_indicator_construction() {
    let mut context = HashMap::new();
    context.insert("api_call".to_string(), "CreateRemoteThread".to_string());
    context.insert("dll".to_string(), "kernel32.dll".to_string());

    let indicator = ThreatIndicator {
        indicator_type: IndicatorType::ProcessInjection,
        description: "Suspicious process injection technique detected".to_string(),
        severity: Severity::High,
        confidence: 0.85,
        mitre_technique: Some("T1055".to_string()),
        context,
    };

    assert_eq!(indicator.indicator_type, IndicatorType::ProcessInjection);
    assert_eq!(
        indicator.description,
        "Suspicious process injection technique detected"
    );
    assert_eq!(indicator.severity, Severity::High);
    assert!((indicator.confidence - 0.85).abs() < f32::EPSILON);
    assert_eq!(indicator.mitre_technique, Some("T1055".to_string()));
    assert_eq!(indicator.context.len(), 2);
}

#[test]
fn test_indicator_type_variants() {
    let types = vec![
        IndicatorType::KnownMalwareFamily,
        IndicatorType::SuspiciousBehavior,
        IndicatorType::ExploitTechnique,
        IndicatorType::AntiAnalysis,
        IndicatorType::NetworkIndicator,
        IndicatorType::PersistenceMechanism,
        IndicatorType::DataExfiltration,
        IndicatorType::CryptoOperation,
        IndicatorType::SystemModification,
        IndicatorType::ProcessInjection,
        IndicatorType::PrivilegeEscalation,
        IndicatorType::LateralMovement,
        IndicatorType::CommandAndControl,
        IndicatorType::DefenseEvasion,
        IndicatorType::Discovery,
        IndicatorType::Collection,
        IndicatorType::Exfiltration,
        IndicatorType::Impact,
    ];

    assert_eq!(types.len(), 18);

    // Test equality
    assert_eq!(
        IndicatorType::ProcessInjection,
        IndicatorType::ProcessInjection
    );
    assert_ne!(IndicatorType::ProcessInjection, IndicatorType::AntiAnalysis);
}

#[test]
fn test_scan_statistics_construction() {
    let stats = ScanStatistics {
        scan_duration: Duration::from_secs(5),
        rules_evaluated: 150,
        patterns_matched: 3,
        file_size_scanned: 1024 * 1024, // 1MB
    };

    assert_eq!(stats.scan_duration, Duration::from_secs(5));
    assert_eq!(stats.rules_evaluated, 150);
    assert_eq!(stats.patterns_matched, 3);
    assert_eq!(stats.file_size_scanned, 1024 * 1024);
}

#[test]
fn test_scan_target_variants() {
    use std::path::PathBuf;

    let file_target = ScanTarget::File(PathBuf::from("/tmp/test.exe"));
    let memory_target = ScanTarget::Memory {
        data: vec![0x4d, 0x5a, 0x90, 0x00], // PE header
        name: Some("test_sample.exe".to_string()),
    };
    let dir_target = ScanTarget::Directory(PathBuf::from("/tmp/samples"));

    match file_target {
        ScanTarget::File(path) => assert_eq!(path, PathBuf::from("/tmp/test.exe")),
        _ => panic!("Expected File variant"),
    }

    match memory_target {
        ScanTarget::Memory { data, name } => {
            assert_eq!(data, vec![0x4d, 0x5a, 0x90, 0x00]);
            assert_eq!(name, Some("test_sample.exe".to_string()));
        }
        _ => panic!("Expected Memory variant"),
    }

    match dir_target {
        ScanTarget::Directory(path) => assert_eq!(path, PathBuf::from("/tmp/samples")),
        _ => panic!("Expected Directory variant"),
    }
}

#[test]
fn test_engine_config_construction() {
    let mut settings = HashMap::new();
    settings.insert("timeout".to_string(), "300".to_string());
    settings.insert("max_rules".to_string(), "1000".to_string());

    let rule_source = RuleSource {
        name: "yara-rules".to_string(),
        url: "https://github.com/Yara-Rules/rules".to_string(),
        source_type: RuleSourceType::Git,
        auth: None,
    };

    let config = EngineConfig {
        settings,
        rule_sources: vec![rule_source],
        update_interval: 12, // 12 hours
    };

    assert_eq!(config.settings.len(), 2);
    assert_eq!(config.rule_sources.len(), 1);
    assert_eq!(config.update_interval, 12);
    assert_eq!(config.rule_sources[0].name, "yara-rules");
    assert_eq!(config.rule_sources[0].source_type, RuleSourceType::Git);
}

#[test]
fn test_engine_config_default() {
    let config = EngineConfig::default();
    assert!(config.settings.is_empty());
    assert!(config.rule_sources.is_empty());
    assert_eq!(config.update_interval, 24);
}

#[test]
fn test_rule_source_types() {
    assert_eq!(RuleSourceType::Git, RuleSourceType::Git);
    assert_eq!(RuleSourceType::Http, RuleSourceType::Http);
    assert_eq!(RuleSourceType::Local, RuleSourceType::Local);
    assert_eq!(RuleSourceType::Builtin, RuleSourceType::Builtin);

    assert_ne!(RuleSourceType::Git, RuleSourceType::Http);
    assert_ne!(RuleSourceType::Local, RuleSourceType::Builtin);
}

#[test]
fn test_scan_config_construction() {
    let config = ScanConfig {
        max_file_size: 50 * 1024 * 1024,      // 50MB
        scan_timeout: Duration::from_mins(3), // 3 minutes
        max_concurrent_scans: 8,
    };

    assert_eq!(config.max_file_size, 50 * 1024 * 1024);
    assert_eq!(config.scan_timeout, Duration::from_mins(3));
    assert_eq!(config.max_concurrent_scans, 8);
}

#[test]
fn test_scan_config_default() {
    let config = ScanConfig::default();
    assert_eq!(config.max_file_size, 100 * 1024 * 1024);
    assert_eq!(config.scan_timeout, Duration::from_mins(5));
    assert_eq!(config.max_concurrent_scans, 4);
}

#[test]
fn test_compiled_rules_construction() {
    let mut metadata = HashMap::new();
    metadata.insert(
        "test_rule".to_string(),
        RuleMetadata {
            name: "test_rule".to_string(),
            author: Some("Security Researcher".to_string()),
            description: Some("Test rule for validation".to_string()),
            version: Some("1.0".to_string()),
            date: Some("2023-01-01".to_string()),
            tags: vec!["test".to_string(), "validation".to_string()],
        },
    );

    let compiled = CompiledRules {
        rule_count: 1,
        errors: vec![],
        warnings: vec!["Deprecated syntax in rule xyz".to_string()],
        metadata,
    };

    assert_eq!(compiled.rule_count, 1);
    assert!(compiled.errors.is_empty());
    assert_eq!(compiled.warnings.len(), 1);
    assert_eq!(compiled.metadata.len(), 1);

    let rule_meta = &compiled.metadata["test_rule"];
    assert_eq!(rule_meta.name, "test_rule");
    assert_eq!(rule_meta.author, Some("Security Researcher".to_string()));
    assert_eq!(rule_meta.tags.len(), 2);
}

#[test]
fn test_rule_metadata_construction() {
    let metadata = RuleMetadata {
        name: "malware_detection".to_string(),
        author: Some("Threat Intel Team".to_string()),
        description: Some("Detects known malware families".to_string()),
        version: Some("2.1".to_string()),
        date: Some("2023-12-01".to_string()),
        tags: vec![
            "malware".to_string(),
            "trojan".to_string(),
            "apt".to_string(),
        ],
    };

    assert_eq!(metadata.name, "malware_detection");
    assert_eq!(metadata.author, Some("Threat Intel Team".to_string()));
    assert_eq!(
        metadata.description,
        Some("Detects known malware families".to_string())
    );
    assert_eq!(metadata.version, Some("2.1".to_string()));
    assert_eq!(metadata.date, Some("2023-12-01".to_string()));
    assert_eq!(metadata.tags.len(), 3);
    assert!(metadata.tags.contains(&"malware".to_string()));
    assert!(metadata.tags.contains(&"trojan".to_string()));
    assert!(metadata.tags.contains(&"apt".to_string()));
}

#[test]
fn test_threat_analysis_construction() {
    let yara_match = YaraMatch {
        rule_identifier: "test_malware".to_string(),
        tags: vec!["trojan".to_string()],
        metadata: HashMap::new(),
        strings: vec![],
    };

    let indicator = ThreatIndicator {
        indicator_type: IndicatorType::KnownMalwareFamily,
        description: "Known malware signature detected".to_string(),
        severity: Severity::Critical,
        confidence: 0.95,
        mitre_technique: None,
        context: HashMap::new(),
    };

    let analysis = ThreatAnalysis {
        matches: vec![yara_match],
        threat_level: ThreatLevel::Malicious,
        classifications: vec![ThreatClassification::Trojan],
        indicators: vec![indicator],
        scan_stats: ScanStatistics {
            scan_duration: Duration::from_secs(2),
            rules_evaluated: 100,
            patterns_matched: 1,
            file_size_scanned: 4096,
        },
        recommendations: vec![
            "Quarantine the file immediately".to_string(),
            "Scan related files in the directory".to_string(),
        ],
    };

    assert_eq!(analysis.matches.len(), 1);
    assert_eq!(analysis.threat_level, ThreatLevel::Malicious);
    assert_eq!(analysis.classifications.len(), 1);
    assert_eq!(analysis.indicators.len(), 1);
    assert_eq!(analysis.recommendations.len(), 2);
    assert_eq!(analysis.scan_stats.rules_evaluated, 100);
}

#[test]
fn test_confidence_score_validation() {
    // Test that confidence scores are reasonable
    let indicator = ThreatIndicator {
        indicator_type: IndicatorType::SuspiciousBehavior,
        description: "Test indicator".to_string(),
        severity: Severity::Medium,
        confidence: 0.75,
        mitre_technique: None,
        context: HashMap::new(),
    };

    assert!(indicator.confidence >= 0.0);
    assert!(indicator.confidence <= 1.0);

    // Test edge cases
    let high_confidence = ThreatIndicator {
        confidence: 1.0,
        ..indicator.clone()
    };
    assert!((high_confidence.confidence - 1.0).abs() < f32::EPSILON);

    let low_confidence = ThreatIndicator {
        confidence: 0.0,
        ..indicator
    };
    assert!(low_confidence.confidence.abs() < f32::EPSILON);
}

#[cfg(feature = "serde")]
#[test]
fn test_serialization() {
    use serde_json;

    let threat_level = ThreatLevel::Malicious;
    let json = serde_json::to_string(&threat_level).unwrap();
    let deserialized: ThreatLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(threat_level, deserialized);

    let classification = ThreatClassification::Trojan;
    let json = serde_json::to_string(&classification).unwrap();
    let deserialized: ThreatClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classification, deserialized);

    let severity = Severity::High;
    let json = serde_json::to_string(&severity).unwrap();
    let deserialized: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(severity, deserialized);
}
