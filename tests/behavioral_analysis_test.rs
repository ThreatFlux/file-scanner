use file_scanner::behavioral_analysis::*;
use file_scanner::function_analysis::*;
use file_scanner::strings::ExtractedStrings;
use tempfile::tempdir;

/// Helper function to create test strings with specific patterns
fn create_test_strings_with_patterns(patterns: Vec<&str>) -> ExtractedStrings {
    ExtractedStrings {
        total_count: patterns.len(),
        unique_count: patterns.len(),
        ascii_strings: patterns.iter().map(|s| s.to_string()).collect(),
        unicode_strings: vec![],
        interesting_strings: vec![],
    }
}

/// Helper function to create test symbol table with specific function names
fn create_test_symbols_with_functions(function_names: Vec<&str>) -> SymbolTable {
    let functions = function_names
        .iter()
        .enumerate()
        .map(|(i, name)| FunctionInfo {
            name: name.to_string(),
            address: 0x1000 + (i * 0x100) as u64,
            size: 100,
            function_type: if name.contains("import") {
                FunctionType::Imported
            } else {
                FunctionType::Local
            },
            calling_convention: Some(CallingConvention::Stdcall),
            parameters: vec![],
            is_entry_point: name == &"main" || name == &"_start",
            is_exported: name.contains("export"),
            is_imported: name.contains("import"),
        })
        .collect();

    SymbolTable {
        functions,
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: function_names.len(),
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    }
}

#[test]
fn test_anti_analysis_technique_creation() {
    let technique = AntiAnalysisTechnique {
        technique_type: AntiAnalysisType::AntiDebug,
        indicators: vec!["IsDebuggerPresent".to_string()],
        confidence: 0.9,
        description: "Debugger detection found".to_string(),
    };

    assert!(matches!(
        technique.technique_type,
        AntiAnalysisType::AntiDebug
    ));
    assert_eq!(technique.indicators.len(), 1);
    assert_eq!(technique.confidence, 0.9);
    assert_eq!(technique.description, "Debugger detection found");
}

#[test]
fn test_all_anti_analysis_types() {
    let types = vec![
        AntiAnalysisType::AntiDebug,
        AntiAnalysisType::AntiVM,
        AntiAnalysisType::AntiSandbox,
        AntiAnalysisType::AntiDisassembly,
        AntiAnalysisType::Obfuscation,
        AntiAnalysisType::TimeDelays,
        AntiAnalysisType::EnvironmentChecks,
        AntiAnalysisType::ProcessHollowing,
        AntiAnalysisType::CodeInjection,
    ];

    for anti_type in types {
        let technique = AntiAnalysisTechnique {
            technique_type: anti_type.clone(),
            indicators: vec!["test".to_string()],
            confidence: 0.8,
            description: "Test technique".to_string(),
        };

        assert!(
            std::mem::discriminant(&technique.technique_type) == std::mem::discriminant(&anti_type)
        );
    }
}

#[test]
fn test_persistence_mechanism_creation() {
    let mechanism = PersistenceMechanism {
        mechanism_type: PersistenceType::RegistryKeys,
        target_locations: vec!["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()],
        severity: Severity::High,
        description: "Registry persistence detected".to_string(),
    };

    assert!(matches!(
        mechanism.mechanism_type,
        PersistenceType::RegistryKeys
    ));
    assert_eq!(mechanism.target_locations.len(), 1);
    assert!(matches!(mechanism.severity, Severity::High));
}

#[test]
fn test_all_persistence_types() {
    let types = vec![
        PersistenceType::RegistryKeys,
        PersistenceType::ServiceInstallation,
        PersistenceType::ScheduledTasks,
        PersistenceType::StartupFolders,
        PersistenceType::DLLHijacking,
        PersistenceType::ProcessInjection,
        PersistenceType::BootkitRootkit,
        PersistenceType::WMIEventSubscription,
        PersistenceType::BrowserExtension,
        PersistenceType::OfficeAddins,
    ];

    for pers_type in types {
        let mechanism = PersistenceMechanism {
            mechanism_type: pers_type.clone(),
            target_locations: vec![],
            severity: Severity::Medium,
            description: "Test persistence".to_string(),
        };

        assert!(
            std::mem::discriminant(&mechanism.mechanism_type) == std::mem::discriminant(&pers_type)
        );
    }
}

#[test]
fn test_network_pattern_creation() {
    let pattern = NetworkPattern {
        pattern_type: NetworkPatternType::CommandAndControl,
        indicators: vec!["http://malicious.com".to_string()],
        protocols: vec!["HTTP".to_string()],
        ports: vec![80, 443],
        suspicious_level: SuspicionLevel::High,
    };

    assert!(matches!(
        pattern.pattern_type,
        NetworkPatternType::CommandAndControl
    ));
    assert_eq!(pattern.indicators.len(), 1);
    assert_eq!(pattern.protocols.len(), 1);
    assert_eq!(pattern.ports.len(), 2);
    assert!(matches!(pattern.suspicious_level, SuspicionLevel::High));
}

#[test]
fn test_all_network_pattern_types() {
    let types = vec![
        NetworkPatternType::CommandAndControl,
        NetworkPatternType::DataExfiltration,
        NetworkPatternType::DomainGeneration,
        NetworkPatternType::TorUsage,
        NetworkPatternType::P2PCommunication,
        NetworkPatternType::HTTPSBypass,
        NetworkPatternType::DNSTunneling,
        NetworkPatternType::IRCCommunication,
    ];

    for pattern_type in types {
        let pattern = NetworkPattern {
            pattern_type: pattern_type.clone(),
            indicators: vec![],
            protocols: vec![],
            ports: vec![],
            suspicious_level: SuspicionLevel::Medium,
        };

        assert!(
            std::mem::discriminant(&pattern.pattern_type) == std::mem::discriminant(&pattern_type)
        );
    }
}

#[test]
fn test_file_operation_creation() {
    let operation = FileOperation {
        operation_type: FileOpType::FileEncryption,
        targets: vec!["CryptEncrypt".to_string()],
        suspicious: true,
    };

    assert!(matches!(
        operation.operation_type,
        FileOpType::FileEncryption
    ));
    assert_eq!(operation.targets.len(), 1);
    assert!(operation.suspicious);
}

#[test]
fn test_all_file_operation_types() {
    let types = vec![
        FileOpType::FileCreation,
        FileOpType::FileDeletion,
        FileOpType::FileModification,
        FileOpType::FileEncryption,
        FileOpType::FileCopying,
        FileOpType::FileHiding,
    ];

    for op_type in types {
        let operation = FileOperation {
            operation_type: op_type.clone(),
            targets: vec![],
            suspicious: false,
        };

        assert!(
            std::mem::discriminant(&operation.operation_type) == std::mem::discriminant(&op_type)
        );
    }
}

#[test]
fn test_registry_operation_creation() {
    let operation = RegistryOperation {
        operation_type: RegistryOpType::KeyCreation,
        keys: vec!["HKEY_LOCAL_MACHINE\\SOFTWARE\\Test".to_string()],
        purpose: "Test registry operation".to_string(),
    };

    assert!(matches!(
        operation.operation_type,
        RegistryOpType::KeyCreation
    ));
    assert_eq!(operation.keys.len(), 1);
    assert_eq!(operation.purpose, "Test registry operation");
}

#[test]
fn test_process_operation_creation() {
    let operation = ProcessOperation {
        operation_type: ProcessOpType::ProcessInjection,
        targets: vec!["target_process.exe".to_string()],
        techniques: vec!["CreateRemoteThread".to_string()],
    };

    assert!(matches!(
        operation.operation_type,
        ProcessOpType::ProcessInjection
    ));
    assert_eq!(operation.targets.len(), 1);
    assert_eq!(operation.techniques.len(), 1);
}

#[test]
fn test_all_process_operation_types() {
    let types = vec![
        ProcessOpType::ProcessCreation,
        ProcessOpType::ProcessTermination,
        ProcessOpType::ProcessInjection,
        ProcessOpType::ProcessHollowing,
        ProcessOpType::ThreadCreation,
        ProcessOpType::PrivilegeEscalation,
    ];

    for op_type in types {
        let operation = ProcessOperation {
            operation_type: op_type.clone(),
            targets: vec![],
            techniques: vec![],
        };

        assert!(
            std::mem::discriminant(&operation.operation_type) == std::mem::discriminant(&op_type)
        );
    }
}

#[test]
fn test_suspicious_behavior_creation() {
    let behavior = SuspiciousBehavior {
        behavior_type: "Ransomware".to_string(),
        description: "File encryption with ransom note".to_string(),
        severity: Severity::Critical,
        evidence: vec![
            "CryptEncrypt API".to_string(),
            "Ransom note text".to_string(),
        ],
    };

    assert_eq!(behavior.behavior_type, "Ransomware");
    assert!(matches!(behavior.severity, Severity::Critical));
    assert_eq!(behavior.evidence.len(), 2);
}

#[test]
fn test_severity_levels() {
    let severities = vec![
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    for severity in severities {
        let behavior = SuspiciousBehavior {
            behavior_type: "Test".to_string(),
            description: "Test behavior".to_string(),
            severity: severity.clone(),
            evidence: vec![],
        };

        assert!(std::mem::discriminant(&behavior.severity) == std::mem::discriminant(&severity));
    }
}

#[test]
fn test_anti_debug_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // Create test strings with anti-debug indicators
    let strings = create_test_strings_with_patterns(vec![
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugString",
    ]);

    let symbols = create_test_symbols_with_functions(vec!["NtQueryInformationProcess"]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(!analysis.anti_analysis.is_empty());

    let anti_debug = analysis
        .anti_analysis
        .iter()
        .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiDebug));
    assert!(anti_debug.is_some());
    assert!(anti_debug.unwrap().indicators.len() >= 3);
}

#[test]
fn test_anti_vm_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec!["VMware", "VirtualBox", "QEMU", "vmci"]);

    let result = analyze_behavior(&test_path, Some(&strings), None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let anti_vm = analysis
        .anti_analysis
        .iter()
        .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiVM));
    assert!(anti_vm.is_some());
}

#[test]
fn test_anti_sandbox_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings =
        create_test_strings_with_patterns(vec!["SbieDll", "sandbox", "sample", "GetCursorPos"]);

    let result = analyze_behavior(&test_path, Some(&strings), None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let anti_sandbox = analysis
        .anti_analysis
        .iter()
        .find(|t| matches!(t.technique_type, AntiAnalysisType::AntiSandbox));
    assert!(anti_sandbox.is_some());
}

#[test]
fn test_registry_persistence_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec![
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]);

    let result = analyze_behavior(&test_path, Some(&strings), None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(!analysis.persistence.is_empty());

    let registry_persistence = analysis
        .persistence
        .iter()
        .find(|p| matches!(p.mechanism_type, PersistenceType::RegistryKeys));
    assert!(registry_persistence.is_some());
}

#[test]
fn test_service_persistence_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let symbols =
        create_test_symbols_with_functions(vec!["CreateService", "OpenSCManager", "StartService"]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let service_persistence = analysis
        .persistence
        .iter()
        .find(|p| matches!(p.mechanism_type, PersistenceType::ServiceInstallation));
    assert!(service_persistence.is_some());
}

#[test]
fn test_network_communication_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec![
        "http://",
        "https://",
        "192.168.1.1",
        "malicious.com",
    ]);

    let symbols = create_test_symbols_with_functions(vec!["socket", "connect", "send", "recv"]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(!analysis.network_behavior.is_empty());
}

#[test]
fn test_tor_usage_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec![".onion", "tor.exe", "9050"]);

    let result = analyze_behavior(&test_path, Some(&strings), None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let tor_pattern = analysis
        .network_behavior
        .iter()
        .find(|n| matches!(n.pattern_type, NetworkPatternType::TorUsage));
    assert!(tor_pattern.is_some());
}

#[test]
fn test_file_encryption_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings =
        create_test_strings_with_patterns(vec!["CryptEncrypt", "AES", ".encrypted", "ransom"]);

    let result = analyze_behavior(&test_path, Some(&strings), None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let encryption_op = analysis
        .file_operations
        .iter()
        .find(|op| matches!(op.operation_type, FileOpType::FileEncryption));
    assert!(encryption_op.is_some());
    assert!(encryption_op.unwrap().suspicious);
}

#[test]
fn test_process_injection_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let symbols = create_test_symbols_with_functions(vec![
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "OpenProcess",
    ]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let injection_op = analysis
        .process_operations
        .iter()
        .find(|op| matches!(op.operation_type, ProcessOpType::ProcessInjection));
    assert!(injection_op.is_some());
}

#[test]
fn test_process_hollowing_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let symbols = create_test_symbols_with_functions(vec![
        "NtUnmapViewOfSection",
        "CreateProcess",
        "WriteProcessMemory",
        "SetThreadContext",
        "ResumeThread",
    ]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let hollowing_op = analysis
        .process_operations
        .iter()
        .find(|op| matches!(op.operation_type, ProcessOpType::ProcessHollowing));
    assert!(hollowing_op.is_some());
}

#[test]
fn test_privilege_escalation_detection() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let symbols = create_test_symbols_with_functions(vec![
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValue",
    ]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let priv_esc_op = analysis
        .process_operations
        .iter()
        .find(|op| matches!(op.operation_type, ProcessOpType::PrivilegeEscalation));
    assert!(priv_esc_op.is_some());
}

#[test]
fn test_ransomware_behavior_identification() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // Need at least 2 crypto indicators to trigger FileEncryption operation
    let strings = create_test_strings_with_patterns(vec![
        "CryptEncrypt",
        "AES", // Add second crypto indicator
    ]);

    // File operations need to be detected via symbols, not strings
    let symbols = create_test_symbols_with_functions(vec![
        "FindFirstFile", // File enumeration API
        "DeleteFile",    // File deletion API
    ]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    let ransomware_behavior = analysis
        .suspicious_behaviors
        .iter()
        .find(|b| b.behavior_type == "Ransomware");
    assert!(ransomware_behavior.is_some());
    assert!(matches!(
        ransomware_behavior.unwrap().severity,
        Severity::Critical
    ));
}

#[test]
fn test_rootkit_behavior_identification() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // Need both native APIs and process injection/service functions
    // Use process hollowing APIs that put "Nt" functions in techniques
    let symbols = create_test_symbols_with_functions(vec![
        "NtUnmapViewOfSection", // Native API that gets put in techniques (contains "Nt")
        "CreateProcess",        // Process creation for hollowing
        "WriteProcessMemory",   // Memory writing for hollowing
        "SetThreadContext",     // Thread context for hollowing
        "ResumeThread",         // Resume thread for hollowing (need >= 4 for hollowing)
        "CreateService",        // Service installation API
        "OpenSCManager",        // Additional service API to trigger service persistence
    ]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();

    let rootkit_behavior = analysis
        .suspicious_behaviors
        .iter()
        .find(|b| b.behavior_type == "Rootkit");
    assert!(rootkit_behavior.is_some());
}

#[test]
fn test_backdoor_behavior_identification() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec![
        "http://",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]);

    let symbols = create_test_symbols_with_functions(vec!["CreateProcess", "socket"]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let backdoor_behavior = analysis
        .suspicious_behaviors
        .iter()
        .find(|b| b.behavior_type == "Backdoor");
    assert!(backdoor_behavior.is_some());
}

#[test]
fn test_data_theft_behavior_identification() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let strings = create_test_strings_with_patterns(vec!["https://"]);

    let symbols = create_test_symbols_with_functions(vec!["CopyFile", "socket"]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let data_theft_behavior = analysis
        .suspicious_behaviors
        .iter()
        .find(|b| b.behavior_type == "DataTheft");
    assert!(data_theft_behavior.is_some());
}

#[test]
fn test_dropper_behavior_identification() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // URLDownloadToFile needs to be in symbols to be detected as network API
    let symbols = create_test_symbols_with_functions(vec![
        "URLDownloadToFile", // Network download API - needs to be in symbols
        "CreateFile",        // File creation API
        "CreateProcess",     // Process creation API
    ]);

    let result = analyze_behavior(&test_path, None, Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    let dropper_behavior = analysis
        .suspicious_behaviors
        .iter()
        .find(|b| b.behavior_type == "Dropper");
    assert!(dropper_behavior.is_some());
}

#[test]
fn test_evasion_score_calculation() {
    let _anti_analysis = vec![
        AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: vec!["IsDebuggerPresent".to_string()],
            confidence: 0.9,
            description: "Anti-debug".to_string(),
        },
        AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiVM,
            indicators: vec!["VMware".to_string()],
            confidence: 0.8,
            description: "Anti-VM".to_string(),
        },
    ];

    let _suspicious_behaviors = vec![SuspiciousBehavior {
        behavior_type: "Ransomware".to_string(),
        description: "File encryption".to_string(),
        severity: Severity::Critical,
        evidence: vec![],
    }];

    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    let result = analyze_behavior(&test_path, None, None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(analysis.evasion_score >= 0.0 && analysis.evasion_score <= 100.0);
}

#[test]
fn test_behavioral_recommendations_generation() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // Need at least 2 crypto indicators to trigger ransomware behavior
    let strings = create_test_strings_with_patterns(vec![
        "IsDebuggerPresent",
        "CryptEncrypt",
        "ransom", // This is also a crypto indicator
        "AES",    // Add another crypto indicator to trigger FileEncryption
    ]);

    // File operations need to be detected via symbols, not strings
    let symbols = create_test_symbols_with_functions(vec![
        "FindFirstFile", // File enumeration API
        "DeleteFile",    // File deletion API
    ]);

    let result = analyze_behavior(&test_path, Some(&strings), Some(&symbols), None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(!analysis.recommendations.is_empty());

    // Should contain ransomware-specific recommendations
    let has_ransomware_recommendation = analysis
        .recommendations
        .iter()
        .any(|r| r.contains("RANSOMWARE") || r.contains("encrypt"));
    assert!(has_ransomware_recommendation);
}

#[test]
fn test_empty_analysis() {
    let temp_dir = tempdir().unwrap();
    let test_path = temp_dir.path().join("test.exe");

    // No strings or symbols provided
    let result = analyze_behavior(&test_path, None, None, None);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert!(analysis.anti_analysis.is_empty());
    assert!(analysis.persistence.is_empty());
    assert!(analysis.network_behavior.is_empty());
    assert!(analysis.file_operations.is_empty());
    assert!(analysis.process_operations.is_empty());
    assert!(analysis.suspicious_behaviors.is_empty());
    assert_eq!(analysis.evasion_score, 0.0);
    assert!(!analysis.recommendations.is_empty()); // Should have default recommendations
}

#[test]
fn test_serialization_deserialization() {
    let analysis = BehavioralAnalysis {
        anti_analysis: vec![AntiAnalysisTechnique {
            technique_type: AntiAnalysisType::AntiDebug,
            indicators: vec!["test".to_string()],
            confidence: 0.8,
            description: "Test".to_string(),
        }],
        persistence: vec![],
        network_behavior: vec![],
        file_operations: vec![],
        registry_operations: vec![],
        process_operations: vec![],
        evasion_score: 25.0,
        suspicious_behaviors: vec![],
        recommendations: vec!["Test recommendation".to_string()],
    };

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: BehavioralAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(
        analysis.anti_analysis.len(),
        deserialized.anti_analysis.len()
    );
    assert_eq!(analysis.evasion_score, deserialized.evasion_score);
    assert_eq!(
        analysis.recommendations.len(),
        deserialized.recommendations.len()
    );
}
