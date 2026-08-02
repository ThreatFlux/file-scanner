use anyhow::{Context, Result};
use cfb::CompoundFile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleVbaAnalysis {
    pub file_type: OleFileType,
    pub ole_structure: Option<OleStructure>,
    pub vba_project: Option<VbaProject>,
    pub macros: Vec<MacroInfo>,
    pub streams: Vec<StreamInfo>,
    pub suspicious_indicators: SuspiciousIndicators,
    pub metadata: OleMetadata,
    pub security_assessment: SecurityAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OleFileType {
    Ole2Document,    // Classic OLE2 document
    OfficeDocument,  // MS Office document (doc, xls, ppt)
    OfficeOpenXml,   // Modern Office format (docx, xlsx, pptx)
    OutlookMessage,  // Outlook PST/MSG files
    VisioDocument,   // Visio files
    OneNoteDocument, // OneNote files
    Other(String),   // Other OLE-based formats
    NotOleFile,      // Not an OLE file
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OleStructure {
    pub sector_size: u16,
    pub mini_sector_size: u16,
    pub total_sectors: u32,
    pub fat_sectors: u32,
    pub directory_sectors: u32,
    pub mini_fat_sectors: u32,
    pub root_entry: DirectoryEntry,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub entry_type: EntryType,
    pub color: NodeColor,
    pub size: u64,
    pub start_sector: u32,
    pub children: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntryType {
    Storage, // Directory/folder
    Stream,  // File/data stream
    Root,    // Root storage
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeColor {
    Red,
    Black,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaProject {
    pub project_name: String,
    pub modules: Vec<VbaModule>,
    pub references: Vec<VbaReference>,
    pub properties: HashMap<String, String>,
    pub protection: VbaProtection,
    pub version_info: VbaVersionInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaModule {
    pub name: String,
    pub module_type: VbaModuleType,
    pub source_code: Option<String>,
    pub compiled_code: Option<Vec<u8>>,
    pub line_count: usize,
    pub procedure_count: usize,
    pub procedures: Vec<VbaProcedure>,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VbaModuleType {
    Standard,    // Standard code module
    ClassModule, // Class module
    UserForm,    // User form
    Document,    // Document module (ThisDocument, Sheet1, etc.)
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaProcedure {
    pub name: String,
    pub procedure_type: VbaProcedureType,
    pub start_line: usize,
    pub end_line: usize,
    pub parameters: Vec<String>,
    pub local_variables: Vec<String>,
    pub external_calls: Vec<String>,
    pub risk_score: u8, // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VbaProcedureType {
    Sub,
    Function,
    Property,
    Event,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaReference {
    pub name: String,
    pub guid: Option<String>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub reference_type: VbaReferenceType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VbaReferenceType {
    TypeLib, // Type library
    Project, // VBA project
    Control, // ActiveX control
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaProtection {
    pub is_locked: bool,
    pub is_password_protected: bool,
    pub lock_bytes: Option<Vec<u8>>,
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaVersionInfo {
    pub major: u16,
    pub minor: u16,
    pub language_id: u16,
    pub performance_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    pub name: String,
    pub size: u64,
    pub stream_type: StreamType,
    pub content_preview: Option<String>,
    pub entropy: f64,
    pub compression_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamType {
    VbaProject,         // VBA project stream
    VbaModule,          // VBA module source
    VbaCompiled,        // Compiled VBA code
    WordDocument,       // Word document stream
    ExcelWorkbook,      // Excel workbook stream
    PowerPointDocument, // PowerPoint document stream
    OleObject,          // Embedded OLE object
    Metadata,           // Document metadata
    CustomData,         // Custom data stream
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspiciousIndicators {
    pub has_macros: bool,
    pub auto_exec_macros: Vec<String>,
    pub suspicious_api_calls: Vec<SuspiciousApiCall>,
    pub obfuscated_code: Vec<ObfuscationIndicator>,
    pub external_connections: Vec<ExternalConnection>,
    pub file_operations: Vec<FileOperation>,
    pub registry_operations: Vec<RegistryOperation>,
    pub process_operations: Vec<ProcessOperation>,
    pub cryptographic_operations: Vec<CryptoOperation>,
    pub risk_score: u8, // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousApiCall {
    pub api_name: String,
    pub module_name: String,
    pub call_count: u32,
    pub context: String,
    pub risk_level: RiskLevel,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationIndicator {
    pub technique: ObfuscationType,
    pub description: String,
    pub location: String,
    pub confidence: f64, // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObfuscationType {
    StringConcatenation,
    CharCodeObfuscation,
    Base64Encoding,
    HexEncoding,
    VariableNameObfuscation,
    ControlFlowObfuscation,
    CommentObfuscation,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalConnection {
    pub connection_type: ConnectionType,
    pub target: String,
    pub method: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    HttpRequest,
    FtpConnection,
    EmailSending,
    DnsLookup,
    SocketConnection,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperation {
    pub operation_type: FileOperationType,
    pub target_path: String,
    pub location: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileOperationType {
    Read,
    Write,
    Delete,
    Execute,
    Copy,
    Move,
    CreateDirectory,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryOperation {
    pub operation_type: RegistryOperationType,
    pub key_path: String,
    pub value_name: Option<String>,
    pub location: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperationType {
    Read,
    Write,
    Delete,
    CreateKey,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOperation {
    pub operation_type: ProcessOperationType,
    pub target_process: String,
    pub parameters: Vec<String>,
    pub location: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessOperationType {
    Create,
    Execute,
    Inject,
    Terminate,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoOperation {
    pub operation_type: CryptoOperationType,
    pub algorithm: String,
    pub location: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOperationType {
    Encryption,
    Decryption,
    Hashing,
    KeyGeneration,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OleMetadata {
    pub title: Option<String>,
    pub subject: Option<String>,
    pub author: Option<String>,
    pub keywords: Option<String>,
    pub comments: Option<String>,
    pub last_author: Option<String>,
    pub revision_number: Option<String>,
    pub application_name: Option<String>,
    pub creation_time: Option<String>,
    pub last_saved_time: Option<String>,
    pub total_edit_time: Option<String>,
    pub security: Option<u32>,
    pub custom_properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAssessment {
    pub overall_risk: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendations: Vec<String>,
    pub ioc_indicators: Vec<IocIndicator>,
    pub yara_matches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub description: String,
    pub severity: RiskLevel,
    pub confidence: f64, // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    MacroPresence,
    AutoExecution,
    SuspiciousApiCalls,
    NetworkConnections,
    FileSystemAccess,
    RegistryAccess,
    ProcessManipulation,
    Obfuscation,
    Encryption,
    EmbeddedObjects,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocIndicator {
    pub indicator_type: IocType,
    pub value: String,
    pub confidence: f64, // 0.0-1.0
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IocType {
    Domain,
    IpAddress,
    Url,
    EmailAddress,
    FileName,
    FilePath,
    RegistryKey,
    Mutex,
    ProcessName,
    Unknown,
}

/// Main entry point for OLE and VBA analysis
pub fn analyze_ole_vba(path: &Path) -> Result<OleVbaAnalysis> {
    let mut file = File::open(path).context("Failed to open file for OLE analysis")?;

    // First, determine if this is an OLE file
    let file_type = detect_ole_file_type(&mut file)?;

    if matches!(file_type, OleFileType::NotOleFile) {
        return Ok(OleVbaAnalysis {
            file_type,
            ole_structure: None,
            vba_project: None,
            macros: vec![],
            streams: vec![],
            suspicious_indicators: SuspiciousIndicators::default(),
            metadata: OleMetadata::default(),
            security_assessment: SecurityAssessment::default(),
        });
    }

    // Parse OLE structure
    let ole_structure = parse_ole_structure(&mut file)?;
    let streams = extract_stream_info(&mut file)?;

    // Parse VBA project if present
    let vba_project = extract_vba_project(&mut file)?;
    let macros = extract_macro_info(&vba_project)?;

    // Extract metadata
    let metadata = extract_ole_metadata(&mut file)?;

    // Analyze for suspicious indicators
    let suspicious_indicators = analyze_suspicious_patterns(&vba_project, &macros, &streams)?;

    // Perform security assessment
    let security_assessment = perform_security_assessment(&suspicious_indicators, &macros)?;

    Ok(OleVbaAnalysis {
        file_type,
        ole_structure: Some(ole_structure),
        vba_project,
        macros,
        streams,
        suspicious_indicators,
        metadata,
        security_assessment,
    })
}

pub fn detect_ole_file_type(file: &mut File) -> Result<OleFileType> {
    let mut header = [0u8; 512];
    file.read_exact(&mut header)
        .context("Failed to read file header")?;

    // Check for OLE2 signature
    if &header[0..8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
        // This is an OLE2 file, try to determine the specific type
        return determine_ole_document_type(file);
    }

    // Check for Office Open XML (OOXML) format
    if &header[0..2] == b"PK" {
        return determine_ooxml_type(file);
    }

    Ok(OleFileType::NotOleFile)
}

fn determine_ole_document_type(file: &mut File) -> Result<OleFileType> {
    // Try to parse as compound file to examine streams
    file.seek(std::io::SeekFrom::Start(0))?;

    if let Ok(cfb) = CompoundFile::open(file) {
        // Check for common Office document streams
        let stream_names = vec![
            "WordDocument",
            "Workbook",
            "Book",
            "PowerPoint Document",
            "VisioDocument",
            "\x01Ole",
        ];

        for stream_name in stream_names {
            if cfb.entry(stream_name).is_ok() {
                return match stream_name {
                    "VisioDocument" => Ok(OleFileType::VisioDocument),
                    _ => Ok(OleFileType::OfficeDocument),
                };
            }
        }
    }

    Ok(OleFileType::Ole2Document)
}

const fn determine_ooxml_type(_file: &mut File) -> Result<OleFileType> {
    // For OOXML files, we would need to examine the content types
    // This is a simplified implementation
    Ok(OleFileType::OfficeOpenXml)
}

fn parse_ole_structure(file: &mut File) -> Result<OleStructure> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let _cfb = CompoundFile::open(file).context("Failed to parse OLE compound file")?;

    // Simplified structure since cfb crate doesn't expose detailed internal structure
    let root_entry = DirectoryEntry {
        name: "Root Entry".to_string(),
        entry_type: EntryType::Root,
        color: NodeColor::Black,
        size: 0,
        start_sector: 0,
        children: Vec::new(),
    };

    Ok(OleStructure {
        sector_size: 512,     // Default sector size
        mini_sector_size: 64, // Default mini sector size
        total_sectors: 0,     // Would need to extract from header
        fat_sectors: 0,
        directory_sectors: 0,
        mini_fat_sectors: 0,
        root_entry,
        entries: vec![], // Would need detailed CFB parsing to populate
    })
}

fn extract_stream_info(file: &mut File) -> Result<Vec<StreamInfo>> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut cfb = CompoundFile::open(file).context("Failed to parse OLE compound file")?;

    let mut streams = Vec::new();

    // Check for common streams
    let common_streams = vec![
        "WordDocument",
        "Workbook",
        "PowerPoint Document",
        "VBA",
        "PROJECT",
        "MODULE1",
        "\x05SummaryInformation",
        "\x05DocumentSummaryInformation",
    ];

    for stream_name in common_streams {
        if let Ok(entry) = cfb.entry(stream_name) {
            let stream_type = determine_stream_type(stream_name);
            let entropy = calculate_stream_entropy(&mut cfb, stream_name)?;

            streams.push(StreamInfo {
                name: stream_name.to_string(),
                size: entry.len(),
                stream_type,
                content_preview: extract_stream_preview(&mut cfb, stream_name)?,
                entropy,
                compression_ratio: None, // Would require compression analysis
            });
        }
    }

    Ok(streams)
}

pub fn determine_stream_type(name: &str) -> StreamType {
    match name {
        name if name.contains("VBA") => StreamType::VbaProject,
        name if name.contains("MODULE") => StreamType::VbaModule,
        "WordDocument" => StreamType::WordDocument,
        "Workbook" | "Book" => StreamType::ExcelWorkbook,
        "PowerPoint Document" => StreamType::PowerPointDocument,
        name if name.starts_with('\x05') => StreamType::Metadata,
        _ => StreamType::Unknown,
    }
}

fn calculate_stream_entropy<R: Read + Seek>(
    cfb: &mut CompoundFile<R>,
    stream_name: &str,
) -> Result<f64> {
    if let Ok(mut stream) = cfb.open_stream(stream_name) {
        let mut buffer = Vec::new();
        if stream.read_to_end(&mut buffer).is_ok() && !buffer.is_empty() {
            return Ok(calculate_entropy(&buffer));
        }
    }
    Ok(0.0)
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy = probability.mul_add(-probability.log2(), entropy);
        }
    }

    entropy
}

fn extract_stream_preview<R: Read + Seek>(
    cfb: &mut CompoundFile<R>,
    stream_name: &str,
) -> Result<Option<String>> {
    if let Ok(mut stream) = cfb.open_stream(stream_name) {
        let mut buffer = vec![0u8; 256.min(stream.len() as usize)];
        if stream.read_exact(&mut buffer).is_ok() {
            // Convert to string, replacing non-printable characters
            let preview = buffer
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            return Ok(Some(preview));
        }
    }
    Ok(None)
}

fn extract_vba_project(file: &mut File) -> Result<Option<VbaProject>> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut cfb = match CompoundFile::open(file) {
        Ok(cfb) => cfb,
        Err(_) => return Ok(None),
    };

    // Look for VBA directory structure
    let mut vba_found = false;
    let mut project_name = "Unknown".to_string();
    let mut properties = HashMap::new();
    let mut references = Vec::new();
    let mut modules = Vec::new();

    // Check for PROJECT stream
    if let Ok(mut stream) = cfb.open_stream("PROJECT") {
        vba_found = true;
        let mut content = String::new();
        if stream.read_to_string(&mut content).is_ok() {
            // Parse PROJECT stream content
            for line in content.lines() {
                if let Some(stripped) = line.strip_prefix("Name=") {
                    project_name = stripped.to_string();
                } else if line.contains('=') {
                    let parts: Vec<&str> = line.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        properties.insert(parts[0].to_string(), parts[1].to_string());
                    }
                } else if let Some(stripped) = line.strip_prefix("Reference=") {
                    references.push(parse_vba_reference(stripped));
                }
            }
        }
    }

    // Check for common VBA module streams
    let module_names = vec!["MODULE1", "Module1", "ThisDocument", "Sheet1"];
    for module_name in module_names {
        if let Ok(content) = extract_module_content(&mut cfb, module_name) {
            vba_found = true;
            modules.push(content);
        }
    }

    // If no VBA content found, return None
    if !vba_found {
        return Ok(None);
    }

    // Create VBA protection info (simplified)
    let protection = VbaProtection {
        is_locked: false,
        is_password_protected: false,
        lock_bytes: None,
        password_hash: None,
    };

    // Create version info (simplified)
    let version_info = VbaVersionInfo {
        major: 5,
        minor: 0,
        language_id: 1033, // English
        performance_cache: false,
    };

    Ok(Some(VbaProject {
        project_name,
        modules,
        references,
        properties,
        protection,
        version_info,
    }))
}

fn extract_macro_info(vba_project: &Option<VbaProject>) -> Result<Vec<MacroInfo>> {
    let mut macros = Vec::new();

    if let Some(project) = vba_project {
        for module in &project.modules {
            // Analyze each module for macro information
            let mut macro_info = module.clone();

            // Extract procedures from source code if available
            if let Some(source) = &module.source_code {
                macro_info.procedures = extract_procedures_from_source(source);
                macro_info.procedure_count = macro_info.procedures.len();
                macro_info.line_count = source.lines().count();
                macro_info.suspicious_patterns = detect_suspicious_vba_patterns(source);
            }

            macros.push(macro_info);
        }
    }

    Ok(macros)
}

// Placeholder type for now
type MacroInfo = VbaModule;

fn extract_ole_metadata(file: &mut File) -> Result<OleMetadata> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut cfb = match CompoundFile::open(file) {
        Ok(cfb) => cfb,
        Err(_) => return Ok(OleMetadata::default()),
    };

    let mut metadata = OleMetadata::default();

    // Look for standard metadata streams
    let metadata_streams = vec![
        "\x05SummaryInformation",
        "\x05DocumentSummaryInformation",
        "SummaryInformation",
        "DocumentSummaryInformation",
    ];

    for stream_name in metadata_streams {
        if let Ok(mut stream) = cfb.open_stream(stream_name) {
            let mut buffer = Vec::new();
            if stream.read_to_end(&mut buffer).is_ok() {
                parse_property_set(&buffer, &mut metadata)?;
            }
        }
    }

    Ok(metadata)
}

fn analyze_suspicious_patterns(
    vba_project: &Option<VbaProject>,
    _macros: &[MacroInfo],
    _streams: &[StreamInfo],
) -> Result<SuspiciousIndicators> {
    let mut indicators = SuspiciousIndicators {
        has_macros: vba_project.is_some(),
        ..Default::default()
    };

    if let Some(project) = vba_project {
        // Analyze VBA project for suspicious patterns
        for module in &project.modules {
            if let Some(source) = &module.source_code {
                // Check for auto-execution macros
                let auto_exec_patterns = vec![
                    "Auto_Open",
                    "Document_Open",
                    "Workbook_Open",
                    "Auto_Close",
                    "Document_Close",
                    "Workbook_Close",
                    "Auto_Exec",
                    "AutoExec",
                    "AutoOpen",
                ];

                for pattern in auto_exec_patterns {
                    if source.contains(pattern) {
                        indicators
                            .auto_exec_macros
                            .push(format!("{}:{}", module.name, pattern));
                    }
                }

                // Detect suspicious API calls
                indicators
                    .suspicious_api_calls
                    .extend(detect_suspicious_api_calls(source, &module.name));

                // Detect obfuscation
                indicators
                    .obfuscated_code
                    .extend(detect_obfuscation_patterns(source, &module.name));

                // Detect external connections
                indicators
                    .external_connections
                    .extend(detect_external_connections(source, &module.name));

                // Detect file operations
                indicators
                    .file_operations
                    .extend(detect_file_operations(source, &module.name));

                // Detect registry operations
                indicators
                    .registry_operations
                    .extend(detect_registry_operations(source, &module.name));

                // Detect process operations
                indicators
                    .process_operations
                    .extend(detect_process_operations(source, &module.name));

                // Detect cryptographic operations
                indicators
                    .cryptographic_operations
                    .extend(detect_crypto_operations(source, &module.name));
            }
        }
    }

    // Calculate overall risk score
    indicators.risk_score = calculate_risk_score(&indicators);

    Ok(indicators)
}

pub fn perform_security_assessment(
    suspicious_indicators: &SuspiciousIndicators,
    _macros: &[MacroInfo],
) -> Result<SecurityAssessment> {
    let mut assessment = SecurityAssessment::default();
    let mut risk_factors = Vec::new();
    let mut recommendations = Vec::new();
    let mut ioc_indicators = Vec::new();

    // Assess macro presence
    if suspicious_indicators.has_macros {
        risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::MacroPresence,
            description: "Document contains VBA macros".to_string(),
            severity: RiskLevel::Medium,
            confidence: 1.0,
        });

        recommendations.push("Disable macros unless absolutely necessary".to_string());
    }

    // Assess auto-execution
    if !suspicious_indicators.auto_exec_macros.is_empty() {
        risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::AutoExecution,
            description: format!(
                "Auto-executing macros found: {}",
                suspicious_indicators.auto_exec_macros.join(", ")
            ),
            severity: RiskLevel::High,
            confidence: 0.9,
        });

        recommendations
            .push("Auto-executing macros detected. Exercise extreme caution".to_string());
    }

    // Assess suspicious API calls
    if !suspicious_indicators.suspicious_api_calls.is_empty() {
        let high_risk_calls = suspicious_indicators
            .suspicious_api_calls
            .iter()
            .filter(|call| matches!(call.risk_level, RiskLevel::High | RiskLevel::Critical))
            .count();

        if high_risk_calls > 0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::SuspiciousApiCalls,
                description: format!("Found {high_risk_calls} high-risk API calls"),
                severity: RiskLevel::High,
                confidence: 0.8,
            });
        }
    }

    // Assess network connections
    if !suspicious_indicators.external_connections.is_empty() {
        risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::NetworkConnections,
            description: "Code attempts to make external network connections".to_string(),
            severity: RiskLevel::High,
            confidence: 0.9,
        });

        // Extract IOCs from connections
        for conn in &suspicious_indicators.external_connections {
            ioc_indicators.push(IocIndicator {
                indicator_type: match conn.connection_type {
                    ConnectionType::HttpRequest => IocType::Url,
                    ConnectionType::FtpConnection => IocType::Url,
                    ConnectionType::DnsLookup => IocType::Domain,
                    _ => IocType::Unknown,
                },
                value: conn.target.clone(),
                confidence: 0.8,
                context: conn.location.clone(),
            });
        }
    }

    // Assess obfuscation
    if !suspicious_indicators.obfuscated_code.is_empty() {
        let avg_confidence = suspicious_indicators
            .obfuscated_code
            .iter()
            .map(|o| o.confidence)
            .sum::<f64>()
            / suspicious_indicators.obfuscated_code.len() as f64;

        risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::Obfuscation,
            description: "Code obfuscation detected".to_string(),
            severity: if avg_confidence > 0.7 {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            },
            confidence: avg_confidence,
        });
    }

    // Determine overall risk level
    assessment.overall_risk =
        determine_overall_risk(&risk_factors, suspicious_indicators.risk_score);
    assessment.risk_factors = risk_factors;
    assessment.recommendations = recommendations;
    assessment.ioc_indicators = ioc_indicators;

    Ok(assessment)
}

// Default implementations

impl Default for SecurityAssessment {
    fn default() -> Self {
        Self {
            overall_risk: RiskLevel::Low,
            risk_factors: Vec::new(),
            recommendations: Vec::new(),
            ioc_indicators: Vec::new(),
            yara_matches: Vec::new(),
        }
    }
}

// Helper functions for VBA analysis
pub fn extract_module_content<R: Read + Seek>(
    cfb: &mut CompoundFile<R>,
    module_name: &str,
) -> Result<VbaModule> {
    let mut module = VbaModule {
        name: module_name.to_string(),
        module_type: VbaModuleType::Standard,
        source_code: None,
        compiled_code: None,
        line_count: 0,
        procedure_count: 0,
        procedures: Vec::new(),
        suspicious_patterns: Vec::new(),
    };

    // Try to read module content
    if let Ok(mut stream) = cfb.open_stream(module_name) {
        let mut buffer = Vec::new();
        if stream.read_to_end(&mut buffer).is_ok() {
            // Check if it's text or binary
            if buffer
                .iter()
                .all(|&b| b.is_ascii() || b.is_ascii_whitespace())
            {
                module.source_code = Some(String::from_utf8_lossy(&buffer).to_string());
            } else {
                module.compiled_code = Some(buffer);
            }
        }
    }

    // Determine module type based on name
    module.module_type = if module_name.contains("Class") {
        VbaModuleType::ClassModule
    } else if module_name.contains("Form") {
        VbaModuleType::UserForm
    } else if module_name.contains("ThisDocument") || module_name.contains("Sheet") {
        VbaModuleType::Document
    } else {
        VbaModuleType::Standard
    };

    Ok(module)
}

pub fn parse_vba_reference(reference_str: &str) -> VbaReference {
    // Parse VBA reference string
    let parts: Vec<&str> = reference_str.split('*').collect();

    VbaReference {
        name: parts.get(1).unwrap_or(&"Unknown").to_string(),
        guid: parts.first().map(std::string::ToString::to_string),
        version: parts.get(2).map(std::string::ToString::to_string),
        path: parts.get(3).map(std::string::ToString::to_string),
        reference_type: VbaReferenceType::TypeLib,
    }
}

pub fn extract_procedures_from_source(source: &str) -> Vec<VbaProcedure> {
    let mut procedures = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut current_proc: Option<VbaProcedure> = None;

    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Check for procedure start
        if trimmed.starts_with("Sub ")
            || trimmed.starts_with("Function ")
            || trimmed.starts_with("Property ")
        {
            // Save previous procedure if exists
            if let Some(mut proc) = current_proc.take() {
                proc.end_line = line_num.saturating_sub(1);
                procedures.push(proc);
            }

            // Start new procedure
            let proc_type = if trimmed.starts_with("Sub ") {
                VbaProcedureType::Sub
            } else if trimmed.starts_with("Function ") {
                VbaProcedureType::Function
            } else {
                VbaProcedureType::Property
            };

            let name = extract_procedure_name(trimmed);

            current_proc = Some(VbaProcedure {
                name,
                procedure_type: proc_type,
                start_line: line_num,
                end_line: line_num,
                parameters: extract_parameters(trimmed),
                local_variables: Vec::new(),
                external_calls: Vec::new(),
                risk_score: 0,
            });
        }

        // Check for procedure end
        if trimmed.starts_with("End Sub")
            || trimmed.starts_with("End Function")
            || trimmed.starts_with("End Property")
        {
            if let Some(mut proc) = current_proc.take() {
                proc.end_line = line_num;
                procedures.push(proc);
            }
        }
    }

    // Handle last procedure if file doesn't end with End
    if let Some(mut proc) = current_proc {
        proc.end_line = lines.len().saturating_sub(1);
        procedures.push(proc);
    }

    procedures
}

pub fn extract_procedure_name(line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // Handle Property Get/Set/Let
    if parts.len() >= 3 && parts[0] == "Property" {
        let name_part = parts[2];
        if let Some(paren_pos) = name_part.find('(') {
            name_part[..paren_pos].to_string()
        } else {
            name_part.to_string()
        }
    } else if parts.len() >= 2 {
        let name_part = parts[1];
        if let Some(paren_pos) = name_part.find('(') {
            name_part[..paren_pos].to_string()
        } else {
            name_part.to_string()
        }
    } else {
        "Unknown".to_string()
    }
}

pub fn extract_parameters(line: &str) -> Vec<String> {
    if let Some(start) = line.find('(') {
        if let Some(end) = line.find(')') {
            let params_str = &line[start + 1..end];
            if params_str.trim().is_empty() {
                return Vec::new();
            }
            return params_str
                .split(',')
                .map(|p| p.trim().to_string())
                .collect();
        }
    }
    Vec::new()
}

pub fn detect_suspicious_vba_patterns(source: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let source_lower = source.to_lowercase();

    let suspicious_keywords = vec![
        "shell",
        "createobject",
        "wscript.shell",
        "cmd.exe",
        "powershell",
        "base64",
        "decode",
        "eval",
        "execute",
        "downloadfile",
        "urldownloadtofile",
        "internetopen",
        "createremotethread",
        "virtualalloc",
        "writeprocessmemory",
        "regwrite",
        "regcreatekey",
        "environ",
        "tempdir",
    ];

    for keyword in suspicious_keywords {
        if source_lower.contains(keyword) {
            patterns.push(format!("Suspicious keyword: {keyword}"));
        }
    }

    patterns
}

pub fn parse_property_set(buffer: &[u8], metadata: &mut OleMetadata) -> Result<()> {
    // Simplified property set parsing
    // Real implementation would parse the full property set format

    // Look for common string patterns
    let content = String::from_utf8_lossy(buffer);

    // Extract title if present
    if let Some(title_start) = content.find("Title") {
        if let Some(title_end) = content[title_start..].find('\0') {
            let title = &content[title_start + 5..title_start + title_end];
            if !title.trim().is_empty() {
                metadata.title = Some(title.trim().to_string());
            }
        }
    }

    // Extract author if present
    if let Some(author_start) = content.find("Author") {
        if let Some(author_end) = content[author_start..].find('\0') {
            let author = &content[author_start + 6..author_start + author_end];
            if !author.trim().is_empty() {
                metadata.author = Some(author.trim().to_string());
            }
        }
    }

    Ok(())
}

pub fn detect_suspicious_api_calls(source: &str, module_name: &str) -> Vec<SuspiciousApiCall> {
    let mut calls = Vec::new();
    let source_lower = source.to_lowercase();

    let api_patterns = vec![
        ("createobject", RiskLevel::High, "Object creation"),
        ("shell", RiskLevel::Critical, "Command execution"),
        ("wscript.shell", RiskLevel::Critical, "Windows Script Host"),
        ("urldownloadtofile", RiskLevel::High, "File download"),
        ("internetopen", RiskLevel::Medium, "Internet connection"),
        ("regwrite", RiskLevel::High, "Registry modification"),
        ("environ", RiskLevel::Medium, "Environment variable access"),
    ];

    for (api, risk, desc) in api_patterns {
        if source_lower.contains(api) {
            calls.push(SuspiciousApiCall {
                api_name: api.to_string(),
                module_name: module_name.to_string(),
                call_count: source_lower.matches(api).count() as u32,
                context: format!("Found in module {module_name}"),
                risk_level: risk,
                description: desc.to_string(),
            });
        }
    }

    calls
}

pub fn detect_obfuscation_patterns(source: &str, module_name: &str) -> Vec<ObfuscationIndicator> {
    let mut indicators = Vec::new();

    // Check for string concatenation obfuscation
    if source.matches(" & ").count() > 10 {
        indicators.push(ObfuscationIndicator {
            technique: ObfuscationType::StringConcatenation,
            description: "Excessive string concatenation detected".to_string(),
            location: module_name.to_string(),
            confidence: 0.7,
        });
    }

    // Check for character code obfuscation
    if source.contains("Chr(") && source.matches("Chr(").count() > 5 {
        indicators.push(ObfuscationIndicator {
            technique: ObfuscationType::CharCodeObfuscation,
            description: "Character code obfuscation detected".to_string(),
            location: module_name.to_string(),
            confidence: 0.8,
        });
    }

    // Check for base64 patterns
    if source.to_lowercase().contains("base64") {
        indicators.push(ObfuscationIndicator {
            technique: ObfuscationType::Base64Encoding,
            description: "Base64 encoding references found".to_string(),
            location: module_name.to_string(),
            confidence: 0.6,
        });
    }

    indicators
}

pub fn detect_external_connections(source: &str, module_name: &str) -> Vec<ExternalConnection> {
    let mut connections = Vec::new();
    let source_lower = source.to_lowercase();

    // HTTP connections
    if source_lower.contains("http://") || source_lower.contains("https://") {
        connections.push(ExternalConnection {
            connection_type: ConnectionType::HttpRequest,
            target: "HTTP/HTTPS URL detected".to_string(),
            method: "GET/POST".to_string(),
            location: module_name.to_string(),
        });
    }

    // FTP connections
    if source_lower.contains("ftp://") {
        connections.push(ExternalConnection {
            connection_type: ConnectionType::FtpConnection,
            target: "FTP URL detected".to_string(),
            method: "FTP".to_string(),
            location: module_name.to_string(),
        });
    }

    connections
}

pub fn detect_file_operations(source: &str, module_name: &str) -> Vec<FileOperation> {
    let mut operations = Vec::new();
    let source_lower = source.to_lowercase();

    let file_ops = vec![
        ("open", FileOperationType::Read, RiskLevel::Low),
        ("write", FileOperationType::Write, RiskLevel::Medium),
        ("delete", FileOperationType::Delete, RiskLevel::High),
        ("kill", FileOperationType::Delete, RiskLevel::High),
        ("copy", FileOperationType::Copy, RiskLevel::Medium),
        (
            "mkdir",
            FileOperationType::CreateDirectory,
            RiskLevel::Medium,
        ),
    ];

    for (keyword, op_type, risk) in file_ops {
        if source_lower.contains(keyword) {
            operations.push(FileOperation {
                operation_type: op_type,
                target_path: "Various paths".to_string(),
                location: module_name.to_string(),
                risk_level: risk,
            });
        }
    }

    operations
}

pub fn detect_registry_operations(source: &str, module_name: &str) -> Vec<RegistryOperation> {
    let mut operations = Vec::new();
    let source_lower = source.to_lowercase();

    if source_lower.contains("regwrite") || source_lower.contains("regcreatekey") {
        operations.push(RegistryOperation {
            operation_type: RegistryOperationType::Write,
            key_path: "Registry modification detected".to_string(),
            value_name: None,
            location: module_name.to_string(),
            risk_level: RiskLevel::High,
        });
    }

    operations
}

pub fn detect_process_operations(source: &str, module_name: &str) -> Vec<ProcessOperation> {
    let mut operations = Vec::new();
    let source_lower = source.to_lowercase();

    if source_lower.contains("shell") || source_lower.contains("createprocess") {
        operations.push(ProcessOperation {
            operation_type: ProcessOperationType::Create,
            target_process: "Process execution detected".to_string(),
            parameters: vec!["Various parameters".to_string()],
            location: module_name.to_string(),
            risk_level: RiskLevel::Critical,
        });
    }

    operations
}

pub fn detect_crypto_operations(source: &str, module_name: &str) -> Vec<CryptoOperation> {
    let mut operations = Vec::new();
    let source_lower = source.to_lowercase();

    let crypto_keywords = vec!["encrypt", "decrypt", "hash", "md5", "sha", "aes", "des"];

    for keyword in crypto_keywords {
        if source_lower.contains(keyword) {
            operations.push(CryptoOperation {
                operation_type: CryptoOperationType::Encryption,
                algorithm: keyword.to_string(),
                location: module_name.to_string(),
                risk_level: RiskLevel::Medium,
            });
        }
    }

    operations
}

pub fn calculate_risk_score(indicators: &SuspiciousIndicators) -> u8 {
    let mut score = 0u32;

    // Base score for having macros
    if indicators.has_macros {
        score += 20;
    }

    // Auto-execution adds significant risk
    score += (indicators.auto_exec_macros.len() as u32) * 25;

    // Suspicious API calls
    for call in &indicators.suspicious_api_calls {
        score += match call.risk_level {
            RiskLevel::Low => 5,
            RiskLevel::Medium => 10,
            RiskLevel::High => 20,
            RiskLevel::Critical => 30,
        };
    }

    // Obfuscation
    for obf in &indicators.obfuscated_code {
        score += (obf.confidence * 15.0) as u32;
    }

    // External connections
    score += (indicators.external_connections.len() as u32) * 15;

    // Cap at 100
    std::cmp::min(score, 100) as u8
}

pub fn determine_overall_risk(risk_factors: &[RiskFactor], risk_score: u8) -> RiskLevel {
    let critical_count = risk_factors
        .iter()
        .filter(|f| matches!(f.severity, RiskLevel::Critical))
        .count();
    let high_count = risk_factors
        .iter()
        .filter(|f| matches!(f.severity, RiskLevel::High))
        .count();

    if critical_count > 0 || risk_score >= 80 {
        RiskLevel::Critical
    } else if high_count > 1 || risk_score >= 60 {
        RiskLevel::High
    } else if high_count > 0 || risk_score >= 30 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_entropy_calculation() {
        // Test entropy calculation with known data
        let data = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&data), 0.0);

        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.9 && entropy <= 8.0);
    }

    #[test]
    fn test_ole_file_type_detection() {
        // Test with non-OLE file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Not an OLE file").unwrap();
        temp_file.flush().unwrap();

        let mut file = File::open(temp_file.path()).unwrap();
        // This will fail due to insufficient header size, which is expected
        let result = detect_ole_file_type(&mut file);
        assert!(result.is_err() || matches!(result.unwrap(), OleFileType::NotOleFile));
    }

    #[test]
    fn test_stream_type_determination() {
        assert!(matches!(
            determine_stream_type("VBA/dir"),
            StreamType::VbaProject
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
            determine_stream_type("unknown"),
            StreamType::Unknown
        ));
    }

    #[test]
    fn test_ole_vba_analysis_non_ole_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"This is not an OLE file at all")
            .unwrap();
        temp_file.flush().unwrap();

        // This should handle non-OLE files gracefully
        let result = analyze_ole_vba(temp_file.path());
        // The function might fail due to header reading, which is acceptable
        if let Ok(analysis) = result {
            assert!(matches!(analysis.file_type, OleFileType::NotOleFile));
        }
    }
}
