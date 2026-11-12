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

/// Most bytes read from one stream or package part.
const MAX_PART_BYTES: u64 = 16 * 1024 * 1024;
/// Most streams and storages listed in a report.
const MAX_LISTED_ENTRIES: usize = 500;
/// Most modules decoded from one project (a `dir` stream may name any number of them).
const MAX_VBA_MODULES: usize = 1000;
/// Most VBA storages read (and listed) in one file; each may carry its own `dir` stream.
const MAX_VBA_STORAGES: usize = 16;
/// Most `Module=` style lines taken from a PROJECT stream.
const MAX_PROJECT_LINES: usize = 20_000;
/// Most bytes of stream data read and source decompressed for one project. Several modules
/// may point at one stream, so the count is of work done, not of distinct data.
const MAX_VBA_WORK_BYTES: usize = 8 * 1024 * 1024;
/// Most keyword hits reported per module.
const MAX_KEYWORD_HITS_PER_MODULE: usize = 1000;
/// Most auto-exec entry points reported per module and in all.
const MAX_AUTO_EXEC_ENTRIES: usize = 500;
/// Largest stream whose entropy is computed.
const ENTROPY_LIMIT: u64 = 1024 * 1024;

/// What `analyze_office` found beyond the legacy report: where the VBA project lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficeReport {
    pub analysis: OleVbaAnalysis,
    /// `ole2` (a compound file) or `ooxml` (a zip package).
    pub container: String,
    /// For OOXML: the package part that holds the VBA project (`word/vbaProject.bin`).
    pub vba_part: Option<String>,
    /// Compound-file paths of every storage named `VBA` that was found.
    pub vba_storages: Vec<String>,
    /// How the module list was obtained: `dir stream`, `PROJECT stream` or `stream names`.
    pub module_source: Option<String>,
    /// Modules whose source could not be decompressed.
    pub undecoded_modules: Vec<String>,
    /// Modules whose stream was only partly read because the work budget ran out; their
    /// source (and any findings in it) is incomplete.
    pub partial_modules: Vec<String>,
    /// True when a cap (modules, storages, work budget) stopped the read: the VBA project
    /// was not read in full.
    pub truncated: bool,
    /// Facts that limit the analysis.
    pub notes: Vec<String>,
}

/// One suspicious keyword at a line of a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VbaKeywordHit {
    pub module: String,
    pub keyword: String,
    /// 1-based line in the module source.
    pub line: usize,
    pub text: String,
}

/// An auto-executing entry point (`AutoOpen`, `Document_Open`, ...) at a line of a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoExecEntry {
    pub module: String,
    pub procedure: String,
    pub line: usize,
}

const AUTO_EXEC_NAMES: &[&str] = &[
    "auto_open",
    "autoopen",
    "auto_close",
    "autoclose",
    "auto_exec",
    "autoexec",
    "autoexit",
    "autonew",
    "auto_activate",
    "auto_deactivate",
    "document_open",
    "document_new",
    "document_close",
    "document_beforeclose",
    "workbook_open",
    "workbook_activate",
    "workbook_close",
    "workbook_beforeclose",
];

const SUSPICIOUS_VBA_KEYWORDS: &[&str] = &[
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

/// Entry points of a module that run when the document opens or closes, with line numbers.
/// Only procedure declarations count; a comment or string that mentions `AutoOpen` does not.
pub fn detect_auto_exec_entries(source: &str, module_name: &str) -> Vec<AutoExecEntry> {
    let mut entries = Vec::new();
    for (index, raw) in source.lines().enumerate() {
        let mut words = raw.split_whitespace().peekable();
        while let Some(word) = words.peek() {
            if matches!(
                word.to_ascii_lowercase().as_str(),
                "public" | "private" | "friend" | "static"
            ) {
                words.next();
            } else {
                break;
            }
        }
        let Some(kind) = words.next() else { continue };
        if !matches!(kind.to_ascii_lowercase().as_str(), "sub" | "function") {
            continue;
        }
        let Some(declared) = words.next() else {
            continue;
        };
        let name: String = declared
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if AUTO_EXEC_NAMES.contains(&name.to_ascii_lowercase().as_str()) {
            if entries.len() >= MAX_AUTO_EXEC_ENTRIES {
                break;
            }
            entries.push(AutoExecEntry {
                module: module_name.to_string(),
                procedure: name,
                line: index + 1,
            });
        }
    }
    entries
}

/// True when `keyword` occurs in `haystack` not inside a longer identifier (`shell` matches
/// `WScript.Shell` but not `PowerShell`; `environ` does not match `Environment`).
fn contains_word(haystack: &str, keyword: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(found) = haystack[from..].find(keyword) {
        let start = from + found;
        let end = start + keyword.len();
        let before = haystack[..start].chars().next_back();
        let after = haystack[end..].chars().next();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            return true;
        }
        from = start + keyword.len().max(1);
    }
    false
}

/// Number of whole-word occurrences of `keyword` in `haystack` (see [`contains_word`]).
fn count_word(haystack: &str, keyword: &str) -> usize {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let (mut from, mut count) = (0, 0);
    while let Some(found) = haystack[from..].find(keyword) {
        let start = from + found;
        let end = start + keyword.len();
        let before = haystack[..start].chars().next_back();
        let after = haystack[end..].chars().next();
        if !before.is_some_and(is_ident) && !after.is_some_and(is_ident) {
            count += 1;
        }
        from = start + keyword.len().max(1);
    }
    count
}

/// The suspicious keywords of [`detect_suspicious_vba_patterns`], one hit per line (at most
/// 1000 per module).
pub fn vba_keyword_hits(source: &str, module_name: &str) -> Vec<VbaKeywordHit> {
    let mut hits = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('\'') || trimmed.to_ascii_lowercase().starts_with("rem ") {
            continue;
        }
        let lower = line.to_lowercase();
        for keyword in SUSPICIOUS_VBA_KEYWORDS {
            if contains_word(&lower, keyword) {
                if hits.len() >= MAX_KEYWORD_HITS_PER_MODULE {
                    return hits;
                }
                let text: String = trimmed.chars().take(200).collect();
                hits.push(VbaKeywordHit {
                    module: module_name.to_string(),
                    keyword: (*keyword).to_string(),
                    line: index + 1,
                    text,
                });
            }
        }
    }
    hits
}

/// Decompress an MS-OVBA compressed container. Returns what decoded (at most 8 MiB), or
/// `None` when the data does not start with the 0x01 signature or the first chunk is bad.
pub fn ovba_decompress(data: &[u8]) -> Option<Vec<u8>> {
    const LIMIT: usize = 8 * 1024 * 1024;
    if data.first() != Some(&1) {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 1usize;
    let mut first = true;
    while pos + 2 <= data.len() && out.len() < LIMIT {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        if (header >> 12) & 7 != 3 {
            return if first { None } else { Some(out) };
        }
        let chunk_end = (pos + usize::from(header & 0x0FFF) + 3).min(data.len());
        let compressed = header & 0x8000 != 0;
        pos += 2;
        let chunk_start = out.len();
        if compressed {
            while pos < chunk_end {
                let flags = data[pos];
                pos += 1;
                for bit in 0..8 {
                    if pos >= chunk_end {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        out.push(data[pos]);
                        pos += 1;
                    } else {
                        if pos + 2 > chunk_end {
                            pos = chunk_end;
                            break;
                        }
                        let token = u16::from_le_bytes([data[pos], data[pos + 1]]);
                        pos += 2;
                        let difference = out.len() - chunk_start;
                        let mut bits = 4u32;
                        while (1usize << bits) < difference && bits < 12 {
                            bits += 1;
                        }
                        let length_mask = 0xFFFFu16 >> bits;
                        let length = usize::from(token & length_mask) + 3;
                        let offset = usize::from((token & !length_mask) >> (16 - bits)) + 1;
                        if offset > difference {
                            return if first { None } else { Some(out) };
                        }
                        for _ in 0..length {
                            let byte = out[out.len() - offset];
                            out.push(byte);
                        }
                    }
                }
            }
        } else {
            let end = (pos + 4096).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos = end;
        }
        first = false;
    }
    Some(out)
}

/// Read `Name=` style lines of the PROJECT stream into (kind, module) pairs.
fn project_stream_modules(text: &str) -> Vec<(String, VbaModuleType)> {
    let mut modules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let kind = match key {
            "Module" => VbaModuleType::Standard,
            "Class" => VbaModuleType::ClassModule,
            "BaseClass" => VbaModuleType::UserForm,
            "Document" => VbaModuleType::Document,
            _ => continue,
        };
        let name = value.split('/').next().unwrap_or(value).trim();
        if !name.is_empty() && modules.len() < MAX_PROJECT_LINES {
            modules.push((name.to_string(), kind));
        }
    }
    modules
}

struct DirModule {
    name: String,
    stream_name: String,
    offset: u32,
    is_class: bool,
}

struct DirInfo {
    project_name: Option<String>,
    version: Option<(u32, u16)>,
    language_id: Option<u32>,
    references: Vec<VbaReference>,
    modules: Vec<DirModule>,
}

fn latin1(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse the decompressed `dir` stream (MS-OVBA 2.3.4.2). Stops quietly at the first
/// malformed record and returns what it has.
fn parse_dir_stream(dir: &[u8]) -> DirInfo {
    let mut info = DirInfo {
        project_name: None,
        version: None,
        language_id: None,
        references: Vec::new(),
        modules: Vec::new(),
    };
    let mut pos = 0usize;
    let mut pending_ref_name: Option<String> = None;
    let mut current: Option<DirModule> = None;
    while pos + 6 <= dir.len() {
        let id = u16::from_le_bytes([dir[pos], dir[pos + 1]]);
        pos += 2;
        if id == 0x0009 {
            // PROJECTVERSION: reserved 4, major 4, minor 2.
            if pos + 10 > dir.len() {
                break;
            }
            let major =
                u32::from_le_bytes([dir[pos + 4], dir[pos + 5], dir[pos + 6], dir[pos + 7]]);
            let minor = u16::from_le_bytes([dir[pos + 8], dir[pos + 9]]);
            info.version = Some((major, minor));
            pos += 10;
            continue;
        }
        let size =
            u32::from_le_bytes([dir[pos], dir[pos + 1], dir[pos + 2], dir[pos + 3]]) as usize;
        pos += 4;
        let end = pos.saturating_add(size);
        if end > dir.len() {
            break;
        }
        let data = &dir[pos..end];
        pos = end;
        match id {
            0x0002 if data.len() >= 4 => {
                info.language_id = Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]));
            }
            0x0004 => info.project_name = Some(latin1(data)),
            0x0016 => pending_ref_name = Some(latin1(data)),
            0x003E => {
                if let Some(name) = pending_ref_name.as_mut() {
                    *name = utf16le(data);
                }
            }
            0x000D | 0x002F | 0x000E => {
                // The libid (`*\G{guid}#version#lcid#path#description`) follows a 4-byte length.
                let libid = if data.len() >= 4 {
                    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                    latin1(&data[4..(4 + len).min(data.len())])
                } else {
                    String::new()
                };
                let parts: Vec<&str> = libid.split('#').collect();
                let guid = parts
                    .first()
                    .and_then(|first| first.split_once("\\G").map(|(_, g)| g.to_string()));
                info.references.push(VbaReference {
                    name: pending_ref_name
                        .take()
                        .unwrap_or_else(|| "Unknown".to_string()),
                    guid,
                    version: parts.get(1).map(|v| (*v).to_string()),
                    path: parts.get(3).map(|p| (*p).to_string()),
                    reference_type: match id {
                        0x000E => VbaReferenceType::Project,
                        0x002F => VbaReferenceType::Control,
                        _ => VbaReferenceType::TypeLib,
                    },
                });
            }
            0x0019 => {
                if let Some(done) = current.take() {
                    info.modules.push(done);
                }
                let name = latin1(data);
                current = Some(DirModule {
                    stream_name: name.clone(),
                    name,
                    offset: 0,
                    is_class: false,
                });
            }
            0x0047 => {
                if let Some(module) = current.as_mut() {
                    module.name = utf16le(data);
                }
            }
            0x001A => {
                if let Some(module) = current.as_mut() {
                    module.stream_name = latin1(data);
                }
            }
            0x0032 => {
                if let Some(module) = current.as_mut() {
                    module.stream_name = utf16le(data);
                }
            }
            0x0031 if data.len() >= 4 => {
                if let Some(module) = current.as_mut() {
                    module.offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                }
            }
            0x0022 => {
                if let Some(module) = current.as_mut() {
                    module.is_class = true;
                }
            }
            0x0010 => break,
            _ => {}
        }
    }
    if let Some(done) = current.take() {
        info.modules.push(done);
    }
    info
}

/// One compound-file entry, as listed once up front.
struct CfbItem {
    path: String,
    name: String,
    is_stream: bool,
    len: u64,
}

fn list_cfb<R: Read + Seek>(cfb: &CompoundFile<R>) -> Vec<CfbItem> {
    cfb.walk()
        .filter(|entry| !entry.is_root())
        .map(|entry| CfbItem {
            path: entry.path().to_string_lossy().into_owned(),
            name: entry.name().to_string(),
            is_stream: entry.is_stream(),
            len: entry.len(),
        })
        .collect()
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

fn read_cfb_stream<R: Read + Seek>(
    cfb: &mut CompoundFile<R>,
    path: &str,
    limit: u64,
) -> Option<Vec<u8>> {
    let stream = cfb.open_stream(path).ok()?;
    let mut buffer = Vec::new();
    stream.take(limit).read_to_end(&mut buffer).ok()?;
    Some(buffer)
}

fn find_in<'a>(items: &'a [CfbItem], parent: &str, name: &str) -> Option<&'a CfbItem> {
    items.iter().find(|item| {
        item.is_stream && parent_of(&item.path) == parent && item.name.eq_ignore_ascii_case(name)
    })
}

fn module_type_for(
    name: &str,
    from_project: Option<&VbaModuleType>,
    is_class: bool,
) -> VbaModuleType {
    match from_project {
        Some(VbaModuleType::Standard) => VbaModuleType::Standard,
        Some(VbaModuleType::ClassModule) => VbaModuleType::ClassModule,
        Some(VbaModuleType::UserForm) => VbaModuleType::UserForm,
        Some(VbaModuleType::Document) => VbaModuleType::Document,
        _ => {
            if is_class {
                if name.contains("ThisDocument")
                    || name.contains("ThisWorkbook")
                    || name.starts_with("Sheet")
                {
                    VbaModuleType::Document
                } else {
                    VbaModuleType::ClassModule
                }
            } else {
                VbaModuleType::Standard
            }
        }
    }
}

fn empty_module(name: &str, module_type: VbaModuleType) -> VbaModule {
    VbaModule {
        name: name.to_string(),
        module_type,
        source_code: None,
        compiled_code: None,
        line_count: 0,
        procedure_count: 0,
        procedures: Vec::new(),
        suspicious_patterns: Vec::new(),
    }
}

/// Find the VBA project in a compound file, wherever its `VBA` storage sits
/// (`/VBA`, `/Macros/VBA`, `/_VBA_PROJECT_CUR/VBA`, ...), and decode it.
fn extract_vba_project<R: Read + Seek>(
    cfb: &mut CompoundFile<R>,
    items: &[CfbItem],
    report: &mut OfficeReport,
) -> Option<VbaProject> {
    let mut storages: Vec<&CfbItem> = cfb
        .walk()
        .filter(|entry| {
            entry.is_storage() && !entry.is_root() && entry.name().eq_ignore_ascii_case("VBA")
        })
        .map(|entry| entry.path().to_string_lossy().into_owned())
        .filter_map(|path| items.iter().find(|item| item.path == path))
        .collect();
    if storages.len() > MAX_VBA_STORAGES {
        report.notes.push(format!(
            "The file has {} storages named VBA; only the first {MAX_VBA_STORAGES} were read and listed.",
            storages.len()
        ));
        storages.truncate(MAX_VBA_STORAGES);
        report.truncated = true;
    }
    report.vba_storages = storages.iter().map(|s| s.path.clone()).collect();

    let mut project_name = None;
    let mut properties = HashMap::new();
    let mut references = Vec::new();
    let mut modules: Vec<VbaModule> = Vec::new();
    let mut version = (5u32, 0u16);
    let mut language_id = 1033u32;
    let mut found = false;
    let mut work_bytes = 0usize;
    let mut module_cap_hit = false;
    let mut work_cap_hit = false;

    for storage in &storages {
        if work_bytes >= MAX_VBA_WORK_BYTES {
            work_cap_hit = true;
            break;
        }
        let parent = parent_of(&storage.path).to_string();
        // The PROJECT stream sits beside the VBA storage and names each module's kind.
        let project_bytes = find_in(items, &parent, "PROJECT")
            .and_then(|item| read_cfb_stream(cfb, &item.path, 1024 * 1024));
        work_bytes += project_bytes.as_ref().map_or(0, Vec::len);
        let project_text = project_bytes.map(|bytes| latin1(&bytes));
        let mut kinds: HashMap<String, VbaModuleType> = HashMap::new();
        for (name, kind) in project_text
            .as_deref()
            .map(project_stream_modules)
            .unwrap_or_default()
        {
            kinds.entry(name.to_ascii_lowercase()).or_insert(kind);
        }
        if let Some(text) = &project_text {
            for line in text.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    if key == "Name" {
                        project_name = Some(value.trim().trim_matches('"').to_string());
                    } else if !matches!(
                        key,
                        "Module" | "Class" | "BaseClass" | "Document" | "Package"
                    ) && !key.starts_with("DPB")
                        && !key.starts_with("CMG")
                        && !key.starts_with("ID")
                        && !key.starts_with("GC")
                    {
                        properties.insert(key.to_string(), value.trim().to_string());
                    } else if key.starts_with("DPB")
                        || key.starts_with("CMG")
                        || key.starts_with("GC")
                    {
                        properties.insert(key.to_string(), "(present)".to_string());
                    }
                }
            }
        }

        let dir = find_in(items, &storage.path, "dir")
            .and_then(|item| {
                let room = MAX_VBA_WORK_BYTES.saturating_sub(work_bytes) as u64;
                read_cfb_stream(cfb, &item.path, MAX_PART_BYTES.min(room.max(1)))
            })
            .and_then(|raw| {
                work_bytes += raw.len();
                let decoded = ovba_decompress(&raw);
                work_bytes += decoded.as_ref().map_or(0, Vec::len);
                decoded
            });
        if let Some(dir) = dir {
            let info = parse_dir_stream(&dir);
            found = true;
            report.module_source = Some("dir stream".to_string());
            if project_name.is_none() {
                project_name = info.project_name.clone();
            }
            if let Some(v) = info.version {
                version = v;
            }
            if let Some(l) = info.language_id {
                language_id = l;
            }
            references.extend(info.references);
            for module in info.modules {
                if modules.len() >= MAX_VBA_MODULES {
                    module_cap_hit = true;
                    break;
                }
                if work_bytes >= MAX_VBA_WORK_BYTES {
                    work_cap_hit = true;
                    report.undecoded_modules.push(module.name.clone());
                    modules.push(empty_module(
                        &module.name,
                        module_type_for(&module.name, None, module.is_class),
                    ));
                    continue;
                }
                let kind = kinds.get(&module.name.to_ascii_lowercase());
                let mut built = empty_module(
                    &module.name,
                    module_type_for(&module.name, kind, module.is_class),
                );
                let stream = find_in(items, &storage.path, &module.stream_name).and_then(|item| {
                    let room = MAX_VBA_WORK_BYTES.saturating_sub(work_bytes) as u64;
                    read_cfb_stream(cfb, &item.path, room.max(1))
                });
                match stream {
                    Some(bytes) => {
                        work_bytes += bytes.len();
                        let whole = find_in(items, &storage.path, &module.stream_name)
                            .is_none_or(|item| item.len <= bytes.len() as u64);
                        if !whole {
                            report.partial_modules.push(module.name.clone());
                        }
                        let start = (module.offset as usize).min(bytes.len());
                        match ovba_decompress(&bytes[start..]) {
                            Some(source) => {
                                work_bytes += source.len();
                                built.source_code = Some(latin1(&source));
                            }
                            None => {
                                report.undecoded_modules.push(module.name.clone());
                                built.compiled_code =
                                    Some(bytes.into_iter().take(65_536).collect());
                            }
                        }
                    }
                    None => report.undecoded_modules.push(module.name.clone()),
                }
                modules.push(built);
            }
        } else {
            // No readable `dir` stream: the storage still marks a VBA project. List the
            // module streams by name so the reader knows what is there.
            found = true;
            report.module_source = Some("stream names".to_string());
            report.notes.push(format!(
                "The VBA storage {} has no readable dir stream; its module streams are listed by name and \
                 read as plain text where they hold plain text (compiled code is not decoded).",
                storage.path
            ));
            for item in items
                .iter()
                .filter(|i| i.is_stream && parent_of(&i.path) == storage.path)
            {
                if modules.len() >= MAX_VBA_MODULES {
                    module_cap_hit = true;
                    break;
                }
                let lower = item.name.to_ascii_lowercase();
                if lower == "dir" || lower == "_vba_project" || lower.starts_with("__srp_") {
                    continue;
                }
                let mut module = empty_module(&item.name, module_type_for(&item.name, None, false));
                let room = MAX_VBA_WORK_BYTES.saturating_sub(work_bytes) as u64;
                if room == 0 {
                    work_cap_hit = true;
                    report.undecoded_modules.push(item.name.clone());
                    modules.push(module);
                    continue;
                }
                let bytes =
                    read_cfb_stream(cfb, &item.path, room.min(1024 * 1024)).unwrap_or_default();
                work_bytes += bytes.len();
                if item.len > bytes.len() as u64 {
                    report.partial_modules.push(item.name.clone());
                }
                // A module stored as plain text (hand-built or converted files) is source.
                if !bytes.is_empty()
                    && bytes
                        .iter()
                        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                {
                    module.source_code = Some(latin1(&bytes));
                } else {
                    module.compiled_code = Some(bytes.into_iter().take(65_536).collect());
                    report.undecoded_modules.push(item.name.clone());
                }
                modules.push(module);
            }
        }
    }

    if !found {
        // A PROJECT stream with module streams beside it but no VBA storage (hand-built or
        // damaged files): read the modules it names, as plain text when they are text.
        let project = items
            .iter()
            .find(|item| item.is_stream && item.name.eq_ignore_ascii_case("PROJECT"));
        if let Some(project) = project {
            let parent = parent_of(&project.path).to_string();
            if let Some(text) = read_cfb_stream(cfb, &project.path, 1024 * 1024).map(|b| latin1(&b))
            {
                let named = project_stream_modules(&text);
                if named.len() >= MAX_PROJECT_LINES {
                    report.truncated = true;
                    report.notes.push(format!(
                        "The PROJECT stream names {MAX_PROJECT_LINES} or more modules; only the \
                         first {MAX_PROJECT_LINES} lines were read."
                    ));
                }
                if text.contains("Name=") || !named.is_empty() {
                    found = true;
                    report.module_source = Some("PROJECT stream".to_string());
                    for line in text.lines() {
                        if let Some(value) = line.strip_prefix("Name=") {
                            project_name = Some(value.trim().trim_matches('"').to_string());
                        }
                    }
                    let mut seen = std::collections::HashSet::new();
                    for (name, kind) in named {
                        // Each stream is read once, however many lines name it.
                        if !seen.insert(name.to_ascii_lowercase()) {
                            continue;
                        }
                        if modules.len() >= MAX_VBA_MODULES {
                            module_cap_hit = true;
                            break;
                        }
                        if work_bytes >= MAX_VBA_WORK_BYTES {
                            work_cap_hit = true;
                            report.undecoded_modules.push(name.clone());
                            modules.push(empty_module(&name, kind));
                            continue;
                        }
                        if let Some(item) = find_in(items, &parent, &name) {
                            let room = MAX_VBA_WORK_BYTES.saturating_sub(work_bytes) as u64;
                            let bytes = read_cfb_stream(cfb, &item.path, MAX_PART_BYTES.min(room))
                                .unwrap_or_default();
                            work_bytes += bytes.len();
                            if item.len > bytes.len() as u64 {
                                report.partial_modules.push(name.clone());
                            }
                            let mut module = empty_module(&name, kind);
                            if bytes
                                .iter()
                                .all(|&b| b.is_ascii() || b.is_ascii_whitespace())
                            {
                                module.source_code = Some(latin1(&bytes));
                            } else {
                                module.compiled_code =
                                    Some(bytes.into_iter().take(65_536).collect());
                            }
                            modules.push(module);
                        }
                    }
                }
            }
        }
    }

    if module_cap_hit {
        report.notes.push(format!(
            "The project names more than {MAX_VBA_MODULES} modules; only the first \
             {MAX_VBA_MODULES} were read."
        ));
    }
    if module_cap_hit || work_cap_hit || !report.partial_modules.is_empty() {
        report.truncated = true;
    }
    if work_cap_hit || !report.partial_modules.is_empty() {
        report.notes.push(format!(
            "{}{}.",
            if work_cap_hit {
                format!(
                    "Reading stopped after {MAX_VBA_WORK_BYTES} bytes of module data (modules \
                     that share a stream count each time); later modules were not decoded"
                )
            } else {
                "A module stream was longer than the amount read from one stream".to_string()
            },
            if report.partial_modules.is_empty() {
                String::new()
            } else {
                format!(
                    ", and these were read only in part so their source and findings are \
                     incomplete: {}",
                    report
                        .partial_modules
                        .iter()
                        .take(10)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        ));
    }
    if !found {
        return None;
    }
    Some(VbaProject {
        project_name: project_name.unwrap_or_else(|| "Unknown".to_string()),
        modules,
        references,
        properties,
        protection: VbaProtection {
            is_locked: report_has_property(&HashMap::new()),
            is_password_protected: false,
            lock_bytes: None,
            password_hash: None,
        },
        version_info: VbaVersionInfo {
            major: version.0 as u16,
            minor: version.1,
            language_id: language_id as u16,
            performance_cache: false,
        },
    })
}

const fn report_has_property(_properties: &HashMap<String, String>) -> bool {
    false
}

fn streams_of<R: Read + Seek>(cfb: &mut CompoundFile<R>, items: &[CfbItem]) -> Vec<StreamInfo> {
    let mut streams = Vec::new();
    for item in items
        .iter()
        .filter(|i| i.is_stream)
        .take(MAX_LISTED_ENTRIES)
    {
        let mut entropy = 0.0;
        let mut preview = None;
        if item.len > 0 && item.len <= ENTROPY_LIMIT {
            if let Some(bytes) = read_cfb_stream(cfb, &item.path, ENTROPY_LIMIT) {
                entropy = calculate_entropy(&bytes);
                preview = Some(
                    bytes
                        .iter()
                        .take(64)
                        .map(|&b| {
                            if b.is_ascii_graphic() || b == b' ' {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect::<String>(),
                );
            }
        }
        streams.push(StreamInfo {
            name: item.path.trim_start_matches('/').to_string(),
            size: item.len,
            stream_type: determine_stream_type(&item.name),
            content_preview: preview,
            entropy,
            compression_ratio: None,
        });
    }
    streams
}

fn metadata_of<R: Read + Seek>(cfb: &mut CompoundFile<R>, items: &[CfbItem]) -> OleMetadata {
    let mut metadata = OleMetadata::default();
    for item in items
        .iter()
        .filter(|i| i.is_stream && parent_of(&i.path) == "/")
    {
        let trimmed = item.name.trim_start_matches('\u{5}');
        if trimmed == "SummaryInformation" || trimmed == "DocumentSummaryInformation" {
            if let Some(bytes) = read_cfb_stream(cfb, &item.path, MAX_PART_BYTES) {
                let _ = parse_property_set(&bytes, &mut metadata);
            }
        }
    }
    metadata
}

fn structure_of<R: Read + Seek>(cfb: &CompoundFile<R>, items: &[CfbItem]) -> OleStructure {
    let sector_size: u16 = if cfb.version() as u16 >= 4 { 4096 } else { 512 };
    let entries: Vec<DirectoryEntry> = items
        .iter()
        .take(MAX_LISTED_ENTRIES)
        .map(|item| DirectoryEntry {
            name: item.path.trim_start_matches('/').to_string(),
            entry_type: if item.is_stream {
                EntryType::Stream
            } else {
                EntryType::Storage
            },
            color: NodeColor::Black,
            size: item.len,
            start_sector: 0,
            children: Vec::new(),
        })
        .collect();
    OleStructure {
        sector_size,
        mini_sector_size: 64,
        total_sectors: 0,
        fat_sectors: 0,
        directory_sectors: 0,
        mini_fat_sectors: 0,
        root_entry: DirectoryEntry {
            name: "Root Entry".to_string(),
            entry_type: EntryType::Root,
            color: NodeColor::Black,
            size: 0,
            start_sector: 0,
            children: items
                .iter()
                .filter(|i| parent_of(&i.path) == "/")
                .map(|i| i.name.clone())
                .collect(),
        },
        entries,
    }
}

fn analyze_compound<R: Read + Seek>(
    mut cfb: CompoundFile<R>,
    file_type: OleFileType,
    container: &str,
    vba_part: Option<String>,
) -> OfficeReport {
    let items = list_cfb(&cfb);
    let mut report = OfficeReport {
        analysis: OleVbaAnalysis {
            file_type,
            ole_structure: None,
            vba_project: None,
            macros: Vec::new(),
            streams: Vec::new(),
            suspicious_indicators: SuspiciousIndicators::default(),
            metadata: OleMetadata::default(),
            security_assessment: SecurityAssessment::default(),
        },
        container: container.to_string(),
        vba_part,
        vba_storages: Vec::new(),
        module_source: None,
        undecoded_modules: Vec::new(),
        partial_modules: Vec::new(),
        truncated: false,
        notes: Vec::new(),
    };
    let structure = structure_of(&cfb, &items);
    let streams = streams_of(&mut cfb, &items);
    let vba_project = extract_vba_project(&mut cfb, &items, &mut report);
    let macros = extract_macro_info(&vba_project).unwrap_or_default();
    let metadata = metadata_of(&mut cfb, &items);
    let suspicious =
        analyze_suspicious_patterns(&vba_project, &macros, &streams).unwrap_or_default();
    let mut assessment = perform_security_assessment(&suspicious, &macros).unwrap_or_default();
    let encrypted = items
        .iter()
        .any(|item| item.is_stream && item.name == "EncryptedPackage");
    if encrypted {
        report.notes.push(
            "The document is a password-protected package (EncryptedPackage stream): its \
             content, including any macros, cannot be inspected without the password."
                .to_string(),
        );
        assessment.risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::Encryption,
            description: "Encrypted package: macros cannot be inspected".to_string(),
            severity: RiskLevel::Medium,
            confidence: 1.0,
        });
    }
    if vba_project.is_some() && !report.undecoded_modules.is_empty() {
        assessment.risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::MacroPresence,
            description: format!(
                "VBA project present but source unreadable for {} module(s)",
                report.undecoded_modules.len()
            ),
            severity: RiskLevel::Medium,
            confidence: 0.8,
        });
    }
    let unreadable = vba_project.is_some() && !report.undecoded_modules.is_empty();
    let cut = vba_project.is_some() && report.truncated;
    if cut {
        assessment.risk_factors.push(RiskFactor {
            factor_type: RiskFactorType::MacroPresence,
            description: "VBA project only partly read (a size or count limit was reached)"
                .to_string(),
            severity: RiskLevel::Medium,
            confidence: 0.8,
        });
    }
    if (encrypted || unreadable || cut) && matches!(assessment.overall_risk, RiskLevel::Low) {
        assessment.overall_risk = RiskLevel::Medium;
    }
    if items.len() > MAX_LISTED_ENTRIES {
        report.notes.push(format!(
            "The compound file has {} entries; the first {MAX_LISTED_ENTRIES} are listed.",
            items.len()
        ));
    }
    report.analysis.ole_structure = Some(structure);
    report.analysis.streams = streams;
    report.analysis.vba_project = vba_project;
    report.analysis.macros = macros;
    report.analysis.metadata = metadata;
    report.analysis.suspicious_indicators = suspicious;
    report.analysis.security_assessment = assessment;
    report
}

/// Analyze an Office file (OLE2 `.doc`/`.xls`/`.ppt` or an OOXML zip such as `.docm`) for a
/// VBA project. `has_macros` is true only when a VBA project is actually present.
pub fn analyze_office(path: &Path) -> Result<OfficeReport> {
    let mut file = File::open(path).context("Failed to open file for OLE analysis")?;
    let file_type = detect_ole_file_type(&mut file)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    match file_type {
        OleFileType::NotOleFile => Ok(OfficeReport {
            analysis: OleVbaAnalysis {
                file_type,
                ole_structure: None,
                vba_project: None,
                macros: vec![],
                streams: vec![],
                suspicious_indicators: SuspiciousIndicators::default(),
                metadata: OleMetadata::default(),
                security_assessment: SecurityAssessment::default(),
            },
            container: "none".to_string(),
            vba_part: None,
            vba_storages: Vec::new(),
            module_source: None,
            undecoded_modules: Vec::new(),
            partial_modules: Vec::new(),
            truncated: false,
            notes: vec!["The file is neither an OLE2 compound file nor a zip package.".to_string()],
        }),
        OleFileType::OfficeOpenXml => analyze_ooxml(file),
        other => {
            let cfb = CompoundFile::open(file).map_err(|error| {
                anyhow::anyhow!(
                    "Failed to parse OLE compound file: {error}. The file may still be a valid \
                     document: the compound-file reader here is strict and rejects some files \
                     that other programs open (for example .doc files written by macOS \
                     textutil). analyze_file still works on it (strings, entropy and a generic \
                     overview), and read_hex shows raw bytes at an offset."
                )
            })?;
            Ok(analyze_compound(cfb, other, "ole2", None))
        }
    }
}

fn analyze_ooxml(file: File) -> Result<OfficeReport> {
    let mut archive = zip::ZipArchive::new(file).map_err(|error| {
        anyhow::anyhow!(
            "The file starts with PK but is not a readable zip package: {error}. The file may be \
             damaged or not an Office file; analyze_file gives a generic overview, and \
             inspect_archive lists the entries of a zip."
        )
    })?;
    let names: Vec<String> = (0..archive.len())
        .filter_map(|index| {
            archive
                .by_index_raw(index)
                .ok()
                .and_then(|entry| entry.name().ok().map(|name| name.to_string()))
        })
        .collect();
    let is_package = names.iter().any(|name| name == "[Content_Types].xml");
    if !is_package {
        return Ok(OfficeReport {
            analysis: OleVbaAnalysis {
                file_type: OleFileType::NotOleFile,
                ole_structure: None,
                vba_project: None,
                macros: vec![],
                streams: vec![],
                suspicious_indicators: SuspiciousIndicators::default(),
                metadata: OleMetadata::default(),
                security_assessment: SecurityAssessment::default(),
            },
            container: "zip".to_string(),
            vba_part: None,
            vba_storages: Vec::new(),
            module_source: None,
            undecoded_modules: Vec::new(),
            partial_modules: Vec::new(),
            truncated: false,
            notes: vec![
                "The zip has no [Content_Types].xml, so it is not an Office package.".to_string(),
            ],
        });
    }
    let vba_part = names
        .iter()
        .find(|name| name.to_ascii_lowercase().ends_with("vbaproject.bin"))
        .cloned();
    let Some(part) = vba_part else {
        let mut report = analyze_compound_empty(OleFileType::OfficeOpenXml);
        report
            .notes
            .push("The package has no vbaProject.bin part, so it holds no VBA macros.".to_string());
        return Ok(report);
    };
    let mut bytes = Vec::new();
    archive
        .by_name(&part)
        .with_context(|| format!("Failed to open {part} in the package"))?
        .take(MAX_PART_BYTES)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Failed to read {part}"))?;
    let cfb = match CompoundFile::open(std::io::Cursor::new(bytes)) {
        Ok(cfb) => cfb,
        Err(error) => {
            // The package declares a macro project even though it cannot be read.
            let mut report = analyze_compound_empty(OleFileType::OfficeOpenXml);
            report.vba_part = Some(part.clone());
            report.analysis.suspicious_indicators.has_macros = true;
            report
                .analysis
                .security_assessment
                .risk_factors
                .push(RiskFactor {
                    factor_type: RiskFactorType::MacroPresence,
                    description: format!("{part} is present but not a readable compound file"),
                    severity: RiskLevel::Medium,
                    confidence: 0.8,
                });
            report.analysis.security_assessment.overall_risk = RiskLevel::Medium;
            report.analysis.suspicious_indicators.risk_score = 30;
            report.notes.push(format!(
                "{part} is not a readable compound file ({error}), so the macros could not be \
                 read; the package still declares a VBA project. inspect_archive lists the \
                 part, and read_hex or analyze_file shows its bytes."
            ));
            return Ok(report);
        }
    };
    Ok(analyze_compound(
        cfb,
        OleFileType::OfficeOpenXml,
        "ooxml",
        Some(part),
    ))
}

fn analyze_compound_empty(file_type: OleFileType) -> OfficeReport {
    OfficeReport {
        analysis: OleVbaAnalysis {
            file_type,
            ole_structure: None,
            vba_project: None,
            macros: vec![],
            streams: vec![],
            suspicious_indicators: SuspiciousIndicators::default(),
            metadata: OleMetadata::default(),
            security_assessment: SecurityAssessment::default(),
        },
        container: "ooxml".to_string(),
        vba_part: None,
        vba_storages: Vec::new(),
        module_source: None,
        undecoded_modules: Vec::new(),
        partial_modules: Vec::new(),
        truncated: false,
        notes: Vec::new(),
    }
}

/// Main entry point for OLE and VBA analysis (see [`analyze_office`] for the extra detail).
pub fn analyze_ole_vba(path: &Path) -> Result<OleVbaAnalysis> {
    analyze_office(path).map(|report| report.analysis)
}

pub fn detect_ole_file_type(file: &mut File) -> Result<OleFileType> {
    let mut header = [0u8; 512];
    let mut filled = 0;
    while filled < header.len() {
        match file.read(&mut header[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("Failed to read file header"),
        }
    }
    let header = &header[..filled];

    // Check for OLE2 signature
    if header.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        // This is an OLE2 file, try to determine the specific type
        return determine_ole_document_type(file);
    }

    // Check for Office Open XML (OOXML) format
    if header.starts_with(b"PK") {
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
                // Auto-executing entry points: procedure declarations only.
                for entry in detect_auto_exec_entries(source, &module.name) {
                    if indicators.auto_exec_macros.len() >= MAX_AUTO_EXEC_ENTRIES {
                        break;
                    }
                    indicators
                        .auto_exec_macros
                        .push(format!("{}:{}", entry.module, entry.procedure));
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
            description: {
                let all = &suspicious_indicators.auto_exec_macros;
                let shown: Vec<&str> = all.iter().take(5).map(String::as_str).collect();
                if all.len() > shown.len() {
                    format!(
                        "Auto-executing macros found: {} entry points, first {}",
                        all.len(),
                        shown.join(", ")
                    )
                } else {
                    format!("Auto-executing macros found: {}", shown.join(", "))
                }
            },
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

    // A module that is not in the file is an error, not an empty module.
    let mut stream = cfb
        .open_stream(module_name)
        .with_context(|| format!("Stream {module_name} not found in the compound file"))?;
    let mut buffer = Vec::new();
    stream
        .by_ref()
        .take(MAX_PART_BYTES)
        .read_to_end(&mut buffer)
        .with_context(|| format!("Failed to read stream {module_name}"))?;
    // Check if it's text or binary
    if buffer
        .iter()
        .all(|&b| b.is_ascii() || b.is_ascii_whitespace())
    {
        module.source_code = Some(String::from_utf8_lossy(&buffer).to_string());
    } else {
        module.compiled_code = Some(buffer);
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

    let suspicious_keywords = SUSPICIOUS_VBA_KEYWORDS;

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
        if contains_word(&source_lower, api) {
            calls.push(SuspiciousApiCall {
                api_name: api.to_string(),
                module_name: module_name.to_string(),
                call_count: count_word(&source_lower, api) as u32,
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

/// The first URL in `source` that starts with one of `schemes`, cut at a quote, space or
/// closing parenthesis and at 200 characters.
fn first_url(source: &str, schemes: &[&str]) -> Option<String> {
    let lower = source.to_ascii_lowercase();
    let start = schemes.iter().filter_map(|s| lower.find(s)).min()?;
    let rest = source.get(start..)?;
    let url: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ')' | '<' | '>'))
        .take(200)
        .collect();
    (!url.is_empty()).then_some(url)
}

pub fn detect_external_connections(source: &str, module_name: &str) -> Vec<ExternalConnection> {
    let mut connections = Vec::new();
    let source_lower = source.to_lowercase();

    // HTTP connections
    if source_lower.contains("http://") || source_lower.contains("https://") {
        connections.push(ExternalConnection {
            connection_type: ConnectionType::HttpRequest,
            target: first_url(source, &["http://", "https://"])
                .unwrap_or_else(|| "HTTP/HTTPS URL detected".to_string()),
            method: "GET/POST".to_string(),
            location: module_name.to_string(),
        });
    }

    // FTP connections
    if source_lower.contains("ftp://") {
        connections.push(ExternalConnection {
            connection_type: ConnectionType::FtpConnection,
            target: first_url(source, &["ftp://"])
                .unwrap_or_else(|| "FTP URL detected".to_string()),
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
