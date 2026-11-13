use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

/// Comprehensive PDF analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfAnalysis {
    pub document_info: PdfDocumentInfo,
    pub structure: PdfStructure,
    pub security: PdfSecurity,
    pub content_analysis: PdfContentAnalysis,
    pub suspicious_indicators: PdfSuspiciousIndicators,
    pub metadata: PdfMetadata,
    pub risk_assessment: PdfRiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfDocumentInfo {
    pub version: String,
    pub page_count: u32,
    pub file_size: u64,
    pub producer: Option<String>,
    pub creator: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub is_linearized: bool,
    pub is_encrypted: bool,
    pub is_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfStructure {
    pub pages: Vec<PdfPageInfo>,
    pub xref_count: u32,
    pub object_count: u32,
    pub stream_count: u32,
    pub catalog_info: CatalogInfo,
    pub object_streams: Vec<ObjectStreamInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfPageInfo {
    pub page_number: u32,
    pub width: f32,
    pub height: f32,
    pub rotation: i32,
    pub has_javascript: bool,
    pub has_forms: bool,
    pub has_annotations: bool,
    pub embedded_files: Vec<String>,
    pub resource_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogInfo {
    pub page_layout: Option<String>,
    pub page_mode: Option<String>,
    pub viewer_preferences: HashMap<String, String>,
    pub has_acroform: bool,
    pub has_javascript: bool,
    pub has_embedded_files: bool,
    pub has_open_action: bool,
    pub open_action_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStreamInfo {
    pub object_id: u32,
    pub stream_type: String,
    pub size: u64,
    pub filter: Option<String>,
    pub is_compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfSecurity {
    pub encryption: Option<EncryptionInfo>,
    pub permissions: PdfPermissions,
    pub digital_signatures: Vec<DigitalSignatureInfo>,
    pub security_handler: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub key_length: u32,
    pub revision: u32,
    pub is_owner_password_set: bool,
    pub is_user_password_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfPermissions {
    pub can_print: bool,
    pub can_modify: bool,
    pub can_copy: bool,
    pub can_annotate: bool,
    pub can_fill_forms: bool,
    pub can_extract: bool,
    pub can_assemble: bool,
    pub print_quality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignatureInfo {
    pub signer_name: Option<String>,
    pub sign_date: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub is_valid: bool,
    pub certificate_info: Option<CertificateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfContentAnalysis {
    pub javascript: Vec<JavaScriptInfo>,
    pub embedded_files: Vec<EmbeddedFileInfo>,
    pub forms: Vec<FormInfo>,
    pub actions: Vec<ActionInfo>,
    pub urls: Vec<String>,
    pub launch_actions: Vec<LaunchActionInfo>,
    pub suspicious_names: Vec<String>,
    pub redirection_chains: Vec<RedirectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaScriptInfo {
    pub location: String,
    pub code_preview: String,
    pub length: usize,
    pub obfuscation_score: f32,
    pub suspicious_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFileInfo {
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: u64,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInfo {
    pub field_name: String,
    pub field_type: String,
    pub has_javascript: bool,
    pub submit_url: Option<String>,
    pub is_hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    pub action_type: String,
    pub trigger: String,
    pub target: Option<String>,
    pub javascript_code: Option<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchActionInfo {
    pub target_application: String,
    pub parameters: Vec<String>,
    pub location: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectionInfo {
    pub source: String,
    pub destination: String,
    pub redirect_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfSuspiciousIndicators {
    pub has_javascript: bool,
    pub has_embedded_files: bool,
    pub has_launch_actions: bool,
    pub has_suspicious_names: bool,
    pub has_auto_actions: bool,
    pub javascript_count: u32,
    pub embedded_file_count: u32,
    pub form_count: u32,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub exploitation_vectors: Vec<ExploitationVector>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_type: String,
    pub description: String,
    pub location: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitationVector {
    pub vector_type: String,
    pub description: String,
    pub cve_references: Vec<String>,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PdfMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
    pub trapped: Option<String>,
    pub custom_properties: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfRiskAssessment {
    pub overall_risk: RiskLevel,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendations: Vec<String>,
    pub ioc_indicators: Vec<IocIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: String,
    pub description: String,
    pub severity: RiskLevel,
    pub mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocIndicator {
    pub indicator_type: String,
    pub value: String,
    pub context: String,
    pub confidence: f32,
}

// ---------------------------------------------------------------------------
// Structural scan
// ---------------------------------------------------------------------------

/// Most bytes of a PDF that are read and scanned.
pub const MAX_PDF_BYTES: usize = 64 * 1024 * 1024;
/// Most decompressed bytes taken from one stream.
const MAX_STREAM_INFLATE: usize = 4 * 1024 * 1024;
/// Most decompressed bytes taken from the object streams of one file. Object streams have
/// a budget of their own so that padding streams cannot use it up before the object stream
/// that holds the catalog is reached.
const MAX_OBJSTM_INFLATE: usize = 32 * 1024 * 1024;
/// Most decompressed bytes taken from all other streams of one file.
const MAX_CONTENT_INFLATE: usize = 32 * 1024 * 1024;
/// Most decompressed (or copied) bytes taken from streams that hold a script.
const MAX_SCRIPT_INFLATE: usize = 16 * 1024 * 1024;
/// Most bytes the second pass (objects hidden in stream data, objects the cross-reference
/// table points at) may read or lex in all.
const RESCAN_BUDGET: usize = 64 * 1024 * 1024;
/// Most single objects re-read from cross-reference offsets.
const MAX_SINGLE_RESCANS: usize = 5_000;
/// Longest stretch read for one such object.
const MAX_SINGLE_RESCAN_BYTES: usize = 1024 * 1024;
/// Least charged to the second-pass budget for one single-object rescan, so that many
/// short objects still add up.
const MIN_SINGLE_RESCAN_CHARGE: usize = 4096;
/// Most cross-reference entries read in all.
const MAX_XREF_ENTRIES: usize = 4_000_000;
/// Most passes of the hidden-object search (a hidden region can hold another).
const MAX_RESCAN_ROUNDS: usize = 6;
/// Most objects (and pages) kept in the lookup tables; more are counted only.
const MAX_OBJECT_TABLE: usize = 1_000_000;
/// Most stream ranges remembered for the second pass.
const MAX_STREAM_RANGES: usize = 1_000_000;
/// Most object header positions remembered for the whole-file pass.
const MAX_OBJ_BODIES: usize = 4_000_000;
/// Most object streams described in the result (the count is kept in full).
const MAX_OBJECT_STREAM_ROWS: usize = 10_000;
/// Evidence offsets kept per feature.
const MAX_EVIDENCE: usize = 25;
/// Most URLs, JavaScript items, launch actions and embedded files kept.
const MAX_ITEMS: usize = 200;
/// Most link targets (`/URI`) kept; launch and submit targets keep [`MAX_ITEMS`] of their own.
const MAX_LINK_TARGETS: usize = 5_000;
/// Characters of JavaScript kept as a preview.
const JS_PREVIEW_CHARS: usize = 400;
/// Longest string token the lexer will read before giving up on it.
const MAX_STRING_BYTES: usize = 256 * 1024;

/// The risk-bearing names the scan counts. A name written with `#xx` escapes
/// (`/J#61vaScript`) is decoded before it is compared.
pub const TRACKED_NAMES: &[&str] = &[
    "JavaScript",
    "JS",
    "OpenAction",
    "AA",
    "Launch",
    "EmbeddedFile",
    "EmbeddedFiles",
    "URI",
    "SubmitForm",
    "RichMedia",
    "XFA",
    "Encrypt",
    "ObjStm",
    "AcroForm",
    "GoToR",
    "GoToE",
    "ImportData",
    "JBIG2Decode",
    "Linearized",
    "ByteRange",
    "XRef",
];

/// One place a feature was seen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfEvidence {
    /// Byte offset in the file. For something found inside a decompressed stream, the
    /// offset where that stream's data starts.
    pub offset: u64,
    /// Object number the name was in, when known.
    pub object: Option<u32>,
    /// True when found inside a decompressed stream (typically an object stream).
    pub in_stream: bool,
}

/// How often a tracked name occurs, and where.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfFeature {
    pub name: String,
    pub count: u32,
    /// The first places it was seen (at most 25).
    pub evidence: Vec<PdfEvidence>,
}

/// One JavaScript action or script found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfScript {
    pub offset: u64,
    pub object: Option<u32>,
    /// Total length of the script in bytes (0 when it could not be resolved).
    pub length: usize,
    pub preview: String,
    pub suspicious_patterns: Vec<String>,
}

/// A link, launch target or submit target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfTarget {
    /// `URI`, `Launch` or `SubmitForm`.
    pub kind: String,
    pub value: String,
    pub offset: u64,
}

/// An attached file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfAttachment {
    pub filename: Option<String>,
    pub size: Option<u64>,
    pub offset: u64,
    pub object: Option<u32>,
}

/// The result of [`scan_pdf`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfScan {
    /// Header version (`1.7`), or `unknown` when the header has none.
    pub version: String,
    /// Offset of `%PDF-` (junk before the header is allowed by readers).
    pub header_offset: u64,
    pub file_size: u64,
    pub bytes_scanned: u64,
    /// True when the file is bigger than [`MAX_PDF_BYTES`] and the rest was not read.
    pub scan_truncated: bool,
    pub object_count: u32,
    pub stream_count: u32,
    pub page_count: u32,
    pub xref_sections: u32,
    pub trailers: u32,
    pub is_encrypted: bool,
    pub encryption: Option<EncryptionInfo>,
    pub is_linearized: bool,
    pub is_signed: bool,
    pub object_streams: Vec<ObjectStreamInfo>,
    pub features: Vec<PdfFeature>,
    /// Names that were written with `#xx` escapes, decoded (an evasion signal).
    pub escaped_names: Vec<String>,
    pub scripts: Vec<PdfScript>,
    pub targets: Vec<PdfTarget>,
    pub attachments: Vec<PdfAttachment>,
    /// True number of scripts found (the list above keeps at most 200).
    pub scripts_total: usize,
    /// True number of `/URI` links found (the list of targets keeps at most 200).
    pub links_total: usize,
    /// True number of launch and submit targets found.
    pub action_targets_total: usize,
    /// True number of attachments referenced.
    pub attachments_total: usize,
    /// True number of object streams (the list above keeps at most 10,000).
    pub object_streams_total: usize,
    /// What the scan could not read, one reason each. Empty when everything was read.
    pub unread: Vec<String>,
    /// The `/S` type of the document's `/OpenAction` (for example `JavaScript`).
    pub open_action_type: Option<String>,
    pub info: HashMap<String, String>,
    /// Facts a reader should know that limit the scan (encrypted streams, truncation).
    pub notes: Vec<String>,
    pub risk_score: u8,
    pub overall_risk: RiskLevel,
    /// Why the score is what it is.
    pub risk_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
enum Tok {
    /// A name token: byte range after the `/`.
    Name(usize, usize),
    /// A literal or hex string, decoded.
    Str(usize, Vec<u8>),
    /// A bare word (number or keyword): byte range.
    Word(usize, usize),
    DictOpen,
    DictClose,
    ArrayOpen,
    ArrayClose,
}

/// Bytes a scan may spend on literal strings that never close. Each unbalanced `(` would
/// otherwise cost up to [`MAX_STRING_BYTES`] of lookahead, so a tiny file of `(` bytes could
/// hold the scanner for hours.
const FAILED_STRING_BUDGET: usize = 16 * 1024 * 1024;

thread_local! {
    static STRING_BUDGET: std::cell::Cell<usize> = const { std::cell::Cell::new(FAILED_STRING_BUDGET) };
    static STRING_BUDGET_HIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct Lexer<'a> {
    buf: &'a [u8],
    pos: usize,
}

const fn is_ws(byte: u8) -> bool {
    matches!(byte, 0 | 9 | 10 | 12 | 13 | 32)
}

const fn is_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

impl<'a> Lexer<'a> {
    const fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    fn next_token(&mut self) -> Option<Tok> {
        let buf = self.buf;
        loop {
            let byte = *buf.get(self.pos)?;
            if is_ws(byte) {
                self.pos += 1;
                continue;
            }
            match byte {
                b'%' => {
                    while self.pos < buf.len() && buf[self.pos] != b'\n' && buf[self.pos] != b'\r' {
                        self.pos += 1;
                    }
                }
                b'/' => {
                    let start = self.pos + 1;
                    let mut end = start;
                    while end < buf.len() && !is_ws(buf[end]) && !is_delim(buf[end]) {
                        end += 1;
                    }
                    self.pos = end;
                    return Some(Tok::Name(start, end));
                }
                b'(' => return Some(self.literal_string()),
                b'<' => {
                    if buf.get(self.pos + 1) == Some(&b'<') {
                        self.pos += 2;
                        return Some(Tok::DictOpen);
                    }
                    return Some(self.hex_string());
                }
                b'>' => {
                    if buf.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        return Some(Tok::DictClose);
                    }
                    self.pos += 1;
                }
                b'[' => {
                    self.pos += 1;
                    return Some(Tok::ArrayOpen);
                }
                b']' => {
                    self.pos += 1;
                    return Some(Tok::ArrayClose);
                }
                b')' | b'{' | b'}' => self.pos += 1,
                _ => {
                    let start = self.pos;
                    while self.pos < buf.len() && !is_ws(buf[self.pos]) && !is_delim(buf[self.pos])
                    {
                        self.pos += 1;
                    }
                    return Some(Tok::Word(start, self.pos));
                }
            }
        }
    }

    fn literal_string(&mut self) -> Tok {
        let buf = self.buf;
        let start = self.pos;
        if STRING_BUDGET.with(std::cell::Cell::get) == 0 {
            STRING_BUDGET_HIT.with(|hit| hit.set(true));
            self.pos = start + 1;
            return Tok::Str(start, Vec::new());
        }
        let mut i = self.pos + 1;
        let mut depth = 1usize;
        let mut out = Vec::new();
        let limit = (i + MAX_STRING_BYTES).min(buf.len());
        while i < limit {
            let byte = buf[i];
            match byte {
                b'\\' => {
                    i += 1;
                    let Some(&next) = buf.get(i) else { break };
                    match next {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'\r' => {
                            if buf.get(i + 1) == Some(&b'\n') {
                                i += 1;
                            }
                        }
                        b'\n' => {}
                        b'0'..=b'7' => {
                            let mut value = u32::from(next - b'0');
                            let mut digits = 1;
                            while digits < 3 {
                                match buf.get(i + 1) {
                                    Some(d @ b'0'..=b'7') => {
                                        value = value * 8 + u32::from(d - b'0');
                                        i += 1;
                                        digits += 1;
                                    }
                                    _ => break,
                                }
                            }
                            out.push((value & 0xFF) as u8);
                        }
                        other => out.push(other),
                    }
                }
                b'(' => {
                    depth += 1;
                    out.push(byte);
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos = i + 1;
                        return Tok::Str(start, out);
                    }
                    out.push(byte);
                }
                _ => out.push(byte),
            }
            i += 1;
        }
        // Unbalanced: resume right after the opening parenthesis, and charge what the failed
        // scan cost to the budget.
        let spent = i.saturating_sub(start).max(1);
        STRING_BUDGET.with(|budget| budget.set(budget.get().saturating_sub(spent)));
        self.pos = start + 1;
        Tok::Str(start, Vec::new())
    }

    fn hex_string(&mut self) -> Tok {
        let buf = self.buf;
        let start = self.pos;
        let mut i = self.pos + 1;
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        let limit = (i + MAX_STRING_BYTES * 2).min(buf.len());
        while i < limit {
            let byte = buf[i];
            if byte == b'>' {
                if let Some(h) = high {
                    out.push(h << 4);
                }
                self.pos = i + 1;
                return Tok::Str(start, out);
            }
            if let Some(value) = (byte as char).to_digit(16) {
                match high.take() {
                    Some(h) => out.push((h << 4) | value as u8),
                    None => high = Some(value as u8),
                }
            } else if !is_ws(byte) {
                break;
            }
            i += 1;
        }
        self.pos = start + 1;
        Tok::Str(start, Vec::new())
    }
}

/// Decode `#xx` escapes in a name. Returns the decoded bytes and whether any escape was used.
fn decode_name(raw: &[u8]) -> (Vec<u8>, bool) {
    if !raw.contains(&b'#') {
        return (raw.to_vec(), false);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut escaped = false;
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 3 <= raw.len() {
            if let Some(value) = std::str::from_utf8(&raw[i + 1..i + 3])
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
            {
                out.push(value);
                escaped = true;
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    (out, escaped)
}

fn find_bytes(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = from;
    while i <= last_start {
        i += hay[i..=last_start].iter().position(|&b| b == first)?;
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn word_int(buf: &[u8], start: usize, end: usize) -> Option<u32> {
    std::str::from_utf8(&buf[start..end]).ok()?.parse().ok()
}

/// PDF text string: UTF-16BE with a BOM, or single-byte text.
fn pdf_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        bytes.iter().map(|&b| b as char).collect()
    }
}

fn cut_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(max_chars).collect();
        cut.push_str("...");
        cut
    }
}

#[derive(Default, Clone)]
struct ObjInfo {
    /// Offset of the first token after `obj`.
    body: usize,
    /// Data range of the stream, when the object is a stream.
    stream: Option<(usize, usize)>,
    flate: bool,
}

#[derive(Default)]
struct ScanState {
    objects: HashMap<u32, ObjInfo>,
    object_count: u32,
    stream_count: u32,
    page_objects: std::collections::HashSet<u32>,
    page_marks_unkeyed: u32,
    xref_sections: u32,
    trailers: u32,
    features: std::collections::BTreeMap<String, (u32, Vec<PdfEvidence>)>,
    escaped_names: Vec<String>,
    script_refs: Vec<(u64, Option<u32>, u32)>,
    scripts: Vec<PdfScript>,
    targets: Vec<PdfTarget>,
    attachments: Vec<PdfAttachment>,
    attachment_refs: Vec<(usize, u32)>,
    attachment_names: HashMap<usize, String>,
    object_streams: Vec<ObjectStreamInfo>,
    encrypt_ref: Option<u32>,
    encryption: Option<EncryptionInfo>,
    open_action_type: Option<String>,
    info: HashMap<String, String>,
    inflated_content: usize,
    inflated_objstm: usize,
    inflated_scripts: usize,
    undecoded_streams: u32,
    notes: Vec<String>,
    scripts_total: usize,
    links_total: usize,
    targets_total: usize,
    /// Launch and submit targets kept (they are capped apart from links).
    action_targets_kept: usize,
    attachments_total: usize,
    /// Objects whose script was already resolved (a second reference adds nothing).
    resolved_scripts: std::collections::HashSet<u32>,
    /// Name/string pairs of an object's dictionary, read once per object.
    dict_cache: HashMap<u32, HashMap<String, String>>,
    content_budget_hit: bool,
    objstm_budget_hit: bool,
    script_budget_hit: bool,
    /// Streams whose decompressed data was longer than [`MAX_STREAM_INFLATE`] and was cut.
    streams_cut: u32,
    /// Streams that start with `stream` but never reach `endstream`.
    unterminated_streams: u32,
    /// Object streams that were not read (budget, other filter, corrupt data, too long).
    objstm_unread: u32,
    object_streams_total: usize,
    embedded_streams_total: usize,
    objects_capped: bool,
    /// Every top-level stream, for the search of objects hidden in stream data.
    streams: Vec<StreamRange>,
    ranges_capped: bool,
    /// Positions just after each `xref` keyword.
    xref_positions: Vec<usize>,
    xref_done: usize,
    xref_entries: usize,
    xref_entries_capped: bool,
    rescan_budget: usize,
    rescan_budget_hit: bool,
    /// Stream start -> offset the rescan of that stream began at.
    rescanned: HashMap<usize, usize>,
    single_rescans: usize,
    single_rescan_cap_hit: bool,
    /// Regions of stream data that held objects, re-read as top-level syntax.
    hidden_regions: u32,
    hidden_objects_seen: u32,
    /// Objects the cross-reference table points at that the first pass never saw.
    missed_objects: u32,
    /// Objects found by searching the whole file for headers, not by an xref offset.
    searched_objects: u32,
    /// Positions just after every `N G obj` header the scan has read as an object.
    obj_bodies: std::collections::HashSet<usize>,
    /// Objects longer than the read window for one object; the rest of each was not read.
    window_cut_objects: u32,
}

/// Where a top-level stream's data sits, and whether it could hold unread objects.
#[derive(Clone, Copy)]
struct StreamRange {
    start: usize,
    end: usize,
    /// True when the data was neither decoded nor skipped as an image, font or attachment,
    /// so a linear read never looked at it.
    candidate: bool,
}

const INFO_KEYS: &[&str] = &[
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Trapped",
];

const JS_SUSPICIOUS: &[(&str, &str)] = &[
    ("eval(", "eval"),
    ("unescape(", "unescape"),
    ("String.fromCharCode", "String.fromCharCode"),
    ("app.launchURL", "app.launchURL"),
    ("exportDataObject", "exportDataObject"),
    ("util.printf", "util.printf"),
    ("collab.getIcon", "collab.getIcon"),
    ("Collab.collectEmailInfo", "collectEmailInfo"),
    ("getAnnots", "getAnnots"),
    ("media.newPlayer", "media.newPlayer"),
    ("submitForm", "submitForm"),
    ("this.getField", "getField"),
    ("SOAP.", "SOAP"),
    ("importDataObject", "importDataObject"),
    ("app.setTimeOut", "app.setTimeOut"),
    ("new ActiveXObject", "ActiveXObject"),
];

fn js_patterns(code: &str) -> Vec<String> {
    let mut found: Vec<String> = JS_SUSPICIOUS
        .iter()
        .filter(|(needle, _)| code.contains(needle))
        .map(|(_, label)| (*label).to_string())
        .collect();
    let escapes = code.matches("\\x").count() + code.matches("%u").count();
    if escapes > 20 {
        found.push("long escape runs (possible shellcode)".to_string());
    }
    found
}

/// What the dictionary of the object being read has said so far.
#[derive(Default)]
struct ObjCtx {
    filters: Vec<Vec<u8>>,
    is_objstm: bool,
    is_embedded_file: bool,
    /// Image or font data: not worth decompressing for syntax.
    skip_decode: bool,
}

/// Where a scan of one buffer stopped, and the object (if any) it was inside of when the
/// buffer ended: its number, its body position and whether this scan created its table entry.
struct ScanStop {
    /// How far the lexer got.
    pos: usize,
    open: Option<(u32, usize, bool)>,
}

/// After a scan of a window that ended before the end of the file, an object that was still
/// open was cut by the window: take it back out of the tables so that a search of the whole
/// file reads it again in a window of its own.
fn release_cut_object(
    buf_len: usize,
    window_end: usize,
    start_body: usize,
    stop: &ScanStop,
    state: &mut ScanState,
) {
    let Some((number, body, created)) = stop.open else {
        return;
    };
    if window_end >= buf_len {
        return;
    }
    if body == start_body {
        // The object the window started at is longer than the window and never gets another
        // one: keep what was read and say that the rest was not.
        state.window_cut_objects += 1;
        return;
    }
    if state.obj_bodies.remove(&body) {
        state.object_count = state.object_count.saturating_sub(1);
    }
    if created {
        state.objects.remove(&number);
    }
}

/// Scan one buffer of PDF syntax. `base` is the file offset where the stream data starts when
/// the buffer is a decompressed stream (`decoded`), `owner` the object that holds the stream.
fn scan_syntax(
    buf: &[u8],
    start: usize,
    decoded: bool,
    base: u64,
    owner: Option<u32>,
    state: &mut ScanState,
    single_object: bool,
) -> ScanStop {
    let mut open: Option<(u32, usize, bool)> = None;
    let mut lexer = Lexer::at(buf, start);
    let mut prev: [Option<(usize, usize)>; 2] = [None, None];
    let mut cur_obj: Option<u32> = owner;
    let mut ctx = ObjCtx::default();
    // True right after the `>>` that ends an object's dictionary: the only place a real
    // `stream` keyword can follow.
    let mut after_dict = false;
    // True right after the name `/S`, so its value is an action type, not a second use.
    let mut after_s = false;

    while let Some(token) = lexer.next_token() {
        let was_after_dict = std::mem::take(&mut after_dict);
        let was_after_s = std::mem::take(&mut after_s);
        match token {
            Tok::DictClose => {
                after_dict = true;
                prev = [prev[1], None];
            }
            Tok::Word(s, e) => {
                match &buf[s..e] {
                    b"obj" if !decoded => {
                        if let (Some(num), Some(_generation)) = (
                            prev[0].and_then(|(a, b)| word_int(buf, a, b)),
                            prev[1].and_then(|(a, b)| word_int(buf, a, b)),
                        ) {
                            cur_obj = Some(num);
                            state.object_count += 1;
                            let mut recorded = false;
                            if state.obj_bodies.len() < MAX_OBJ_BODIES {
                                recorded = state.obj_bodies.insert(e);
                            } else {
                                state.objects_capped = true;
                            }
                            open = recorded.then(|| (num, e, !state.objects.contains_key(&num)));
                            if state.objects.len() < MAX_OBJECT_TABLE
                                || state.objects.contains_key(&num)
                            {
                                state.objects.entry(num).or_default().body = e;
                            } else {
                                state.objects_capped = true;
                            }
                            ctx = ObjCtx::default();
                        }
                    }
                    b"endobj" if !decoded => {
                        cur_obj = None;
                        open = None;
                        if single_object {
                            return ScanStop {
                                pos: lexer.pos,
                                open: None,
                            };
                        }
                    }
                    b"xref" if !decoded => {
                        state.xref_sections += 1;
                        if state.xref_positions.len() < 100_000 {
                            state.xref_positions.push(e);
                        }
                    }
                    b"trailer" if !decoded => state.trailers += 1,
                    b"stream" if !decoded && cur_obj.is_some() && was_after_dict => {
                        lexer.pos = handle_stream(buf, e, cur_obj, &ctx, state);
                    }
                    _ => {}
                }
                prev = [prev[1], Some((s, e))];
            }
            Tok::Name(s, e) => {
                let (name, escaped) = decode_name(&buf[s..e]);
                let name_text = String::from_utf8_lossy(&name).into_owned();
                let offset = base + if decoded { 0 } else { s as u64 - 1 };
                after_s = name_text == "S";
                // `/S /URI` names the action type; the link itself is the `/URI` key.
                let action_type_value = was_after_s && name_text == "URI";
                if !action_type_value && TRACKED_NAMES.contains(&name_text.as_str()) {
                    if escaped && state.escaped_names.len() < MAX_ITEMS {
                        let line = format!("/{name_text}");
                        if !state.escaped_names.contains(&line) {
                            state.escaped_names.push(line);
                        }
                    }
                    let entry = state.features.entry(name_text.clone()).or_default();
                    entry.0 += 1;
                    if entry.1.len() < MAX_EVIDENCE {
                        entry.1.push(PdfEvidence {
                            offset,
                            object: cur_obj,
                            in_stream: decoded,
                        });
                    }
                }
                let site = NameSite {
                    buf,
                    after: lexer.pos,
                    offset,
                    decoded,
                    cur_obj,
                };
                handle_name(&name_text, &site, state, &mut ctx);
                prev = [prev[1], None];
            }
            _ => prev = [prev[1], None],
        }
    }
    ScanStop {
        pos: lexer.pos.min(buf.len()),
        open,
    }
}

/// Record a stream that starts after the `stream` keyword ending at `after_keyword`, scan
/// its decoded content when that is worthwhile, and return where lexing resumes.
fn handle_stream(
    buf: &[u8],
    after_keyword: usize,
    cur_obj: Option<u32>,
    ctx: &ObjCtx,
    state: &mut ScanState,
) -> usize {
    let mut data_start = after_keyword;
    if buf.get(data_start) == Some(&b'\r') {
        data_start += 1;
        if buf.get(data_start) == Some(&b'\n') {
            data_start += 1;
        }
    } else if buf.get(data_start) == Some(&b'\n') {
        data_start += 1;
    }
    let data_end = match find_bytes(buf, b"endstream", data_start) {
        Some(end) => end,
        None => {
            state.unterminated_streams += 1;
            buf.len()
        }
    };
    state.stream_count += 1;
    let flate = ctx
        .filters
        .first()
        .is_some_and(|f| f == b"FlateDecode" || f == b"Fl");
    let mut size = (data_end - data_start) as u64;
    if size > 0 && buf[data_end - 1] == b'\n' {
        size -= 1;
    }
    if let Some(num) = cur_obj {
        if state.objects.len() < MAX_OBJECT_TABLE || state.objects.contains_key(&num) {
            let info = state.objects.entry(num).or_default();
            info.stream = Some((data_start, data_end));
            info.flate = flate;
        } else {
            state.objects_capped = true;
        }
    }
    if ctx.is_objstm {
        state.object_streams_total += 1;
        if state.object_streams.len() < MAX_OBJECT_STREAM_ROWS {
            state.object_streams.push(ObjectStreamInfo {
                object_id: cur_obj.unwrap_or(0),
                stream_type: "ObjStm".to_string(),
                size,
                filter: ctx
                    .filters
                    .first()
                    .map(|f| String::from_utf8_lossy(f).into_owned()),
                is_compressed: flate,
            });
        }
    }
    // Every range whose data was not read as syntax could hold hidden objects: a reader that
    // follows the cross-reference data or rebuilds the file sees objects the linear read
    // stepped over, whatever the dummy stream calls itself (image, font, attachment, an
    // unsupported filter, or a Flate stream with a few bytes of padding).
    let candidate = data_end > data_start && !(ctx.is_objstm && flate);
    if ctx.is_embedded_file {
        state.embedded_streams_total += 1;
        if state.attachments.len() < MAX_ITEMS {
            state.attachments.push(PdfAttachment {
                filename: None,
                size: Some(size),
                offset: data_start as u64,
                object: cur_obj,
            });
        }
    } else if data_end == data_start || ctx.skip_decode {
        // Nothing worth reading.
    } else if flate {
        let (spent, limit) = if ctx.is_objstm {
            (state.inflated_objstm, MAX_OBJSTM_INFLATE)
        } else {
            (state.inflated_content, MAX_CONTENT_INFLATE)
        };
        let room = limit.saturating_sub(spent);
        let cap = MAX_STREAM_INFLATE.min(room);
        let mut inflated = Vec::new();
        if cap > 0 {
            inflated = inflate(&buf[data_start..data_end], cap);
            if ctx.is_objstm {
                state.inflated_objstm += inflated.len();
            } else {
                state.inflated_content += inflated.len();
            }
        }
        let budget_out = cap == 0 || inflated.len() >= room;
        if budget_out {
            if ctx.is_objstm {
                state.objstm_budget_hit = true;
            } else {
                state.content_budget_hit = true;
            }
        }
        if cap > 0 && inflated.len() >= MAX_STREAM_INFLATE {
            state.streams_cut += 1;
        }
        if inflated.is_empty() {
            if ctx.is_objstm {
                state.objstm_unread += 1;
            }
        } else {
            if ctx.is_objstm && (budget_out || inflated.len() >= MAX_STREAM_INFLATE) {
                state.objstm_unread += 1;
            }
            scan_syntax(&inflated, 0, true, data_start as u64, cur_obj, state, false);
        }
    } else if ctx.filters.is_empty() {
        if ctx.is_objstm {
            // An uncompressed object stream holds objects in plain syntax.
            if data_end - data_start <= MAX_STREAM_INFLATE {
                let raw = buf[data_start..data_end].to_vec();
                scan_syntax(&raw, 0, true, data_start as u64, cur_obj, state, false);
            } else {
                state.objstm_unread += 1;
                state.streams_cut += 1;
            }
        }
    } else {
        state.undecoded_streams += 1;
        if ctx.is_objstm {
            state.objstm_unread += 1;
        }
    }
    if state.streams.len() < MAX_STREAM_RANGES {
        state.streams.push(StreamRange {
            start: data_start,
            end: data_end,
            candidate,
        });
    } else {
        state.ranges_capped = true;
    }
    data_end
}

/// Where a name was read.
struct NameSite<'a> {
    buf: &'a [u8],
    /// Position just after the name.
    after: usize,
    offset: u64,
    decoded: bool,
    cur_obj: Option<u32>,
}

/// The name/string pairs among the next `count` tokens.
fn pairs_ahead(look: &mut Lexer<'_>, count: usize) -> HashMap<String, String> {
    let buf = look.buf;
    let mut out = HashMap::new();
    let mut key: Option<String> = None;
    for _ in 0..count {
        match look.next_token() {
            Some(Tok::Name(s, e)) => {
                key = Some(String::from_utf8_lossy(&decode_name(&buf[s..e]).0).into_owned());
            }
            Some(Tok::Str(_, bytes)) => {
                if let Some(k) = key.take() {
                    out.entry(k).or_insert_with(|| pdf_text(&bytes));
                }
            }
            None => break,
            _ => {}
        }
    }
    out
}

fn handle_name(name: &str, site: &NameSite<'_>, state: &mut ScanState, ctx: &mut ObjCtx) {
    let NameSite {
        buf,
        after,
        offset,
        decoded,
        cur_obj,
    } = *site;
    let mut look = Lexer::at(buf, after);
    match name {
        "Type" => {
            if let Some(Tok::Name(s, e)) = look.next_token() {
                let (value, _) = decode_name(&buf[s..e]);
                match value.as_slice() {
                    b"Page" => match cur_obj {
                        Some(num) if !decoded && state.page_objects.len() < MAX_OBJECT_TABLE => {
                            state.page_objects.insert(num);
                        }
                        _ => state.page_marks_unkeyed += 1,
                    },
                    b"ObjStm" => ctx.is_objstm = true,
                    b"EmbeddedFile" => ctx.is_embedded_file = true,
                    _ => {}
                }
            }
        }
        "Subtype" => {
            if let Some(Tok::Name(s, e)) = look.next_token() {
                if &buf[s..e] == b"Image" {
                    ctx.skip_decode = true;
                }
            }
        }
        "Length1" | "Length2" | "FontFile" => ctx.skip_decode = true,
        "Filter" => match look.next_token() {
            Some(Tok::Name(s, e)) => ctx.filters.push(decode_name(&buf[s..e]).0),
            Some(Tok::ArrayOpen) => {
                for _ in 0..6 {
                    match look.next_token() {
                        Some(Tok::Name(s, e)) => ctx.filters.push(decode_name(&buf[s..e]).0),
                        _ => break,
                    }
                }
            }
            _ => {}
        },
        "JS" => match look.next_token() {
            Some(Tok::Str(_, bytes)) => {
                if state.scripts.len() >= MAX_ITEMS {
                    state.scripts_total += 1;
                } else {
                    push_script(state, offset, cur_obj, &pdf_text(&bytes));
                }
            }
            Some(Tok::Word(s, e)) => {
                if let (Some(num), Some(Tok::Word(gs, ge)), Some(Tok::Word(rs, re))) =
                    (word_int(buf, s, e), look.next_token(), look.next_token())
                {
                    if word_int(buf, gs, ge).is_some() && &buf[rs..re] == b"R" {
                        if state.script_refs.len() < MAX_ITEMS {
                            state.script_refs.push((offset, cur_obj, num));
                        } else {
                            state.scripts_total += 1;
                        }
                    }
                }
            }
            _ => {}
        },
        "URI" => {
            if let Some(Tok::Str(_, bytes)) = look.next_token() {
                state.links_total += 1;
                state.targets_total += 1;
                if state.targets.len() - state.action_targets_kept < MAX_LINK_TARGETS {
                    state.targets.push(PdfTarget {
                        kind: "URI".to_string(),
                        value: cut_text(&pdf_text(&bytes), 300),
                        offset,
                    });
                }
            }
        }
        "Launch" | "SubmitForm" => {
            state.targets_total += 1;
            if state.action_targets_kept >= MAX_ITEMS {
                return;
            }
            // The target sits in the same action dictionary, before or after this name.
            let mut pairs = match (decoded, cur_obj) {
                (false, Some(num)) => cached_dict_strings(state, buf, num),
                _ => HashMap::new(),
            };
            for (key, value) in pairs_ahead(&mut look, 40) {
                pairs.entry(key).or_insert(value);
            }
            let target = ["F", "UF", "D"]
                .iter()
                .find_map(|key| pairs.get(*key).cloned());
            let mut value = target.unwrap_or_default();
            if let Some(params) = pairs.get("P") {
                value = format!("{value} {params}").trim().to_string();
            }
            {
                state.action_targets_kept += 1;
                state.targets.push(PdfTarget {
                    kind: name.to_string(),
                    value: cut_text(&value, 300),
                    offset,
                });
            }
        }
        "OpenAction" if state.open_action_type.is_none() => {
            // `/OpenAction << /S /JavaScript ... >>`, or a reference to the action object.
            let mut tokens = Vec::new();
            for _ in 0..12 {
                match look.next_token() {
                    Some(token) => tokens.push(token),
                    None => break,
                }
            }
            let mut found = None;
            for window in tokens.windows(2) {
                if let (Tok::Name(s, e), Tok::Name(vs, ve)) = (&window[0], &window[1]) {
                    if &buf[*s..*e] == b"S" {
                        found = Some(
                            String::from_utf8_lossy(&decode_name(&buf[*vs..*ve]).0).into_owned(),
                        );
                        break;
                    }
                }
            }
            state.open_action_type = Some(found.unwrap_or_else(|| "action".to_string()));
        }
        "Encrypt" => match look.next_token() {
            Some(Tok::DictOpen) => {
                // One parse is enough; a file of repeated `/Encrypt <<` must not cost one each.
                if state.encryption.is_none() {
                    state.encryption = Some(parse_encrypt_dict(buf, look.pos));
                }
            }
            Some(Tok::Word(s, e)) => {
                if let Some(num) = word_int(buf, s, e) {
                    state.encrypt_ref = Some(num);
                }
            }
            _ => {}
        },
        "EF" if !decoded => {
            state.attachments_total += 1;
            // Past this many, the references are only counted: a look-ahead per name would
            // let a file of nothing but `/EF` cost far more than it weighs.
            if state.attachment_refs.len() >= MAX_ITEMS || state.attachments_total > 4 * MAX_ITEMS {
                return;
            }
            // `/EF << /F N 0 R >>`: remember the stream object, resolve its size later.
            let mut tokens = Vec::new();
            for _ in 0..8 {
                match look.next_token() {
                    Some(token) => tokens.push(token),
                    None => break,
                }
            }
            for pair in tokens.windows(2) {
                if let (Tok::Name(_, _), Tok::Word(s, e)) = (&pair[0], &pair[1]) {
                    if let Some(num) = word_int(buf, *s, *e) {
                        state.attachment_refs.push((offset as usize, num));
                        let strings = cur_obj
                            .map_or_else(HashMap::new, |n| cached_dict_strings(state, buf, n));
                        if let Some(filename) =
                            strings.get("UF").or_else(|| strings.get("F")).cloned()
                        {
                            state.attachment_names.insert(offset as usize, filename);
                        }
                        break;
                    }
                }
            }
        }
        key if INFO_KEYS.contains(&key) && !decoded => {
            if let Some(Tok::Str(_, bytes)) = look.next_token() {
                state
                    .info
                    .entry(key.to_string())
                    .or_insert_with(|| cut_text(&pdf_text(&bytes), 200));
            }
        }
        _ => {}
    }
}

/// The name/string pairs of object `num`'s dictionary, read once per object.
fn cached_dict_strings(state: &mut ScanState, buf: &[u8], num: u32) -> HashMap<String, String> {
    if let Some(hit) = state.dict_cache.get(&num) {
        return hit.clone();
    }
    let strings = state
        .objects
        .get(&num)
        .map_or_else(HashMap::new, |o| dict_strings(buf, o.body));
    state.dict_cache.insert(num, strings.clone());
    strings
}

fn push_script(state: &mut ScanState, offset: u64, object: Option<u32>, code: &str) {
    state.scripts_total += 1;
    if state.scripts.len() >= MAX_ITEMS {
        return;
    }
    state.scripts.push(PdfScript {
        offset,
        object,
        length: code.len(),
        preview: cut_text(code.trim(), JS_PREVIEW_CHARS),
        suspicious_patterns: js_patterns(code),
    });
}

/// Name/string pairs of the dictionary that starts at `from` (at most 400 tokens).
fn dict_strings(buf: &[u8], from: usize) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut lexer = Lexer::at(buf, from);
    let mut key: Option<String> = None;
    for _ in 0..400 {
        match lexer.next_token() {
            Some(Tok::Name(s, e)) => {
                key = Some(String::from_utf8_lossy(&decode_name(&buf[s..e]).0).into_owned())
            }
            Some(Tok::Str(_, bytes)) => {
                if let Some(k) = key.take() {
                    out.entry(k)
                        .or_insert_with(|| cut_text(&pdf_text(&bytes), 300));
                }
            }
            Some(Tok::Word(s, e)) if &buf[s..e] == b"endobj" => break,
            None => break,
            _ => {}
        }
    }
    out
}

fn parse_encrypt_dict(buf: &[u8], from: usize) -> EncryptionInfo {
    let mut lexer = Lexer::at(buf, from);
    let mut key: Option<String> = None;
    let (mut version, mut revision, mut length) = (None, None, None);
    let mut filter = None;
    let (mut owner, mut user) = (false, false);
    let mut depth = 1;
    for _ in 0..300 {
        match lexer.next_token() {
            Some(Tok::DictOpen) => depth += 1,
            Some(Tok::DictClose) => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            Some(Tok::Name(s, e)) => {
                let text = String::from_utf8_lossy(&decode_name(&buf[s..e]).0).into_owned();
                if key.as_deref() == Some("Filter") && filter.is_none() {
                    filter = Some(text.clone());
                }
                key = Some(text);
            }
            Some(Tok::Word(s, e)) => match key.as_deref() {
                Some("V") => version = word_int(buf, s, e),
                Some("R") => revision = word_int(buf, s, e),
                Some("Length") => length = word_int(buf, s, e),
                _ => {}
            },
            Some(Tok::Str(_, bytes)) => match key.as_deref() {
                Some("O") => owner = !bytes.is_empty(),
                Some("U") => user = !bytes.is_empty(),
                _ => {}
            },
            None => break,
            _ => {}
        }
    }
    let algorithm = match (version, length) {
        (Some(1), _) => "RC4 40-bit".to_string(),
        (Some(2 | 3), Some(bits)) => format!("RC4 {bits}-bit"),
        (Some(4), _) => "RC4 or AES-128 (crypt filters)".to_string(),
        (Some(5), _) => "AES-256".to_string(),
        _ => format!(
            "{} (version unknown)",
            filter.unwrap_or_else(|| "Standard".to_string())
        ),
    };
    EncryptionInfo {
        algorithm,
        key_length: length.unwrap_or(match version {
            Some(1) => 40,
            Some(4) => 128,
            Some(5) => 256,
            _ => 0,
        }),
        revision: revision.unwrap_or(0),
        is_owner_password_set: owner,
        is_user_password_set: user,
    }
}

fn inflate(data: &[u8], cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = Vec::new();
    let mut decoder = flate2::read::ZlibDecoder::new(data).take(cap as u64);
    // A corrupt or encrypted stream still yields whatever decoded before the error.
    let _ = decoder.read_to_end(&mut out);
    out
}

/// Read up to [`MAX_PDF_BYTES`] of a PDF and scan its structure.
///
/// Counts objects, streams and pages; finds the risk-bearing names (including hex-escaped
/// spellings and names inside Flate-compressed object streams) with byte offsets; reads
/// JavaScript, URI, launch and attachment details; and scores the result.
pub fn scan_pdf<P: AsRef<Path>>(path: P) -> Result<PdfScan> {
    use std::io::Read;
    let path = path.as_ref();
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let file_size = file.metadata()?.len();
    let mut buf = Vec::new();
    file.take(MAX_PDF_BYTES as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let scan_truncated = file_size > buf.len() as u64;

    let head = &buf[..buf.len().min(1024)];
    let header_offset = find_bytes(head, b"%PDF-", 0).ok_or_else(|| {
        anyhow::anyhow!("Not a valid PDF file: no %PDF- header in the first 1024 bytes")
    })?;
    let version_bytes: Vec<u8> = buf[header_offset + 5..]
        .iter()
        .take(8)
        .take_while(|b| b.is_ascii_digit() || **b == b'.')
        .copied()
        .collect();
    let version = if version_bytes.is_empty() {
        "unknown".to_string()
    } else {
        String::from_utf8_lossy(&version_bytes).into_owned()
    };

    let mut state = ScanState {
        rescan_budget: RESCAN_BUDGET,
        ..ScanState::default()
    };
    STRING_BUDGET.with(|budget| budget.set(FAILED_STRING_BUDGET));
    STRING_BUDGET_HIT.with(|hit| hit.set(false));
    scan_syntax(&buf, header_offset, false, 0, None, &mut state, false);
    rescan_hidden(&buf, header_offset, &mut state);
    rescan_unrecorded(&buf, header_offset, &mut state);

    // Phase two: references that needed the whole file.
    let refs = std::mem::take(&mut state.script_refs);
    for (offset, owner, target) in refs {
        // Several references to one object are one script: resolve each object once.
        if !state.resolved_scripts.insert(target) {
            state.scripts_total += 1;
            continue;
        }
        if state.scripts.len() >= MAX_ITEMS {
            state.scripts_total += 1;
            continue;
        }
        if let Some(code) = resolve_text_object(&buf, &mut state, target) {
            push_script(&mut state, offset, owner, &code);
        }
    }
    if let Some(num) = state.encrypt_ref {
        if let Some(info) = state.objects.get(&num) {
            let mut lexer = Lexer::at(&buf, info.body);
            if matches!(lexer.next_token(), Some(Tok::DictOpen)) {
                state.encryption = Some(parse_encrypt_dict(&buf, lexer.pos));
            }
        }
    }
    let attachment_refs = std::mem::take(&mut state.attachment_refs);
    for (offset, target) in attachment_refs {
        let size = state
            .objects
            .get(&target)
            .and_then(|o| o.stream)
            .map(|(s, e)| (e - s) as u64);
        let filename = state.attachment_names.remove(&offset);
        if let Some(existing) = state
            .attachments
            .iter_mut()
            .find(|a| a.object == Some(target))
        {
            if existing.filename.is_none() {
                existing.filename = filename;
            }
        } else if state.attachments.len() < MAX_ITEMS {
            state.attachments.push(PdfAttachment {
                filename,
                size,
                offset: offset as u64,
                object: Some(target),
            });
        }
    }

    let page_count = state.page_objects.len() as u32 + state.page_marks_unkeyed;
    let is_encrypted = state.features.contains_key("Encrypt");
    let encryption = if is_encrypted {
        Some(state.encryption.clone().unwrap_or(EncryptionInfo {
            algorithm: "Standard (parameters not readable)".to_string(),
            key_length: 0,
            revision: 0,
            is_owner_password_set: false,
            is_user_password_set: false,
        }))
    } else {
        None
    };

    let mut notes = std::mem::take(&mut state.notes);
    if scan_truncated {
        notes.push(format!(
            "Only the first {MAX_PDF_BYTES} bytes of {file_size} were scanned."
        ));
    }
    if is_encrypted {
        notes.push(
            "The document is encrypted: stream contents (including JavaScript and object \
             streams) cannot be read, so features inside them are not counted."
                .to_string(),
        );
    }
    if state.undecoded_streams > 0 {
        notes.push(format!(
            "{} stream(s) use a filter other than Flate first and were not decoded.",
            state.undecoded_streams
        ));
    }
    if header_offset > 0 {
        notes.push(format!(
            "{header_offset} bytes of data precede the %PDF- header."
        ));
    }
    if state.scripts_total > state.scripts.len() {
        notes.push(format!(
            "{} script reference(s) found; {} script(s) are listed (duplicates of one object \
             and anything past {MAX_ITEMS} are not).",
            state.scripts_total,
            state.scripts.len()
        ));
    }
    if state.targets_total > state.targets.len() {
        notes.push(format!(
            "{} link, launch and submit target(s) found; {} are listed (the first {MAX_LINK_TARGETS} \
             links, and only the first {MAX_ITEMS} launch and submit targets). The rest cannot \
             be retrieved; search_strings finds a specific URL in the file.",
            state.targets_total,
            state.targets.len()
        ));
    }
    if state.attachments_total > state.attachments.len() {
        notes.push(format!(
            "{} attachment reference(s) found; only the first {MAX_ITEMS} are listed.",
            state.attachments_total
        ));
    }
    if STRING_BUDGET_HIT.with(std::cell::Cell::get) {
        notes.push(
            "The file has a very large number of unterminated ( strings; scanning of strings \
             was cut short, so later keywords may be missed."
                .to_string(),
        );
    }
    if state.content_budget_hit {
        notes.push(format!(
            "Decompression of page, font and other streams stopped at {MAX_CONTENT_INFLATE} \
             bytes in total; later streams were not read."
        ));
    }
    if state.objstm_budget_hit {
        notes.push(format!(
            "Decompression of object streams stopped at {MAX_OBJSTM_INFLATE} bytes in total; \
             later object streams were not read."
        ));
    }
    if state.script_budget_hit {
        notes.push(format!(
            "Reading of script streams stopped at {MAX_SCRIPT_INFLATE} bytes in total; later \
             scripts were not read."
        ));
    }
    if state.streams_cut > 0 {
        notes.push(format!(
            "{} stream(s) hold more than {MAX_STREAM_INFLATE} bytes once decompressed; only the \
             first {MAX_STREAM_INFLATE} bytes of each were read.",
            state.streams_cut
        ));
    }
    if state.objstm_unread > 0 && !is_encrypted {
        notes.push(format!(
            "{} object stream(s) could not be read (decompression budget, an unsupported \
             filter, corrupt data or too long), so objects inside them are not counted.",
            state.objstm_unread
        ));
    }
    if state.window_cut_objects > 0 {
        notes.push(format!(
            "{} object(s) run past the 1 MiB read for one object; the rest of each was not read.",
            state.window_cut_objects
        ));
    }
    if state.hidden_regions > 0 {
        notes.push(format!(
            "{} region(s) of stream data hold PDF objects ({} object(s)) that a reader following \
             the cross-reference table or rebuilding the file would see; they were read as \
             top-level syntax. Defining objects inside a stream is a way to hide them.",
            state.hidden_regions, state.hidden_objects_seen
        ));
    }
    if state.missed_objects > 0 {
        notes.push(format!(
            "{} object(s) the cross-reference table points at were missed by the first read \
             (an unbalanced string or similar) and were read from their offsets.",
            state.missed_objects
        ));
    }
    if state.searched_objects > 0 {
        notes.push(format!(
            "{} object(s) were missed by the first read (an unbalanced string or similar) and \
             were found by searching the whole file for object headers.",
            state.searched_objects
        ));
    }
    if state.rescan_budget_hit || state.single_rescan_cap_hit {
        notes.push(
            "The second pass over stream data and cross-reference offsets stopped at its work \
             limit; some hidden objects may not have been read."
                .to_string(),
        );
    }
    if state.xref_entries_capped {
        notes.push(format!(
            "More than {MAX_XREF_ENTRIES} cross-reference entries; the rest were not checked."
        ));
    }
    if state.ranges_capped {
        notes.push(format!(
            "More than {MAX_STREAM_RANGES} streams; those after the first {MAX_STREAM_RANGES} \
             were not checked for hidden objects."
        ));
    }
    if state.objects_capped {
        notes.push(format!(
            "More than {MAX_OBJECT_TABLE} distinct objects; later ones are counted but cannot be \
             looked up, so references to them are not followed."
        ));
    }
    if state.unterminated_streams > 0 {
        notes.push(format!(
            "{} stream(s) have no endstream keyword; the rest of the file was treated as stream data.",
            state.unterminated_streams
        ));
    }
    if state.object_count == 0 {
        notes.push(
            "No objects were found: the file has a PDF header but no readable PDF body, so it \
             may be damaged, not a PDF, or hide its content."
                .to_string(),
        );
    } else if state.trailers == 0
        && state.xref_sections == 0
        && !state.features.contains_key("XRef")
    {
        notes.push(
            "No xref table or trailer was found: the file may be truncated or rebuilt on open."
                .to_string(),
        );
    }

    let features: Vec<PdfFeature> = state
        .features
        .iter()
        .map(|(name, (count, evidence))| PdfFeature {
            name: name.clone(),
            count: *count,
            evidence: evidence.clone(),
        })
        .collect();

    let mut unread = Vec::new();
    if scan_truncated {
        unread.push(format!(
            "only the first {MAX_PDF_BYTES} of {file_size} bytes were scanned"
        ));
    }
    if state.content_budget_hit {
        unread.push("decompression budget for page and other streams ran out".to_string());
    }
    if state.objstm_budget_hit {
        unread.push("decompression budget for object streams ran out".to_string());
    }
    if state.script_budget_hit {
        unread.push("script stream budget ran out".to_string());
    }
    if state.objstm_unread > 0 && !is_encrypted {
        unread.push(format!(
            "{} object stream(s) could not be read",
            state.objstm_unread
        ));
    }
    if state.window_cut_objects > 0 {
        unread.push(format!(
            "{} object(s) are longer than the 1 MiB read for one object",
            state.window_cut_objects
        ));
    }
    if state.rescan_budget_hit || state.single_rescan_cap_hit {
        unread.push("the search for objects hidden in stream data hit its limit".to_string());
    }
    if state.objects_capped || state.ranges_capped || state.xref_entries_capped {
        unread.push("a table size limit was reached".to_string());
    }
    if STRING_BUDGET_HIT.with(std::cell::Cell::get) {
        unread.push("string scanning was cut short".to_string());
    }
    let attachments_len = state.attachments.len();
    let attachments_total = state
        .attachments_total
        .max(state.embedded_streams_total)
        .max(attachments_len);
    let mut scan = PdfScan {
        version,
        header_offset: header_offset as u64,
        file_size,
        bytes_scanned: buf.len() as u64,
        scan_truncated,
        object_count: state.object_count,
        stream_count: state.stream_count,
        page_count,
        xref_sections: state.xref_sections,
        trailers: state.trailers,
        is_encrypted,
        encryption,
        is_linearized: state.features.contains_key("Linearized"),
        is_signed: state.features.contains_key("ByteRange"),
        object_streams: state.object_streams,
        features,
        escaped_names: state.escaped_names,
        scripts: state.scripts,
        targets: state.targets,
        attachments: state.attachments,
        scripts_total: state.scripts_total,
        links_total: state.links_total,
        action_targets_total: state.targets_total.saturating_sub(state.links_total),
        attachments_total,
        object_streams_total: state.object_streams_total,
        unread,
        open_action_type: state.open_action_type,
        info: state.info,
        notes,
        risk_score: 0,
        overall_risk: RiskLevel::Low,
        risk_reasons: Vec::new(),
    };
    score_scan(&mut scan);
    Ok(scan)
}

/// The object number and body position when `buf` holds `N G obj` at `pos`.
fn obj_header_at(buf: &[u8], pos: usize) -> Option<(u32, usize)> {
    let mut lexer = Lexer::at(buf, pos);
    let Some(Tok::Word(a, b)) = lexer.next_token() else {
        return None;
    };
    let num = word_int(buf, a, b)?;
    let Some(Tok::Word(ga, gb)) = lexer.next_token() else {
        return None;
    };
    word_int(buf, ga, gb)?;
    let Some(Tok::Word(oa, ob)) = lexer.next_token() else {
        return None;
    };
    (&buf[oa..ob] == b"obj").then_some((num, ob))
}

/// Start of the first `N G obj` header inside `buf[start..end]`.
fn find_obj_marker(buf: &[u8], start: usize, end: usize) -> Option<usize> {
    find_obj_header(buf, start, end).map(|(at, _)| at)
}

/// Walk back from `k` over bytes that satisfy `pred`, but not below `floor`.
fn walk_back(slice: &[u8], floor: usize, mut k: usize, pred: fn(u8) -> bool) -> usize {
    while k > floor && pred(slice[k - 1]) {
        k -= 1;
    }
    k
}

/// Start of the first `N G obj` header inside `buf[start..end]` and the end of its `obj`
/// keyword. Any amount of white space and any number of digits (leading zeros) is accepted,
/// as a reader does; whether the numbers fit is checked by `obj_header_at`. Work is linear
/// in the bytes searched: a header cannot contain an earlier `obj`, so each walk back stops at
/// the end of the previous marker and every byte is walked over at most once.
fn find_obj_header(buf: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let slice = &buf[..end.min(buf.len())];
    let mut from = start;
    while let Some(at) = find_bytes(slice, b"obj", from) {
        let floor = from;
        from = at + 3;
        if slice
            .get(at + 3)
            .is_some_and(|&b| !is_ws(b) && !is_delim(b))
        {
            continue;
        }
        let generation_end = walk_back(slice, floor, at, is_ws);
        if generation_end == at || generation_end == floor {
            continue;
        }
        let space_end = walk_back(slice, floor, generation_end, |b| b.is_ascii_digit());
        if space_end == generation_end || space_end == floor {
            continue;
        }
        let number_end = walk_back(slice, floor, space_end, is_ws);
        if number_end == space_end || number_end == floor {
            continue;
        }
        let k = walk_back(slice, floor, number_end, |b| b.is_ascii_digit());
        if k == number_end {
            continue;
        }
        if k > start && !is_ws(slice[k - 1]) && !is_delim(slice[k - 1]) {
            continue;
        }
        return Some((k, at + 3));
    }
    None
}

impl ScanState {
    /// Take `bytes` from the second-pass work budget; false (and a flag) when it is spent.
    fn spend_rescan(&mut self, bytes: usize) -> bool {
        if bytes > self.rescan_budget {
            self.rescan_budget_hit = true;
            self.rescan_budget = 0;
            return false;
        }
        self.rescan_budget -= bytes;
        true
    }
}

/// In-use offsets of the classic cross-reference table that starts after the `xref` keyword
/// at `pos`.
fn xref_offsets(buf: &[u8], pos: usize, state: &mut ScanState, out: &mut Vec<usize>) {
    let mut lexer = Lexer::at(buf, pos);
    loop {
        let Some(Tok::Word(a, b)) = lexer.next_token() else {
            return;
        };
        if word_int(buf, a, b).is_none() {
            return;
        }
        let Some(Tok::Word(ca, cb)) = lexer.next_token() else {
            return;
        };
        let Some(count) = word_int(buf, ca, cb) else {
            return;
        };
        // An entry takes at least six bytes, so the table cannot be longer than the file.
        let count = (count as usize).min((buf.len() - lexer.pos.min(buf.len())) / 6);
        for _ in 0..count {
            if state.xref_entries >= MAX_XREF_ENTRIES {
                state.xref_entries_capped = true;
                return;
            }
            let (Some(Tok::Word(oa, ob)), Some(Tok::Word(ga, gb)), Some(Tok::Word(ka, kb))) =
                (lexer.next_token(), lexer.next_token(), lexer.next_token())
            else {
                return;
            };
            state.xref_entries += 1;
            if word_int(buf, ga, gb).is_none() {
                return;
            }
            match &buf[ka..kb] {
                b"n" => {
                    if let Some(offset) = word_int(buf, oa, ob) {
                        out.push(offset as usize);
                    }
                }
                b"f" => {}
                _ => return,
            }
        }
    }
}

/// The second pass. A reader follows the cross-reference table (or rebuilds the file by
/// looking for `N G obj` anywhere), so objects the first, linear read stepped over still
/// count: the data of a stream that never gets decoded, or text a stray string swallowed.
/// Read them as top-level syntax, within a work budget.
fn rescan_hidden(buf: &[u8], header_offset: usize, state: &mut ScanState) {
    for _ in 0..MAX_RESCAN_ROUNDS {
        let mut progressed = false;
        // 1. Object headers inside stream data nobody decoded.
        let mut index = 0;
        while index < state.streams.len() {
            let range = state.streams[index];
            index += 1;
            if !range.candidate || state.rescanned.contains_key(&range.start) {
                continue;
            }
            if !state.spend_rescan(range.end - range.start) {
                return;
            }
            state.rescanned.insert(range.start, usize::MAX);
            if let Some(at) = find_obj_marker(buf, range.start, range.end) {
                if !state.spend_rescan(range.end - at) {
                    return;
                }
                state.rescanned.insert(range.start, at);
                let before = state.object_count;
                state.hidden_regions += 1;
                scan_syntax(&buf[..range.end], at, false, 0, None, state, false);
                state.hidden_objects_seen += state.object_count - before;
                progressed = true;
            }
        }
        // 2. Offsets the cross-reference tables point at.
        let mut offsets = Vec::new();
        while state.xref_done < state.xref_positions.len() {
            let pos = state.xref_positions[state.xref_done];
            state.xref_done += 1;
            xref_offsets(buf, pos, state, &mut offsets);
        }
        if !offsets.is_empty() {
            let mut sorted: Vec<StreamRange> = state.streams.clone();
            sorted.sort_by_key(|r| r.start);
            let mut earliest: std::collections::BTreeMap<(usize, usize), usize> =
                std::collections::BTreeMap::new();
            let mut missing: Vec<usize> = Vec::new();
            for raw in offsets {
                let offset = raw.saturating_add(header_offset);
                let Some((number, _)) = obj_header_at(buf, offset) else {
                    continue;
                };
                let slot = sorted.partition_point(|r| r.start <= offset);
                let inside = sorted[..slot]
                    .iter()
                    .rev()
                    .take(4)
                    .find(|r| offset < r.end)
                    .copied();
                if let Some(range) = inside {
                    let entry = earliest.entry((range.start, range.end)).or_insert(offset);
                    *entry = (*entry).min(offset);
                } else if !state.objects_capped
                    && !state.objects.contains_key(&number)
                    && missing.len() < MAX_SINGLE_RESCANS
                {
                    missing.push(offset);
                }
            }
            for ((start, end), offset) in earliest {
                let done = state.rescanned.get(&start).copied().unwrap_or(usize::MAX);
                if (state.rescanned.contains_key(&start) && done <= offset) || offset >= end {
                    continue;
                }
                if !state.spend_rescan(end - offset) {
                    return;
                }
                state.rescanned.insert(start, offset);
                let before = state.object_count;
                state.hidden_regions += 1;
                scan_syntax(&buf[..end], offset, false, 0, None, state, false);
                state.hidden_objects_seen += state.object_count - before;
                progressed = true;
            }
            for offset in missing {
                if state.single_rescans >= MAX_SINGLE_RESCANS {
                    state.single_rescan_cap_hit = true;
                    break;
                }
                let Some((number, start_body)) = obj_header_at(buf, offset) else {
                    continue;
                };
                if state.objects.contains_key(&number) {
                    continue;
                }
                let end = buf.len().min(offset + MAX_SINGLE_RESCAN_BYTES);
                if !state.spend_rescan(MIN_SINGLE_RESCAN_CHARGE.min(end - offset)) {
                    return;
                }
                state.single_rescans += 1;
                state.missed_objects += 1;
                let stop = scan_syntax(&buf[..end], offset, false, 0, None, state, true);
                release_cut_object(buf.len(), end, start_body, &stop, state);
                let read = stop.pos.saturating_sub(offset);
                if !state.spend_rescan(read.saturating_sub(MIN_SINGLE_RESCAN_CHARGE)) {
                    return;
                }
                progressed = true;
            }
        }
        if !progressed {
            return;
        }
    }
}

/// Whatever the cross-reference data says (a stray table, a stream, nothing): a reader
/// can rebuild the object list by looking for `N G obj` anywhere. Read every header the first
/// pass did not record as an object (text swallowed by a stray string, say), within limits.
fn rescan_unrecorded(buf: &[u8], header_offset: usize, state: &mut ScanState) {
    if state.objects_capped {
        return;
    }
    let mut from = header_offset;
    while let Some((at, keyword_end)) = find_obj_header(buf, from, buf.len()) {
        from = keyword_end;
        let Some((_, body)) = obj_header_at(buf, at) else {
            continue;
        };
        let start_body = body;
        if state.obj_bodies.contains(&body) {
            continue;
        }
        if state.single_rescans >= MAX_SINGLE_RESCANS {
            state.single_rescan_cap_hit = true;
            return;
        }
        let end = buf.len().min(at + MAX_SINGLE_RESCAN_BYTES);
        if !state.spend_rescan(MIN_SINGLE_RESCAN_CHARGE.min(end - at)) {
            return;
        }
        state.single_rescans += 1;
        state.searched_objects += 1;
        let stop = scan_syntax(&buf[..end], at, false, 0, None, state, true);
        // An object a window cut that started later is read again in a window of its own
        // when the search reaches its header; the window's own object is kept and flagged.
        release_cut_object(buf.len(), end, start_body, &stop, state);
        let read = stop.pos.saturating_sub(at);
        if !state.spend_rescan(read.saturating_sub(MIN_SINGLE_RESCAN_CHARGE)) {
            return;
        }
    }
}

fn resolve_text_object(buf: &[u8], state: &mut ScanState, target: u32) -> Option<String> {
    let info = state.objects.get(&target)?.clone();
    if let Some((start, end)) = info.stream {
        let raw = &buf[start..end];
        let room = MAX_SCRIPT_INFLATE.saturating_sub(state.inflated_scripts);
        let cap = MAX_STREAM_INFLATE.min(room);
        if cap == 0 {
            state.script_budget_hit = true;
            return None;
        }
        let bytes = if info.flate {
            inflate(raw, cap)
        } else {
            raw[..raw.len().min(cap)].to_vec()
        };
        state.inflated_scripts += bytes.len();
        return Some(pdf_text(&bytes));
    }
    let mut lexer = Lexer::at(buf, info.body);
    match lexer.next_token() {
        Some(Tok::Str(_, bytes)) => Some(pdf_text(&bytes)),
        _ => None,
    }
}

fn feature_count(scan: &PdfScan, name: &str) -> u32 {
    scan.features
        .iter()
        .find(|f| f.name == name)
        .map_or(0, |f| f.count)
}

fn score_scan(scan: &mut PdfScan) {
    let mut score = 0u32;
    let mut reasons = Vec::new();
    let mut add = |points: u32, reason: String| {
        score += points;
        reasons.push(reason);
    };
    if scan.object_count == 0 {
        add(
            15,
            "Nothing could be read: no PDF object was found, so hidden content cannot be ruled out"
                .to_string(),
        );
    }
    let js = feature_count(scan, "JavaScript").max(feature_count(scan, "JS"));
    if js > 0 {
        add(30, format!("JavaScript present ({js} reference(s))"));
    }
    if feature_count(scan, "Launch") > 0 {
        add(35, "Launch action (starts another program)".to_string());
    }
    let open = feature_count(scan, "OpenAction");
    if open > 0 {
        add(15, "OpenAction runs when the document opens".to_string());
        if js > 0 {
            add(20, "OpenAction together with JavaScript".to_string());
        }
    }
    if feature_count(scan, "AA") > 0 {
        add(10, "Additional actions (/AA) run on events".to_string());
    }
    if feature_count(scan, "EmbeddedFile") + feature_count(scan, "EmbeddedFiles") > 0 {
        add(15, "Embedded file(s)".to_string());
    }
    if feature_count(scan, "RichMedia") > 0 {
        add(15, "RichMedia content".to_string());
    }
    if feature_count(scan, "SubmitForm") + feature_count(scan, "ImportData") > 0 {
        add(10, "Form submit or import action".to_string());
    }
    if feature_count(scan, "GoToR") + feature_count(scan, "GoToE") > 0 {
        add(10, "Jump to a remote or embedded document".to_string());
    }
    if feature_count(scan, "XFA") > 0 {
        add(
            10,
            "XFA forms (scriptable, large attack surface)".to_string(),
        );
    }
    if feature_count(scan, "JBIG2Decode") > 0 {
        add(10, "JBIG2 image filter (a past exploit vector)".to_string());
    }
    if scan.is_encrypted {
        add(10, "Encrypted: content cannot be inspected".to_string());
    }
    if !scan.escaped_names.is_empty() {
        add(
            15,
            format!(
                "Names written with #xx escapes ({}): a way to hide keywords",
                scan.escaped_names.join(", ")
            ),
        );
    }
    if feature_count(scan, "EmbeddedFile") + feature_count(scan, "EmbeddedFiles") == 0
        && scan.attachments_total > 0
    {
        add(15, "Embedded file(s)".to_string());
    }
    if scan
        .notes
        .iter()
        .any(|n| n.contains("found by searching the whole file"))
    {
        add(
            5,
            "Objects the first read missed were found by searching the whole file: the \
             structure is not one a reader follows cleanly"
                .to_string(),
        );
    }
    if scan.notes.iter().any(|n| n.contains("hold PDF objects")) {
        add(
            15,
            "Objects are defined inside stream data (hidden from a linear reader)".to_string(),
        );
    }
    let uris = scan
        .links_total
        .max(scan.targets.iter().filter(|t| t.kind == "URI").count());
    if uris > 0 {
        add(uris.min(3) as u32, format!("{uris} link(s)"));
    }
    if !scan.unread.is_empty() {
        add(
            10,
            format!(
                "Not everything was read ({}): hidden content cannot be ruled out",
                scan.unread.join("; ")
            ),
        );
    }
    scan.risk_score = score.min(100) as u8;
    scan.overall_risk = match scan.risk_score {
        0..=9 => RiskLevel::Low,
        10..=29 => RiskLevel::Medium,
        30..=59 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };
    scan.risk_reasons = reasons;
}

/// Main entry point for PDF analysis: the structural scan, shaped into the report types.
pub fn analyze_pdf<P: AsRef<Path>>(path: P) -> Result<PdfAnalysis> {
    let scan = scan_pdf(path)?;
    Ok(scan_to_analysis(&scan))
}

fn scan_to_analysis(scan: &PdfScan) -> PdfAnalysis {
    let has = |name: &str| feature_count(scan, name) > 0;
    let has_js = has("JavaScript") || has("JS");
    let info = |key: &str| scan.info.get(key).cloned();

    let document_info = PdfDocumentInfo {
        version: scan.version.clone(),
        page_count: scan.page_count,
        file_size: scan.file_size,
        producer: info("Producer"),
        creator: info("Creator"),
        creation_date: info("CreationDate"),
        modification_date: info("ModDate"),
        is_linearized: scan.is_linearized,
        is_encrypted: scan.is_encrypted,
        is_signed: scan.is_signed,
    };

    let structure = PdfStructure {
        pages: Vec::new(),
        xref_count: scan.xref_sections,
        object_count: scan.object_count,
        stream_count: scan.stream_count,
        catalog_info: CatalogInfo {
            page_layout: None,
            page_mode: None,
            viewer_preferences: HashMap::new(),
            has_acroform: has("AcroForm"),
            has_javascript: has_js,
            has_embedded_files: has("EmbeddedFile") || has("EmbeddedFiles"),
            has_open_action: has("OpenAction"),
            open_action_type: scan.open_action_type.clone(),
        },
        object_streams: scan.object_streams.clone(),
    };

    let security = PdfSecurity {
        encryption: scan.encryption.clone(),
        permissions: PdfPermissions::default(),
        digital_signatures: Vec::new(),
        security_handler: scan.encryption.as_ref().map(|_| "Standard".to_string()),
    };

    let content_analysis = PdfContentAnalysis {
        javascript: scan
            .scripts
            .iter()
            .map(|s| JavaScriptInfo {
                location: format!("offset {}", s.offset),
                code_preview: s.preview.clone(),
                length: s.length,
                obfuscation_score: if s.suspicious_patterns.is_empty() {
                    0.0
                } else {
                    0.5
                },
                suspicious_patterns: s.suspicious_patterns.clone(),
            })
            .collect(),
        embedded_files: scan
            .attachments
            .iter()
            .map(|a| EmbeddedFileInfo {
                filename: a.filename.clone().unwrap_or_default(),
                mime_type: None,
                size: a.size.unwrap_or(0),
                creation_date: None,
                modification_date: None,
                checksum: None,
            })
            .collect(),
        forms: Vec::new(),
        actions: scan
            .features
            .iter()
            .filter(|f| {
                matches!(
                    f.name.as_str(),
                    "OpenAction"
                        | "AA"
                        | "Launch"
                        | "SubmitForm"
                        | "GoToR"
                        | "GoToE"
                        | "ImportData"
                )
            })
            .map(|f| ActionInfo {
                action_type: f.name.clone(),
                trigger: f
                    .evidence
                    .first()
                    .map_or_else(String::new, |e| format!("offset {}", e.offset)),
                target: None,
                javascript_code: None,
                risk_level: if f.name == "Launch" {
                    RiskLevel::Critical
                } else {
                    RiskLevel::Medium
                },
            })
            .collect(),
        urls: scan
            .targets
            .iter()
            .filter(|t| t.kind == "URI")
            .map(|t| t.value.clone())
            .collect(),
        launch_actions: scan
            .targets
            .iter()
            .filter(|t| t.kind == "Launch")
            .map(|t| LaunchActionInfo {
                target_application: t.value.clone(),
                parameters: Vec::new(),
                location: format!("offset {}", t.offset),
                risk_level: RiskLevel::Critical,
            })
            .collect(),
        suspicious_names: scan.escaped_names.clone(),
        redirection_chains: Vec::new(),
    };

    let mut patterns = Vec::new();
    for feature in &scan.features {
        let risky = matches!(
            feature.name.as_str(),
            "JavaScript"
                | "JS"
                | "OpenAction"
                | "AA"
                | "Launch"
                | "EmbeddedFile"
                | "RichMedia"
                | "XFA"
                | "SubmitForm"
                | "GoToR"
                | "ImportData"
                | "JBIG2Decode"
        );
        if risky {
            patterns.push(SuspiciousPattern {
                pattern_type: feature.name.clone(),
                description: format!("/{} occurs {} time(s)", feature.name, feature.count),
                location: feature
                    .evidence
                    .first()
                    .map_or_else(String::new, |e| format!("offset {}", e.offset)),
                confidence: 1.0,
            });
        }
    }
    let suspicious_indicators = PdfSuspiciousIndicators {
        has_javascript: has_js,
        has_embedded_files: has("EmbeddedFile") || has("EmbeddedFiles"),
        has_launch_actions: has("Launch"),
        has_suspicious_names: !scan.escaped_names.is_empty(),
        has_auto_actions: has("OpenAction") || has("AA"),
        javascript_count: scan.scripts.len() as u32,
        embedded_file_count: scan.attachments.len() as u32,
        form_count: feature_count(scan, "AcroForm"),
        suspicious_patterns: patterns,
        exploitation_vectors: Vec::new(),
        risk_score: scan.risk_score,
    };

    let metadata = PdfMetadata {
        title: info("Title"),
        author: info("Author"),
        subject: info("Subject"),
        keywords: info("Keywords"),
        creator: info("Creator"),
        producer: info("Producer"),
        creation_date: info("CreationDate"),
        modification_date: info("ModDate"),
        trapped: info("Trapped"),
        custom_properties: HashMap::new(),
    };

    let risk_assessment = PdfRiskAssessment {
        overall_risk: scan.overall_risk.clone(),
        risk_factors: scan
            .risk_reasons
            .iter()
            .map(|reason| RiskFactor {
                factor_type: "structure".to_string(),
                description: reason.clone(),
                severity: scan.overall_risk.clone(),
                mitigation: "Open only in a sandbox or a viewer with scripting disabled"
                    .to_string(),
            })
            .collect(),
        recommendations: scan.notes.clone(),
        ioc_indicators: scan
            .targets
            .iter()
            .map(|t| IocIndicator {
                indicator_type: t.kind.clone(),
                value: t.value.clone(),
                context: format!("offset {}", t.offset),
                confidence: 0.8,
            })
            .collect(),
    };

    PdfAnalysis {
        document_info,
        structure,
        security,
        content_analysis,
        suspicious_indicators,
        metadata,
        risk_assessment,
    }
}

// Default implementation for RiskAssessment
impl Default for PdfRiskAssessment {
    fn default() -> Self {
        Self {
            overall_risk: RiskLevel::Low,
            risk_factors: Vec::new(),
            recommendations: Vec::new(),
            ioc_indicators: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pdf_analysis_structures() {
        // Test serialization of main structures
        let analysis = PdfAnalysis {
            document_info: PdfDocumentInfo {
                version: "1.4".to_string(),
                page_count: 10,
                file_size: 1024 * 1024,
                producer: Some("Test Producer".to_string()),
                creator: Some("Test Creator".to_string()),
                creation_date: Some("2024-01-01".to_string()),
                modification_date: Some("2024-01-02".to_string()),
                is_linearized: false,
                is_encrypted: false,
                is_signed: false,
            },
            structure: PdfStructure {
                pages: vec![],
                xref_count: 100,
                object_count: 50,
                stream_count: 20,
                catalog_info: CatalogInfo {
                    page_layout: Some("SinglePage".to_string()),
                    page_mode: Some("UseNone".to_string()),
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
                has_embedded_files: false,
                has_launch_actions: false,
                has_suspicious_names: false,
                has_auto_actions: false,
                javascript_count: 1,
                embedded_file_count: 0,
                form_count: 0,
                suspicious_patterns: vec![],
                exploitation_vectors: vec![],
                risk_score: 30,
            },
            metadata: PdfMetadata::default(),
            risk_assessment: PdfRiskAssessment::default(),
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let _deserialized: PdfAnalysis = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_analyze_pdf_non_pdf_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This is not a PDF file").unwrap();
        temp_file.flush().unwrap();

        let result = analyze_pdf(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_pdf_valid_header() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"%PDF-1.4\n").unwrap();
        temp_file.flush().unwrap();

        let result = analyze_pdf(temp_file.path());
        assert!(result.is_ok());
        let analysis = result.unwrap();
        assert_eq!(analysis.document_info.version, "1.4");
    }
}
