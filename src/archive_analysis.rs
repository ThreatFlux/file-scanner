use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::read::ZipArchive;

/// Comprehensive archive analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAnalysis {
    pub archive_type: ArchiveType,
    pub metadata: ArchiveMetadata,
    pub entries: Vec<ArchiveEntry>,
    pub security_analysis: ArchiveSecurityAnalysis,
    pub suspicious_indicators: SuspiciousArchiveIndicators,
    pub nested_archives: Vec<NestedArchiveInfo>,
    /// Limits that were hit or parts that could not be read (for example an
    /// encrypted header or a compressed 7z header). Empty when everything was read.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Most entries any analyzer records; the rest are counted but not listed.
pub const MAX_ENTRIES: usize = 100_000;
/// Most decompressed bytes a compressed archive is read through (1 GiB).
pub const MAX_STREAM_BYTES: u64 = 1 << 30;
/// Prefix of the note an analyzer adds when the entries could not be read at
/// all, so callers can tell "nothing readable" from "an empty archive".
pub const LISTING_UNAVAILABLE: &str = "Entry listing is unavailable";
/// Longest archive or entry comment kept in a result (bytes).
pub(crate) const MAX_COMMENT_BYTES: usize = 512;

/// Space saved by compression, from 0.0 (none, or the container is larger
/// than its content) to 1.0.
pub(crate) fn saved_ratio(compressed: u64, uncompressed: u64) -> f64 {
    if uncompressed == 0 {
        return 0.0;
    }
    (1.0 - compressed as f64 / uncompressed as f64).clamp(0.0, 1.0)
}

/// A comment cut to [`MAX_COMMENT_BYTES`], with its full length when cut.
pub(crate) fn capped_comment(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= MAX_COMMENT_BYTES {
        return text.into_owned();
    }
    let mut end = MAX_COMMENT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes in all)", &text[..end], text.len())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchiveType {
    Zip,
    ZipEncrypted,
    ZipSelfExtracting,
    Rar,
    SevenZip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMetadata {
    pub total_entries: usize,
    pub total_size_compressed: u64,
    pub total_size_uncompressed: u64,
    pub compression_ratio: f64,
    pub has_encryption: bool,
    pub has_password: bool,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub file_name: String,
    pub is_directory: bool,
    pub size_compressed: u64,
    pub size_uncompressed: u64,
    pub compression_method: String,
    pub compression_ratio: f64,
    pub last_modified: Option<String>,
    pub crc32: Option<u32>,
    pub is_encrypted: bool,
    pub is_text: bool,
    pub permissions: Option<u32>,
    pub comment: Option<String>,
    pub file_type: FileType,
    pub risk_indicators: Vec<RiskIndicator>,
    /// What the entry is (file, directory, link, device node, ...).
    #[serde(default)]
    pub entry_kind: EntryKind,
    /// Where a symbolic or hard link points.
    #[serde(default)]
    pub link_target: Option<String>,
}

/// The kind of an archive entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    #[default]
    File,
    Directory,
    Symlink,
    Hardlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    Executable,
    Script,
    Document,
    Archive,
    Image,
    Text,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveSecurityAnalysis {
    pub overall_risk: RiskLevel,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub suspicious_files: Vec<SuspiciousFile>,
    pub path_traversal_risks: Vec<PathTraversalRisk>,
    pub zip_bomb_indicators: ZipBombIndicators,
    pub hidden_content: Vec<HiddenContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPattern {
    pub pattern_type: String,
    pub description: String,
    pub matched_files: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTraversalRisk {
    pub entry_path: String,
    pub resolved_path: String,
    pub risk_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZipBombIndicators {
    pub is_potential_bomb: bool,
    pub compression_ratio: f64,
    pub nesting_level: u32,
    pub recursive_entries: Vec<String>,
    pub quine_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenContent {
    pub content_type: String,
    pub location: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspiciousArchiveIndicators {
    pub has_executable: bool,
    pub has_script: bool,
    pub has_double_extension: bool,
    pub has_path_traversal: bool,
    pub has_hidden_files: bool,
    pub has_suspicious_names: bool,
    pub executable_count: u32,
    pub script_count: u32,
    pub suspicious_patterns: Vec<String>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedArchiveInfo {
    pub path: String,
    pub archive_type: ArchiveType,
    pub size: u64,
    pub depth: u32,
}

/// Main entry point for ZIP analysis
pub fn analyze_zip<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open ZIP file")?;

    let mut archive = ZipArchive::new(file).context("Failed to read ZIP archive")?;

    let mut metadata = extract_zip_metadata(&mut archive)?;
    let mut entries = Vec::new();
    let mut suspicious_indicators = SuspiciousArchiveIndicators::default();
    let mut notes = Vec::new();

    let listed = archive.len().min(MAX_ENTRIES);
    if archive.len() > listed {
        notes.push(format!(
            "Only the first {listed} of {} entries were analyzed.",
            archive.len()
        ));
    }

    // Analyze each entry from its central-directory record; nothing is
    // decompressed, so encrypted entries and unsupported methods still list.
    for i in 0..listed {
        let link_target = zip_symlink_target(&mut archive, i);
        let mut entry = archive.by_index_raw(i)?;
        let entry_info = analyze_zip_entry(&mut entry, link_target, &mut suspicious_indicators)?;
        entries.push(entry_info);
    }
    metadata.has_encryption = entries.iter().any(|e| e.is_encrypted);

    finish_analysis(
        ArchiveType::Zip,
        metadata,
        entries,
        suspicious_indicators,
        notes,
    )
}

/// A bounds-checked little-endian reader over a header buffer. Every read
/// returns `None` past the end, so a damaged header ends parsing instead of
/// panicking.
pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub(crate) fn skip(&mut self, n: usize) -> Option<()> {
        self.bytes(n).map(|_| ())
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub(crate) fn u16le(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32le(&mut self) -> Option<u32> {
        self.bytes(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn u64le(&mut self) -> Option<u64> {
        self.bytes(8).map(|b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            u64::from_le_bytes(a)
        })
    }

    /// RAR 5 variable-length integer: 7 bits per byte, low group first.
    pub(crate) fn rar_vint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// 7z `NUMBER`: the count of leading one bits in the first byte says how
    /// many extra bytes follow.
    pub(crate) fn sevenz_number(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                value |= u64::from(first & (mask - 1)) << (8 * i);
                return Some(value);
            }
            value |= u64::from(self.u8()?) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }
}

/// Entry kind from the file-type bits of a unix mode.
pub(crate) fn unix_kind(mode: u32) -> EntryKind {
    match mode & 0o170_000 {
        0o040_000 => EntryKind::Directory,
        0o120_000 => EntryKind::Symlink,
        0o020_000 => EntryKind::CharDevice,
        0o060_000 => EntryKind::BlockDevice,
        0o010_000 => EntryKind::Fifo,
        _ => EntryKind::File,
    }
}

/// Everything the shared per-entry checks need to know about one entry.
#[derive(Default)]
pub(crate) struct EntrySpec {
    pub path: String,
    pub kind: EntryKind,
    pub size_compressed: u64,
    pub size_uncompressed: u64,
    pub method: String,
    pub last_modified: Option<String>,
    pub crc32: Option<u32>,
    pub is_encrypted: bool,
    pub permissions: Option<u32>,
    pub comment: Option<String>,
    pub link_target: Option<String>,
}

/// Why `path` would write outside the extraction directory, if it would.
pub(crate) fn path_risk(path: &str) -> Option<&'static str> {
    let normalized = path.replace('\\', "/");
    let bytes = normalized.as_bytes();
    if normalized.starts_with('/') {
        return Some("absolute path");
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some("drive-letter path");
    }
    if normalized.split('/').any(|part| part == "..") {
        return Some("parent-directory (..) component");
    }
    None
}

/// `path` with `.` and `..` components resolved lexically; leading `..`
/// components that climb out of the root are kept.
fn lexical_resolve(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." if parts.last().is_some_and(|p| *p != "..") => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if normalized.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Whether a link at `entry_path` that points at `target` leaves the
/// extraction root. `relative_to_entry` is true for symbolic links (resolved
/// from the link's own directory) and false for hard links (from the root).
pub(crate) fn link_escapes(entry_path: &str, target: &str, relative_to_entry: bool) -> bool {
    let target = target.replace('\\', "/");
    if target.starts_with('/') || path_risk(&target) == Some("drive-letter path") {
        return true;
    }
    let mut depth: i64 = 0;
    if relative_to_entry {
        let entry = entry_path.replace('\\', "/");
        let parts: Vec<&str> = entry
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        depth = parts.len().saturating_sub(1) as i64;
    }
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Build an [`ArchiveEntry`] from raw facts and run the checks every format
/// shares (type by extension, double extension, traversal, link escape,
/// device nodes, setuid bits, hidden and suspicious names).
pub(crate) fn build_entry(
    spec: EntrySpec,
    indicators: &mut SuspiciousArchiveIndicators,
) -> ArchiveEntry {
    let path = spec.path;
    let normalized = path.replace('\\', "/");
    let file_name = normalized
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let is_directory = spec.kind == EntryKind::Directory;
    let compression_ratio = saved_ratio(spec.size_compressed, spec.size_uncompressed);

    let file_type = if is_directory {
        FileType::Unknown
    } else {
        determine_file_type(&file_name, &path)
    };
    let mut risk_indicators = Vec::new();
    let mut flag = |indicator_type: &str, description: String, severity: RiskLevel| {
        risk_indicators.push(RiskIndicator {
            indicator_type: indicator_type.to_string(),
            description,
            severity,
        });
    };

    if matches!(file_type, FileType::Executable) {
        indicators.has_executable = true;
        indicators.executable_count += 1;
        flag(
            "Executable",
            "Archive contains executable file".to_string(),
            RiskLevel::Medium,
        );
    }

    if matches!(file_type, FileType::Script) {
        indicators.has_script = true;
        indicators.script_count += 1;
        flag(
            "Script",
            "Archive contains script file".to_string(),
            RiskLevel::Medium,
        );
    }

    if has_double_extension(&file_name) {
        indicators.has_double_extension = true;
        flag(
            "DoubleExtension",
            "File has double extension (possible masquerading)".to_string(),
            RiskLevel::High,
        );
    }

    if let Some(why) = path_risk(&path) {
        indicators.has_path_traversal = true;
        flag(
            "PathTraversal",
            format!("Entry path escapes the extraction directory: {why}"),
            RiskLevel::Critical,
        );
    }

    match (spec.kind, spec.link_target.as_deref()) {
        (EntryKind::Symlink | EntryKind::Hardlink, Some(target)) => {
            let relative = spec.kind == EntryKind::Symlink;
            if link_escapes(&path, target, relative) {
                indicators.has_path_traversal = true;
                flag(
                    "LinkEscape",
                    format!("Link points outside the extraction directory: {target}"),
                    RiskLevel::Critical,
                );
            } else {
                flag("Link", format!("Link to {target}"), RiskLevel::Low);
            }
        }
        (EntryKind::Symlink | EntryKind::Hardlink, None) => {
            flag("Link", "Link entry".to_string(), RiskLevel::Low);
        }
        (EntryKind::CharDevice | EntryKind::BlockDevice, _) => {
            indicators
                .suspicious_patterns
                .push(format!("device node: {path}"));
            flag(
                "DeviceNode",
                "Device node entry (extracting as root would create it)".to_string(),
                RiskLevel::High,
            );
        }
        (EntryKind::Fifo, _) => {
            flag("Fifo", "Named pipe entry".to_string(), RiskLevel::Medium);
        }
        _ => {}
    }

    if let Some(mode) = spec.permissions {
        if mode & 0o4000 != 0 {
            indicators
                .suspicious_patterns
                .push(format!("setuid: {path}"));
            flag(
                "Setuid",
                format!("Setuid bit set (mode {:o})", mode & 0o7777),
                RiskLevel::High,
            );
        }
        if mode & 0o2000 != 0 && !is_directory {
            indicators
                .suspicious_patterns
                .push(format!("setgid: {path}"));
            flag(
                "Setgid",
                format!("Setgid bit set (mode {:o})", mode & 0o7777),
                RiskLevel::High,
            );
        }
    }

    let hidden = normalized
        .split('/')
        .any(|part| part.starts_with('.') && part != "." && part != "..");
    if hidden {
        indicators.has_hidden_files = true;
        flag(
            "HiddenFile",
            "Hidden file detected".to_string(),
            RiskLevel::Low,
        );
    }

    if is_suspicious_filename(&file_name) {
        indicators.has_suspicious_names = true;
        indicators.suspicious_patterns.push(file_name.clone());
    }

    ArchiveEntry {
        path,
        file_name,
        is_directory,
        size_compressed: spec.size_compressed,
        size_uncompressed: spec.size_uncompressed,
        compression_method: spec.method,
        compression_ratio,
        last_modified: spec.last_modified,
        crc32: spec.crc32,
        is_encrypted: spec.is_encrypted,
        is_text: false, // Would need content analysis
        permissions: spec.permissions,
        comment: spec.comment,
        file_type,
        risk_indicators,
        entry_kind: spec.kind,
        link_target: spec.link_target,
    }
}

/// Turn a list of entries into the final analysis: nested archives, the
/// security analysis and the risk score.
pub(crate) fn finish_analysis(
    archive_type: ArchiveType,
    metadata: ArchiveMetadata,
    entries: Vec<ArchiveEntry>,
    mut suspicious_indicators: SuspiciousArchiveIndicators,
    notes: Vec<String>,
) -> Result<ArchiveAnalysis> {
    let nested_archives = entries
        .iter()
        .filter(|e| matches!(e.file_type, FileType::Archive))
        .map(|e| NestedArchiveInfo {
            path: e.path.clone(),
            archive_type: detect_archive_type(&e.file_name),
            size: e.size_uncompressed,
            depth: 1,
        })
        .collect();

    let compressed = !matches!(archive_type, ArchiveType::Tar);
    let security_analysis = perform_security_analysis(&entries, &metadata, compressed)?;
    suspicious_indicators.risk_score =
        calculate_risk_score(&suspicious_indicators, &security_analysis);

    Ok(ArchiveAnalysis {
        archive_type,
        metadata,
        entries,
        security_analysis,
        suspicious_indicators,
        nested_archives,
        notes,
    })
}

/// Unix mode of a ZIP entry including the setuid/setgid/sticky bits, which
/// `ZipFile::unix_mode` clears.
fn zip_mode<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Option<u32> {
    if entry.system() == zip::System::Unix {
        let mode = entry.external_attributes() >> 16;
        if mode != 0 {
            return Some(mode);
        }
    }
    entry.unix_mode()
}

/// Largest symlink target read from an archive (bytes).
const MAX_LINK_TARGET: u64 = 4096;

/// The target of a symlink entry (its data), when it is small enough to read.
fn zip_symlink_target<R: Read + Seek>(archive: &mut ZipArchive<R>, index: usize) -> Option<String> {
    let (is_link, size, encrypted) = {
        let entry = archive.by_index_raw(index).ok()?;
        let mode = zip_mode(&entry)?;
        (
            mode & 0o170_000 == 0o120_000,
            entry.size(),
            entry.encrypted(),
        )
    };
    if !is_link || encrypted || size == 0 || size > MAX_LINK_TARGET {
        return None;
    }
    let entry = archive.by_index(index).ok()?;
    let mut data = Vec::new();
    entry.take(MAX_LINK_TARGET).read_to_end(&mut data).ok()?;
    Some(String::from_utf8_lossy(&data).into_owned())
}

fn extract_zip_metadata<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<ArchiveMetadata> {
    let mut total_compressed = 0u64;
    let mut total_uncompressed = 0u64;

    for i in 0..archive.len().min(MAX_ENTRIES) {
        if let Ok(entry) = archive.by_index_raw(i) {
            total_compressed = total_compressed.saturating_add(entry.compressed_size());
            total_uncompressed = total_uncompressed.saturating_add(entry.size());
        }
    }

    let compression_ratio = saved_ratio(total_compressed, total_uncompressed);

    Ok(ArchiveMetadata {
        total_entries: archive.len(),
        total_size_compressed: total_compressed,
        total_size_uncompressed: total_uncompressed,
        compression_ratio,
        has_encryption: false, // set from the entries by the caller
        has_password: false,
        comment: if archive.comment().is_empty() {
            None
        } else {
            Some(capped_comment(archive.comment()))
        },
        created_by: None, // Would need to parse ZIP extra fields
        creation_date: None,
    })
}

fn analyze_zip_entry<R: std::io::Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    link_target: Option<String>,
    indicators: &mut SuspiciousArchiveIndicators,
) -> Result<ArchiveEntry> {
    let path = entry.name()?.into_owned();
    let mode = zip_mode(entry);
    let permissions = mode.map(|m| m & 0o7777);
    let kind = if entry.is_dir() {
        EntryKind::Directory
    } else {
        match mode.map(|m| m & 0o170_000) {
            Some(0o120_000) => EntryKind::Symlink,
            Some(0o020_000) => EntryKind::CharDevice,
            Some(0o060_000) => EntryKind::BlockDevice,
            Some(0o010_000) => EntryKind::Fifo,
            _ => EntryKind::File,
        }
    };
    let last_modified = entry.last_modified().map(|dt| {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
    });
    let comment = if entry.comment().is_empty() {
        None
    } else {
        Some(capped_comment(entry.comment().as_bytes()))
    };

    Ok(build_entry(
        EntrySpec {
            path,
            kind,
            size_compressed: entry.compressed_size(),
            size_uncompressed: entry.size(),
            method: format!("{:?}", entry.compression()),
            last_modified,
            crc32: Some(entry.crc32()),
            is_encrypted: entry.encrypted(),
            permissions,
            comment,
            link_target,
        },
        indicators,
    ))
}

fn determine_file_type(file_name: &str, _path: &str) -> FileType {
    let lower_name = file_name.to_lowercase();

    // Check extensions
    if lower_name.ends_with(".exe")
        || lower_name.ends_with(".dll")
        || lower_name.ends_with(".so")
        || lower_name.ends_with(".dylib")
        || lower_name.ends_with(".com")
        || lower_name.ends_with(".scr")
    {
        FileType::Executable
    } else if lower_name.ends_with(".ps1")
        || lower_name.ends_with(".py")
        || lower_name.ends_with(".js")
        || lower_name.ends_with(".vbs")
        || lower_name.ends_with(".bat")
        || lower_name.ends_with(".cmd")
        || lower_name.ends_with(".sh")
        || lower_name.ends_with(".pl")
    {
        FileType::Script
    } else if lower_name.ends_with(".doc")
        || lower_name.ends_with(".docx")
        || lower_name.ends_with(".xls")
        || lower_name.ends_with(".xlsx")
        || lower_name.ends_with(".ppt")
        || lower_name.ends_with(".pptx")
        || lower_name.ends_with(".pdf")
    {
        FileType::Document
    } else if lower_name.ends_with(".zip")
        || lower_name.ends_with(".rar")
        || lower_name.ends_with(".7z")
        || lower_name.ends_with(".tar")
        || lower_name.ends_with(".gz")
        || lower_name.ends_with(".bz2")
    {
        FileType::Archive
    } else if lower_name.ends_with(".jpg")
        || lower_name.ends_with(".jpeg")
        || lower_name.ends_with(".png")
        || lower_name.ends_with(".gif")
        || lower_name.ends_with(".bmp")
        || lower_name.ends_with(".ico")
    {
        FileType::Image
    } else if lower_name.ends_with(".txt")
        || lower_name.ends_with(".log")
        || lower_name.ends_with(".ini")
        || lower_name.ends_with(".cfg")
        || lower_name.ends_with(".conf")
        || lower_name.ends_with(".json")
    {
        FileType::Text
    } else {
        FileType::Unknown
    }
}

fn has_double_extension(file_name: &str) -> bool {
    let lower_name = file_name.to_lowercase();

    // Common double extension patterns
    let suspicious_patterns = [
        ".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe", ".txt.exe", ".mp3.exe", ".mp4.exe",
        ".avi.exe", ".pdf.scr", ".doc.scr", ".jpg.scr", ".png.scr", ".pdf.com", ".doc.com",
        ".jpg.com", ".png.com", ".txt.com", ".mp3.com", ".mp4.com", ".avi.com",
    ];

    suspicious_patterns
        .iter()
        .any(|pattern| lower_name.ends_with(pattern))
}

fn is_suspicious_filename(file_name: &str) -> bool {
    let lower_name = file_name.to_lowercase();

    // Suspicious keywords
    let suspicious_keywords = [
        "crack",
        "keygen",
        "patch",
        "loader",
        "activator",
        "hack",
        "cheat",
        "exploit",
        "payload",
        "backdoor",
        "trojan",
        "virus",
        "malware",
        "ransom",
        "cryptor",
        "stealer",
        "keylog",
        "bot",
        "rat",
        "rootkit",
    ];

    // Short keywords ("bot", "rat") match whole words only, so "operation" and
    // "elaborate" are not flagged.
    suspicious_keywords.iter().any(|keyword| {
        if keyword.len() <= 3 {
            lower_name
                .split(|c: char| !c.is_ascii_alphanumeric())
                .any(|token| token == *keyword)
        } else {
            lower_name.contains(keyword)
        }
    })
}

fn detect_archive_type(file_name: &str) -> ArchiveType {
    let lower_name = file_name.to_lowercase();

    if lower_name.ends_with(".zip") {
        ArchiveType::Zip
    } else if lower_name.ends_with(".rar") {
        ArchiveType::Rar
    } else if lower_name.ends_with(".7z") {
        ArchiveType::SevenZip
    } else if lower_name.ends_with(".tar") {
        ArchiveType::Tar
    } else if lower_name.ends_with(".tar.gz") || lower_name.ends_with(".tgz") {
        ArchiveType::TarGz
    } else if lower_name.ends_with(".tar.bz2") || lower_name.ends_with(".tbz2") {
        ArchiveType::TarBz2
    } else if lower_name.ends_with(".tar.xz") || lower_name.ends_with(".txz") {
        ArchiveType::TarXz
    } else {
        ArchiveType::Unknown
    }
}

fn perform_security_analysis(
    entries: &[ArchiveEntry],
    metadata: &ArchiveMetadata,
    compressed: bool,
) -> Result<ArchiveSecurityAnalysis> {
    let malicious_patterns = Vec::new();
    let mut suspicious_files = Vec::new();
    let mut path_traversal_risks = Vec::new();
    let mut hidden_content = Vec::new();

    // Check for malicious patterns
    for entry in entries {
        // Path traversal and links that leave the extraction root
        for indicator in &entry.risk_indicators {
            if indicator.indicator_type == "PathTraversal"
                || indicator.indicator_type == "LinkEscape"
            {
                path_traversal_risks.push(PathTraversalRisk {
                    entry_path: entry.path.clone(),
                    resolved_path: if indicator.indicator_type == "LinkEscape" {
                        entry.link_target.clone().unwrap_or_default()
                    } else {
                        lexical_resolve(&entry.path)
                    },
                    risk_type: if indicator.indicator_type == "LinkEscape" {
                        "Link Escape".to_string()
                    } else {
                        "Directory Traversal".to_string()
                    },
                });
            }
        }

        // Suspicious files: a hidden file or an ordinary link alone (Low) is
        // not worth raising the archive's risk level.
        if entry
            .risk_indicators
            .iter()
            .any(|r| !matches!(r.severity, RiskLevel::Low))
        {
            let max_risk = entry
                .risk_indicators
                .iter()
                .map(|r| &r.severity)
                .max_by_key(|s| match s {
                    RiskLevel::Low => 1,
                    RiskLevel::Medium => 2,
                    RiskLevel::High => 3,
                    RiskLevel::Critical => 4,
                })
                .unwrap_or(&RiskLevel::Low);

            suspicious_files.push(SuspiciousFile {
                path: entry.path.clone(),
                reason: entry.risk_indicators[0].description.clone(),
                risk_level: max_risk.clone(),
                indicators: entry
                    .risk_indicators
                    .iter()
                    .map(|r| r.indicator_type.clone())
                    .collect(),
            });
        }

        // Check for hidden content
        if entry.file_name.starts_with('.') && entry.file_name != "." && entry.file_name != ".." {
            hidden_content.push(HiddenContent {
                content_type: "Hidden File".to_string(),
                location: entry.path.clone(),
                description: "File name starts with dot".to_string(),
            });
        }
    }

    // Check for zip bomb indicators
    let zip_bomb_indicators = check_zip_bomb(entries, metadata, compressed);

    // Determine overall risk
    let overall_risk = determine_overall_risk(
        &suspicious_files,
        &path_traversal_risks,
        &zip_bomb_indicators,
    );

    Ok(ArchiveSecurityAnalysis {
        overall_risk,
        malicious_patterns,
        suspicious_files,
        path_traversal_risks,
        zip_bomb_indicators,
        hidden_content,
    })
}

/// Uncompressed size below which a high ratio is not worth a bomb flag (10 MiB).
const BOMB_MIN_BYTES: u64 = 10 * 1024 * 1024;
/// Uncompressed total that is a bomb risk by itself (4 GiB).
const BOMB_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Bomb rules compare compressed and uncompressed sizes, so they apply only
/// to compressed formats; a plain tar of any size is not a bomb.
fn check_zip_bomb(
    entries: &[ArchiveEntry],
    metadata: &ArchiveMetadata,
    compressed: bool,
) -> ZipBombIndicators {
    let mut indicators = ZipBombIndicators {
        is_potential_bomb: false,
        compression_ratio: metadata.compression_ratio,
        nesting_level: 0,
        recursive_entries: Vec::new(),
        quine_detection: false,
    };

    // 100:1 or better over the whole archive, and big enough to matter
    // (a few KiB of zeros always compresses that well).
    if compressed
        && metadata.compression_ratio > 0.99
        && metadata.total_size_uncompressed >= BOMB_MIN_BYTES
    {
        indicators.is_potential_bomb = true;
    }
    if compressed && metadata.total_size_uncompressed >= BOMB_TOTAL_BYTES {
        indicators.is_potential_bomb = true;
    }

    // Check for suspicious file sizes
    for entry in entries {
        let extreme_ratio = compressed
            && entry.size_compressed > 0
            && entry.size_uncompressed / entry.size_compressed >= 1000
            && entry.size_uncompressed >= BOMB_MIN_BYTES;
        if (compressed && entry.size_compressed < 1000 && entry.size_uncompressed > 1_000_000_000)
            || extreme_ratio
        {
            indicators.is_potential_bomb = true;
            indicators.recursive_entries.push(entry.path.clone());
        }

        // Check for nested archives
        if matches!(entry.file_type, FileType::Archive) {
            indicators.nesting_level += 1;
        }
    }

    indicators
}

fn determine_overall_risk(
    suspicious_files: &[SuspiciousFile],
    path_traversal_risks: &[PathTraversalRisk],
    zip_bomb_indicators: &ZipBombIndicators,
) -> RiskLevel {
    let critical_count = suspicious_files
        .iter()
        .filter(|f| matches!(f.risk_level, RiskLevel::Critical))
        .count();
    let high_count = suspicious_files
        .iter()
        .filter(|f| matches!(f.risk_level, RiskLevel::High))
        .count();

    if critical_count > 0
        || !path_traversal_risks.is_empty()
        || zip_bomb_indicators.is_potential_bomb
    {
        RiskLevel::Critical
    } else if high_count > 0 {
        RiskLevel::High
    } else if !suspicious_files.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn calculate_risk_score(
    indicators: &SuspiciousArchiveIndicators,
    security: &ArchiveSecurityAnalysis,
) -> u8 {
    let mut score = 0u8;

    if indicators.has_executable {
        score += 20;
    }
    if indicators.has_script {
        score += 15;
    }
    if indicators.has_double_extension {
        score += 30;
    }
    if indicators.has_path_traversal {
        score += 40;
    }
    if indicators.has_hidden_files {
        score += 5;
    }
    if indicators.has_suspicious_names {
        score += 10;
    }

    // Add score based on counts
    score += (indicators.executable_count * 5).min(20) as u8;
    score += (indicators.script_count * 3).min(15) as u8;

    // Add score based on security analysis
    match security.overall_risk {
        RiskLevel::Critical => score += 30,
        RiskLevel::High => score += 20,
        RiskLevel::Medium => score += 10,
        RiskLevel::Low => score += 0,
    }

    score.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_archive_type_detection() {
        assert!(matches!(detect_archive_type("test.zip"), ArchiveType::Zip));
        assert!(matches!(detect_archive_type("test.rar"), ArchiveType::Rar));
        assert!(matches!(
            detect_archive_type("test.7z"),
            ArchiveType::SevenZip
        ));
        assert!(matches!(
            detect_archive_type("test.tar.gz"),
            ArchiveType::TarGz
        ));
        assert!(matches!(
            detect_archive_type("test.tgz"),
            ArchiveType::TarGz
        ));
    }

    #[test]
    fn test_file_type_detection() {
        assert!(matches!(
            determine_file_type("test.exe", "test.exe"),
            FileType::Executable
        ));
        assert!(matches!(
            determine_file_type("script.ps1", "script.ps1"),
            FileType::Script
        ));
        assert!(matches!(
            determine_file_type("doc.pdf", "doc.pdf"),
            FileType::Document
        ));
        assert!(matches!(
            determine_file_type("image.jpg", "image.jpg"),
            FileType::Image
        ));
        assert!(matches!(
            determine_file_type("config.ini", "config.ini"),
            FileType::Text
        ));
    }

    #[test]
    fn test_double_extension_detection() {
        assert!(has_double_extension("document.pdf.exe"));
        assert!(has_double_extension("image.jpg.scr"));
        assert!(has_double_extension("file.txt.com"));
        assert!(!has_double_extension("normal.exe"));
        assert!(!has_double_extension("document.pdf"));
    }

    #[test]
    fn test_suspicious_filename_detection() {
        assert!(is_suspicious_filename("crack.exe"));
        assert!(is_suspicious_filename("keygen_2024.exe"));
        assert!(is_suspicious_filename("game_hack.dll"));
        assert!(is_suspicious_filename("trojan_loader.bat"));
        assert!(!is_suspicious_filename("notepad.exe"));
        assert!(!is_suspicious_filename("document.pdf"));
    }

    #[test]
    fn test_empty_zip_analysis() {
        use zip::write::ZipWriter;

        let temp_file = NamedTempFile::new().unwrap();
        {
            let file = temp_file.reopen().unwrap();
            let zip = ZipWriter::new(file);
            zip.finish().unwrap();
        }

        let result = analyze_zip(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(matches!(analysis.archive_type, ArchiveType::Zip));
        assert!(matches!(
            analysis.security_analysis.overall_risk,
            RiskLevel::Low
        ));
    }

    #[test]
    fn test_zip_with_files() {
        use zip::write::{SimpleFileOptions, ZipWriter};

        let temp_file = NamedTempFile::new().unwrap();
        {
            let file = temp_file.reopen().unwrap();
            let mut zip = ZipWriter::new(file);

            // Add a text file
            zip.start_file("readme.txt", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"This is a test file").unwrap();

            // Add a suspicious file
            zip.start_file("crack.exe", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"MZ\x90\x00").unwrap(); // PE header

            zip.finish().unwrap();
        }

        let result = analyze_zip(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.metadata.total_entries, 2);
        assert!(analysis.suspicious_indicators.has_executable);
        assert!(analysis.suspicious_indicators.has_suspicious_names);
        assert!(analysis.suspicious_indicators.risk_score > 0);
    }
}
