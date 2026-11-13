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
/// Prefix of the note an analyzer adds when the entries it read are only part of
/// the archive, so the counts and sizes are lower bounds and are not reported
/// as totals.
pub const LISTING_PARTIAL: &str = "Entry listing is incomplete";
/// Prefix of the note an analyzer adds when a name was cut before the risk
/// checks ran, so a "low" risk cannot be claimed for the archive.
pub const NAMES_UNCHECKED: &str = "Some names were cut before the risk checks";
/// Text of the note an analyzer adds when entries are password-protected; the
/// note reads "N entries are password-protected; their content was not inspected".
pub const ENCRYPTED_NOTE: &str = "password-protected; their content was not inspected";
/// Sentence appended to that note when no entry could be read at all.
pub const ALL_ENCRYPTED: &str = "Every entry is encrypted";
/// Prefix of the note naming nested archives that were counted but not opened.
pub const NESTED_NOT_OPENED: &str = "Nested archives are counted but not opened";
/// Most nested archive names a note spells out.
const NESTED_NAMES_IN_NOTE: usize = 5;
/// "1 entry" or "N entries".
pub(crate) fn count_entries(n: usize) -> String {
    if n == 1 {
        "1 entry".to_string()
    } else {
        format!("{n} entries")
    }
}

/// Start of the note an analyzer adds when the header gives a total entry count
/// but only the first [`MAX_ENTRIES`] were recorded: the entry count is true, the
/// sizes and the risk level cover the recorded entries only.
pub const LISTING_CAPPED: &str = "Only the first";
/// Longest archive or entry comment kept in a result (bytes).
pub(crate) const MAX_COMMENT_BYTES: usize = 512;

/// Longest entry path or link target kept in a result (bytes); PATH_MAX.
pub(crate) const MAX_PATH_CHARS: usize = 4096;
/// Archive-wide budget for the names and link targets kept in a listing
/// (bytes). A hostile archive can name 100,000 entries with 4,096 characters
/// each; once the budget is spent, names are kept to [`SHORT_PATH_CHARS`].
pub(crate) const NAME_BUDGET_BYTES: usize = 8 << 20;
/// Longest name kept once [`NAME_BUDGET_BYTES`] is spent (bytes).
pub(crate) const SHORT_PATH_CHARS: usize = 255;
/// Hard budget for everything kept from names, link targets and the texts
/// built from them (bytes). The per-name caps keep a full 100,000-entry
/// listing well under it; an analyzer that reaches it stops recording entries
/// and says so.
pub(crate) const LISTING_BUDGET_BYTES: usize = 128 << 20;
/// Names and link targets examined in full, archive-wide (bytes). Past this,
/// a name longer than [`CHECK_PREFIX_BYTES`] is checked only up to that length.
pub(crate) const FULL_CHECK_BUDGET_BYTES: usize = 64 << 20;
/// How much of a name is still checked once [`FULL_CHECK_BUDGET_BYTES`] is spent.
pub(crate) const CHECK_PREFIX_BYTES: usize = 4096;
/// Longest file name the keyword check reads whole (bytes); a longer one is
/// checked at its start and end only.
const KEYWORD_SCAN_BYTES: usize = 8192;
/// Longest path shown in the security lists, which repeat the paths of risky entries.
const MAX_RISK_PATH_CHARS: usize = 256;
/// Longest name copied into a pattern or indicator text.
const MAX_PATTERN_CHARS: usize = 256;
/// Most rows kept in each per-entry security list (the counts stay exact).
pub(crate) const MAX_SECURITY_ROWS: usize = 1000;
/// Most strings kept in `suspicious_patterns`.
const MAX_PATTERNS: usize = 100;

fn push_pattern(indicators: &mut SuspiciousArchiveIndicators, text: impl FnOnce() -> String) {
    if indicators.suspicious_patterns.len() < MAX_PATTERNS {
        indicators.suspicious_patterns.push(text());
    }
}

/// The largest prefix of `text` of at most `max` bytes that ends on a
/// character boundary.
fn prefix_end(text: &str, max: usize) -> usize {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// A name cut to `max` bytes (on a character boundary), with its full length
/// in bytes when cut. The risk checks run on the whole name before it is cut.
/// Built at its exact size, so the kept text costs what it measures.
pub(crate) fn capped_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let end = prefix_end(text, max);
    let marker = format!("... ({} bytes in all)", text.len());
    let mut out = String::with_capacity(end + marker.len());
    out.push_str(&text[..end]);
    out.push_str(&marker);
    out
}

/// `text` with backslashes read as slashes; borrowed when it has none.
fn slashed(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\\') {
        std::borrow::Cow::Owned(text.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

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
    /// Number of traversal and link-escape risks found; the list above keeps
    /// only the first 1,000 of them.
    #[serde(default)]
    pub path_traversal_total: usize,
    /// Number of entries with at least one traversal or link-escape risk.
    #[serde(default)]
    pub unsafe_entries: usize,
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
    /// Bytes of names and link targets kept so far across the whole archive;
    /// past 8 MiB further names are cut much shorter.
    #[serde(default, skip_serializing)]
    pub name_bytes: usize,
    /// Names or link targets that were cut under the short cap.
    #[serde(default, skip_serializing)]
    pub names_cut: usize,
    /// Bytes of names and link targets examined in full so far.
    #[serde(default, skip_serializing)]
    pub examined_bytes: usize,
    /// Names that were checked only in part (the archive-wide check budget
    /// was spent, or the name is too long to scan for keywords).
    #[serde(default, skip_serializing)]
    pub names_unscanned: usize,
}

impl SuspiciousArchiveIndicators {
    /// Whether the kept names have used up [`LISTING_BUDGET_BYTES`]; an
    /// analyzer stops recording entries when this is true.
    pub(crate) const fn listing_full(&self) -> bool {
        self.name_bytes >= LISTING_BUDGET_BYTES
    }
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

    let directory = zip_end_record(path);
    let listed = archive.len().min(MAX_ENTRIES);
    if archive.len() > listed {
        notes.push(format!(
            "{LISTING_CAPPED} {listed} of {} entries were analyzed; sizes and the risk level \
             cover only those.",
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
        if suspicious_indicators.listing_full() {
            notes.push(format!(
                "{LISTING_PARTIAL}: the names of the first {} used up the {} MiB listing \
                 budget, so later entries are not recorded; the counts, sizes and risk rating \
                 cover only those.",
                count_entries(entries.len()),
                LISTING_BUDGET_BYTES >> 20
            ));
            break;
        }
    }

    // The zip reader trusts the entry count in the end record and keeps one
    // record per name. Walk the central directory itself: when its headers
    // differ from what was read, list the extra ones from the directory (so a
    // hidden `../x.sh` or setuid file is still seen) and say that the listing
    // is not the archive's own count. A directory that cannot be followed up to
    // the end record is never rated as if it had been checked.
    if let Some(dir) = directory {
        let read = archive.len();
        let mut start = dir.offset;
        let mut walk = zip_directory_headers(path, start, &dir, &mut |_, _| ());
        // The offset and the size give two places for the directory to start; when they
        // disagree (a lowered or wrong offset, a prefix in front of the archive), the
        // size's reading is used if it runs cleanly up to the end record and holds more.
        let alt = dir.end.saturating_sub(dir.size);
        if alt != start {
            if let Some(found) = zip_directory_headers(path, alt, &dir, &mut |_, _| ())
                .filter(|w| w.stop == WalkStop::AtEnd && w.found > 0)
            {
                let better = walk
                    .as_ref()
                    .is_none_or(|w| !w.reliable() || found.found > w.found);
                if better {
                    start = alt;
                    walk = Some(found);
                }
            }
        }
        if let Some(walk) = walk {
            let capped = matches!(walk.stop, WalkStop::EntryCap | WalkStop::ByteCap);
            let broken = walk.stop == WalkStop::Broken;
            let differs = walk.found != read && !(capped && walk.found < read);
            let mut appended = 0usize;
            if differs {
                let known: std::collections::HashSet<Vec<u8>> = (0..listed)
                    .filter_map(|i| archive.by_index_raw(i).ok().map(|e| e.name_raw().to_vec()))
                    .collect();
                let mut extra: Vec<EntrySpec> = Vec::new();
                let room = MAX_ENTRIES.saturating_sub(entries.len());
                zip_directory_headers(path, start, &dir, &mut |raw, spec| {
                    if !known.contains(raw) && extra.len() < room {
                        extra.push(spec);
                    }
                });
                appended = extra.len();
                for spec in extra {
                    metadata.total_size_compressed = metadata
                        .total_size_compressed
                        .saturating_add(spec.size_compressed);
                    metadata.total_size_uncompressed = metadata
                        .total_size_uncompressed
                        .saturating_add(spec.size_uncompressed);
                    entries.push(build_entry(spec, &mut suspicious_indicators));
                }
            }
            let cap_text = match walk.stop {
                WalkStop::EntryCap => {
                    format!("more than {MAX_ENTRIES} header(s) (the walk stops there)")
                }
                WalkStop::ByteCap => format!(
                    "at least {} header(s) (the walk stops after {} MiB of directory)",
                    walk.found,
                    MAX_DIRECTORY_BYTES >> 20
                ),
                _ => format!("{} header(s)", walk.found),
            };
            if differs || broken || walk.stop == WalkStop::ByteCap {
                let mut what = if differs {
                    format!(
                        "the end record declares {} but the central directory holds {cap_text}",
                        count_entries(dir.declared)
                    )
                } else if capped {
                    format!(
                        "the central directory is larger than {} MiB and was read up to that \
                         point ({cap_text}); entries beyond it may not be listed",
                        MAX_DIRECTORY_BYTES >> 20
                    )
                } else {
                    format!(
                        "the end record declares {} and the directory holds {cap_text}",
                        count_entries(dir.declared)
                    )
                };
                if appended > 0 {
                    what.push_str(&format!(
                        "; {appended} that the zip reader skipped are listed from the directory"
                    ));
                }
                let shared_names = walk.found.saturating_sub(appended + listed);
                if differs && !capped && shared_names > 0 {
                    what.push_str(&format!(
                        "; {shared_names} share a name with a listed entry and are not listed"
                    ));
                }
                if broken {
                    what.push_str(&format!(
                        "; the headers do not run up to the end record ({} byte(s) before it \
                         were not read as headers)",
                        walk.unread
                    ));
                }
                notes.push(format!(
                    "{LISTING_PARTIAL}: {what}. Sizes and the risk level cover only the listed \
                     entries."
                ));
            }
        } else {
            notes.push(format!(
                "{LISTING_PARTIAL}: the end record declares {} but the central directory it \
                 points at could not be read. Sizes and the risk level cover only the listed \
                 entries.",
                count_entries(dir.declared)
            ));
        }
    } else {
        notes.push(format!(
            "{LISTING_PARTIAL}: the end-of-central-directory record could not be checked \
             against the central directory (it is damaged, or its ZIP64 record cannot be found). \
             Sizes and the risk level cover only the listed entries."
        ));
    }
    metadata.total_entries = entries.len();
    metadata.has_encryption = entries.iter().any(|e| e.is_encrypted);

    finish_analysis(
        ArchiveType::Zip,
        metadata,
        entries,
        suspicious_indicators,
        notes,
    )
}

/// What the end-of-central-directory record says about the central directory.
struct ZipEndRecord {
    /// The entry count it declares.
    declared: usize,
    offset: u64,
    /// The size it declares. The walk does not trust it: it can be lowered to hide headers.
    size: u64,
    /// Where the end record (or the ZIP64 end record) starts: the directory cannot run past it.
    end: u64,
}

/// Largest central directory walked for the header count (bytes).
const MAX_DIRECTORY_BYTES: u64 = 64 << 20;

/// The end record, read from the end of the file. A ZIP64 archive is followed
/// through its locator to the ZIP64 end record, which holds the real counts.
/// The last signature whose comment fits in the file counts (bytes may follow
/// it, as the zip reader, `unzip` and Python accept). `None` when no end record
/// can be found or a ZIP64 one cannot be read.
fn zip_end_record(path: &Path) -> Option<ZipEndRecord> {
    use std::io::SeekFrom;
    let mut file = File::open(path).ok()?;
    let size = file.seek(SeekFrom::End(0)).ok()?;
    let take = size.min(22 + 20 + 65_535 + 65_536);
    let tail_start = size - take;
    file.seek(SeekFrom::Start(tail_start)).ok()?;
    let mut tail = vec![0u8; usize::try_from(take).ok()?];
    file.read_exact(&mut tail).ok()?;
    let mut pos = tail.len().checked_sub(22)?;
    loop {
        if tail[pos..].starts_with(b"PK\x05\x06") {
            let comment = usize::from(u16::from_le_bytes([tail[pos + 20], tail[pos + 21]]));
            if pos + 22 + comment <= tail.len() {
                let total = u16::from_le_bytes([tail[pos + 10], tail[pos + 11]]);
                let cd_size = u32::from_le_bytes(tail[pos + 12..pos + 16].try_into().ok()?);
                let cd_offset = u32::from_le_bytes(tail[pos + 16..pos + 20].try_into().ok()?);
                let end = tail_start + pos as u64;
                if total == 0xFFFF || cd_size == u32::MAX || cd_offset == u32::MAX {
                    return zip64_end_record(&mut file, &tail[..pos], tail_start, end, size);
                }
                return Some(ZipEndRecord {
                    declared: usize::from(total),
                    offset: u64::from(cd_offset),
                    size: u64::from(cd_size),
                    end,
                });
            }
        }
        pos = pos.checked_sub(1)?;
    }
}

/// The fields of a ZIP64 end record that starts at `at`.
fn zip64_fields(record: &[u8], at: u64) -> Option<ZipEndRecord> {
    if record.len() < 56 || !record.starts_with(b"PK\x06\x06") {
        return None;
    }
    let u64_at = |i: usize| u64::from_le_bytes(record[i..i + 8].try_into().unwrap_or([0; 8]));
    Some(ZipEndRecord {
        declared: usize::try_from(u64_at(32)).unwrap_or(usize::MAX),
        offset: u64_at(48),
        size: u64_at(40),
        end: at,
    })
}

/// The ZIP64 end record named by the locator that sits in front of the classic
/// end record (`before` holds the bytes up to it, starting at file offset
/// `before_start`; `end` is where the classic record starts). When the
/// locator's offset does not hold the record, it is looked for in front of the
/// locator instead, where Python and `unzip` look.
fn zip64_end_record(
    file: &mut File,
    before: &[u8],
    before_start: u64,
    end: u64,
    file_size: u64,
) -> Option<ZipEndRecord> {
    use std::io::SeekFrom;
    let locator_at = before.len().checked_sub(20)?;
    let locator = &before[locator_at..];
    if !locator.starts_with(b"PK\x06\x07") {
        return None;
    }
    let at = u64::from_le_bytes(locator[8..16].try_into().ok()?);
    if at.checked_add(56).is_some_and(|stop| stop <= end) && end <= file_size {
        file.seek(SeekFrom::Start(at)).ok()?;
        let mut record = [0u8; 56];
        if file.read_exact(&mut record).is_ok() {
            if let Some(found) = zip64_fields(&record, at) {
                return Some(found);
            }
        }
    }
    // Fallback: the last record in front of the locator whose own size reaches it.
    let region = &before[..locator_at];
    let mut idx = region.len().checked_sub(56)?;
    loop {
        if region[idx..].starts_with(b"PK\x06\x06") {
            let own = u64::from_le_bytes(region[idx + 4..idx + 12].try_into().ok()?);
            if (idx as u64).checked_add(12)?.checked_add(own)? == region.len() as u64 {
                return zip64_fields(&region[idx..], before_start + idx as u64);
            }
        }
        idx = idx.checked_sub(1)?;
    }
}

/// How a walk of the central directory ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WalkStop {
    /// The headers ran exactly up to the end record.
    AtEnd,
    /// `MAX_ENTRIES + 1` headers were counted.
    EntryCap,
    /// The directory is longer than `MAX_DIRECTORY_BYTES`; the walk read that much.
    ByteCap,
    /// Something other than a header (or a cut header) came before the end record.
    Broken,
}

/// The result of walking a central directory.
struct DirectoryWalk {
    /// Headers found, at most `MAX_ENTRIES + 1`.
    found: usize,
    stop: WalkStop,
    /// Bytes between where the walk stopped and the end record (`Broken` only).
    unread: u64,
}

impl DirectoryWalk {
    /// The count says something true about the directory: it was followed to the
    /// end record or stopped at a cap of ours.
    fn reliable(&self) -> bool {
        self.stop != WalkStop::Broken
    }
}

/// Walk the central directory from `start` and hand each header (as the facts
/// the shared checks need) to `each`. The declared size is not trusted: headers
/// are read from `start` while their signature matches, up to the end record,
/// and every field is checked against the bytes left. A cut header or other
/// bytes end the walk as `Broken`. `None` when the directory cannot be read.
fn zip_directory_headers(
    path: &Path,
    start: u64,
    dir: &ZipEndRecord,
    each: &mut dyn FnMut(&[u8], EntrySpec),
) -> Option<DirectoryWalk> {
    use std::io::SeekFrom;
    let mut file = File::open(path).ok()?;
    let file_size = file.seek(SeekFrom::End(0)).ok()?;
    let limit = dir.end.min(file_size);
    if start > limit {
        return None;
    }
    let truncated = limit - start > MAX_DIRECTORY_BYTES;
    let span = (limit - start).min(MAX_DIRECTORY_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut data = vec![0u8; usize::try_from(span).ok()?];
    file.read_exact(&mut data).ok()?;
    let mut reader = ByteReader::new(&data);
    let mut found = 0usize;
    let stop = loop {
        if found > MAX_ENTRIES {
            break WalkStop::EntryCap;
        }
        let rest = &data[reader.position()..];
        if !truncated
            && (rest.is_empty()
                || rest.starts_with(b"PK\x05\x05")
                || rest.starts_with(b"PK\x06\x06"))
        {
            // A digital signature record, or the ZIP64 end record of an archive whose
            // classic record carries no markers, may sit before the end record.
            break WalkStop::AtEnd;
        }
        if !rest.starts_with(b"PK\x01\x02") && !(truncated && rest.len() < 4) {
            break WalkStop::Broken;
        }
        match zip_central_header(&mut reader) {
            Some((raw, spec)) => {
                found += 1;
                each(raw, spec);
            }
            None if truncated => break WalkStop::ByteCap,
            None => break WalkStop::Broken,
        }
    };
    let unread = if stop == WalkStop::Broken {
        let at = start + reader.position() as u64;
        limit.saturating_sub(at)
    } else {
        0
    };
    Some(DirectoryWalk {
        found,
        stop,
        unread,
    })
}

/// One central-directory header, or `None` when the signature is wrong or the
/// header runs past the buffer.
fn zip_central_header<'a>(reader: &mut ByteReader<'a>) -> Option<(&'a [u8], EntrySpec)> {
    if reader.bytes(4)? != b"PK\x01\x02" {
        return None;
    }
    let made_by = reader.u16le()?;
    reader.skip(2)?;
    let flags = reader.u16le()?;
    let method = reader.u16le()?;
    reader.skip(4)?;
    let crc = reader.u32le()?;
    let compressed = reader.u32le()?;
    let uncompressed = reader.u32le()?;
    let name_len = usize::from(reader.u16le()?);
    let extra_len = usize::from(reader.u16le()?);
    let comment_len = usize::from(reader.u16le()?);
    reader.skip(4)?;
    let external = reader.u32le()?;
    reader.skip(4)?;
    let name = reader.bytes(name_len)?;
    reader.skip(extra_len.checked_add(comment_len)?)?;
    let path = String::from_utf8_lossy(name).into_owned();
    let mode = (made_by >> 8 == 3)
        .then_some(external >> 16)
        .filter(|mode| *mode != 0);
    let kind = if path.ends_with('/') {
        EntryKind::Directory
    } else {
        mode.map_or(EntryKind::File, unix_kind)
    };
    Some((
        name,
        EntrySpec {
            path,
            kind,
            size_compressed: u64::from(compressed),
            size_uncompressed: u64::from(uncompressed),
            method: match method {
                0 => "Stored".to_string(),
                8 => "Deflated".to_string(),
                other => format!("Method({other})"),
            },
            last_modified: None,
            crc32: Some(crc),
            is_encrypted: flags & 1 != 0,
            permissions: mode.map(|m| m & 0o7777),
            comment: None,
            link_target: None,
        },
    ))
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
    let normalized = slashed(path);
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
/// A name without the " (N bytes in all)" marker [`capped_text`] appends.
fn uncut(name: &str) -> &str {
    if name.ends_with(" bytes in all)") {
        if let Some(at) = name.rfind("... (") {
            return &name[..at];
        }
    }
    name
}

/// A name already cut by [`capped_text`] shortened further for the security
/// lists, keeping the original full length in its marker.
fn short_path(name: &str) -> String {
    match (name.ends_with(" bytes in all)"), name.rfind("... (")) {
        (true, Some(at)) => {
            let end = prefix_end(&name[..at], MAX_RISK_PATH_CHARS);
            format!("{}{}", &name[..end], &name[at..])
        }
        _ => capped_text(name, MAX_RISK_PATH_CHARS),
    }
}

fn lexical_resolve(path: &str) -> String {
    let normalized = slashed(path);
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
    let target = slashed(target);
    if target.starts_with('/') || path_risk(&target) == Some("drive-letter path") {
        return true;
    }
    let mut depth: i64 = 0;
    if relative_to_entry {
        let entry = slashed(entry_path);
        let parts = entry
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .count();
        depth = parts.saturating_sub(1) as i64;
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
    mut spec: EntrySpec,
    indicators: &mut SuspiciousArchiveIndicators,
) -> ArchiveEntry {
    // Every name and link target is examined in full until an archive-wide
    // budget is spent; after that a long one is checked only up to a prefix,
    // and the archive says so (its risk is then never "low").
    let examined = spec.path.len() + spec.link_target.as_ref().map_or(0, String::len);
    indicators.examined_bytes = indicators.examined_bytes.saturating_add(examined);
    if indicators.examined_bytes > FULL_CHECK_BUDGET_BYTES {
        let mut clipped = false;
        if spec.path.len() > CHECK_PREFIX_BYTES {
            let end = prefix_end(&spec.path, CHECK_PREFIX_BYTES);
            spec.path.truncate(end);
            clipped = true;
        }
        if let Some(target) = spec.link_target.as_mut() {
            if target.len() > CHECK_PREFIX_BYTES {
                let end = prefix_end(target, CHECK_PREFIX_BYTES);
                target.truncate(end);
                clipped = true;
            }
        }
        indicators.names_unscanned += usize::from(clipped);
    }
    let full_path = spec.path;
    let path: &str = &full_path;
    let normalized = slashed(path);
    let file_name: &str = normalized
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let is_directory = spec.kind == EntryKind::Directory;
    let compression_ratio = saved_ratio(spec.size_compressed, spec.size_uncompressed);

    let file_type = if is_directory {
        FileType::Unknown
    } else {
        determine_file_type(file_name, path)
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

    if has_double_extension(file_name) {
        indicators.has_double_extension = true;
        flag(
            "DoubleExtension",
            "File has double extension (possible masquerading)".to_string(),
            RiskLevel::High,
        );
    }

    if let Some(why) = path_risk(path) {
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
            if link_escapes(path, target, relative) {
                indicators.has_path_traversal = true;
                flag(
                    "LinkEscape",
                    format!(
                        "Link points outside the extraction directory: {}",
                        capped_text(target, MAX_PATTERN_CHARS)
                    ),
                    RiskLevel::Critical,
                );
            } else {
                flag(
                    "Link",
                    format!("Link to {}", capped_text(target, MAX_PATTERN_CHARS)),
                    RiskLevel::Low,
                );
            }
        }
        (EntryKind::Symlink | EntryKind::Hardlink, None) => {
            flag("Link", "Link entry".to_string(), RiskLevel::Low);
        }
        (EntryKind::CharDevice | EntryKind::BlockDevice, _) => {
            push_pattern(indicators, || {
                format!("device node: {}", capped_text(path, MAX_PATTERN_CHARS))
            });
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
            push_pattern(indicators, || {
                format!("setuid: {}", capped_text(path, MAX_PATTERN_CHARS))
            });
            flag(
                "Setuid",
                format!("Setuid bit set (mode {:o})", mode & 0o7777),
                RiskLevel::High,
            );
        }
        if mode & 0o2000 != 0 && !is_directory {
            push_pattern(indicators, || {
                format!("setgid: {}", capped_text(path, MAX_PATTERN_CHARS))
            });
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

    if file_name.len() > KEYWORD_SCAN_BYTES {
        indicators.names_unscanned += 1;
    }
    if is_suspicious_filename(file_name) {
        indicators.has_suspicious_names = true;
        push_pattern(indicators, || capped_text(file_name, MAX_PATTERN_CHARS));
    }

    let name_cap = if indicators.name_bytes > NAME_BUDGET_BYTES {
        SHORT_PATH_CHARS
    } else {
        MAX_PATH_CHARS
    };
    let kept_path = capped_text(path, name_cap);
    let kept_file_name = capped_text(file_name, name_cap);
    let kept_target = spec
        .link_target
        .as_deref()
        .map(|target| capped_text(target, name_cap));
    if name_cap == SHORT_PATH_CHARS
        && (path.len() > name_cap
            || file_name.len() > name_cap
            || spec
                .link_target
                .as_ref()
                .is_some_and(|t| t.len() > name_cap))
    {
        indicators.names_cut += 1;
    }
    // Everything kept from the names is charged to one budget: the path, the
    // file name, the link target and the texts built from them.
    let kept_texts: usize = risk_indicators
        .iter()
        .map(|r| r.description.len() + r.indicator_type.len())
        .sum();
    indicators.name_bytes = indicators
        .name_bytes
        .saturating_add(kept_path.len() + kept_file_name.len() + kept_texts)
        .saturating_add(kept_target.as_ref().map_or(0, String::len));
    ArchiveEntry {
        path: kept_path,
        file_name: kept_file_name,
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
        link_target: kept_target,
    }
}

/// Turn a list of entries into the final analysis: nested archives, the
/// security analysis and the risk score.
pub(crate) fn finish_analysis(
    archive_type: ArchiveType,
    metadata: ArchiveMetadata,
    mut entries: Vec<ArchiveEntry>,
    mut suspicious_indicators: SuspiciousArchiveIndicators,
    notes: Vec<String>,
) -> Result<ArchiveAnalysis> {
    let nested_archives: Vec<NestedArchiveInfo> = entries
        .iter()
        .filter(|e| matches!(e.file_type, FileType::Archive))
        .map(|e| NestedArchiveInfo {
            path: e.path.clone(),
            archive_type: detect_archive_type(&e.file_name),
            size: e.size_uncompressed,
            depth: 1,
        })
        .collect();

    let mut notes = notes;
    let encrypted_entries = entries.iter().filter(|e| e.is_encrypted).count();
    if encrypted_entries > 0 {
        let mut note = format!(
            "{} {} {ENCRYPTED_NOTE}.",
            count_entries(encrypted_entries),
            if encrypted_entries == 1 { "is" } else { "are" }
        );
        if encrypted_entries == entries.len() {
            note.push_str(&format!(
                " {ALL_ENCRYPTED}, so no entry content could be rated."
            ));
        }
        note.push_str(" Get the password and extract them to inspect their content.");
        notes.push(note);
    }
    if !nested_archives.is_empty() {
        let names: Vec<String> = nested_archives
            .iter()
            .take(NESTED_NAMES_IN_NOTE)
            .map(|n| capped_text(&n.path, MAX_RISK_PATH_CHARS))
            .collect();
        let more = nested_archives.len().saturating_sub(names.len());
        notes.push(format!(
            "{NESTED_NOT_OPENED}: {} nested archive(s) ({}{}); their content was not \
             inspected, so the risk level says nothing about it. Extract them and inspect \
             each one.",
            nested_archives.len(),
            names.join(", "),
            if more > 0 {
                format!(", and {more} more")
            } else {
                String::new()
            }
        ));
    }
    if suspicious_indicators.names_cut > 0 {
        notes.push(format!(
            "The names and link targets of this archive are very long: after the first {} MiB, \
             {} names were cut to {SHORT_PATH_CHARS} bytes (risk checks still ran on the \
             whole names).",
            NAME_BUDGET_BYTES >> 20,
            suspicious_indicators.names_cut
        ));
    }
    if suspicious_indicators.names_unscanned > 0 {
        notes.push(format!(
            "{NAMES_UNCHECKED}: {} names were too long to check in full (over {} KiB, or past \
             the archive-wide limit on long names); only their start (and end) was read, \
             so a low risk level is not claimed.",
            suspicious_indicators.names_unscanned,
            KEYWORD_SCAN_BYTES >> 10
        ));
    }
    let compressed = !matches!(archive_type, ArchiveType::Tar);
    let mut security_analysis = perform_security_analysis(&entries, &metadata, compressed)?;
    if security_analysis.zip_bomb_indicators.is_potential_bomb {
        mark_bomb_entries(&mut entries, compressed);
    }
    // Content that cannot be read is not "low": the archive's own entries
    // were listed, but what is inside the encrypted ones is unknown.
    // When every entry is encrypted nothing was rated, which callers report as
    // "unknown" rather than a level.
    if encrypted_entries > 0
        && encrypted_entries < entries.len()
        && matches!(security_analysis.overall_risk, RiskLevel::Low)
    {
        security_analysis.overall_risk = RiskLevel::Medium;
    }
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

/// The last 16 characters of a name, lowercased: all the extension checks
/// need, without lowercasing a 4,096-character name once per check.
fn lower_tail(name: &str) -> String {
    let start = name.char_indices().rev().nth(15).map_or(0, |(i, _)| i);
    name[start..].to_lowercase()
}

fn determine_file_type(file_name: &str, _path: &str) -> FileType {
    let lower_name = lower_tail(file_name);

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
    let lower_name = lower_tail(file_name);

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
    // A name over KEYWORD_SCAN_BYTES is read at its start and its end, so the
    // cost of a hostile name stays small and linear (the caller counts it).
    let lower_name = if file_name.len() > KEYWORD_SCAN_BYTES {
        let head = &file_name[..prefix_end(file_name, KEYWORD_SCAN_BYTES / 2)];
        let mut from = file_name.len() - KEYWORD_SCAN_BYTES / 2;
        while !file_name.is_char_boundary(from) {
            from += 1;
        }
        // A separator between the two parts keeps a word from being formed
        // across the cut.
        format!("{head}/{}", &file_name[from..]).to_lowercase()
    } else {
        file_name.to_lowercase()
    };

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
    let lower_name = lower_tail(file_name);

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
    // Exact counts: the lists keep only the first MAX_SECURITY_ROWS rows.
    let mut traversal_total = 0usize;
    let mut unsafe_entries = 0usize;
    let mut any_critical = false;
    let mut any_high = false;
    let mut any_suspicious = false;

    // Check for malicious patterns
    for entry in entries {
        let mut entry_unsafe = false;
        // Path traversal and links that leave the extraction root
        for indicator in &entry.risk_indicators {
            if indicator.indicator_type == "PathTraversal"
                || indicator.indicator_type == "LinkEscape"
            {
                entry_unsafe = true;
                traversal_total += 1;
                if path_traversal_risks.len() >= MAX_SECURITY_ROWS {
                    continue;
                }
                path_traversal_risks.push(PathTraversalRisk {
                    entry_path: short_path(&entry.path),
                    resolved_path: if indicator.indicator_type == "LinkEscape" {
                        short_path(entry.link_target.as_deref().unwrap_or_default())
                    } else {
                        capped_text(&lexical_resolve(uncut(&entry.path)), MAX_RISK_PATH_CHARS)
                    },
                    risk_type: if indicator.indicator_type == "LinkEscape" {
                        "Link Escape".to_string()
                    } else {
                        "Directory Traversal".to_string()
                    },
                });
            }
        }

        if entry_unsafe {
            unsafe_entries += 1;
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

            any_suspicious = true;
            match max_risk {
                RiskLevel::Critical => any_critical = true,
                RiskLevel::High => any_high = true,
                _ => {}
            }
            if suspicious_files.len() < MAX_SECURITY_ROWS {
                suspicious_files.push(SuspiciousFile {
                    path: short_path(&entry.path),
                    reason: entry.risk_indicators[0].description.clone(),
                    risk_level: max_risk.clone(),
                    indicators: entry
                        .risk_indicators
                        .iter()
                        .map(|r| r.indicator_type.clone())
                        .collect(),
                });
            }
        }

        // Check for hidden content
        if hidden_content.len() < MAX_SECURITY_ROWS
            && entry.file_name.starts_with('.')
            && entry.file_name != "."
            && entry.file_name != ".."
        {
            hidden_content.push(HiddenContent {
                content_type: "Hidden File".to_string(),
                location: short_path(&entry.path),
                description: "File name starts with dot".to_string(),
            });
        }
    }

    // Check for zip bomb indicators
    let zip_bomb_indicators = check_zip_bomb(entries, metadata, compressed);

    // Determine overall risk
    let overall_risk = determine_overall_risk(
        any_critical,
        any_high,
        any_suspicious,
        traversal_total > 0,
        &zip_bomb_indicators,
    );

    Ok(ArchiveSecurityAnalysis {
        overall_risk,
        malicious_patterns,
        suspicious_files,
        path_traversal_risks,
        zip_bomb_indicators,
        hidden_content,
        path_traversal_total: traversal_total,
        unsafe_entries,
    })
}

/// Uncompressed size below which a high ratio is not worth a bomb flag (10 MiB).
const BOMB_MIN_BYTES: u64 = 10 * 1024 * 1024;
/// Uncompressed total that is a bomb risk when it also compresses 10:1 (4 GiB).
const BOMB_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Whether one entry alone expands far out of proportion to its packed size.
fn entry_looks_like_bomb(entry: &ArchiveEntry, compressed: bool) -> bool {
    let extreme_ratio = compressed
        && entry.size_compressed > 0
        && entry.size_uncompressed / entry.size_compressed >= 1000
        && entry.size_uncompressed >= BOMB_MIN_BYTES;
    (compressed && entry.size_compressed < 1000 && entry.size_uncompressed > 1_000_000_000)
        || extreme_ratio
}

/// Give the entries behind a possible bomb a risk indicator, so a listing
/// narrowed to risky entries shows them. When the archive as a whole trips the
/// rule and no single entry does, the largest entry carries the mark.
fn mark_bomb_entries(entries: &mut [ArchiveEntry], compressed: bool) {
    let indicator = |entry: &ArchiveEntry| RiskIndicator {
        indicator_type: "CompressionBomb".to_string(),
        description: format!(
            "Possible compression bomb: {} bytes unpack from {} bytes",
            entry.size_uncompressed, entry.size_compressed
        ),
        // The archive is rated critical for a possible bomb, so its entry carries the
        // same level (the score and the level are one scale).
        severity: RiskLevel::Critical,
    };
    let mut marked = false;
    for entry in entries.iter_mut() {
        if entry_looks_like_bomb(entry, compressed) {
            let risk = indicator(entry);
            entry.risk_indicators.push(risk);
            marked = true;
        }
    }
    if !marked {
        if let Some(entry) = entries.iter_mut().max_by_key(|e| e.size_uncompressed) {
            let risk = indicator(entry);
            entry.risk_indicators.push(risk);
        }
    }
}

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
    // A large total alone is not a bomb: content stored 1:1 is just big.
    if compressed
        && metadata.total_size_uncompressed >= BOMB_TOTAL_BYTES
        && metadata.compression_ratio > 0.9
    {
        indicators.is_potential_bomb = true;
    }

    // Check for suspicious file sizes
    for entry in entries {
        if entry_looks_like_bomb(entry, compressed) {
            indicators.is_potential_bomb = true;
            if indicators.recursive_entries.len() < MAX_SECURITY_ROWS {
                indicators.recursive_entries.push(entry.path.clone());
            }
        }

        // Check for nested archives
        if matches!(entry.file_type, FileType::Archive) {
            indicators.nesting_level += 1;
        }
    }

    indicators
}

fn determine_overall_risk(
    any_critical: bool,
    any_high: bool,
    any_suspicious: bool,
    any_traversal: bool,
    zip_bomb_indicators: &ZipBombIndicators,
) -> RiskLevel {
    if any_critical || any_traversal || zip_bomb_indicators.is_potential_bomb {
        RiskLevel::Critical
    } else if any_high {
        RiskLevel::High
    } else if any_suspicious {
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

    #[test]
    fn content_stored_one_to_one_is_not_a_bomb_however_big() {
        let metadata = |ratio: f64| ArchiveMetadata {
            total_entries: 2,
            total_size_compressed: 8 << 30,
            total_size_uncompressed: 8 << 30,
            compression_ratio: ratio,
            has_encryption: false,
            has_password: false,
            comment: None,
            created_by: None,
            creation_date: None,
        };
        assert!(!check_zip_bomb(&[], &metadata(0.0), true).is_potential_bomb);
        assert!(check_zip_bomb(&[], &metadata(0.95), true).is_potential_bomb);
    }

    fn spec(path: String) -> EntrySpec {
        EntrySpec {
            path,
            ..Default::default()
        }
    }

    #[test]
    fn names_are_capped_in_bytes_on_a_character_boundary() {
        let name = "\u{1F600}".repeat(1000);
        let cut = capped_text(&name, 255);
        let (head, marker) = cut.split_once("... (").unwrap();
        assert!(head.len() <= 255 && head.chars().all(|c| c == '\u{1F600}'));
        assert_eq!(marker, "4000 bytes in all)");
        assert_eq!(capped_text("short", 255), "short");
        assert_eq!(cut.capacity(), cut.len(), "built at its exact size");
    }

    #[test]
    fn long_names_after_the_check_budget_are_checked_by_prefix_and_said_so() {
        let mut indicators = SuspiciousArchiveIndicators::default();
        // A traversal at the start of a huge name is still found.
        let evil = format!("../x/{}", "\u{130}".repeat(500_000));
        indicators.examined_bytes = FULL_CHECK_BUDGET_BYTES;
        let entry = build_entry(spec(evil.clone()), &mut indicators);
        assert!(indicators.has_path_traversal);
        assert_eq!(indicators.names_unscanned, 1);
        assert!(entry.path.len() < 4200, "{}", entry.path.len());
        // Within the budget the same name is examined whole: no note.
        let mut fresh = SuspiciousArchiveIndicators::default();
        build_entry(spec(format!("ok/{}", "a".repeat(5000))), &mut fresh);
        assert_eq!(fresh.names_unscanned, 0);
        // A traversal after 20,000 characters is seen while the budget lasts.
        let late = format!("{}/../../x", "d".repeat(20_000));
        let mut fresh = SuspiciousArchiveIndicators::default();
        build_entry(spec(late), &mut fresh);
        assert!(fresh.has_path_traversal);
        // The archive is not rated low: the note names the cut names.
        let analysis = finish_analysis(
            ArchiveType::Tar,
            ArchiveMetadata {
                total_entries: 1,
                total_size_compressed: 0,
                total_size_uncompressed: 0,
                compression_ratio: 0.0,
                has_encryption: false,
                has_password: false,
                comment: None,
                created_by: None,
                creation_date: None,
            },
            vec![entry],
            indicators,
            Vec::new(),
        )
        .unwrap();
        assert!(analysis
            .notes
            .iter()
            .any(|n| n.starts_with(NAMES_UNCHECKED)));
    }

    #[test]
    fn a_name_too_long_to_scan_for_keywords_is_counted() {
        let mut indicators = SuspiciousArchiveIndicators::default();
        let name = format!("{}.keygen", "a".repeat(30_000));
        build_entry(spec(name), &mut indicators);
        assert_eq!(indicators.names_unscanned, 1);
        // The end of a long name is still read.
        assert!(indicators.has_suspicious_names);
        let mut indicators = SuspiciousArchiveIndicators::default();
        build_entry(
            spec(format!("{}/keygen.exe", "a".repeat(30_000))),
            &mut indicators,
        );
        assert!(indicators.has_suspicious_names);
        let mut indicators = SuspiciousArchiveIndicators::default();
        build_entry(spec("a".repeat(2000)), &mut indicators);
        assert_eq!(indicators.names_unscanned, 0);
    }

    #[test]
    fn the_kept_texts_are_charged_to_the_name_budget() {
        let mut indicators = SuspiciousArchiveIndicators::default();
        let entry = build_entry(
            EntrySpec {
                path: "a/b".to_string(),
                kind: EntryKind::Symlink,
                link_target: Some("t".repeat(2000)),
                ..Default::default()
            },
            &mut indicators,
        );
        let description: usize = entry
            .risk_indicators
            .iter()
            .map(|r| r.description.len())
            .sum();
        assert!(description >= 200);
        assert!(indicators.name_bytes >= 3 + 1 + 2000 + description);
        assert!(!indicators.listing_full());
        indicators.name_bytes = LISTING_BUDGET_BYTES;
        assert!(indicators.listing_full());
    }
}
