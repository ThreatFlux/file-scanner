//! Archive inspection (`inspect_archive`) and the content-based file-kind
//! detection that `analyze_file` uses for its overview.
//!
//! `detect_file_kind` and `format_overview` are called from `tools_analyze.rs`:
//! keep their names, arguments and return types. Document and script tools
//! live in `tools_documents.rs`.

use std::path::Path;

use rmcp::tool_router;
use serde::Serialize;

use super::FileScannerMcp;

/// What a file is, decided from its content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileKind {
    /// Stable machine name: `elf`, `pe`, `macho`, `macho-fat`, `java-class`,
    /// `jar`, `apk`, `ooxml`, `zip`, `gzip`, `tar`, `rar`, `7z`, `ole2`, `pdf`,
    /// `script`, `text` or `unknown`.
    pub kind: String,
    /// The same for a person, for example "Mach-O universal binary (2 slices)".
    pub label: String,
    /// Media type, `application/octet-stream` when unknown.
    pub mime: String,
}

/// Decide what `path` is from its bytes (then its name).
///
/// Placeholder until the detection package lands: everything is `unknown`.
// Called from `tools_analyze.rs` once the overview lands.
#[allow(dead_code)]
pub(crate) fn detect_file_kind(path: &Path) -> std::io::Result<FileKind> {
    std::fs::metadata(path)?;
    Ok(FileKind {
        kind: "unknown".to_string(),
        label: "Unknown".to_string(),
        mime: "application/octet-stream".to_string(),
    })
}

/// A compact, format-specific summary for the `analyze_file` overview, or
/// `None` when the kind has nothing to add. It must stay small (a few hundred
/// bytes) and name the tool to call for more.
///
/// Placeholder until the detection package lands: always `None`.
// Called from `tools_analyze.rs` once the overview lands.
#[allow(dead_code)]
pub(crate) fn format_overview(_path: &Path, _kind: &FileKind) -> Option<serde_json::Value> {
    None
}

#[tool_router(router = formats_router, vis = "pub(crate)", allow_empty)]
impl FileScannerMcp {}
