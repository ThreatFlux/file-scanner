//! Archive inspection (`inspect_archive`) and the content-based file-kind
//! detection that `analyze_file` uses for its overview.
//!
//! `detect_file_kind` and `format_overview` are called from `tools_analyze.rs`:
//! keep their names, arguments and return types. Document and script tools
//! live in `tools_documents.rs`.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
};

use rmcp::{
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    archive_analysis::{
        analyze_zip, capped_text, ArchiveAnalysis, ArchiveEntry, ArchiveType, EntryKind, RiskLevel,
    },
    rar_analysis::analyze_rar,
    sevenz_analysis::analyze_7z,
    tar_analysis::analyze_tar_limited,
};

use super::{
    output::{input_schema_with_budget, parse_request, respond, tool_error},
    paths::Expect,
    FileScannerMcp,
};

/// What a file is, decided from its content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileKind {
    /// Stable machine name: `elf`, `pe`, `macho`, `macho-fat`, `java-class`,
    /// `jar`, `apk`, `ooxml`, `zip`, `gzip`, `tar`, `rar`, `7z`, `ole2`, `pdf`,
    /// `script`, `text` or `unknown`. Also `rtf`, `bzip2` and `xz`.
    pub kind: String,
    /// The same for a person, for example "Mach-O universal binary (2 slices)".
    pub label: String,
    /// Media type, `application/octet-stream` when unknown.
    pub mime: String,
}

impl FileKind {
    fn new(kind: &str, label: impl Into<String>, mime: &str) -> Self {
        Self {
            kind: kind.to_string(),
            label: label.into(),
            mime: mime.to_string(),
        }
    }
}

/// Bytes read from the start of the file for detection.
const HEAD_BYTES: usize = 4096;

/// Decide what `path` is from its bytes (then its name).
///
/// Magic bytes come first (executables, Java class, the ZIP family, gzip, tar,
/// RAR, 7z, OLE2, PDF, RTF); a shebang line or a known script extension on a
/// text file comes next; then plain text; everything else is `unknown`.
pub(crate) fn detect_file_kind(path: &Path) -> std::io::Result<FileKind> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut head = Vec::with_capacity(HEAD_BYTES);
    (&mut file).take(HEAD_BYTES as u64).read_to_end(&mut head)?;
    Ok(detect_from_head(path, &head, len, &mut file))
}

fn detect_from_head(path: &Path, head: &[u8], len: u64, file: &mut File) -> FileKind {
    if head.is_empty() {
        return FileKind::new("unknown", "Empty file", "application/octet-stream");
    }
    let ext = extension(path);

    if head.starts_with(b"\x7fELF") {
        return elf_kind(head);
    }
    if head.starts_with(b"MZ") {
        return pe_kind(head, file);
    }
    if let Some(kind) = macho_or_java_kind(head) {
        return kind;
    }
    if head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x05\x06")
        || head.starts_with(b"PK\x07\x08")
    {
        return zip_family_kind(path, &ext, file);
    }
    if head.starts_with(&[0x1f, 0x8b]) {
        return gzip_kind(file);
    }
    if head.starts_with(b"BZh") {
        return FileKind::new("bzip2", "bzip2 compressed data", "application/x-bzip2");
    }
    if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return FileKind::new("xz", "xz compressed data", "application/x-xz");
    }
    if let Some(version) = crate::rar_analysis::rar_signature_version(head) {
        return FileKind::new(
            "rar",
            format!("RAR archive (version {version})"),
            "application/vnd.rar",
        );
    }
    if crate::sevenz_analysis::has_7z_signature(head) {
        let label = if head.len() > 7 {
            format!("7-Zip archive (format version {}.{})", head[6], head[7])
        } else {
            "7-Zip archive".to_string()
        };
        return FileKind::new("7z", label, "application/x-7z-compressed");
    }
    if head.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return ole2_kind(file);
    }
    if let Some(pos) = find(&head[..head.len().min(1024)], b"%PDF-") {
        let version: String = head[pos + 5..]
            .iter()
            .take_while(|b| b.is_ascii_digit() || **b == b'.')
            .map(|&b| char::from(b))
            .collect();
        let label = if version.is_empty() {
            "PDF document".to_string()
        } else {
            format!("PDF document (version {version})")
        };
        return FileKind::new("pdf", label, "application/pdf");
    }
    if head.starts_with(b"{\\rtf") {
        return FileKind::new("rtf", "Rich Text Format document", "application/rtf");
    }
    if is_tar_block(head, len) {
        return FileKind::new("tar", "tar archive", "application/x-tar");
    }

    // A truncated "Rar!\x1a" signature is not a text file.
    if !head.starts_with(b"Rar!\x1a") && is_text(head) {
        if let Some((language, mime)) = shebang_language(head) {
            return FileKind::new(
                "script",
                format!("{language} script (from its #! line)"),
                mime,
            );
        }
        if let Some((language, mime)) = extension_language(&ext) {
            return FileKind::new(
                "script",
                format!("{language} script (from its extension)"),
                mime,
            );
        }
        return text_kind(head, &ext);
    }

    FileKind::new("unknown", "Unknown binary data", "application/octet-stream")
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn elf_kind(head: &[u8]) -> FileKind {
    let class = match head.get(4) {
        Some(1) => "32-bit",
        Some(2) => "64-bit",
        _ => "",
    };
    let little = head.get(5) != Some(&2);
    let u16_at = |at: usize| -> Option<u16> {
        let b = head.get(at..at + 2)?;
        Some(if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let file_type = match u16_at(16) {
        Some(1) => "relocatable object",
        Some(2) => "executable",
        Some(3) => "shared object or PIE executable",
        Some(4) => "core dump",
        _ => "file",
    };
    let machine = match u16_at(18) {
        Some(0x03) => "x86",
        Some(0x3e) => "x86-64",
        Some(0x28) => "ARM",
        Some(0xb7) => "AArch64",
        Some(0x08) => "MIPS",
        Some(0x14) => "PowerPC",
        Some(0x15) => "PowerPC64",
        Some(0xf3) => "RISC-V",
        Some(0x16) => "s390x",
        Some(0x2b) => "SPARC V9",
        _ => "unknown architecture",
    };
    FileKind::new(
        "elf",
        format!("ELF {class} {file_type} ({machine})").replace("  ", " "),
        "application/x-elf",
    )
}

fn pe_kind(head: &[u8], file: &mut File) -> FileKind {
    let not_pe = || {
        FileKind::new(
            "unknown",
            "DOS MZ executable without a PE header",
            "application/x-dosexec",
        )
    };
    let Some(offset) = head
        .get(0x3c..0x40)
        .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    else {
        return not_pe();
    };
    let Some(pe) = read_at(file, offset, 28) else {
        return not_pe();
    };
    if &pe[..4] != b"PE\0\0" {
        return not_pe();
    }
    let machine = match u16::from_le_bytes([pe[4], pe[5]]) {
        0x014c => "x86",
        0x8664 => "x86-64",
        0x01c0 | 0x01c4 => "ARM",
        0xaa64 => "ARM64",
        0x0200 => "Itanium",
        _ => "unknown architecture",
    };
    let characteristics = u16::from_le_bytes([pe[22], pe[23]]);
    let optional = match u16::from_le_bytes([pe[24], pe[25]]) {
        0x20b => "PE32+",
        0x10b => "PE32",
        _ => "PE",
    };
    let what = if characteristics & 0x2000 != 0 {
        "DLL"
    } else {
        "executable"
    };
    FileKind::new(
        "pe",
        format!("{optional} {what} ({machine})"),
        "application/vnd.microsoft.portable-executable",
    )
}

fn macho_cpu(cputype: u32) -> &'static str {
    match cputype {
        7 => "x86",
        0x0100_0007 => "x86-64",
        12 => "ARM",
        0x0100_000c => "arm64",
        0x0200_000c => "arm64_32",
        18 => "PowerPC",
        0x0100_0012 => "PowerPC64",
        _ => "unknown CPU",
    }
}

fn macho_or_java_kind(head: &[u8]) -> Option<FileKind> {
    let magic = head.get(..4)?;
    let be32 = |at: usize| -> Option<u32> {
        let b = head.get(at..at + 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let thin = match magic {
        [0xfe, 0xed, 0xfa, 0xce] => Some((false, true)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((true, true)),
        [0xce, 0xfa, 0xed, 0xfe] => Some((false, false)),
        [0xcf, 0xfa, 0xed, 0xfe] => Some((true, false)),
        _ => None,
    };
    if let Some((is64, big_endian)) = thin {
        let read = |at: usize| -> Option<u32> {
            let b = head.get(at..at + 4)?;
            let bytes = [b[0], b[1], b[2], b[3]];
            Some(if big_endian {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            })
        };
        let cpu = read(4).map_or("unknown CPU", macho_cpu);
        let file_type = match read(12) {
            Some(1) => "object file",
            Some(2) => "executable",
            Some(3) => "fixed VM library",
            Some(4) => "core dump",
            Some(6) => "dynamic library",
            Some(7) => "dynamic linker",
            Some(8) => "bundle",
            Some(10) => "debug symbols",
            Some(11) => "kernel extension",
            _ => "file",
        };
        let bits = if is64 { "64-bit" } else { "32-bit" };
        return Some(FileKind::new(
            "macho",
            format!("Mach-O {bits} {file_type} ({cpu})"),
            "application/x-mach-binary",
        ));
    }
    let fat64 = magic == [0xca, 0xfe, 0xba, 0xbf];
    if magic == [0xca, 0xfe, 0xba, 0xbe] || fat64 {
        // 0xCAFEBABE is also a Java class: the next four bytes are minor and
        // major version there (at least 45) and a slice count here.
        let next = be32(4)?;
        if !fat64 && next >= 45 {
            let major = u32::from(u16::from_be_bytes([*head.get(6)?, *head.get(7)?]));
            let label = if major >= 49 {
                format!(
                    "Java class file (class version {major}, Java {})",
                    major - 44
                )
            } else {
                format!("Java class file (class version {major})")
            };
            return Some(FileKind::new("java-class", label, "application/java-vm"));
        }
        let entry = if fat64 { 32 } else { 20 };
        let slices = (0..next.min(32) as usize)
            .filter_map(|i| be32(8 + i * entry).map(macho_cpu))
            .collect::<Vec<_>>();
        let label = format!(
            "Mach-O universal binary ({next} slice{}: {})",
            if next == 1 { "" } else { "s" },
            slices.join(", ")
        );
        return Some(FileKind::new(
            "macho-fat",
            label,
            "application/x-mach-binary",
        ));
    }
    None
}

fn zip_family_kind(path: &Path, ext: &str, file: &mut File) -> FileKind {
    let plain = || FileKind::new("zip", "ZIP archive", "application/zip");
    if file.seek(SeekFrom::Start(0)).is_err() {
        return plain();
    }
    let Ok(archive) = zip::ZipArchive::new(&mut *file) else {
        return FileKind::new(
            "zip",
            "ZIP archive (central directory unreadable: truncated or damaged)",
            "application/zip",
        );
    };
    let owned: Vec<String> = archive
        .file_names()
        .take(200_000)
        .filter_map(|n| n.ok().map(std::borrow::Cow::into_owned))
        .collect();
    let names: Vec<&str> = owned.iter().map(String::as_str).collect();
    let has = |name: &str| names.iter().any(|n| n.eq_ignore_ascii_case(name));
    let any_prefix = |prefix: &str| names.iter().any(|n| n.starts_with(prefix));

    if has("[Content_Types].xml")
        && (any_prefix("word/") || any_prefix("xl/") || any_prefix("ppt/"))
    {
        let (app, mime) = if any_prefix("word/") {
            (
                "Word document (.docx)",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        } else if any_prefix("xl/") {
            (
                "Excel workbook (.xlsx)",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        } else {
            (
                "PowerPoint presentation (.pptx)",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            )
        };
        let macros = names
            .iter()
            .any(|n| n.to_ascii_lowercase().ends_with("vbaproject.bin"));
        let label = format!(
            "Office Open XML {app}{}",
            if macros {
                " containing a VBA project"
            } else {
                ""
            }
        );
        return FileKind::new("ooxml", label, mime);
    }
    if has("AndroidManifest.xml")
        && any_prefix("classes")
        && names.iter().any(|n| n.ends_with(".dex"))
    {
        return FileKind::new(
            "apk",
            "Android package (APK)",
            "application/vnd.android.package-archive",
        );
    }
    if has("AndroidManifest.xml") && has("classes.jar") {
        return FileKind::new(
            "jar",
            "Java Android library (AAR)",
            "application/java-archive",
        );
    }
    let class_entries = names.iter().any(|n| n.ends_with(".class"));
    if has("META-INF/MANIFEST.MF") || class_entries {
        let flavor = if any_prefix("WEB-INF/") || ext == "war" {
            "web application archive (WAR)"
        } else if ext == "ear" {
            "enterprise archive (EAR)"
        } else if has("AndroidManifest.xml") || ext == "aar" {
            "Android library (AAR)"
        } else {
            "archive (JAR)"
        };
        return FileKind::new("jar", format!("Java {flavor}"), "application/java-archive");
    }
    let _ = path;
    plain()
}

fn gzip_kind(file: &mut File) -> FileKind {
    let mut block = [0u8; 512];
    let inner_tar = file.seek(SeekFrom::Start(0)).is_ok()
        && flate2::read::MultiGzDecoder::new(&mut *file)
            .read_exact(&mut block)
            .is_ok()
        && is_tar_block(&block, 512);
    if inner_tar {
        FileKind::new(
            "gzip",
            "gzip-compressed tar archive (.tar.gz)",
            "application/gzip",
        )
    } else {
        FileKind::new("gzip", "gzip compressed data", "application/gzip")
    }
}

/// A tar header block: `ustar` at offset 257, or a name plus a valid checksum.
fn is_tar_block(head: &[u8], len: u64) -> bool {
    len >= 512 && crate::tar_analysis::is_tar_header(head)
}

fn ole2_kind(file: &mut File) -> FileKind {
    let mime_default = "application/x-ole-storage";
    let (app, mime) = file
        .seek(SeekFrom::Start(0))
        .ok()
        .and_then(|_| cfb::CompoundFile::open(&mut *file).ok())
        .map_or(("", mime_default), |cfb| {
            let has = |name: &str| cfb.entry(name).is_ok();
            if has("WordDocument") {
                ("Word document (.doc)", "application/msword")
            } else if has("Workbook") || has("Book") {
                ("Excel workbook (.xls)", "application/vnd.ms-excel")
            } else if has("PowerPoint Document") {
                (
                    "PowerPoint presentation (.ppt)",
                    "application/vnd.ms-powerpoint",
                )
            } else if has("__properties_version1.0") {
                ("Outlook message (.msg)", "application/vnd.ms-outlook")
            } else if has("VisioDocument") {
                ("Visio drawing", "application/vnd.visio")
            } else {
                ("", mime_default)
            }
        });
    let label = if app.is_empty() {
        "OLE2 compound document".to_string()
    } else {
        format!("OLE2 compound document: {app}")
    };
    FileKind::new("ole2", label, mime)
}

/// The language named by a `#!` line.
fn shebang_language(head: &[u8]) -> Option<(&'static str, &'static str)> {
    let rest = head.strip_prefix(b"#!")?;
    let line = rest.split(|&b| b == b'\n').next()?;
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    let mut program = words.next()?;
    if program.rsplit('/').next() == Some("env") {
        // `#!/usr/bin/env -S python3 -u`: the first word that is not a flag or NAME=value.
        program = words.find(|w| !w.starts_with('-') && !w.contains('='))?;
    }
    let name = program.rsplit('/').next()?.to_ascii_lowercase();
    let name = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match name {
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "fish" | "csh" | "tcsh" => {
            Some(("Shell", "text/x-shellscript"))
        }
        "python" => Some(("Python", "text/x-python")),
        "perl" => Some(("Perl", "text/x-perl")),
        "ruby" => Some(("Ruby", "text/x-ruby")),
        "node" | "nodejs" | "deno" | "bun" => Some(("JavaScript", "text/javascript")),
        "php" => Some(("PHP", "text/x-php")),
        "pwsh" | "powershell" => Some(("PowerShell", "text/x-powershell")),
        "lua" => Some(("Lua", "text/x-lua")),
        "awk" | "gawk" => Some(("AWK", "text/x-awk")),
        _ => None,
    }
}

fn extension_language(ext: &str) -> Option<(&'static str, &'static str)> {
    Some(match ext {
        "ps1" | "psm1" | "psd1" => ("PowerShell", "text/x-powershell"),
        "sh" | "bash" | "zsh" | "ksh" => ("Shell", "text/x-shellscript"),
        "py" | "pyw" => ("Python", "text/x-python"),
        "js" | "mjs" | "cjs" => ("JavaScript", "text/javascript"),
        "vbs" | "vbe" => ("VBScript", "text/vbscript"),
        "bat" | "cmd" => ("Batch", "text/x-msdos-batch"),
        "pl" | "pm" => ("Perl", "text/x-perl"),
        "rb" => ("Ruby", "text/x-ruby"),
        "php" => ("PHP", "text/x-php"),
        "lua" => ("Lua", "text/x-lua"),
        _ => return None,
    })
}

/// Whether the bytes read like text: a UTF-16 byte order mark, or no NUL bytes
/// and mostly printable (a multi-byte character cut at the end is fine).
fn is_text(head: &[u8]) -> bool {
    if head.starts_with(&[0xff, 0xfe]) || head.starts_with(&[0xfe, 0xff]) {
        return true;
    }
    // NUL is never text. A few other C0 control bytes (BEL, backspace overstrike,
    // vertical tab, Ctrl-Z) occur in real scripts and man pages; more than a tenth
    // of the head is binary data.
    if head.contains(&0) {
        return false;
    }
    let controls = head
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | 0x1b))
        .count();
    if controls * 10 > head.len() {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(error) if error.error_len().is_none() => true,
        Err(_) => {
            let printable = head
                .iter()
                .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
                .count();
            printable * 100 >= head.len() * 95
        }
    }
}

fn text_kind(head: &[u8], ext: &str) -> FileKind {
    let start = String::from_utf8_lossy(&head[..head.len().min(256)])
        .trim_start_matches('\u{feff}')
        .trim_start()
        .to_ascii_lowercase();
    if start.starts_with("<?xml") {
        return FileKind::new("text", "XML text", "text/xml");
    }
    if start.starts_with("<!doctype html") || start.starts_with("<html") {
        return FileKind::new("text", "HTML text", "text/html");
    }
    if ext == "json" && (start.starts_with('{') || start.starts_with('[')) {
        return FileKind::new("text", "JSON text", "application/json");
    }
    FileKind::new("text", "Text", "text/plain")
}

// -- overview ---------------------------------------------------------------

/// Largest number of top-level names shown in an overview.
const TOP_LEVEL_NAMES: usize = 10;
/// Longest top-level name, and longest note, shown in an overview (characters).
const OVERVIEW_NAME_CHARS: usize = 80;
const OVERVIEW_NOTE_CHARS: usize = 240;
/// Most notes shown in an overview.
const OVERVIEW_NOTES: usize = 3;
/// A tar.gz is read through at most this many decompressed bytes for an
/// overview (the note says so when it cuts the listing).
const OVERVIEW_STREAM_BYTES: u64 = 32 << 20;

/// A compact, format-specific summary for the `analyze_file` overview, or
/// `None` when the kind has nothing to add. It must stay small (a few hundred
/// bytes) and name the tool to call for more.
///
/// Archives (ZIP family, tar, gzip-compressed tar, RAR, 7z) get entry counts,
/// sizes, the top-level names and risk flags; documents and scripts name the
/// tool to call; Java kinds name `analyze_java_file`.
// The caller runs it on the blocking pool: it opens the archive and reads at
// most 32 MiB of a compressed tar.
pub(crate) fn format_overview(path: &Path, kind: &FileKind) -> Option<Value> {
    let file_path = path.to_string_lossy().into_owned();
    let tool = |name: &str| {
        json!({
            "kind": kind.kind,
            "tool": name,
            "arguments": {"file_path": file_path},
        })
    };
    match kind.kind.as_str() {
        "pdf" | "ole2" | "rtf" | "ooxml" => {
            let mut value = tool("analyze_document");
            if kind.kind == "ooxml" {
                value["also"] = json!("inspect_archive lists the package parts");
            }
            Some(value)
        }
        "script" => Some(tool("analyze_script")),
        "java-class" => Some(tool("analyze_java_file")),
        "zip" | "jar" | "apk" | "gzip" | "tar" | "rar" | "7z" | "bzip2" | "xz" => {
            Some(archive_overview(path, kind))
        }
        _ => None,
    }
}

fn analyze_archive(
    path: &Path,
    kind: &FileKind,
    stream_limit: u64,
) -> Result<ArchiveAnalysis, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let outcome = match kind.kind.as_str() {
        "zip" | "jar" | "apk" | "ooxml" => analyze_zip(path),
        "gzip" | "tar" | "bzip2" | "xz" => analyze_tar_limited(path, stream_limit),
        "rar" => analyze_rar(path),
        "7z" => analyze_7z(path),
        other => {
            return Err(format!(
                "{name} is not an archive inspect_archive can list (detected: {} [{other}]). {}",
                kind.label,
                alternative_for(other)
            ))
        }
    };
    outcome.map_err(|error| {
        if matches!(kind.kind.as_str(), "gzip" | "bzip2" | "xz") {
            format!(
                "{name} is a {} but not a tar archive ({error:#}). inspect_archive lists .tar, \
                 .tar.gz/.tgz, .zip, .jar, .rar and .7z files; decompress other streams first.",
                kind.label
            )
        } else {
            format!("Could not read {name} as {}: {error:#}", kind.label)
        }
    })
}

fn alternative_for(kind: &str) -> &'static str {
    match kind {
        "pdf" | "ole2" | "rtf" => "Call analyze_document for documents.",
        "script" => "Call analyze_script for scripts.",
        "java-class" => "Call analyze_java_file for class files.",
        _ => "Call analyze_file for an overview of the file.",
    }
}

fn risk_flags(analysis: &ArchiveAnalysis) -> Vec<&'static str> {
    let s = &analysis.suspicious_indicators;
    let mut flags = Vec::new();
    for (set, name) in [
        (s.has_path_traversal, "path_traversal_or_link_escape"),
        (
            analysis
                .security_analysis
                .zip_bomb_indicators
                .is_potential_bomb,
            "possible_bomb",
        ),
        (analysis.metadata.has_encryption, "encrypted"),
        (s.has_executable, "executables"),
        (s.has_script, "scripts"),
        (s.has_double_extension, "double_extension"),
        (s.has_hidden_files, "hidden_files"),
        (s.has_suspicious_names, "suspicious_names"),
        (!analysis.nested_archives.is_empty(), "nested_archives"),
    ] {
        if set {
            flags.push(name);
        }
    }
    if analysis.entries.iter().any(|e| {
        e.risk_indicators
            .iter()
            .any(|r| r.indicator_type == "Setuid" || r.indicator_type == "Setgid")
    }) {
        flags.push("setuid_or_setgid");
    }
    if analysis
        .entries
        .iter()
        .any(|e| matches!(e.entry_kind, EntryKind::CharDevice | EntryKind::BlockDevice))
    {
        flags.push("device_nodes");
    }
    flags
}

fn top_level_names(entries: &[ArchiveEntry]) -> (Vec<String>, usize) {
    let mut seen = Vec::new();
    for entry in entries {
        let normalized = entry.path.replace('\\', "/");
        let trimmed = normalized.trim_start_matches("./");
        let first = trimmed.split('/').next().unwrap_or_default();
        if !first.is_empty() && !seen.iter().any(|s: &String| s == first) {
            seen.push(first.to_string());
        }
    }
    let total = seen.len();
    seen.truncate(TOP_LEVEL_NAMES);
    let seen = seen
        .iter()
        .map(|name| capped_text(name, OVERVIEW_NAME_CHARS))
        .collect();
    (seen, total)
}

fn format_name(archive_type: &ArchiveType) -> &'static str {
    match archive_type {
        ArchiveType::Zip | ArchiveType::ZipEncrypted | ArchiveType::ZipSelfExtracting => "ZIP",
        ArchiveType::Rar => "RAR",
        ArchiveType::SevenZip => "7z",
        ArchiveType::Tar => "tar",
        ArchiveType::TarGz => "tar.gz",
        ArchiveType::TarBz2 => "tar.bz2",
        ArchiveType::TarXz => "tar.xz",
        ArchiveType::Unknown => "unknown",
    }
}

fn risk_name(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

/// What the notes of a listing say about how much of the archive was read.
/// Counts that were not measured are reported as null, and "low" risk is not
/// claimed for entries that were not read.
#[derive(Clone, Copy, Default)]
struct ListingGaps {
    /// The entries could not be read, or only some were (counts are lower bounds).
    counts_unknown: bool,
    /// The header gave a total, but only the first entries were recorded.
    capped: bool,
    /// Some names were cut before the risk checks; counts and sizes are exact.
    unchecked: bool,
}

impl ListingGaps {
    fn of<'a>(notes: impl IntoIterator<Item = &'a str>) -> Self {
        let mut gaps = Self::default();
        for note in notes {
            if note.starts_with(crate::archive_analysis::LISTING_UNAVAILABLE)
                || note.starts_with(crate::archive_analysis::LISTING_PARTIAL)
            {
                gaps.counts_unknown = true;
            } else if note.starts_with(crate::archive_analysis::LISTING_CAPPED) {
                gaps.capped = true;
            } else if note.starts_with(crate::archive_analysis::NAMES_UNCHECKED) {
                gaps.unchecked = true;
            }
        }
        gaps
    }

    /// An entry count: the header's total survives a cap, not a read failure.
    fn count(self, value: Value) -> Value {
        if self.counts_unknown {
            Value::Null
        } else {
            value
        }
    }

    /// A size or ratio, which only covers the entries recorded.
    fn sizes(self, value: Value) -> Value {
        if self.counts_unknown || self.capped {
            Value::Null
        } else {
            value
        }
    }

    /// A risk label, "unknown" instead of "low" when part of the archive was not read.
    fn risk(self, risk: &str) -> String {
        if (self.counts_unknown || self.capped || self.unchecked)
            && risk.eq_ignore_ascii_case("low")
        {
            "unknown".to_string()
        } else {
            risk.to_lowercase()
        }
    }
}

fn archive_overview(path: &Path, kind: &FileKind) -> Value {
    let file_path = path.to_string_lossy().into_owned();
    let mut next_steps = vec![json!({
        "tool": "inspect_archive",
        "arguments": {"file_path": file_path},
        "why": "page through every entry, filter by name or risk",
    })];
    if matches!(kind.kind.as_str(), "jar" | "apk") {
        next_steps.push(json!({
            "tool": "analyze_java_file",
            "arguments": {"file_path": file_path},
        }));
    }
    // A gzip stream that holds no tar, and bzip2/xz streams (not decodable
    // here), are compressed data rather than listable archives.
    if (kind.kind == "gzip" && !kind.label.contains("tar"))
        || matches!(kind.kind.as_str(), "bzip2" | "xz")
    {
        return json!({
            "kind": kind.kind,
            "note": "compressed stream; inspect_archive cannot list it (decompress it first, or it is not a tar archive)",
        });
    }
    match analyze_archive(path, kind, OVERVIEW_STREAM_BYTES) {
        Ok(analysis) => {
            let (top, top_total) = top_level_names(&analysis.entries);
            let mut notes: Vec<String> = analysis
                .notes
                .iter()
                .take(OVERVIEW_NOTES)
                .map(|n| capped_text(n, OVERVIEW_NOTE_CHARS))
                .collect();
            if analysis.notes.len() > OVERVIEW_NOTES {
                notes.push(format!(
                    "{} more note(s); inspect_archive lists them all",
                    analysis.notes.len() - OVERVIEW_NOTES
                ));
            }
            let gaps = ListingGaps::of(analysis.notes.iter().map(String::as_str));
            let risk = risk_name(&analysis.security_analysis.overall_risk);
            json!({
                "kind": kind.kind,
                "archive": {
                    "format": format_name(&analysis.archive_type),
                    "entries": gaps.count(json!(analysis.metadata.total_entries)),
                    "uncompressed_bytes": gaps.sizes(json!(analysis.metadata.total_size_uncompressed)),
                    "compressed_bytes": analysis.metadata.total_size_compressed,
                    "top_level": top,
                    "top_level_total": top_total,
                    "risk": gaps.risk(risk),
                    "risk_flags": risk_flags(&analysis),
                    "notes": notes,
                },
                "next_steps": next_steps,
            })
        }
        Err(message) => json!({
            "kind": kind.kind,
            "archive": {"error": message},
            "next_steps": next_steps,
        }),
    }
}

// -- inspect_archive --------------------------------------------------------

const INSPECT_ARCHIVE_DESCRIPTION: &str = "List the entries of an archive without extracting \
it: .zip (also .jar/.apk/.docx and other ZIP-based files), .tar, .tar.gz/.tgz, .rar and .7z. \
Returns a summary (format, entry count, sizes, risk level and flags, notes about anything that \
could not be read) and one page of entries (path, kind, sizes, mode, link target, risk \
indicators). Page with `offset` and `limit`; narrow with `filter` (case-insensitive text in the \
path) or `risky_only` (entries with a medium or higher risk indicator: path traversal, links \
leaving the extraction root, device nodes, setuid bits, executables, double extensions). \
Encrypted or compressed RAR/7z headers cannot be listed and are reported in `notes`; .tar.bz2 \
and .tar.xz are recognized but not listed. The complete listing is cached by the file's SHA-256, \
so paging and filtering do not parse the archive again. Call analyze_file first for an overview. Times are UTC and end in Z for tar, 7z and RAR 5 \
archives; ZIP and RAR 4 store DOS times with no zone, shown without a Z (local time of the \
archiver). \
Results are compact JSON capped at `max_output_bytes` (default 80000, ceiling 400000).";

/// Arguments of `inspect_archive`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InspectArchiveRequest {
    #[schemars(description = "Absolute path of the archive")]
    pub file_path: String,
    #[schemars(description = "Only entries whose path contains this text (case-insensitive)")]
    pub filter: Option<String>,
    #[schemars(
        description = "Only entries with a medium or higher risk indicator (default false)"
    )]
    pub risky_only: Option<bool>,
    #[schemars(description = "Number of entries to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Number of entries to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

/// Section-cache key for the complete listing; the file's SHA-256 is the other half.
const ARCHIVE_CACHE_KEY: &str = "archive:listing:v4";

#[tool_router(router = formats_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "inspect_archive",
        title = "Inspect archive",
        description = INSPECT_ARCHIVE_DESCRIPTION,
        input_schema = input_schema_with_budget::<InspectArchiveRequest>(),
        annotations(
            title = "Inspect archive",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn inspect_archive_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let (request, budget, _raw) = match parse_request::<InspectArchiveRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let path = match self
            .state
            .resolve_path(&request.file_path, "File", Expect::File)
        {
            Ok(path) => path,
            Err(message) => return Ok(tool_error(message)),
        };
        let sha256 = match crate::hash::calculate_sha256_only(&path).await {
            Ok(sha) => sha,
            Err(error) => {
                return Ok(tool_error(format!(
                    "Could not read {}: {error:#}",
                    request.file_path
                )))
            }
        };

        // The cached value holds the compact rows of the listing and the
        // content-derived kind, so paging and filtering parse neither the
        // archive nor its central directory again. Only a Java archive's label
        // can depend on the file name (WAR, EAR), so only that kind is
        // detected again. Reading a large cached value back inflates and parses
        // it, so the lookup, the analysis and the page all run off the async thread.
        let state = Arc::clone(&self.state);
        let worker_path = path.clone();
        let worker_sha = sha256.clone();
        let built = self
            .state
            .run_blocking("inspect_archive", move || {
                let cache = state.section_cache();
                let cached = cache
                    .get(&worker_sha, ARCHIVE_CACHE_KEY)
                    .filter(|hit| hit["listing"].is_object() && hit["detected"].is_object());
                let (stored, cache_state) = if let Some(hit) = cached {
                    (hit, "hit")
                } else {
                    let kind = detect_file_kind(&worker_path)
                        .map_err(|e| format!("Could not read the file: {e}"))?;
                    let analysis = analyze_archive(
                        &worker_path,
                        &kind,
                        crate::archive_analysis::MAX_STREAM_BYTES,
                    )?;
                    let stored = stored_listing(analysis, &kind)?;
                    cache.put(&worker_sha, ARCHIVE_CACHE_KEY, &stored);
                    (Arc::new(stored), "miss")
                };
                let mut detected = stored["detected"].clone();
                if detected["kind"] == "jar" {
                    if let Ok(kind) = detect_file_kind(&worker_path) {
                        detected = json!({"kind": kind.kind, "label": kind.label});
                    }
                }
                Ok::<Value, String>(build_listing(
                    &stored["listing"],
                    &detected,
                    &request,
                    &worker_sha,
                    cache_state,
                    budget,
                ))
            })
            .await;
        match built {
            Ok(Ok(value)) => Ok(respond(value, budget)),
            Ok(Err(message)) | Err(message) => Ok(tool_error(message)),
        }
    }
}

/// The value kept in the section cache: the analysis with its entries replaced
/// by compact rows (one allocation per entry, the full entries dropped as they
/// are converted) and the detected kind. Rows of entries with a medium or
/// higher risk carry `"risky": true`.
fn stored_listing(mut analysis: ArchiveAnalysis, kind: &FileKind) -> Result<Value, String> {
    let entries = std::mem::take(&mut analysis.entries);
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        let full = serde_json::to_value(&entry)
            .map_err(|e| format!("Could not serialize the listing: {e}"))?;
        let mut row = compact_entry(&full);
        if entry_is_risky(&full) {
            row["risky"] = true.into();
        }
        rows.push(row);
    }
    // Per-entry duplicates of what the rows hold; inspect_archive does not
    // show them, so they are dropped before serializing.
    analysis.security_analysis.suspicious_files = Vec::new();
    analysis.security_analysis.hidden_content = Vec::new();
    let mut listing = serde_json::to_value(&analysis)
        .map_err(|e| format!("Could not serialize the listing: {e}"))?;
    drop(analysis);
    if let Some(security) = listing["security_analysis"].as_object_mut() {
        security.remove("suspicious_files");
        security.remove("hidden_content");
    }
    listing["entries"] = Value::Array(rows);
    let mut stored = serde_json::Map::new();
    stored.insert("listing".into(), listing);
    stored.insert(
        "detected".into(),
        json!({"kind": kind.kind, "label": kind.label}),
    );
    Ok(Value::Object(stored))
}

fn entry_is_risky(entry: &Value) -> bool {
    // A stored compact row carries the answer.
    if entry["risky"] == true {
        return true;
    }
    entry["risk_indicators"].as_array().is_some_and(|list| {
        list.iter()
            .any(|r| matches!(r["severity"].as_str(), Some("Medium" | "High" | "Critical")))
    })
}

/// One entry in the compact form that `inspect_archive` returns.
fn compact_entry(entry: &Value) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("path".into(), entry["path"].clone());
    if let Some(kind) = entry["entry_kind"].as_str() {
        out.insert("kind".into(), kind.into());
    }
    out.insert("size".into(), entry["size_uncompressed"].clone());
    if entry["size_compressed"] != entry["size_uncompressed"] {
        out.insert("packed".into(), entry["size_compressed"].clone());
    }
    if let Some(method) = entry["compression_method"].as_str() {
        out.insert("method".into(), method.into());
    }
    if let Some(mode) = entry["permissions"].as_u64() {
        out.insert("mode".into(), format!("{mode:04o}").into());
    }
    if let Some(modified) = entry["last_modified"].as_str() {
        out.insert("modified".into(), modified.into());
    }
    if let Some(target) = entry["link_target"].as_str() {
        out.insert("link_target".into(), target.into());
    }
    if let Some(crc) = entry["crc32"].as_u64() {
        out.insert("crc32".into(), format!("{crc:08x}").into());
    }
    if entry["is_encrypted"] == true {
        out.insert("encrypted".into(), true.into());
    }
    if let Some(list) = entry["risk_indicators"]
        .as_array()
        .filter(|l| !l.is_empty())
    {
        let risks: Vec<String> = list
            .iter()
            .map(|r| {
                format!(
                    "{} ({}): {}",
                    r["indicator_type"].as_str().unwrap_or("?"),
                    r["severity"].as_str().unwrap_or("?").to_lowercase(),
                    r["description"].as_str().unwrap_or("")
                )
            })
            .collect();
        out.insert("risks".into(), risks.into());
    }
    Value::Object(out)
}

fn build_listing(
    listing: &Value,
    detected: &Value,
    request: &InspectArchiveRequest,
    sha256: &str,
    cache: &str,
    budget: usize,
) -> Value {
    let all: &[Value] = listing["entries"].as_array().map_or(&[], Vec::as_slice);
    let needle = request
        .filter
        .as_deref()
        .filter(|f| !f.is_empty())
        .map(str::to_lowercase);
    let risky_only = request.risky_only.unwrap_or(false);
    let selected: Vec<&Value> = all
        .iter()
        .filter(|e| {
            needle.as_ref().is_none_or(|n| {
                e["path"]
                    .as_str()
                    .is_some_and(|p| p.to_lowercase().contains(n.as_str()))
            }) && (!risky_only || entry_is_risky(e))
        })
        .collect();
    let offset = request.offset.unwrap_or(0);
    let limit = request.limit.unwrap_or(super::output::DEFAULT_LIMIT);
    // Only the rows of this page are put in compact form.
    let total_selected = selected.len();
    let start = offset.min(total_selected);
    let end = start
        .saturating_add(limit.clamp(1, super::output::MAX_LIMIT))
        .min(total_selected);
    let rows: Vec<Value> = selected[start..end]
        .iter()
        .map(|e| {
            let mut row = (*e).clone();
            if let Some(map) = row.as_object_mut() {
                map.remove("risky");
            }
            row
        })
        .collect();
    let mut entries = json!({
        "items": rows,
        "total": total_selected,
        "returned": rows.len(),
        "offset": offset,
    });
    if end < total_selected {
        entries["next_offset"] = end.into();
    }

    let security = &listing["security_analysis"];
    let traversal: Vec<&Value> = security["path_traversal_risks"]
        .as_array()
        .map_or_else(Vec::new, |l| l.iter().take(10).collect());
    let metadata = &listing["metadata"];
    // When the entries could not be read, or only part of them, counts and
    // sizes are unknown (null), not zero, and a "low" risk is "unknown".
    let gaps = ListingGaps::of(
        listing["notes"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(Value::as_str),
    );
    let risk = security["overall_risk"]
        .as_str()
        .map(|r| gaps.risk(&r.to_lowercase()));
    let mut summary = json!({
        "format": detected["label"],
        "archive_type": listing["archive_type"],
        "entries": gaps.count(metadata["total_entries"].clone()),
        "listed_entries": all.len(),
        "uncompressed_bytes": gaps.sizes(metadata["total_size_uncompressed"].clone()),
        "compressed_bytes": metadata["total_size_compressed"],
        "compression_ratio": gaps.sizes(metadata["compression_ratio"].clone()),
        "encrypted": metadata["has_encryption"],
        "risk": risk,
        "risk_score": listing["suspicious_indicators"]["risk_score"],
        "possible_bomb": security["zip_bomb_indicators"]["is_potential_bomb"],
        "unsafe_paths": security["unsafe_entries"]
            .as_u64()
            .or_else(|| security["path_traversal_risks"].as_array().map(|l| l.len() as u64)),
        "nested_archives": listing["nested_archives"].as_array().map(Vec::len),
        "notes": listing["notes"],
    });
    if !traversal.is_empty() {
        summary["unsafe_path_examples"] = json!(traversal);
    }
    if let Some(comment) = metadata["comment"].as_str() {
        summary["comment"] = comment.into();
    }

    let rest_size = serde_json::to_vec(&summary).map_or(0, |b| b.len());
    super::output::fit_rows(
        &mut entries,
        "items",
        budget.saturating_sub(rest_size + 1000),
        offset,
        total_selected,
    );
    let mut next_steps = Vec::new();
    if let Some(next) = entries["next_offset"].as_u64() {
        next_steps.push(format!(
            "More entries: call inspect_archive again with offset={next}."
        ));
    }
    if needle.is_none()
        && !risky_only
        && security["path_traversal_risks"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
    {
        next_steps.push(
            "Unsafe paths exist: call inspect_archive with risky_only=true to list them."
                .to_string(),
        );
    }
    if matches!(detected["label"].as_str(), Some(l) if l.starts_with("Java")) {
        next_steps
            .push("Java archive: analyze_java_file inspects classes and the manifest.".to_string());
    }

    let mut out = json!({
        "file_path": request.file_path,
        "sha256": sha256,
        "cache": cache,
        "summary": summary,
        "entries": entries,
        "filter": request.filter,
        "risky_only": risky_only.then_some(true),
    });
    if !next_steps.is_empty() {
        out["next_steps"] = json!(next_steps);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn kind_of(dir: &Path, name: &str, bytes: &[u8]) -> FileKind {
        detect_file_kind(&write(dir, name, bytes)).unwrap()
    }

    fn zip_with(names: &[&str]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            for name in names {
                zip.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(b"x").unwrap();
            }
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    /// 3,000 symlink headers that trip every per-entry check: the security
    /// lists are capped, their counts stay exact, and the stored listing stays small.
    #[test]
    fn stored_listing_caps_the_per_entry_security_lists() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..3000 {
            let name = format!("../{i:04}/.keygen.pdf.exe");
            let mut header = tar::Header::new_gnu();
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_mode(0o7777);
            header.set_size(0);
            header.as_old_mut().linkname[..9].copy_from_slice(b"../../../");
            header.set_cksum();
            builder.append(&header, &b""[..]).unwrap();
        }
        let path = write(dir.path(), "all.tar", &builder.into_inner().unwrap());
        let kind = detect_file_kind(&path).unwrap();
        let analysis = analyze_archive(&path, &kind, 1 << 30).unwrap();
        assert_eq!(analysis.security_analysis.path_traversal_risks.len(), 1000);
        assert_eq!(analysis.security_analysis.path_traversal_total, 6000);
        assert_eq!(analysis.security_analysis.unsafe_entries, 3000);
        assert_eq!(analysis.security_analysis.suspicious_files.len(), 1000);
        assert!(analysis.suspicious_indicators.suspicious_patterns.len() <= 100);
        assert!(matches!(
            analysis.security_analysis.overall_risk,
            crate::archive_analysis::RiskLevel::Critical
        ));
        let stored = stored_listing(analysis, &kind).unwrap();
        let security = &stored["listing"]["security_analysis"];
        assert!(security.get("suspicious_files").is_none());
        assert_eq!(
            security["path_traversal_risks"].as_array().unwrap().len(),
            1000
        );
        let request = InspectArchiveRequest {
            file_path: "x".into(),
            filter: None,
            risky_only: None,
            offset: None,
            limit: None,
        };
        let page = build_listing(
            &stored["listing"],
            &stored["detected"],
            &request,
            "sha",
            "miss",
            80_000,
        );
        assert_eq!(page["summary"]["unsafe_paths"], 3000);
    }

    #[test]
    fn a_stray_control_byte_does_not_make_a_script_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let kind = kind_of(dir.path(), "bell.sh", b"#!/bin/sh\necho 'a\x07b'\n");
        assert_eq!(kind.kind, "script", "{}", kind.label);
        let kind = kind_of(dir.path(), "run.bat", b"@echo off\r\necho hi\r\n\x1a");
        assert_eq!(kind.kind, "script", "{}", kind.label);
        // A truncated RAR signature and NUL-filled data stay binary.
        assert_eq!(kind_of(dir.path(), "r", b"Rar!\x1a").kind, "unknown");
        assert_eq!(kind_of(dir.path(), "z", b"ab\0cd").kind, "unknown");
    }

    #[test]
    fn a_zip_with_a_repeated_name_is_marked_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        // The writer refuses duplicate names, so make the second one equal by hand.
        let mut bytes = zip_with(&["toolA", "readme.txt", "toolB"]);
        let mut at = 0;
        while let Some(pos) = find(&bytes[at..], b"toolB") {
            bytes[at + pos + 4] = b'A';
            at += pos + 5;
        }
        let path = write(dir.path(), "dup.zip", &bytes);
        let kind = detect_file_kind(&path).unwrap();
        let analysis = analyze_archive(&path, &kind, 1 << 30).unwrap();
        let notes = analysis.notes.join(" ");
        assert!(notes.contains("Entry listing is incomplete"), "{notes}");
        let gaps = ListingGaps::of(analysis.notes.iter().map(String::as_str));
        assert_eq!(gaps.risk("low"), "unknown");
    }

    #[test]
    fn executables_and_class_files_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16] = 3;
        elf[18] = 0x3e;
        let kind = kind_of(dir.path(), "a.out", &elf);
        assert_eq!(kind.kind, "elf");
        assert_eq!(
            kind.label,
            "ELF 64-bit shared object or PIE executable (x86-64)"
        );

        let mut pe = vec![0u8; 256];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84] = 0x64;
        pe[0x85] = 0x86;
        pe[0x96] = 0x22;
        pe[0x97] = 0x20; // DLL
        pe[0x98] = 0x0b;
        pe[0x99] = 0x02;
        let kind = kind_of(dir.path(), "x.dll", &pe);
        assert_eq!(
            (kind.kind.as_str(), kind.label.as_str()),
            ("pe", "PE32+ DLL (x86-64)")
        );
        assert_eq!(
            kind_of(dir.path(), "dos.exe", b"MZ\x90\x00 not a pe").kind,
            "unknown"
        );

        let mut macho = vec![0u8; 32];
        macho[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        macho[12..16].copy_from_slice(&2u32.to_le_bytes());
        let kind = kind_of(dir.path(), "m", &macho);
        assert_eq!(kind.label, "Mach-O 64-bit executable (arm64)");

        // Fat binary with two slices (x86-64, arm64): same magic as Java.
        let mut fat = vec![0u8; 8 + 40];
        fat[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        fat[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        fat[28..32].copy_from_slice(&0x0100_000cu32.to_be_bytes());
        let kind = kind_of(dir.path(), "fat", &fat);
        assert_eq!(kind.kind, "macho-fat");
        assert_eq!(
            kind.label,
            "Mach-O universal binary (2 slices: x86-64, arm64)"
        );

        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0];
        let kind = kind_of(dir.path(), "A.class", &class);
        assert_eq!(kind.kind, "java-class");
        assert!(kind.label.contains("Java 8"), "{}", kind.label);
        assert_eq!(kind.mime, "application/java-vm");
    }

    #[test]
    fn zip_family_is_classified_by_its_entries_not_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (vec!["META-INF/MANIFEST.MF", "a/B.class"], "jar"),
            (vec!["AndroidManifest.xml", "classes.dex"], "apk"),
            (vec!["[Content_Types].xml", "word/document.xml"], "ooxml"),
            (vec!["readme.txt"], "zip"),
        ];
        for (names, expected) in cases {
            // A misleading extension must not matter.
            let kind = kind_of(dir.path(), "thing.bin", &zip_with(&names));
            assert_eq!(kind.kind, expected, "{names:?}");
        }
        let docx = kind_of(
            dir.path(),
            "m.docx",
            &zip_with(&[
                "[Content_Types].xml",
                "word/vbaProject.bin",
                "word/document.xml",
            ]),
        );
        assert!(docx.label.contains("Word") && docx.label.contains("VBA project"));
        assert_eq!(
            kind_of(dir.path(), "x.zip", b"PK\x03\x04 truncated").kind,
            "zip"
        );
    }

    #[test]
    fn containers_documents_and_scripts() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            kind_of(dir.path(), "a", b"Rar!\x1a\x07\x00....").label,
            "RAR archive (version 4)"
        );
        assert_eq!(
            kind_of(dir.path(), "b", b"Rar!\x1a\x07\x01\x00..").label,
            "RAR archive (version 5)"
        );
        assert_eq!(
            kind_of(dir.path(), "c", b"7z\xbc\xaf\x27\x1c\x00\x04....").kind,
            "7z"
        );
        assert_eq!(
            kind_of(dir.path(), "d.bin", b"%PDF-1.7\n1 0 obj").label,
            "PDF document (version 1.7)"
        );
        assert_eq!(kind_of(dir.path(), "e.bin", b"{\\rtf1\\ansi").kind, "rtf");
        let mut ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
        ole.extend_from_slice(&[0u8; 600]);
        assert_eq!(kind_of(dir.path(), "f.doc", &ole).kind, "ole2");

        let script = kind_of(dir.path(), "run", b"#!/usr/bin/env python3\nprint(1)\n");
        assert_eq!(
            (script.kind.as_str(), script.mime.as_str()),
            ("script", "text/x-python")
        );
        assert!(kind_of(dir.path(), "g", b"#!/bin/bash\nls\n")
            .label
            .starts_with("Shell"));
        assert!(kind_of(dir.path(), "h.ps1", b"Get-ChildItem | Out-Null\n")
            .label
            .starts_with("PowerShell"));
        assert_eq!(
            kind_of(dir.path(), "i.js", b"console.log(1)\n").mime,
            "text/javascript"
        );
        let plain = kind_of(dir.path(), "notes.txt", b"just some words\n");
        assert_eq!(
            (plain.kind.as_str(), plain.mime.as_str()),
            ("text", "text/plain")
        );
        // A .ps1 name on binary data is not a script.
        assert_eq!(
            kind_of(dir.path(), "j.ps1", &[0, 1, 2, 3, 0, 0xff]).kind,
            "unknown"
        );
        assert_eq!(kind_of(dir.path(), "empty", b"").label, "Empty file");
        assert!(detect_file_kind(&dir.path().join("missing")).is_err());
    }

    fn tar_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            // Raw name: the builder's own path setter refuses `..`.
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn tar_is_found_by_the_ustar_marker_and_gzip_by_what_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let tar = tar_with(&[("a.txt", b"hello")]);
        assert_eq!(kind_of(dir.path(), "x.dat", &tar).kind, "tar");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let kind = kind_of(dir.path(), "x.dat", &gz);
        assert_eq!(kind.kind, "gzip");
        assert!(kind.label.contains("tar"), "{}", kind.label);
        let mut plain = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        plain.write_all(b"just text").unwrap();
        let kind = kind_of(dir.path(), "y.dat", &plain.finish().unwrap());
        assert_eq!(kind.label, "gzip compressed data");
    }

    #[test]
    fn overview_summarizes_archives_and_names_tools_for_documents() {
        let dir = tempfile::tempdir().unwrap();
        let tar = tar_with(&[("src/a.rs", b"fn a() {}"), ("../evil.sh", b"rm -rf x")]);
        let path = write(dir.path(), "pkg.tar", &tar);
        let kind = detect_file_kind(&path).unwrap();
        let overview = format_overview(&path, &kind).unwrap();
        assert_eq!(overview["archive"]["entries"], 2);
        assert_eq!(overview["archive"]["top_level"], json!(["src", ".."]));
        let flags = overview["archive"]["risk_flags"].to_string();
        assert!(flags.contains("path_traversal"), "{flags}");
        assert_eq!(overview["next_steps"][0]["tool"], "inspect_archive");
        assert!(overview.to_string().len() < 1500);

        let pdf = write(dir.path(), "a.pdf", b"%PDF-1.4\n");
        let overview = format_overview(&pdf, &detect_file_kind(&pdf).unwrap()).unwrap();
        assert_eq!(overview["tool"], "analyze_document");
        let sh = write(dir.path(), "a.sh", b"#!/bin/sh\necho\n");
        let overview = format_overview(&sh, &detect_file_kind(&sh).unwrap()).unwrap();
        assert_eq!(overview["tool"], "analyze_script");
        let txt = write(dir.path(), "a.txt", b"hello\n");
        assert!(format_overview(&txt, &detect_file_kind(&txt).unwrap()).is_none());
    }

    #[test]
    fn an_android_library_is_recognized_by_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let kind = kind_of(
            dir.path(),
            "lib.zip",
            &zip_with(&["AndroidManifest.xml", "classes.jar", "R.txt"]),
        );
        assert_eq!(kind.kind, "jar");
        assert!(kind.label.contains("AAR"), "{}", kind.label);
    }

    #[test]
    fn the_overview_of_a_non_tar_gzip_has_no_archive_block() {
        let dir = tempfile::tempdir().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"plain text, not a tar").unwrap();
        let path = write(dir.path(), "t.gz", &gz.finish().unwrap());
        let kind = detect_file_kind(&path).unwrap();
        let overview = format_overview(&path, &kind).unwrap();
        assert!(overview.get("archive").is_none(), "{overview}");
    }

    #[test]
    fn partial_listings_have_no_counts_and_no_low_risk() {
        let none = ListingGaps::of(["Solid archive."]);
        assert_eq!(none.count(json!(3)), json!(3));
        assert_eq!(none.risk("Low"), "low");
        let partial = ListingGaps::of([format!(
            "{}: reading stopped",
            crate::archive_analysis::LISTING_PARTIAL
        )
        .as_str()]);
        assert_eq!(partial.count(json!(3)), Value::Null);
        assert_eq!(partial.sizes(json!(9)), Value::Null);
        assert_eq!(partial.risk("low"), "unknown");
        assert_eq!(partial.risk("critical"), "critical");
        let capped = ListingGaps::of(["Only the first 100000 of 150000 entries were analyzed."]);
        assert_eq!(capped.count(json!(150_000)), json!(150_000));
        assert_eq!(capped.sizes(json!(9)), Value::Null);
        assert_eq!(capped.risk("low"), "unknown");
    }

    #[test]
    fn the_overview_of_a_tar_gz_cut_by_the_stream_limit_has_no_counts() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![0u8; (OVERVIEW_STREAM_BYTES as usize) + (4 << 20)];
        let tar = tar_with(&[("a.bin", &big), ("b.txt", b"x")]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let path = write(dir.path(), "big.tar.gz", &gz.finish().unwrap());
        let kind = detect_file_kind(&path).unwrap();
        let overview = format_overview(&path, &kind).unwrap();
        let archive = &overview["archive"];
        assert_eq!(archive["entries"], Value::Null, "{archive}");
        assert_eq!(archive["uncompressed_bytes"], Value::Null);
        // Zeros compress so well that the bomb rule may rate it; never "low".
        assert_ne!(archive["risk"], "low", "{archive}");
        assert!(archive["notes"].to_string().contains("incomplete"));
    }
}
