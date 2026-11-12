use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    build_entry, finish_analysis, saved_ratio, ArchiveAnalysis, ArchiveEntry, ArchiveMetadata,
    ArchiveType, EntryKind, EntrySpec, SuspiciousArchiveIndicators, MAX_ENTRIES, MAX_STREAM_BYTES,
};

/// TAR file header structure
const TAR_BLOCK_SIZE: usize = 512;
const TAR_HEADER_SIZE: usize = 512;

/// Longest GNU long-name, long-link or pax record read into memory (1 MiB).
const MAX_RECORD_BYTES: u64 = 1 << 20;

/// A tar source that can skip forward cheaply (a file seeks, a stream reads).
trait Source: Read {
    fn skip(&mut self, n: u64) -> std::io::Result<()>;
}

impl Source for BufReader<File> {
    fn skip(&mut self, n: u64) -> std::io::Result<()> {
        self.seek_relative(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

impl<R: Read> Source for std::io::Take<flate2::read::GzDecoder<R>> {
    fn skip(&mut self, n: u64) -> std::io::Result<()> {
        std::io::copy(&mut self.by_ref().take(n), &mut std::io::sink()).map(|_| ())
    }
}

/// Analyze a TAR archive (plain or gzip-compressed) by reading its entries.
///
/// The entry list is bounded: at most [`MAX_ENTRIES`] entries are recorded, a
/// compressed stream is read through at most [`MAX_STREAM_BYTES`] decompressed
/// bytes and no long-name or pax record over 1 MiB is read. `.tar.bz2` and
/// `.tar.xz` are recognized but their entries cannot be listed (no decoder is
/// linked); the result says so in `notes`.
pub fn analyze_tar<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open TAR file")?;
    let mut reader = BufReader::new(file);

    let archive_type = detect_tar_type(&mut reader)?;
    let file_size = std::fs::metadata(path)?.len();

    let mut notes = Vec::new();
    let mut indicators = SuspiciousArchiveIndicators::default();
    let mut entries = Vec::new();

    reader.seek(SeekFrom::Start(0))?;
    let outcome = match archive_type {
        ArchiveType::Tar => walk_tar(reader, &mut entries, &mut indicators, &mut notes),
        ArchiveType::TarGz => {
            let decoder = flate2::read::GzDecoder::new(reader).take(MAX_STREAM_BYTES);
            walk_tar(decoder, &mut entries, &mut indicators, &mut notes)
        }
        _ => {
            notes.push(format!(
                "Entry listing is unavailable: this is a {} stream (a tar archive if it is a \
                 .tar.bz2/.tar.xz) and no decoder for it is built in.",
                get_tar_variant_name(&archive_type)
            ));
            Ok(false)
        }
    };
    match outcome {
        Ok(true) => notes.push(format!(
            "Only the first {MAX_ENTRIES} entries were recorded."
        )),
        Ok(false) => {}
        Err(reason) => notes.push(format!(
            "Stopped reading after {} entries: {reason}. The archive may be damaged or longer \
             than the {} MiB decompression limit.",
            entries.len(),
            MAX_STREAM_BYTES >> 20
        )),
    }

    let total_uncompressed = entries
        .iter()
        .fold(0u64, |acc, e| acc.saturating_add(e.size_uncompressed));
    let compressed = !matches!(archive_type, ArchiveType::Tar);
    let listing_possible = matches!(archive_type, ArchiveType::Tar | ArchiveType::TarGz);
    let metadata = ArchiveMetadata {
        total_entries: entries.len(),
        total_size_compressed: file_size,
        total_size_uncompressed: if listing_possible {
            total_uncompressed
        } else {
            0
        },
        compression_ratio: if compressed {
            saved_ratio(file_size, total_uncompressed)
        } else {
            0.0
        },
        has_encryption: false, // TAR itself doesn't support encryption
        has_password: false,
        comment: None,
        created_by: Some(format!("TAR ({})", get_tar_variant_name(&archive_type))),
        creation_date: None,
    };

    finish_analysis(archive_type, metadata, entries, indicators, notes)
}

/// Read up to a whole block; returns how many bytes were read.
fn read_block<S: Read>(
    source: &mut S,
    block: &mut [u8; TAR_BLOCK_SIZE],
) -> Result<usize, &'static str> {
    let mut got = 0;
    while got < block.len() {
        match source.read(&mut block[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("the data could not be read"),
        }
    }
    Ok(got)
}

/// Walk the headers of a tar stream. Returns whether the entry limit cut the
/// list short, or a fixed sentence saying why reading stopped.
fn walk_tar<S: Source>(
    mut source: S,
    entries: &mut Vec<ArchiveEntry>,
    indicators: &mut SuspiciousArchiveIndicators,
    notes: &mut Vec<String>,
) -> Result<bool, &'static str> {
    use tar::EntryType;
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut pax_size: Option<u64> = None;
    let mut skipped_records = 0usize;
    let result = loop {
        if entries.len() >= MAX_ENTRIES {
            break Ok(true);
        }
        let mut block = [0u8; TAR_BLOCK_SIZE];
        match read_block(&mut source, &mut block) {
            Ok(0) => break Ok(false),
            Ok(n) if n < TAR_BLOCK_SIZE => break Err("the data ended inside a header block"),
            Ok(_) => {}
            Err(reason) => break Err(reason),
        }
        if block.iter().all(|&b| b == 0) {
            break Ok(false); // end-of-archive marker
        }
        if !validate_tar_checksum(&block) {
            break Err("a header block failed its checksum");
        }
        let header = tar::Header::from_byte_slice(&block);
        let Ok(mut size) = header.entry_size() else {
            break Err("an entry has an invalid size");
        };
        let kind = header.entry_type();
        let is_record = matches!(
            kind,
            EntryType::GNULongName
                | EntryType::GNULongLink
                | EntryType::XHeader
                | EntryType::XGlobalHeader
        );
        let padding =
            (TAR_BLOCK_SIZE as u64 - size % TAR_BLOCK_SIZE as u64) % TAR_BLOCK_SIZE as u64;
        if is_record {
            if size > MAX_RECORD_BYTES || kind == EntryType::XGlobalHeader {
                if size > MAX_RECORD_BYTES {
                    skipped_records += 1;
                }
                if source.skip(size.saturating_add(padding)).is_err() {
                    break Err("the data could not be skipped");
                }
                continue;
            }
            let mut data = vec![0u8; size as usize];
            if source.read_exact(&mut data).is_err() {
                break Err("the data ended inside a name or extended-header record");
            }
            if source.skip(padding).is_err() {
                break Err("the data could not be skipped");
            }
            match kind {
                EntryType::GNULongName => long_name = Some(cstr(&data)),
                EntryType::GNULongLink => long_link = Some(cstr(&data)),
                _ => {
                    for extension in tar::PaxExtensions::new(&data).flatten() {
                        match extension.key() {
                            Ok("path") => long_name = Some(extension.value_bytes().to_vec()),
                            Ok("linkpath") => long_link = Some(extension.value_bytes().to_vec()),
                            Ok("size") => {
                                pax_size = extension.value().ok().and_then(|v| v.parse().ok());
                            }
                            _ => {}
                        }
                    }
                }
            }
            continue;
        }
        if let Some(over) = pax_size.take() {
            size = over;
        }
        let data_len = size.saturating_add(
            (TAR_BLOCK_SIZE as u64 - size % TAR_BLOCK_SIZE as u64) % TAR_BLOCK_SIZE as u64,
        );
        entries.push(tar_entry(
            header,
            size,
            long_name.take(),
            long_link.take(),
            indicators,
        ));
        if source.skip(data_len).is_err() {
            break Err("the data could not be skipped");
        }
    };
    if skipped_records > 0 {
        notes.push(format!(
            "{skipped_records} long-name or extended-header record(s) over 1 MiB were skipped \
             (the affected entries show their short header names)."
        ));
    }
    result
}

/// The bytes of a NUL-terminated name record.
fn cstr(data: &[u8]) -> Vec<u8> {
    data.split(|&b| b == 0).next().unwrap_or_default().to_vec()
}

fn tar_entry(
    header: &tar::Header,
    size: u64,
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    indicators: &mut SuspiciousArchiveIndicators,
) -> ArchiveEntry {
    use tar::EntryType;
    let kind = match header.entry_type() {
        EntryType::Directory => EntryKind::Directory,
        EntryType::Symlink => EntryKind::Symlink,
        EntryType::Link => EntryKind::Hardlink,
        EntryType::Char => EntryKind::CharDevice,
        EntryType::Block => EntryKind::BlockDevice,
        EntryType::Fifo => EntryKind::Fifo,
        EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => EntryKind::File,
        _ => EntryKind::Other,
    };
    let mode = header.mode().ok();
    let last_modified = header
        .mtime()
        .ok()
        .and_then(|secs| i64::try_from(secs).ok())
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
    let path_bytes = long_name.unwrap_or_else(|| header.path_bytes().into_owned());
    let path = String::from_utf8_lossy(&path_bytes).into_owned();
    let link_target = long_link
        .or_else(|| header.link_name_bytes().map(std::borrow::Cow::into_owned))
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

    build_entry(
        EntrySpec {
            path,
            kind,
            size_compressed: size,
            size_uncompressed: if matches!(kind, EntryKind::File) {
                size
            } else {
                0
            },
            method: "stored".to_string(),
            last_modified,
            crc32: None,
            is_encrypted: false,
            permissions: mode,
            comment: None,
            link_target,
        },
        indicators,
    )
}

/// Detect the TAR type from the content alone (magic bytes), so the same
/// bytes give the same answer under any file name.
fn detect_tar_type<R: Read + Seek>(reader: &mut BufReader<R>) -> Result<ArchiveType> {
    let mut magic = [0u8; 6];
    let read = reader.read(&mut magic)?;
    reader.seek(SeekFrom::Start(0))?;
    let magic = &magic[..read];

    if magic.starts_with(&[0x1f, 0x8b]) {
        if gzip_holds_tar(reader)? {
            return Ok(ArchiveType::TarGz);
        }
        anyhow::bail!(
            "Not a valid TAR file: this is a gzip stream that does not contain a tar archive"
        );
    }
    if magic.starts_with(b"BZh") {
        return Ok(ArchiveType::TarBz2);
    }
    if magic.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return Ok(ArchiveType::TarXz);
    }

    // Check for plain TAR by examining header structure
    if is_valid_tar_header(reader)? {
        Ok(ArchiveType::Tar)
    } else {
        anyhow::bail!("Not a valid TAR file");
    }
}

/// Whether a gzip stream is a tar.gz, decided from the content alone: the
/// first decompressed block is a tar header (or the all-zero block of an empty
/// tar), or the stream cannot be decompressed at all (a damaged tar.gz is
/// reported with a note, not mistaken for another kind of file). A stream that
/// decompresses cleanly to something else is not a tar.
fn gzip_holds_tar<R: Read + Seek>(reader: &mut BufReader<R>) -> Result<bool> {
    let mut block = [0u8; TAR_HEADER_SIZE];
    let mut decoder = flate2::read::GzDecoder::new(&mut *reader);
    let mut got = 0;
    let mut damaged = false;
    while got < block.len() {
        match decoder.read(&mut block[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                damaged = true;
                break;
            }
        }
    }
    let holds = if damaged {
        true
    } else {
        got == block.len() && (has_tar_signature(&block) || block.iter().all(|&b| b == 0))
    };
    reader.seek(SeekFrom::Start(0))?;
    Ok(holds)
}

fn has_tar_signature(header: &[u8; TAR_HEADER_SIZE]) -> bool {
    &header[257..262] == b"ustar" || (header[0] != 0 && validate_tar_checksum(header))
}

/// Check if the file has a valid TAR header
fn is_valid_tar_header<R: Read + Seek>(reader: &mut BufReader<R>) -> Result<bool> {
    let mut header = [0u8; TAR_HEADER_SIZE];

    // Try to read TAR header
    if reader.read_exact(&mut header).is_err() {
        return Ok(false);
    }

    reader.seek(SeekFrom::Start(0))?;

    // Check for TAR magic number in header (bytes 257-262)
    let magic = &header[257..262];
    let ustar_magic = b"ustar";

    // Check for various TAR formats
    if magic == ustar_magic ||
       &header[257..265] == b"ustar\x00\x30\x30" || // POSIX TAR
       &header[257..265] == b"ustar  \x00"
    {
        // GNU TAR
        return Ok(true);
    }

    // Check if it looks like a TAR header by examining filename field
    let filename = &header[0..100];

    // If first 100 bytes contain mostly printable characters, likely TAR
    let printable_count = filename
        .iter()
        .take_while(|&&b| b != 0) // Stop at null terminator
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'/' || b == b'.')
        .count();

    // If we have a reasonable filename and checksum validates, it's likely TAR
    if printable_count > 0 && validate_tar_checksum(&header) {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Validate TAR header checksum
fn validate_tar_checksum(header: &[u8; TAR_HEADER_SIZE]) -> bool {
    // TAR checksum is stored in bytes 148-155 (8 bytes)
    let checksum_field = &header[148..156];

    // Parse stored checksum (octal string, may be null-terminated)
    let checksum_str = std::str::from_utf8(checksum_field).unwrap_or("0");
    let clean_checksum_str = checksum_str.trim_matches(|c: char| c == '\0' || c == ' ');

    let stored_checksum = u32::from_str_radix(clean_checksum_str, 8).unwrap_or(0);

    // Calculate checksum (sum of all bytes, treating checksum field as spaces)
    let mut calculated_checksum = 0u32;
    for (i, &byte) in header.iter().enumerate() {
        if (148..156).contains(&i) {
            calculated_checksum += u32::from(b' '); // Treat checksum field as spaces
        } else {
            calculated_checksum += u32::from(byte);
        }
    }

    stored_checksum == calculated_checksum
}

/// Get human-readable name for TAR variant
const fn get_tar_variant_name(archive_type: &ArchiveType) -> &'static str {
    match archive_type {
        ArchiveType::Tar => "uncompressed",
        ArchiveType::TarGz => "gzip compressed",
        ArchiveType::TarBz2 => "bzip2 compressed",
        ArchiveType::TarXz => "xz compressed",
        _ => "unknown",
    }
}

/// Check if a file is a TAR archive by examining its structure
pub fn is_tar_file<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    if let Ok(file) = File::open(path) {
        let mut reader = BufReader::new(file);

        // Try to detect compressed TAR first
        if let Ok(archive_type) = detect_tar_type(&mut reader) {
            return matches!(
                archive_type,
                ArchiveType::Tar | ArchiveType::TarGz | ArchiveType::TarBz2 | ArchiveType::TarXz
            );
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_analysis::RiskLevel;
    use tempfile::NamedTempFile;

    fn create_minimal_tar() -> Vec<u8> {
        let mut tar = vec![0u8; TAR_HEADER_SIZE * 3]; // Header + data + end blocks

        // Create a simple file entry "test.txt"
        tar[0..8].copy_from_slice(b"test.txt");
        tar[100..108].copy_from_slice(b"0000644 "); // Mode
        tar[108..116].copy_from_slice(b"0001750 "); // UID
        tar[116..124].copy_from_slice(b"0001750 "); // GID
        tar[124..135].copy_from_slice(b"00000000014"); // Size (12 bytes)
        tar[136..148].copy_from_slice(b"14174607250 "); // Mtime
        tar[156] = b'0'; // File type (regular file)
        tar[257..262].copy_from_slice(b"ustar"); // Magic
        tar[263..265].copy_from_slice(b"00"); // Version

        // Initialize checksum field with spaces
        tar[148..156].copy_from_slice(b"        ");

        // Calculate checksum
        let mut checksum = 0u32;
        for &byte in &tar[0..TAR_HEADER_SIZE] {
            checksum += u32::from(byte);
        }

        // Set checksum in proper format
        let checksum_str = format!("{checksum:06o}\0 ");
        tar[148..156].copy_from_slice(checksum_str.as_bytes());

        tar
    }

    #[test]
    fn test_tar_signature_detection() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        assert!(is_tar_file(temp_file.path()));
    }

    #[test]
    fn test_non_tar_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Not a TAR file").unwrap();

        assert!(!is_tar_file(temp_file.path()));
    }

    #[test]
    fn test_analyze_tar_valid() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        let result = analyze_tar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Tar));
        assert!(analysis.metadata.created_by.is_some());
    }

    #[test]
    fn test_analyze_tar_invalid() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Invalid TAR").unwrap();

        let result = analyze_tar(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_tar_checksum_validation() {
        // Basic test that the checksum function doesn't panic
        let tar_data = create_minimal_tar();
        let header: [u8; TAR_HEADER_SIZE] = tar_data[0..TAR_HEADER_SIZE].try_into().unwrap();

        assert!(validate_tar_checksum(&header));
    }

    #[test]
    fn test_tar_serialization() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        let analysis = analyze_tar(temp_file.path()).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized.archive_type, ArchiveType::Tar));
        assert_eq!(
            deserialized.metadata.created_by,
            analysis.metadata.created_by
        );
    }

    /// A header block with a raw (unvalidated) name, as a hostile archive has.
    fn raw_entry(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &str,
        kind: tar::EntryType,
        mode: u32,
        link: Option<&str>,
        data: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(data.len() as u64);
        if let Some(link) = link {
            header.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
        }
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }

    fn risk_types(analysis: &ArchiveAnalysis, path: &str) -> Vec<String> {
        analysis
            .entries
            .iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("no entry {path}"))
            .risk_indicators
            .iter()
            .map(|r| r.indicator_type.clone())
            .collect()
    }

    #[test]
    fn entries_are_read_and_flagged() {
        use tar::EntryType::{Block, Char, Directory, Link, Regular, Symlink};
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(&mut b, "pkg/", Directory, 0o755, None, b"");
        raw_entry(&mut b, "pkg/ok.txt", Regular, 0o644, None, b"hello");
        raw_entry(&mut b, "../outside.txt", Regular, 0o644, None, b"x");
        raw_entry(&mut b, "/etc/cron.d/job", Regular, 0o644, None, b"x");
        raw_entry(&mut b, "pkg/in.lnk", Symlink, 0o777, Some("ok.txt"), b"");
        raw_entry(
            &mut b,
            "pkg/out.lnk",
            Symlink,
            0o777,
            Some("../../etc/passwd"),
            b"",
        );
        raw_entry(
            &mut b,
            "pkg/abs.lnk",
            Symlink,
            0o777,
            Some("/etc/passwd"),
            b"",
        );
        raw_entry(&mut b, "pkg/hard", Link, 0o644, Some("/etc/shadow"), b"");
        raw_entry(&mut b, "dev/null", Char, 0o666, None, b"");
        raw_entry(&mut b, "dev/sda", Block, 0o660, None, b"");
        raw_entry(&mut b, "bin/su", Regular, 0o4755, None, b"x");
        let data = b.into_inner().unwrap();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &data).unwrap();

        let analysis = analyze_tar(file.path()).unwrap();
        assert_eq!(analysis.metadata.total_entries, 11);
        assert_eq!(analysis.metadata.total_size_uncompressed, 5 + 1 + 1 + 1);
        assert!(risk_types(&analysis, "pkg/ok.txt").is_empty());
        assert!(risk_types(&analysis, "../outside.txt").contains(&"PathTraversal".to_string()));
        assert!(risk_types(&analysis, "/etc/cron.d/job").contains(&"PathTraversal".to_string()));
        assert_eq!(risk_types(&analysis, "pkg/in.lnk"), ["Link"]);
        assert!(risk_types(&analysis, "pkg/out.lnk").contains(&"LinkEscape".to_string()));
        assert!(risk_types(&analysis, "pkg/abs.lnk").contains(&"LinkEscape".to_string()));
        assert!(risk_types(&analysis, "pkg/hard").contains(&"LinkEscape".to_string()));
        assert!(risk_types(&analysis, "dev/null").contains(&"DeviceNode".to_string()));
        assert!(risk_types(&analysis, "dev/sda").contains(&"DeviceNode".to_string()));
        assert!(risk_types(&analysis, "bin/su").contains(&"Setuid".to_string()));
        assert!(analysis.suspicious_indicators.has_path_traversal);
        assert!(matches!(
            analysis.security_analysis.overall_risk,
            RiskLevel::Critical
        ));
        assert_eq!(analysis.security_analysis.path_traversal_risks.len(), 5);
    }

    #[test]
    fn gzip_tar_is_decompressed_and_measured() {
        use std::io::Write;
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(
            &mut b,
            "big.txt",
            tar::EntryType::Regular,
            0o644,
            None,
            &vec![b'a'; 100_000],
        );
        raw_entry(
            &mut b,
            "../evil",
            tar::EntryType::Regular,
            0o644,
            None,
            b"x",
        );
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).unwrap();
        let gz = gz.finish().unwrap();
        let dir = tempfile::tempdir().unwrap();
        // The extension does not matter: the gzip magic and the tar inside do.
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, &gz).unwrap();

        let analysis = analyze_tar(&path).unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::TarGz));
        assert_eq!(analysis.metadata.total_entries, 2);
        assert_eq!(analysis.metadata.total_size_uncompressed, 100_001);
        assert_eq!(analysis.metadata.total_size_compressed, gz.len() as u64);
        assert!(analysis.metadata.compression_ratio > 0.9);
        assert_ne!(analysis.metadata.compression_ratio, 0.7);
        assert!(analysis.suspicious_indicators.has_path_traversal);
        assert!(analysis.notes.is_empty(), "{:?}", analysis.notes);
    }

    fn gzip_of(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn damaged_gzip_reports_a_note_instead_of_failing() {
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(&mut b, "a.txt", tar::EntryType::Regular, 0o644, None, b"hi");
        let mut tar = b.into_inner().unwrap();
        tar.truncate(1024); // header and data block, without the end marker
        tar.extend(vec![7u8; 4000]); // not a header: the next block is garbage
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.tar.gz");
        std::fs::write(&path, gzip_of(&tar)).unwrap();
        let analysis = analyze_tar(&path).unwrap();
        assert_eq!(analysis.metadata.total_entries, 1);
        let note = analysis.notes.join(" ");
        assert!(note.contains("Stopped reading"), "{note}");
        assert!(!note.contains('\u{7}'), "no raw bytes in notes: {note:?}");
    }

    #[test]
    fn the_file_name_never_changes_the_result() {
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(&mut b, "a.txt", tar::EntryType::Regular, 0o644, None, b"hi");
        let gz = gzip_of(&b.into_inner().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("tiny.tar.gz");
        let named = dir.path().join("keygen_crack_payload.gz");
        std::fs::write(&plain, &gz).unwrap();
        std::fs::write(&named, &gz).unwrap();
        let (x, y) = (analyze_tar(&plain).unwrap(), analyze_tar(&named).unwrap());
        assert_eq!(x.suspicious_indicators.risk_score, 0);
        assert_eq!(
            x.suspicious_indicators.risk_score,
            y.suspicious_indicators.risk_score
        );
        assert!(matches!(y.archive_type, ArchiveType::TarGz));
        // A gzip of text is not a tar under either name.
        let text = gzip_of(b"just some text, not a tar archive\n");
        for name in ["t.gz", "t.tar.gz"] {
            let path = dir.path().join(name);
            std::fs::write(&path, &text).unwrap();
            let error = analyze_tar(&path).unwrap_err().to_string();
            assert!(!error.contains("just some text"), "{error}");
        }
    }

    #[test]
    fn a_v7_style_checksum_is_accepted() {
        // No ustar magic; checksum written as digits, NUL, space.
        let mut tar = create_minimal_tar();
        tar[257..265].fill(0);
        tar[148..156].fill(b' ');
        let sum: u32 = tar[..TAR_HEADER_SIZE].iter().map(|&b| u32::from(b)).sum();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &tar).unwrap();
        let analysis = analyze_tar(file.path()).unwrap();
        assert_eq!(analysis.entries[0].path, "test.txt");
    }

    #[test]
    fn an_oversized_long_name_record_is_skipped_not_read() {
        let mut header = tar::Header::new_gnu();
        header.set_path("././@LongLink").unwrap();
        header.set_entry_type(tar::EntryType::GNULongName);
        header.set_size(256 << 20); // 256 MiB declared, none present
        header.set_cksum();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), header.as_bytes()).unwrap();
        let analysis = analyze_tar(file.path()).unwrap();
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(
            analysis.notes.iter().any(|n| n.contains("over 1 MiB")),
            "{:?}",
            analysis.notes
        );
    }

    #[test]
    fn long_names_and_pax_paths_are_applied() {
        let mut b = tar::Builder::new(Vec::new());
        let long = format!("{}/file.txt", "d".repeat(150));
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut header, &long, &b"x"[..]).unwrap();
        let data = b.into_inner().unwrap();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &data).unwrap();
        let analysis = analyze_tar(file.path()).unwrap();
        assert_eq!(analysis.entries[0].path, long);
    }

    #[test]
    fn a_tar_holding_one_zip_is_not_a_bomb() {
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(
            &mut b,
            "inner.zip",
            tar::EntryType::Regular,
            0o644,
            None,
            &[0u8; 113],
        );
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b.into_inner().unwrap()).unwrap();
        let analysis = analyze_tar(file.path()).unwrap();
        assert!(
            !analysis
                .security_analysis
                .zip_bomb_indicators
                .is_potential_bomb
        );
        assert!(matches!(
            analysis.security_analysis.overall_risk,
            RiskLevel::Low
        ));
    }

    #[test]
    fn huge_declared_sizes_do_not_overflow() {
        let mut b = tar::Builder::new(Vec::new());
        for name in ["a", "b"] {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(1 << 62);
            header.set_cksum();
            b.get_mut().extend_from_slice(header.as_bytes());
        }
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b.into_inner().unwrap()).unwrap();
        let analysis = analyze_tar(file.path()).unwrap();
        assert!(analysis.metadata.total_size_uncompressed >= 1 << 62);
    }

    #[test]
    fn bzip2_and_xz_are_recognized_but_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.tar.bz2");
        std::fs::write(&path, b"BZh91AY&SY....").unwrap();
        let analysis = analyze_tar(&path).unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::TarBz2));
        assert!(analysis.notes[0].contains("unavailable"));
    }

    #[test]
    fn a_plain_gzip_file_is_not_a_tar() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&vec![b'z'; 2000]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt.gz");
        std::fs::write(&path, gz.finish().unwrap()).unwrap();
        assert!(analyze_tar(&path).is_err());
    }
}
