use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    build_entry, finish_analysis, saved_ratio, unix_kind, ArchiveAnalysis, ArchiveEntry,
    ArchiveMetadata, ArchiveType, ByteReader, EntryKind, EntrySpec, SuspiciousArchiveIndicators,
    LISTING_PARTIAL, LISTING_UNAVAILABLE, MAX_ENTRIES,
};

/// RAR file header signatures
const RAR_SIGNATURE_V4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR_SIGNATURE_V5: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// Largest header block read (RAR 5 allows more; a bigger one is treated as damaged).
const MAX_HEADER_BYTES: u64 = 1 << 20;
/// Most header blocks (of any type) examined; each costs a seek and a read.
const MAX_BLOCKS: u32 = 1_000_000;

/// What the header walk found.
#[derive(Default)]
struct Walk {
    entries: Vec<ArchiveEntry>,
    headers_encrypted: bool,
    /// The end-of-archive block was reached.
    ended: bool,
    /// The walk stopped because the file ended inside a header or entry data.
    cut_short: bool,
    notes: Vec<String>,
}

/// Analyze a RAR archive by reading its file headers (RAR 4 and RAR 5).
///
/// Only headers are read; nothing is decompressed. An archive whose headers are
/// encrypted lists no entries and says so in `notes`. Names, sizes, link
/// targets and the encryption flag come from the headers themselves.
pub fn analyze_rar<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open RAR file")?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header = [0u8; 8];
    let read = {
        let mut total = 0;
        while total < header.len() {
            let n = reader
                .read(&mut header[total..])
                .context("Failed to read RAR header")?;
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    };
    if read < 7 {
        anyhow::bail!("Failed to read RAR header: file is shorter than the RAR signature");
    }

    // Determine RAR version
    let (version, first_block) = if read == 8 && header == RAR_SIGNATURE_V5 {
        (5, 8)
    } else if &header[0..7] == RAR_SIGNATURE_V4 {
        (4, 7)
    } else {
        anyhow::bail!("Not a valid RAR file");
    };

    let file_size = std::fs::metadata(path)?.len();
    let mut indicators = SuspiciousArchiveIndicators::default();
    let mut walk = Walk::default();
    let walked = if version == 5 {
        walk_v5(
            &mut reader,
            first_block,
            file_size,
            &mut indicators,
            &mut walk,
        )
    } else {
        walk_v4(
            &mut reader,
            first_block,
            file_size,
            &mut indicators,
            &mut walk,
        )
    };
    let walk_failed = walked.is_err();
    if let Err(error) = walked {
        walk.notes.push(if walk.entries.is_empty() {
            format!("{LISTING_UNAVAILABLE}: stopped reading headers ({error})")
        } else {
            format!(
                "{LISTING_PARTIAL}: stopped reading headers after {} ({error}); later entries are \
                 missing, and the counts, sizes and risk rating cover only the entries read.",
                crate::archive_analysis::count_entries(walk.entries.len())
            )
        });
    }
    if walk.headers_encrypted {
        walk.notes.push(format!(
            "{LISTING_UNAVAILABLE}: the archive headers are encrypted, so entry names and sizes \
             cannot be read without the password."
        ));
    } else if !walk_failed
        && !walk.ended
        && walk.entries.len() < MAX_ENTRIES
        && !walk.entries.is_empty()
        && walk.notes.is_empty()
    {
        walk.notes.push(if walk.cut_short {
            format!("{LISTING_PARTIAL}: the file ends inside an entry's data or a header: it is truncated, damaged or one volume of a multi-volume set, so later entries may be missing.")
        } else {
            format!("{LISTING_PARTIAL}: the archive has no end-of-archive block: it is truncated, damaged or one volume of a multi-volume set, so later entries may be missing.")
        });
    }
    if walk.entries.is_empty() && !walk.headers_encrypted && walk.notes.is_empty() {
        walk.notes
            .push("No file headers were found in this archive.".to_string());
    }

    let total_uncompressed = walk
        .entries
        .iter()
        .fold(0u64, |acc, e| acc.saturating_add(e.size_uncompressed));
    let has_encryption = walk.headers_encrypted || walk.entries.iter().any(|e| e.is_encrypted);
    let metadata = ArchiveMetadata {
        total_entries: walk.entries.len(),
        total_size_compressed: file_size,
        total_size_uncompressed: total_uncompressed,
        compression_ratio: saved_ratio(file_size, total_uncompressed),
        has_encryption,
        has_password: has_encryption,
        comment: None,
        created_by: Some(format!("RAR {version}.x")),
        creation_date: None,
    };

    finish_analysis(
        ArchiveType::Rar,
        metadata,
        walk.entries,
        indicators,
        walk.notes,
    )
}

/// DOS date and time (as RAR 4 stores them) to `YYYY-MM-DD HH:MM:SS`.
/// The note for a walk that stopped at [`MAX_BLOCKS`] header blocks.
fn blocks_note(read: usize) -> String {
    if read == 0 {
        format!(
            "{LISTING_UNAVAILABLE}: reading stopped after {MAX_BLOCKS} header blocks without \
             finding an entry."
        )
    } else {
        format!(
            "{LISTING_PARTIAL}: reading stopped after {MAX_BLOCKS} header blocks; later entries, \
             if any, are missing, and the counts, sizes and risk rating cover only the {} read.",
            crate::archive_analysis::count_entries(read)
        )
    }
}

fn dos_time(value: u32) -> Option<String> {
    let (date, time) = (value >> 16, value & 0xffff);
    let (month, day) = ((date >> 5) & 0xf, date & 0x1f);
    if month == 0 || month > 12 || day == 0 {
        return None;
    }
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        1980 + (date >> 9),
        month,
        day,
        time >> 11,
        (time >> 5) & 0x3f,
        (time & 0x1f) * 2
    ))
}

fn walk_v4<R: Read + Seek>(
    reader: &mut R,
    mut pos: u64,
    file_size: u64,
    indicators: &mut SuspiciousArchiveIndicators,
    walk: &mut Walk,
) -> Result<()> {
    let mut blocks = 0u32;
    while walk.entries.len() < MAX_ENTRIES {
        blocks += 1;
        if blocks > MAX_BLOCKS {
            walk.notes.push(blocks_note(walk.entries.len()));
            break;
        }
        if pos.saturating_add(7) > file_size {
            walk.cut_short = pos != file_size;
            break;
        }
        reader.seek(SeekFrom::Start(pos))?;
        let mut fixed = [0u8; 7];
        reader.read_exact(&mut fixed)?;
        let block_type = fixed[2];
        let flags = u16::from_le_bytes([fixed[3], fixed[4]]);
        let head_size = u64::from(u16::from_le_bytes([fixed[5], fixed[6]]));
        if head_size < 7 {
            anyhow::bail!("damaged block header at offset {pos} (size {head_size})");
        }
        if pos + head_size > file_size {
            anyhow::bail!("archive is truncated inside the block header at offset {pos}");
        }
        let mut body = vec![0u8; (head_size - 7) as usize];
        reader.read_exact(&mut body)?;
        let mut data_size = 0u64;
        match block_type {
            0x73 => {
                if flags & 0x80 != 0 {
                    walk.headers_encrypted = true;
                    return Ok(());
                }
            }
            0x74 => {
                let (entry, packed) = parse_v4_file(&body, flags, indicators)?;
                data_size = packed;
                walk.entries.push(entry);
            }
            0x7b => {
                walk.ended = true;
                break;
            }
            _ => {
                if flags & 0x8000 != 0 {
                    data_size = ByteReader::new(&body).u32le().map_or(0, u64::from);
                }
            }
        }
        pos = pos.saturating_add(head_size).saturating_add(data_size);
        if pos > file_size {
            walk.cut_short = true;
        }
    }
    if walk.entries.len() >= MAX_ENTRIES {
        walk.notes.push(format!(
            "{LISTING_PARTIAL}: only the first {MAX_ENTRIES} entries were recorded; the counts, \
             sizes and risk rating cover only those."
        ));
    }
    Ok(())
}

fn parse_v4_file(
    body: &[u8],
    flags: u16,
    indicators: &mut SuspiciousArchiveIndicators,
) -> Result<(ArchiveEntry, u64)> {
    let truncated = || anyhow::anyhow!("a file header is shorter than its fields");
    let mut r = ByteReader::new(body);
    let mut packed = u64::from(r.u32le().ok_or_else(truncated)?);
    let mut unpacked = u64::from(r.u32le().ok_or_else(truncated)?);
    let host_os = r.u8().ok_or_else(truncated)?;
    let crc = r.u32le().ok_or_else(truncated)?;
    let ftime = r.u32le().ok_or_else(truncated)?;
    let _version = r.u8().ok_or_else(truncated)?;
    let method = r.u8().ok_or_else(truncated)?;
    let name_size = usize::from(r.u16le().ok_or_else(truncated)?);
    let attr = r.u32le().ok_or_else(truncated)?;
    if flags & 0x100 != 0 {
        packed |= u64::from(r.u32le().ok_or_else(truncated)?) << 32;
        unpacked |= u64::from(r.u32le().ok_or_else(truncated)?) << 32;
    }
    let raw_name = r.bytes(name_size).ok_or_else(truncated)?;
    // With the Unicode flag the field holds the OEM name, a NUL, then an
    // encoded Unicode form; the OEM part is what is shown.
    let name_bytes = if flags & 0x200 != 0 {
        raw_name.split(|&b| b == 0).next().unwrap_or(raw_name)
    } else {
        raw_name
    };
    let path = String::from_utf8_lossy(name_bytes).replace('\\', "/");

    let unix = host_os == 3;
    let mut kind = if flags & 0xe0 == 0xe0 {
        EntryKind::Directory
    } else if unix {
        unix_kind(attr)
    } else {
        EntryKind::File
    };
    if !unix && kind == EntryKind::File && attr & 0x10 != 0 && unpacked == 0 {
        kind = EntryKind::Directory;
    }
    let method_name = match method {
        0x30 => "store",
        0x31 => "fastest",
        0x32 => "fast",
        0x33 => "normal",
        0x34 => "good",
        0x35 => "best",
        _ => "unknown",
    };
    let entry = build_entry(
        EntrySpec {
            path,
            kind,
            size_compressed: packed,
            size_uncompressed: unpacked,
            method: method_name.to_string(),
            last_modified: dos_time(ftime),
            crc32: Some(crc),
            is_encrypted: flags & 0x04 != 0,
            permissions: unix.then_some(attr & 0o7777),
            comment: None,
            link_target: None,
        },
        indicators,
    );
    Ok((entry, packed))
}

fn walk_v5<R: Read + Seek>(
    reader: &mut R,
    mut pos: u64,
    file_size: u64,
    indicators: &mut SuspiciousArchiveIndicators,
    walk: &mut Walk,
) -> Result<()> {
    let mut blocks = 0u32;
    while walk.entries.len() < MAX_ENTRIES {
        blocks += 1;
        if blocks > MAX_BLOCKS {
            walk.notes.push(blocks_note(walk.entries.len()));
            break;
        }
        if pos.saturating_add(6) > file_size {
            walk.cut_short = pos != file_size;
            break;
        }
        reader.seek(SeekFrom::Start(pos + 4))?; // skip the header CRC
        let mut size_bytes = [0u8; 3];
        let got = reader.read(&mut size_bytes)?;
        let head_size = ByteReader::new(&size_bytes[..got])
            .rar_vint()
            .ok_or_else(|| anyhow::anyhow!("damaged header size at offset {pos}"))?;
        let vint_len = {
            let mut n = 1;
            while n < got && size_bytes[n - 1] & 0x80 != 0 {
                n += 1;
            }
            n as u64
        };
        if head_size == 0 || head_size > MAX_HEADER_BYTES {
            anyhow::bail!("damaged or oversized header ({head_size} bytes) at offset {pos}");
        }
        let body_start = pos + 4 + vint_len;
        if body_start + head_size > file_size {
            anyhow::bail!("archive is truncated inside the header at offset {pos}");
        }
        reader.seek(SeekFrom::Start(body_start))?;
        let mut body = vec![0u8; head_size as usize];
        reader.read_exact(&mut body)?;

        let mut r = ByteReader::new(&body);
        let damaged = || anyhow::anyhow!("damaged header at offset {pos}");
        let block_type = r.rar_vint().ok_or_else(damaged)?;
        let flags = r.rar_vint().ok_or_else(damaged)?;
        let extra_size = if flags & 1 != 0 {
            r.rar_vint().ok_or_else(damaged)?
        } else {
            0
        };
        let data_size = if flags & 2 != 0 {
            r.rar_vint().ok_or_else(damaged)?
        } else {
            0
        };
        match block_type {
            4 => {
                walk.headers_encrypted = true;
                return Ok(());
            }
            5 => {
                walk.ended = true;
                break;
            }
            2 => {
                let entry = parse_v5_file(&mut r, &body, extra_size, data_size, indicators)
                    .ok_or_else(damaged)?;
                walk.entries.push(entry);
            }
            _ => {}
        }
        pos = body_start
            .saturating_add(head_size)
            .saturating_add(data_size);
        if pos > file_size {
            walk.cut_short = true;
        }
    }
    if walk.entries.len() >= MAX_ENTRIES {
        walk.notes.push(format!(
            "{LISTING_PARTIAL}: only the first {MAX_ENTRIES} entries were recorded; the counts, \
             sizes and risk rating cover only those."
        ));
    }
    Ok(())
}

fn parse_v5_file(
    r: &mut ByteReader<'_>,
    body: &[u8],
    extra_size: u64,
    data_size: u64,
    indicators: &mut SuspiciousArchiveIndicators,
) -> Option<ArchiveEntry> {
    let file_flags = r.rar_vint()?;
    let unpacked = r.rar_vint()?;
    let attributes = r.rar_vint()?;
    let mtime = if file_flags & 2 != 0 { r.u32le() } else { None };
    let crc = if file_flags & 4 != 0 { r.u32le() } else { None };
    let comp_info = r.rar_vint()?;
    let host_os = r.rar_vint()?;
    let name_len = usize::try_from(r.rar_vint()?).ok()?;
    let name = String::from_utf8_lossy(r.bytes(name_len)?).into_owned();

    let unix = host_os == 1;
    let mut kind = if file_flags & 1 != 0 {
        EntryKind::Directory
    } else if unix {
        unix_kind(u32::try_from(attributes & 0xffff_ffff).unwrap_or(0))
    } else {
        EntryKind::File
    };

    // The extra area is the last `extra_size` bytes of the header.
    let mut encrypted = false;
    let mut link_target = None;
    if let Some(start) = body.len().checked_sub(usize::try_from(extra_size).ok()?) {
        let mut extra = ByteReader::new(&body[start..]);
        while extra.remaining() > 0 {
            let Some(size) = extra.rar_vint().and_then(|s| usize::try_from(s).ok()) else {
                break;
            };
            let Some(record) = extra.bytes(size) else {
                break;
            };
            let mut rec = ByteReader::new(record);
            match rec.rar_vint() {
                Some(0x01) => encrypted = true,
                Some(0x05) => {
                    let redirect = rec.rar_vint();
                    let _flags = rec.rar_vint();
                    let target_len = rec.rar_vint().and_then(|n| usize::try_from(n).ok());
                    if let (Some(redirect), Some(len)) = (redirect, target_len) {
                        link_target = rec
                            .bytes(len)
                            .map(|b| String::from_utf8_lossy(b).into_owned());
                        kind = match redirect {
                            1..=3 => EntryKind::Symlink,
                            4 | 5 => EntryKind::Hardlink,
                            _ => kind,
                        };
                    }
                }
                _ => {}
            }
        }
    }

    let method = (comp_info >> 7) & 7;
    Some(build_entry(
        EntrySpec {
            path: name,
            kind,
            size_compressed: data_size,
            size_uncompressed: unpacked,
            method: if method == 0 {
                "store".to_string()
            } else {
                format!("method {method}")
            },
            last_modified: mtime.and_then(|secs| {
                chrono::DateTime::from_timestamp(i64::from(secs), 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%SZ").to_string())
            }),
            crc32: crc,
            is_encrypted: encrypted,
            permissions: unix.then(|| u32::try_from(attributes & 0o7777).unwrap_or(0)),
            comment: None,
            link_target,
        },
        indicators,
    ))
}

/// RAR format version (4 or 5) when `head` starts with a RAR signature.
pub fn rar_signature_version(head: &[u8]) -> Option<u8> {
    if head.starts_with(RAR_SIGNATURE_V5) {
        Some(5)
    } else if head.starts_with(RAR_SIGNATURE_V4) {
        Some(4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_rar_signature_detection() {
        // Test RAR v4 signature
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), RAR_SIGNATURE_V4).unwrap();

        // Test RAR v5 signature
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), RAR_SIGNATURE_V5).unwrap();
    }

    #[test]
    fn test_non_rar_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Not a RAR file").unwrap();
        temp_file.flush().unwrap();
    }

    #[test]
    fn test_analyze_rar_invalid_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Invalid RAR").unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_rar_v4() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V4).unwrap();
        // Add some dummy data
        temp_file.write_all(&[0u8; 100]).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Rar));
        assert_eq!(analysis.metadata.created_by, Some("RAR 4.x".to_string()));
    }

    #[test]
    fn test_analyze_rar_v5() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V5).unwrap();
        // Add some dummy data
        temp_file.write_all(&[0u8; 100]).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Rar));
        assert_eq!(analysis.metadata.created_by, Some("RAR 5.x".to_string()));
    }

    fn vint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// A RAR 4 file block followed by `data`.
    fn v4_file(
        name: &str,
        flags: u16,
        unpacked: u32,
        host_os: u8,
        attr: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend((data.len() as u32).to_le_bytes());
        body.extend(unpacked.to_le_bytes());
        body.push(host_os);
        body.extend(0xdead_beefu32.to_le_bytes());
        body.extend(0x5a21_8000u32.to_le_bytes()); // DOS time: 2025-01-01 16:00:00
        body.push(29);
        body.push(0x33);
        body.extend((name.len() as u16).to_le_bytes());
        body.extend(attr.to_le_bytes());
        body.extend(name.as_bytes());
        let mut out = vec![0, 0, 0x74];
        out.extend((flags | 0x8000).to_le_bytes());
        out.extend(((body.len() + 7) as u16).to_le_bytes());
        out.extend(body);
        out.extend(data);
        out
    }

    fn v4_main(flags: u16) -> Vec<u8> {
        let mut out = vec![0, 0, 0x73];
        out.extend(flags.to_le_bytes());
        out.extend(13u16.to_le_bytes());
        out.extend([0u8; 6]);
        out
    }

    /// A RAR 5 block: `fields` is everything after the flags and the optional sizes.
    fn v5_block(block_type: u64, extra: &[u8], data_size: u64, fields: &[u8]) -> Vec<u8> {
        let mut flags = 0;
        let mut body = vint(block_type);
        if !extra.is_empty() {
            flags |= 1;
        }
        if data_size > 0 {
            flags |= 2;
        }
        body.extend(vint(flags));
        if !extra.is_empty() {
            body.extend(vint(extra.len() as u64));
        }
        if data_size > 0 {
            body.extend(vint(data_size));
        }
        body.extend(fields);
        body.extend(extra);
        let mut out = vec![0u8; 4];
        out.extend(vint(body.len() as u64));
        out.extend(body);
        out
    }

    fn v5_file(
        name: &str,
        unpacked: u64,
        attr: u64,
        host_os: u64,
        extra: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut f = vint(0x04); // CRC present
        f.extend(vint(unpacked));
        f.extend(vint(attr));
        f.extend(0x1234_5678u32.to_le_bytes());
        f.extend(vint(0x0080)); // method 1
        f.extend(vint(host_os));
        f.extend(vint(name.len() as u64));
        f.extend(name.as_bytes());
        let mut out = v5_block(2, extra, data.len() as u64, &f);
        out.extend(data);
        out
    }

    fn analyze_bytes(bytes: &[u8]) -> ArchiveAnalysis {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        analyze_rar(file.path()).unwrap()
    }

    #[test]
    fn rar4_headers_give_names_sizes_and_flags() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0));
        rar.extend(v4_file("docs\\", 0xe0, 0, 2, 0x10, b""));
        rar.extend(v4_file("docs\\readme.txt", 0, 5000, 2, 0x20, &[1; 40]));
        rar.extend(v4_file("..\\..\\evil.exe", 0x04, 10, 2, 0x20, &[2; 10])); // password-protected
        rar.extend(v4_file("bin/su", 0, 10, 3, 0o104_755, &[3; 10])); // unix setuid
        rar.extend([0, 0, 0x7b, 0, 0, 7, 0]);
        let analysis = analyze_bytes(&rar);
        assert_eq!(analysis.metadata.total_entries, 4);
        let by = |p: &str| analysis.entries.iter().find(|e| e.path == p).unwrap();
        assert!(by("docs/").is_directory);
        assert_eq!(by("docs/readme.txt").size_uncompressed, 5000);
        assert_eq!(by("docs/readme.txt").size_compressed, 40);
        assert_eq!(by("docs/readme.txt").crc32, Some(0xdead_beef));
        assert!(!by("docs/readme.txt").is_encrypted);
        assert_eq!(
            by("docs/readme.txt").last_modified.as_deref(),
            Some("2025-01-01 16:00:00")
        );
        assert!(by("../../evil.exe").is_encrypted);
        assert!(by("../../evil.exe")
            .risk_indicators
            .iter()
            .any(|r| r.indicator_type == "PathTraversal"));
        assert!(by("bin/su")
            .risk_indicators
            .iter()
            .any(|r| r.indicator_type == "Setuid"));
        assert!(analysis.metadata.has_encryption);
        assert!(analysis.suspicious_indicators.has_path_traversal);
        assert!(analysis.notes.is_empty(), "{:?}", analysis.notes);
    }

    #[test]
    fn rar4_without_encryption_reports_none_even_with_flaggy_bytes() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0x08)); // solid, not password
        rar.extend(v4_file("a.txt", 0, 3, 3, 0o100_644, b"abc"));
        let analysis = analyze_bytes(&rar);
        assert!(!analysis.metadata.has_encryption);
        assert_eq!(analysis.metadata.total_entries, 1);
    }

    #[test]
    fn rar4_encrypted_headers_cannot_be_listed() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0x80));
        rar.extend([0xaa; 64]);
        let analysis = analyze_bytes(&rar);
        assert!(analysis.metadata.has_encryption);
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(analysis.notes.iter().any(|n| n.contains("encrypted")));
    }

    #[test]
    fn rar5_headers_give_names_links_and_encryption() {
        let mut rar = RAR_SIGNATURE_V5.to_vec();
        rar.extend(v5_block(1, &[], 0, &vint(0)));
        rar.extend(v5_file("src/main.c", 1234, 0o100_644, 1, &[], &[7; 100]));
        // Symlink with a redirection record pointing out of the tree.
        let target = "../../etc/passwd";
        let mut record = vint(5);
        record.extend(vint(1));
        record.extend(vint(0));
        record.extend(vint(target.len() as u64));
        record.extend(target.as_bytes());
        let mut extra = vint(record.len() as u64);
        extra.extend(record);
        rar.extend(v5_file("src/link", 0, 0o120_777, 1, &extra, b""));
        // File encryption record.
        let mut enc = vint(1);
        enc.extend([0u8; 4]);
        let mut extra = vint(enc.len() as u64);
        extra.extend(enc);
        rar.extend(v5_file("secret.bin", 50, 0x20, 0, &extra, &[9; 50]));
        rar.extend(v5_block(5, &[], 0, &vint(0)));

        let analysis = analyze_bytes(&rar);
        assert_eq!(analysis.metadata.total_entries, 3, "{:?}", analysis.notes);
        let by = |p: &str| analysis.entries.iter().find(|e| e.path == p).unwrap();
        assert_eq!(by("src/main.c").size_uncompressed, 1234);
        assert_eq!(by("src/main.c").size_compressed, 100);
        assert_eq!(by("src/main.c").crc32, Some(0x1234_5678));
        assert_eq!(
            by("src/link").entry_kind,
            crate::archive_analysis::EntryKind::Symlink
        );
        assert_eq!(by("src/link").link_target.as_deref(), Some(target));
        assert!(by("src/link")
            .risk_indicators
            .iter()
            .any(|r| r.indicator_type == "LinkEscape"));
        assert!(by("secret.bin").is_encrypted);
        assert!(analysis.metadata.has_encryption);
    }

    #[test]
    fn rar5_encrypted_headers_cannot_be_listed() {
        let mut rar = RAR_SIGNATURE_V5.to_vec();
        rar.extend(v5_block(4, &[], 0, &[0u8; 20]));
        let analysis = analyze_bytes(&rar);
        assert!(analysis.metadata.has_encryption);
        assert!(analysis.notes.iter().any(|n| n.contains("encrypted")));
    }

    #[test]
    fn truncated_and_garbage_headers_do_not_panic() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_file("a.txt", 0, 3, 3, 0o100_644, b"abc"));
        for cut in 7..rar.len() {
            let _ = analyze_bytes(&rar[..cut]);
        }
        let mut v5 = RAR_SIGNATURE_V5.to_vec();
        v5.extend(v5_file("a.txt", 3, 0o100_644, 1, &[], b"abc"));
        for cut in 8..v5.len() {
            let _ = analyze_bytes(&v5[..cut]);
        }
        let mut junk = RAR_SIGNATURE_V5.to_vec();
        junk.extend([0xff; 64]);
        let analysis = analyze_bytes(&junk);
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(!analysis.notes.is_empty());
    }

    #[test]
    fn declared_sizes_that_overflow_are_summed_without_panicking() {
        let mut rar = RAR_SIGNATURE_V5.to_vec();
        rar.extend(v5_block(1, &[], 0, &vint(0)));
        rar.extend(v5_file("a", 1 << 63, 0x20, 0, &[], b"x"));
        rar.extend(v5_file("b", 1 << 63, 0x20, 0, &[], b"x"));
        rar.extend(v5_block(5, &[], 0, &vint(0)));
        let analysis = analyze_bytes(&rar);
        assert_eq!(analysis.metadata.total_entries, 2);
        assert_eq!(analysis.metadata.total_size_uncompressed, u64::MAX);
    }

    #[test]
    fn a_walk_that_ends_without_an_end_block_says_so() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0));
        rar.extend(v4_file("a.txt", 0, 3, 3, 0o100_644, b"abc"));
        let analysis = analyze_bytes(&rar);
        assert_eq!(analysis.metadata.total_entries, 1);
        assert!(
            analysis.notes.iter().any(|n| n.contains("end-of-archive")),
            "{:?}",
            analysis.notes
        );
        // Cut inside the data of the second entry.
        rar.extend(v4_file("b.txt", 0, 30, 3, 0o100_644, &[1; 30]));
        rar.truncate(rar.len() - 10);
        let analysis = analyze_bytes(&rar);
        assert!(
            analysis.notes.iter().any(|n| n.contains("truncated")),
            "{:?}",
            analysis.notes
        );
    }

    #[test]
    fn an_unreadable_listing_is_marked_unavailable() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0x80));
        rar.extend([0xaa; 64]);
        let analysis = analyze_bytes(&rar);
        assert!(analysis
            .notes
            .iter()
            .any(|n| n.starts_with(LISTING_UNAVAILABLE)));
        assert_eq!(analysis.metadata.total_size_uncompressed, 0);
    }

    #[test]
    fn the_archive_name_does_not_change_the_result() {
        let mut rar = RAR_SIGNATURE_V4.to_vec();
        rar.extend(v4_main(0));
        rar.extend(v4_file("a.txt", 0, 3, 3, 0o100_644, b"abc"));
        rar.extend([0, 0, 0x7b, 0, 0, 7, 0]);
        let dir = tempfile::tempdir().unwrap();
        let (plain, named) = (dir.path().join("a.rar"), dir.path().join("crack_v2.rar"));
        std::fs::write(&plain, &rar).unwrap();
        std::fs::write(&named, &rar).unwrap();
        let (a, b) = (analyze_rar(&plain).unwrap(), analyze_rar(&named).unwrap());
        assert_eq!(
            a.suspicious_indicators.risk_score,
            b.suspicious_indicators.risk_score
        );
        assert!(!b.suspicious_indicators.has_suspicious_names);
    }
}
