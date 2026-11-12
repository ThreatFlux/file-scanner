use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    build_entry, finish_analysis, saved_ratio, unix_kind, ArchiveAnalysis, ArchiveEntry,
    ArchiveMetadata, ArchiveType, ByteReader, EntryKind, EntrySpec, SuspiciousArchiveIndicators,
    LISTING_CAPPED, LISTING_UNAVAILABLE, MAX_ENTRIES, NAMES_UNCHECKED,
};

/// 7-Zip file header signatures
const SEVENZ_SIGNATURE: &[u8] = b"7z\xBC\xAF\x27\x1C";

/// Size of the fixed start header.
const START_HEADER: u64 = 32;
/// Largest end header read (64 MiB); a bigger one is treated as damaged.
const MAX_HEADER_BYTES: u64 = 64 << 20;
/// Cap on any count read from a header.
const MAX_COUNT: u64 = 1 << 24;
/// Longest file name read, in UTF-16 units; the rest of a longer name is
/// dropped before the risk checks, and the result says so.
const NAME_UNITS: usize = 1 << 18;
/// Most coders in a folder, and most streams in or out of all of them; real
/// archives use a handful.
const MAX_CODERS: u64 = 32;
const MAX_FOLDER_STREAMS: u64 = 64;

/// Method id of AES-256 + SHA-256 (7-Zip's encryption).
const AES_ID: [u8; 4] = [0x06, 0xf1, 0x07, 0x01];

struct Coder {
    id: Vec<u8>,
}

struct Folder {
    coders: Vec<Coder>,
    bind_out: Vec<u64>,
    packed_streams: u64,
    unpack_sizes: Vec<u64>,
    /// Index of the output that no bind pair feeds into another coder: the
    /// stream the folder finally produces. Found once, when the folder is read.
    final_out: Option<usize>,
    crc: Option<u32>,
}

impl Folder {
    /// Size of the stream the folder finally produces.
    fn unpack_size(&self) -> u64 {
        self.final_out
            .and_then(|out| self.unpack_sizes.get(out).copied())
            .unwrap_or(0)
    }

    fn has_aes(&self) -> bool {
        self.coders.iter().any(|c| c.id == AES_ID)
    }

    fn method(&self) -> String {
        self.coders
            .iter()
            .map(|c| method_name(&c.id))
            .collect::<Vec<_>>()
            .join("+")
    }
}

fn method_name(id: &[u8]) -> String {
    match id {
        [0x00] => "copy".to_string(),
        [0x03] => "delta".to_string(),
        [0x04] => "bcj-x86".to_string(),
        [0x21] => "lzma2".to_string(),
        [0x03, 0x01, 0x01] => "lzma".to_string(),
        [0x03, 0x04, 0x01] => "ppmd".to_string(),
        [0x04, 0x01, 0x08] => "deflate".to_string(),
        [0x04, 0x02, 0x02] => "bzip2".to_string(),
        [0x06, 0xf1, 0x07, 0x01] => "aes256".to_string(),
        other => other.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }
}

#[derive(Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<Folder>,
    /// Streams per folder.
    counts: Vec<u64>,
    /// One entry per stream, in folder order: (size, crc).
    streams: Vec<(u64, Option<u32>)>,
}

fn count(r: &mut ByteReader<'_>) -> Option<u64> {
    r.sevenz_number().filter(|&n| n <= MAX_COUNT)
}

/// A count of items that each take at least `min_bytes` of the bytes left in
/// the header, so a tiny header cannot ask for a huge allocation.
fn bounded_count(r: &mut ByteReader<'_>, min_bytes: usize) -> Option<u64> {
    let n = count(r)?;
    let room = (r.remaining() / min_bytes.max(1)) as u64;
    (n <= room).then_some(n)
}

fn bit_vector(r: &mut ByteReader<'_>, n: u64) -> Option<Vec<bool>> {
    let n = usize::try_from(n).ok()?;
    let bytes = r.bytes(n.div_ceil(8))?;
    Some(
        (0..n)
            .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
            .collect(),
    )
}

/// `AllAreDefined` byte, an optional bit vector, then the caller reads the values.
fn defined_vector(r: &mut ByteReader<'_>, n: u64) -> Option<Vec<bool>> {
    if r.u8()? == 0 {
        bit_vector(r, n)
    } else {
        // Every defined value takes at least one byte.
        if n > r.remaining() as u64 {
            return None;
        }
        Some(vec![true; usize::try_from(n).ok()?])
    }
}

fn digests(r: &mut ByteReader<'_>, n: u64) -> Option<Vec<Option<u32>>> {
    let defined = defined_vector(r, n)?;
    let wanted = defined.iter().filter(|&&d| d).count();
    if wanted.checked_mul(4)? > r.remaining() {
        return None;
    }
    defined
        .into_iter()
        .map(|d| if d { r.u32le().map(Some) } else { Some(None) })
        .collect()
}

fn parse_folder(r: &mut ByteReader<'_>) -> Option<Folder> {
    let num_coders = count(r)?;
    if num_coders == 0 || num_coders > MAX_CODERS {
        return None;
    }
    let mut coders = Vec::new();
    let (mut total_in, mut total_out) = (0u64, 0u64);
    for _ in 0..num_coders {
        let flags = r.u8()?;
        if flags & 0x80 != 0 {
            return None;
        }
        let id = r.bytes(usize::from(flags & 0x0f))?.to_vec();
        let (n_in, n_out) = if flags & 0x10 != 0 {
            (count(r)?, count(r)?)
        } else {
            (1, 1)
        };
        if n_in > MAX_CODERS || n_out > MAX_CODERS {
            return None;
        }
        if flags & 0x20 != 0 {
            let props = usize::try_from(count(r)?).ok()?;
            r.skip(props)?;
        }
        total_in += n_in;
        total_out += n_out;
        coders.push(Coder { id });
    }
    if total_in > MAX_FOLDER_STREAMS || total_out > MAX_FOLDER_STREAMS {
        return None;
    }
    let pairs = total_out.checked_sub(1)?;
    let mut bind_out = Vec::new();
    for _ in 0..pairs {
        let _in_index = count(r)?;
        bind_out.push(count(r)?);
    }
    let packed_streams = total_in.checked_sub(pairs)?;
    if packed_streams > 1 {
        for _ in 0..packed_streams {
            count(r)?;
        }
    }
    let final_out = (0..total_out).find(|out| !bind_out.contains(out));
    Some(Folder {
        coders,
        bind_out,
        packed_streams,
        unpack_sizes: vec![0; usize::try_from(total_out).ok()?],
        final_out: final_out.and_then(|out| usize::try_from(out).ok()),
        crc: None,
    })
}

fn parse_streams_info(r: &mut ByteReader<'_>) -> Option<StreamsInfo> {
    let mut info = StreamsInfo::default();
    let mut counts: Option<Vec<u64>> = None;
    let mut sizes: Option<Vec<u64>> = None;
    let mut stream_crcs: Option<Vec<Option<u32>>> = None;
    let (mut seen_pack, mut seen_folders, mut seen_substreams) = (false, false, false);
    loop {
        match r.u8()? {
            0x00 => break,
            0x06 => {
                info.pack_pos = r.sevenz_number()?;
                if seen_pack {
                    return None;
                }
                seen_pack = true;
                let n = bounded_count(r, 1)?;
                let (mut seen_sizes, mut seen_digests) = (false, false);
                loop {
                    match r.u8()? {
                        0x00 => break,
                        0x09 if !seen_sizes => {
                            seen_sizes = true;
                            for _ in 0..n {
                                info.pack_sizes.push(r.sevenz_number()?);
                            }
                        }
                        0x0a if !seen_digests => {
                            seen_digests = true;
                            digests(r, n)?;
                        }
                        _ => return None,
                    }
                }
            }
            0x07 => {
                if seen_folders {
                    return None;
                }
                seen_folders = true;
                if r.u8()? != 0x0b {
                    return None;
                }
                let n = bounded_count(r, 2)?;
                if r.u8()? != 0 {
                    return None; // external folder data
                }
                for _ in 0..n {
                    info.folders.push(parse_folder(r)?);
                }
                let (mut seen_sizes, mut seen_crcs) = (false, false);
                loop {
                    match r.u8()? {
                        0x00 => break,
                        0x0c if !seen_sizes => {
                            seen_sizes = true;
                            for folder in &mut info.folders {
                                for size in &mut folder.unpack_sizes {
                                    *size = r.sevenz_number()?;
                                }
                            }
                        }
                        0x0a if !seen_crcs => {
                            seen_crcs = true;
                            let crcs = digests(r, n)?;
                            for (folder, crc) in info.folders.iter_mut().zip(crcs) {
                                folder.crc = crc;
                            }
                        }
                        _ => return None,
                    }
                }
            }
            0x08 => {
                if seen_substreams {
                    return None;
                }
                seen_substreams = true;
                let (mut seen_counts, mut seen_sizes, mut seen_crcs) = (false, false, false);
                loop {
                    match r.u8()? {
                        0x00 => break,
                        0x0d if !seen_counts => {
                            seen_counts = true;
                            let mut c = Vec::new();
                            let mut total = 0u64;
                            for _ in 0..info.folders.len() {
                                let n = count(r)?;
                                total = total.checked_add(n)?;
                                c.push(n);
                            }
                            // Each stream but the last of a folder needs a size
                            // of at least one byte, and each file at least one
                            // name byte later on.
                            if total > (r.remaining() + info.folders.len()) as u64 {
                                return None;
                            }
                            counts = Some(c);
                        }
                        0x09 if !seen_sizes => {
                            seen_sizes = true;
                            let mut all = Vec::new();
                            let default_counts;
                            let c = match counts.as_ref() {
                                Some(c) => c,
                                None => {
                                    default_counts = vec![1; info.folders.len()];
                                    &default_counts
                                }
                            };
                            for (folder, &n) in info.folders.iter().zip(c) {
                                if n == 0 {
                                    continue;
                                }
                                let mut sum = 0u64;
                                for _ in 1..n {
                                    let size = r.sevenz_number()?;
                                    sum = sum.checked_add(size)?;
                                    all.push(size);
                                }
                                all.push(folder.unpack_size().checked_sub(sum)?);
                            }
                            sizes = Some(all);
                        }
                        0x0a if !seen_crcs => {
                            seen_crcs = true;
                            let default_counts;
                            let c = match counts.as_ref() {
                                Some(c) => c,
                                None => {
                                    default_counts = vec![1; info.folders.len()];
                                    &default_counts
                                }
                            };
                            let unknown: u64 = info
                                .folders
                                .iter()
                                .zip(c)
                                .map(|(f, &n)| if n == 1 && f.crc.is_some() { 0 } else { n })
                                .sum();
                            stream_crcs = Some(digests(r, unknown)?);
                        }
                        _ => return None,
                    }
                }
            }
            _ => return None,
        }
    }

    let counts = counts.unwrap_or_else(|| vec![1; info.folders.len()]);
    let sizes = match sizes {
        Some(s) => s,
        None => {
            // No size list: only valid when every folder holds one stream.
            let mut all = Vec::new();
            for (folder, &n) in info.folders.iter().zip(&counts) {
                match n {
                    0 => {}
                    1 => all.push(folder.unpack_size()),
                    _ => return None,
                }
            }
            all
        }
    };
    let mut crc_iter = stream_crcs.unwrap_or_default().into_iter();
    let mut size_iter = sizes.into_iter();
    for (folder, &n) in info.folders.iter().zip(&counts) {
        for _ in 0..n {
            let crc = if n == 1 && folder.crc.is_some() {
                folder.crc
            } else {
                crc_iter.next().flatten()
            };
            info.streams.push((size_iter.next()?, crc));
        }
    }
    info.counts = counts;
    Some(info)
}

struct FileRecord {
    name: String,
    empty_stream: bool,
    empty_file: bool,
    attributes: Option<u32>,
    mtime: Option<String>,
}

fn filetime(value: u64) -> Option<String> {
    let secs = i64::try_from(value / 10_000_000).ok()? - 11_644_473_600;
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.format("%Y-%m-%d %H:%M:%SZ").to_string())
}

/// The files of a header: the first [`MAX_ENTRIES`] in full, the rest counted.
struct FilesInfo {
    records: Vec<FileRecord>,
    total: usize,
    /// Files that own a data stream.
    with_stream: u64,
    /// Names longer than [`NAME_UNITS`] that were cut before the risk checks.
    names_cut: usize,
}

fn parse_files_info(r: &mut ByteReader<'_>) -> Option<FilesInfo> {
    // Every file has a name of at least its terminating UTF-16 NUL (two bytes).
    let n = count(r)?;
    if n > (r.remaining() / 2) as u64 {
        return None;
    }
    let total = usize::try_from(n).ok()?;
    let kept = total.min(MAX_ENTRIES);
    let mut empty_stream = vec![false; total];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut attributes: Vec<Option<u32>> = Vec::new();
    let mut mtimes: Vec<Option<String>> = Vec::new();
    let mut seen = [false; 6];
    let mut names_cut = 0usize;
    loop {
        let property = r.sevenz_number()?;
        if property == 0 {
            break;
        }
        let size = usize::try_from(r.sevenz_number()?).ok()?;
        let data = r.bytes(size)?;
        let mut d = ByteReader::new(data);
        let slot = match property {
            0x0e => 0,
            0x0f => 1,
            0x11 => 2,
            0x14 => 3,
            0x15 => 4,
            _ => 5,
        };
        if slot < 5 {
            if seen[slot] {
                return None; // each property once
            }
            seen[slot] = true;
        }
        match property {
            0x0e => empty_stream = bit_vector(&mut d, n)?,
            0x0f => {
                let empties = empty_stream.iter().filter(|&&e| e).count() as u64;
                empty_file = bit_vector(&mut d, empties)?;
            }
            0x11 => {
                if d.u8()? != 0 {
                    return None; // external names
                }
                let mut units: Vec<u16> = Vec::new();
                let mut cut = false;
                while d.remaining() >= 2 && names.len() < kept {
                    let unit = d.u16le()?;
                    if unit == 0 {
                        names.push(String::from_utf16_lossy(&units));
                        units.clear();
                        names_cut += usize::from(cut);
                        cut = false;
                    } else if units.len() < NAME_UNITS {
                        units.push(unit);
                    } else {
                        cut = true;
                    }
                }
            }
            0x14 => {
                let defined = defined_vector(&mut d, n)?;
                if d.u8()? != 0 {
                    return None;
                }
                for def in defined.into_iter().take(kept) {
                    mtimes.push(if def { filetime(d.u64le()?) } else { None });
                }
            }
            0x15 => {
                let defined = defined_vector(&mut d, n)?;
                if d.u8()? != 0 {
                    return None;
                }
                for def in defined.into_iter().take(kept) {
                    attributes.push(if def { Some(d.u32le()?) } else { None });
                }
            }
            _ => {}
        }
    }
    let mut empty_index = 0usize;
    let mut with_stream = 0u64;
    let mut records = Vec::with_capacity(kept);
    for (i, &is_empty) in empty_stream.iter().enumerate() {
        let is_empty_file = if is_empty {
            let v = empty_file.get(empty_index).copied().unwrap_or(false);
            empty_index += 1;
            v
        } else {
            with_stream += 1;
            false
        };
        if i < kept {
            records.push(FileRecord {
                name: names.get(i).cloned().unwrap_or_default(),
                empty_stream: is_empty,
                empty_file: is_empty_file,
                attributes: attributes.get(i).copied().flatten(),
                mtime: mtimes.get_mut(i).and_then(Option::take),
            });
        }
    }
    Some(FilesInfo {
        records,
        total,
        with_stream,
        names_cut,
    })
}

/// What parsing the end header produced.
struct Parsed {
    entries: Vec<ArchiveEntry>,
    total_files: usize,
    has_aes: bool,
    solid: bool,
    names_cut: usize,
}

fn parse_header(data: &[u8], indicators: &mut SuspiciousArchiveIndicators) -> Option<Parsed> {
    let mut r = ByteReader::new(data);
    if r.u8()? != 0x01 {
        return None;
    }
    let mut streams = StreamsInfo::default();
    let mut files = FilesInfo {
        records: Vec::new(),
        total: 0,
        with_stream: 0,
        names_cut: 0,
    };
    let (mut seen_streams, mut seen_files) = (false, false);
    loop {
        match r.u8()? {
            0x00 => break,
            0x02 => {
                // ArchiveProperties: (type, size, data)* until type 0
                loop {
                    if r.u8()? == 0 {
                        break;
                    }
                    let size = usize::try_from(r.sevenz_number()?).ok()?;
                    r.skip(size)?;
                }
            }
            0x03 => {
                parse_streams_info(&mut r)?;
            }
            0x04 if !seen_streams => {
                seen_streams = true;
                streams = parse_streams_info(&mut r)?;
            }
            0x05 if !seen_files => {
                seen_files = true;
                files = parse_files_info(&mut r)?;
            }
            _ => return None,
        }
    }

    // Packed size of each folder and which stream belongs to which folder.
    let mut folder_pack = Vec::new();
    let mut pack_index = 0usize;
    for folder in &streams.folders {
        let mut total = 0u64;
        for _ in 0..folder.packed_streams {
            total = total.saturating_add(streams.pack_sizes.get(pack_index).copied().unwrap_or(0));
            pack_index += 1;
        }
        folder_pack.push(total);
    }
    let mut stream_folder = Vec::new();
    for (index, &n) in streams.counts.iter().enumerate() {
        for _ in 0..n {
            stream_folder.push(index);
        }
    }

    if files.with_stream > streams.streams.len() as u64 {
        return None; // more files with data than streams
    }
    let has_aes = streams.folders.iter().any(Folder::has_aes);
    let solid = streams.counts.iter().any(|&n| n > 1);
    let mut entries = Vec::new();
    let mut next_stream = 0usize;
    for file in &files.records {
        let (size, crc, folder) = if file.empty_stream {
            (0, None, None)
        } else {
            let slot = streams.streams.get(next_stream)?;
            let folder = stream_folder.get(next_stream).copied();
            next_stream += 1;
            (slot.0, slot.1, folder)
        };
        let unix = file.attributes.filter(|a| a & 0x8000 != 0).map(|a| a >> 16);
        let mut kind = if file.empty_stream && !file.empty_file {
            EntryKind::Directory
        } else if let Some(mode) = unix {
            unix_kind(mode)
        } else if file.attributes.is_some_and(|a| a & 0x10 != 0) {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        if file.empty_stream && file.empty_file && kind == EntryKind::Directory {
            kind = EntryKind::File;
        }
        let (packed, method, encrypted) = folder.map_or((0, "stored".to_string(), false), |f| {
            let unpack = streams.folders[f].unpack_size();
            let pack = folder_pack[f];
            let share = if unpack == 0 {
                0
            } else {
                u64::try_from(u128::from(pack) * u128::from(size) / u128::from(unpack)).unwrap_or(0)
            };
            (
                share,
                streams.folders[f].method(),
                streams.folders[f].has_aes(),
            )
        });
        entries.push(build_entry(
            EntrySpec {
                path: file.name.replace('\\', "/"),
                kind,
                size_compressed: packed,
                size_uncompressed: size,
                method,
                last_modified: file.mtime.clone(),
                crc32: crc,
                is_encrypted: encrypted,
                permissions: unix.map(|m| m & 0o7777),
                comment: None,
                link_target: None,
            },
            indicators,
        ));
    }
    Some(Parsed {
        entries,
        total_files: files.total,
        has_aes,
        solid,
        names_cut: files.names_cut,
    })
}

/// How the end header was obtained.
enum Header {
    Plain(Vec<u8>),
    /// Why the entry list cannot be read.
    Unavailable(String, bool),
}

fn read_at<R: Read + Seek>(reader: &mut R, pos: u64, len: u64) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(pos))?;
    let mut buf = vec![0u8; usize::try_from(len)?];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Fetch the end header; follows an encoded header when it is stored with the
/// Copy method and reports why it cannot be read otherwise.
fn load_header<R: Read + Seek>(
    reader: &mut R,
    mut data: Vec<u8>,
    file_size: u64,
) -> Result<Header> {
    for _ in 0..4 {
        match data.first() {
            Some(0x01) => return Ok(Header::Plain(data)),
            Some(0x17) => {
                let mut r = ByteReader::new(&data[1..]);
                let Some(info) = parse_streams_info(&mut r) else {
                    return Ok(Header::Unavailable(
                        "the compressed end header could not be parsed".to_string(),
                        false,
                    ));
                };
                let Some(folder) = info.folders.first() else {
                    return Ok(Header::Unavailable(
                        "the encoded header has no data".to_string(),
                        false,
                    ));
                };
                if folder.has_aes() {
                    return Ok(Header::Unavailable(
                        "the archive header is encrypted (AES-256); a password is needed to list entries".to_string(),
                        true,
                    ));
                }
                let single_copy = folder.coders.len() == 1 && folder.coders[0].id == [0x00];
                if !single_copy {
                    return Ok(Header::Unavailable(
                        format!(
                            "the archive header is compressed with {} and cannot be read without a decompressor; \
                             create the archive without header compression (7z -mhc=off) to list entries",
                            folder.method()
                        ),
                        false,
                    ));
                }
                let (Some(&len), start) = (
                    info.pack_sizes.first(),
                    START_HEADER.saturating_add(info.pack_pos),
                ) else {
                    return Ok(Header::Unavailable(
                        "the encoded header has no pack stream".to_string(),
                        false,
                    ));
                };
                if len > MAX_HEADER_BYTES || start.saturating_add(len) > file_size {
                    return Ok(Header::Unavailable(
                        "the encoded header points outside the file".to_string(),
                        false,
                    ));
                }
                data = read_at(reader, start, len)?;
            }
            _ => {
                return Ok(Header::Unavailable(
                    "the end header is not a valid 7z header".to_string(),
                    false,
                ))
            }
        }
    }
    Ok(Header::Unavailable(
        "the end header is nested too deeply".to_string(),
        false,
    ))
}

/// Analyze a 7-Zip archive by reading its end header.
///
/// Entries are listed when the header is stored plain or with the Copy method.
/// A header compressed with LZMA (the 7-Zip default) or encrypted cannot be
/// read without a decompressor, and the result says so in `notes`.
pub fn analyze_7z<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open 7z file")?;
    let mut reader = BufReader::new(file);

    let mut start = [0u8; START_HEADER as usize];
    let mut got = 0;
    while got < start.len() {
        let n = reader
            .read(&mut start[got..])
            .context("Failed to read 7z header")?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got < SEVENZ_SIGNATURE.len() || &start[..SEVENZ_SIGNATURE.len()] != SEVENZ_SIGNATURE {
        anyhow::bail!("Not a valid 7z file");
    }

    let file_size = std::fs::metadata(path)?.len();
    let mut indicators = SuspiciousArchiveIndicators::default();
    let mut notes = Vec::new();
    let mut parsed: Option<Parsed> = None;
    let mut headers_encrypted = false;

    if got < start.len() {
        notes.push(format!(
            "{LISTING_UNAVAILABLE}: the file ends inside the 7z start header."
        ));
    } else {
        let offset = u64::from_le_bytes(start[12..20].try_into().unwrap_or_default());
        let size = u64::from_le_bytes(start[20..28].try_into().unwrap_or_default());
        let begin = START_HEADER.saturating_add(offset);
        if size == 0 {
            notes.push("The archive has no end header (it holds no entries).".to_string());
        } else if size > MAX_HEADER_BYTES || begin.saturating_add(size) > file_size {
            notes.push(format!(
                "{LISTING_UNAVAILABLE}: the end header (offset {offset}, {size} bytes) lies outside the file; the archive is truncated or damaged."
            ));
        } else {
            let raw = read_at(&mut reader, begin, size)?;
            match load_header(&mut reader, raw, file_size)? {
                Header::Plain(bytes) => match parse_header(&bytes, &mut indicators) {
                    Some(result) => parsed = Some(result),
                    None => notes.push(format!(
                        "{LISTING_UNAVAILABLE}: the 7z header could not be parsed; the archive may be damaged."
                    )),
                },
                Header::Unavailable(reason, encrypted) => {
                    headers_encrypted = encrypted;
                    notes.push(format!("{LISTING_UNAVAILABLE}: {reason}."));
                }
            }
        }
    }

    let (entries, total_files, has_aes, solid, names_cut) = parsed
        .map_or((Vec::new(), 0, false, false, 0), |p| {
            (p.entries, p.total_files, p.has_aes, p.solid, p.names_cut)
        });
    if names_cut > 0 {
        notes.push(format!(
            "{NAMES_UNCHECKED}: {names_cut} names are longer than {NAME_UNITS} characters and \
             the risk checks ran only on their first {NAME_UNITS} characters."
        ));
    }
    if total_files > entries.len() {
        notes.push(format!(
            "{LISTING_CAPPED} {} of {total_files} entries were recorded; sizes and the risk \
             level cover only those.",
            entries.len()
        ));
    }
    if solid {
        notes.push(
            "Solid archive: per-entry compressed sizes are proportional estimates.".to_string(),
        );
    }
    let has_encryption = headers_encrypted || has_aes;
    let total_uncompressed = entries
        .iter()
        .fold(0u64, |acc, e| acc.saturating_add(e.size_uncompressed));
    let metadata = ArchiveMetadata {
        total_entries: total_files,
        total_size_compressed: file_size,
        total_size_uncompressed: total_uncompressed,
        compression_ratio: saved_ratio(file_size, total_uncompressed),
        has_encryption,
        has_password: has_encryption,
        comment: None,
        created_by: Some("7-Zip".to_string()),
        creation_date: None,
    };

    finish_analysis(ArchiveType::SevenZip, metadata, entries, indicators, notes)
}

/// Whether `head` starts with the 7z signature.
pub fn has_7z_signature(head: &[u8]) -> bool {
    head.starts_with(SEVENZ_SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_analysis::EntryKind;
    use tempfile::NamedTempFile;

    #[test]
    fn test_7z_signature_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), SEVENZ_SIGNATURE).unwrap();
    }

    #[test]
    fn test_non_7z_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Not a 7z file").unwrap();
    }

    #[test]
    fn test_analyze_7z_invalid_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Invalid 7z").unwrap();

        let result = analyze_7z(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_7z_valid() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 100]); // Add some dummy data
        std::fs::write(temp_file.path(), &content).unwrap();

        let result = analyze_7z(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::SevenZip));
        assert_eq!(analysis.metadata.created_by, Some("7-Zip".to_string()));
    }

    #[test]
    fn test_7z_serialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 1024]);
        std::fs::write(temp_file.path(), &content).unwrap();

        let analysis = analyze_7z(temp_file.path()).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized.archive_type, ArchiveType::SevenZip));
        assert_eq!(
            deserialized.metadata.created_by,
            analysis.metadata.created_by
        );
    }

    /// A 7z NUMBER.
    fn num(v: u64) -> Vec<u8> {
        if v < 0x80 {
            return vec![v as u8];
        }
        for extra in 1..8u32 {
            if v < 1u64 << (8 * extra + (7 - extra)) {
                let mask = (0xffu32 << (8 - extra)) as u8;
                let first = mask | (v >> (8 * extra)) as u8;
                let mut out = vec![first];
                out.extend(&v.to_le_bytes()[..extra as usize]);
                return out;
            }
        }
        let mut out = vec![0xff];
        out.extend(v.to_le_bytes());
        out
    }

    fn names_property(names: &[&str]) -> Vec<u8> {
        let mut data = vec![0u8]; // not external
        for name in names {
            for unit in name.encode_utf16() {
                data.extend(unit.to_le_bytes());
            }
            data.extend([0, 0]);
        }
        let mut out = vec![0x11];
        out.extend(num(data.len() as u64));
        out.extend(data);
        out
    }

    /// An end header for one folder (one coder `coder_id`) holding every
    /// non-empty file; `files` is (name, size, is_empty_stream).
    fn plain_header(
        files: &[(&str, u64, bool)],
        coder_id: &[u8],
        packed: u64,
        attrs: Option<&[u32]>,
    ) -> Vec<u8> {
        let sizes: Vec<u64> = files.iter().filter(|f| !f.2).map(|f| f.1).collect();
        let total: u64 = sizes.iter().sum();
        let mut h = vec![0x01];
        if !sizes.is_empty() {
            h.push(0x04);
            h.extend([0x06, 0x00, 0x01, 0x09]);
            h.extend(num(packed));
            h.push(0x00);
            h.extend([0x07, 0x0b, 0x01, 0x00]);
            h.extend([0x01, coder_id.len() as u8]);
            h.extend(coder_id);
            h.push(0x0c);
            h.extend(num(total));
            h.push(0x00);
            h.extend([0x08, 0x0d]);
            h.extend(num(sizes.len() as u64));
            if sizes.len() > 1 {
                h.push(0x09);
                for size in &sizes[..sizes.len() - 1] {
                    h.extend(num(*size));
                }
            }
            h.extend([0x00, 0x00]);
        }
        h.push(0x05);
        h.extend(num(files.len() as u64));
        let mut bits = vec![0u8; files.len().div_ceil(8)];
        for (i, f) in files.iter().enumerate() {
            if f.2 {
                bits[i / 8] |= 0x80 >> (i % 8);
            }
        }
        if files.iter().any(|f| f.2) {
            h.push(0x0e);
            h.extend(num(bits.len() as u64));
            h.extend(bits);
        }
        h.extend(names_property(
            &files.iter().map(|f| f.0).collect::<Vec<_>>(),
        ));
        if let Some(attrs) = attrs {
            let mut data = vec![1u8, 0u8]; // all defined, not external
            for a in attrs {
                data.extend(a.to_le_bytes());
            }
            h.push(0x15);
            h.extend(num(data.len() as u64));
            h.extend(data);
        }
        h.extend([0x00, 0x00]);
        h
    }

    fn build_7z(packed: &[u8], header: &[u8]) -> Vec<u8> {
        let mut out = SEVENZ_SIGNATURE.to_vec();
        out.extend([0, 4]);
        out.extend([0u8; 4]);
        out.extend((packed.len() as u64).to_le_bytes());
        out.extend((header.len() as u64).to_le_bytes());
        out.extend([0u8; 4]);
        out.extend(packed);
        out.extend(header);
        out
    }

    fn analyze_bytes(bytes: &[u8]) -> ArchiveAnalysis {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        analyze_7z(file.path()).unwrap()
    }

    #[test]
    fn a_plain_header_lists_entries_sizes_and_unix_modes() {
        let files = [
            ("docs", 0, true),
            ("docs/a.txt", 1000, false),
            ("../evil.sh", 20, false),
            ("bin/su", 30, false),
        ];
        let attrs = [0x10u32, 0x20, 0x20, (0o104_755 << 16) | 0x8000 | 0x20];
        let header = plain_header(&files, &[0x21], 120, Some(&attrs));
        let analysis = analyze_bytes(&build_7z(&[0u8; 120], &header));
        assert_eq!(analysis.metadata.total_entries, 4, "{:?}", analysis.notes);
        let by = |p: &str| analysis.entries.iter().find(|e| e.path == p).unwrap();
        assert_eq!(by("docs").entry_kind, EntryKind::Directory);
        assert_eq!(by("docs/a.txt").size_uncompressed, 1000);
        assert_eq!(by("docs/a.txt").compression_method, "lzma2");
        assert_eq!(analysis.metadata.total_size_uncompressed, 1050);
        assert!(by("../evil.sh")
            .risk_indicators
            .iter()
            .any(|r| r.indicator_type == "PathTraversal"));
        assert!(by("bin/su")
            .risk_indicators
            .iter()
            .any(|r| r.indicator_type == "Setuid"));
        assert!(!analysis.metadata.has_encryption);
        assert!(analysis.suspicious_indicators.has_path_traversal);
    }

    #[test]
    fn an_aes_coder_marks_entries_encrypted() {
        let files = [("secret.bin", 64, false)];
        let header = plain_header(&files, &[0x06, 0xf1, 0x07, 0x01], 80, None);
        let analysis = analyze_bytes(&build_7z(&[0u8; 80], &header));
        assert!(analysis.metadata.has_encryption);
        assert!(analysis.entries[0].is_encrypted);
        assert_eq!(analysis.entries[0].compression_method, "aes256");
    }

    #[test]
    fn a_copy_coded_encoded_header_is_followed() {
        let files = [("a.txt", 5, false), ("b.txt", 7, false)];
        let inner = plain_header(&files, &[0x00], 12, None);
        // Data area: 12 packed bytes, then the inner header stored as a pack stream.
        let mut packed = vec![0u8; 12];
        packed.extend(&inner);
        let mut encoded = vec![0x17, 0x06];
        encoded.extend(num(12)); // pack position
        encoded.extend([0x01, 0x09]);
        encoded.extend(num(inner.len() as u64));
        encoded.push(0x00);
        encoded.extend([0x07, 0x0b, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0c]);
        encoded.extend(num(inner.len() as u64));
        encoded.extend([0x00, 0x00]);
        let analysis = analyze_bytes(&build_7z(&packed, &encoded));
        assert_eq!(analysis.metadata.total_entries, 2, "{:?}", analysis.notes);
        assert_eq!(analysis.entries[1].path, "b.txt");
    }

    #[test]
    fn an_lzma_encoded_header_is_reported_not_guessed() {
        let mut encoded = vec![0x17, 0x06, 0x00, 0x01, 0x09, 0x20, 0x00];
        // One coder: LZMA (030101) with 5 property bytes.
        encoded.extend([0x07, 0x0b, 0x01, 0x00, 0x01, 0x23, 0x03, 0x01, 0x01, 0x05]);
        encoded.extend([0x5d, 0, 0, 0x10, 0]);
        encoded.extend([0x0c, 0x40, 0x00, 0x00]);
        let analysis = analyze_bytes(&build_7z(&[0u8; 32], &encoded));
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(!analysis.metadata.has_encryption);
        let note = analysis.notes.join(" ");
        assert!(
            note.contains("lzma") && note.contains("unavailable"),
            "{note}"
        );
    }

    #[test]
    fn damaged_headers_never_panic() {
        let files = [("a.txt", 5, false), ("dir", 0, true)];
        let header = plain_header(&files, &[0x00], 5, None);
        let full = build_7z(&[1u8; 5], &header);
        for cut in 6..full.len() {
            let _ = analyze_bytes(&full[..cut]);
        }
        for i in 37..full.len() {
            let mut copy = full.clone();
            copy[i] ^= 0xff;
            let _ = analyze_bytes(&copy);
        }
    }

    fn parses(header: &[u8]) -> bool {
        parse_header(header, &mut SuspiciousArchiveIndicators::default()).is_some()
    }

    #[test]
    fn a_tiny_header_cannot_ask_for_a_huge_file_list() {
        // CF: a 2^24 file count with no data behind it.
        let mut h = vec![0x01, 0x05];
        h.extend(num(1 << 24));
        h.extend([0, 0]);
        assert!(!parses(&h));
        let analysis = analyze_bytes(&build_7z(&[], &h));
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(analysis.notes.join(" ").contains("unavailable"));
    }

    #[test]
    fn stream_counts_and_digests_are_bounded_by_the_header() {
        // 64 folders that each claim 2^24 streams, then a digest record.
        let mut h = vec![0x01, 0x04, 0x07, 0x0b];
        h.extend(num(64));
        h.push(0x00);
        for _ in 0..64 {
            h.extend([0x01, 0x00]);
        }
        h.push(0x00);
        h.extend([0x08, 0x0d]);
        for _ in 0..64 {
            h.extend(num(1 << 24));
        }
        h.extend([0x0a, 0x01]);
        assert!(!parses(&h));
        // A digest vector larger than the bytes left is refused too.
        let mut r = ByteReader::new(&[0x01, 0, 0, 0, 0]);
        assert!(digests(&mut r, 1 << 20).is_none());
    }

    #[test]
    fn a_coder_with_200000_streams_is_refused_quickly() {
        let n = 200_000u64;
        let mut folder = vec![0x01, 0x11, 0x00];
        folder.extend(num(n));
        folder.extend(num(n));
        for i in 0..n - 1 {
            folder.extend(num(i));
            folder.extend(num(n - 2 - i));
        }
        let mut h = vec![0x01, 0x04, 0x07, 0x0b, 0x01, 0x00];
        h.extend(folder);
        h.push(0x0c);
        h.extend(vec![0u8; n as usize]);
        h.extend([0x00, 0x08, 0x0d]);
        h.extend(num(40));
        h.push(0x09);
        h.extend(vec![0u8; 39]);
        h.extend([0x00, 0x00, 0x05]);
        h.extend(num(40));
        h.extend([0x00, 0x00]);
        let started = std::time::Instant::now();
        assert!(!parses(&h));
        assert!(started.elapsed().as_secs() < 2);
    }

    #[test]
    fn repeated_substream_records_are_refused_not_looped_over() {
        // 300000 folders that hold no streams, then 300000 repeated size ids.
        let folders = 300_000u64;
        let mut h = vec![0x01, 0x04, 0x07, 0x0b];
        h.extend(num(folders));
        h.push(0x00);
        for _ in 0..folders {
            h.extend([0x01, 0x00]);
        }
        h.push(0x00);
        h.extend([0x08, 0x0d]);
        h.extend(vec![0u8; folders as usize]);
        h.extend(vec![0x09u8; 300_000]);
        h.extend([0x00, 0x00, 0x00]);
        let started = std::time::Instant::now();
        assert!(!parses(&h));
        assert!(started.elapsed().as_secs() < 2, "{:?}", started.elapsed());
    }

    #[test]
    fn a_file_count_the_header_cannot_name_is_refused() {
        // 2^24 files claimed, but the header has room for 32768 names at most.
        let mut h = vec![0x01, 0x05];
        h.extend(num(1 << 24));
        h.push(0x19); // some other property, 64 KiB long
        h.extend(num(65_536));
        h.extend(vec![0u8; 65_536]);
        h.extend([0x00, 0x00]);
        assert!(!parses(&h));
    }

    #[test]
    fn more_files_than_the_entry_cap_are_counted_but_not_all_kept() {
        let n = MAX_ENTRIES + 50_000;
        let names: Vec<&str> = vec!["a"; n];
        let mut h = vec![0x01, 0x05];
        h.extend(num(n as u64));
        h.push(0x0e);
        h.extend(num(n.div_ceil(8) as u64));
        h.extend(vec![0xffu8; n.div_ceil(8)]);
        h.extend(names_property(&names));
        h.extend([0x00, 0x00]);
        let analysis = analyze_bytes(&build_7z(&[], &h));
        assert_eq!(analysis.metadata.total_entries, n);
        assert_eq!(analysis.entries.len(), MAX_ENTRIES);
        assert!(analysis.notes.join(" ").contains("Only the first"));
    }

    /// One empty file with this name.
    fn analyze_one_name(name: &str) -> ArchiveAnalysis {
        let mut h = vec![0x01, 0x05, 0x01, 0x0e, 0x01, 0x80];
        h.extend(names_property(&[name]));
        h.extend([0x00, 0x00]);
        analyze_bytes(&build_7z(&[], &h))
    }

    #[test]
    fn a_long_name_is_checked_whole_and_a_cut_name_is_reported() {
        // A traversal after 16,384 units is still seen.
        let within = format!("{}/../../etc/evil.sh", "x".repeat(20_000));
        let analysis = analyze_one_name(&within);
        assert!(analysis.suspicious_indicators.has_path_traversal);
        assert!(analysis
            .notes
            .iter()
            .all(|n| !n.starts_with(NAMES_UNCHECKED)));
        // Beyond the read limit the name is cut and the result says so.
        let beyond = format!("{}/../../etc/evil.sh", "x".repeat(NAME_UNITS + 10));
        let analysis = analyze_one_name(&beyond);
        assert!(
            analysis
                .notes
                .iter()
                .any(|n| n.starts_with(NAMES_UNCHECKED)),
            "{:?}",
            analysis.notes
        );
    }

    #[test]
    fn modified_times_are_marked_utc() {
        // One empty file (empty stream, empty file) with a modification time.
        let mut h = vec![0x01, 0x05, 0x01, 0x0e, 0x01, 0x80, 0x0f, 0x01, 0x80, 0x14];
        let mut data = vec![1u8, 0];
        data.extend(((1_700_000_000u64 + 11_644_473_600) * 10_000_000).to_le_bytes());
        h.extend(num(data.len() as u64));
        h.extend(data);
        h.extend(names_property(&["a"]));
        h.extend([0x00, 0x00]);
        let analysis = analyze_bytes(&build_7z(&[], &h));
        let modified = analysis.entries[0].last_modified.as_deref().unwrap();
        assert!(modified.ends_with('Z'), "{modified}");
    }

    #[test]
    fn sizes_that_overflow_are_summed_without_panicking() {
        // Two folders of 2^63 bytes each.
        let mut h = vec![
            0x01, 0x04, 0x07, 0x0b, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0c,
        ];
        h.extend(num(1 << 63));
        h.extend(num(1 << 63));
        h.extend([0x00, 0x00, 0x05, 0x02]);
        h.extend(names_property(&["a", "b"]));
        h.extend([0x00, 0x00]);
        let analysis = analyze_bytes(&build_7z(&[], &h));
        assert_eq!(analysis.metadata.total_entries, 2, "{:?}", analysis.notes);
        assert_eq!(analysis.metadata.total_size_uncompressed, u64::MAX);
        assert!(analysis.metadata.compression_ratio >= 0.0);
    }

    #[test]
    fn the_archive_name_does_not_change_the_result() {
        let files = [("a.txt", 5, false)];
        let header = plain_header(&files, &[0x00], 5, None);
        let bytes = build_7z(&[1u8; 5], &header);
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("tiny.7z");
        let named = dir.path().join("keygen_crack_payload.7z");
        std::fs::write(&plain, &bytes).unwrap();
        std::fs::write(&named, &bytes).unwrap();
        let (a, b) = (analyze_7z(&plain).unwrap(), analyze_7z(&named).unwrap());
        assert_eq!(
            a.suspicious_indicators.risk_score,
            b.suspicious_indicators.risk_score
        );
    }
}
