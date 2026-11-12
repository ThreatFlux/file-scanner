use anyhow::{Context, Result};
use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub sections: Vec<SectionEntropy>,
    pub packed_indicators: PackedIndicators,
    pub encryption_indicators: EncryptionIndicators,
    pub obfuscation_score: f64,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub is_suspicious: bool,
    pub characteristics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedIndicators {
    pub likely_packed: bool,
    pub packer_signatures: Vec<String>,
    pub compression_ratio_estimate: f64,
    pub import_table_anomalies: Vec<String>,
    pub section_anomalies: Vec<String>,
    pub entry_point_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionIndicators {
    pub likely_encrypted: bool,
    pub high_entropy_regions: Vec<HighEntropyRegion>,
    pub crypto_constants_found: Vec<String>,
    pub random_data_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighEntropyRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub description: String,
}

const ENTROPY_THRESHOLD_PACKED: f64 = 7.0;
const ENTROPY_THRESHOLD_ENCRYPTED: f64 = 7.5;
const ENTROPY_THRESHOLD_COMPRESSED: f64 = 6.5;
/// Below this many bytes an entropy figure says nothing (8 bytes cannot even
/// reach 3 bits), so the range rules are not applied.
const MIN_MEASURABLE_SECTION: u64 = 256;
/// "Encrypted" needs a high-entropy region at least this large.
const MIN_ENCRYPTED_REGION: u64 = 1024;
/// Section headers measured per file, and bytes measured in total. Section
/// tables are file-controlled and may overlap, so the work is bounded.
const MAX_SECTIONS: usize = 4096;
const MAX_MEASURED_BYTES: u64 = 1 << 30;
/// Marker kept in `SectionEntropy::characteristics` for a section whose
/// content was verified to be compressed (not merely named like one).
const COMPRESSED: &str = "compressed";
/// Marker for a zstd-compressed debug section whose frame header fits but whose
/// stream was not decompressed.
const ZSTD_UNVERIFIED: &str = "zstd-compressed (frame header checked, not decompressed)";
/// Marker for a pseudo section made of bytes no section header accounts for.
const UNCOVERED: &str = "not covered by any section";

/// Work budget shared by the section walkers; `notes` ends up in the
/// recommendations so a cut is never silent.
struct Budget {
    measured: u64,
    sections: usize,
    outside_file: usize,
    /// Bytes inflated while verifying compressed sections.
    inflated: u64,
    notes: Vec<String>,
    /// Facts worth knowing that do not mean the analysis was cut (ranges that
    /// were validated and deliberately not measured).
    info: Vec<String>,
    /// Section names kept so far (a name is cut and every copy is charged).
    names: crate::binary_parser::NameBudget,
}

impl Budget {
    /// A section name to keep: cut at the name cap and charged to the shared
    /// name budget. Once the budget is used up every further name reads
    /// "[name omitted]" (the section is still measured) and a note says so.
    fn keep_name(&mut self, name: &str) -> String {
        let capped = crate::binary_parser::capped_name(name);
        if self.names.charge(&capped, 1) {
            return capped.into_owned();
        }
        let note = crate::binary_parser::name_budget_note("sections");
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
        "[name omitted]".to_string()
    }

    fn new() -> Self {
        Self {
            names: crate::binary_parser::NameBudget::default(),
            measured: 0,
            sections: 0,
            outside_file: 0,
            inflated: 0,
            notes: Vec::new(),
            info: Vec::new(),
        }
    }

    /// The bytes `[offset, offset+size)` of `buffer`, if they lie inside it and
    /// the budget allows measuring them.
    fn take<'a>(
        &mut self,
        buffer: &'a [u8],
        offset: u64,
        size: u64,
        name: &str,
    ) -> Option<&'a [u8]> {
        let end = offset.checked_add(size);
        let Some(end) = end.filter(|e| *e <= buffer.len() as u64) else {
            if size > 0 {
                self.outside_file += 1;
            }
            return None;
        };
        if self.sections >= MAX_SECTIONS || self.measured.saturating_add(size) > MAX_MEASURED_BYTES
        {
            if self.notes.is_empty() {
                let shown = crate::binary_parser::capped_name(name);
                self.notes.push(format!(
                    "Some sections were not measured: from section '{shown}' on, the section table exceeds {MAX_SECTIONS} sections or {} MiB of content (overlapping sections?).",
                    MAX_MEASURED_BYTES >> 20
                ));
            }
            return None;
        }
        self.sections += 1;
        self.measured += size;
        Some(&buffer[offset as usize..end as usize])
    }
}

/// Characteristic for an allocated or executable section that claims
/// `SHF_COMPRESSED`: compressed DWARF is never loaded, so the flag there is an
/// anomaly, not an excuse.
const BOGUS_COMPRESSED: &str = "SHF_COMPRESSED on an allocated or executable section";

/// Output one compressed section may inflate to, and all of them together.
const MAX_INFLATE_PER_SECTION: u64 = 256 << 20;
const MAX_INFLATE_TOTAL: u64 = 1 << 30;

/// True when `stream` is a complete zlib stream: it ends (`StreamEnd`), inflates
/// to exactly `expected` bytes, uses all of the stored bytes but a few of
/// padding, and the inflated data is not itself random. A valid two-byte header
/// or a valid prefix followed by anything else does not pass.
fn zlib_stream_inflates(stream: &[u8], expected: u64, budget: &mut Budget) -> bool {
    use flate2::{Decompress, FlushDecompress, Status};
    if stream.len() < 2
        || expected == 0
        || expected > MAX_INFLATE_PER_SECTION
        || budget.inflated.saturating_add(expected) > MAX_INFLATE_TOTAL
    {
        return false;
    }
    let mut out = vec![0u8; 64 << 10];
    let mut frequency = [0u64; 256];
    let mut inflater = Decompress::new(true);
    let ended = loop {
        let consumed = inflater.total_in() as usize;
        let before = inflater.total_out();
        let status = inflater.decompress(&stream[consumed..], &mut out, FlushDecompress::None);
        let produced = (inflater.total_out() - before) as usize;
        budget.inflated = budget.inflated.saturating_add(produced as u64);
        for &byte in &out[..produced] {
            frequency[byte as usize] += 1;
        }
        if inflater.total_out() > expected {
            break false;
        }
        match status {
            Ok(Status::StreamEnd) => break true,
            Ok(Status::Ok) if produced > 0 || inflater.total_in() as usize > consumed => {}
            _ => break false,
        }
    };
    if !ended || inflater.total_out() != expected {
        return false;
    }
    if stream.len() as u64 - inflater.total_in() > 7 {
        return false;
    }
    // Compressed DWARF inflates to structured data; random output is a payload
    entropy_from_frequency(&frequency, expected) <= ENTROPY_THRESHOLD_ENCRYPTED
        || expected < MIN_ENCRYPTED_REGION
}

fn entropy_from_frequency(frequency: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    frequency.iter().filter(|c| **c > 0).fold(0.0, |e, &c| {
        let p = c as f64 / len;
        p.mul_add(-p.log2(), e)
    })
}

/// What a section's content proves about being compressed.
#[derive(PartialEq, Eq)]
enum Compression {
    No,
    /// A complete zlib stream that inflates to the size the header claims.
    Zlib,
    /// zstd (`ch_type` 2) with a frame header that agrees with the section
    /// header; the stream is not decompressed (no decoder).
    ZstdHeaderOnly,
}

/// Plausibility of a zstd frame header (RFC 8878): magic, no reserved bit, and
/// when a content size is present it equals `expected`.
fn zstd_frame_header_fits(stream: &[u8], expected: u64) -> bool {
    if stream.len() < 6 || stream[..4] != [0x28, 0xb5, 0x2f, 0xfd] {
        return false;
    }
    let descriptor = stream[4];
    if descriptor & 0x08 != 0 {
        return false; // reserved bit
    }
    let single_segment = descriptor & 0x20 != 0;
    let fcs_flag = descriptor >> 6;
    let dict_id_len = [0usize, 1, 2, 4][usize::from(descriptor & 3)];
    let window = usize::from(!single_segment);
    let fcs_len = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let at = 5 + window + dict_id_len;
    let Some(field) = stream.get(at..at + fcs_len) else {
        return false;
    };
    if fcs_len == 0 {
        return true;
    }
    let mut value = 0u64;
    for (i, b) in field.iter().enumerate() {
        value |= u64::from(*b) << (8 * i);
    }
    if fcs_flag == 1 {
        value += 256;
    }
    value == expected
}

/// Evidence that an ELF section really holds compressed data. Only compressed
/// DWARF qualifies: a `.debug_*` section outside the loaded image (not
/// `SHF_ALLOC`, not `SHF_EXECINSTR`) with a valid `Elf_Chdr` whose zlib stream
/// is complete and inflates to the claimed size, or a legacy `.zdebug_*`
/// section with a `ZLIB` header and such a stream. A zstd stream cannot be
/// decompressed here; its frame header is checked and the result is labelled.
fn elf_section_is_compressed(
    name: &str,
    flags: u64,
    data: &[u8],
    is_64: bool,
    le: bool,
    budget: &mut Budget,
) -> Compression {
    const SHF_ALLOC: u64 = 0x2;
    const SHF_EXECINSTR: u64 = 0x4;
    if flags & (SHF_ALLOC | SHF_EXECINSTR) != 0 {
        return Compression::No;
    }
    if flags & 0x800 != 0 {
        if !name.starts_with(".debug_") {
            return Compression::No;
        }
        let rd32 = |o: usize| {
            data.get(o..o + 4).map(|b| {
                let b = [b[0], b[1], b[2], b[3]];
                if le {
                    u32::from_le_bytes(b)
                } else {
                    u32::from_be_bytes(b)
                }
            })
        };
        let (ch_type, header_len, ch_size) = if is_64 {
            let size = data.get(8..16).map(|b| {
                let b: [u8; 8] = b.try_into().unwrap_or([0; 8]);
                if le {
                    u64::from_le_bytes(b)
                } else {
                    u64::from_be_bytes(b)
                }
            });
            (rd32(0), 24usize, size)
        } else {
            (rd32(0), 12usize, rd32(4).map(u64::from))
        };
        let (Some(ch_type), Some(ch_size)) = (ch_type, ch_size) else {
            return Compression::No;
        };
        let payload = data.get(header_len..).unwrap_or(&[]);
        // Compression must shrink the data: the claimed size exceeds what is stored
        if ch_size <= payload.len() as u64 {
            return Compression::No;
        }
        return match ch_type {
            1 if zlib_stream_inflates(payload, ch_size, budget) => Compression::Zlib,
            2 if zstd_frame_header_fits(payload, ch_size) => Compression::ZstdHeaderOnly,
            _ => Compression::No,
        };
    }
    if name.starts_with(".zdebug_") && data.starts_with(b"ZLIB") && data.len() > 12 {
        let size = data
            .get(4..12)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(0, u64::from_be_bytes);
        if zlib_stream_inflates(&data[12..], size, budget) {
            return Compression::Zlib;
        }
    }
    Compression::No
}

pub fn analyze_entropy(path: &Path) -> Result<EntropyAnalysis> {
    let mut file = File::open(path).context("Failed to open file for entropy analysis")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Failed to read file")?;

    let overall_entropy = calculate_entropy(&buffer);
    let mut budget = Budget::new();
    let (mut sections, scope) = analyze_sections(&buffer, path, &mut budget)?;
    if let Some(scope) = scope {
        add_uncovered_ranges(&buffer, &mut sections, &scope, &mut budget);
    }
    let budget_info = std::mem::take(&mut budget.info);
    let packed_indicators = detect_packing(&buffer, &sections, path)?;
    let encryption_indicators = detect_encryption(&buffer, &sections);
    let obfuscation_score =
        calculate_obfuscation_score(&sections, &packed_indicators, &encryption_indicators);
    let mut recommendations =
        generate_recommendations(&sections, &packed_indicators, &encryption_indicators);
    if budget.outside_file > 0 {
        budget.notes.push(format!(
            "{} section header(s) point outside the file and were not measured.",
            budget.outside_file
        ));
    }
    let nothing_found = |r: &String| r.starts_with("No significant obfuscation");
    if !budget.notes.is_empty() {
        // A cut analysis is never reported as "nothing found"; the notes lead.
        recommendations.retain(|r| !nothing_found(r));
        for (i, note) in budget.notes.into_iter().enumerate() {
            recommendations.insert(i, note);
        }
    }
    if overall_entropy > ENTROPY_THRESHOLD_PACKED
        && encryption_indicators.high_entropy_regions.is_empty()
    {
        // Whatever else is listed, a high overall figure that no region explains
        // is said outright (and replaces the "nothing found" line).
        recommendations.retain(|r| !nothing_found(r));
        recommendations.push(format!(
            "Overall entropy is {overall_entropy:.2}, above the packed threshold, but no measured section explains it; the file may hold data the section table does not describe."
        ));
    }
    recommendations.extend(budget_info);

    Ok(EntropyAnalysis {
        overall_entropy,
        sections,
        packed_indicators,
        encryption_indicators,
        obfuscation_score,
        recommendations,
    })
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / len;
            entropy = probability.mul_add(-probability.log2(), entropy);
        }
    }

    entropy
}

/// The byte range of the image whose sections were walked, and ranges that are
/// legitimately outside every section (headers, a validated signature).
struct Scope {
    lo: u64,
    hi: u64,
    covered: Vec<(u64, u64)>,
}

/// Minimum size of a range outside every section that is measured on its own.
const MIN_UNCOVERED_RANGE: u64 = 1024;
/// Ranges outside the sections that are listed per file (all are measured).
const MAX_UNCOVERED_RANGES: usize = 64;
/// Window for finding a high-entropy run inside a large uncovered range.
const UNCOVERED_WINDOW: u64 = 64 << 10;

/// Measures the bytes no section accounts for (an appended payload, the data of
/// a section whose header points past the file or is typed NOBITS) as pseudo
/// sections `overlay` and `unmapped`, so they cannot hide from the thresholds.
/// Every range is measured (the cost is at most the file size); only the
/// listing is capped, with the suspicious ones first and a note for the rest.
/// A range larger than one window is also scanned in windows, so a payload
/// diluted with zeros is not averaged away; such a run is listed as its own
/// section.
fn add_uncovered_ranges(
    buffer: &[u8],
    sections: &mut Vec<SectionEntropy>,
    scope: &Scope,
    budget: &mut Budget,
) {
    let hi = scope.hi.min(buffer.len() as u64);
    let mut ranges: Vec<(u64, u64)> = sections
        .iter()
        .map(|s| (s.offset, s.offset.saturating_add(s.size)))
        .chain(scope.covered.iter().copied())
        .map(|(a, b)| (a.max(scope.lo), b.min(hi)))
        .filter(|(a, b)| a < b)
        .collect();
    ranges.sort_unstable();
    let mut gaps = Vec::new();
    let mut cursor = scope.lo;
    for (a, b) in ranges {
        if a > cursor {
            gaps.push((cursor, a));
        }
        cursor = cursor.max(b);
    }
    if cursor < hi {
        gaps.push((cursor, hi));
    }
    let mut found = Vec::new();
    for (a, b) in gaps
        .into_iter()
        .filter(|(a, b)| b - a >= MIN_UNCOVERED_RANGE)
    {
        let name = if b == hi { "overlay" } else { "unmapped" };
        let mut push = |name: String, a: u64, b: u64| {
            let entropy = calculate_entropy(&buffer[a as usize..b as usize]);
            let size = b - a;
            let characteristics = vec![UNCOVERED.to_string()];
            let is_suspicious =
                determine_suspicious_entropy(&name, entropy, size, &characteristics);
            found.push(SectionEntropy {
                name,
                offset: a,
                size,
                entropy,
                is_suspicious,
                characteristics,
            });
        };
        push(name.to_string(), a, b);
        if b - a > UNCOVERED_WINDOW {
            // First run of consecutive windows above the encrypted threshold
            let mut run: Option<(u64, u64)> = None;
            let mut at = a;
            while at < b {
                let end = (at + UNCOVERED_WINDOW).min(b);
                let high = end - at >= MIN_ENCRYPTED_REGION
                    && calculate_entropy(&buffer[at as usize..end as usize])
                        > ENTROPY_THRESHOLD_ENCRYPTED;
                match (&mut run, high) {
                    (None, true) => run = Some((at, end)),
                    (Some(r), true) => r.1 = end,
                    (Some(_), false) => break,
                    (None, false) => {}
                }
                at = end;
            }
            if let Some((ra, rb)) = run.filter(|(ra, rb)| (*ra, *rb) != (a, b)) {
                push(format!("{name} window"), ra, rb);
            }
        }
    }
    found.sort_by(|x, y| {
        y.is_suspicious
            .cmp(&x.is_suspicious)
            .then(y.size.cmp(&x.size))
            .then(x.offset.cmp(&y.offset))
    });
    if found.len() > MAX_UNCOVERED_RANGES {
        let rest = found.split_off(MAX_UNCOVERED_RANGES);
        let bytes: u64 = rest.iter().map(|r| r.size).sum();
        // Suspicious ranges sort first, so one left over means more than the
        // cap are suspicious: that is a cut, never "none of them".
        if rest.iter().any(|r| r.is_suspicious) {
            budget.notes.push(format!(
                "{} further ranges outside every section ({bytes} bytes in all) were measured but are not listed, and some of them are suspicious.",
                rest.len()
            ));
        } else {
            budget.info.push(format!(
                "{} smaller ranges outside every section ({bytes} bytes in all) were measured but are not listed; none of them is suspicious.",
                rest.len()
            ));
        }
    }
    sections.extend(found);
}

/// A DER `SEQUENCE` header at the start of `body` whose length fits `body`
/// with at most 8 bytes left over.
fn der_sequence_fills(body: &[u8]) -> bool {
    if body.len() < 4 || body[0] != 0x30 {
        return false;
    }
    let (header, content) = match body[1] {
        n if n < 0x80 => (2usize, usize::from(n)),
        n if (0x81..=0x84).contains(&n) => {
            let count = usize::from(n & 0x7f);
            let mut v = 0usize;
            for b in &body[2..(2 + count).min(body.len())] {
                v = (v << 8) | usize::from(*b);
            }
            (2 + count, v)
        }
        _ => return false,
    };
    let total = header.saturating_add(content);
    total <= body.len() && body.len() - total <= 8
}

/// Largest Authenticode certificate table that is exempted from measuring.
const MAX_EXEMPT_CERTIFICATE_TABLE: u64 = 64 << 10;

/// True when `[start, start+size)` is a chain of `WIN_CERTIFICATE` records
/// (revision 1.0 or 2.0, type X.509 or PKCS#7) whose bodies are DER sequences
/// that fill them, exactly covering the directory. Anything else (random bytes
/// behind a forged header, an oversized table) is measured like any other range.
fn pe_certificate_table_is_valid(buffer: &[u8], start: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(size).filter(|e| {
        (8..=MAX_EXEMPT_CERTIFICATE_TABLE).contains(&size) && *e <= buffer.len() as u64
    }) else {
        return false;
    };
    let mut cursor = start;
    while cursor < end {
        let Some(head) = buffer.get(cursor as usize..(cursor + 8).min(end) as usize) else {
            return false;
        };
        if head.len() < 8 {
            return false;
        }
        let length = u64::from(u32::from_le_bytes([head[0], head[1], head[2], head[3]]));
        let revision = u16::from_le_bytes([head[4], head[5]]);
        let kind = u16::from_le_bytes([head[6], head[7]]);
        if length < 12
            || length > end - cursor
            || !matches!(revision, 0x0100 | 0x0200)
            || !matches!(kind, 1 | 2)
        {
            return false;
        }
        let body = &buffer[(cursor + 8) as usize..(cursor + length) as usize];
        // A PKCS#7 record starts like a CMS signedData (SEQUENCE, then the
        // signedData OID); random bytes behind a forged length do not.
        if !der_sequence_fills(body) || (kind == 2 && !cms_blob_has_signed_data_header(body)) {
            return false;
        }
        cursor += (length + 7) & !7;
    }
    cursor - end < 8
}

/// Largest total of non-code-directory blobs (certificate chain, requirements,
/// entitlements) in an exempted code signature.
const MAX_EXEMPT_SIGNATURE_EXTRAS: usize = 64 << 10;
/// Most bytes a CodeDirectory may spend before its hash slots (header,
/// identifier, team id and the special-slot hashes after them).
const MAX_CODE_DIRECTORY_PREFIX: usize = 2048;

/// The DER of a CMS `ContentInfo` for `signedData` (`06 09 2a 86 48 86 f7 0d
/// 01 07 02`) right after the `SEQUENCE` header, indefinite or definite length.
fn cms_blob_has_signed_data_header(payload: &[u8]) -> bool {
    const OID: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    let Some((&0x30, rest)) = payload.split_first() else {
        return false;
    };
    let Some((&len_byte, rest)) = rest.split_first() else {
        return false;
    };
    let rest = match len_byte {
        0x80 => rest,
        0x81 => rest.get(1..).unwrap_or_default(),
        0x82 => rest.get(2..).unwrap_or_default(),
        0x83 => rest.get(3..).unwrap_or_default(),
        b if b < 0x80 => rest,
        _ => return false,
    };
    rest.starts_with(&OID)
}

/// True when `data[off..off+size]` has the layout of an embedded code
/// signature (`SuperBlob` 0xfade0cc0): a sane index; every blob inside it with
/// a `0xfade....` magic; the blobs tiling it from the end of the index to its
/// end (no gap of more than a few bytes of padding, no overlap), so no bytes
/// hide between them; each CodeDirectory with hash slots exactly as many as its
/// `codeLimit` needs at a page size of 4 KiB or more and a small header and
/// identifier before them; a certificate blob that starts like a CMS
/// `signedData`; and the blobs other than CodeDirectories at most
/// [`MAX_EXEMPT_SIGNATURE_EXTRAS`] together. Anything else is measured.
fn macho_signature_is_valid(data: &[u8], off: u64, size: u64) -> bool {
    let Some(end) = off.checked_add(size).filter(|e| *e <= data.len() as u64) else {
        return false;
    };
    let blob = &data[off as usize..end as usize];
    let be32 = |o: usize| {
        blob.get(o..o.checked_add(4)?)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let (Some(magic), Some(length), Some(count)) = (be32(0), be32(4), be32(8)) else {
        return false;
    };
    if magic != 0xfade_0cc0
        || length < 12
        || length > blob.len()
        || blob.len() - length > 16
        || count > 64
        || 12 + count * 8 > length
    {
        return false;
    }
    let mut extras = 0usize;
    let mut blobs: Vec<(usize, usize)> = Vec::with_capacity(count);
    for i in 0..count {
        let Some(at) = be32(12 + i * 8 + 4) else {
            return false;
        };
        let (Some(sub_magic), Some(sub_len)) = (be32(at), be32(at + 4)) else {
            return false;
        };
        if sub_magic >> 16 != 0xfade || sub_len < 8 || at.saturating_add(sub_len) > length {
            return false;
        }
        blobs.push((at, sub_len));
        if sub_magic == 0xfade_0c02 {
            let (Some(hash_off), Some(n_special), Some(n_code), Some(code_limit)) =
                (be32(at + 16), be32(at + 24), be32(at + 28), be32(at + 32))
            else {
                return false;
            };
            let (Some(&hash_size), Some(&page_shift)) = (blob.get(at + 36), blob.get(at + 39))
            else {
                return false;
            };
            let page = if page_shift == 0 {
                code_limit.max(1)
            } else if (12..=20).contains(&page_shift) {
                1usize << page_shift
            } else {
                return false;
            };
            let hash_end = hash_off.saturating_add(n_code.saturating_mul(usize::from(hash_size)));
            let specials = n_special.saturating_mul(usize::from(hash_size));
            if !(20..=64).contains(&hash_size)
                || hash_end > sub_len
                || sub_len - hash_end > 64
                || code_limit as u64 > off
                || n_code != code_limit.div_ceil(page)
                || n_special > 16
                || hash_off.saturating_sub(specials) > MAX_CODE_DIRECTORY_PREFIX
            {
                return false;
            }
        } else {
            extras = extras.saturating_add(sub_len);
            if sub_magic == 0xfade_0b01 {
                let payload = blob.get(at + 8..at + sub_len).unwrap_or_default();
                if !cms_blob_has_signed_data_header(payload) {
                    return false;
                }
            }
        }
    }
    // The blobs must tile the SuperBlob
    blobs.sort_unstable();
    let mut cursor = 12 + count * 8;
    for (at, len) in blobs {
        if at < cursor || at - cursor > 8 {
            return false;
        }
        cursor = at + len;
    }
    extras <= MAX_EXEMPT_SIGNATURE_EXTRAS && length >= cursor && length - cursor <= 16
}

/// goblin's Mach-O parse, unless the load commands would make it slow (see
/// `binary_parser::check_mach_load_commands`).
fn parse_mach_checked(buffer: &[u8]) -> Option<Mach<'_>> {
    crate::binary_parser::check_mach_load_commands(buffer).ok()?;
    Mach::parse(buffer).ok()
}

fn analyze_sections(
    buffer: &[u8],
    _path: &Path,
    budget: &mut Budget,
) -> Result<(Vec<SectionEntropy>, Option<Scope>)> {
    let mut sections = Vec::new();
    let mut scope = None;

    // Try to parse as different binary formats
    if let Some(selection) = crate::binary_parser::select_fat_slice(buffer, None) {
        // Universal Mach-O: measure the chosen slice; offsets stay file offsets
        if let Some(mach) = parse_mach_checked(selection.data) {
            let base = selection.slices[selection.selected].offset;
            let mut found = analyze_mach_sections(&mach, selection.data, budget)?;
            for section in &mut found {
                section.offset = section.offset.saturating_add(base);
            }
            let covered = mach_covered_ranges(&mach, selection.data, budget)
                .into_iter()
                .map(|(a, b)| (a.saturating_add(base), b.saturating_add(base)))
                .collect();
            scope = Some(Scope {
                lo: base,
                hi: base.saturating_add(selection.data.len() as u64),
                covered,
            });
            sections.extend(found);
        }
    } else if let Ok(elf) = goblin::elf::Elf::parse(buffer) {
        sections.extend(analyze_elf_sections(&elf, buffer, budget)?);
        scope = Some(Scope {
            lo: 0,
            hi: buffer.len() as u64,
            covered: elf_covered_ranges(&elf),
        });
    } else if let Ok(pe) = goblin::pe::PE::parse(buffer) {
        sections.extend(analyze_pe_sections(&pe, buffer, budget)?);
        scope = Some(Scope {
            lo: 0,
            hi: buffer.len() as u64,
            covered: pe_covered_ranges(&pe, buffer, budget),
        });
    } else if let Some(mach) = parse_mach_checked(buffer) {
        sections.extend(analyze_mach_sections(&mach, buffer, budget)?);
        scope = Some(Scope {
            lo: 0,
            hi: buffer.len() as u64,
            covered: mach_covered_ranges(&mach, buffer, budget),
        });
    }

    if sections.is_empty() {
        // Fallback (unknown format, or a known one without measurable
        // sections): analyze the whole file as one section
        let entropy = calculate_entropy(buffer);
        sections.push(SectionEntropy {
            name: "entire_file".to_string(),
            offset: 0,
            size: buffer.len() as u64,
            entropy,
            is_suspicious: entropy > ENTROPY_THRESHOLD_PACKED,
            characteristics: vec![format!("Raw entropy: {:.2}", entropy)],
        });
        scope = None;
    }

    Ok((sections, scope))
}

/// The ELF header and the program and section header tables: structure, not
/// content. Their sizes come from the entry sizes of the class, never from the
/// `e_*entsize` fields.
fn elf_covered_ranges(elf: &Elf) -> Vec<(u64, u64)> {
    let (ehdr, phent, shent) = if elf.is_64 {
        (64u64, 56u64, 64u64)
    } else {
        (52, 32, 40)
    };
    let h = &elf.header;
    vec![
        (0, ehdr),
        (
            h.e_phoff,
            h.e_phoff.saturating_add(u64::from(h.e_phnum) * phent),
        ),
        (h.e_shoff, h.e_shoff.saturating_add(shnum(elf) * shent)),
    ]
}

fn shnum(elf: &Elf) -> u64 {
    elf.section_headers.len() as u64
}

/// The PE headers (up to the first section's data, at most 64 KiB) and the
/// Authenticode certificate table when it is a valid one. A table that is not
/// is measured as a pseudo section.
fn pe_covered_ranges(pe: &PE, buffer: &[u8], budget: &mut Budget) -> Vec<(u64, u64)> {
    let mut covered = Vec::new();
    if let Some(oh) = pe.header.optional_header {
        let first_data = pe
            .sections
            .iter()
            .map(|s| u64::from(s.pointer_to_raw_data))
            .filter(|p| *p > 0)
            .min()
            .unwrap_or(u64::MAX);
        let headers = u64::from(oh.windows_fields.size_of_headers)
            .min(first_data)
            .min(64 << 10);
        covered.push((0, headers));
        if let Some(d) = oh.data_directories.get_certificate_table() {
            let (start, size) = (u64::from(d.virtual_address), u64::from(d.size));
            if pe_certificate_table_is_valid(buffer, start, size) {
                covered.push((start, start + size));
                budget.info.push(format!(
                    "The Authenticode certificate table ({size} bytes at offset {start}) is laid out like an Authenticode certificate table (records, a DER sequence and the signedData header) and was not measured; at most {} KiB are exempted this way.", MAX_EXEMPT_CERTIFICATE_TABLE >> 10
                ));
            }
        }
    }
    covered
}

/// The Mach-O header with its load commands, and the embedded code signature
/// when it is a well-formed one (`macho_signature_is_valid`). The rest of the
/// segments' bytes (`__LINKEDIT` and any other) that no section covers is
/// measured as a pseudo section.
fn mach_covered_ranges(mach: &Mach, data: &[u8], budget: &mut Budget) -> Vec<(u64, u64)> {
    let Mach::Binary(macho) = mach else {
        return Vec::new();
    };
    let header = if macho.is_64 { 32u64 } else { 28 };
    let mut covered = vec![(0, header + u64::from(macho.header.sizeofcmds))];
    for lc in &macho.load_commands {
        if let goblin::mach::load_command::CommandVariant::CodeSignature(sig) = &lc.command {
            let (off, size) = (u64::from(sig.dataoff), u64::from(sig.datasize));
            if macho_signature_is_valid(data, off, size) {
                covered.push((off, off + size));
                budget.info.push(format!(
                    "The embedded code signature ({size} bytes at offset {off}) has the layout of a code signature (hash slots that match the code size, at most {} KiB of other blobs) and was not measured.", MAX_EXEMPT_SIGNATURE_EXTRAS >> 10
                ));
            }
        }
    }
    covered
}

fn analyze_elf_sections(
    elf: &Elf,
    buffer: &[u8],
    budget: &mut Budget,
) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    for section in &elf.section_headers {
        // SHT_NOBITS sections (.bss, .tbss) occupy no bytes in the file
        if section.sh_size == 0 || section.sh_type == goblin::elf::section_header::SHT_NOBITS {
            continue;
        }

        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("unknown");

        if let Some(section_data) = budget.take(buffer, section.sh_offset, section.sh_size, name) {
            let entropy = calculate_entropy(section_data);

            let mut characteristics = Vec::new();
            if section.is_executable() {
                characteristics.push("executable".to_string());
            }
            if section.is_writable() {
                characteristics.push("writable".to_string());
            }
            // Only evidence counts: SHF_COMPRESSED or a `.zdebug_` name alone
            // does not make random bytes "compressed debug data".
            let compression = elf_section_is_compressed(
                name,
                section.sh_flags,
                section_data,
                elf.is_64,
                elf.little_endian,
                budget,
            );
            if compression == Compression::Zlib {
                characteristics.push(COMPRESSED.to_string());
            } else if compression == Compression::ZstdHeaderOnly {
                characteristics.push(ZSTD_UNVERIFIED.to_string());
            } else if section.sh_flags & 0x800 != 0 && section.sh_flags & 0x6 != 0 {
                characteristics.push(BOGUS_COMPRESSED.to_string());
            }

            let is_suspicious =
                determine_suspicious_entropy(name, entropy, section.sh_size, &characteristics);

            sections.push(SectionEntropy {
                name: budget.keep_name(name),
                offset: section.sh_offset,
                size: section.sh_size,
                entropy,
                is_suspicious,
                characteristics,
            });
        }
    }

    Ok(sections)
}

fn analyze_pe_sections(pe: &PE, buffer: &[u8], budget: &mut Budget) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    for section in &pe.sections {
        // A PE section name is at most 8 bytes
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        if let Some(section_data) = budget.take(
            buffer,
            u64::from(section.pointer_to_raw_data),
            u64::from(section.size_of_raw_data),
            &name,
        ) {
            let entropy = calculate_entropy(section_data);

            let mut characteristics = Vec::new();
            if section.characteristics & 0x2000_0000 != 0 {
                characteristics.push("executable".to_string());
            }
            if section.characteristics & 0x8000_0000 != 0 {
                characteristics.push("writable".to_string());
            }

            let is_suspicious = determine_suspicious_entropy(
                &name,
                entropy,
                u64::from(section.size_of_raw_data),
                &characteristics,
            );

            sections.push(SectionEntropy {
                name,
                offset: u64::from(section.pointer_to_raw_data),
                size: u64::from(section.size_of_raw_data),
                entropy,
                is_suspicious,
                characteristics,
            });
        }
    }

    Ok(sections)
}

fn analyze_mach_sections(
    mach: &Mach,
    buffer: &[u8],
    budget: &mut Budget,
) -> Result<Vec<SectionEntropy>> {
    let mut sections = Vec::new();

    match mach {
        Mach::Binary(macho) => {
            for segment in &macho.segments {
                for (section, _) in segment.sections()? {
                    let name = section.name()?;
                    // Zero-fill sections (__bss, __common) have no file content
                    let zerofill = matches!(section.flags & 0xff, 0x01 | 0x0c | 0x12);
                    if zerofill || section.size == 0 {
                        continue;
                    }
                    if let Some(section_data) =
                        budget.take(buffer, u64::from(section.offset), section.size, name)
                    {
                        let entropy = calculate_entropy(section_data);

                        let characteristics = vec![format!("segment: {}", segment.name()?)];

                        let is_suspicious = determine_suspicious_entropy(
                            name,
                            entropy,
                            section.size,
                            &characteristics,
                        );

                        sections.push(SectionEntropy {
                            name: budget.keep_name(name),
                            offset: u64::from(section.offset),
                            size: section.size,
                            entropy,
                            is_suspicious,
                            characteristics,
                        });
                    }
                }
            }
        }
        Mach::Fat(_) => {
            // analyze_sections hands over the selected slice, never the fat image
        }
    }

    Ok(sections)
}

/// Verified-compressed sections (see `elf_section_is_compressed`) look like
/// random data by design.
fn is_compressed_section(characteristics: &[String]) -> bool {
    characteristics
        .iter()
        .any(|c| c == COMPRESSED || c == ZSTD_UNVERIFIED)
}

fn determine_suspicious_entropy(
    name: &str,
    entropy: f64,
    size: u64,
    characteristics: &[String],
) -> bool {
    if is_compressed_section(characteristics) {
        return false;
    }
    // A few bytes cannot be judged: an 8-byte __text is not "suspicious".
    if size < MIN_MEASURABLE_SECTION {
        return false;
    }
    // Text sections should have moderate entropy (4-6)
    if name == ".text" || name == "__text" {
        return !(4.0..=ENTROPY_THRESHOLD_PACKED).contains(&entropy);
    }

    // Data sections usually have lower entropy
    if name == ".data" || name == "__data" || name == ".rdata" {
        return entropy > 6.0;
    }

    // Executable sections with very high entropy are suspicious
    if characteristics.contains(&"executable".to_string()) && entropy > ENTROPY_THRESHOLD_PACKED {
        return true;
    }

    // Any section with entropy > 7.5 is suspicious
    entropy > ENTROPY_THRESHOLD_ENCRYPTED
}

fn detect_packing(
    buffer: &[u8],
    sections: &[SectionEntropy],
    _path: &Path,
) -> Result<PackedIndicators> {
    let mut packer_signatures = Vec::new();
    let mut import_table_anomalies = Vec::new();
    let mut section_anomalies = Vec::new();
    let mut entry_point_suspicious = false;

    // Check for known packer signatures
    if let Some(sig) = detect_packer_signature(buffer) {
        packer_signatures.push(sig);
    }

    // Check section characteristics
    for section in sections {
        if section.name.is_empty() || section.name.chars().all(|c| !c.is_alphanumeric()) {
            section_anomalies.push(format!("Suspicious section name: '{}'", section.name));
        }

        if section.characteristics.contains(&"executable".to_string())
            && section.characteristics.contains(&"writable".to_string())
        {
            section_anomalies.push(format!(
                "Section {} is both writable and executable",
                section.name
            ));
        }

        if section
            .characteristics
            .iter()
            .any(|c| c == BOGUS_COMPRESSED)
        {
            section_anomalies.push(format!(
                "Section {} carries SHF_COMPRESSED but is allocated or executable",
                section.name
            ));
        }

        if section.entropy > ENTROPY_THRESHOLD_PACKED
            && section.characteristics.contains(&"executable".to_string())
        {
            section_anomalies.push(format!(
                "Section {} has high entropy ({:.2}) for executable code",
                section.name, section.entropy
            ));
        }
    }

    // Check import table (simplified check)
    if let Ok(pe) = goblin::pe::PE::parse(buffer) {
        if pe.imports.is_empty() || pe.imports.len() < 3 {
            import_table_anomalies.push("Unusually small import table".to_string());
        }

        // Check if entry point is in an unusual section
        let entry = pe.entry;
        let mut found_in_normal_section = false;
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name);
            let name = name.trim_end_matches('\0');
            if name == ".text" || name == "CODE" {
                let start = section.virtual_address;
                let end = start.saturating_add(section.virtual_size);
                if entry >= start && entry < end {
                    found_in_normal_section = true;
                    break;
                }
            }
        }
        if !found_in_normal_section {
            entry_point_suspicious = true;
        }
    }

    let compression_ratio_estimate = estimate_compression_ratio(sections);
    let likely_packed = !packer_signatures.is_empty()
        || compression_ratio_estimate > 0.7
        || sections
            .iter()
            .any(|s| s.is_suspicious && s.characteristics.contains(&"executable".to_string()));

    Ok(PackedIndicators {
        likely_packed,
        packer_signatures,
        compression_ratio_estimate,
        import_table_anomalies,
        section_anomalies,
        entry_point_suspicious,
    })
}

fn detect_packer_signature(buffer: &[u8]) -> Option<String> {
    // Common packer signatures (simplified)
    let signatures = vec![
        (&b"UPX0"[..], "UPX"),
        (&b"UPX1"[..], "UPX"),
        (&b"UPX!"[..], "UPX"),
        (&b"MPRESS1"[..], "MPRESS"),
        (&b"MPRESS2"[..], "MPRESS"),
        (&b".petite"[..], "Petite"),
        (&b"PECompact"[..], "PECompact"),
        (&b"ASPack"[..], "ASPack"),
        (&b"FSG!"[..], "FSG"),
        (&b"PEC2"[..], "PECrypt"),
    ];

    for (sig, name) in signatures {
        if buffer.windows(sig.len()).any(|window| window == sig) {
            return Some(name.to_string());
        }
    }

    None
}

fn estimate_compression_ratio(sections: &[SectionEntropy]) -> f64 {
    let high_entropy_sections = sections
        .iter()
        .filter(|s| s.entropy > ENTROPY_THRESHOLD_COMPRESSED)
        .count() as f64;

    if sections.is_empty() {
        return 0.0;
    }

    high_entropy_sections / sections.len() as f64
}

fn detect_encryption(buffer: &[u8], sections: &[SectionEntropy]) -> EncryptionIndicators {
    let mut high_entropy_regions = Vec::new();
    let mut crypto_constants = Vec::new();

    // Look for regions with very high entropy. A verified-compressed section
    // is listed (so the result never reads as "nothing found") but its
    // entropy is expected and does not count toward "encrypted".
    let mut encrypted_region = false;
    for section in sections {
        if section.entropy > ENTROPY_THRESHOLD_ENCRYPTED && section.size >= MIN_MEASURABLE_SECTION {
            let compressed = is_compressed_section(&section.characteristics);
            if !compressed && section.size >= MIN_ENCRYPTED_REGION {
                encrypted_region = true;
            }
            high_entropy_regions.push(HighEntropyRegion {
                offset: section.offset,
                size: section.size,
                entropy: section.entropy,
                description: if section.characteristics.iter().any(|c| c == UNCOVERED) {
                    format!(
                        "Bytes outside every section ('{}', offset {}, {} bytes) have encryption-level entropy",
                        section.name, section.offset, section.size
                    )
                } else if section.characteristics.iter().any(|c| c == ZSTD_UNVERIFIED) {
                    format!(
                        "Section {} is zstd-compressed debug data (only the frame header was checked, the stream was not decompressed); this could not be verified, so treat it as unexplained high entropy",
                        section.name
                    )
                } else if compressed {
                    format!(
                        "Section {} is compressed data (the whole stream inflates to the size it claims); high entropy is expected",
                        section.name
                    )
                } else {
                    format!("Section {} has encryption-level entropy", section.name)
                },
            });
        }
    }

    // Look for known crypto constants
    crypto_constants.extend(find_crypto_constants(buffer));

    // Calculate percentage of random-looking data
    let random_bytes = buffer
        .iter()
        .filter(|&&b| (32..=126).contains(&b)) // Printable ASCII
        .count();
    let random_data_percentage = if buffer.is_empty() {
        0.0
    } else {
        1.0 - (random_bytes as f64 / buffer.len() as f64)
    };

    // "Encrypted" needs a high-entropy region of real size that is not
    // verified-compressed data. Crypto constants (every Go or TLS-linked binary
    // carries some) are reported as their own field and never decide this.
    let likely_encrypted = encrypted_region;

    EncryptionIndicators {
        likely_encrypted,
        high_entropy_regions,
        crypto_constants_found: crypto_constants,
        random_data_percentage,
    }
}

fn find_crypto_constants(buffer: &[u8]) -> Vec<String> {
    let mut found = Vec::new();

    // Common crypto constants (simplified)
    let constants: Vec<(&[u8], &str)> = vec![
        // AES S-box beginning
        (&[0x63, 0x7c, 0x77, 0x7b, 0xf2], "AES S-box"),
        // SHA-256 initial hash values
        (&[0x67, 0xe6, 0x09, 0x6a], "SHA-256 constant"),
        // RC4 initialization
        (
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            "Possible RC4 init",
        ),
        // MD5 constants
        (
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            "MD5 constant",
        ),
    ];

    for (constant, name) in constants {
        if buffer
            .windows(constant.len())
            .any(|window| window == constant)
        {
            found.push(name.to_string());
        }
    }

    found
}

fn calculate_obfuscation_score(
    sections: &[SectionEntropy],
    packed: &PackedIndicators,
    encrypted: &EncryptionIndicators,
) -> f64 {
    let mut score = 0.0;

    // Nothing was measured, so nothing can be scored
    if sections.is_empty() {
        return 0.0;
    }

    // Base score from entropy
    let avg_entropy = sections.iter().map(|s| s.entropy).sum::<f64>() / sections.len() as f64;
    score = (avg_entropy / 8.0).mul_add(30.0, score); // Max 30 points for entropy

    // Packing indicators
    if packed.likely_packed {
        score += 20.0;
    }
    if !packed.packer_signatures.is_empty() {
        score += 10.0;
    }
    if packed.entry_point_suspicious {
        score += 10.0;
    }

    // Encryption indicators
    if encrypted.likely_encrypted {
        score += 15.0;
    }

    // Section anomalies
    score = (packed.section_anomalies.len() as f64)
        .min(3.0)
        .mul_add(5.0, score);

    score.min(100.0) // Cap at 100
}

fn generate_recommendations(
    sections: &[SectionEntropy],
    packed: &PackedIndicators,
    encrypted: &EncryptionIndicators,
) -> Vec<String> {
    let mut recommendations = Vec::new();

    if packed.likely_packed {
        recommendations
            .push("Binary appears to be packed. Consider unpacking before analysis.".to_string());
        if !packed.packer_signatures.is_empty() {
            recommendations.push(format!(
                "Detected packer: {}. Use appropriate unpacking tool.",
                packed.packer_signatures.join(", ")
            ));
        }
    }

    if encrypted.likely_encrypted {
        recommendations.push(
            "Binary contains encrypted/obfuscated regions (encryption-level entropy).".to_string(),
        );
    } else if let Some(region) = encrypted.high_entropy_regions.first() {
        recommendations.push(format!(
            "{} ({} high-entropy region(s) in total).",
            region.description,
            encrypted.high_entropy_regions.len()
        ));
    }
    if !encrypted.crypto_constants_found.is_empty() {
        recommendations.push(format!(
            "Crypto constants present ({}); common in ordinary code and not evidence of encryption by themselves.",
            encrypted.crypto_constants_found.join(", ")
        ));
    }

    for section in sections {
        if section.is_suspicious {
            recommendations.push(format!(
                "Section '{}' has suspicious entropy ({:.2}). Investigate further.",
                section.name, section.entropy
            ));
        }
    }

    if packed.entry_point_suspicious {
        recommendations.push(
            "Entry point is in an unusual section. May indicate runtime unpacking.".to_string(),
        );
    }

    if recommendations.is_empty() {
        recommendations.push(
            "No significant obfuscation detected. Standard analysis should be effective."
                .to_string(),
        );
    }

    recommendations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // All zeros - minimum entropy
        let data1 = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&data1), 0.0);

        // Random data - high entropy
        let data2: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let entropy2 = calculate_entropy(&data2);
        assert!(entropy2 > 7.9 && entropy2 <= 8.0);

        // Text-like data - medium entropy
        let data3 = b"Hello, world! This is a test string with normal text entropy.";
        let entropy3 = calculate_entropy(data3);
        assert!(entropy3 > 3.0 && entropy3 < 6.0);
    }

    /// ELF64 with a NOBITS `.bss` whose offset happens to land on random bytes
    fn elf_with_bss_over_random_bytes() -> Vec<u8> {
        let shstrtab = b"\0.bss\0.shstrtab\0";
        let data_off = 64 + 3 * 64 + shstrtab.len();
        let mut b = vec![0u8; 64];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // 64-bit
        b[5] = 1; // little endian
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        b[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx
        let shdr = |name: u32, kind: u32, off: usize, size: usize| {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&kind.to_le_bytes());
            h[24..32].copy_from_slice(&(off as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            h
        };
        b.extend(shdr(0, 0, 0, 0));
        b.extend(shdr(1, 8, data_off, 4096)); // .bss, SHT_NOBITS
        b.extend(shdr(6, 3, 64 + 3 * 64, shstrtab.len()));
        b.extend_from_slice(shstrtab);
        let mut x = 0x1234_5678u32;
        for _ in 0..4096 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b.push((x >> 24) as u8);
        }
        b
    }

    #[test]
    fn nobits_sections_are_not_measured() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&elf_with_bss_over_random_bytes()).unwrap();
        file.flush().unwrap();
        let result = analyze_entropy(file.path()).unwrap();
        assert!(
            result.sections.iter().all(|s| s.name != ".bss"),
            "{:?}",
            result.sections
        );
        assert!(result.sections.iter().any(|s| s.name == ".shstrtab"));
    }

    #[test]
    fn obfuscation_score_without_sections_is_zero() {
        let packed = PackedIndicators {
            likely_packed: false,
            packer_signatures: vec![],
            compression_ratio_estimate: 0.0,
            import_table_anomalies: vec![],
            section_anomalies: vec![],
            entry_point_suspicious: false,
        };
        let encrypted = EncryptionIndicators {
            likely_encrypted: false,
            high_entropy_regions: vec![],
            crypto_constants_found: vec![],
            random_data_percentage: 0.9,
        };
        let score = calculate_obfuscation_score(&[], &packed, &encrypted);
        assert_eq!(score, 0.0);
    }

    fn section(name: &str, offset: u64, size: u64) -> SectionEntropy {
        SectionEntropy {
            name: name.to_string(),
            offset,
            size,
            entropy: 0.0,
            is_suspicious: false,
            characteristics: Vec::new(),
        }
    }

    fn random(n: usize) -> Vec<u8> {
        let mut x = 0x2545_F491u32;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x >> 11) as u8
            })
            .collect()
    }

    #[test]
    fn random_gap_after_seventy_small_gaps_is_still_found() {
        let mut buffer = Vec::new();
        let mut sections = Vec::new();
        for _ in 0..70 {
            sections.push(section("s", buffer.len() as u64, 16));
            buffer.extend_from_slice(&[1u8; 16]);
            buffer.extend_from_slice(&[0u8; 1024]);
        }
        sections.push(section("end", buffer.len() as u64, 16));
        buffer.extend_from_slice(&[1u8; 16]);
        buffer.extend_from_slice(&random(65536));
        let scope = Scope {
            lo: 0,
            hi: buffer.len() as u64,
            covered: Vec::new(),
        };
        let mut budget = Budget::new();
        add_uncovered_ranges(&buffer, &mut sections, &scope, &mut budget);
        assert!(
            sections.iter().any(|s| s.is_suspicious && s.size >= 65536),
            "the random range was cut away"
        );
        assert!(budget.info.iter().any(|n| n.contains("not listed")));
    }

    #[test]
    fn overlay_diluted_with_zeros_is_found_by_windows() {
        let mut buffer = random(1 << 20);
        buffer.extend(vec![0u8; 300 << 10]);
        let scope = Scope {
            lo: 0,
            hi: buffer.len() as u64,
            covered: Vec::new(),
        };
        let mut sections = Vec::new();
        let mut budget = Budget::new();
        add_uncovered_ranges(&buffer, &mut sections, &scope, &mut budget);
        let window = sections
            .iter()
            .find(|s| s.name.ends_with("window"))
            .expect("no window section");
        assert!(window.is_suspicious && window.offset == 0);
    }

    fn signature_blob(n_code: u32, code_limit: u32, page_shift: u8) -> Vec<u8> {
        let hash_off = 88u32;
        let cd_len = hash_off + n_code * 32;
        let mut cd = Vec::new();
        cd.extend_from_slice(&0xfade_0c02u32.to_be_bytes());
        cd.extend_from_slice(&cd_len.to_be_bytes());
        cd.extend_from_slice(&0x20400u32.to_be_bytes());
        cd.extend_from_slice(&0u32.to_be_bytes());
        cd.extend_from_slice(&hash_off.to_be_bytes());
        cd.extend_from_slice(&0u32.to_be_bytes());
        cd.extend_from_slice(&0u32.to_be_bytes());
        cd.extend_from_slice(&n_code.to_be_bytes());
        cd.extend_from_slice(&code_limit.to_be_bytes());
        cd.extend_from_slice(&[32, 2, 0, page_shift]);
        cd.resize(cd_len as usize, 7);
        let total = 20 + cd.len();
        let mut b = Vec::new();
        b.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
        b.extend_from_slice(&(total as u32).to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&20u32.to_be_bytes());
        b.extend_from_slice(&cd);
        while b.len() % 16 != 0 {
            b.push(0);
        }
        b
    }

    #[test]
    fn code_signature_is_exempt_only_when_its_hash_slots_add_up() {
        let mut data = vec![0u8; 16384];
        let good = signature_blob(2, 8192, 12);
        data.extend_from_slice(&good);
        assert!(macho_signature_is_valid(&data, 16384, good.len() as u64));
        // hash slots for 16 MiB of code in a 16 KiB file
        let mut data = vec![0u8; 16384];
        let forged = signature_blob(4096, 4096 * 4096, 12);
        data.extend_from_slice(&forged);
        assert!(!macho_signature_is_valid(&data, 16384, forged.len() as u64));
        // random bytes with the right magic
        let mut junk = vec![0xfa, 0xde, 0x0c, 0xc0];
        junk.extend(random(5000));
        let mut data = vec![0u8; 16384];
        data.extend_from_slice(&junk);
        assert!(!macho_signature_is_valid(&data, 16384, junk.len() as u64));
    }

    #[test]
    fn zstd_frame_header_must_agree_with_the_claimed_size() {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&1000u32.to_le_bytes());
        frame.extend_from_slice(&[1, 2, 3]);
        assert!(zstd_frame_header_fits(&frame, 1000));
        assert!(!zstd_frame_header_fits(&frame, 1001));
        assert!(!zstd_frame_header_fits(&[0u8; 32], 1000));
    }
}
