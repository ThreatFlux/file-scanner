//! `llm_analyze_file`: the small, YARA-oriented digest of one file.
//!
//! Identity (SHA-256, file type, architecture), the strings worth putting in a
//! rule, header and footer bytes, imports, the first instructions at the entry
//! point and a draft rule, all inside an output budget (`token_limit`). When
//! the budget forces anything out, the answer says what and how to get it back.

use std::path::{Path, PathBuf};

use capstone::{Arch, Capstone, Mode, NO_EXTRA_MODE};
use goblin::Object;
use rmcp::handler::server::wrapper::Json;
use serde::Serialize;
use serde_json::{json, Value};

use super::{sections::category_rank, LlmFileAnalysisRequest, LlmFileAnalysisResult};
use crate::{
    binary_parser::parse_binary,
    entropy_analysis::analyze_entropy,
    hash::calculate_all_hashes,
    hexdump::{generate_hex_dump, HexDumpOptions},
    mcp_server::{output::strip_nulls, tools_formats::detect_file_kind, FileScannerMcp},
    strings::{extract_strings, ExtractedStrings},
};

/// `token_limit` when the caller names none (characters of compact JSON).
pub const DEFAULT_TOKEN_LIMIT: usize = 25_000;
/// Largest `hex_pattern_size`.
pub const MAX_HEX_PATTERN_SIZE: usize = 1024;
/// Bytes read at the entry point to find its first instructions.
const ENTRY_WINDOW: usize = 64;
/// Largest file the entry point is looked up in (the file is read whole).
const ENTRY_MAX_FILE: u64 = 512 * 1024 * 1024;

/// What `llm_analyze_file` answers: the digest plus who the file is.
#[derive(Debug, Serialize)]
pub struct LlmDigest {
    pub sha256: String,
    /// What the file is ("ELF 64-bit executable", a detected kind, ...).
    pub file_type: Option<String>,
    pub architecture: Option<String>,
    pub is_packed: Option<bool>,
    #[serde(flatten)]
    pub result: LlmFileAnalysisResult,
    /// Why a part is empty or approximate.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Why no draft rule came with the digest, when one was asked for and
    /// `suggest_yara_rule` refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara_rule_note: Option<String>,
    /// Present when the output budget cut something: what and how to get it back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<Value>,
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The characters of the compact JSON of `digest` as it is sent (null
/// members are omitted there).
fn size_of(digest: &LlmDigest) -> usize {
    serde_json::to_value(digest).map_or(usize::MAX, |mut value| {
        strip_nulls(&mut value);
        value.to_string().len()
    })
}

/// How many entries each trimmable list had before trimming.
struct Counts {
    key_strings: usize,
    imports: usize,
    opcodes: usize,
    hex_patterns: usize,
    had_rule: bool,
}

impl Counts {
    fn of(result: &LlmFileAnalysisResult) -> Self {
        Self {
            key_strings: result.key_strings.len(),
            imports: result.imports.len(),
            opcodes: result.opcodes.len(),
            hex_patterns: result.hex_patterns.len(),
            had_rule: result.yara_rule_suggestion.is_some(),
        }
    }

    /// The `truncated` object for `now`, or `None` when nothing was cut. `how`
    /// names the limit that was hit.
    fn report(&self, now: &LlmFileAnalysisResult, how: &str) -> Option<Value> {
        let mut cut = serde_json::Map::new();
        for (name, before, after) in [
            ("key_strings", self.key_strings, now.key_strings.len()),
            ("imports", self.imports, now.imports.len()),
            ("opcodes", self.opcodes, now.opcodes.len()),
            ("hex_patterns", self.hex_patterns, now.hex_patterns.len()),
        ] {
            if after < before {
                cut.insert(
                    name.into(),
                    json!({"kept": after, "dropped": before - after}),
                );
            }
        }
        if self.had_rule && now.yara_rule_suggestion.is_none() {
            cut.insert("yara_rule_suggestion".into(), "dropped".into());
        }
        if cut.is_empty() {
            return None;
        }
        Some(json!({"cut": cut, "how": how}))
    }
}

/// The limit a digest is fitted to and what it is called: `token_limit`, or
/// `max_output_bytes` when that is the smaller of the two (the one the answer
/// actually ran into).
pub(super) fn limit_of(token_limit: Option<usize>, budget: usize) -> (usize, &'static str) {
    let token = token_limit.unwrap_or(DEFAULT_TOKEN_LIMIT);
    if budget < token {
        (budget, "max_output_bytes")
    } else {
        (token, "token_limit")
    }
}

/// The text of `truncated.how` for a digest cut at `limit` (called `name`).
fn how_text(limit: usize, name: &str) -> String {
    if name == "max_output_bytes" {
        format!(
            "over max_output_bytes {limit}: raise it (at most {}), or lower max_strings, \
             max_imports, max_opcodes, hex_pattern_size; query_analysis has the full lists",
            crate::mcp_server::output::MAX_OUTPUT_BYTES
        )
    } else {
        format!(
            "over token_limit {limit}: raise it or lower max_strings, max_imports, max_opcodes; \
             query_analysis has the full lists"
        )
    }
}

/// The lists of a result before trimming, to put back what the trim took
/// beyond what the limit required.
struct Full {
    key_strings: Vec<String>,
    imports: Vec<String>,
    opcodes: Vec<String>,
    hex_patterns: Vec<String>,
    rule: Option<String>,
}

impl Full {
    fn of(result: &LlmFileAnalysisResult) -> Self {
        Self {
            key_strings: result.key_strings.clone(),
            imports: result.imports.clone(),
            opcodes: result.opcodes.clone(),
            hex_patterns: result.hex_patterns.clone(),
            rule: result.yara_rule_suggestion.clone(),
        }
    }
}

/// Which list an item put back belongs to.
#[derive(Clone, Copy)]
enum Slot {
    Imports,
    KeyStrings,
    Opcodes,
    HexPatterns,
    Rule,
}

/// Entries a result holds, for comparing two fits of the same limit.
fn kept_entries(result: &LlmFileAnalysisResult) -> usize {
    result.key_strings.len()
        + result.imports.len()
        + result.opcodes.len()
        + result.hex_patterns.len()
        + usize::from(result.yara_rule_suggestion.is_some())
}

/// After the trim: fill the limit again from the identity, in this order, with
/// what fits: the first few key strings, the imports, the opcodes, each hex
/// pattern that fits, the rule, then more key strings. The trim drops the small
/// lists first, so one large member (a 1 KB hex pattern) could leave an answer
/// of a few strings; this uses the room that is there. The trimmed result is
/// kept when it holds more entries.
fn regrow(digest: &mut LlmDigest, full: &Full, before: &Counts, limit: usize, how: &str) {
    // Room for the cut report to name larger numbers.
    const SLACK: usize = 64;
    const FIRST_STRINGS: usize = 5;
    let trimmed = Full::of(&digest.result);
    let trimmed_entries = kept_entries(&digest.result);
    digest.result.key_strings.clear();
    digest.result.imports.clear();
    digest.result.opcodes.clear();
    digest.result.hex_patterns.clear();
    digest.result.yara_rule_suggestion = None;
    digest.truncated = before.report(&digest.result, how);
    let mut running = size_of(digest);
    let mut put_back: Vec<Slot> = Vec::new();
    let cost = |text: &String| serde_json::to_string(text).map_or(usize::MAX, |t| t.len() + 1);
    let fits =
        |running: usize, add: usize| running.saturating_add(add).saturating_add(SLACK) <= limit;
    // The next entries of a list, in order, until one does not fit.
    macro_rules! refill {
        ($list:ident, $slot:expr, $upto:expr) => {
            while digest.result.$list.len() < full.$list.len().min($upto) {
                let next = &full.$list[digest.result.$list.len()];
                let add = cost(next);
                if !fits(running, add) {
                    break;
                }
                digest.result.$list.push(next.clone());
                running += add;
                put_back.push($slot);
            }
        };
    }
    refill!(key_strings, Slot::KeyStrings, FIRST_STRINGS);
    refill!(imports, Slot::Imports, usize::MAX);
    refill!(opcodes, Slot::Opcodes, usize::MAX);
    for pattern in &full.hex_patterns {
        let add = cost(pattern);
        if fits(running, add) {
            digest.result.hex_patterns.push(pattern.clone());
            running += add;
            put_back.push(Slot::HexPatterns);
        }
    }
    if let Some(rule) = &full.rule {
        let add = cost(rule) + 32;
        if fits(running, add) {
            digest.result.yara_rule_suggestion = Some(rule.clone());
            running += add;
            put_back.push(Slot::Rule);
        }
    }
    refill!(key_strings, Slot::KeyStrings, usize::MAX);
    // The estimate is close, not exact: take entries back until it fits.
    loop {
        digest.truncated = before.report(&digest.result, how);
        if size_of(digest) <= limit {
            break;
        }
        match put_back.pop() {
            Some(Slot::Imports) => {
                digest.result.imports.pop();
            }
            Some(Slot::KeyStrings) => {
                digest.result.key_strings.pop();
            }
            Some(Slot::Opcodes) => {
                digest.result.opcodes.pop();
            }
            Some(Slot::HexPatterns) => {
                digest.result.hex_patterns.pop();
            }
            Some(Slot::Rule) => digest.result.yara_rule_suggestion = None,
            None => break,
        }
    }
    if kept_entries(&digest.result) < trimmed_entries {
        digest.result.key_strings = trimmed.key_strings;
        digest.result.imports = trimmed.imports;
        digest.result.opcodes = trimmed.opcodes;
        digest.result.hex_patterns = trimmed.hex_patterns;
        digest.result.yara_rule_suggestion = trimmed.rule;
        digest.truncated = before.report(&digest.result, how);
    }
}

/// One step of trimming; `false` when nothing is left to trim.
fn trim_step(result: &mut LlmFileAnalysisResult) -> bool {
    if result.key_strings.len() > 20 {
        result.key_strings.truncate(result.key_strings.len() - 5);
    } else if result.imports.len() > 10 {
        result.imports.truncate(result.imports.len() - 5);
    } else if result.opcodes.len() > 5 {
        result.opcodes.truncate(result.opcodes.len() - 2);
    } else if result.key_strings.len() > 5 {
        result.key_strings.pop();
    } else if !result.imports.is_empty() {
        let keep = result.imports.len().saturating_sub(5);
        result.imports.truncate(keep);
    } else if !result.opcodes.is_empty() {
        result.opcodes.pop();
    } else if !result.hex_patterns.is_empty() {
        result.hex_patterns.pop();
    } else if result.yara_rule_suggestion.is_some() {
        result.yara_rule_suggestion = None;
    } else if !result.key_strings.is_empty() {
        result.key_strings.pop();
    } else {
        return false;
    }
    true
}

/// Trim `digest` until its compact JSON is at most `limit` characters, and say
/// what was cut. `Err` when even the bare identity does not fit.
fn fit(digest: &mut LlmDigest, limit: usize) -> Result<(), String> {
    fit_named(digest, limit, "token_limit")
}

/// [`fit`] for a limit called `name` (`token_limit` or `max_output_bytes`).
fn fit_named(digest: &mut LlmDigest, limit: usize, name: &str) -> Result<(), String> {
    let before = Counts::of(&digest.result);
    let full = Full::of(&digest.result);
    let how = how_text(limit, name);
    loop {
        digest.truncated = before.report(&digest.result, &how);
        let size = size_of(digest);
        if size <= limit {
            if digest.truncated.is_some() {
                regrow(digest, &full, &before, limit, &how);
            }
            return Ok(());
        }
        if !trim_step(&mut digest.result) {
            // The identity alone is over the limit: drop the notes, then give up.
            if !digest.notes.is_empty() || digest.yara_rule_note.is_some() {
                digest.notes.clear();
                digest.yara_rule_note = None;
                continue;
            }
            return Err(format!(
                "{name} {limit} is smaller than the smallest digest ({size} characters: \
                 identity, entropy and sizes). Use a {name} of at least {size}, or call \
                 analyze_file for the overview."
            ));
        }
    }
}

// -- entry-point opcodes ----------------------------------------------------

/// The architecture, file offset and address of the entry point of `buffer`.
fn entry_of(buffer: &[u8]) -> Result<(Arch, Mode, usize, u64), String> {
    // goblin's own parse of a crafted Mach-O or PE can take very long: ask the
    // guards first, and report a refusal as the reason there are no opcodes.
    crate::binary_parser::check_mach_load_commands(buffer)?;
    crate::binary_parser::check_pe_imports(buffer)?;
    match Object::parse(buffer).map_err(|e| format!("not a recognized executable ({e})"))? {
        Object::Elf(elf) => {
            let (arch, mode) = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => (Arch::X86, Mode::Mode64),
                goblin::elf::header::EM_386 => (Arch::X86, Mode::Mode32),
                goblin::elf::header::EM_ARM => (Arch::ARM, Mode::Arm),
                goblin::elf::header::EM_AARCH64 => (Arch::ARM64, Mode::Arm),
                other => return Err(format!("unsupported ELF machine {other}")),
            };
            let entry = elf.header.e_entry;
            let load = elf
                .program_headers
                .iter()
                .find(|ph| {
                    ph.p_type == goblin::elf::program_header::PT_LOAD
                        && ph.p_vaddr <= entry
                        && entry < ph.p_vaddr.saturating_add(ph.p_filesz)
                })
                .ok_or("the entry point is not inside a loaded segment")?;
            // The offset comes from the file; a crafted value must not overflow.
            let offset = (entry - load.p_vaddr)
                .checked_add(load.p_offset)
                .ok_or("the entry point is outside the file")?;
            Ok((
                arch,
                mode,
                usize::try_from(offset).unwrap_or(usize::MAX),
                entry,
            ))
        }
        Object::PE(pe) => {
            let mode = if pe.is_64 { Mode::Mode64 } else { Mode::Mode32 };
            let rva = pe.entry as u64;
            let section = pe
                .sections
                .iter()
                .find(|s| {
                    let start = u64::from(s.virtual_address);
                    let size = u64::from(s.virtual_size.max(s.size_of_raw_data));
                    start <= rva && rva < start.saturating_add(size)
                })
                .ok_or("the entry point is not inside a section")?;
            let offset = (rva - u64::from(section.virtual_address))
                .checked_add(u64::from(section.pointer_to_raw_data))
                .ok_or("the entry point is outside the file")?;
            Ok((
                Arch::X86,
                mode,
                usize::try_from(offset).unwrap_or(usize::MAX),
                pe.image_base.wrapping_add(rva),
            ))
        }
        _ => Err("entry-point opcodes are supported for ELF and PE files".to_string()),
    }
}

/// The byte patterns of the first instructions at the entry point of `path`
/// (each a YARA-ready hex string), at most `max` distinct ones, and the entry
/// address. `Err` says why there are none.
fn entry_opcodes(path: &Path, max: usize) -> Result<(Vec<String>, u64), String> {
    if max == 0 {
        return Ok((Vec::new(), 0));
    }
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > ENTRY_MAX_FILE {
        return Err("the file is too large to look up its entry point".to_string());
    }
    let buffer = std::fs::read(path).map_err(|e| e.to_string())?;
    let (arch, mode, offset, address) = entry_of(&buffer)?;
    let window = buffer
        .get(offset..)
        .map(|rest| &rest[..rest.len().min(ENTRY_WINDOW)])
        .filter(|w| !w.is_empty())
        .ok_or("the entry point is outside the file")?;
    let cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)
        .map_err(|e| format!("disassembler unavailable: {e:?}"))?;
    let decoded = cs
        .disasm_all(window, address)
        .map_err(|e| format!("could not decode the entry point: {e:?}"))?;
    let mut out: Vec<String> = Vec::new();
    for insn in decoded.iter() {
        let pattern = hex_of(insn.bytes());
        if !out.contains(&pattern) {
            out.push(pattern);
        }
        if out.len() >= max {
            break;
        }
        // The window runs past a short entry stub into whatever follows (other
        // code, data); the instructions after an unconditional transfer are
        // not the entry point's.
        if matches!(
            insn.mnemonic().unwrap_or_default(),
            "ret"
                | "retn"
                | "retf"
                | "hlt"
                | "ud2"
                | "int3"
                | "jmp"
                | "b"
                | "br"
                | "bx"
                | "brk"
                | "udf"
        ) {
            break;
        }
    }
    Ok((out, address))
}

// -- the digest ---------------------------------------------------------------

impl FileScannerMcp {
    /// The digest of one file, not yet fitted to a budget.
    pub(super) async fn llm_digest(
        &self,
        request: &LlmFileAnalysisRequest,
    ) -> Result<LlmDigest, String> {
        let pattern_size = request.hex_pattern_size.unwrap_or(32);
        if pattern_size == 0 || pattern_size > MAX_HEX_PATTERN_SIZE {
            return Err(format!(
                "hex_pattern_size {pattern_size} is not allowed: use 1 to {MAX_HEX_PATTERN_SIZE} \
                 bytes (default 32)."
            ));
        }
        let min_string_len = request.min_string_length.unwrap_or(6);
        if min_string_len == 0 {
            return Err("min_string_length must be at least 1 (default 6).".to_string());
        }
        let path = PathBuf::from(&request.file_path);
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }
        let file_size = std::fs::metadata(&path)
            .map_err(|e| format!("{e:#}"))?
            .len();
        let hashes = calculate_all_hashes(&path)
            .await
            .map_err(|e| format!("{e:#}"))?;

        let strings = extract_strings(&path, min_string_len).map_err(|e| format!("{e:#}"))?;
        let key_strings = self.extract_key_strings(&strings, request.max_strings.unwrap_or(50));
        let hex_patterns = self.extract_hex_patterns(&path, pattern_size)?;

        let mut notes = Vec::new();
        let (imports, format, architecture) = match parse_binary(&path) {
            // A file that parses only as "Raw" has no executable structure.
            Ok(info) if matches!(info.format.as_str(), "Raw" | "Unknown") => {
                notes.push("not an executable (no imports, architecture or entry point)".into());
                (Vec::new(), None, None)
            }
            Ok(info) => (
                info.imports
                    .into_iter()
                    .take(request.max_imports.unwrap_or(30))
                    .collect(),
                Some(info.format),
                Some(info.architecture),
            ),
            Err(error) => {
                notes.push(format!("imports: not an executable format ({error:#})"));
                (Vec::new(), None, None)
            }
        };
        let max_opcodes = request.max_opcodes.unwrap_or(10);
        let opcodes = match entry_opcodes(&path, max_opcodes) {
            Ok((opcodes, address)) => {
                if !opcodes.is_empty() {
                    notes.push(format!(
                        "opcodes: the first instructions at the entry point 0x{address:x}"
                    ));
                }
                opcodes
            }
            Err(reason) => {
                if max_opcodes > 0 {
                    notes.push(format!("opcodes: none, {reason}"));
                }
                Vec::new()
            }
        };
        let entropy_analysis = analyze_entropy(&path).ok();
        let kind = detect_file_kind(&path).ok().filter(|k| k.kind != "unknown");
        let file_type = kind
            .map(|k| k.label)
            .or_else(|| format.clone().map(|f| format!("{f} executable")));

        let mut result = LlmFileAnalysisResult {
            md5: hashes.md5.clone(),
            file_size,
            key_strings,
            hex_patterns,
            imports,
            opcodes,
            entropy: entropy_analysis.as_ref().map(|e| e.overall_entropy),
            yara_rule_suggestion: None,
        };
        let mut yara_rule_note = None;
        if request.suggest_yara_rule.unwrap_or(true) {
            match crate::mcp_server::tools_yara::suggest_yara_rule(&result, &request.file_path) {
                Ok(rule) => result.yara_rule_suggestion = Some(rule),
                Err(reason) => yara_rule_note = Some(format!("no draft rule: {reason}")),
            }
        }
        Ok(LlmDigest {
            sha256: hashes.sha256,
            file_type,
            architecture,
            is_packed: entropy_analysis.map(|e| e.packed_indicators.likely_packed),
            result,
            notes,
            yara_rule_note,
            truncated: None,
        })
    }

    /// The digest of one file, fitted to `token_limit` characters of compact
    /// JSON (and to `budget`, the tool's output cap).
    pub(super) async fn llm_digest_within(
        &self,
        request: &LlmFileAnalysisRequest,
        budget: usize,
    ) -> Result<LlmDigest, String> {
        let mut digest = self.llm_digest(request).await?;
        let (limit, name) = limit_of(request.token_limit, budget);
        fit_named(&mut digest, limit, name)?;
        Ok(digest)
    }

    /// The digest as the library API returns it (no identity members).
    pub async fn llm_analyze_file(
        &self,
        request: LlmFileAnalysisRequest,
    ) -> Result<Json<LlmFileAnalysisResult>, String> {
        let digest = self
            .llm_digest_within(&request, crate::mcp_server::output::MAX_OUTPUT_BYTES)
            .await?;
        Ok(Json(digest.result))
    }

    /// Key strings for a rule: the categorized strings first (URLs, IPs, then
    /// the rest by how telling the category is), then plain ASCII strings, each
    /// value once.
    pub(super) fn extract_key_strings(
        &self,
        strings: &ExtractedStrings,
        max_count: usize,
    ) -> Vec<String> {
        let mut key_strings: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // A categorized string that is too long to be a key string as a whole
        // (a Go blob holding a URL) is represented by the text that made it
        // categorized.
        let mut interesting: Vec<(usize, usize, &str)> = strings
            .interesting_strings
            .iter()
            .filter_map(|s| {
                let text = key_text(&s.value, 100)?;
                Some((category_rank(&s.category), s.offset, text))
            })
            .collect();
        interesting.sort_by_key(|(rank, offset, _)| (*rank, *offset));
        for (_, _, text) in interesting {
            if key_strings.len() >= max_count {
                return key_strings;
            }
            if seen.insert(text) {
                key_strings.push(text.to_string());
            }
        }
        for s in &strings.ascii_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if (8..=100).contains(&s.len()) && seen.insert(s.as_str()) {
                key_strings.push(s.clone());
            }
        }
        key_strings
    }

    /// The first and last `pattern_size` bytes of the file as hex.
    pub(super) fn extract_hex_patterns(
        &self,
        path: &Path,
        pattern_size: usize,
    ) -> Result<Vec<String>, String> {
        if pattern_size == 0 {
            return Err("hex_pattern_size must be at least 1.".to_string());
        }
        let mut patterns = Vec::new();
        let dump = |offset: u64| {
            generate_hex_dump(
                path,
                HexDumpOptions {
                    offset,
                    length: Some(pattern_size),
                    bytes_per_line: pattern_size,
                    max_lines: Some(1),
                },
            )
        };
        if let Ok(header) = dump(0) {
            if let Some(line) = header.lines.first() {
                patterns.push(hex_of(&line.raw_bytes));
            }
        }
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > pattern_size as u64 {
                if let Ok(footer) = dump(metadata.len() - pattern_size as u64) {
                    if let Some(line) = footer.lines.first() {
                        patterns.push(hex_of(&line.raw_bytes));
                    }
                }
            }
        }
        Ok(patterns)
    }

    /// The first instructions at the entry point, as hex patterns; none (not an
    /// error) when the file has no entry point to read.
    pub(super) fn extract_key_opcodes(
        &self,
        path: &Path,
        max_count: usize,
    ) -> Result<Vec<String>, String> {
        Ok(entry_opcodes(path, max_count)
            .map(|(opcodes, _)| opcodes)
            .unwrap_or_default())
    }

    /// Trim a result until its compact JSON fits `token_limit` characters.
    pub(super) fn trim_results_to_token_limit(
        &self,
        result: LlmFileAnalysisResult,
        token_limit: usize,
    ) -> LlmFileAnalysisResult {
        let mut digest = LlmDigest {
            sha256: String::new(),
            file_type: None,
            architecture: None,
            is_packed: None,
            result,
            notes: Vec::new(),
            yara_rule_note: None,
            truncated: None,
        };
        // Past the point where nothing can be trimmed the result is returned as it is.
        let _ = fit(&mut digest, token_limit);
        digest.result
    }
}

/// The part of a categorized string worth putting in a rule: the whole string
/// when it is 8 to `max` bytes, otherwise the text that made it categorized
/// (cut to `max` bytes), when that is at least 8 bytes.
pub(super) fn key_text(value: &str, max: usize) -> Option<&str> {
    const MIN: usize = 8;
    if (MIN..=max).contains(&value.len()) {
        return Some(value);
    }
    if value.len() < MIN {
        return None;
    }
    let (from, to) = crate::strings::category_span(value)?;
    let from = value.ceil_char_boundary(from);
    let to = value.floor_char_boundary(to.min(from + max).min(value.len()));
    let text = value.get(from..to)?;
    (text.len() >= MIN).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason a draft rule was left out is in the answer the caller reads.
    #[test]
    fn the_reason_a_rule_was_left_out_reaches_the_caller() {
        let digest = LlmDigest {
            sha256: "00".into(),
            file_type: None,
            architecture: None,
            is_packed: None,
            result: LlmFileAnalysisResult {
                md5: String::new(),
                file_size: 0,
                key_strings: Vec::new(),
                hex_patterns: Vec::new(),
                imports: Vec::new(),
                opcodes: Vec::new(),
                entropy: None,
                yara_rule_suggestion: None,
            },
            notes: Vec::new(),
            yara_rule_note: Some("no draft rule: did not compile".into()),
            truncated: None,
        };
        let text = serde_json::to_string(&digest).unwrap();
        assert!(
            text.contains("\"yara_rule_note\":\"no draft rule"),
            "{text}"
        );
    }

    /// A minimal ELF64 with one PT_LOAD segment whose file offset is `p_offset`.
    fn elf_with_segment_offset(p_offset: u64) -> Vec<u8> {
        let mut b = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        b.extend_from_slice(&[0; 8]);
        b.extend_from_slice(&2u16.to_le_bytes()); // e_type
        b.extend_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0x401000u64.to_le_bytes()); // e_entry
        b.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        b.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&64u16.to_le_bytes());
        b.extend_from_slice(&56u16.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        b.extend_from_slice(&64u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b.extend_from_slice(&5u32.to_le_bytes());
        b.extend_from_slice(&p_offset.to_le_bytes());
        b.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        b.extend_from_slice(&0x400000u64.to_le_bytes());
        b.extend_from_slice(&0x2000u64.to_le_bytes()); // p_filesz
        b.extend_from_slice(&0x2000u64.to_le_bytes());
        b.extend_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    #[test]
    fn a_crafted_segment_offset_does_not_overflow_the_entry_lookup() {
        let sane = entry_of(&elf_with_segment_offset(0)).unwrap();
        assert_eq!(sane.2, 0x1000);
        let crafted = entry_of(&elf_with_segment_offset(u64::MAX));
        assert!(
            crafted
                .as_ref()
                .is_err_and(|e| e.contains("outside the file")),
            "{crafted:?}"
        );
    }

    fn digest_with(result: LlmFileAnalysisResult) -> LlmDigest {
        LlmDigest {
            sha256: "00".repeat(32),
            file_type: Some("ELF 64-bit executable".into()),
            architecture: Some("x86_64".into()),
            is_packed: Some(false),
            result,
            notes: Vec::new(),
            yara_rule_note: None,
            truncated: None,
        }
    }

    /// The limit that is named is the one that was hit, and the answer uses the
    /// bytes it has: two large hex patterns do not empty it.
    #[test]
    fn a_cut_names_its_limit_and_keeps_what_fits() {
        assert_eq!(
            limit_of(Some(1_000_000), 4_000),
            (4_000, "max_output_bytes")
        );
        assert_eq!(limit_of(Some(1_000), 4_000), (1_000, "token_limit"));
        assert_eq!(
            limit_of(None, 400_000),
            (DEFAULT_TOKEN_LIMIT, "token_limit")
        );
        let result = LlmFileAnalysisResult {
            md5: "0".repeat(32),
            file_size: 1,
            key_strings: (0..3_000)
                .map(|i| format!("a key string number {i}"))
                .collect(),
            hex_patterns: vec!["AA ".repeat(1024), "BB ".repeat(1024)],
            imports: (0..38).map(|i| format!("import_{i}")).collect(),
            opcodes: vec!["F3 0F 1E FA".into()],
            entropy: Some(6.5),
            yara_rule_suggestion: Some("rule x { condition: true }".into()),
        };
        let mut digest = digest_with(result);
        fit_named(&mut digest, 4_000, "max_output_bytes").unwrap();
        let size = size_of(&digest);
        assert!(size <= 4_000, "{size}");
        assert!(size > 3_500, "the bytes available are used: {size}");
        assert_eq!(digest.result.imports.len(), 38);
        assert_eq!(digest.result.opcodes.len(), 1);
        assert!(digest.result.key_strings.len() > 20);
        assert!(digest.result.hex_patterns.is_empty(), "too big to fit");
        let how = digest.truncated.as_ref().unwrap()["how"].as_str().unwrap();
        assert!(how.contains("max_output_bytes 4000"), "{how}");
        assert!(!how.contains("token_limit"), "{how}");

        // Nothing is dropped when everything fits; the same call under
        // `token_limit` names that limit.
        let mut small = digest_with(LlmFileAnalysisResult {
            md5: String::new(),
            file_size: 1,
            key_strings: (0..400).map(|i| format!("string {i}")).collect(),
            hex_patterns: Vec::new(),
            imports: Vec::new(),
            opcodes: Vec::new(),
            entropy: None,
            yara_rule_suggestion: None,
        });
        fit_named(&mut small, 2_000, "token_limit").unwrap();
        assert!(size_of(&small) <= 2_000);
        let how = small.truncated.as_ref().unwrap()["how"].as_str().unwrap();
        assert!(how.contains("token_limit 2000"), "{how}");
    }

    /// A Mach-O whose load commands would make goblin's parse slow is refused
    /// by the guard before goblin sees it.
    #[test]
    fn the_entry_point_lookup_asks_the_parse_guards_first() {
        let mut macho: Vec<u8> = Vec::new();
        for v in [0xfeed_facf_u32, 0x0100_0007, 3, 2, 1, 24, 0, 0] {
            macho.extend_from_slice(&v.to_le_bytes());
        }
        // LC_LOAD_DYLIB whose name offset points outside its command.
        for v in [0xc_u32, 24, 0x1000, 0, 0, 0] {
            macho.extend_from_slice(&v.to_le_bytes());
        }
        let refused = entry_of(&macho).unwrap_err();
        assert!(refused.contains("outside its command"), "{refused}");
    }
}
