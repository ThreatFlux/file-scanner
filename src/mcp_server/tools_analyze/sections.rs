//! The analysis sections behind `analyze_file` and `query_analysis`.
//!
//! A *section* is one analysis of one file (`strings`, `symbols`,
//! `disassembly`, ...). Every section is computed in full, stored in the
//! [`SectionCache`] under the file's SHA-256 and a key made of the section name
//! and the options that change its content, and then handed out as a SUMMARY
//! (counts, headline numbers, a few top items) or sliced, filtered and paged by
//! `query_analysis`. Nothing here returns a whole heavy section to a caller.

use std::{collections::BTreeSet, path::Path, sync::Arc};

use serde_json::{json, Map, Value};

use crate::{
    behavioral_analysis::analyze_behavior,
    binary_parser::{parse_binary, BinaryInfo},
    code_metrics::analyze_code_quality,
    control_flow::{analyze_control_flow, ControlFlowAnalysis},
    dependency_analysis::analyze_dependencies,
    disassembly::{disassemble_binary, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols, SymbolTable},
    hash::{calculate_all_hashes, Hashes},
    hexdump::{generate_hex_dump, HexDumpOptions},
    mcp_server::{
        state::{mark_section, SectionCache},
        tools_formats::{detect_file_kind, format_overview},
    },
    metadata::FileMetadata,
    signature::verify_signature,
    strings::{scan_strings, StringScan},
    threat_detection::{analyze_threats, analyze_threats_enhanced},
    vulnerability_detection::analyze_vulnerabilities,
};

use super::YaraIndicators;

/// Every analysis `analyze_file` can run, in result order. `all: true` runs
/// all of them.
pub(super) const ANALYSES: [&str; 17] = [
    "metadata",
    "hashes",
    "strings",
    "hex_dump",
    "binary_info",
    "signatures",
    "symbols",
    "control_flow",
    "vulnerabilities",
    "code_quality",
    "dependencies",
    "entropy",
    "disassembly",
    "threats",
    "enhanced_threats",
    "behavioral",
    "yara_indicators",
];

/// Minimum string length when the caller names none.
pub(super) const DEFAULT_MIN_STRING: usize = 4;
/// Bytes of the `hex_dump` section when the caller names no size (also under `all`).
pub(super) const DEFAULT_HEX_DUMP: usize = 256;
/// Most hex-dump lines a summary shows inline.
const HEX_SUMMARY_LINES: usize = 16;
/// Largest hex dump (in lines) returned whole in a summary.
const HEX_WHOLE_LINES: usize = 64;
/// Items shown from each list in a summary.
const SAMPLE: usize = 3;
/// Longest string a summary or row shows (characters).
const CLIP: usize = 160;
/// Strings handed to the string tracker per call.
const TRACKER_STRINGS: usize = 2000;

// ---------------------------------------------------------------------------
// What to compute
// ---------------------------------------------------------------------------

/// The options that change what a section contains.
#[derive(Debug, Clone, Copy)]
pub(super) struct Options {
    pub min: usize,
    pub hex_size: usize,
    pub hex_offset: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min: DEFAULT_MIN_STRING,
            hex_size: DEFAULT_HEX_DUMP,
            hex_offset: 0,
        }
    }
}

/// One section to produce and the key it is cached under.
#[derive(Debug, Clone)]
pub(super) struct Planned {
    pub name: &'static str,
    pub key: String,
}

/// The cache key of `name` under `options`. The metadata key holds the path
/// and mtime because the metadata contains both.
pub(super) fn plan(name: &'static str, options: &Options, path: &str, mtime_ns: u128) -> Planned {
    let key = match name {
        "metadata" => format!("metadata:{path}:{mtime_ns}"),
        "strings" => format!("strings:min={}", options.min),
        "hex_dump" => format!(
            "hex_dump:size={}:offset={}",
            options.hex_size, options.hex_offset
        ),
        "dependencies" | "behavioral" | "yara_indicators" => {
            format!("{name}:min={}", options.min)
        }
        "threats" => "threats:basic".to_string(),
        "enhanced_threats" => "threats:enhanced".to_string(),
        other => other.to_string(),
    };
    Planned { name, key }
}

/// Why a section produced nothing.
#[derive(Debug, Clone)]
pub(super) enum Failure {
    /// The analysis failed.
    Error(String),
    /// The analysis does not apply to this kind of file.
    NotApplicable(String),
}

impl Failure {
    pub(super) fn message(&self) -> &str {
        match self {
            Self::Error(message) | Self::NotApplicable(message) => message,
        }
    }
}

/// An analyzer's error message, as a [`Failure`]: "only ELF is supported" is a
/// property of the file, anything else a failure.
fn classify(message: String) -> Failure {
    let lower = message.to_lowercase();
    if lower.contains("supported") || lower.contains("not applicable") {
        Failure::NotApplicable(message)
    } else {
        Failure::Error(message)
    }
}

fn error(e: impl std::fmt::Display) -> Failure {
    Failure::Error(format!("{e:#}"))
}

// ---------------------------------------------------------------------------
// Computing a section
// ---------------------------------------------------------------------------

/// What several sections of one file share while they are computed, so the
/// symbol table or the string scan is built once per call.
pub(super) struct Ctx<'a> {
    path: &'a Path,
    runtime: &'a tokio::runtime::Handle,
    options: Options,
    scan: Option<Arc<StringScan>>,
    symbols: Option<Result<Arc<SymbolTable>, String>>,
    control_flow: Option<Result<Arc<ControlFlowAnalysis>, String>>,
    disassembly: Option<Result<Arc<DisassemblyResult>, String>>,
    entropy: Option<Result<Arc<EntropyAnalysis>, String>>,
    binary_info: Option<Result<Arc<BinaryInfo>, String>>,
    hashes: Option<Arc<Hashes>>,
}

impl<'a> Ctx<'a> {
    pub(super) fn new(
        path: &'a Path,
        runtime: &'a tokio::runtime::Handle,
        options: Options,
    ) -> Self {
        Self {
            path,
            runtime,
            options,
            scan: None,
            symbols: None,
            control_flow: None,
            disassembly: None,
            entropy: None,
            binary_info: None,
            hashes: None,
        }
    }

    fn scan(&mut self) -> Result<Arc<StringScan>, Failure> {
        if let Some(scan) = &self.scan {
            return Ok(Arc::clone(scan));
        }
        mark_section("strings");
        let scan = Arc::new(scan_strings(self.path, self.options.min).map_err(error)?);
        self.scan = Some(Arc::clone(&scan));
        Ok(scan)
    }

    fn symbols(&mut self) -> Result<Arc<SymbolTable>, String> {
        let path = self.path;
        self.symbols
            .get_or_insert_with(|| {
                mark_section("symbols");
                analyze_symbols(path)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn control_flow(&mut self) -> Result<Arc<ControlFlowAnalysis>, String> {
        let symbols = self.symbols()?;
        let path = self.path;
        self.control_flow
            .get_or_insert_with(|| {
                mark_section("control_flow");
                analyze_control_flow(path, &symbols)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn disassembly(&mut self) -> Result<Arc<DisassemblyResult>, String> {
        let symbols = self.symbols()?;
        let path = self.path;
        self.disassembly
            .get_or_insert_with(|| {
                mark_section("disassembly");
                disassemble_binary(path, &symbols)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn entropy(&mut self) -> Result<Arc<EntropyAnalysis>, String> {
        let path = self.path;
        self.entropy
            .get_or_insert_with(|| {
                mark_section("entropy");
                analyze_entropy(path)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn binary_info(&mut self) -> Result<Arc<BinaryInfo>, String> {
        let path = self.path;
        self.binary_info
            .get_or_insert_with(|| {
                mark_section("binary_info");
                parse_binary(path)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn hashes(&mut self) -> Result<Arc<Hashes>, Failure> {
        if let Some(hashes) = &self.hashes {
            return Ok(Arc::clone(hashes));
        }
        mark_section("hashes");
        let hashes = Arc::new(
            self.runtime
                .block_on(calculate_all_hashes(self.path))
                .map_err(error)?,
        );
        self.hashes = Some(Arc::clone(&hashes));
        Ok(hashes)
    }

    /// Compute section `name` in full.
    pub(super) fn compute(&mut self, name: &str) -> Result<Value, Failure> {
        mark_section(match name {
            "metadata" => "metadata",
            "hashes" => "hashes",
            "strings" => "strings",
            "hex_dump" => "hex_dump",
            "binary_info" => "binary_info",
            "signatures" => "signatures",
            "symbols" => "symbols",
            "control_flow" => "control_flow",
            "vulnerabilities" => "vulnerabilities",
            "code_quality" => "code_quality",
            "dependencies" => "dependencies",
            "entropy" => "entropy",
            "disassembly" => "disassembly",
            "threats" => "threats",
            "enhanced_threats" => "enhanced_threats",
            "behavioral" => "behavioral",
            _ => "yara_indicators",
        });
        let path = self.path;
        match name {
            "metadata" => {
                let mut metadata = FileMetadata::new(path).map_err(error)?;
                metadata.extract_basic_info().map_err(error)?;
                self.runtime
                    .block_on(metadata.calculate_hashes())
                    .map_err(error)?;
                to_value(&metadata)
            }
            "hashes" => to_value(&*self.hashes()?),
            "strings" => to_value(&*self.scan()?),
            "hex_dump" => self.hex_dump(),
            "binary_info" => {
                let info = self.binary_info().map_err(classify_binary)?;
                to_value(&*info)
            }
            "signatures" => match verify_signature(path) {
                Ok(info) => {
                    let mut value = to_value(&info)?;
                    value["status"] = "success".into();
                    Ok(value)
                }
                Err(e) => Err(classify(format!("{e:#}"))),
            },
            "symbols" => to_value(&*self.symbols().map_err(classify)?),
            "control_flow" => to_value(&*self.control_flow().map_err(classify)?),
            "vulnerabilities" => {
                let symbols = self.symbols().map_err(classify)?;
                let flow = self.control_flow().map_err(classify)?;
                to_value(&analyze_vulnerabilities(path, &symbols, &flow).map_err(error)?)
            }
            "code_quality" => {
                let symbols = self.symbols().map_err(classify)?;
                let flow = self.control_flow().map_err(classify)?;
                to_value(&analyze_code_quality(path, &symbols, &flow).map_err(error)?)
            }
            "dependencies" => {
                let symbols = self.symbols().map_err(classify)?;
                let strings = self.scan()?.to_extracted();
                to_value(&analyze_dependencies(path, &symbols, Some(&strings)).map_err(error)?)
            }
            "entropy" => to_value(&*self.entropy().map_err(classify)?),
            "disassembly" => to_value(&*self.disassembly().map_err(classify)?),
            "threats" => to_value(&analyze_threats(path).map_err(error)?),
            "enhanced_threats" => {
                let analysis = self
                    .runtime
                    .block_on(analyze_threats_enhanced(path))
                    .map_err(error)?;
                to_value(&analysis)
            }
            "behavioral" => {
                // Symbols and disassembly sharpen the result but a text file has none.
                let symbols = self.symbols().ok();
                let disassembly = self.disassembly().ok();
                let strings = self.scan()?.to_extracted();
                let analysis = analyze_behavior(
                    path,
                    Some(&strings),
                    symbols.as_deref(),
                    disassembly.as_deref(),
                )
                .map_err(error)?;
                to_value(&analysis)
            }
            _ => self.yara_indicators(),
        }
    }

    fn hex_dump(&mut self) -> Result<Value, Failure> {
        let dump = generate_hex_dump(
            self.path,
            HexDumpOptions {
                offset: self.options.hex_offset,
                length: Some(self.options.hex_size),
                bytes_per_line: 16,
                max_lines: None,
            },
        )
        .map_err(error)?;
        let lines: Vec<String> = dump
            .lines
            .iter()
            .map(|l| format!("{:08x}  {}  |{}|", l.offset, l.hex_bytes, l.ascii_repr))
            .collect();
        Ok(json!({
            "offset": dump.offset,
            "length": dump.length,
            "total_bytes": dump.total_bytes,
            "bytes_per_line": dump.bytes_per_line,
            "lines": lines,
        }))
    }

    fn yara_indicators(&mut self) -> Result<Value, Failure> {
        let hashes = self.hashes()?;
        let entropy = self.entropy().map_err(Failure::Error)?;
        let scan = self.scan()?;
        let file_size = std::fs::metadata(self.path).map_err(error)?.len();
        let magic = {
            let dump = generate_hex_dump(
                self.path,
                HexDumpOptions {
                    offset: 0,
                    length: Some(8),
                    bytes_per_line: 8,
                    max_lines: Some(1),
                },
            )
            .map_err(error)?;
            dump.lines
                .first()
                .map(|line| {
                    line.raw_bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
        };
        // A sorted set, so the same file always gives the same 20 strings.
        let unique_strings: Vec<String> = scan
            .interesting()
            .filter(|s| (8..=50).contains(&s.value.len()))
            .map(|s| s.value.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(20)
            .collect();
        let (imports, sections) = match self.binary_info() {
            Ok(info) => (
                info.imports.clone(),
                info.sections.iter().map(|s| s.name.clone()).collect(),
            ),
            Err(_) => (Vec::new(), Vec::new()),
        };
        to_value(&YaraIndicators {
            sha256: hashes.sha256.clone(),
            md5: hashes.md5.clone(),
            file_size,
            magic_bytes: magic,
            entropy: entropy.overall_entropy,
            unique_strings,
            imports,
            sections,
            is_packed: entropy.packed_indicators.likely_packed || entropy.overall_entropy > 7.0,
        })
    }
}

fn classify_binary(message: String) -> Failure {
    Failure::NotApplicable(format!("not a recognized executable format ({message})"))
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, Failure> {
    serde_json::to_value(value)
        .map_err(|e| Failure::Error(format!("Could not serialize the result: {e}")))
}

// ---------------------------------------------------------------------------
// The cache around the computation
// ---------------------------------------------------------------------------

/// A section that is ready, or why it is not.
pub(super) type SectionResult = Result<Arc<Value>, Failure>;

/// Looks sections up in the cache and computes and stores the missing ones.
pub(super) struct Engine<'a> {
    cache: &'a SectionCache,
    sha: &'a str,
    ctx: Ctx<'a>,
    /// Sections answered from the cache.
    pub cached: usize,
    /// Sections computed (and stored).
    pub computed: usize,
    /// Sections too big for the cache, with their size in bytes.
    pub not_kept: Vec<(&'static str, usize)>,
    /// Section keys of this file the cache dropped to make room.
    pub evicted: Vec<String>,
}

impl<'a> Engine<'a> {
    pub(super) fn new(cache: &'a SectionCache, sha: &'a str, ctx: Ctx<'a>) -> Self {
        Self {
            cache,
            sha,
            ctx,
            cached: 0,
            computed: 0,
            not_kept: Vec::new(),
            evicted: Vec::new(),
        }
    }

    /// The section: from the cache when this unchanged file has it, otherwise
    /// computed, stored and returned. A failure is not stored.
    pub(super) fn load(&mut self, planned: &Planned) -> SectionResult {
        if let Some(hit) = self.cache.get(self.sha, &planned.key) {
            self.cached += 1;
            return Ok(hit);
        }
        // An analyzer that panics on a malformed sample fails its own section,
        // not the whole call.
        let ctx = &mut self.ctx;
        let name = planned.name;
        let value =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.compute(name))) {
                Ok(result) => result?,
                Err(panic) => {
                    let detail = panic
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| panic.downcast_ref::<&str>().copied())
                        .unwrap_or("unknown panic");
                    return Err(Failure::Error(format!(
                        "the {name} analyzer crashed on this file ({detail})"
                    )));
                }
            };
        self.computed += 1;
        let outcome = self.cache.put(self.sha, &planned.key, &value);
        if !outcome.kept {
            self.not_kept.push((planned.name, outcome.bytes));
        }
        self.evicted.extend(outcome.evicted_same_file);
        Ok(Arc::new(value))
    }

    /// `"hit"` when nothing was computed, `"miss"` when nothing was cached,
    /// `"partial"` otherwise.
    pub(super) fn cache_state(&self) -> &'static str {
        if self.computed == 0 {
            "hit"
        } else if self.cached == 0 {
            "miss"
        } else {
            "partial"
        }
    }

    pub(super) fn cache_note(&self) -> Option<String> {
        let mut notes = Vec::new();
        if !self.not_kept.is_empty() {
            let list = self
                .not_kept
                .iter()
                .map(|(name, bytes)| format!("{name} ({:.0} MiB)", *bytes as f64 / 1_048_576.0))
                .collect::<Vec<_>>()
                .join(", ");
            notes.push(format!(
                "Not kept in the section cache because it is over the cache limit: {list}. \
                 Asking for it again recomputes it; raise FILE_SCANNER_SECTION_CACHE_MB to keep it."
            ));
        }
        let mut dropped: Vec<&str> = Vec::new();
        for key in &self.evicted {
            let name = key.split(':').next().unwrap_or(key);
            if !dropped.contains(&name) {
                dropped.push(name);
            }
        }
        if !dropped.is_empty() {
            notes.push(format!(
                "Dropped from the section cache to make room for this file's other sections: {}. \
                 Asking for one of them again recomputes it; raise FILE_SCANNER_SECTION_CACHE_MB \
                 to keep them all.",
                dropped.join(", ")
            ));
        }
        (!notes.is_empty()).then(|| notes.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Lists inside sections (what `query_analysis` pages)
// ---------------------------------------------------------------------------

/// A list inside a section: where it is and what it is called.
#[derive(Debug, Clone, Copy)]
pub(super) struct ListSpec {
    pub name: &'static str,
    /// JSON pointer into the section; `@behaviors` merges every behavior group.
    pub pointer: &'static str,
}

const fn list(name: &'static str, pointer: &'static str) -> ListSpec {
    ListSpec { name, pointer }
}

/// The behavior groups of the `behavioral` section.
pub(super) const BEHAVIOR_GROUPS: [&str; 7] = [
    "anti_analysis",
    "persistence",
    "network_behavior",
    "file_operations",
    "registry_operations",
    "process_operations",
    "suspicious_behaviors",
];

/// A `&'static [ListSpec]` from `name => pointer` pairs.
macro_rules! specs {
    ($($name:literal => $pointer:literal),* $(,)?) => {
        const { &[$(list($name, $pointer)),*] }
    };
}

/// The pageable lists of a section, the default one first. Empty when the
/// section is small enough that `analyze_file` returns it whole.
pub(super) fn lists(section: &str) -> &'static [ListSpec] {
    match section {
        "strings" => specs!("strings" => "/strings"),
        "binary_info" => specs!(
            "sections" => "/sections", "imports" => "/imports", "exports" => "/exports"
        ),
        "symbols" => specs!(
            "functions" => "/functions",
            "imports" => "/imports",
            "exports" => "/exports",
            "global_variables" => "/global_variables",
            "cross_references" => "/cross_references",
        ),
        "control_flow" => specs!("functions" => "/cfgs"),
        "vulnerabilities" => specs!("vulnerabilities" => "/vulnerabilities"),
        "code_quality" => specs!(
            "functions" => "/function_metrics",
            "quality_issues" => "/quality_report/quality_issues",
        ),
        "dependencies" => specs!(
            "dependencies" => "/dependencies",
            "compliance_issues" => "/license_summary/compliance_issues",
        ),
        "entropy" => specs!(
            "sections" => "/sections",
            "high_entropy_regions" => "/encryption_indicators/high_entropy_regions",
        ),
        "disassembly" => specs!(
            "functions" => "/functions",
            "instructions" => "/instructions",
            "suspicious_patterns" => "/analysis/suspicious_patterns",
        ),
        "threats" | "enhanced_threats" => {
            specs!("matches" => "/matches", "indicators" => "/indicators")
        }
        "behavioral" => specs!(
            "findings" => "@behaviors",
            "anti_analysis" => "/anti_analysis",
            "persistence" => "/persistence",
            "network_behavior" => "/network_behavior",
            "file_operations" => "/file_operations",
            "registry_operations" => "/registry_operations",
            "process_operations" => "/process_operations",
            "suspicious_behaviors" => "/suspicious_behaviors",
        ),
        "yara_indicators" => specs!(
            "unique_strings" => "/unique_strings",
            "imports" => "/imports",
            "sections" => "/sections",
        ),
        _ => &[],
    }
}

/// Number of items in a list of `section`, when the list is a plain array.
fn list_total(section: &str, spec: &ListSpec, value: &Value) -> Option<usize> {
    if spec.pointer == "@behaviors" {
        let mut total = 0;
        for group in BEHAVIOR_GROUPS {
            total += value
                .get(group)
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
        }
        return Some(total);
    }
    let _ = section;
    value.pointer(spec.pointer)?.as_array().map(Vec::len)
}

// ---------------------------------------------------------------------------
// Summaries
// ---------------------------------------------------------------------------

/// `s` cut to [`CLIP`] characters.
pub(super) fn clip(s: &str) -> String {
    if s.len() <= CLIP {
        return s.to_string();
    }
    let mut out: String = s.chars().take(CLIP).collect();
    if out.len() < s.len() {
        out.push('…');
    }
    out
}

/// `s` cut to [`CLIP`] characters around `span` (a byte range worth seeing),
/// so the indicator of a long string stays visible.
fn clip_around_span(s: &str, span: Option<(usize, usize)>) -> String {
    let Some((from, to)) = span.filter(|(_, to)| *to > CLIP) else {
        return clip(s);
    };
    let to = s.floor_char_boundary(to.min(s.len()));
    // Start at the match, a little before it; the match itself may be long.
    let start = s.ceil_char_boundary(from.saturating_sub(20).min(to));
    let tail: String = s[start..].chars().take(CLIP).collect();
    let more = start + tail.len() < s.len();
    format!(
        "{}{tail}{}",
        if start > 0 { "…" } else { "" },
        if more { "…" } else { "" }
    )
}

/// A one-level view of `value`: its scalar fields (strings clipped), the
/// length of each array as `<name>_count`, and the scalar fields of a small
/// nested object.
pub(super) fn brief(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                match item {
                    Value::Null => {}
                    Value::Array(items) => {
                        out.insert(format!("{key}_count"), items.len().into());
                    }
                    Value::Object(inner) => {
                        if inner.len() <= 8 && inner.values().all(is_scalar) {
                            out.insert(key.clone(), brief(item));
                        }
                    }
                    Value::String(s) => {
                        out.insert(key.clone(), clip(s).into());
                    }
                    other => {
                        out.insert(key.clone(), other.clone());
                    }
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => json!({"count": items.len()}),
        Value::String(s) => clip(s).into(),
        other => other.clone(),
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

/// A bounded digest: lists become `{count, sample}`, big maps `{keys, sample}`,
/// nesting stops at three levels.
fn digest(value: &Value, depth: usize) -> Value {
    match value {
        Value::Array(items) => json!({
            "count": items.len(),
            "sample": items.iter().take(SAMPLE).map(brief).collect::<Vec<_>>(),
        }),
        Value::Object(map) => {
            if depth >= 2 {
                return brief(value);
            }
            if map.len() > 16 {
                let sample: Map<String, Value> = map
                    .iter()
                    .take(5)
                    .map(|(k, v)| (k.clone(), digest(v, depth + 1)))
                    .collect();
                return json!({"keys": map.len(), "sample": sample});
            }
            Value::Object(
                map.iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k.clone(), digest(v, depth + 1)))
                    .collect(),
            )
        }
        Value::String(s) => clip(s).into(),
        other => other.clone(),
    }
}

/// Rank of a severity word, most severe first.
fn severity_rank(item: &Value) -> usize {
    match item
        .get("severity")
        .and_then(Value::as_str)
        .map(str::to_lowercase)
        .as_deref()
    {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") => 2,
        Some("low") => 3,
        _ => 4,
    }
}

/// Rank of a string category, most telling first.
pub(super) fn category_rank(category: &str) -> usize {
    match category {
        "URL" => 0,
        "IP Address" => 1,
        "Email" => 2,
        "Password" => 3,
        "API Key" => 4,
        "Secret/Token" => 5,
        "File Path" => 6,
        "Environment Variable" => 7,
        "Copyright" | "Version" => 8,
        "Error/Warning" => 9,
        _ => 10,
    }
}

/// The most telling categorized strings of a `strings` section, deduplicated.
pub(super) fn top_strings(section: &Value, count: usize) -> Vec<Value> {
    let Some(items) = section.get("strings").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut picked: Vec<(usize, &Value)> = items
        .iter()
        .filter_map(|s| {
            let category = s.get("category")?.as_str()?;
            Some((category_rank(category), s))
        })
        .collect();
    picked.sort_by_key(|(rank, s)| (*rank, s.get("offset").and_then(Value::as_u64)));
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (_, s) in picked {
        let value = s.get("value").and_then(Value::as_str).unwrap_or_default();
        if !seen.insert(value) {
            continue;
        }
        out.push(json!({
            "category": s.get("category"),
            "value": clip_around_span(value, crate::strings::category_span(value)),
            "offset": s.get("offset"),
        }));
        if out.len() >= count {
            break;
        }
    }
    out
}

fn strings_summary(section: &Value) -> Value {
    let mut by_category: std::collections::BTreeMap<(usize, String), usize> = Default::default();
    if let Some(items) = section.get("strings").and_then(Value::as_array) {
        for item in items {
            if let Some(category) = item.get("category").and_then(Value::as_str) {
                *by_category
                    .entry((category_rank(category), category.to_string()))
                    .or_default() += 1;
            }
        }
    }
    let categories: Map<String, Value> = by_category
        .into_iter()
        .map(|((_, name), count)| (name, count.into()))
        .collect();
    json!({
        "total_count": section.get("total_count"),
        "unique_count": section.get("unique_count"),
        "ascii_count": section.get("ascii_count"),
        "utf16_count": section.get("utf16_count"),
        "min_length": section.get("min_length"),
        "categories": categories,
        "top": top_strings(section, 10),
    })
}

fn hex_summary(section: &Value) -> Value {
    let lines: Vec<&str> = section
        .get("lines")
        .and_then(Value::as_array)
        .map(|lines| lines.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut out = json!({
        "offset": section.get("offset"),
        "length": section.get("length"),
        "total_bytes": section.get("total_bytes"),
        "lines": lines.len(),
    });
    if lines.len() <= HEX_WHOLE_LINES {
        out["text"] = lines.join("\n").into();
    } else {
        out["text"] = lines[..HEX_SUMMARY_LINES].join("\n").into();
        out["shown_lines"] = HEX_SUMMARY_LINES.into();
        out["more"] = format!(
            "only the first {HEX_SUMMARY_LINES} of {} lines are shown; call read_hex with \
             offset {} to read the rest",
            lines.len(),
            section.get("offset").and_then(Value::as_u64).unwrap_or(0)
        )
        .into();
    }
    out
}

/// The summary of a section: what `analyze_file` returns for it.
pub(super) fn summarize(name: &str, section: &Value) -> Value {
    match name {
        "strings" => strings_summary(section),
        "hex_dump" => hex_summary(section),
        // Small and the whole point of asking.
        "metadata" => {
            // The hashes have their own section and size is file_size.
            let mut out = digest_or_whole(section);
            if let Some(map) = out.as_object_mut() {
                for key in ["hashes", "size"] {
                    map.remove(key);
                }
            }
            out
        }
        "hashes" | "yara_indicators" => digest_or_whole(section),
        "signatures" => digest_or_whole(section),
        "vulnerabilities" => {
            let mut out = digest(section, 0);
            if let Some(items) = section.get("vulnerabilities").and_then(Value::as_array) {
                let mut ranked: Vec<&Value> = items.iter().collect();
                ranked.sort_by_key(|v| severity_rank(v));
                out["vulnerabilities"]["sample"] =
                    ranked.into_iter().take(SAMPLE).map(brief).collect();
            }
            out
        }
        "entropy" => {
            let mut out = digest(section, 0);
            if let Some(items) = section.get("sections").and_then(Value::as_array) {
                let mut ranked: Vec<&Value> = items.iter().collect();
                ranked.sort_by(|a, b| {
                    let key = |v: &Value| v.get("entropy").and_then(Value::as_f64).unwrap_or(0.0);
                    key(b).total_cmp(&key(a))
                });
                out["sections"]["sample"] = ranked.into_iter().take(SAMPLE).map(brief).collect();
            }
            out
        }
        "behavioral" => {
            let mut out = digest(section, 0);
            if let Some(map) = out.as_object_mut() {
                map.insert(
                    "lists".into(),
                    json!({"findings": list_total(name, &lists(name)[0], section)}),
                );
            }
            out
        }
        _ => digest(section, 0),
    }
}

/// The section itself when it is under a few KB, otherwise its digest.
fn digest_or_whole(section: &Value) -> Value {
    let size = serde_json::to_string(section).map_or(usize::MAX, |t| t.len());
    if size <= 4_000 {
        section.clone()
    } else {
        digest(section, 0)
    }
}

/// The hint that points from a summary to the call that pages its lists.
pub(super) fn drill_down(name: &str, file_path: &str, section: &Value) -> Option<Value> {
    let specs = lists(name);
    let first = specs.first()?;
    let total = list_total(name, first, section);
    let others: Vec<&str> = specs.iter().skip(1).map(|s| s.name).collect();
    let mut arguments = json!({"file_path": file_path, "section": name});
    if name == "strings" {
        arguments["category"] = "URL".into();
    }
    let mut step = json!({
        "tool": "query_analysis",
        "arguments": arguments,
        "why": format!(
            "page{} the {} {} (offset, limit, filter, category)",
            if name == "strings" { " and filter" } else { "" },
            total.map_or_else(String::new, |t| t.to_string()),
            first.name
        ),
    });
    if !others.is_empty() {
        step["other_lists"] = others.into();
    }
    if name == "disassembly" {
        step["then"] = json!({
            "tool": "disassemble",
            "arguments": {"file_path": file_path, "function": "<name from the functions list>"},
            "gives": "the instruction listing of one function (200 instructions by default)",
        });
    }
    Some(step)
}

/// Strings to hand the string tracker: the categorized ones first, then the
/// rest in file order, at most [`TRACKER_STRINGS`].
pub(super) fn tracker_strings(section: &Value) -> Vec<String> {
    let Some(items) = section.get("strings").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for categorized in [true, false] {
        for item in items {
            if item.get("category").is_some() != categorized {
                continue;
            }
            let Some(value) = item.get("value").and_then(Value::as_str) else {
                continue;
            };
            if seen.insert(value) {
                out.push(value.to_string());
                if out.len() >= TRACKER_STRINGS {
                    return out;
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The overview
// ---------------------------------------------------------------------------

/// What the overview is made of.
pub(super) struct Overview {
    pub value: Map<String, Value>,
    /// The strings section, when it was available (for the string tracker).
    pub strings: Option<Arc<Value>>,
}

fn scalar_fields(value: &Value, keys: &[&str]) -> Value {
    let mut out = Map::new();
    for key in keys {
        if let Some(v) = value.get(*key).filter(|v| !v.is_null()) {
            out.insert((*key).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

/// The triage overview of one file.
/// Above this size the overview skips the sections that read the whole file
/// into memory (strings, symbols, entropy, binary_info) and says how to run
/// each one on purpose.
const OVERVIEW_WHOLE_FILE_LIMIT: u64 = 256 * 1024 * 1024;

pub(super) fn overview(
    engine: &mut Engine<'_>,
    path: &Path,
    file_path: &str,
    size: u64,
    sha256: &str,
    options: &Options,
    mtime_ns: u128,
) -> Overview {
    let mut out = Map::new();
    let mut errors = Map::new();
    let mut notes = Map::new();
    let mut record = |name: &str, failure: &Failure| match failure {
        Failure::Error(m) => {
            errors.insert(name.to_string(), m.clone().into());
        }
        Failure::NotApplicable(m) => {
            notes.insert(name.to_string(), m.clone().into());
        }
    };
    let load = |engine: &mut Engine<'_>, name: &'static str| {
        let planned = plan(name, options, file_path, mtime_ns);
        engine.load(&planned)
    };

    let heavy = size > OVERVIEW_WHOLE_FILE_LIMIT;
    if heavy {
        let why = format!(
            "skipped: the file is {} MiB, over the {} MiB the overview reads whole; \
             call analyze_file with sections: [\"{{}}\"] to run it deliberately",
            size / (1024 * 1024),
            OVERVIEW_WHOLE_FILE_LIMIT / (1024 * 1024)
        );
        for name in ["binary_info", "entropy", "strings", "symbols"] {
            record(name, &Failure::NotApplicable(why.replace("{}", name)));
        }
    }

    out.insert("view".into(), "overview".into());
    out.insert("file_path".into(), file_path.into());
    out.insert("size".into(), size.into());
    out.insert("sha256".into(), sha256.into());

    // Identity: type, mime, md5.
    let kind = detect_file_kind(path).ok();
    let metadata = match load(engine, "metadata") {
        Ok(value) => Some(value),
        Err(failure) => {
            record("metadata", &failure);
            None
        }
    };
    if let Some(metadata) = &metadata {
        if let Some(name) = metadata.get("file_name") {
            out.insert("name".into(), name.clone());
        }
    }
    let kind_is_known = kind.as_ref().is_some_and(|k| k.kind != "unknown");
    if let Some(kind) = kind.as_ref().filter(|_| kind_is_known) {
        out.insert("type".into(), kind.label.clone().into());
        out.insert("kind".into(), kind.kind.clone().into());
        out.insert("mime".into(), kind.mime.clone().into());
    } else if let Some(mime) = metadata.as_ref().and_then(|m| m.get("mime_type")) {
        out.insert("mime".into(), mime.clone());
    }
    match load(engine, "hashes") {
        Ok(hashes) => {
            if let Some(md5) = hashes.get("md5") {
                out.insert("md5".into(), md5.clone());
            }
        }
        Err(failure) => record("hashes", &failure),
    }

    // Format facts.
    let mut available: Vec<&str> = vec!["metadata", "hashes", "strings", "hex_dump"];
    let mut binary_ok = false;
    let binary_info = if heavy {
        Err(Failure::NotApplicable(String::new()))
    } else {
        load(engine, "binary_info")
    };
    match binary_info {
        Err(Failure::NotApplicable(m)) if m.is_empty() => {}
        Ok(info) => {
            // A file that parses only as "Raw" has no executable structure.
            binary_ok = !matches!(
                info.get("format").and_then(Value::as_str),
                Some("Raw" | "Unknown") | None
            );
            let mut format = scalar_fields(
                &info,
                &[
                    "format",
                    "architecture",
                    "compiler",
                    "linker",
                    "entry_point",
                    "is_stripped",
                    "has_debug_info",
                ],
            );
            for key in ["sections", "imports", "exports"] {
                if let Some(items) = info.get(key).and_then(Value::as_array) {
                    format[format!("{key}_count")] = items.len().into();
                }
            }
            out.insert("format".into(), format);
        }
        Err(failure) => record("binary_info", &failure),
    }
    match load(engine, "signatures") {
        Ok(signature) => {
            out.insert(
                "signature".into(),
                scalar_fields(
                    &signature,
                    &[
                        "is_signed",
                        "signature_type",
                        "signer",
                        "verification_status",
                    ],
                ),
            );
        }
        Err(failure) => record("signatures", &failure),
    }
    let entropy = if heavy {
        Err(Failure::NotApplicable(String::new()))
    } else {
        load(engine, "entropy")
    };
    match entropy {
        Err(Failure::NotApplicable(m)) if m.is_empty() => {}
        Ok(entropy) => {
            let mut headline = Map::new();
            headline.insert("overall".into(), entropy["overall_entropy"].clone());
            if let Some(v) = entropy.pointer("/packed_indicators/likely_packed") {
                headline.insert("likely_packed".into(), v.clone());
            }
            if let Some(v) = entropy.pointer("/encryption_indicators/likely_encrypted") {
                headline.insert("likely_encrypted".into(), v.clone());
            }
            if let Some(v) = entropy.get("obfuscation_score") {
                headline.insert("obfuscation_score".into(), v.clone());
            }
            if let Some(v) = entropy.get("sections").and_then(Value::as_array) {
                headline.insert("sections".into(), v.len().into());
            }
            out.insert("entropy".into(), Value::Object(headline));
        }
        Err(failure) => record("entropy", &failure),
    }

    // Counts and the strings worth reading first.
    let mut counts = Map::new();
    let strings_loaded = if heavy {
        Err(Failure::NotApplicable(String::new()))
    } else {
        load(engine, "strings")
    };
    let strings = match strings_loaded {
        Err(Failure::NotApplicable(m)) if m.is_empty() => None,
        Ok(strings) => {
            counts.insert("strings".into(), strings["total_count"].clone());
            counts.insert("unique_strings".into(), strings["unique_count"].clone());
            let top = top_strings(&strings, 8);
            if !top.is_empty() {
                out.insert("interesting_strings".into(), top.into());
            }
            Some(strings)
        }
        Err(failure) => {
            record("strings", &failure);
            None
        }
    };
    if binary_ok && !heavy {
        match load(engine, "symbols") {
            Ok(symbols) => {
                if let Some(items) = symbols.get("functions").and_then(Value::as_array) {
                    counts.insert("functions".into(), items.len().into());
                }
                if let Some(imports) = symbols.get("imports").and_then(Value::as_array) {
                    counts.insert("imported_symbols".into(), imports.len().into());
                }
                if let Some(exports) = symbols.get("exports").and_then(Value::as_array) {
                    counts.insert("exported_symbols".into(), exports.len().into());
                }
            }
            Err(failure) => record("symbols", &failure),
        }
    }
    out.insert("counts".into(), Value::Object(counts));

    let binary_ok = binary_ok || heavy;
    if let Some(kind) = kind.as_ref().filter(|_| kind_is_known && !heavy) {
        if let Some(details) = format_overview(path, kind) {
            out.insert("format_details".into(), details);
        }
    }

    // What can be asked next.
    let mut not_available = Map::new();
    if binary_ok {
        available.extend([
            "binary_info",
            "signatures",
            "symbols",
            "control_flow",
            "vulnerabilities",
            "code_quality",
            "dependencies",
            "entropy",
            "disassembly",
        ]);
    } else {
        available.extend(["signatures", "entropy"]);
        let why = "this file is not a recognized executable (PE, ELF, Mach-O, Java class)";
        for name in [
            "binary_info",
            "symbols",
            "control_flow",
            "vulnerabilities",
            "code_quality",
            "dependencies",
            "disassembly",
        ] {
            not_available.insert(name.to_string(), why.into());
        }
    }
    available.extend([
        "threats",
        "enhanced_threats",
        "behavioral",
        "yara_indicators",
    ]);
    out.insert("available_sections".into(), available.clone().into());
    if !not_available.is_empty() {
        out.insert("not_applicable".into(), Value::Object(not_available));
    }
    let mut steps: Vec<Value> = vec![json!({
        "tool": "analyze_file",
        "arguments": {"file_path": file_path, "sections": ["<one or more of available_sections>"]},
        "gives": "a summary of each named section (headline numbers, top few items, totals); \
                  the full section is cached for query_analysis",
    })];
    steps.push(json!({
        "tool": "query_analysis",
        "arguments": {"file_path": file_path, "section": "strings", "category": "URL"},
        "gives": "page and filter every string (filter, category, encoding, offset, limit)",
    }));
    if binary_ok {
        steps.push(json!({
            "tool": "query_analysis",
            "arguments": {"file_path": file_path, "section": "symbols", "list": "imports"},
            "gives": "page the imported symbols",
        }));
    }
    if binary_ok {
        steps.push(json!({
            "tool": "disassemble",
            "arguments": {"file_path": file_path},
            "gives": "the function list, then pass `function` or `address` for one function's instructions",
        }));
    }
    steps.push(json!({
        "tool": "read_hex",
        "arguments": {"file_path": file_path, "offset": 0, "length": 256},
        "gives": "raw bytes (a negative offset reads from the end of the file)",
    }));
    out.insert("next_steps".into(), steps.into());
    if !errors.is_empty() {
        out.insert("errors".into(), Value::Object(errors));
    }
    if !notes.is_empty() {
        out.insert("notes".into(), Value::Object(notes));
    }
    Overview {
        value: out,
        strings,
    }
}
