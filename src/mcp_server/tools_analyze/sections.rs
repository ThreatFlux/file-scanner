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
    binary_parser::{parse_binary_with_arch, BinaryInfo},
    call_graph::{generate_call_graph, summarize_call_graph},
    code_metrics::analyze_code_quality,
    control_flow::{analyze_control_flow, ControlFlowAnalysis},
    dependency_analysis::analyze_dependencies,
    disassembly::FlowControl,
    disassembly::{disassemble_binary_with_coverage, DisassemblyCoverage, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols_with_arch, SymbolTable},
    hash::{calculate_all_hashes, Hashes},
    hexdump::{generate_hex_dump, HexDumpOptions},
    mcp_server::{
        state::{mark_section, SectionCache},
        tools_formats::{detect_file_kind, format_overview},
    },
    metadata::FileMetadata,
    signature::verify_signature,
    strings::{scan_strings, StringScan},
    taint_tracking::taint_report_for_path,
    threat_detection::{analyze_threats, analyze_threats_enhanced},
    vulnerability_detection::analyze_vulnerabilities,
};

use super::YaraIndicators;

/// Every analysis `analyze_file` can run, in result order. `all: true` runs
/// all of them.
pub(super) const ANALYSES: [&str; 19] = [
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
    "call_graph",
    "threats",
    "enhanced_threats",
    "behavioral",
    "taint",
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
#[derive(Debug, Clone)]
pub(super) struct Options {
    pub min: usize,
    pub hex_size: usize,
    pub hex_offset: u64,
    /// The slice of a universal Mach-O to analyze (`binary_info.universal_slices`
    /// names the valid ones). Part of every cache key that depends on it.
    pub arch: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min: DEFAULT_MIN_STRING,
            hex_size: DEFAULT_HEX_DUMP,
            hex_offset: 0,
            arch: None,
        }
    }
}

/// Longest `min_string_length` a call may ask for. The scan costs about the
/// square of the minimum on a file of long printable runs: 4096 keeps the
/// worst case near one second on 10 MB.
pub(super) const MAX_MIN_STRING: usize = 4_096;

/// Longest `arch` value kept: slice names are a few characters.
const ARCH_MAX: usize = 32;

/// The `arch` argument as an option value: blank means none; lowercase, only
/// letters, digits and `_ . -`, at most [`ARCH_MAX`] characters (it is echoed
/// in a note and is part of the cache key, so `ARM64E` and `arm64e` are one).
pub(super) fn arch_option(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .map(|a| {
            a.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                .take(ARCH_MAX)
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|a| !a.is_empty())
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
    let arch = options
        .arch
        .as_deref()
        .map(|a| format!(":arch={a}"))
        .unwrap_or_default();
    let key = match name {
        "metadata" => format!("metadata:{path}:{mtime_ns}"),
        "strings" => format!("strings:min={}", options.min),
        "hex_dump" => format!(
            "hex_dump:size={}:offset={}",
            options.hex_size, options.hex_offset
        ),
        "dependencies" | "behavioral" | "yara_indicators" => {
            format!("{name}:min={}{arch}", options.min)
        }
        "threats" => "threats:basic".to_string(),
        "enhanced_threats" => "threats:enhanced".to_string(),
        // Everything built from the symbol table or the parsed binary.
        "binary_info" | "symbols" | "control_flow" | "vulnerabilities" | "code_quality"
        | "disassembly" | "call_graph" => format!("{name}{arch}"),
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
    coverage: Option<DisassemblyCoverage>,
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
            coverage: None,
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
        let arch = self.options.arch.clone();
        self.symbols
            .get_or_insert_with(|| {
                mark_section("symbols");
                analyze_symbols_with_arch(path, arch.as_deref())
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
        if let Some(done) = &self.disassembly {
            return done.clone();
        }
        let outcome = self.symbols().and_then(|symbols| {
            mark_section("disassembly");
            disassemble_binary_with_coverage(self.path, &symbols).map_err(|e| format!("{e:#}"))
        });
        let outcome = outcome.map(|(result, coverage)| {
            self.coverage = Some(coverage);
            Arc::new(result)
        });
        self.disassembly = Some(outcome.clone());
        outcome
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
        let arch = self.options.arch.clone();
        self.binary_info
            .get_or_insert_with(|| {
                mark_section("binary_info");
                parse_binary_with_arch(path, arch.as_deref())
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
            "call_graph" => "call_graph",
            "threats" => "threats",
            "enhanced_threats" => "enhanced_threats",
            "behavioral" => "behavioral",
            "taint" => "taint",
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
            "control_flow" => {
                let flow = self.control_flow().map_err(classify)?;
                bounded_control_flow(&flow)
            }
            "vulnerabilities" => {
                let symbols = self.symbols().map_err(classify)?;
                let flow = self.control_flow().map_err(classify)?;
                let value =
                    to_value(&analyze_vulnerabilities(path, &symbols, &flow).map_err(error)?)?;
                Ok(with_notes(value, partial_flow_notes(&flow)))
            }
            "code_quality" => {
                let symbols = self.symbols().map_err(classify)?;
                let flow = self.control_flow().map_err(classify)?;
                let value = to_value(&analyze_code_quality(path, &symbols, &flow).map_err(error)?)?;
                Ok(with_notes(value, partial_flow_notes(&flow)))
            }
            "dependencies" => {
                let symbols = self.symbols().map_err(classify)?;
                let strings = self.scan()?.to_extracted();
                to_value(&analyze_dependencies(path, &symbols, Some(&strings)).map_err(error)?)
            }
            "entropy" => to_value(&*self.entropy().map_err(classify)?),
            "disassembly" => {
                let result = self.disassembly().map_err(classify)?;
                bounded_disassembly(&result, self.coverage.as_ref())
            }
            "call_graph" => self.call_graph(),
            "taint" => match taint_report_for_path(path) {
                Ok(report) => to_value(&report),
                // Source text only; the analyzer's own reason is the note.
                Err(e) => Err(Failure::NotApplicable(format!("{e:#}"))),
            },
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

    /// The bounded call graph, built from the symbols and disassembly this
    /// call already shares (what `call_graph_for_path` does from scratch).
    fn call_graph(&mut self) -> Result<Value, Failure> {
        let symbols = self.symbols().map_err(classify)?;
        let disassembly = self.disassembly().map_err(classify)?;
        let calls = disassembly
            .instructions
            .iter()
            .filter(|i| matches!(i.flow_control, Some(FlowControl::Call { .. })))
            .count();
        let graph = generate_call_graph(self.path, &disassembly, &symbols).map_err(error)?;
        let no_edges = graph.edges.is_empty();
        let mut report = summarize_call_graph(graph);
        if let Some(coverage) = self.coverage.as_ref().filter(|c| c.truncated) {
            report.truncated = true;
            report.notes.push(format!(
                "built from a partial disassembly: {}",
                coverage.notes.join("; ")
            ));
        }
        if no_edges && calls > 0 {
            report.notes.push(format!(
                "the code has {calls} call instructions but none could be attributed to a \
                 function: the file has no function symbols for its code (stripped), so the \
                 graph has no edges"
            ));
        }
        to_value(&report)
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
        // The most telling categories first (URLs, secrets ...), each indicator
        // once; a long string is represented by the text that made it
        // categorized. A sorted set, so the same file always gives the same 20.
        let unique_strings: Vec<String> = scan
            .interesting()
            .filter_map(|s| {
                let text = super::llm::key_text(&s.value, 50)?;
                Some((category_rank(s.category.as_deref().unwrap_or("")), text))
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(20)
            .map(|(_, text)| text.to_string())
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

/// The limits control-flow analysis hit, for the sections built on it
/// (vulnerabilities, code quality): they saw only the functions it analyzed.
fn partial_flow_notes(flow: &ControlFlowAnalysis) -> Vec<String> {
    flow.analysis_stats
        .errors
        .iter()
        .filter(|e| e.starts_with("Limit"))
        .map(|e| format!("built on a partial control-flow analysis. {e}"))
        .collect()
}

/// `value` with a `notes` list (when there is anything to say).
fn with_notes(mut value: Value, notes: Vec<String>) -> Value {
    if notes.is_empty() {
        return value;
    }
    if let Some(map) = value.as_object_mut() {
        map.insert("notes".into(), notes.into());
    }
    value
}

fn classify_binary(message: String) -> Failure {
    Failure::NotApplicable(format!("not a recognized executable format ({message})"))
}

/// Instructions of the flat listing kept in the stored disassembly section.
pub(super) const STORED_FLAT: usize = 20_000;
/// Instructions kept inside function entries, all functions together.
pub(super) const STORED_FUNCTION_INSTRUCTIONS: usize = 30_000;
/// Rows kept of each analysis list (system calls, patterns ...).
const STORED_ANALYSIS_ROWS: usize = 500;

/// One instruction as the stored section and `disassemble` carry it: the
/// bytes are one hex string, not an array of numbers.
pub(super) fn instruction_value(i: &crate::disassembly::Instruction) -> Value {
    let mut bytes = String::with_capacity(i.bytes.len() * 3);
    for (n, b) in i.bytes.iter().enumerate() {
        if n > 0 {
            bytes.push(' ');
        }
        bytes.push_str(&format!("{b:02x}"));
    }
    json!({
        "address": i.address,
        "bytes": bytes,
        "mnemonic": i.mnemonic,
        "operands": i.operands,
        "instruction_type": serde_json::to_value(&i.instruction_type).unwrap_or(Value::Null),
        "flow_control": serde_json::to_value(&i.flow_control).unwrap_or(Value::Null),
        "size": i.size,
    })
}

/// The part of a [`DisassemblyResult`] that is stored and served: summary,
/// coverage, the function table (each with its instruction count), the first
/// [`STORED_FLAT`] instructions and the instructions of as many functions as
/// [`STORED_FUNCTION_INSTRUCTIONS`] allows. Never the whole result as JSON:
/// that cost gigabytes on a few megabytes of code. `disassemble` decodes a
/// window again for what is not stored.
pub(super) fn bounded_disassembly(
    result: &DisassemblyResult,
    coverage: Option<&DisassemblyCoverage>,
) -> Result<Value, Failure> {
    let rows = |len: usize| len.min(STORED_ANALYSIS_ROWS);
    let a = &result.analysis;
    let mut notes: Vec<String> = Vec::new();
    let mut cut_lists: Vec<&str> = Vec::new();
    let mut analysis = json!({
        "total_instructions": a.total_instructions,
        "instruction_types": a.instruction_types,
        "control_flow_summary": to_value(&a.control_flow_summary)?,
        "memory_accesses_count": a.memory_accesses.len(),
        "register_usage_counts": a
            .register_usage
            .iter()
            .map(|(k, v)| (k.clone(), json!(v.len())))
            .collect::<Map<String, Value>>(),
    });
    analysis["system_calls"] = to_value(&a.system_calls[..rows(a.system_calls.len())].to_vec())?;
    analysis["crypto_operations"] =
        to_value(&a.crypto_operations[..rows(a.crypto_operations.len())].to_vec())?;
    let mut patterns = Vec::new();
    for p in a.suspicious_patterns.iter().take(STORED_ANALYSIS_ROWS) {
        let mut v = to_value(p)?;
        v["addresses_count"] = p.addresses.len().into();
        if let Some(list) = v.get_mut("addresses").and_then(Value::as_array_mut) {
            list.truncate(50);
        }
        patterns.push(v);
    }
    analysis["suspicious_patterns"] = Value::Array(patterns);
    for (name, len) in [
        ("system_calls", a.system_calls.len()),
        ("crypto_operations", a.crypto_operations.len()),
        ("suspicious_patterns", a.suspicious_patterns.len()),
    ] {
        if len > STORED_ANALYSIS_ROWS {
            cut_lists.push(name);
        }
    }
    if !cut_lists.is_empty() {
        notes.push(format!(
            "Limit: {} keep the first {STORED_ANALYSIS_ROWS} rows each in the stored analysis.",
            cut_lists.join(", ")
        ));
    }

    let mut budget = STORED_FUNCTION_INSTRUCTIONS;
    let mut unstored = 0usize;
    let functions: Vec<Value> = result
        .functions
        .iter()
        .map(|f| {
            let keep = f.instructions.len() <= budget;
            let instructions: Vec<Value> = if keep {
                budget -= f.instructions.len();
                f.instructions.iter().map(instruction_value).collect()
            } else {
                unstored += 1;
                Vec::new()
            };
            json!({
                "address": f.address,
                "name": f.name,
                "size": f.size,
                "complexity": f.complexity,
                "instruction_count": f.instructions.len(),
                "basic_blocks_count": f.basic_blocks.len(),
                "instructions": instructions,
            })
        })
        .collect();
    if unstored > 0 {
        notes.push(format!(
            "Limit: the instructions of {unstored} of {} functions are not stored; `disassemble` \
             with that function decodes them again.",
            result.functions.len()
        ));
    }
    let flat: Vec<Value> = result
        .instructions
        .iter()
        .take(STORED_FLAT)
        .map(instruction_value)
        .collect();
    if result.instructions.len() > STORED_FLAT {
        notes.push(format!(
            "Limit: the flat instruction list keeps the first {STORED_FLAT} of {}; `disassemble` \
             with an address decodes any other range again.",
            result.instructions.len()
        ));
    }
    let mut value = json!({
        "architecture": result.architecture,
        "analysis": analysis,
        "functions": functions,
        "instructions": flat,
        "instructions_total": result.instructions.len(),
    });
    // The range of the whole list, not of the stored part.
    if let (Some(first), Some(last)) = (result.instructions.first(), result.instructions.last()) {
        value["instructions_first_address"] = first.address.into();
        value["instructions_last_address"] = last.address.into();
    }
    if let Some(coverage) = coverage {
        value["coverage"] = to_value(coverage)?;
    }
    if !notes.is_empty() {
        value["notes"] = notes.into();
    }
    Ok(value)
}

/// Basic blocks kept in the stored control-flow section, all functions together.
const STORED_CFG_BLOCKS: usize = 20_000;
/// Instructions kept inside those blocks, all functions together.
const STORED_CFG_INSTRUCTIONS: usize = 20_000;
/// Edges kept, all functions together.
const STORED_CFG_EDGES: usize = 40_000;

/// The stored control-flow section: the metrics and statistics whole, one row
/// per function graph with its true counts, and the blocks, edges and block
/// instructions of the first graphs up to fixed totals. Never the whole
/// analysis as JSON: that cost 12 GiB on an 83 KB file with overlapping
/// function symbols.
pub(super) fn bounded_control_flow(flow: &ControlFlowAnalysis) -> Result<Value, Failure> {
    let mut blocks_left = STORED_CFG_BLOCKS;
    let mut instructions_left = STORED_CFG_INSTRUCTIONS;
    let mut edges_left = STORED_CFG_EDGES;
    let mut cut_blocks = 0usize;
    let mut cut_instructions = 0usize;
    let mut cut_edges = 0usize;
    let mut cfgs: Vec<Value> = Vec::with_capacity(flow.cfgs.len());
    for cfg in &flow.cfgs {
        let keep_blocks = cfg.basic_blocks.len().min(blocks_left);
        blocks_left -= keep_blocks;
        cut_blocks += cfg.basic_blocks.len() - keep_blocks;
        let mut blocks: Vec<Value> = Vec::with_capacity(keep_blocks);
        for b in cfg.basic_blocks.iter().take(keep_blocks) {
            let keep = b.instructions.len() <= instructions_left;
            let instructions: Vec<Value> = if keep {
                instructions_left -= b.instructions.len();
                b.instructions.iter().map(instruction_value_cf).collect()
            } else {
                cut_instructions += b.instructions.len();
                Vec::new()
            };
            let row = json!({
                "id": b.id,
                "start_address": b.start_address,
                "end_address": b.end_address,
                "successors": b.successors,
                "predecessors": b.predecessors,
                "block_type": to_value(&b.block_type)?,
                "instruction_count": b.instruction_count,
                "instructions": instructions,
            });
            blocks.push(row);
        }
        let keep_edges = cfg.edges.len().min(edges_left);
        edges_left -= keep_edges;
        cut_edges += cfg.edges.len() - keep_edges;
        let edges = to_value(&cfg.edges[..keep_edges].to_vec())?;
        cfgs.push(json!({
            "function_address": cfg.function_address,
            "function_name": cfg.function_name,
            "basic_blocks": blocks,
            "basic_blocks_count": cfg.basic_blocks.len(),
            "edges": edges,
            "edges_count": cfg.edges.len(),
            "entry_block": cfg.entry_block,
            "exit_blocks": cfg.exit_blocks,
            "loops": to_value(&cfg.loops)?,
            "complexity": to_value(&cfg.complexity)?,
        }));
    }
    let mut notes: Vec<String> = Vec::new();
    if cut_blocks > 0 {
        notes.push(format!(
            "Limit: the stored section keeps {STORED_CFG_BLOCKS} basic blocks in all; {cut_blocks} \
             blocks of later functions are counted (basic_blocks_count) but not listed."
        ));
    }
    if cut_instructions > 0 {
        notes.push(format!(
            "Limit: {cut_instructions} instructions inside basic blocks are not stored (the cap is \
             {STORED_CFG_INSTRUCTIONS}); `disassemble` lists the instructions of a function."
        ));
    }
    if cut_edges > 0 {
        notes.push(format!(
            "Limit: the stored section keeps {STORED_CFG_EDGES} edges in all; {cut_edges} edges of \
             later functions are counted (edges_count) but not listed."
        ));
    }
    let mut value = json!({
        "cfgs": cfgs,
        "overall_metrics": to_value(&flow.overall_metrics)?,
        "analysis_stats": to_value(&flow.analysis_stats)?,
    });
    if !notes.is_empty() {
        value["notes"] = notes.into();
    }
    Ok(value)
}

fn instruction_value_cf(i: &crate::control_flow::Instruction) -> Value {
    json!({
        "address": i.address,
        "bytes": i.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
        "mnemonic": i.mnemonic,
        "operands": i.operands,
        "instruction_type": serde_json::to_value(&i.instruction_type).unwrap_or(Value::Null),
        "flow_control": serde_json::to_value(&i.flow_control).unwrap_or(Value::Null),
        "size": i.size,
    })
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, Failure> {
    serde_json::to_value(value)
        .map_err(|e| Failure::Error(format!("Could not serialize the result: {e}")))
}

// ---------------------------------------------------------------------------
// The cache around the computation
// ---------------------------------------------------------------------------

/// Runs `compute`; a panic inside an analyzer (a malformed sample it does not
/// guard against) fails that one section with a message instead of the call.
fn contain(name: &str, compute: impl FnOnce() -> Result<Value, Failure>) -> Result<Value, Failure> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(compute)) {
        Ok(result) => result,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            Err(Failure::Error(format!(
                "the {name} analyzer crashed on this file ({detail})"
            )))
        }
    }
}

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
    /// False under `--no-cache`: nothing is kept, so a note about the size
    /// limit would be wrong.
    cache_enabled: bool,
}

impl<'a> Engine<'a> {
    pub(super) fn new(
        cache: &'a SectionCache,
        sha: &'a str,
        ctx: Ctx<'a>,
        cache_enabled: bool,
    ) -> Self {
        Self {
            cache_enabled,
            cache,
            sha,
            ctx,
            cached: 0,
            computed: 0,
            not_kept: Vec::new(),
            evicted: Vec::new(),
        }
    }

    /// The typed disassembly of this call, decoded again when only the bounded
    /// section is stored: what `disassemble` reads a window from.
    pub(super) fn typed_disassembly(&mut self) -> Result<Arc<DisassemblyResult>, String> {
        self.ctx.disassembly()
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
        let value = contain(name, || ctx.compute(name))?;
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
        if !self.cache_enabled {
            return (self.computed > 0).then(|| {
                "The section cache is off (--no-cache): every call recomputes its sections, so \
                 query_analysis on this file computes again each time."
                    .to_string()
            });
        }
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
        "call_graph" => specs!(
            "functions" => "/graph/nodes",
            "edges" => "/graph/edges",
            "unreachable_functions" => "/graph/unreachable_functions",
        ),
        "taint" => specs!(
            "flows" => "/analysis/taint_flows",
            "vulnerabilities" => "/analysis/vulnerabilities",
            "sources" => "/analysis/sources",
            "sinks" => "/analysis/sinks",
            "sanitizers" => "/analysis/sanitizers",
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
                    // A function row that stores no instructions has a true
                    // `instruction_count`; the length of the empty list would
                    // contradict it.
                    Value::Array(_)
                        if key == "instructions" && map.contains_key("instruction_count") => {}
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
                    // The address bounds are for `disassemble`, not the summary.
                    .filter(|(k, v)| {
                        !v.is_null()
                            && !matches!(
                                k.as_str(),
                                "instructions_first_address" | "instructions_last_address"
                            )
                    })
                    .map(|(k, v)| {
                        let kept = if is_note_key(k) { keep_notes(v) } else { None };
                        (k.clone(), kept.unwrap_or_else(|| digest(v, depth + 1)))
                    })
                    .collect(),
            )
        }
        Value::String(s) => clip(s).into(),
        other => other.clone(),
    }
}

/// Keys that hold what an analyzer said about its own limits and failures.
pub(super) fn is_note_key(key: &str) -> bool {
    matches!(key, "note" | "notes" | "errors" | "warnings")
}

/// Longest note kept whole, in bytes.
const NOTE_LIMIT: usize = 600;

/// `text` cut at a sentence boundary under [`NOTE_LIMIT`] (never at the
/// 160 characters other strings get: a limit note loses its point there).
fn clip_note(text: &str) -> String {
    if text.len() <= NOTE_LIMIT {
        return text.to_string();
    }
    let end = text.floor_char_boundary(NOTE_LIMIT);
    let head = &text[..end];
    match head.rfind(". ") {
        Some(at) if at > NOTE_LIMIT / 3 => format!("{}…", &head[..=at]),
        _ => format!("{head}…"),
    }
}

/// A note, or a list of notes, with each text kept to [`NOTE_LIMIT`].
fn keep_notes(value: &Value) -> Option<Value> {
    match value {
        Value::String(text) => Some(clip_note(text).into()),
        Value::Array(items) if items.iter().all(Value::is_string) => Some(
            items
                .iter()
                .take(10)
                .filter_map(Value::as_str)
                .map(|t| Value::from(clip_note(t)))
                .collect::<Vec<_>>()
                .into(),
        ),
        _ => None,
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

/// The most telling category any string of a `strings` section has, if any.
pub(super) fn top_category(section: &Value) -> Option<String> {
    let counted = section.get("category_counts").and_then(Value::as_object);
    let categories: Vec<&str> = match counted {
        Some(counts) if !counts.is_empty() => counts.keys().map(String::as_str).collect(),
        _ => section
            .get("strings")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(|s| s.get("category").and_then(Value::as_str))
            .collect(),
    };
    categories
        .into_iter()
        .min_by_key(|c| category_rank(c))
        .map(str::to_string)
}

fn strings_summary(section: &Value) -> Value {
    let mut by_category: std::collections::BTreeMap<(usize, String), usize> = Default::default();
    if let Some(counts) = section.get("category_counts").and_then(Value::as_object) {
        // Exact counts over every string, kept or not.
        for (category, count) in counts {
            by_category.insert(
                (category_rank(category), category.clone()),
                count.as_u64().unwrap_or(0) as usize,
            );
        }
    } else if let Some(items) = section.get("strings").and_then(Value::as_array) {
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
    let mut out = json!({
        "total_count": section.get("total_count"),
        "unique_count": section.get("unique_count"),
        "ascii_count": section.get("ascii_count"),
        "utf16_count": section.get("utf16_count"),
        "min_length": section.get("min_length"),
        "categories": categories,
        "top": top_strings(section, 10),
    });
    if section.get("truncated").and_then(Value::as_bool) == Some(true) {
        out["kept"] = section.get("kept").cloned().unwrap_or(Value::Null);
        out["note"] = section.get("note").cloned().unwrap_or(Value::Null);
    }
    out
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
             offset {} to continue after them",
            lines.len(),
            // The dump's lines are 16 bytes each.
            section
                .get("offset")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_add(HEX_SUMMARY_LINES as u64 * 16)
        )
        .into();
    }
    out
}

/// Where an analyzer reports what it skipped, stopped at or could not do.
const NOTE_POINTERS: [&str; 6] = [
    "/analysis_stats/errors",
    "/coverage/notes",
    "/notes",
    "/errors",
    "/warnings",
    "/note",
];
/// Most note lines a summary keeps from one list.
const NOTES_KEPT: usize = 10;

/// The summary of a section: what `analyze_file` returns for it. Whatever the
/// analyzer said about its own limits and errors is kept whole (a bounded
/// number of lines), never reduced to a count.
pub(super) fn summarize(name: &str, section: &Value) -> Value {
    let mut out = summarize_body(name, section);
    for pointer in NOTE_POINTERS {
        let Some(found) = section.pointer(pointer) else {
            continue;
        };
        let kept = match found {
            Value::Array(lines) if !lines.is_empty() => {
                let mut lines: Vec<Value> = lines
                    .iter()
                    .take(NOTES_KEPT)
                    .map(|l| {
                        l.as_str()
                            .map_or_else(|| l.clone(), |t| clip_note(t).into())
                    })
                    .collect();
                if found.as_array().map_or(0, Vec::len) > NOTES_KEPT {
                    lines.push(
                        format!(
                            "... {} more",
                            found.as_array().map_or(0, Vec::len) - NOTES_KEPT
                        )
                        .into(),
                    );
                }
                Value::Array(lines)
            }
            Value::String(text) if !text.is_empty() => clip_note(text).into(),
            _ => continue,
        };
        set_at(&mut out, pointer, kept);
    }
    out
}

/// Set the value at a JSON pointer, making the objects on the way.
fn set_at(root: &mut Value, pointer: &str, value: Value) {
    let mut node = root;
    let mut parts = pointer.split('/').skip(1).peekable();
    while let Some(part) = parts.next() {
        if !node.is_object() {
            return;
        }
        if parts.peek().is_none() {
            node[part] = value;
            return;
        }
        node = &mut node[part];
        if node.is_null() {
            *node = Value::Object(Map::new());
        }
    }
}

fn summarize_body(name: &str, section: &Value) -> Value {
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
        "disassembly" => {
            let mut out = digest(section, 0);
            if let Some(map) = out.as_object_mut() {
                // A second copy of the listing as text: query_analysis and
                // disassemble give the instructions.
                map.remove("output_formats");
            }
            out
        }
        "call_graph" => call_graph_summary(section),
        "taint" => taint_summary(section),
        _ => digest(section, 0),
    }
}

/// Scalar fields of an object (null and nested values left out).
fn scalars(value: Option<&Value>) -> Value {
    Value::Object(
        value
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter(|(_, v)| is_scalar(v) && !v.is_null())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default(),
    )
}

/// The `n` nodes with the most calls in (`degree` = `in_degree`) or out.
fn top_nodes(nodes: &[Value], degree: &str, n: usize) -> Vec<Value> {
    let mut ranked: Vec<&Value> = nodes
        .iter()
        .filter(|node| node.get(degree).and_then(Value::as_u64).unwrap_or(0) > 0)
        .collect();
    ranked.sort_by_key(|node| std::cmp::Reverse(node.get(degree).and_then(Value::as_u64)));
    ranked
        .into_iter()
        .take(n)
        .map(|node| {
            json!({
                "name": node.get("function_name").and_then(Value::as_str).map(clip),
                "address": node.get("function_address"),
                "in": node.get("in_degree"),
                "out": node.get("out_degree"),
            })
        })
        .collect()
}

/// Headline numbers of a call graph; the notes are kept whole.
fn call_graph_summary(section: &Value) -> Value {
    let nodes = section
        .pointer("/graph/nodes")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let count_of = |pointer: &str| {
        section
            .pointer(pointer)
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    };
    json!({
        "nodes_total": section.get("nodes_total"),
        "edges_total": section.get("edges_total"),
        "truncated": section.get("truncated"),
        "statistics": scalars(section.pointer("/graph/statistics")),
        "entry_points": count_of("/graph/entry_points"),
        "unreachable_functions": count_of("/graph/unreachable_functions"),
        "most_called": top_nodes(nodes, "in_degree", SAMPLE),
        "most_calling": top_nodes(nodes, "out_degree", SAMPLE),
        "notes": section
            .get("notes")
            .filter(|n| n.as_array().is_some_and(|a| !a.is_empty())),
    })
}

/// Headline numbers of a taint report; the notes are kept whole.
fn taint_summary(section: &Value) -> Value {
    let mut ranked: Vec<&Value> = section
        .pointer("/analysis/vulnerabilities")
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default();
    ranked.sort_by_key(|v| severity_rank(v));
    json!({
        "totals": section.get("totals"),
        "flow_summary": section.pointer("/analysis/flow_summary"),
        "truncated": section.get("truncated"),
        "top_vulnerabilities": ranked.into_iter().take(SAMPLE).map(brief).collect::<Vec<_>>(),
        "notes": section.get("notes"),
    })
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
        if let Some(category) = top_category(section) {
            arguments["category"] = category.into();
        }
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
/// into memory (strings, symbols, entropy, binary_info, signatures) and says how to run
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
        for name in ["binary_info", "entropy", "strings", "symbols", "signatures"] {
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
    let signatures = if heavy {
        Err(Failure::NotApplicable(String::new()))
    } else {
        load(engine, "signatures")
    };
    match signatures {
        Err(Failure::NotApplicable(m)) if m.is_empty() => {}
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

    let mut binary_ok = binary_ok || heavy;
    if let Some(kind) = kind.as_ref().filter(|_| kind_is_known && !heavy) {
        if let Some(mut details) = format_overview(path, kind) {
            // The tools to call are the overview's own next_steps.
            if let Some(map) = details.as_object_mut() {
                for key in ["next_steps", "tool", "arguments"] {
                    map.remove(key);
                }
            }
            out.insert("format_details".into(), cap_details(details, 0));
        }
    }

    // What can be asked next.
    let mut not_available = Map::new();
    let kind_name = kind.as_ref().map_or("", |k| k.kind.as_str());
    // A Java archive has no native code to analyze, whatever the parser made of it.
    if matches!(kind_name, "jar" | "apk") {
        binary_ok = false;
    }
    // Code analysis does not read a slice of a universal Mach-O yet.
    let fat = binary_ok && kind_name == "macho-fat";
    if binary_ok {
        available.extend([
            "binary_info",
            "signatures",
            "symbols",
            "dependencies",
            "entropy",
        ]);
        if fat {
            for name in [
                "control_flow",
                "vulnerabilities",
                "code_quality",
                "disassembly",
                "call_graph",
            ] {
                not_available.insert(
                    name.to_string(),
                    "this is a universal (fat) Mach-O; code analysis does not read one of its \
                     slices yet (binary_info and symbols take `arch`, one of \
                     format.universal_slices)"
                        .into(),
                );
            }
        } else {
            available.extend([
                "control_flow",
                "vulnerabilities",
                "code_quality",
                "disassembly",
                "call_graph",
            ]);
        }
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
            "call_graph",
        ] {
            not_available.insert(name.to_string(), why.into());
        }
    }
    available.extend(["threats", "enhanced_threats", "behavioral"]);
    // Taint analysis reads source text.
    let is_text = kind
        .as_ref()
        .is_some_and(|k| matches!(k.kind.as_str(), "text" | "script"));
    if is_text {
        available.push("taint");
    } else if !heavy {
        not_available.insert(
            "taint".to_string(),
            "applies to UTF-8 source or script text only, not to this kind of file".into(),
        );
    }
    available.push("yara_indicators");
    out.insert("available_sections".into(), available.clone().into());
    if !not_available.is_empty() {
        out.insert("not_applicable".into(), Value::Object(not_available));
    }
    let mut steps: Vec<Value> = kind
        .as_ref()
        .filter(|_| kind_is_known)
        .map(|k| specialist_steps(k, path, file_path))
        .unwrap_or_default();
    steps.push(json!({
        "tool": "analyze_file",
        "arguments": {"file_path": file_path, "sections": ["<one or more of available_sections>"]},
        "gives": "a summary of each named section (headline numbers, top few items, totals); \
                  the full section is cached for query_analysis",
    }));
    let mut string_arguments = json!({"file_path": file_path, "section": "strings"});
    if let Some(category) = strings.as_deref().and_then(top_category) {
        string_arguments["category"] = category.into();
    }
    steps.push(json!({
        "tool": "query_analysis",
        "arguments": string_arguments,
        "gives": "page and filter every string (filter, category, encoding, offset, limit)",
    }));
    if binary_ok {
        steps.push(json!({
            "tool": "query_analysis",
            "arguments": {"file_path": file_path, "section": "symbols", "list": "imports"},
            "gives": "page the imported symbols",
        }));
    }
    if binary_ok && !fat {
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

/// What happened to the `arch` argument, when it changed nothing the caller
/// would expect: ignored on a file that is not a universal Mach-O, or no slice
/// of that name (the default slice was analyzed instead).
pub(super) fn arch_note(
    engine: &mut Engine<'_>,
    options: &Options,
    file_path: &str,
    mtime_ns: u128,
) -> Option<String> {
    let arch = options.arch.as_deref()?;
    let info = engine
        .load(&plan("binary_info", options, file_path, mtime_ns))
        .ok()?;
    let Some(slices) = info.get("universal_slices").and_then(Value::as_array) else {
        return Some(format!(
            "arch '{arch}' was ignored: only a universal (fat) Mach-O has architecture slices, \
             and this file is not one."
        ));
    };
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '_', ' '], "");
    let names: Vec<&str> = slices
        .iter()
        .filter_map(|s| s.get("architecture").and_then(Value::as_str))
        .collect();
    let wanted = norm(arch);
    let found = names.iter().any(|n| {
        let n = norm(n);
        n == wanted || (wanted == "aarch64" && n == "arm64") || (wanted == "amd64" && n == "x8664")
    });
    (!found).then(|| {
        format!(
            "arch '{arch}' is not a slice of this file, so the default slice ({}) was analyzed. \
             Slices: {}.",
            info.get("analyzed_slice")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            names.join(", ")
        )
    })
}

/// Longest string, and most list items, `format_details` keeps.
const DETAIL_TEXT: usize = 160;
const DETAIL_ITEMS: usize = 10;

/// `value` cut to a few hundred bytes of shape: long names and long lists are
/// shortened (a list says how many items it had), nesting stops at four levels.
fn cap_details(value: Value, depth: usize) -> Value {
    match value {
        Value::String(text) => clip_to(&text, DETAIL_TEXT).into(),
        Value::Array(items) if depth >= 4 => json!({"count": items.len()}),
        Value::Array(items) => {
            let total = items.len();
            let mut kept: Vec<Value> = items
                .into_iter()
                .take(DETAIL_ITEMS)
                .map(|item| cap_details(item, depth + 1))
                .collect();
            if total > DETAIL_ITEMS {
                kept.push(format!("... {} more", total - DETAIL_ITEMS).into());
            }
            kept.into()
        }
        Value::Object(map) if depth >= 4 => json!({"keys": map.len()}),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, cap_details(v, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

/// `text` cut to `max` characters, with an ellipsis.
fn clip_to(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// The tool that specializes in this kind of file, as overview `next_steps`
/// (first, before the generic drill-down).
fn specialist_steps(
    kind: &crate::mcp_server::tools_formats::FileKind,
    path: &Path,
    file_path: &str,
) -> Vec<Value> {
    let call = |tool: &str, why: &str| {
        json!({
            "tool": tool,
            "arguments": {"file_path": file_path},
            "why": why,
        })
    };
    let package = |tool: &str, why: &str| {
        json!({
            "tool": tool,
            "arguments": {"package_path": file_path},
            "why": why,
        })
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let mut steps = Vec::new();
    match kind.kind.as_str() {
        "pdf" | "ole2" | "ooxml" => steps.push(call(
            "analyze_document",
            "structure, macros, embedded objects and risk flags of this document",
        )),
        "script" => {
            if name == "setup.py" {
                steps.push(package(
                    "analyze_python_package",
                    "install-time hooks, dependencies and findings of this Python package",
                ));
            }
            steps.push(call(
                "analyze_script",
                "risky constructs, obfuscation and decoded payloads of this script",
            ));
            steps.push(json!({
                "tool": "analyze_file",
                "arguments": {"file_path": file_path, "sections": ["taint"]},
                "why": "sources of user-controlled data reaching dangerous calls (heuristic)",
            }));
        }
        "java-class" => steps.push(call(
            "analyze_java_file",
            "class structure, constant pool and risky API use",
        )),
        "jar" | "apk" => {
            steps.push(call(
                "inspect_archive",
                "list and filter the entries of the archive",
            ));
            steps.push(call(
                "analyze_java_file",
                "classes, manifest and risky API use",
            ));
        }
        "zip" | "gzip" | "tar" | "rar" | "7z" | "bzip2" | "xz" => {
            steps.push(call(
                "inspect_archive",
                "list and filter the entries of the archive",
            ));
            // A package is also an archive; the file name says which kind.
            if name.ends_with(".whl") || (kind.kind == "zip" && name.ends_with(".egg")) {
                steps.push(package(
                    "analyze_python_package",
                    "install-time hooks, dependencies and findings of this Python package",
                ));
            } else if name.ends_with(".tgz") || name.ends_with(".tar.gz") {
                steps.push(package(
                    "analyze_npm_package",
                    "if this is an npm package: lifecycle scripts, dependencies and findings",
                ));
                if name.ends_with(".tar.gz") {
                    steps.push(package(
                        "analyze_python_package",
                        "if this is a Python source distribution: install hooks and findings",
                    ));
                }
            }
        }
        "text" => {
            if matches!(name.as_str(), "package.json" | "package-lock.json") {
                steps.push(package(
                    "analyze_npm_package",
                    "lifecycle scripts, dependencies and findings of this npm package",
                ));
            } else if matches!(
                name.as_str(),
                "requirements.txt" | "poetry.lock" | "pyproject.toml" | "setup.py"
            ) {
                steps.push(package(
                    "analyze_python_package",
                    "install-time hooks, dependencies and findings of this Python package",
                ));
            }
        }
        _ => {}
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_analyzer_fails_its_section_not_the_call() {
        let failed = contain("disassembly", || -> Result<Value, Failure> {
            let bytes: Vec<u8> = Vec::new();
            Ok(Value::from(bytes[3]))
        });
        let Err(Failure::Error(message)) = failed else {
            panic!("expected a section error")
        };
        assert!(
            message.starts_with("the disassembly analyzer crashed"),
            "{message}"
        );
        assert!(contain("x", || Ok(Value::from(1))).is_ok());
    }
    /// The stored disassembly of a large, overlapping decode stays small: it
    /// used to be the whole result as JSON (gigabytes for a few megabytes).
    #[test]
    fn the_stored_disassembly_is_bounded() {
        use crate::disassembly::{
            ControlFlowSummary, DisassembledFunction, GraphVisualizationData, Instruction,
            InstructionAnalysis, InstructionType, OutputFormats,
        };
        let nop = |address: u64| Instruction {
            address,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
            instruction_type: InstructionType::Other,
            flow_control: None,
            size: 1,
        };
        let instructions: Vec<Instruction> = (0..200_000).map(nop).collect();
        // Fifty functions that all cover the same 100,000 instructions.
        let functions: Vec<DisassembledFunction> = (0..50)
            .map(|n| DisassembledFunction {
                address: n,
                name: format!("f{n}"),
                size: 100_000,
                instructions: instructions[..100_000].to_vec(),
                basic_blocks: Vec::new(),
                complexity: 1,
            })
            .collect();
        let result = DisassemblyResult {
            architecture: "x86_64".into(),
            analysis: InstructionAnalysis {
                total_instructions: instructions.len(),
                instruction_types: Default::default(),
                register_usage: Default::default(),
                memory_accesses: Vec::new(),
                system_calls: Vec::new(),
                crypto_operations: Vec::new(),
                suspicious_patterns: Vec::new(),
                control_flow_summary: ControlFlowSummary {
                    total_jumps: 0,
                    conditional_jumps: 0,
                    unconditional_jumps: 0,
                    function_calls: 0,
                    indirect_calls: 0,
                    returns: 0,
                    interrupts: 0,
                },
            },
            instructions,
            functions,
            output_formats: OutputFormats {
                assembly: String::new(),
                json_structured: Value::Null,
                graph_data: GraphVisualizationData {
                    nodes: Vec::new(),
                    edges: Vec::new(),
                },
            },
        };
        let value = bounded_disassembly(&result, None).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap().len();
        assert!(bytes < 16_000_000, "{bytes} bytes stored");
        assert!(value.get("output_formats").is_none());
        assert_eq!(value["instructions_total"], 200_000);
        assert_eq!(value["functions"].as_array().unwrap().len(), 50);
        // The function table keeps the true counts even where the
        // instructions are not stored.
        assert_eq!(value["functions"][49]["instruction_count"], 100_000);
        assert_eq!(
            value["functions"][49]["instructions"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let notes = value["notes"].to_string();
        assert!(
            notes.contains("not stored") && notes.contains("decodes"),
            "{notes}"
        );
    }

    /// A note about a limit is kept whole up to a few hundred bytes and is cut
    /// at a sentence boundary beyond that.
    #[test]
    fn limit_notes_are_not_clipped_at_the_string_limit() {
        let note = "Limit: 3817 of 5817 functions were not analyzed because the analysis stops \
                    after 2000 functions. Ask for one function by name to see the rest of them, or raise the limit in the \
                    analyzer settings and repeat the call to cover every function of the file.";
        assert!(note.len() > CLIP);
        let summary = digest(&json!({"notes": [note], "name": "x".repeat(400)}), 0);
        assert_eq!(summary["notes"][0], note);
        assert!(summary["name"].as_str().unwrap().len() < 200);
        let long = format!("{}. {}", "a".repeat(400), "b".repeat(400));
        let cut = clip_note(&long);
        assert!(cut.len() <= NOTE_LIMIT + 4 && cut.ends_with('…'), "{cut}");
    }

    #[test]
    fn arch_values_are_normalized_and_bounded() {
        assert_eq!(arch_option(Some(" ARM64E ")).as_deref(), Some("arm64e"));
        assert_eq!(arch_option(Some("   ")), None);
        let long = "A".repeat(200_000);
        assert_eq!(arch_option(Some(&long)).unwrap().len(), ARCH_MAX);
        assert_eq!(arch_option(Some("x86 64;rm")).as_deref(), Some("x8664rm"));
    }

    /// Fifty graphs of 1,000 blocks of 10 instructions each: the stored
    /// control-flow section keeps true counts and bounded lists, and says so.
    #[test]
    fn the_stored_control_flow_is_bounded() {
        use crate::control_flow::{
            AnalysisStats, BasicBlock, BlockType, CfgEdge, ControlFlowGraph, ControlFlowMetrics,
            EdgeType, FlowControl, Instruction, InstructionType, OverallMetrics,
        };
        let instruction = |address: u64| Instruction {
            address,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
            instruction_type: InstructionType::Nop,
            flow_control: FlowControl::Fall,
            size: 1,
        };
        let blocks: Vec<BasicBlock> = (0..1000)
            .map(|id| BasicBlock {
                id,
                start_address: id as u64 * 10,
                end_address: id as u64 * 10 + 9,
                instructions: (0..10).map(|n| instruction(id as u64 * 10 + n)).collect(),
                successors: vec![id + 1],
                predecessors: Vec::new(),
                block_type: BlockType::Normal,
                instruction_count: 10,
            })
            .collect();
        let edges: Vec<CfgEdge> = (0..1000)
            .map(|from| CfgEdge {
                from_block: from,
                to_block: from + 1,
                edge_type: EdgeType::Fall,
            })
            .collect();
        let cfgs: Vec<ControlFlowGraph> = (0..50)
            .map(|n| ControlFlowGraph {
                function_address: n,
                function_name: format!("f{n}"),
                basic_blocks: blocks.clone(),
                edges: edges.clone(),
                entry_block: 0,
                exit_blocks: vec![999],
                loops: Vec::new(),
                complexity: ControlFlowMetrics {
                    cyclomatic_complexity: 1,
                    cognitive_complexity: 0,
                    nesting_depth: 0,
                    basic_block_count: 1000,
                    edge_count: 1000,
                    loop_count: 0,
                    unreachable_blocks: Vec::new(),
                },
            })
            .collect();
        let flow = ControlFlowAnalysis {
            cfgs,
            overall_metrics: OverallMetrics {
                total_functions: 50,
                analyzed_functions: 50,
                total_basic_blocks: 50_000,
                average_complexity: 1.0,
                max_complexity: 1,
                function_with_max_complexity: Some("f0".into()),
            },
            analysis_stats: AnalysisStats {
                analysis_duration: 1,
                bytes_analyzed: 500_000,
                instructions_analyzed: 500_000,
                errors: vec!["one analyzer error".into()],
            },
        };
        let value = bounded_control_flow(&flow).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap().len();
        assert!(bytes < 16_000_000, "{bytes} bytes stored");
        let cfgs = value["cfgs"].as_array().unwrap();
        assert_eq!(cfgs.len(), 50);
        assert_eq!(cfgs[49]["basic_blocks_count"], 1000);
        assert_eq!(cfgs[49]["basic_blocks"].as_array().unwrap().len(), 0);
        assert_eq!(cfgs[0]["basic_blocks"].as_array().unwrap().len(), 1000);
        assert_eq!(value["analysis_stats"]["errors"][0], "one analyzer error");
        assert_eq!(value["overall_metrics"]["total_basic_blocks"], 50_000);
        let notes = value["notes"].to_string();
        assert!(
            notes.contains("Limit") && notes.contains("basic blocks"),
            "{notes}"
        );
    }
}
