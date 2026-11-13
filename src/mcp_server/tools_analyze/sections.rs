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
    call_graph::{generate_call_graph_with_arch, summarize_call_graph},
    code_metrics::analyze_code_quality,
    control_flow::{analyze_control_flow_with_arch, BlockType, ControlFlowAnalysis},
    dependency_analysis::analyze_dependencies,
    disassembly::FlowControl,
    disassembly::{disassemble_binary_with_arch, DisassemblyCoverage, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols_with_arch, SymbolTable},
    hash::{calculate_all_hashes, Hashes},
    hexdump::{generate_hex_dump, HexDumpOptions},
    mcp_server::{
        state::{mark_section, SectionCache},
        tools_formats::{detect_file_kind, format_overview},
    },
    metadata::FileMetadata,
    signature::{verify_signature, verify_signature_with},
    strings::{scan_strings, StringScan},
    taint_tracking::taint_report_for_path,
    threat_detection::{analyze_threats, analyze_threats_enhanced},
    vulnerability_detection::analyze_vulnerabilities_with_arch,
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
/// letters, digits, spaces and `_ . - ( )` (so a slice name as the overview
/// prints it, `ARM64 (subtype 12)`, is accepted), at most [`ARCH_MAX`]
/// characters (it is echoed in a note and is part of the cache key, so
/// `ARM64E` and `arm64e` are one).
pub(super) fn arch_option(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .map(|a| {
            a.chars()
                .filter(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | ' ' | '(' | ')')
                })
                .take(ARCH_MAX)
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|a| !a.is_empty())
}

/// A slice's architecture as `arch` accepts it and the overview prints it:
/// lowercase and without spaces or parentheses (`ARM64 (subtype 12)` is
/// `arm64-subtype-12`). The old spelling is still accepted.
pub(super) fn slice_name(architecture: &str) -> String {
    let lower = architecture.to_ascii_lowercase();
    match lower
        .strip_prefix("arm64 (subtype ")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        Some(n) => format!("arm64-subtype-{n}"),
        None => lower.replace(' ', "-"),
    }
}

/// `arch` or a slice name with the characters that do not matter removed.
fn arch_key(name: &str) -> String {
    name.to_ascii_lowercase()
        .replace(['-', '_', ' ', '(', ')'], "")
}

/// The slice of a universal Mach-O that `arch` names, as the name the parser
/// matches. Beyond the exact names (see [`slice_name`]) `arm64` names the one
/// ARM64-family slice when the file has exactly one. A file that is not
/// universal, or a name that matches nothing (or several slices), is returned
/// as it is: [`check_arch`] answers for it.
pub(super) fn resolve_arch(path: &Path, arch: Option<String>) -> Option<String> {
    let wanted = arch?;
    let resolved = (|| {
        use std::io::Read;
        let mut file = std::fs::File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        let mut header = Vec::new();
        file.by_ref().take(4096).read_to_end(&mut header).ok()?;
        let slices = crate::binary_parser::fat_slice_table(&header, len, |_| false)?;
        let key = arch_key(&wanted);
        let exact = slices.iter().find(|s| {
            let have = arch_key(&s.architecture);
            have == key
                || (key == "aarch64" && have == "arm64")
                || (key == "amd64" && have == "x8664")
        });
        let chosen = exact.or_else(|| {
            if !matches!(key.as_str(), "arm64" | "aarch64") {
                return None;
            }
            let mut family = slices
                .iter()
                .filter(|s| s.architecture.to_ascii_lowercase().starts_with("arm64"));
            match (family.next(), family.next()) {
                (Some(one), None) => Some(one),
                _ => None,
            }
        })?;
        Some(chosen.architecture.to_ascii_lowercase())
    })();
    Some(resolved.unwrap_or(wanted))
}

/// `arguments` with the caller's `arch` carried over, so a next step lands on
/// the slice the call was about.
pub(super) fn with_arch(mut arguments: Value, arch: Option<&str>) -> Value {
    if let (Some(arch), Some(map)) = (arch.filter(|a| !a.is_empty()), arguments.as_object_mut()) {
        // The parser's slice name (`arm64 (subtype 12)`) is written the way
        // the overview and every other step spell it.
        let arch = if arch.starts_with("arm64 (subtype ") {
            slice_name(arch)
        } else {
            arch.to_string()
        };
        map.insert("arch".into(), arch.into());
    }
    arguments
}

/// One section to produce and the key it is cached under.
#[derive(Debug, Clone)]
pub(super) struct Planned {
    pub name: &'static str,
    pub key: String,
    /// False when the answer depends on something the key cannot capture (the
    /// detached signature files next to this path, the user's keyring): the
    /// section is then computed on every call and neither read from nor
    /// written to the cache.
    pub cacheable: bool,
}

/// Revision of the stored `threats` and `enhanced_threats` sections. Bump it
/// whenever the built-in rules or the weak-evidence logic change.
const THREATS_REVISION: u32 = 3;

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
        "dependencies" | "behavioral" => format!("{name}:min={}{arch}", options.min),
        // Reads the imports and sections of `binary_info`, so it depends on the
        // name's class too.
        "yara_indicators" => format!(
            "yara_indicators:min={}{arch}:name={}",
            options.min,
            name_class(path)
        ),
        // Bump THREATS_REVISION whenever the built-in rules or the weak-evidence
        // logic change, so ratings stored by an earlier build are not served.
        "threats" => format!("threats:basic:r{THREATS_REVISION}"),
        "enhanced_threats" => format!("threats:enhanced:r{THREATS_REVISION}"),
        // Revision 2: answers stored under the bare name by an earlier build did
        // not know about detached signature files.
        "signatures" => "signatures:r2".to_string(),
        // The parser routes a file by the class of its name (a Java archive
        // or class name is read as one, whatever the bytes are).
        "binary_info" => format!("binary_info{arch}:name={}", name_class(path)),
        // Everything built from the symbol table or the parsed binary.
        "symbols" | "control_flow" | "vulnerabilities" | "code_quality" | "disassembly"
        | "call_graph" => format!("{name}{arch}"),
        // The sources and sinks rows carry the analyzed path in their
        // locations, so the answer is stored per path.
        "taint" => format!("taint:{path}"),
        other => other.to_string(),
    };
    // A detached signature next to this path is read by the check but is not
    // part of the file's SHA-256, so the shared answer is only valid when there
    // is none.
    let cacheable = name != "signatures" || !has_detached_signature(Path::new(path));
    Planned {
        name,
        key,
        cacheable,
    }
}

/// How `binary_parser::parse_binary_buffer` classifies a file by its name:
/// `.jar`, `.war`, `.ear`, `.apk` and `.aar` are read as Java archives,
/// `.class` as a Java class file, any other name by its content alone. Two
/// names of one class never differ in the answer; a cached answer is shared
/// only inside a class.
fn name_class(path: &str) -> &'static str {
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match extension.as_str() {
        "jar" | "war" | "ear" | "apk" | "aar" => "java-archive",
        "class" => "java-class",
        _ => "content",
    }
}

/// Whether a detached signature file (`<file>.sig`, `<file>.asc`) exists for
/// `path`. An entry that cannot be inspected counts as present.
fn has_detached_signature(path: &Path) -> bool {
    crate::signature::detached_signature_candidates(path)
        .iter()
        .any(|candidate| match std::fs::symlink_metadata(candidate) {
            Ok(_) => true,
            Err(error) => error.kind() != std::io::ErrorKind::NotFound,
        })
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
    /// The roots policy of the call this context was built in (none: the
    /// command line or a test), for paths derived from `path`.
    policy: Option<crate::mcp_server::paths::PathPolicy>,
}

impl<'a> Ctx<'a> {
    /// `policy` is the roots policy of the server call this context serves, or
    /// `None` on purpose where there is no server (the command line, a test):
    /// a detached signature link is then followed as the command-line scanner
    /// does. A server path passes `Some(state.path_policy())`.
    pub(super) fn new(
        path: &'a Path,
        runtime: &'a tokio::runtime::Handle,
        options: Options,
        policy: Option<crate::mcp_server::paths::PathPolicy>,
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
            policy,
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
        let arch = self.options.arch.clone();
        self.control_flow
            .get_or_insert_with(|| {
                mark_section("control_flow");
                analyze_control_flow_with_arch(path, arch.as_deref(), &symbols)
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .clone()
    }

    fn disassembly(&mut self) -> Result<Arc<DisassemblyResult>, String> {
        if let Some(done) = &self.disassembly {
            return done.clone();
        }
        let arch = self.options.arch.clone();
        let outcome = self.symbols().and_then(|symbols| {
            mark_section("disassembly");
            disassemble_binary_with_arch(self.path, arch.as_deref(), &symbols)
                .map_err(|e| format!("{e:#}"))
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

    /// The signatures section: a detached signature file beside the path is
    /// read only when the roots policy of the call allows where it resolves.
    fn verify_signature(&self) -> anyhow::Result<crate::signature::SignatureInfo> {
        match &self.policy {
            Some(policy) => {
                verify_signature_with(self.path, &|candidate| policy.side_file(candidate))
            }
            None => verify_signature(self.path),
        }
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
            "signatures" => match self.verify_signature() {
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
                let value = to_value(
                    &analyze_vulnerabilities_with_arch(
                        path,
                        self.options.arch.as_deref(),
                        &symbols,
                        &flow,
                    )
                    .map_err(error)?,
                )?;
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
        let graph = generate_call_graph_with_arch(
            self.path,
            self.options.arch.as_deref(),
            &disassembly,
            &symbols,
        )
        .map_err(error)?;
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
/// (vulnerabilities, code quality). A limit that left functions or
/// instructions out says the section was "built on a partial control-flow
/// analysis"; one that only shortened a listed set (loops, exit blocks,
/// unreachable blocks: the counts stay complete) is passed on as it is.
fn partial_flow_notes(flow: &ControlFlowAnalysis) -> Vec<String> {
    flow.analysis_stats
        .errors
        .iter()
        .filter(|e| e.starts_with("Limit"))
        .map(|e| {
            if e.starts_with("Limit: the lists of ") {
                e.clone()
            } else {
                format!("built on a partial control-flow analysis. {e}")
            }
        })
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
/// Entries kept in all, over every function, of each of: loops (a loop and its
/// block lists count by their entries), exit blocks, unreachable blocks, and
/// the successor and predecessor lists of the kept blocks.
const STORED_CFG_LISTS: usize = 20_000;

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
    let mut loops_left = STORED_CFG_LISTS;
    let mut exits_left = STORED_CFG_LISTS;
    let mut unreachable_left = STORED_CFG_LISTS;
    let mut links_left = STORED_CFG_LISTS;
    let mut cut_loops = 0usize;
    let mut cut_exits = 0usize;
    let mut cut_unreachable = 0usize;
    let mut cut_links = 0usize;
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
            let links = b.successors.len() + b.predecessors.len();
            let (successors, predecessors): (&[usize], &[usize]) = if links <= links_left {
                links_left -= links;
                (&b.successors, &b.predecessors)
            } else {
                cut_links += links;
                (&[], &[])
            };
            let row = json!({
                "id": b.id,
                "start_address": b.start_address,
                "end_address": b.end_address,
                "successors": successors,
                "successors_count": b.successors.len(),
                "predecessors": predecessors,
                "predecessors_count": b.predecessors.len(),
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
        let keep_exits = cfg.exit_blocks.len().min(exits_left);
        exits_left -= keep_exits;
        cut_exits += cfg.exit_blocks.len() - keep_exits;
        let mut loops: Vec<Value> = Vec::new();
        for l in &cfg.loops {
            let cost = 1 + l.body_blocks.len() + l.exit_blocks.len();
            if cost > loops_left {
                break;
            }
            loops_left -= cost;
            loops.push(to_value(l)?);
        }
        cut_loops += cfg.loops.len() - loops.len();
        let keep_unreachable = cfg
            .complexity
            .unreachable_blocks
            .len()
            .min(unreachable_left);
        unreachable_left -= keep_unreachable;
        cut_unreachable += cfg.complexity.unreachable_blocks.len() - keep_unreachable;
        // The analysis cuts these lists across all functions, so their lengths
        // are not the counts: the loop count is kept whole in `complexity`, and
        // every exit block is a block of type Return or Exit.
        let loops_total = cfg.complexity.loop_count.max(cfg.loops.len());
        let exit_blocks_total = cfg
            .basic_blocks
            .iter()
            .filter(|b| matches!(b.block_type, BlockType::Return | BlockType::Exit))
            .count()
            .max(cfg.exit_blocks.len());
        let mut complexity_cut = cfg.complexity.clone();
        complexity_cut.unreachable_blocks.truncate(keep_unreachable);
        cfgs.push(json!({
            "function_address": cfg.function_address,
            "function_name": cfg.function_name,
            "basic_blocks": blocks,
            "basic_blocks_count": cfg.basic_blocks.len(),
            "edges": edges,
            "edges_count": cfg.edges.len(),
            "entry_block": cfg.entry_block,
            "exit_blocks": &cfg.exit_blocks[..keep_exits],
            "exit_blocks_count": exit_blocks_total,
            "loops": loops,
            "loops_count": loops_total,
            "complexity": to_value(&complexity_cut)?,
            "unreachable_blocks_count": cfg.complexity.unreachable_blocks.len(),
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
    for (cut, what, counted) in [
        (
            cut_loops,
            "loops (counting their block lists)",
            "loops_count",
        ),
        (cut_exits, "exit blocks", "exit_blocks_count"),
        (
            cut_unreachable,
            "unreachable blocks",
            "unreachable_blocks_count",
        ),
        (
            cut_links,
            "successor and predecessor entries",
            "successors_count and predecessors_count",
        ),
    ] {
        if cut > 0 {
            notes.push(format!(
                "Limit: the stored section keeps {STORED_CFG_LISTS} {what} in all; {cut} \
                 of later functions are counted ({counted}) but not listed."
            ));
        }
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
        if planned.cacheable {
            if let Some(hit) = self.cache.get(self.sha, &planned.key) {
                self.cached += 1;
                return Ok(hit);
            }
        }
        // An analyzer that panics on a malformed sample fails its own section,
        // not the whole call.
        let ctx = &mut self.ctx;
        let name = planned.name;
        let value = contain(name, || ctx.compute(name))?;
        self.computed += 1;
        if !planned.cacheable {
            return Ok(Arc::new(value));
        }
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

/// What the analyzer said about a cut or a limit in section `name` (kept and
/// real counts), which `query_analysis` carries on every page: a client that
/// pages a list to its end must learn that the list is partial.
pub(super) fn limit_notes(name: &str, section: &Value) -> Vec<String> {
    let lines = |pointer: &str| -> Vec<String> {
        section
            .pointer(pointer)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    // Each note is a sentence of its own, as the notes are joined into one.
    let sentence = |note: String| -> String {
        let mut chars = note.chars();
        let mut text: String = chars
            .next()
            .map(|c| c.to_uppercase().chain(chars).collect())
            .unwrap_or_default();
        if !text.ends_with(['.', '!', '?']) {
            text.push('.');
        }
        text
    };
    let notes: Vec<String> = match name {
        "control_flow" => lines("/notes")
            .into_iter()
            .filter(|n| n.starts_with("Limit"))
            .collect(),
        "call_graph" | "code_quality" => lines("/notes"),
        "disassembly" => {
            // The instruction cap has its own note beside the page.
            let mut notes: Vec<String> = lines("/notes")
                .into_iter()
                .filter(|n| !n.contains("flat instruction list"))
                .collect();
            notes.extend(
                lines("/coverage/notes")
                    .into_iter()
                    .filter(|n| n.contains("not listed")),
            );
            notes
        }
        _ => Vec::new(),
    };
    notes.into_iter().map(sentence).collect()
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
                    // A list the section stores cut (loops, exit blocks ...)
                    // next to its true `<name>_count` keeps that count: the
                    // length of the kept part would contradict it.
                    Value::Array(_)
                        if map
                            .get(&format!("{key}_count"))
                            .is_some_and(Value::is_number) => {}
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
pub(super) fn drill_down(
    name: &str,
    file_path: &str,
    section: &Value,
    arch: Option<&str>,
) -> Option<Value> {
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
        "arguments": with_arch(arguments, arch),
        "gives": format!(
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
        // The first function the section lists, else the first instruction.
        let target = section
            .pointer("/functions/0/name")
            .and_then(Value::as_str)
            .map(|n| json!({"function": n}))
            .or_else(|| {
                section
                    .get("instructions_first_address")
                    .and_then(Value::as_u64)
                    .map(|a| json!({"address": format!("0x{a:x}")}))
            });
        if let Some(Value::Object(target)) = target {
            let mut arguments = Map::new();
            arguments.insert("file_path".into(), file_path.into());
            arguments.extend(target);
            let arguments = Value::Object(arguments);
            step["then"] = json!({
                "tool": "disassemble",
                "arguments": with_arch(arguments, arch),
                "gives": "the instruction listing of one function (200 instructions by default); \
                          name another from the functions list",
            });
        }
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
    let mut kind = detect_file_kind(path).ok();
    // A .war or .ear without a manifest or class entries reads as a plain zip
    // to the detector; the name says what it is.
    if let Some(k) = kind.as_mut().filter(|k| k.kind == "zip") {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(ext.as_str(), "war" | "ear" | "aar") {
            *k = java_archive_kind(&ext);
        }
    }
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
    // What the code analyses need to know about the file's architecture.
    let mut code_arch: Option<String> = None;
    let mut x86_slice: Option<String> = None;
    let mut imports_in_info: Option<usize> = None;
    let binary_info = if heavy {
        Err(Failure::NotApplicable(String::new()))
    } else {
        load(engine, "binary_info")
    };
    match binary_info {
        Err(Failure::NotApplicable(m)) if m.is_empty() => {}
        Ok(info) => {
            // A file that parses only as "Raw" has no executable structure.
            let parsed_format = info.get("format").and_then(Value::as_str);
            binary_ok = !matches!(parsed_format, Some("Raw" | "Unknown") | None);
            // A zip the parser reads as a Java archive (WEB-INF/ entries, a
            // manifest) is one for the overview too, not native code.
            if let Some(ext) = parsed_format.and_then(|f| match f {
                "WAR" => Some("war"),
                "EAR" => Some("ear"),
                "JAR" | "AAR" | "APK" | "Java Archive" => Some("jar"),
                _ => None,
            }) {
                if let Some(k) = kind.as_mut().filter(|k| k.kind == "zip") {
                    *k = java_archive_kind(ext);
                    out.insert("type".into(), k.label.clone().into());
                    out.insert("kind".into(), k.kind.clone().into());
                    out.insert("mime".into(), k.mime.clone().into());
                }
            }
            // An archive has no native code, whatever the parser made of it.
            if kind.as_ref().is_some_and(|k| is_archive_kind(&k.kind)) {
                binary_ok = false;
            }
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
            imports_in_info = info.get("imports").and_then(Value::as_array).map(Vec::len);
            code_arch = info
                .get("architecture")
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(slices) = info.get("universal_slices").and_then(Value::as_array) {
                let names: Vec<&str> = slices
                    .iter()
                    .filter_map(|s| s.get("architecture").and_then(Value::as_str))
                    .collect();
                x86_slice = names
                    .iter()
                    .find(|n| n.to_ascii_lowercase().contains("x86"))
                    .map(|n| slice_name(n));
                // The slices as `arch` accepts them (the detected type names
                // the CPU types only, so two ARM64 slices read alike there).
                out.insert(
                    "type".into(),
                    format!(
                        "Mach-O universal binary ({} slice{}: {})",
                        names.len(),
                        if names.len() == 1 { "" } else { "s" },
                        names
                            .iter()
                            .map(|n| slice_name(n))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .into(),
                );
                if let Some(selected) = info.get("analyzed_slice").and_then(Value::as_str) {
                    format["analyzed_slice"] = slice_name(selected).into();
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
    // A Java archive or class file has no symbol table to read: asking would
    // only add a note about an analysis no step offers.
    let java_kind = kind
        .as_ref()
        .is_some_and(|k| matches!(k.kind.as_str(), "jar" | "apk" | "java-class"));
    if binary_ok && !heavy && !java_kind {
        match load(engine, "symbols") {
            Ok(symbols) => {
                if let Some(items) = symbols.get("functions").and_then(Value::as_array) {
                    counts.insert("functions".into(), items.len().into());
                }
                // One count of the imports: the one `format.imports_count`
                // carries (the symbol table lists fewer on an ELF).
                let imported = imports_in_info.or_else(|| {
                    symbols
                        .get("imports")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                });
                if let Some(imported) = imported {
                    counts.insert("imported_symbols".into(), imported.into());
                }
                if let Some(exports) = symbols.get("exports").and_then(Value::as_array) {
                    counts.insert("exported_symbols".into(), exports.len().into());
                }
            }
            Err(failure) => record("symbols", &failure),
        }
    }
    out.insert("counts".into(), Value::Object(counts));

    // A file too big to parse may be native code; an archive is not.
    let archive_kind = kind.as_ref().is_some_and(|k| is_archive_kind(&k.kind));
    let mut binary_ok = (binary_ok || heavy) && !archive_kind;
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
    // A Java archive or class file has no native code to analyze, whatever the
    // parser made of it.
    if matches!(kind_name, "jar" | "apk" | "java-class") {
        binary_ok = false;
    }
    if binary_ok {
        available.extend([
            "binary_info",
            "signatures",
            "symbols",
            "dependencies",
            "entropy",
        ]);
        // The control-flow analyses read x86 and x86-64 code only.
        let non_x86 = code_arch.as_deref().filter(|a| is_non_x86(a));
        for name in ["control_flow", "vulnerabilities", "code_quality"] {
            match non_x86 {
                Some(arch) => {
                    not_available.insert(
                        name.to_string(),
                        format!(
                            "control-flow analysis and the analyses built on it read x86 and \
                             x86-64 code only; this file's code is {arch}. `disassemble` reads \
                             it{}",
                            x86_slice
                                .as_deref()
                                .map_or_else(String::new, |slice| format!(
                                    ", and the x86 slice of this universal binary is analyzable: \
                                 pass `arch: \"{slice}\"`"
                                ))
                        )
                        .into(),
                    );
                }
                None => available.push(name),
            }
        }
        available.extend(["disassembly", "call_graph"]);
    } else {
        available.extend(["signatures", "entropy"]);
        let why = if kind_name == "java-class" {
            "a Java class file has no native code; analyze_java_file reads it"
        } else {
            "this file is not a recognized executable (PE, ELF, Mach-O, Java class)"
        };
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
    // The archive probe of the overview itself failed: listing would fail too.
    let archive_unreadable = out
        .get("format_details")
        .and_then(|d| d.get("archive"))
        .is_some_and(|a| a.get("error").is_some());
    let mut steps: Vec<Value> = kind
        .as_ref()
        .filter(|_| kind_is_known)
        .map(|k| specialist_steps(k, path, file_path, archive_unreadable))
        .unwrap_or_default();
    // Sections that suit this kind of file, all of them in `available_sections`.
    let suggested: Vec<&str> = if binary_ok {
        ["symbols", "threats"]
    } else {
        ["threats", "behavioral"]
    }
    .into_iter()
    .filter(|name| available.contains(name))
    .collect();
    steps.push(json!({
        "tool": "analyze_file",
        "arguments": with_arch(
            json!({"file_path": file_path, "sections": suggested}),
            options.arch.as_deref(),
        ),
        "gives": "a summary of each named section (headline numbers, top few items, totals); \
                  swap in any of available_sections; the full section is cached for query_analysis",
    }));
    let mut string_arguments = json!({"file_path": file_path, "section": "strings"});
    if let Some(category) = strings.as_deref().and_then(top_category) {
        string_arguments["category"] = category.into();
    }
    steps.push(json!({
        "tool": "query_analysis",
        "arguments": with_arch(string_arguments, options.arch.as_deref()),
        "gives": "page and filter every string (filter, category, encoding, offset, limit)",
    }));
    if binary_ok && imports_in_info != Some(0) {
        // The list the count above is taken from.
        steps.push(json!({
            "tool": "query_analysis",
            "arguments": with_arch(
                json!({"file_path": file_path, "section": "binary_info", "list": "imports"}),
                options.arch.as_deref(),
            ),
            "gives": "page the imported symbols",
        }));
    }
    if binary_ok {
        steps.push(json!({
            "tool": "disassemble",
            "arguments": with_arch(json!({"file_path": file_path}), options.arch.as_deref()),
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

/// Whether slice or architecture name `have` is what `wanted` names (case and
/// `- _ space` do not matter; `aarch64` is `arm64`, `amd64` is `x86_64`).
fn arch_matches(have: &str, wanted: &str) -> bool {
    let (have, wanted) = (arch_key(have), arch_key(wanted));
    have == wanted
        || (wanted == "aarch64" && have == "arm64")
        || (wanted == "amd64" && have == "x8664")
}

/// An `arch` the file does not have is an error that names what it has: the
/// slices of a universal Mach-O, or the one architecture of a thin binary. A
/// file that is not a recognized executable has no architecture to name and
/// passes (the overview notes that `arch` was ignored).
pub(super) fn check_arch(
    engine: &mut Engine<'_>,
    options: &Options,
    file_path: &str,
    mtime_ns: u128,
) -> Result<(), String> {
    let Some(arch) = options.arch.as_deref() else {
        return Ok(());
    };
    let Ok(info) = engine.load(&plan("binary_info", options, file_path, mtime_ns)) else {
        return Ok(());
    };
    if let Some(slices) = info.get("universal_slices").and_then(Value::as_array) {
        let names: Vec<&str> = slices
            .iter()
            .filter_map(|s| s.get("architecture").and_then(Value::as_str))
            .collect();
        if names.iter().any(|n| arch_matches(n, arch)) {
            return Ok(());
        }
        let shown: Vec<String> = names.iter().map(|n| slice_name(n)).collect();
        return Err(format!(
            "arch '{arch}' is not a slice of this universal (fat) Mach-O, or names more than one \
             of them. Its slices: {}. Pass one of them, or leave `arch` out for the host's slice \
             (else the first).",
            shown.join(", ")
        ));
    }
    // Only a native executable with a named architecture can contradict `arch`;
    // text, archives, jars and other raw files just get the "ignored" note.
    let native = info.get("format").and_then(Value::as_str).is_some_and(|f| {
        let f = f.to_ascii_lowercase();
        f.contains("elf") || f.starts_with("pe") || f.contains("mach")
    });
    match info.get("architecture").and_then(Value::as_str) {
        Some(have)
            if native
                && !have.is_empty()
                && !have.eq_ignore_ascii_case("unknown")
                && !have.eq_ignore_ascii_case("universal")
                && !arch_matches(have, arch) =>
        {
            Err(format!(
                "arch '{arch}' does not match this file, a single-architecture binary ({have}); \
             `arch` only picks a slice of a universal (fat) Mach-O. Leave it out, or pass \
             '{have}'."
            ))
        }
        _ => Ok(()),
    }
}

/// What happened to the `arch` argument when it changed nothing the caller
/// would expect: a file that is not a universal Mach-O has no slices, so the
/// (matching) name was ignored. A name the file lacks is refused by
/// [`check_arch`] before this runs.
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
    info.get("universal_slices")
        .and_then(Value::as_array)
        .is_none()
        .then(|| {
            format!(
                "arch '{arch}' was ignored: only a universal (fat) Mach-O has architecture \
                 slices, and this file is not one."
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

/// Whether `architecture` is one the control-flow analyses cannot read.
fn is_non_x86(architecture: &str) -> bool {
    let a = architecture.to_ascii_lowercase();
    !a.contains("x86")
        && [
            "arm", "aarch", "riscv", "mips", "powerpc", "ppc", "sparc", "s390", "loong",
        ]
        .iter()
        .any(|family| a.contains(family))
}

/// Whether a detected kind is a plain archive (never native code).
fn is_archive_kind(kind: &str) -> bool {
    matches!(kind, "zip" | "gzip" | "tar" | "rar" | "7z" | "bzip2" | "xz")
}

/// The kind of a Java archive named by its extension (`war`, `ear`, `aar`).
fn java_archive_kind(ext: &str) -> crate::mcp_server::tools_formats::FileKind {
    let label = match ext {
        "war" => "Java web application archive (WAR)",
        "ear" => "Java enterprise archive (EAR)",
        "aar" => "Java Android library (AAR)",
        _ => "Java archive (JAR)",
    };
    crate::mcp_server::tools_formats::FileKind {
        kind: "jar".into(),
        label: label.into(),
        mime: "application/java-archive".into(),
    }
}

/// Languages `analyze_script` has rules for, as the overview's type label
/// spells them.
const ANALYZE_SCRIPT_LANGUAGES: [&str; 6] = [
    "Shell",
    "PowerShell",
    "JavaScript",
    "Python",
    "Batch",
    "VBScript",
];

/// The tool that specializes in this kind of file, as overview `next_steps`
/// (first, before the generic drill-down).
fn specialist_steps(
    kind: &crate::mcp_server::tools_formats::FileKind,
    path: &Path,
    file_path: &str,
    archive_unreadable: bool,
) -> Vec<Value> {
    let call = |tool: &str, gives: &str| {
        json!({
            "tool": tool,
            "arguments": {"file_path": file_path},
            "gives": gives,
        })
    };
    let package = |tool: &str, gives: &str| {
        json!({
            "tool": tool,
            "arguments": {"package_path": file_path},
            "gives": gives,
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
            // analyze_script refuses a language it has no rules for (Perl, Ruby,
            // PHP, Lua, AWK); the label starts with the language name.
            if ANALYZE_SCRIPT_LANGUAGES
                .iter()
                .any(|language| kind.label.starts_with(&format!("{language} script")))
            {
                steps.push(call(
                    "analyze_script",
                    "risky constructs, obfuscation and decoded payloads of this script",
                ));
            }
            steps.push(json!({
                "tool": "analyze_file",
                "arguments": {"file_path": file_path, "sections": ["taint"]},
                "gives": "sources of user-controlled data reaching dangerous calls (heuristic)",
            }));
        }
        "java-class" => steps.push(call(
            "analyze_java_file",
            "class structure, constant pool and risky API use",
        )),
        "jar" | "apk" => {
            if !archive_unreadable {
                steps.push(call(
                    "inspect_archive",
                    "list and filter the entries of the archive",
                ));
            }
            steps.push(call(
                "analyze_java_file",
                "classes, manifest and risky API use",
            ));
        }
        // A gzip stream that holds no tar is compressed data, not a listable archive.
        "gzip" if !kind.label.contains("tar") => {}
        "zip" | "gzip" | "tar" | "rar" | "7z" | "bzip2" | "xz" => {
            if !archive_unreadable {
                steps.push(call(
                    "inspect_archive",
                    "list and filter the entries of the archive",
                ));
            }
            // A package is also an archive; the file name says which kind.
            if name.ends_with(".whl") || (kind.kind == "zip" && name.ends_with(".egg")) {
                steps.push(package(
                    "analyze_python_package",
                    "install-time hooks, dependencies and findings of this Python package",
                ));
            } else if name.ends_with(".tgz") || name.ends_with(".tar.gz") {
                steps.push(package(
                    "analyze_npm_package",
                    "lifecycle scripts, dependencies and findings of an npm package; errors when this \
                         archive is not an npm package (no package.json)",
                ));
                // A Python sdist is a .tar.gz or a .tgz.
                steps.push(package(
                    "analyze_python_package",
                    "install hooks and findings of a Python source distribution; errors when this \
                         archive is not a Python package (no setup.py, pyproject.toml or PKG-INFO)",
                ));
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
        assert_eq!(arch_option(Some("x86 64;rm")).as_deref(), Some("x86 64rm"));
        assert_eq!(
            arch_option(Some("ARM64 (subtype 12)")).as_deref(),
            Some("arm64 (subtype 12)")
        );
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
        let mut flow = flow;
        flow.cfgs[0].exit_blocks = (0..30_000).collect();
        flow.cfgs[0].complexity.unreachable_blocks = (0..30_000).collect();
        flow.cfgs[0].loops = (0..30_000)
            .map(|n| crate::control_flow::Loop {
                header_block: n,
                body_blocks: vec![n],
                exit_blocks: Vec::new(),
                loop_type: crate::control_flow::LoopType::Natural,
                nesting_level: 0,
            })
            .collect();
        let value = bounded_control_flow(&flow).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap().len();
        assert!(bytes < 16_000_000, "{bytes} bytes stored");
        let first = &value["cfgs"][0];
        assert_eq!(first["exit_blocks_count"], 30_000);
        assert_eq!(first["exit_blocks"].as_array().unwrap().len(), 20_000);
        assert_eq!(first["unreachable_blocks_count"], 30_000);
        assert_eq!(
            first["complexity"]["unreachable_blocks"]
                .as_array()
                .unwrap()
                .len(),
            20_000
        );
        assert_eq!(first["loops_count"], 30_000);
        assert_eq!(first["loops"].as_array().unwrap().len(), 10_000);
        assert_eq!(first["basic_blocks"][0]["successors_count"], 1);
        let all = value["notes"].to_string();
        assert!(
            all.contains("exit blocks") && all.contains("loops"),
            "{all}"
        );
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

    /// A graph whose loop and exit lists were cut by the analysis keeps its
    /// true counts in the stored row and in the brief row a query shows.
    #[test]
    fn counts_come_from_the_metrics_and_block_types_not_from_cut_lists() {
        use crate::control_flow::{
            AnalysisStats, BasicBlock, ControlFlowGraph, ControlFlowMetrics, Loop, LoopType,
            OverallMetrics,
        };
        let blocks: Vec<BasicBlock> = (0..40)
            .map(|id| BasicBlock {
                id,
                start_address: id as u64,
                end_address: id as u64,
                instructions: Vec::new(),
                successors: Vec::new(),
                predecessors: Vec::new(),
                block_type: if id % 2 == 0 {
                    BlockType::Return
                } else {
                    BlockType::Normal
                },
                instruction_count: 0,
            })
            .collect();
        let cfg = ControlFlowGraph {
            function_address: 1,
            function_name: "f".into(),
            basic_blocks: blocks,
            edges: Vec::new(),
            entry_block: 0,
            // What the analysis kept of 20 exits and 3,000 loops.
            exit_blocks: vec![0, 2],
            loops: (0..16)
                .map(|n| Loop {
                    header_block: n,
                    body_blocks: vec![n],
                    exit_blocks: Vec::new(),
                    loop_type: LoopType::Natural,
                    nesting_level: 0,
                })
                .collect(),
            complexity: ControlFlowMetrics {
                cyclomatic_complexity: 1,
                cognitive_complexity: 0,
                nesting_depth: 0,
                basic_block_count: 40,
                edge_count: 0,
                loop_count: 3_000,
                unreachable_blocks: Vec::new(),
            },
        };
        let flow = ControlFlowAnalysis {
            cfgs: vec![cfg],
            overall_metrics: OverallMetrics {
                total_functions: 1,
                analyzed_functions: 1,
                total_basic_blocks: 40,
                average_complexity: 1.0,
                max_complexity: 1,
                function_with_max_complexity: None,
            },
            analysis_stats: AnalysisStats {
                analysis_duration: 0,
                bytes_analyzed: 0,
                instructions_analyzed: 0,
                errors: Vec::new(),
            },
        };
        let value = bounded_control_flow(&flow).unwrap();
        let row = &value["cfgs"][0];
        assert_eq!(row["loops_count"], 3_000);
        assert_eq!(row["exit_blocks_count"], 20);
        let brief_row = brief(row);
        assert_eq!(brief_row["loops_count"], 3_000, "{brief_row}");
        assert_eq!(brief_row["exit_blocks_count"], 20, "{brief_row}");
    }

    /// Only a limit that left functions or instructions out calls the section
    /// "built on a partial control-flow analysis"; a shortened list does not.
    #[test]
    fn only_a_limit_that_left_code_out_is_called_partial() {
        use crate::control_flow::{AnalysisStats, OverallMetrics};
        let flow = |errors: Vec<&str>| ControlFlowAnalysis {
            cfgs: Vec::new(),
            overall_metrics: OverallMetrics {
                total_functions: 0,
                analyzed_functions: 0,
                total_basic_blocks: 0,
                average_complexity: 0.0,
                max_complexity: 0,
                function_with_max_complexity: None,
            },
            analysis_stats: AnalysisStats {
                analysis_duration: 0,
                bytes_analyzed: 0,
                instructions_analyzed: 0,
                errors: errors.into_iter().map(String::from).collect(),
            },
        };
        let lists =
            "Limit: the lists of loops, exit blocks and unreachable blocks are cut to 20000";
        let notes = partial_flow_notes(&flow(vec![lists, "not a limit"]));
        assert_eq!(notes, vec![lists.to_string()]);
        let notes = partial_flow_notes(&flow(vec![
            "Limit: 112 of 128 functions (the highest addresses) were not analyzed because x",
            "Limit: 2 functions longer than 10 bytes were analyzed only up to that size",
        ]));
        assert_eq!(notes.len(), 2);
        assert!(notes
            .iter()
            .all(|n| n.starts_with("built on a partial control-flow analysis. Limit:")));
    }

    /// Every section that reads code is keyed by the slice, so two slices of
    /// one file never share a cached section; the names accepted for a slice
    /// are the ones the overview prints.
    #[test]
    fn slice_names_key_the_code_sections_and_match_the_overview() {
        let key = |name, arch: Option<&str>| {
            let options = Options {
                arch: arch_option(arch),
                ..Options::default()
            };
            plan(name, &options, "/x", 1).key
        };
        for name in [
            "binary_info",
            "symbols",
            "control_flow",
            "vulnerabilities",
            "code_quality",
            "disassembly",
            "call_graph",
        ] {
            let x86 = key(name, Some("x86_64"));
            assert_ne!(x86, key(name, Some("arm64e")), "{name}");
            assert_ne!(x86, key(name, None), "{name}");
        }
        assert_eq!(slice_name("ARM64 (subtype 12)"), "arm64-subtype-12");
        assert_eq!(slice_name("ARM64E"), "arm64e");
        assert_eq!(slice_name("x86_64"), "x86_64");
        assert!(arch_matches("ARM64 (subtype 12)", "arm64-subtype-12"));
        assert!(arch_matches("ARM64 (subtype 12)", "arm64 (subtype 12)"));
        assert!(arch_matches("x86_64", "X86-64"));
        assert!(arch_matches("ARM64", "aarch64"));
        assert!(arch_matches("x86_64", "amd64"));
        assert!(!arch_matches("arm64e", "arm64"));
        assert!(!arch_matches("x86_64", "ppc"));
    }
}
