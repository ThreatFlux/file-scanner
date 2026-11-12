//! `analyze_file` and `llm_analyze_file`.
//!
//! The analysis itself lives in `FileScannerMcp::analyze_file` and
//! `llm_analyze_file` (plain methods without side effects); this module is the
//! tool surface: argument parsing, path policy, panic isolation, the section
//! cache, the side effects the REST routes depend on, and the output budget.

mod compare;
mod inspect;
mod llm;
mod query;
mod sections;
mod triage;

pub use self::{
    compare::CompareFilesRequest,
    inspect::{DisassembleRequest, ReadHexRequest},
};

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Instant, UNIX_EPOCH},
};

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use self::sections::{Ctx, Engine, Failure, Options, Planned, ANALYSES};
use super::{
    output::{
        input_schema_with_budget, parse_request, render, respond_result, respond_text, tool_error,
        DEFAULT_LIMIT,
    },
    paths::Expect,
    state::mark_section,
    FileScannerMcp,
};
use crate::{
    behavioral_analysis::{analyze_behavior, BehavioralAnalysis},
    binary_parser::{parse_binary, BinaryInfo},
    code_metrics::{analyze_code_quality, CodeQualityAnalysis},
    control_flow::{analyze_control_flow, ControlFlowAnalysis},
    dependency_analysis::{analyze_dependencies, DependencyAnalysisResult},
    disassembly::{disassemble_binary, DisassemblyResult},
    entropy_analysis::{analyze_entropy, EntropyAnalysis},
    function_analysis::{analyze_symbols, SymbolTable},
    hash::{calculate_all_hashes, calculate_sha256_only, Hashes},
    hexdump::{format_hex_dump_text, generate_hex_dump, HexDumpOptions},
    metadata::FileMetadata,
    signature::verify_signature,
    strings::extract_strings,
    threat_detection::{analyze_threats, analyze_threats_enhanced, ThreatAnalysis},
    vulnerability_detection::{analyze_vulnerabilities, VulnerabilityDetectionResult},
};

/// Most bytes one `analyze_file` call dumps as hex (the dump is read into memory).
pub const MAX_HEX_DUMP_BYTES: usize = 1024 * 1024;
/// Most bytes one `analyze_file` hex dump covers; read_hex pages further.
pub const ANALYZE_HEX_DUMP_MAX: usize = 4096;

const ANALYZE_FILE_DESCRIPTION: &str = "START HERE. Triage overview of a file: size, type, mime, \
sha256 and md5, format facts (architecture, compiler, stripped), signature state, entropy headline, \
counts of strings, functions and imports, the most telling categorized strings (URLs, IPs, paths, \
secrets), and `next_steps` naming the exact call for each deeper analysis. With no section \
named it never runs the heavy analyses. Name sections (`sections: [\"symbols\", \"vulnerabilities\"]`, \
or the boolean flags, or `all: true`) to run them: each one is computed in full, cached by the \
file's SHA-256, and returned as a SUMMARY (headline numbers, top few items, total counts); `all: true` \
runs every analysis and still returns summaries only. To read the items, call query_analysis (it pages \
and filters strings, symbols, imports, functions, vulnerabilities, ... from the cache, so it is fast). \
A directory path returns a paged triage table, one row per file (`recursive`, `max_files`, \
`offset`, `limit`). Pass an absolute path. Results are compact JSON capped at `max_output_bytes` \
(default 80000, ceiling 400000); anything cut is listed under `truncated`. Sections that fail or do \
not apply to the file's format are listed under `errors` or `notes` with the reason. Then use \
query_analysis to dig in, llm_analyze_file for a YARA-oriented digest, or yara_scan_file to test a rule.";

const QUERY_ANALYSIS_DESCRIPTION: &str = "Dig into one section of a file: page and filter its \
lists. Call analyze_file first (its `next_steps` name the section and list to ask for). Sections \
and lists: strings (strings; filter = substring or regex on the text, category = URL | IP Address | \
Email | Password | API Key | Secret/Token | File Path | ..., encoding = ascii | utf16le | utf16be; \
every row has offset, encoding, value, category), binary_info (sections, imports, exports), symbols \
(functions, imports, exports, global_variables, cross_references), control_flow (functions: one \
summary row per function), vulnerabilities, code_quality (functions, quality_issues), dependencies \
(dependencies, compliance_issues), entropy (sections, high_entropy_regions), disassembly (functions, \
instructions, suspicious_patterns; one function at a time via `filter`), threats and enhanced_threats \
(matches, indicators), behavioral (findings, plus each group), yara_indicators. The answer is `{items, \
total, returned, offset, next_offset, cache}`: `total` counts the rows that match, `next_offset` asks \
for the next page. A section the file's cache already holds is answered at once (`cache: \"hit\"`); \
otherwise it is computed and cached (`cache: \"miss\"`). Rows are compact; `detail: true` returns the \
raw rows. Pass an absolute path. For raw bytes use read_hex, for machine code disassemble, to compare two files compare_files.";

const LLM_ANALYZE_FILE_DESCRIPTION: &str =
    "A small, fixed-size digest of one file for writing a YARA \
rule: sha256 and md5, file type, architecture, entropy and a packed flag, the key strings (URLs, \
IPs and other categorized strings first, no duplicates), header and footer bytes, imports, the \
first instructions at the entry point, and a draft rule. Choose it over analyze_file when the goal \
is a detection rule or a one-call summary that must fit a small context; choose analyze_file \
(overview first, then query_analysis) to investigate what a file does. Call analyze_file first if \
you do not know what the file is; test the draft rule with yara_scan_file. `token_limit` is the \
output budget in characters of compact JSON (about 4 per token, default 25000): when the digest \
does not fit, the answer lists under `truncated` what was cut. It is an error to ask for less than \
the bare identity needs. Pass an absolute path.";

#[tool_router(router = analyze_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "analyze_file",
        title = "Analyze file",
        description = ANALYZE_FILE_DESCRIPTION,
        input_schema = input_schema_with_budget::<AnalyzeFileArgs>(),
        annotations(
            title = "Analyze file",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_file_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_analyze_file(args).await)
    }

    #[tool(
        name = "query_analysis",
        title = "Query analysis",
        description = QUERY_ANALYSIS_DESCRIPTION,
        input_schema = input_schema_with_budget::<QueryAnalysisRequest>(),
        annotations(
            title = "Query analysis",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn query_analysis_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_query_analysis(args).await)
    }

    #[tool(
        name = "llm_analyze_file",
        title = "Analyze file for YARA",
        description = LLM_ANALYZE_FILE_DESCRIPTION,
        input_schema = input_schema_with_budget::<LlmFileAnalysisRequest>(),
        annotations(
            title = "Analyze file for YARA",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn llm_analyze_file_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_llm_analyze_file(args).await)
    }

    #[tool(
        name = "disassemble",
        title = "Disassemble",
        description = inspect::DISASSEMBLE_DESCRIPTION,
        input_schema = input_schema_with_budget::<DisassembleRequest>(),
        annotations(
            title = "Disassemble",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn disassemble_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_disassemble(args).await)
    }

    #[tool(
        name = "read_hex",
        title = "Read hex",
        description = inspect::READ_HEX_DESCRIPTION,
        input_schema = input_schema_with_budget::<ReadHexRequest>(),
        annotations(
            title = "Read hex",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn read_hex_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_read_hex(args).await)
    }

    #[tool(
        name = "compare_files",
        title = "Compare files",
        description = compare::COMPARE_FILES_DESCRIPTION,
        input_schema = input_schema_with_budget::<CompareFilesRequest>(),
        annotations(
            title = "Compare files",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn compare_files_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_compare_files(args).await)
    }
}

/// The sections an `analyze_file` call asks for, in result order.
fn requested_names(args: &AnalyzeFileArgs) -> Result<Vec<&'static str>, String> {
    let all = args.all.unwrap_or(false);
    let flag = |name: &str| {
        match name {
            "metadata" => args.metadata,
            "hashes" => args.hashes,
            "strings" => args.strings,
            "hex_dump" => args.hex_dump,
            "binary_info" => args.binary_info,
            "signatures" => args.signatures,
            "symbols" => args.symbols,
            "control_flow" => args.control_flow,
            "vulnerabilities" => args.vulnerabilities,
            "code_quality" => args.code_quality,
            "dependencies" => args.dependencies,
            "entropy" => args.entropy,
            "disassembly" => args.disassembly,
            "threats" => args.threats,
            "enhanced_threats" => args.enhanced_threats,
            "behavioral" => args.behavioral,
            _ => args.yara_indicators,
        }
        .unwrap_or(false)
    };
    let dump_asked = args.hex_dump.unwrap_or(false)
        || all
        || args
            .sections
            .iter()
            .flatten()
            .any(|s| s.trim().eq_ignore_ascii_case("hex_dump") || s.trim() == "hex-dump");
    if !dump_asked && (args.hex_dump_size.is_some() || args.hex_dump_offset.is_some()) {
        return Err(
            "hex_dump_size and hex_dump_offset only apply together with hex_dump: true (or \
             sections: [\"hex_dump\"]); to read bytes at an offset call read_hex."
                .to_string(),
        );
    }
    let mut named: Vec<&'static str> = Vec::new();
    for section in args.sections.iter().flatten() {
        let wanted = section.trim().to_lowercase().replace('-', "_");
        let Some(found) = ANALYSES.iter().find(|a| **a == wanted) else {
            return Err(format!(
                "Unknown section '{section}'. Sections: {}.",
                ANALYSES.join(", ")
            ));
        };
        named.push(found);
    }
    Ok(ANALYSES
        .iter()
        .copied()
        .filter(|name| all || flag(name) || named.contains(name))
        .collect())
}

/// A section summary as scalars and list lengths only.
fn counts_only(section: &Value) -> Value {
    let Some(map) = section.as_object() else {
        return section.clone();
    };
    let mut out = serde_json::Map::new();
    for (key, value) in map {
        match value {
            Value::Array(items) => {
                out.insert(format!("{key}_count"), items.len().into());
            }
            Value::String(text) if text.len() > 60 => {}
            Value::Object(_) => {}
            other => {
                out.insert(key.clone(), other.clone());
            }
        }
    }
    Value::Object(out)
}

/// A hex-dump offset as a position: negative counts back from the end of a
/// `size`-byte file (clamped to the start).
fn absolute_offset(offset: i64, size: u64) -> u64 {
    if offset >= 0 {
        offset as u64
    } else {
        size.saturating_sub(offset.unsigned_abs())
    }
}

fn mtime_ns_of(meta: &std::fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
}

/// Resolve and hash the file of a call. `Err` is a finished tool error.
async fn identify(
    server: &FileScannerMcp,
    raw_path: &str,
    expect: Expect,
) -> Result<(PathBuf, String, u64, u128), Box<CallToolResult>> {
    let path = server
        .state
        .resolve_path(raw_path, "File", expect)
        .map_err(|m| Box::new(tool_error(m)))?;
    let sha256 = calculate_sha256_only(&path)
        .await
        .map_err(|error| Box::new(tool_error(format!("Cannot read {raw_path}: {error:#}"))))?;
    let meta = std::fs::metadata(&path)
        .map_err(|error| Box::new(tool_error(format!("Cannot read {raw_path}: {error}"))))?;
    Ok((path, sha256, meta.len(), mtime_ns_of(&meta)))
}

impl FileScannerMcp {
    /// The `analyze_file` tool body (shared by every transport through the router).
    ///
    /// Without a named section: the triage overview. With sections: each one is
    /// computed in full (or taken from the section cache, keyed by the file's
    /// SHA-256 and the options that change it) and answered as a summary. A
    /// directory gets a paged triage table.
    pub(crate) async fn run_analyze_file(&self, args: JsonObject) -> CallToolResult {
        let started = Instant::now();
        let (request, budget, raw_args) = match parse_request::<AnalyzeFileArgs>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let raw_path = request.file_path.clone();
        let names = match requested_names(&request) {
            Ok(names) => names,
            Err(message) => return tool_error(message),
        };
        let path = match self
            .state
            .resolve_path(&raw_path, "File", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };

        if path.is_dir() {
            let recursive = request.recursive.unwrap_or(false);
            if let Err(message) = self.state.check_tree(&path, recursive) {
                return tool_error(message);
            }
            let max_files = request
                .max_files
                .unwrap_or(triage::DEFAULT_MAX_FILES)
                .clamp(1, triage::MAX_FILES_CEILING);
            let (offset, limit) = (
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(DEFAULT_LIMIT),
            );
            let runtime = tokio::runtime::Handle::current();
            let shown = path.to_string_lossy().into_owned();
            let dir = path.clone();
            let ignored = names.clone();
            let outcome = self
                .state
                .run_blocking("analyze_file", move || {
                    let mut value = triage::table(
                        &dir, &shown, recursive, max_files, offset, limit, &runtime, budget,
                    );
                    if !ignored.is_empty() {
                        value["note"] = format!(
                            "A directory gets the triage table; the analysis flags/sections ({}) \
                             apply to one file: call analyze_file on a file from the table.",
                            ignored.join(", ")
                        )
                        .into();
                    }
                    render(value, budget)
                })
                .await;
            return match outcome {
                Ok(text) => respond_text(text),
                Err(crash) => tool_error(crash),
            };
        }

        let hex_size = request.hex_dump_size.unwrap_or(sections::DEFAULT_HEX_DUMP);
        if names.contains(&"hex_dump") && hex_size > ANALYZE_HEX_DUMP_MAX {
            return tool_error(format!(
                "hex_dump_size {hex_size} is above the limit of {ANALYZE_HEX_DUMP_MAX} bytes per \
                 call. Ask for at most {ANALYZE_HEX_DUMP_MAX} and move with hex_dump_offset, or use \
                 read_hex (negative offsets count from the end) to page through the file."
            ));
        }
        let (path, sha256, file_size, mtime_ns) =
            match identify(self, &raw_path, Expect::File).await {
                Ok(identity) => identity,
                Err(error) => return *error,
            };
        let options = Options {
            min: request
                .min_string_length
                .unwrap_or(sections::DEFAULT_MIN_STRING),
            hex_size,
            hex_offset: absolute_offset(request.hex_dump_offset.unwrap_or(0), file_size),
        };
        if names.contains(&"hex_dump") && file_size > 0 && options.hex_offset >= file_size {
            return tool_error(format!(
                "hex_dump_offset {} is at or past the end of the {file_size}-byte file; use an \
                 offset below {file_size} (negative counts from the end).",
                options.hex_offset
            ));
        }

        let state = Arc::clone(&self.state);
        let runtime = tokio::runtime::Handle::current();
        let file_path = path.to_string_lossy().into_owned();
        let sha = sha256.clone();
        let outcome = self
            .state
            .run_blocking("analyze_file", move || {
                let ctx = Ctx::new(&path, &runtime, options);
                let mut engine = Engine::new(state.section_cache(), &sha, ctx);
                let mut tracker_source: Option<Arc<Value>> = None;
                let mut value;
                if names.is_empty() {
                    let overview = sections::overview(
                        &mut engine,
                        &path,
                        &file_path,
                        file_size,
                        &sha,
                        &options,
                        mtime_ns,
                    );
                    tracker_source = overview.strings;
                    value = Value::Object(overview.value);
                } else {
                    let mut out = serde_json::Map::new();
                    out.insert("file_path".into(), file_path.clone().into());
                    out.insert("sha256".into(), sha.clone().into());
                    let mut errors = serde_json::Map::new();
                    let mut notes = serde_json::Map::new();
                    let mut steps: Vec<Value> = Vec::new();
                    for name in &names {
                        let planned: Planned = sections::plan(name, &options, &file_path, mtime_ns);
                        match engine.load(&planned) {
                            Ok(section) => {
                                out.insert((*name).into(), sections::summarize(name, &section));
                                if let Some(step) = sections::drill_down(name, &file_path, &section)
                                {
                                    steps.push(step);
                                }
                                if *name == "strings" {
                                    tracker_source = Some(section);
                                }
                            }
                            Err(Failure::Error(message)) => {
                                errors.insert((*name).into(), message.into());
                            }
                            Err(Failure::NotApplicable(message)) => {
                                notes.insert((*name).into(), message.into());
                            }
                        }
                    }
                    if out.len() == 2 {
                        let all: Vec<String> = errors
                            .iter()
                            .chain(notes.iter())
                            .map(|(k, v)| format!("{k}: {}", v.as_str().unwrap_or_default()))
                            .collect();
                        return Err(format!(
                            "None of the requested analyses produced a result for {file_path}. {} \
                             Call analyze_file with only file_path for an overview and the \
                             sections that apply to this file.",
                            all.join("; ")
                        ));
                    }
                    if !errors.is_empty() {
                        out.insert("errors".into(), Value::Object(errors));
                    }
                    if !notes.is_empty() {
                        out.insert("notes".into(), Value::Object(notes));
                    }
                    if !steps.is_empty() {
                        out.insert("next_steps".into(), steps.into());
                    }
                    value = Value::Object(out);
                    // Many sections at a small budget: keep every section but
                    // as counts only, so the answer stays structured.
                    let fits = serde_json::to_string(&value).map_or(0, |t| t.len()) <= budget;
                    if !fits {
                        for name in &names {
                            if let Some(section) = value.get_mut(*name) {
                                *section = counts_only(section);
                            }
                        }
                        value["note"] = "The section summaries were reduced to counts to fit \
                            max_output_bytes; ask for fewer sections at once, or raise \
                            max_output_bytes, for the details."
                            .into();
                    }
                }
                value["cache"] = engine.cache_state().into();
                if let Some(note) = engine.cache_note() {
                    value["cache_note"] = note.into();
                }
                let strings = tracker_source.as_deref().map(sections::tracker_strings);
                let entry = value.clone();
                Ok((render(value, budget), entry, strings))
            })
            .await;
        let (text, entry, strings) = match outcome {
            Err(crash) => return tool_error(crash),
            Ok(Err(message)) => return tool_error(message),
            Ok(Ok(done)) => done,
        };
        self.state
            .record_analyze_file(
                &raw_args, &raw_path, strings, entry, &sha256, file_size, started,
            )
            .await;
        respond_text(text)
    }

    /// The `query_analysis` tool body.
    pub(crate) async fn run_query_analysis(&self, args: JsonObject) -> CallToolResult {
        let (request, budget, _raw) = match parse_request::<QueryAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let section = request.section.trim().to_lowercase().replace('-', "_");
        let Some(name) = ANALYSES.iter().copied().find(|a| *a == section) else {
            return tool_error(format!(
                "Unknown section '{}'. Sections with lists: strings, binary_info, symbols, \
                 control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, \
                 threats, enhanced_threats, behavioral, yara_indicators.",
                request.section
            ));
        };
        if matches!(name, "metadata" | "hashes" | "signatures") {
            return tool_error(format!(
                "The {name} section is small and has no list to page: call analyze_file with \
                 sections: [\"{name}\"]."
            ));
        }
        if name == "hex_dump" {
            return tool_error(
                "Hex dumps are not paged here: call read_hex with offset and length (4096 bytes \
                 per call, a negative offset counts from the end of the file)."
                    .to_string(),
            );
        }
        let (path, sha256, _size, mtime_ns) =
            match identify(self, &request.file_path, Expect::File).await {
                Ok(identity) => identity,
                Err(error) => return *error,
            };
        let options = Options {
            min: request
                .min_string_length
                .unwrap_or(sections::DEFAULT_MIN_STRING),
            ..Options::default()
        };
        let state = Arc::clone(&self.state);
        let runtime = tokio::runtime::Handle::current();
        let file_path = path.to_string_lossy().into_owned();
        let outcome = self
            .state
            .run_blocking("query_analysis", move || {
                let ctx = Ctx::new(&path, &runtime, options);
                let mut engine = Engine::new(state.section_cache(), &sha256, ctx);
                let planned = sections::plan(name, &options, &file_path, mtime_ns);
                let section = engine.load(&planned).map_err(|failure| match failure {
                    Failure::Error(m) => format!("The {name} analysis failed: {m}"),
                    Failure::NotApplicable(m) => format!(
                        "The {name} analysis does not apply to this file: {m}. Call analyze_file \
                         with only file_path to see which sections apply."
                    ),
                })?;
                let params = query::Params {
                    list: request.list.as_deref(),
                    filter: request.filter.as_deref(),
                    regex: request.regex.unwrap_or(false),
                    category: request.category.as_deref(),
                    encoding: request.encoding.as_deref(),
                    offset: request.offset.unwrap_or(0),
                    limit: request.limit.unwrap_or(DEFAULT_LIMIT),
                    detail: request.detail.unwrap_or(false),
                };
                let mut value = query::answer(name, &section, &params, budget)?;
                value["file_path"] = file_path.clone().into();
                value["cache"] = engine.cache_state().into();
                if let Some(note) = engine.cache_note() {
                    value["cache_note"] = note.into();
                }
                Ok::<String, String>(render(value, budget))
            })
            .await;
        match outcome {
            Err(crash) => tool_error(crash),
            Ok(Err(message)) => tool_error(message),
            Ok(Ok(text)) => respond_text(text),
        }
    }

    /// The `llm_analyze_file` tool body.
    pub(crate) async fn run_llm_analyze_file(&self, args: JsonObject) -> CallToolResult {
        let (mut request, budget, _raw) = match parse_request::<LlmFileAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let path = match self
            .state
            .resolve_path(&request.file_path, "File", Expect::File)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        request.file_path = path.to_string_lossy().into_owned();

        let analyzer = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("llm_analyze_file", move || {
                runtime.block_on(analyzer.llm_digest_within(&request, budget))
            })
            .await;
        respond_result(outcome, budget)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rmcp::{model::CallToolRequestParams, ServiceExt};
    use serde_json::{json, Value};

    use super::super::{
        state::{ServerState, StateConfig, ENTRY_RESULT_MAX_BYTES},
        FileScannerMcp,
    };

    fn sample(name: &str) -> String {
        format!("{}/test_programs/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    async fn call(server: FileScannerMcp, calls: Vec<Value>) -> Vec<Value> {
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = server.serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        let client = ().serve(client_io).await.expect("handshake");
        let mut out = Vec::new();
        for args in calls {
            let result = client
                .call_tool(
                    CallToolRequestParams::new("analyze_file")
                        .with_arguments(args.as_object().unwrap().clone()),
                )
                .await
                .expect("answered");
            assert_ne!(result.is_error, Some(true), "{result:?}");
            let text = result.content[0].as_text().unwrap().text.clone();
            out.push(serde_json::from_str(&text).expect("compact JSON"));
        }
        client.cancel().await.unwrap();
        out
    }

    /// A repeated full run of a multi-megabyte binary is a cache hit (the
    /// verifier saw misses forever above about 2 MB), and so is a drill-down
    /// into a section the full run already computed.
    #[tokio::test]
    async fn repeated_full_run_of_a_large_binary_and_drill_downs_hit() {
        let path = sample("rust_test_binary");
        let results = call(
            FileScannerMcp::new(),
            vec![
                json!({"file_path": path, "all": true}),
                json!({"file_path": path, "all": true}),
                json!({"file_path": path, "disassembly": true}),
                json!({"file_path": path, "strings": true, "hashes": true}),
            ],
        )
        .await;
        assert_eq!(results[0]["cache"], "miss", "{}", results[0]["cache_note"]);
        assert_eq!(results[1]["cache"], "hit");
        assert_eq!(results[2]["cache"], "hit", "drill-down after a full run");
        assert_eq!(results[3]["cache"], "hit");
        assert!(results[2].get("disassembly").is_some());
        assert!(results[3]["hashes"]["sha256"].is_string());
        // A hit carries the same content as the miss did.
        assert_eq!(results[1]["file_path"], results[0]["file_path"]);
    }

    /// A section bigger than the cache is not dropped silently: the call says so.
    #[tokio::test]
    async fn sections_over_the_cache_limit_are_reported_on_every_call() {
        let config = StateConfig {
            section_cache_max_bytes: 4_000,
            cache_dir: tempfile::tempdir().unwrap().keep(),
            ..StateConfig::default()
        };
        let server = FileScannerMcp::with_state(Arc::new(ServerState::new(config)));
        let path = sample("c_advanced_binary");
        let results = call(
            server,
            vec![
                json!({"file_path": path, "disassembly": true, "max_output_bytes": 4000}),
                json!({"file_path": path, "disassembly": true, "max_output_bytes": 4000}),
            ],
        )
        .await;
        // The section is bigger than the cache: each call says so and recomputes.
        for result in &results {
            assert_eq!(result["cache"], "miss");
            let note = result["cache_note"].as_str().expect("a cache_note");
            assert!(note.contains("disassembly"), "{note}");
            assert!(result["disassembly"]["instructions"]["count"].is_u64());
        }
    }

    /// CB12 / LS02: a call that names no analysis is the triage overview, with
    /// the exact calls for digging deeper.
    #[tokio::test]
    async fn a_call_without_flags_is_the_overview() {
        let path = sample("c_advanced_binary");
        let results = call(FileScannerMcp::new(), vec![json!({"file_path": path})]).await;
        let overview = &results[0];
        assert_eq!(overview["view"], "overview");
        assert_eq!(overview["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(overview["md5"].as_str().unwrap().len(), 32);
        assert_eq!(overview["format"]["format"], "ELF");
        assert!(overview["counts"]["strings"].as_u64().unwrap() > 100);
        assert!(overview["entropy"]["overall"].is_f64());
        assert!(overview["next_steps"].as_array().unwrap().len() >= 2);
        assert_eq!(overview["cache"], "miss");
    }

    /// A full run bigger than the cache must not silently evict its own
    /// sections: a later single-section call is a hit, or the full run's
    /// `cache_note` named what was dropped.
    #[tokio::test]
    async fn a_full_run_larger_than_the_cache_names_the_sections_it_dropped() {
        let path = sample("c_advanced_binary");
        let limit = 12_000;
        let fresh = || {
            let config = StateConfig {
                section_cache_max_bytes: limit,
                cache_dir: tempfile::tempdir().unwrap().keep(),
                ..StateConfig::default()
            };
            FileScannerMcp::with_state(Arc::new(ServerState::new(config)))
        };
        let full = call(
            fresh(),
            vec![json!({"file_path": path, "all": true, "max_output_bytes": 60000})],
        )
        .await;
        let note = full[0]["cache_note"].as_str().unwrap_or("").to_string();
        assert!(
            !note.is_empty(),
            "the limit is too big to test: {}",
            full[0]["cache"]
        );
        let mut hits = 0;
        for field in [
            "metadata",
            "hashes",
            "strings",
            "binary_info",
            "symbols",
            "control_flow",
            "disassembly",
            "entropy",
        ] {
            let server = fresh();
            let results = call(
                server,
                vec![
                    json!({"file_path": path, "all": true, "max_output_bytes": 60000}),
                    json!({"file_path": path, field: true, "max_output_bytes": 60000}),
                ],
            )
            .await;
            if results[1]["cache"] == "hit" {
                hits += 1;
            } else {
                assert!(
                    results[0]["cache_note"]
                        .as_str()
                        .unwrap_or("")
                        .contains(field),
                    "{field}: {} but the full run's note was {:?}",
                    results[1]["cache"],
                    results[0]["cache_note"]
                );
            }
        }
        assert!(hits > 0, "the most recent sections survive");
    }

    /// Every call appends its cache entry; the entry is the summary the caller
    /// got (never a whole section), so repeats cannot fill memory or disk.
    #[tokio::test]
    async fn cache_entries_hold_the_summary_not_the_sections() {
        let config = StateConfig {
            cache_dir: tempfile::tempdir().unwrap().keep(),
            ..StateConfig::default()
        };
        let server = FileScannerMcp::with_state(Arc::new(ServerState::new(config)));
        let state = Arc::clone(&server.state);
        let path = sample("rust_test_binary");
        let args = json!({"file_path": path, "all": true});
        call(server, vec![args.clone(), args.clone(), args]).await;
        let entries = state.analysis_cache().get_all_entries().await;
        assert_eq!(entries.len(), 3, "one entry per successful call");
        let largest = entries
            .iter()
            .map(|e| serde_json::to_string(&e.result).unwrap().len())
            .max()
            .unwrap();
        assert!(
            largest <= ENTRY_RESULT_MAX_BYTES,
            "{largest} bytes in one entry"
        );
        assert!(entries
            .iter()
            .all(|e| e.result["symbols"]["functions"]["count"].is_u64()));
    }
}

/// The arguments of the `analyze_file` tool: the flags of [`FileAnalysisRequest`]
/// plus `sections` and the directory-triage paging.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFileArgs {
    #[schemars(
        description = "Absolute path of the file to analyze (a leading ~/ is expanded). A directory returns a paged triage table, one row per file"
    )]
    pub file_path: String,
    #[schemars(
        description = "Analyses to run, by name: metadata, hashes, strings, hex_dump, binary_info, signatures, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, enhanced_threats, behavioral, yara_indicators. With none named (and no flag) the answer is the triage overview. Each named section is returned as a summary; query_analysis pages its items"
    )]
    pub sections: Option<Vec<String>>,
    #[schemars(
        description = "Run every analysis and return the per-section summaries (never the full sections); each full section is cached for query_analysis"
    )]
    pub all: Option<bool>,
    #[schemars(description = "Include file metadata (size, timestamps, permissions)")]
    pub metadata: Option<bool>,
    #[schemars(description = "Include cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)")]
    pub hashes: Option<bool>,
    #[schemars(description = "Strings summary: counts, categories, the most telling strings")]
    pub strings: Option<bool>,
    #[schemars(description = "Minimum string length (default: 4)")]
    pub min_string_length: Option<usize>,
    #[schemars(description = "Hex dump (default 256 bytes)")]
    pub hex_dump: Option<bool>,
    #[schemars(
        description = "Hex dump size in bytes (default 256; at most 4096 per call, an error above that). Up to 1024 bytes come back whole, more shows the first lines only; read_hex reads the rest (offset and length, 4096 bytes per call)"
    )]
    pub hex_dump_size: Option<usize>,
    #[schemars(
        description = "Hex dump offset from start; negative counts from the end of the file (-64 is the last 64 bytes)"
    )]
    pub hex_dump_offset: Option<i64>,
    #[schemars(description = "Analyze binary format (PE/ELF/Mach-O)")]
    pub binary_info: Option<bool>,
    #[schemars(description = "Verify digital signatures")]
    pub signatures: Option<bool>,
    #[schemars(description = "Analyze function symbols")]
    pub symbols: Option<bool>,
    #[schemars(description = "Analyze control flow")]
    pub control_flow: Option<bool>,
    #[schemars(description = "Detect vulnerabilities")]
    pub vulnerabilities: Option<bool>,
    #[schemars(description = "Analyze code quality metrics")]
    pub code_quality: Option<bool>,
    #[schemars(description = "Analyze dependencies")]
    pub dependencies: Option<bool>,
    #[schemars(description = "Analyze entropy patterns")]
    pub entropy: Option<bool>,
    #[schemars(
        description = "Disassemble code (summary; query_analysis pages functions and instructions)"
    )]
    pub disassembly: Option<bool>,
    #[schemars(description = "Detect threats and malware")]
    pub threats: Option<bool>,
    #[schemars(
        description = "Enhanced threat detection using threatflux-threat-detection library"
    )]
    pub enhanced_threats: Option<bool>,
    #[schemars(description = "Analyze behavioral patterns")]
    pub behavioral: Option<bool>,
    #[schemars(description = "Extract YARA rule indicators")]
    pub yara_indicators: Option<bool>,
    #[schemars(description = "Directory only: descend into subdirectories (default false)")]
    pub recursive: Option<bool>,
    #[schemars(
        description = "Directory only: most files to list, sorted by name (default 1000, ceiling 10000)"
    )]
    pub max_files: Option<usize>,
    #[schemars(description = "Directory only: rows to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Directory only: rows to return (default 50, at most 200)")]
    pub limit: Option<usize>,
}

/// The arguments of the `query_analysis` tool.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryAnalysisRequest {
    #[schemars(description = "Absolute path of the file (a leading ~/ is expanded)")]
    pub file_path: String,
    #[schemars(
        description = "Section to query: strings, binary_info, symbols, control_flow, vulnerabilities, code_quality, dependencies, entropy, disassembly, threats, enhanced_threats, behavioral, yara_indicators"
    )]
    pub section: String,
    #[schemars(
        description = "List inside the section (default: its main list; see the description)"
    )]
    pub list: Option<String>,
    #[schemars(
        description = "Keep only rows containing this text (case-insensitive), or matching it when regex is true. For strings it is matched against the string's text"
    )]
    pub filter: Option<String>,
    #[schemars(description = "Treat filter as a regular expression (default false)")]
    pub regex: Option<bool>,
    #[schemars(
        description = "Keep only rows of this category (strings: URL, IP Address, Email, ...; vulnerabilities: category or severity; others: their type field)"
    )]
    pub category: Option<String>,
    #[schemars(description = "Strings only: ascii, utf16le or utf16be")]
    pub encoding: Option<String>,
    #[schemars(description = "Strings only: minimum string length (default 4)")]
    pub min_string_length: Option<usize>,
    #[schemars(description = "Rows to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Rows to return (default 50, at most 500)")]
    pub limit: Option<usize>,
    #[schemars(description = "Return the raw rows instead of compact ones (default false)")]
    pub detail: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileAnalysisRequest {
    #[schemars(description = "Absolute path of the file to analyze (a leading ~/ is expanded)")]
    pub file_path: String,

    // Convenience flag
    #[schemars(description = "Enable all analysis options (overrides individual flags)")]
    pub all: Option<bool>,

    // Analysis options
    #[schemars(description = "Include file metadata (size, timestamps, permissions)")]
    pub metadata: Option<bool>,
    #[schemars(description = "Include cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)")]
    pub hashes: Option<bool>,
    #[schemars(description = "Extract strings from the file")]
    pub strings: Option<bool>,
    #[schemars(description = "Minimum string length (default: 4)")]
    pub min_string_length: Option<usize>,
    #[schemars(description = "Generate hex dump")]
    pub hex_dump: Option<bool>,
    #[schemars(
        description = "Hex dump size in bytes (default: 256, or the first 1 MiB of the file when 'all' is true; at most 1 MiB per call, an error above that - page through larger files with hex_dump_offset)"
    )]
    pub hex_dump_size: Option<usize>,
    #[schemars(
        description = "Hex dump offset from start; negative counts from the end of the file (-64 is the last 64 bytes)"
    )]
    pub hex_dump_offset: Option<i64>,
    #[schemars(description = "Analyze binary format (PE/ELF/Mach-O)")]
    pub binary_info: Option<bool>,
    #[schemars(description = "Verify digital signatures")]
    pub signatures: Option<bool>,
    #[schemars(description = "Analyze function symbols")]
    pub symbols: Option<bool>,
    #[schemars(description = "Analyze control flow")]
    pub control_flow: Option<bool>,
    #[schemars(description = "Detect vulnerabilities")]
    pub vulnerabilities: Option<bool>,
    #[schemars(description = "Analyze code quality metrics")]
    pub code_quality: Option<bool>,
    #[schemars(description = "Analyze dependencies")]
    pub dependencies: Option<bool>,
    #[schemars(description = "Analyze entropy patterns")]
    pub entropy: Option<bool>,
    #[schemars(description = "Disassemble code")]
    pub disassembly: Option<bool>,
    #[schemars(description = "Detect threats and malware")]
    pub threats: Option<bool>,
    #[schemars(
        description = "Enhanced threat detection using threatflux-threat-detection library"
    )]
    pub enhanced_threats: Option<bool>,
    #[schemars(description = "Analyze behavioral patterns")]
    pub behavioral: Option<bool>,
    #[schemars(description = "Extract YARA rule indicators")]
    pub yara_indicators: Option<bool>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FileAnalysisResult {
    pub file_path: String,
    #[schemars(skip)]
    pub metadata: Option<FileMetadata>,
    #[schemars(skip)]
    pub hashes: Option<Hashes>,
    pub strings: Option<Vec<String>>,
    pub hex_dump: Option<String>,
    #[schemars(skip)]
    pub binary_info: Option<BinaryInfo>,
    pub signatures: Option<serde_json::Value>,
    #[schemars(skip)]
    pub symbols: Option<SymbolTable>,
    #[schemars(skip)]
    pub control_flow: Option<ControlFlowAnalysis>,
    #[schemars(skip)]
    pub vulnerabilities: Option<VulnerabilityDetectionResult>,
    #[schemars(skip)]
    pub code_quality: Option<CodeQualityAnalysis>,
    #[schemars(skip)]
    pub dependencies: Option<DependencyAnalysisResult>,
    #[schemars(skip)]
    pub entropy: Option<EntropyAnalysis>,
    #[schemars(skip)]
    pub disassembly: Option<DisassemblyResult>,
    #[schemars(skip)]
    pub threats: Option<ThreatAnalysis>,
    #[schemars(skip)]
    pub behavioral: Option<BehavioralAnalysis>,
    pub yara_indicators: Option<YaraIndicators>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraIndicators {
    pub sha256: String,
    pub md5: String,
    pub file_size: u64,
    pub magic_bytes: String,
    pub entropy: f64,
    pub unique_strings: Vec<String>,
    pub imports: Vec<String>,
    pub sections: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LlmFileAnalysisRequest {
    #[schemars(description = "Absolute path of the file to analyze (a leading ~/ is expanded)")]
    pub file_path: String,

    #[schemars(
        description = "Output budget of the digest in characters of compact JSON, about 4 per token (default 25000). What does not fit is cut and listed under 'truncated'"
    )]
    pub token_limit: Option<usize>,

    #[schemars(
        description = "Minimum string length to extract, at least 1 (default: 6)",
        range(min = 1)
    )]
    pub min_string_length: Option<usize>,

    #[schemars(description = "Maximum number of strings to return (default: 50)")]
    pub max_strings: Option<usize>,

    #[schemars(description = "Maximum number of imports to return (default: 30)")]
    pub max_imports: Option<usize>,

    #[schemars(description = "Maximum number of opcodes to return (default: 10)")]
    pub max_opcodes: Option<usize>,

    #[schemars(
        description = "Bytes in each header and footer hex pattern, 1 to 1024 (default: 32)",
        range(min = 1, max = 1024)
    )]
    pub hex_pattern_size: Option<usize>,

    #[schemars(description = "Generate YARA rule suggestion (default: true)")]
    pub suggest_yara_rule: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LlmFileAnalysisResult {
    pub md5: String,
    pub file_size: u64,
    pub key_strings: Vec<String>,
    pub hex_patterns: Vec<String>,
    pub imports: Vec<String>,
    pub opcodes: Vec<String>,
    pub entropy: Option<f64>,
    pub yara_rule_suggestion: Option<String>,
}

impl FileScannerMcp {
    pub async fn analyze_file(
        &self,
        request: FileAnalysisRequest,
    ) -> Result<Json<FileAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        let mut result = FileAnalysisResult {
            file_path: request.file_path.clone(),
            metadata: None,
            hashes: None,
            strings: None,
            hex_dump: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        // Check if 'all' flag is set
        let all = request.all.unwrap_or(false);

        // Cache extracted strings to avoid multiple expensive extractions
        let mut cached_strings: Option<crate::strings::ExtractedStrings> = None;

        // Preemptively extract strings if any analysis that needs them is requested
        let needs_strings = request.strings.unwrap_or(false)
            || request.dependencies.unwrap_or(false)
            || request.behavioral.unwrap_or(false)
            || request.yara_indicators.unwrap_or(false)
            || all;

        if needs_strings && cached_strings.is_none() {
            mark_section("strings");
            let min_len = request.min_string_length.unwrap_or(4);
            if let Ok(strings) = extract_strings(&path, min_len) {
                cached_strings = Some(strings);
            }
        }

        // Metadata
        if request.metadata.unwrap_or(false) || all {
            mark_section("metadata");
            let mut metadata = FileMetadata::new(&path).map_err(|e| format!("{e:#}"))?;
            metadata
                .extract_basic_info()
                .map_err(|e| format!("{e:#}"))?;
            metadata
                .calculate_hashes()
                .await
                .map_err(|e| format!("{e:#}"))?;
            result.metadata = Some(metadata);
        }

        // Hashes
        if request.hashes.unwrap_or(false) || all {
            mark_section("hashes");
            let hashes = calculate_all_hashes(&path)
                .await
                .map_err(|e| format!("{e:#}"))?;
            result.hashes = Some(hashes);
        }

        // Strings (use cached version)
        if request.strings.unwrap_or(false) || all {
            mark_section("strings");
            if let Some(ref strings) = cached_strings {
                let all_strings = [
                    strings.ascii_strings.clone(),
                    strings.unicode_strings.clone(),
                ]
                .concat();
                result.strings = Some(all_strings);
            }
        }

        // Hex dump
        if request.hex_dump.unwrap_or(false) || all {
            mark_section("hex_dump");
            // The dump is read into memory, so its size is capped. Ask for more
            // with `hex_dump_offset` (page through the file) instead.
            let file_size = std::fs::metadata(&path).map_or(0, |m| m.len());
            let default_size = if all {
                std::cmp::min(file_size as usize, MAX_HEX_DUMP_BYTES)
            } else {
                256
            };

            let size = request.hex_dump_size.unwrap_or(default_size);
            if size > MAX_HEX_DUMP_BYTES {
                return Err(format!(
                    "hex_dump_size {size} is above the limit of {MAX_HEX_DUMP_BYTES} bytes per \
                     call. Ask for at most {MAX_HEX_DUMP_BYTES} and page through the file with \
                     hex_dump_offset."
                ));
            }
            let hex_options = HexDumpOptions {
                offset: absolute_offset(request.hex_dump_offset.unwrap_or(0), file_size),
                length: Some(size),
                bytes_per_line: 16,
                max_lines: None,
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| format!("{e:#}"))?;
            result.hex_dump = Some(format_hex_dump_text(&hex_dump));
        }

        // Binary info
        if request.binary_info.unwrap_or(false) || all {
            mark_section("binary_info");
            if let Ok(binary_info) = parse_binary(&path) {
                result.binary_info = Some(binary_info);
            }
        }

        // Signatures
        if request.signatures.unwrap_or(false) || all {
            mark_section("signatures");
            let sig_result = verify_signature(&path);
            // Convert the result to a JSON-serializable format
            let sig_json = match sig_result {
                Ok(info) => serde_json::json!({
                    "status": "success",
                    "is_signed": info.is_signed,
                    "signature_type": info.signature_type,
                    "signer": info.signer,
                    "timestamp": info.timestamp,
                    "verification_status": info.verification_status,
                    "certificate_chain": info.certificate_chain,
                }),
                Err(e) => serde_json::json!({
                    "status": "error",
                    "error": e.to_string()
                }),
            };
            result.signatures = Some(sig_json);
        }

        // Symbols
        if request.symbols.unwrap_or(false) || all {
            mark_section("symbols");
            if let Ok(symbols) = analyze_symbols(&path) {
                result.symbols = Some(symbols);
            }
        }

        // Control flow
        if request.control_flow.unwrap_or(false) || all {
            mark_section("control_flow");
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    result.control_flow = Some(control_flow);
                }
            }
        }

        // Vulnerabilities
        if request.vulnerabilities.unwrap_or(false) || all {
            mark_section("vulnerabilities");
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(vulns) = analyze_vulnerabilities(&path, &symbols, &control_flow) {
                        result.vulnerabilities = Some(vulns);
                    }
                }
            }
        }

        // Code quality
        if request.code_quality.unwrap_or(false) || all {
            mark_section("code_quality");
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(control_flow) = analyze_control_flow(&path, &symbols) {
                    if let Ok(quality) = analyze_code_quality(&path, &symbols, &control_flow) {
                        result.code_quality = Some(quality);
                    }
                }
            }
        }

        // Dependencies
        if request.dependencies.unwrap_or(false) || all {
            mark_section("dependencies");
            if let Ok(symbols) = analyze_symbols(&path) {
                // Use cached strings if available, otherwise extract with min length 4
                if let Ok(deps) = analyze_dependencies(&path, &symbols, cached_strings.as_ref()) {
                    result.dependencies = Some(deps);
                }
            }
        }

        // Entropy
        if request.entropy.unwrap_or(false) || all {
            mark_section("entropy");
            if let Ok(entropy) = analyze_entropy(&path) {
                result.entropy = Some(entropy);
            }
        }

        // Disassembly
        if request.disassembly.unwrap_or(false) || all {
            mark_section("disassembly");
            if let Ok(symbols) = analyze_symbols(&path) {
                if let Ok(disassembly) = disassemble_binary(&path, &symbols) {
                    result.disassembly = Some(disassembly);
                }
            }
        }

        // Threats
        if request.threats.unwrap_or(false) || all {
            mark_section("threats");
            if let Ok(threats) = analyze_threats(&path) {
                result.threats = Some(threats);
            }
        }

        // Enhanced Threats
        if request.enhanced_threats.unwrap_or(false) || all {
            mark_section("enhanced_threats");
            match analyze_threats_enhanced(&path).await {
                Ok(enhanced_threats) => {
                    result.threats = Some(enhanced_threats);
                }
                Err(e) => {
                    eprintln!("Enhanced threat analysis failed: {e}");
                    // Fallback to regular threat analysis
                    if let Ok(threats) = analyze_threats(&path) {
                        result.threats = Some(threats);
                    }
                }
            }
        }

        // Behavioral
        if request.behavioral.unwrap_or(false) || all {
            mark_section("behavioral");
            let symbols = analyze_symbols(&path).ok();
            let disassembly = if let Some(ref syms) = symbols {
                disassemble_binary(&path, syms).ok()
            } else {
                None
            };

            if let Ok(behavioral) = analyze_behavior(
                &path,
                cached_strings.as_ref(),
                symbols.as_ref(),
                disassembly.as_ref(),
            ) {
                result.behavioral = Some(behavioral);
            }
        }

        // YARA indicators
        if request.yara_indicators.unwrap_or(false) || all {
            mark_section("yara_indicators");
            let file_metadata = std::fs::metadata(&path).map_err(|e| format!("{e:#}"))?;
            let file_size = file_metadata.len();

            // Get hashes if not already calculated
            let hashes = if let Some(h) = &result.hashes {
                h.clone()
            } else {
                let h = calculate_all_hashes(&path)
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                if result.hashes.is_none() {
                    result.hashes = Some(h.clone());
                }
                h
            };

            // Get magic bytes
            let hex_options = HexDumpOptions {
                offset: 0,
                length: Some(8),
                bytes_per_line: 8,
                max_lines: Some(1),
            };
            let hex_dump = generate_hex_dump(&path, hex_options).map_err(|e| format!("{e:#}"))?;
            let magic_bytes = hex_dump
                .lines
                .first()
                .map(|line| {
                    line.raw_bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();

            // Get entropy if not already calculated
            let entropy_analysis = if let Some(e) = result.entropy.clone() {
                e
            } else {
                analyze_entropy(&path).map_err(|e| format!("{e:#}"))?
            };

            // Extract unique strings (use cached if available, otherwise extract with min length 8)
            let strings = if let Some(ref cached) = cached_strings {
                cached
            } else {
                // Fallback: extract strings with min length 8 if not cached
                cached_strings = Some(extract_strings(&path, 8).map_err(|e| format!("{e:#}"))?);
                cached_strings.as_ref().unwrap()
            };
            let mut unique_strings: Vec<String> = strings
                .interesting_strings
                .iter()
                .filter(|s| s.value.len() >= 8 && s.value.len() <= 50)
                .map(|s| s.value.clone())
                // A sorted set, so the same file always gives the same 20 strings.
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .take(20)
                .collect();
            unique_strings.sort();

            // Get imports and sections
            let (imports, sections) = if let Some(ref bi) = result.binary_info {
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
            } else if let Ok(bi) = parse_binary(&path) {
                (
                    bi.imports.clone(),
                    bi.sections.iter().map(|s| s.name.clone()).collect(),
                )
            } else {
                (vec![], vec![])
            };

            result.yara_indicators = Some(YaraIndicators {
                sha256: hashes.sha256,
                md5: hashes.md5,
                file_size,
                magic_bytes,
                entropy: entropy_analysis.overall_entropy,
                unique_strings,
                imports,
                sections,
                is_packed: entropy_analysis.packed_indicators.likely_packed
                    || entropy_analysis.overall_entropy > 7.0,
            });
        }

        Ok(Json(result))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::mcp_server::analyze_file_llm;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file.bin");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[allow(dead_code)]
    fn create_test_elf_file() -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_elf");
        let mut elf_data = vec![
            0x7f, 0x45, 0x4c, 0x46, // ELF magic
            0x02, 0x01, 0x01, 0x00, // 64-bit, little-endian, version 1
        ];
        // Add some padding to make it a minimal valid ELF-like file
        elf_data.extend(vec![0u8; 56]); // Pad to 64 bytes

        let mut file = fs::File::create(&file_path)?;
        file.write_all(&elf_data)?;
        Ok((temp_dir, file_path))
    }

    #[test]
    fn test_file_analysis_request_serialization() {
        let request = FileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(8),
            hex_dump: Some(true),
            hex_dump_size: Some(512),
            hex_dump_offset: Some(0),
            binary_info: Some(true),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(true),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(true),
            enhanced_threats: None,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, request.file_path);
        assert_eq!(deserialized.all, request.all);
        assert_eq!(deserialized.metadata, request.metadata);
        assert_eq!(deserialized.hashes, request.hashes);
        assert_eq!(deserialized.min_string_length, request.min_string_length);
    }

    #[test]
    fn test_llm_file_analysis_request_serialization() {
        let request = LlmFileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            token_limit: Some(20000),
            min_string_length: Some(6),
            max_strings: Some(40),
            max_imports: Some(25),
            max_opcodes: Some(8),
            hex_pattern_size: Some(24),
            suggest_yara_rule: Some(true),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: LlmFileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.file_path, request.file_path);
        assert_eq!(deserialized.token_limit, request.token_limit);
        assert_eq!(deserialized.max_strings, request.max_strings);
    }

    #[test]
    fn test_yara_indicators_serialization() {
        let indicators = YaraIndicators {
            sha256: "abc123".to_string(),
            md5: "def456".to_string(),
            file_size: 1024,
            magic_bytes: "4D 5A".to_string(),
            entropy: 6.5,
            unique_strings: vec!["test".to_string(), "example".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            sections: vec![".text".to_string(), ".data".to_string()],
            is_packed: false,
        };

        // Test JSON serialization
        let json = serde_json::to_string(&indicators).unwrap();
        let deserialized: YaraIndicators = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.sha256, indicators.sha256);
        assert_eq!(deserialized.file_size, indicators.file_size);
        assert_eq!(deserialized.unique_strings, indicators.unique_strings);
    }

    #[tokio::test]
    async fn test_analyze_file_nonexistent() {
        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: "/nonexistent/file.bin".to_string(),
            metadata: Some(true),
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_err());
        match result {
            Err(error_msg) => assert!(error_msg.contains("does not exist")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_analyze_file_basic_metadata() {
        let test_content = b"Hello, World! This is test content for analysis.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: file_path.to_string_lossy().to_string(),
            metadata: Some(true),
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.metadata.is_some());
        assert!(analysis.hashes.is_none());
        assert!(analysis.strings.is_none());
    }

    #[tokio::test]
    async fn test_analyze_file_hashes() {
        let test_content = b"Test content for hash calculation";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: Some(true),
            strings: None,
            min_string_length: None,
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.hashes.is_some());
        let hashes = analysis.hashes.unwrap();
        assert!(!hashes.md5.is_empty());
        assert!(!hashes.sha256.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_strings() {
        let test_content =
            b"Hello World! This is a test string for extraction. Another string here.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: None,
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: None,
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.strings.is_some());
        let strings = analysis.strings.unwrap();
        assert!(!strings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_hex_dump() {
        let test_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: file_path.to_string_lossy().to_string(),
            metadata: None,
            hashes: None,
            strings: None,
            min_string_length: None,
            hex_dump: Some(true),
            hex_dump_size: Some(64),
            hex_dump_offset: Some(0),
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.hex_dump.is_some());
        let hex_dump = analysis.hex_dump.unwrap();
        assert!(hex_dump.contains("41 42 43")); // ABC in hex
    }

    #[tokio::test]
    async fn test_analyze_file_combined_analysis() {
        let test_content = b"Combined analysis test with various features enabled.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            all: None,
            file_path: file_path.to_string_lossy().to_string(),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(6),
            hex_dump: Some(true),
            hex_dump_size: Some(32),
            hex_dump_offset: Some(0),
            binary_info: Some(true), // Will fail but shouldn't error
            signatures: Some(true),  // Will show no signature
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: Some(true),
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(analysis.metadata.is_some());
        assert!(analysis.hashes.is_some());
        assert!(analysis.strings.is_some());
        assert!(analysis.hex_dump.is_some());
        assert!(analysis.signatures.is_some());
        assert!(analysis.entropy.is_some());
    }

    #[tokio::test]
    async fn test_llm_analyze_file_nonexistent() {
        let mcp = FileScannerMcp::new();
        let request = LlmFileAnalysisRequest {
            file_path: "/nonexistent/file.bin".to_string(),
            token_limit: None,
            min_string_length: None,
            max_strings: None,
            max_imports: None,
            max_opcodes: None,
            hex_pattern_size: None,
            suggest_yara_rule: None,
        };

        let result = mcp.llm_analyze_file(request).await;
        assert!(result.is_err());
        match result {
            Err(error_msg) => assert!(error_msg.contains("does not exist")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_llm_analyze_file_basic() {
        let test_content = b"LLM analysis test content with interesting patterns and strings.";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = LlmFileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            token_limit: Some(10000),
            min_string_length: Some(6),
            max_strings: Some(20),
            max_imports: Some(10),
            max_opcodes: Some(5),
            hex_pattern_size: Some(16),
            suggest_yara_rule: Some(true),
        };

        let result = mcp.llm_analyze_file(request).await;
        assert!(result.is_ok());

        let analysis = result.unwrap().0;
        assert!(!analysis.md5.is_empty());
        assert!(analysis.file_size > 0);
        assert!(analysis.yara_rule_suggestion.is_some());
        let yara_rule = analysis.yara_rule_suggestion.unwrap();
        assert!(yara_rule.contains("rule"));
        assert!(yara_rule.contains("filesize"));
    }

    #[tokio::test]
    async fn test_analyze_file_llm_wrapper() {
        let content = b"Wrapper LLM analysis test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let request = LlmFileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            token_limit: Some(1000),
            min_string_length: Some(4),
            max_strings: Some(10),
            max_imports: Some(5),
            max_opcodes: Some(5),
            hex_pattern_size: Some(16),
            suggest_yara_rule: Some(false),
        };

        let result = analyze_file_llm(request).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_key_strings() {
        let mcp = FileScannerMcp::new();

        // Create mock extracted strings
        let extracted_strings = crate::strings::ExtractedStrings {
            total_count: 10,
            unique_count: 8,
            ascii_strings: vec![
                "short".to_string(),
                "this is a longer string for testing".to_string(),
                "medium length string".to_string(),
                "another test string here".to_string(),
            ],
            unicode_strings: vec![],
            interesting_strings: vec![
                crate::strings::InterestingString {
                    category: "URL".to_string(),
                    value: "https://example.com/malware".to_string(),
                    offset: 100,
                },
                crate::strings::InterestingString {
                    category: "File Path".to_string(),
                    value: "/usr/bin/suspicious".to_string(),
                    offset: 200,
                },
            ],
        };

        let key_strings = mcp.extract_key_strings(&extracted_strings, 5);

        assert!(!key_strings.is_empty());
        assert!(key_strings.len() <= 5);

        // Should prioritize interesting strings
        assert!(key_strings.contains(&"https://example.com/malware".to_string()));
        assert!(key_strings.contains(&"/usr/bin/suspicious".to_string()));
    }

    #[test]
    fn test_extract_hex_patterns() {
        let test_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let result = mcp.extract_hex_patterns(&file_path, 16);

        assert!(result.is_ok());
        let patterns = result.unwrap();
        assert!(!patterns.is_empty());

        // Should contain header pattern
        let header_pattern = &patterns[0];
        assert!(header_pattern.contains("41 42 43")); // ABC in hex
    }

    #[test]
    fn test_extract_key_opcodes() {
        let test_content = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // CALL instruction
            0x48, 0x8B, 0x05, 0x00, // MOV instruction
            0x55, 0x48, 0x89, 0xE5, // Function prologue
            0xFF, 0x15, 0x00, 0x00, // Indirect call
        ];
        let (_temp_dir, file_path) = create_test_file(&test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let result = mcp.extract_key_opcodes(&file_path, 5);

        // This test might not find opcodes since it looks at offset 0x1000
        // But it should not error
        assert!(result.is_ok());
    }

    #[test]
    fn test_trim_results_to_token_limit() {
        let mcp = FileScannerMcp::new();

        let result = LlmFileAnalysisResult {
            md5: "abc123".to_string(),
            file_size: 1024,
            key_strings: (0..50).map(|i| format!("string_{i}")).collect(),
            hex_patterns: vec!["4D 5A".to_string()],
            imports: (0..40).map(|i| format!("import_{i}.dll")).collect(),
            opcodes: (0..20).map(|i| format!("opcode_{i:02X}")).collect(),
            entropy: Some(6.5),
            yara_rule_suggestion: Some("very long yara rule here".to_string()),
        };

        let trimmed = mcp.trim_results_to_token_limit(result, 500);

        // Should have fewer strings/imports/opcodes
        assert!(trimmed.key_strings.len() < 50);
        assert!(trimmed.imports.len() < 40);
        assert!(trimmed.opcodes.len() < 20);
    }

    #[test]
    fn test_file_analysis_result_defaults() {
        let result = FileAnalysisResult {
            file_path: "test.bin".to_string(),
            metadata: None,
            hashes: None,
            strings: None,
            hex_dump: None,
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
        };

        assert_eq!(result.file_path, "test.bin");
        assert!(result.metadata.is_none());
        assert!(result.hashes.is_none());
        assert!(result.yara_indicators.is_none());
    }

    #[test]
    fn test_llm_file_analysis_result_serialization() {
        let result = LlmFileAnalysisResult {
            md5: "abc123".to_string(),
            file_size: 2048,
            key_strings: vec!["test".to_string()],
            hex_patterns: vec!["4D 5A".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            opcodes: vec!["E8 00".to_string()],
            entropy: Some(6.8),
            yara_rule_suggestion: Some("rule test {}".to_string()),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: LlmFileAnalysisResult = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.md5, result.md5);
        assert_eq!(deserialized.file_size, result.file_size);
        assert_eq!(deserialized.entropy, result.entropy);
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_enables_everything() {
        let test_content = b"Test content for all flag verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(true),
            // Set all individual flags to false to verify 'all' overrides them
            metadata: Some(false),
            hashes: Some(false),
            strings: Some(false),
            min_string_length: Some(6),
            hex_dump: Some(false),
            hex_dump_size: Some(32),
            hex_dump_offset: Some(0),
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify that 'all: true' enables all analysis types despite individual flags being false
        assert!(
            response.metadata.is_some(),
            "metadata should be present with all=true"
        );
        assert!(
            response.hashes.is_some(),
            "hashes should be present with all=true"
        );
        assert!(
            response.strings.is_some(),
            "strings should be present with all=true"
        );
        assert!(
            response.hex_dump.is_some(),
            "hex_dump should be present with all=true"
        );
        assert!(
            response.entropy.is_some(),
            "entropy should be present with all=true"
        );
        assert!(
            response.yara_indicators.is_some(),
            "yara_indicators should be present with all=true"
        );
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_false_respects_individual_flags() {
        let test_content = b"Test content for individual flag verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(false),
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify only the explicitly enabled analyses are present
        assert!(
            response.metadata.is_some(),
            "metadata should be present when explicitly enabled"
        );
        assert!(
            response.hashes.is_none(),
            "hashes should be absent when explicitly disabled"
        );
        assert!(
            response.strings.is_some(),
            "strings should be present when explicitly enabled"
        );
        assert!(
            response.hex_dump.is_none(),
            "hex_dump should be absent when explicitly disabled"
        );
        assert!(
            response.entropy.is_none(),
            "entropy should be absent when explicitly disabled"
        );
        assert!(
            response.yara_indicators.is_none(),
            "yara_indicators should be absent when explicitly disabled"
        );
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_none_uses_individual_flags() {
        let test_content = b"Test content for default behavior verification";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();
        let request = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: None, // Default behavior
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(false),
            min_string_length: None,
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
            enhanced_threats: None,
        };

        let result = mcp.analyze_file(request).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;

        // Verify behavior matches individual flags when 'all' is None
        assert!(
            response.metadata.is_some(),
            "metadata should be present when enabled"
        );
        assert!(
            response.hashes.is_some(),
            "hashes should be present when enabled"
        );
        assert!(
            response.strings.is_none(),
            "strings should be absent when disabled"
        );
        assert!(
            response.hex_dump.is_none(),
            "hex_dump should be absent when disabled"
        );
        assert!(
            response.entropy.is_none(),
            "entropy should be absent when disabled"
        );
    }

    #[test]
    fn test_file_analysis_request_serialization_with_all_flag() {
        // Test with all flag set to true
        let request_all_true = FileAnalysisRequest {
            file_path: "/test/file.bin".to_string(),
            all: Some(true),
            metadata: Some(false),
            hashes: Some(false),
            strings: Some(false),
            min_string_length: Some(8),
            hex_dump: Some(false),
            hex_dump_size: Some(512),
            hex_dump_offset: Some(0),
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
            enhanced_threats: None,
        };

        let json = serde_json::to_string(&request_all_true).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, Some(true));
        assert_eq!(deserialized.file_path, request_all_true.file_path);

        // Test with all flag set to false
        let request_all_false = FileAnalysisRequest {
            file_path: "/test/file2.bin".to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(true),
            strings: Some(true),
            min_string_length: Some(4),
            hex_dump: Some(true),
            hex_dump_size: Some(256),
            hex_dump_offset: Some(0),
            binary_info: Some(true),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(true),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(true),
            enhanced_threats: None,
        };

        let json = serde_json::to_string(&request_all_false).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, Some(false));
        assert_eq!(deserialized.metadata, Some(true));
        assert_eq!(deserialized.entropy, Some(true));

        // Test with all flag as None (default)
        let request_all_none = FileAnalysisRequest {
            file_path: "/test/file3.bin".to_string(),
            all: None,
            metadata: Some(true),
            hashes: Some(false),
            strings: Some(true),
            min_string_length: Some(6),
            hex_dump: Some(false),
            hex_dump_size: None,
            hex_dump_offset: None,
            binary_info: Some(false),
            signatures: Some(false),
            symbols: Some(false),
            control_flow: Some(false),
            vulnerabilities: Some(false),
            code_quality: Some(false),
            dependencies: Some(false),
            entropy: Some(false),
            disassembly: Some(false),
            threats: Some(false),
            behavioral: Some(false),
            yara_indicators: Some(false),
            enhanced_threats: None,
        };

        let json = serde_json::to_string(&request_all_none).unwrap();
        let deserialized: FileAnalysisRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.all, None);
        assert_eq!(deserialized.metadata, Some(true));
        assert_eq!(deserialized.hashes, Some(false));
        assert_eq!(deserialized.strings, Some(true));
    }

    #[tokio::test]
    async fn test_analyze_file_all_flag_comprehensive_verification() {
        let test_content = b"Comprehensive test content with various features for all flag testing";
        let (_temp_dir, file_path) = create_test_file(test_content).unwrap();

        let mcp = FileScannerMcp::new();

        // Test 1: Verify 'all: true' enables more analyses than individual flags
        let request_all = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(true),
            metadata: None,
            hashes: None,
            strings: None,
            min_string_length: Some(4),
            hex_dump: None,
            hex_dump_size: Some(64),
            hex_dump_offset: Some(0),
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result_all = mcp.analyze_file(request_all).await;
        assert!(result_all.is_ok());
        let response_all = result_all.unwrap().0;

        // Test 2: Compare with selective analysis
        let request_selective = FileAnalysisRequest {
            file_path: file_path.to_string_lossy().to_string(),
            all: Some(false),
            metadata: Some(true),
            hashes: Some(true),
            strings: None,
            min_string_length: Some(4),
            hex_dump: None,
            hex_dump_size: Some(64),
            hex_dump_offset: Some(0),
            binary_info: None,
            signatures: None,
            symbols: None,
            control_flow: None,
            vulnerabilities: None,
            code_quality: None,
            dependencies: None,
            entropy: None,
            disassembly: None,
            threats: None,
            behavioral: None,
            yara_indicators: None,
            enhanced_threats: None,
        };

        let result_selective = mcp.analyze_file(request_selective).await;
        assert!(result_selective.is_ok());
        let response_selective = result_selective.unwrap().0;

        // Verify 'all: true' provides more complete analysis
        assert!(response_all.metadata.is_some() && response_selective.metadata.is_some());
        assert!(response_all.hashes.is_some() && response_selective.hashes.is_some());

        // These should be present with 'all: true' but not with selective analysis
        assert!(response_all.strings.is_some());
        assert!(response_selective.strings.is_none());

        assert!(response_all.hex_dump.is_some());
        assert!(response_selective.hex_dump.is_none());

        assert!(response_all.entropy.is_some());
        assert!(response_selective.entropy.is_none());

        assert!(response_all.yara_indicators.is_some());
        assert!(response_selective.yara_indicators.is_none());
    }
}
