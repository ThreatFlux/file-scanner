//! `analyze_file` and `llm_analyze_file`.
//!
//! The analysis itself lives in `FileScannerMcp::analyze_file` and
//! `llm_analyze_file` (plain methods without side effects); this module is the
//! tool surface: argument parsing, path policy, panic isolation, the section
//! cache, the side effects the REST routes depend on, and the output budget.

use std::{
    path::{Path, PathBuf},
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

use super::{
    output::{
        input_schema_with_budget, parse_request, render, respond_result, respond_text, tool_error,
        MAX_OUTPUT_BYTES, MIN_OUTPUT_BYTES,
    },
    paths::Expect,
    state::{mark_section, ENTRY_RESULT_MAX_BYTES},
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

/// Answer to an `analyze_file` call that names no analysis.
const NO_FLAGS_HINT: &str = "No analysis was requested. Pass at least one flag: metadata and \
hashes are a cheap start; strings, binary_info, entropy, symbols, threats, disassembly and the \
others dig in; all:true runs everything.";

/// Room kept free in the budget for the `cache` members spliced into the text.
const CACHE_FIELDS_RESERVE: usize = 400;

const ANALYZE_FILE_DESCRIPTION: &str = "Comprehensive file analysis tool - use flags to control \
which analyses to perform. Start here for an overview of a file; pass `all: true` to run every \
analysis. Pass an absolute path. Results are compact JSON capped at `max_output_bytes` (default \
80000, ceiling 400000); fields that do not fit are cut and listed under `truncated`. A repeated \
identical call on an unchanged file is answered from the in-memory cache (`cache: \"hit\"`), \
and a full run also speeds up later single-section calls on the same file. \
Follow up with llm_analyze_file for a YARA-oriented digest or yara_scan_file to test a rule.";

const LLM_ANALYZE_FILE_DESCRIPTION: &str =
    "LLM-optimized file analysis for YARA rule generation - \
returns focused, token-limited output. Call it after analyze_file when you want key strings, \
hex patterns, imports and a draft YARA rule for one file; then test the rule with yara_scan_file. \
Pass an absolute path. `token_limit` trims the digest (compact JSON bytes); the result is also \
capped at `max_output_bytes`.";

#[tool_router(router = analyze_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "analyze_file",
        title = "Analyze file",
        description = ANALYZE_FILE_DESCRIPTION,
        input_schema = input_schema_with_budget::<FileAnalysisRequest>(),
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
}

/// One part of an `analyze_file` result and the key it is cached under.
struct Section {
    /// Field name in the result.
    field: &'static str,
    /// Section name plus every option that changes its content.
    key: String,
}

/// The sections a request asks for, with their cache keys, in result order.
fn requested_sections(
    request: &FileAnalysisRequest,
    file_size: u64,
    mtime_ns: u128,
) -> Vec<Section> {
    let all = request.all.unwrap_or(false);
    let on = |flag: Option<bool>| flag.unwrap_or(false) || all;
    let min = request.min_string_length.unwrap_or(4);
    let mut out = Vec::new();
    let mut add = |field: &'static str, key: String| out.push(Section { field, key });
    if on(request.metadata) {
        // Timestamps and the path are part of the metadata, so they are in the key.
        add(
            "metadata",
            format!("metadata:{}:{mtime_ns}", request.file_path),
        );
    }
    // `yara_indicators` also puts the hashes in the result.
    if on(request.hashes) || on(request.yara_indicators) {
        add("hashes", "hashes".to_string());
    }
    if on(request.strings) {
        add("strings", format!("strings:min={min}"));
    }
    if on(request.hex_dump) {
        let default_size = if all {
            usize::try_from(file_size).map_or(MAX_HEX_DUMP_BYTES, |s| s.min(MAX_HEX_DUMP_BYTES))
        } else {
            256
        };
        let size = request.hex_dump_size.unwrap_or(default_size);
        let offset = request.hex_dump_offset.unwrap_or(0);
        add("hex_dump", format!("hex_dump:size={size}:offset={offset}"));
    }
    for (field, flag) in [
        ("binary_info", request.binary_info),
        ("signatures", request.signatures),
        ("symbols", request.symbols),
        ("control_flow", request.control_flow),
        ("vulnerabilities", request.vulnerabilities),
        ("code_quality", request.code_quality),
    ] {
        if on(flag) {
            add(field, field.to_string());
        }
    }
    if on(request.dependencies) {
        add("dependencies", format!("dependencies:min={min}"));
    }
    if on(request.entropy) {
        add("entropy", "entropy".to_string());
    }
    if on(request.disassembly) {
        add("disassembly", "disassembly".to_string());
    }
    if on(request.enhanced_threats) {
        add("threats", "threats:enhanced".to_string());
    } else if on(request.threats) {
        add("threats", "threats:basic".to_string());
    }
    if on(request.behavioral) {
        add("behavioral", format!("behavioral:min={min}"));
    }
    if on(request.yara_indicators) {
        add("yara_indicators", format!("yara_indicators:min={min}"));
    }
    out
}

/// A request that computes only the sections in `missing`, with the options
/// their keys promise.
fn request_for(
    original: &FileAnalysisRequest,
    missing: &[&Section],
) -> Result<FileAnalysisRequest, String> {
    let mut args = serde_json::Map::new();
    args.insert("file_path".into(), original.file_path.clone().into());
    args.insert("all".into(), false.into());
    if let Some(min) = original.min_string_length {
        args.insert("min_string_length".into(), min.into());
    }
    for section in missing {
        match section.key.as_str() {
            "threats:enhanced" => args.insert("enhanced_threats".into(), true.into()),
            "threats:basic" => args.insert("threats".into(), true.into()),
            _ => args.insert(section.field.into(), true.into()),
        };
        if section.field == "hex_dump" {
            // key: hex_dump:size=N:offset=M
            let mut parts = section.key.split(':').skip(1);
            let size = parts
                .next()
                .and_then(|p| p.strip_prefix("size="))
                .and_then(|v| v.parse::<usize>().ok());
            let offset = parts
                .next()
                .and_then(|p| p.strip_prefix("offset="))
                .and_then(|v| v.parse::<u64>().ok());
            if let Some(size) = size {
                args.insert("hex_dump_size".into(), size.into());
            }
            if let Some(offset) = offset {
                args.insert("hex_dump_offset".into(), offset.into());
            }
        }
    }
    serde_json::from_value(Value::Object(args)).map_err(|e| format!("Internal request error: {e}"))
}

/// The result of looking up, computing and assembling the sections.
struct Assembled {
    value: Value,
    /// Size of the whole result as compact JSON.
    total_bytes: usize,
    cached: usize,
    computed: usize,
    /// Sections too big for the cache, with their size in bytes.
    not_kept: Vec<(&'static str, usize)>,
    /// Section keys of this file the cache dropped to make room.
    evicted: Vec<String>,
}

/// The names (not the keys) of the sections in `keys`, once each, in order.
/// Internal `render:` and `entry:` keys are left out.
fn evicted_section_names(keys: &[String]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for key in keys {
        let name = key.split(':').next().unwrap_or(key);
        if name != "render" && name != "entry" && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// The strings of an `analyze_file` result, for the string tracker.
fn strings_of(result: &Value) -> Option<Vec<String>> {
    result
        .get("strings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
}

/// Mebibytes, for messages.
fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Splice `"cache":...` members into the front of a compact JSON object.
fn with_cache_fields(text: &str, state: &str, note: Option<&str>) -> String {
    let mut fields = format!("\"cache\":{}", Value::from(state));
    if let Some(note) = note {
        fields.push_str(&format!(",\"cache_note\":{}", Value::from(note)));
    }
    match text.strip_prefix('{') {
        Some("}") => format!("{{{fields}}}"),
        Some(rest) => format!("{{{fields},{rest}"),
        None => text.to_string(),
    }
}

impl FileScannerMcp {
    /// The `analyze_file` tool body (shared by every transport through the router).
    ///
    /// Each section of the result is cached on its own, keyed by the file's
    /// SHA-256 and the options that change it, so a full run answers a later
    /// drill-down. The rendered answer is cached too, so repeating a call
    /// verbatim costs one pass over the file for the SHA-256.
    pub(crate) async fn run_analyze_file(&self, args: JsonObject) -> CallToolResult {
        let started = Instant::now();
        let (mut request, budget, raw_args) = match parse_request::<FileAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let raw_path = request.file_path.clone();
        let path = match self.state.resolve_path(&raw_path, "File", Expect::File) {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        request.file_path = path.to_string_lossy().into_owned();

        let sha256 = match calculate_sha256_only(&path).await {
            Ok(sha256) => sha256,
            Err(error) => return tool_error(format!("Cannot read {raw_path}: {error:#}")),
        };
        let (file_size, mtime_ns) = std::fs::metadata(&path).map_or((0, 0), |meta| {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            (meta.len(), mtime)
        });

        let render_budget = budget.clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES) - CACHE_FIELDS_RESERVE;
        let cache = self.state.section_cache();
        // Same call, same unchanged file: the answer is already rendered, and
        // the first call left the string and cache-entry side effects behind.
        let render_key = format!(
            "render:{render_budget}:{file_size}:{mtime_ns}:{}",
            serde_json::to_string(&request).unwrap_or_default()
        );
        let entry_key = format!("entry:{render_key}");
        if let Some(text) = cache.get_text(&sha256, &render_key) {
            // Every successful call still appends its cache entry (the contract
            // the REST routes rely on). A small result is kept whole beside the
            // rendered text; a big one is recorded as what the caller received.
            let full = cache
                .get(&sha256, &entry_key)
                .filter(|value| !value.is_null());
            let (strings, entry_result) = match full {
                Some(full) => (strings_of(&full), Arc::unwrap_or_clone(full)),
                None => (None, serde_json::from_str(&text).unwrap_or(Value::Null)),
            };
            self.state
                .record_analyze_file(
                    &raw_args,
                    &raw_path,
                    strings,
                    entry_result,
                    &sha256,
                    file_size,
                    started,
                )
                .await;
            return respond_text(with_cache_fields(&text, "hit", None));
        }

        let sections = requested_sections(&request, file_size, mtime_ns);
        let nothing_requested = sections.is_empty();
        let analyzer = self.clone();
        let state = Arc::clone(&self.state);
        let sha = sha256.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("analyze_file", move || -> Result<Assembled, String> {
                let cache = state.section_cache();
                let mut found: Vec<Option<Arc<Value>>> = Vec::with_capacity(sections.len());
                for section in &sections {
                    found.push(cache.get(&sha, &section.key));
                }
                let cached = found.iter().flatten().count();
                let missing: Vec<&Section> = sections
                    .iter()
                    .zip(&found)
                    .filter(|(_, hit)| hit.is_none())
                    .map(|(section, _)| section)
                    .collect();
                let mut not_kept = Vec::new();
                let mut evicted: Vec<String> = Vec::new();
                let mut total_bytes = 0usize;
                if !missing.is_empty() {
                    let sub_request = request_for(&request, &missing)?;
                    let result = runtime.block_on(analyzer.analyze_file(sub_request))?.0;
                    let mut computed = match serde_json::to_value(&result) {
                        Ok(Value::Object(map)) => map,
                        Ok(_) => return Err("The analysis result is not an object".to_string()),
                        Err(error) => {
                            return Err(format!("Could not serialize the result: {error}"))
                        }
                    };
                    drop(result);
                    // A requested section the analyzer could not produce (for
                    // example binary_info of a text file) is cached as `null`.
                    for section in &missing {
                        let value = computed.remove(section.field).unwrap_or(Value::Null);
                        let outcome = cache.put(&sha, &section.key, &value);
                        if !outcome.kept {
                            not_kept.push((section.field, outcome.bytes));
                        }
                        evicted.extend(outcome.evicted_same_file);
                        let value = Arc::new(value);
                        if let Some(slot) = sections
                            .iter()
                            .position(|s| s.field == section.field && s.key == section.key)
                        {
                            found[slot] = Some(value);
                        }
                    }
                    // Hashes that `yara_indicators` brought along are worth keeping too.
                    if let Some(hashes) = computed.remove("hashes") {
                        if !hashes.is_null() {
                            evicted.extend(cache.put(&sha, "hashes", &hashes).evicted_same_file);
                        }
                    }
                }
                let mut out = serde_json::Map::new();
                out.insert("file_path".into(), request.file_path.clone().into());
                for (section, value) in sections.iter().zip(found) {
                    if let Some(value) = value.filter(|v| !v.is_null()) {
                        total_bytes += serde_json::to_string(&value).map_or(0, |t| t.len());
                        out.insert(section.field.to_string(), Arc::unwrap_or_clone(value));
                    }
                }
                Ok(Assembled {
                    value: Value::Object(out),
                    total_bytes,
                    cached,
                    computed: missing.len(),
                    not_kept,
                    evicted,
                })
            })
            .await;
        let assembled = match outcome {
            Err(crash) => return tool_error(crash),
            Ok(Err(message)) => return tool_error(message),
            Ok(Ok(assembled)) => assembled,
        };
        let Assembled {
            value,
            total_bytes,
            cached,
            computed,
            not_kept,
            mut evicted,
        } = assembled;

        if nothing_requested {
            // Nothing was computed or cached: say what to ask for instead of
            // reporting a cache state. The call still leaves its cache entry.
            let mut result = value;
            result["hint"] = NO_FLAGS_HINT.into();
            self.state
                .record_analyze_file(
                    &raw_args,
                    &raw_path,
                    None,
                    result.clone(),
                    &sha256,
                    file_size,
                    started,
                )
                .await;
            return respond_text(result.to_string());
        }

        // Side effects come from the full result, before it is trimmed.
        let strings = strings_of(&value);
        let small_enough = total_bytes <= ENTRY_RESULT_MAX_BYTES;
        let full_for_entry = small_enough.then(|| value.clone());

        let text = render(value, render_budget);
        evicted.extend(
            cache
                .put_text(&sha256, &render_key, text.clone())
                .evicted_same_file,
        );
        if let Some(full) = &full_for_entry {
            evicted.extend(cache.put(&sha256, &entry_key, full).evicted_same_file);
        }

        let entry_result =
            full_for_entry.unwrap_or_else(|| serde_json::from_str(&text).unwrap_or(Value::Null));
        self.state
            .record_analyze_file(
                &raw_args,
                &raw_path,
                strings,
                entry_result,
                &sha256,
                file_size,
                started,
            )
            .await;

        let cache_state = if computed == 0 {
            "hit"
        } else if cached > 0 {
            "partial"
        } else {
            "miss"
        };
        let mut notes = Vec::new();
        if !not_kept.is_empty() {
            let list = not_kept
                .iter()
                .map(|(field, bytes)| format!("{field} ({:.0} MiB)", mib(*bytes)))
                .collect::<Vec<_>>()
                .join(", ");
            notes.push(format!(
                "Not kept in the section cache because it is over the cache limit: {list}. \
                 Asking for it again recomputes it; raise FILE_SCANNER_SECTION_CACHE_MB to keep it."
            ));
        }
        let dropped = evicted_section_names(&evicted);
        if !dropped.is_empty() {
            notes.push(format!(
                "Dropped from the section cache to make room for this file's other sections: {}. \
                 Asking for one of them again recomputes it; raise FILE_SCANNER_SECTION_CACHE_MB \
                 to keep them all.",
                dropped.join(", ")
            ));
        }
        let note = (!notes.is_empty()).then(|| notes.join(" "));
        respond_text(with_cache_fields(&text, cache_state, note.as_deref()))
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
                runtime
                    .block_on(analyzer.llm_analyze_file(request))
                    .map(|json| json.0)
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

    /// A section bigger than the cache is not dropped silently: the call says
    /// so, and a verbatim repeat is still answered from the rendered answer.
    #[tokio::test]
    async fn sections_over_the_cache_limit_are_reported_and_repeats_still_hit() {
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
        assert_eq!(results[0]["cache"], "miss");
        let note = results[0]["cache_note"].as_str().expect("a cache_note");
        assert!(note.contains("disassembly"), "{note}");
        assert_eq!(results[1]["cache"], "hit");
    }

    /// A call that names no analysis computed nothing: it is not a cache hit,
    /// and it says what to ask for.
    #[tokio::test]
    async fn a_call_without_flags_gets_a_hint_not_a_cache_hit() {
        let path = sample("c_advanced_binary");
        let results = call(FileScannerMcp::new(), vec![json!({"file_path": path})]).await;
        assert!(results[0].get("cache").is_none(), "{}", results[0]);
        let hint = results[0]["hint"].as_str().expect("a hint");
        assert!(
            hint.contains("all:true") && hint.contains("metadata"),
            "{hint}"
        );
        assert_eq!(results[0]["file_path"], path);
    }

    /// A full run bigger than the cache must not silently evict its own
    /// sections: a later single-section call is a hit, or the full run's
    /// `cache_note` named what was dropped.
    #[tokio::test]
    async fn a_full_run_larger_than_the_cache_names_the_sections_it_dropped() {
        let path = sample("c_advanced_binary");
        let limit = 20_000;
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
            vec![json!({"file_path": path, "all": true, "max_output_bytes": 4000})],
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
                    json!({"file_path": path, "all": true, "max_output_bytes": 4000}),
                    json!({"file_path": path, field: true, "max_output_bytes": 4000}),
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

    /// Every call appends its cache entry, but a big result is kept only as the
    /// trimmed answer the caller received, so repeats cannot fill memory or disk.
    #[tokio::test]
    async fn cache_entries_of_big_results_hold_the_trimmed_answer() {
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
            largest <= ENTRY_RESULT_MAX_BYTES + 4096,
            "{largest} bytes in one entry"
        );
        assert!(entries.iter().all(|e| e.result.get("truncated").is_some()));
    }
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
    #[schemars(description = "Hex dump offset from start")]
    pub hex_dump_offset: Option<u64>,
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

    #[schemars(description = "Token limit for the response (default: 25000)")]
    pub token_limit: Option<usize>,

    #[schemars(description = "Minimum string length to extract (default: 6)")]
    pub min_string_length: Option<usize>,

    #[schemars(description = "Maximum number of strings to return (default: 50)")]
    pub max_strings: Option<usize>,

    #[schemars(description = "Maximum number of imports to return (default: 30)")]
    pub max_imports: Option<usize>,

    #[schemars(description = "Maximum number of opcodes to return (default: 10)")]
    pub max_opcodes: Option<usize>,

    #[schemars(description = "Size of hex patterns to extract (default: 32)")]
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
                offset: request.hex_dump_offset.unwrap_or(0),
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
                .collect::<std::collections::HashSet<_>>()
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

    pub async fn llm_analyze_file(
        &self,
        request: LlmFileAnalysisRequest,
    ) -> Result<Json<LlmFileAnalysisResult>, String> {
        use crate::{
            binary_parser::parse_binary, entropy_analysis::analyze_entropy,
            strings::extract_strings,
        };

        let path = PathBuf::from(&request.file_path);
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Get file metadata for MD5 hash
        let metadata = std::fs::metadata(&path).map_err(|e| format!("{e:#}"))?;
        let file_size = metadata.len();

        // Calculate MD5 hash only
        let md5_hash = crate::hash::calculate_md5(&path)
            .await
            .map_err(|e| format!("{e:#}"))?;

        // Extract strings with focus on interesting patterns
        let min_string_len = request.min_string_length.unwrap_or(6);
        let strings = extract_strings(&path, min_string_len).map_err(|e| format!("{e:#}"))?;

        // Filter and prioritize strings for YARA rules
        let key_strings = self.extract_key_strings(&strings, request.max_strings.unwrap_or(50));

        // Get hex patterns from file header/footer
        let hex_patterns =
            self.extract_hex_patterns(&path, request.hex_pattern_size.unwrap_or(32))?;

        // Parse binary for imports
        let imports = if let Ok(binary_info) = parse_binary(&path) {
            binary_info
                .imports
                .into_iter()
                .take(request.max_imports.unwrap_or(30))
                .collect()
        } else {
            vec![]
        };

        // Get interesting opcodes/byte sequences
        let opcodes = self.extract_key_opcodes(&path, request.max_opcodes.unwrap_or(10))?;

        // Calculate entropy for packing detection
        let entropy = analyze_entropy(&path).ok().map(|e| e.overall_entropy);

        // Build focused result
        let mut result = LlmFileAnalysisResult {
            md5: md5_hash,
            file_size,
            key_strings,
            hex_patterns,
            imports,
            opcodes,
            entropy,
            yara_rule_suggestion: None,
        };

        // Generate YARA rule suggestion if requested
        if request.suggest_yara_rule.unwrap_or(true) {
            result.yara_rule_suggestion =
                super::tools_yara::suggest_yara_rule(&result, &request.file_path).ok();
        }

        // Ensure we're within token limit
        let serialized = serde_json::to_string(&result).unwrap_or_default();
        let token_limit = request.token_limit.unwrap_or(25000);

        if serialized.len() > token_limit {
            // Trim results to fit token limit
            result = self.trim_results_to_token_limit(result, token_limit);
        }

        Ok(Json(result))
    }

    fn extract_key_strings(
        &self,
        strings: &crate::strings::ExtractedStrings,
        max_count: usize,
    ) -> Vec<String> {
        let mut key_strings = Vec::new();

        // Prioritize interesting strings
        for s in &strings.interesting_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.value.len() >= 8 && s.value.len() <= 100 {
                key_strings.push(s.value.clone());
            }
        }

        // Add unique ASCII strings
        let mut seen = std::collections::HashSet::new();
        for s in &strings.ascii_strings {
            if key_strings.len() >= max_count {
                break;
            }
            if s.len() >= 8 && s.len() <= 100 && seen.insert(s) {
                key_strings.push(s.clone());
            }
        }

        key_strings
    }

    fn extract_hex_patterns(
        &self,
        path: &PathBuf,
        pattern_size: usize,
    ) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut patterns = Vec::new();

        // Get file header pattern
        let header_options = HexDumpOptions {
            offset: 0,
            length: Some(pattern_size),
            bytes_per_line: pattern_size,
            max_lines: Some(1),
        };

        if let Ok(header_dump) = generate_hex_dump(path, header_options) {
            if let Some(line) = header_dump.lines.first() {
                let hex_pattern = line
                    .raw_bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                patterns.push(hex_pattern);
            }
        }

        // Get file footer pattern if file is large enough
        if let Ok(metadata) = std::fs::metadata(path) {
            if metadata.len() > pattern_size as u64 {
                let footer_options = HexDumpOptions {
                    offset: metadata.len() - pattern_size as u64,
                    length: Some(pattern_size),
                    bytes_per_line: pattern_size,
                    max_lines: Some(1),
                };

                if let Ok(footer_dump) = generate_hex_dump(path, footer_options) {
                    if let Some(line) = footer_dump.lines.first() {
                        let hex_pattern = line
                            .raw_bytes
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        patterns.push(hex_pattern);
                    }
                }
            }
        }

        Ok(patterns)
    }

    fn extract_key_opcodes(&self, path: &Path, max_count: usize) -> Result<Vec<String>, String> {
        use crate::hexdump::{generate_hex_dump, HexDumpOptions};

        let mut opcodes = Vec::new();

        // Look for common opcode patterns in code sections
        let options = HexDumpOptions {
            offset: 0x1000, // Common code section offset
            length: Some(256),
            bytes_per_line: 16,
            max_lines: Some(16),
        };

        if let Ok(dump) = generate_hex_dump(path, options) {
            for line in dump.lines.iter().take(max_count) {
                // Look for interesting opcode sequences
                let bytes = &line.raw_bytes;
                for window in bytes.windows(4) {
                    // Common interesting patterns
                    if (window[0] == 0xE8 || window[0] == 0xE9) || // CALL/JMP
                       (window[0] == 0xFF && (window[1] & 0xF0) == 0x10) || // Indirect calls
                       (window[0] == 0x48 && window[1] == 0x8B) || // MOV patterns
                       (window[0] == 0x55 && window[1] == 0x48)
                    {
                        // Function prologue
                        let pattern = window
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !opcodes.contains(&pattern) {
                            opcodes.push(pattern);
                        }
                    }
                }
            }
        }

        Ok(opcodes.into_iter().take(max_count).collect())
    }

    fn trim_results_to_token_limit(
        &self,
        mut result: LlmFileAnalysisResult,
        token_limit: usize,
    ) -> LlmFileAnalysisResult {
        // Progressively trim results until we fit within token limit
        loop {
            let serialized = serde_json::to_string(&result).unwrap_or_default();
            if serialized.len() <= token_limit {
                break;
            }

            // Trim strategies in order of preference
            if result.key_strings.len() > 20 {
                result.key_strings.truncate(result.key_strings.len() - 5);
            } else if result.imports.len() > 10 {
                result.imports.truncate(result.imports.len() - 5);
            } else if result.opcodes.len() > 5 {
                result.opcodes.truncate(result.opcodes.len() - 2);
            } else if result.key_strings.len() > 5 {
                result.key_strings.truncate(result.key_strings.len() - 1);
            } else {
                // Last resort: remove YARA suggestion
                result.yara_rule_suggestion = None;
                break;
            }
        }

        result
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
