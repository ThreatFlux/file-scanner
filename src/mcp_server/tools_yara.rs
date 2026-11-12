//! `yara_scan_file` and the YARA rule suggestion used by `llm_analyze_file`.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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
        fit_rows, input_schema_with_budget, page, parse_request, respond, tool_error,
        DEFAULT_LIMIT, MAX_OUTPUT_BYTES, MIN_OUTPUT_BYTES,
    },
    paths::Expect,
    tools_analyze::LlmFileAnalysisResult,
    FileScannerMcp,
};
use crate::threat_detection::{
    builtin_rule_sources, compile_rule_sources_with_warnings, load_rule_sources,
    scan_path_with_rules, CustomYaraScanResult, RuleHitCount, YaraFileMatch, YaraScanError,
    YaraScanOptions, YaraSkippedFile, DEFAULT_MAX_FILES, DEFAULT_MAX_MATCHES_PER_RULE,
    DEFAULT_MAX_RULES_PER_FILE, DEFAULT_TIMEOUT_SECONDS,
};

const YARA_SCAN_DESCRIPTION: &str = "Scan a file or directory with YARA rules and get a summary \
first: files scanned and matched, how many files each rule hit, skipped and unscanned files, and \
a paged list of matching files (`offset`, `limit`) whose rule matches carry tags, metadata and the \
first matched strings with their offsets (text, or hex for binary bytes). Give the rules as \
`yara_rule` (rule text, or the word `builtin` for the scanner's own 10 rules) and/or `rule_path` \
(a .yar/.yara file, or a directory of them); `include` directives are not supported. A rule that \
does not compile is an error that carries the compiler's message, line and column, so fix the \
rule and call again. Draft a rule with llm_analyze_file first. Listing is capped: \
`max_matches_per_rule` string matches per rule (the rest are counted in `strings_total`), \
`max_rules_per_file`, `max_files` (the walk stops there; `files_not_scanned` is then a lower bound) \
and `timeout_seconds` for the scan and its own directory walk; whatever was cut is named in \
`limits_reached`. Before the scan starts the server checks every entry under `path` against the \
allowed folders, and that check is not covered by `max_files` or `timeout_seconds`, so a huge tree \
can take longer than `timeout_seconds` to answer. A call without `offset` always scans anew. Later pages (`offset` above 0) are a snapshot of \
that first call, served from the kept result (`cache: \"hit\"`) for 10 minutes. Files over `max_file_size`, symlinks and \
unreadable directories are listed under `skipped`; unreadable files are listed under `errors`. Results are compact JSON capped at `max_output_bytes` \
(default 80000, ceiling 400000).";

#[tool_router(router = yara_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "yara_scan_file",
        title = "Scan with YARA",
        description = YARA_SCAN_DESCRIPTION,
        input_schema = input_schema_with_budget::<YaraScanArgs>(),
        annotations(
            title = "Scan with YARA",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn yara_scan_file_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_yara_scan(args).await)
    }
}

/// Largest `max_file_size` a YARA scan accepts (each file is read into memory).
pub const MAX_YARA_FILE_BYTES: u64 = 100 * 1024 * 1024;
/// Ceilings for the scan limits a caller can ask for.
const MAX_FILES_CEILING: usize = 100_000;
const MAX_MATCHES_PER_RULE_CEILING: usize = 1_000;
const MAX_RULES_PER_FILE_CEILING: usize = 1_000;
const MAX_TIMEOUT_SECONDS: u64 = 600;

/// Largest rule text accepted inline (rule files have their own limits).
const MAX_INLINE_RULE_BYTES: usize = 5 * 1024 * 1024;

/// The word that selects the scanner's own rules in `yara_rule`.
const BUILTIN_KEYWORD: &str = "builtin";

/// Arguments of the `yara_scan_file` tool.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraScanArgs {
    #[schemars(
        description = "Absolute path of the file or directory to scan (a leading ~/ is expanded)"
    )]
    pub path: String,

    #[schemars(
        description = "YARA rule text to scan with, or the word `builtin` for the scanner's own \
                       rule set. Give this, `rule_path`, or both."
    )]
    pub yara_rule: Option<String>,

    #[schemars(
        description = "Absolute path of a rule file (.yar/.yara) or of a directory whose \
                       .yar/.yara files are all loaded. `include` is not supported."
    )]
    pub rule_path: Option<String>,

    #[schemars(description = "If true, recursively scan directories (default: true)")]
    pub recursive: Option<bool>,

    #[schemars(
        description = "Maximum file size to scan in bytes (default and ceiling: 100MB); \
                              larger files are listed under `skipped`"
    )]
    pub max_file_size: Option<u64>,

    #[schemars(description = "List the matched strings (default: true). Off gives only counts.")]
    pub detailed_matches: Option<bool>,

    #[schemars(
        description = "Most matched strings listed per rule per file (default 10, at most 1000); \
                       `strings_total` always has the full count"
    )]
    pub max_matches_per_rule: Option<usize>,

    #[schemars(description = "Most matching rules listed per file (default 100, at most 1000)")]
    pub max_rules_per_file: Option<usize>,

    #[schemars(
        description = "Most files examined (default 10000, at most 100000); the walk stops there \
                       and `files_not_scanned` is then a lower bound (`more_files_not_counted`)"
    )]
    pub max_files: Option<usize>,

    #[schemars(
        description = "Wall-clock budget for the scan and its directory walk in seconds (default \
                       60, at most 600; the server's check of the tree before the scan is not \
                       included); a file still running when it ends is reported in `errors`"
    )]
    pub timeout_seconds: Option<u64>,

    #[schemars(description = "Matching files to skip in the listing (default 0)")]
    pub offset: Option<usize>,

    #[schemars(description = "Matching files per page (default 50, at most 500)")]
    pub limit: Option<usize>,
}

/// The scan the CLI asks for: rule text and the four classic options. The
/// MCP tool takes `YaraScanArgs`, which adds rule files, the built-in rules,
/// limits and paging.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraScanRequest {
    #[schemars(
        description = "Absolute path of the file or directory to scan (a leading ~/ is expanded)"
    )]
    pub path: String,

    #[schemars(description = "YARA rule content to use for scanning")]
    #[serde(default)]
    pub yara_rule: String,

    #[schemars(
        description = "A rule file (.yar/.yara) or a directory of them, instead of or with `yara_rule`"
    )]
    #[serde(default)]
    pub rule_path: Option<String>,

    #[schemars(description = "If true, recursively scan directories (default: true)")]
    pub recursive: Option<bool>,

    #[schemars(description = "Maximum file size to scan in bytes (default: 100MB)")]
    pub max_file_size: Option<u64>,

    #[schemars(description = "Include detailed match information (default: true)")]
    pub detailed_matches: Option<bool>,

    #[schemars(description = "Most files examined (default: no limit on the command line)")]
    #[serde(default)]
    pub max_files: Option<usize>,

    #[schemars(description = "Wall-clock budget in seconds (default: none on the command line)")]
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanResult {
    pub total_files_scanned: usize,
    /// Rule matches over all files (one rule matching one file counts once).
    pub total_matches: usize,
    pub scan_duration_ms: u64,
    /// Files with at least one match.
    pub files_matched: usize,
    /// Rules in the compiled rule set.
    pub rules_compiled: usize,
    /// How many files each rule matched, most first.
    pub rule_hits: Vec<RuleHitCount>,
    pub matches: Vec<YaraFileMatch>,
    pub errors: Vec<YaraScanError>,
    /// Files not scanned (too large, unreadable); the first 100 are named.
    pub skipped: Vec<YaraSkippedFile>,
    pub skipped_total: usize,
    /// Files left unscanned because `max_files` or the time budget was hit;
    /// a lower bound when `more_files_not_counted` is set.
    pub files_not_scanned: usize,
    /// True when `files_not_scanned` is a lower bound: the walk stopped early.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub more_files_not_counted: bool,
    pub timed_out: bool,
    /// Compiler warnings about the rules.
    pub rule_warnings: Vec<String>,
    /// What was cut, and how to ask for more.
    pub limits_reached: Vec<String>,
}

/// A validated scan: where, with which rules, within which limits.
struct ScanPlan {
    path: PathBuf,
    sources: Vec<(String, String)>,
    options: YaraScanOptions,
}

impl FileScannerMcp {
    /// The `yara_scan_file` tool body.
    pub(crate) async fn run_yara_scan(&self, args: JsonObject) -> CallToolResult {
        let started = Instant::now();
        let (request, budget, raw_args) = match parse_request::<YaraScanArgs>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let raw_path = request.path.clone();
        let path = match self
            .state
            .resolve_path(&raw_path, "Path", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        let recursive = request.recursive.unwrap_or(true);
        // The scan reads what is inside a directory, so vet its members too.
        if let Err(message) = self.state.check_tree(&path, recursive) {
            return tool_error(message);
        }

        let mut sources = Vec::new();
        if let Some(rule) = request.yara_rule.as_deref() {
            if rule.trim().eq_ignore_ascii_case(BUILTIN_KEYWORD) {
                sources.extend(builtin_rule_sources());
            } else if rule.len() > MAX_INLINE_RULE_BYTES {
                return tool_error(format!(
                    "`yara_rule` is {} bytes, above the {MAX_INLINE_RULE_BYTES}-byte limit. Put \
                     big rule sets in a file and pass it as `rule_path`.",
                    rule.len()
                ));
            } else if !rule.trim().is_empty() {
                sources.push(("yara_rule".to_string(), rule.to_string()));
            }
        }
        if let Some(raw_rule_path) = request.rule_path.as_deref() {
            let rule_path =
                match self
                    .state
                    .resolve_path(raw_rule_path, "Rule path", Expect::FileOrDir)
                {
                    Ok(rule_path) => rule_path,
                    Err(message) => return tool_error(message),
                };
            if let Err(message) = self.state.check_tree(&rule_path, true) {
                return tool_error(message);
            }
            match load_rule_sources(&rule_path) {
                Ok(loaded) => sources.extend(loaded),
                Err(message) => return tool_error(message),
            }
        }
        if sources.is_empty() {
            return tool_error(
                "No rules given. Pass `yara_rule` (rule text, or the word `builtin` for the \
                 scanner's own rules) and/or `rule_path` (a .yar/.yara file or a directory of \
                 them).",
            );
        }

        let options = match options_from_args(&request) {
            Ok(options) => options,
            Err(message) => return tool_error(message),
        };
        let offset = request.offset.unwrap_or(0);
        let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
        let rule_text_is_a_path = request.yara_rule.as_deref().is_some_and(looks_like_a_path);
        let single_file = path.is_file();
        let key = scan_key(&path, &sources, &options);
        let plan = ScanPlan {
            path,
            sources,
            options,
        };

        let outcome = self
            .state
            .run_blocking("yara_scan_file", move || {
                fetch_or_scan(&plan, key, offset > 0)
            })
            .await;
        let (result, hit, store_note) = match outcome {
            Err(crash) => return tool_error(crash),
            Ok(Err(message)) => {
                return tool_error(if rule_text_is_a_path {
                    format!(
                        "{message}\n`yara_rule` holds rule text, not a file name. To load rules \
                         from a file or a directory, pass it as `rule_path`."
                    )
                } else {
                    message
                })
            }
            Ok(Ok(found)) => found,
        };
        if single_file && result.total_files_scanned == 0 && !result.timed_out {
            if let Some(error) = result.errors.first() {
                return tool_error(format!(
                    "The file could not be scanned: {}: {}",
                    error.file_path, error.error
                ));
            }
        }
        let mut value = reply_value(&result, offset, limit, budget, store_note);
        value["cache"] = if hit { "hit" } else { "miss" }.into();
        if !hit {
            // Only the compact page goes to the analysis cache, never the
            // complete result.
            self.state
                .record_yara_scan(&raw_args, &raw_path, &value, started)
                .await;
        }
        respond(value, budget)
    }
}

/// A `yara_rule` value that reads like a file name, not like rule text.
fn looks_like_a_path(text: &str) -> bool {
    let text = text.trim();
    !text.is_empty()
        && !text.contains('{')
        && !text.contains('\n')
        && !text.contains(char::is_whitespace)
        && (text.starts_with('/')
            || text.starts_with("~/")
            || text.ends_with(".yar")
            || text.ends_with(".yara"))
}

/// The most the kept scan result may take (as compact JSON).
const STORE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// How long a kept scan result answers later pages.
const STORE_TTL: Duration = Duration::from_secs(600);

/// The one scan result kept so later pages need no new scan. It is replaced,
/// never added to, and only stored when it is at most `STORE_MAX_BYTES`.
struct StoredScan {
    key: String,
    result: Arc<YaraScanResult>,
    stored: Instant,
}

static SCAN_STORE: Mutex<Option<StoredScan>> = Mutex::new(None);

/// Identity of a scan: the path (and, for a file, its size and mtime), the
/// rule texts and every option, but not `offset`, `limit` or the budget.
fn scan_key(
    path: &std::path::Path,
    sources: &[(String, String)],
    options: &YaraScanOptions,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(path.to_string_lossy().as_bytes());
    if let Ok(meta) = std::fs::metadata(path) {
        hasher.update(&meta.len().to_le_bytes());
        if let Some(age) = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        {
            hasher.update(&age.as_nanos().to_le_bytes());
        }
    }
    for (origin, text) in sources {
        hasher.update(&(origin.len() as u64).to_le_bytes());
        hasher.update(origin.as_bytes());
        hasher.update(&(text.len() as u64).to_le_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(format!("{options:?}").as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// The kept result for `key`, or a new scan (kept when small enough). The
/// third member says why a result was not kept.
fn fetch_or_scan(
    plan: &ScanPlan,
    key: String,
    later_page: bool,
) -> Result<(Arc<YaraScanResult>, bool, Option<String>), String> {
    // A first call (offset 0) always scans, so edits to the tree are seen;
    // only later pages are a snapshot of that first call.
    if let (true, Ok(store)) = (later_page, SCAN_STORE.lock()) {
        if let Some(kept) = store.as_ref() {
            if kept.key == key && kept.stored.elapsed() < STORE_TTL {
                return Ok((Arc::clone(&kept.result), true, None));
            }
        }
    }
    let result = Arc::new(execute_scan(plan)?);
    let size = json_size(&*result);
    let mut note = None;
    if let Ok(mut store) = SCAN_STORE.lock() {
        if size <= STORE_MAX_BYTES {
            *store = Some(StoredScan {
                key,
                result: Arc::clone(&result),
                stored: Instant::now(),
            });
        } else {
            *store = None;
            note = Some(format!(
                "The full result is {size} bytes, above the {STORE_MAX_BYTES}-byte limit for \
                 keeping it, so every page re-runs the scan. Narrow `path`, lower \
                 `max_matches_per_rule` or turn `detailed_matches` off to make later pages \
                 fast."
            ));
        }
    }
    Ok((result, false, note))
}

/// The compact JSON size of `value`, counted without building the text.
fn json_size<T: serde::Serialize>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if serde_json::to_writer(&mut counter, value).is_err() {
        return usize::MAX;
    }
    counter.0
}

/// Everything in `result` except the matching files.
fn summary_of(result: &YaraScanResult) -> YaraScanResult {
    YaraScanResult {
        total_files_scanned: result.total_files_scanned,
        total_matches: result.total_matches,
        scan_duration_ms: result.scan_duration_ms,
        files_matched: result.files_matched,
        rules_compiled: result.rules_compiled,
        rule_hits: result.rule_hits.clone(),
        matches: Vec::new(),
        errors: result.errors.clone(),
        skipped: result.skipped.clone(),
        skipped_total: result.skipped_total,
        files_not_scanned: result.files_not_scanned,
        more_files_not_counted: result.more_files_not_counted,
        timed_out: result.timed_out,
        rule_warnings: result.rule_warnings.clone(),
        limits_reached: Vec::new(),
    }
}

/// The reply: the summary (always whole, its lists capped with totals) and
/// one page of matching files cut to fit `budget`, with `matches_returned`
/// and `next_offset` describing the files actually listed.
fn reply_value(
    result: &YaraScanResult,
    offset: usize,
    limit: usize,
    budget: usize,
    store_note: Option<String>,
) -> Value {
    let budget = budget.clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES);
    let mut limits = result.limits_reached.clone();
    let hits_cap = (budget / 400).clamp(5, 100);
    let list_cap = (budget / 2_000).clamp(3, 20);
    let mut summary = summary_of(result);
    if summary.rule_hits.len() > hits_cap {
        limits.push(format!(
            "rule_hits lists the {hits_cap} most-hit of {} rules that matched (`rule_hits_total`).",
            summary.rule_hits.len()
        ));
    }
    if summary.errors.len() > list_cap {
        limits.push(format!(
            "errors lists the first {list_cap} of {} (`errors_total`).",
            summary.errors.len()
        ));
    }
    if summary.skipped.len() > list_cap {
        limits.push(format!(
            "skipped names the first {list_cap} of {} files (`skipped_total`).",
            summary.skipped_total
        ));
    }
    limits.extend(store_note);
    let rule_hits_total = summary.rule_hits.len();
    let errors_total = summary.errors.len();
    summary.rule_hits.truncate(hits_cap);
    summary.errors.truncate(list_cap);
    summary.skipped.truncate(list_cap);
    summary.rule_warnings.truncate(10);
    summary.limits_reached = limits;

    let mut value = serde_json::to_value(&summary).unwrap_or(Value::Null);
    let take = rows_that_fit(&result.matches, offset, limit, budget);
    let paged = page(&result.matches, offset, take);
    let Some(map) = value.as_object_mut() else {
        return value;
    };
    map.insert("rule_hits_total".into(), rule_hits_total.into());
    map.insert("errors_total".into(), errors_total.into());
    map.insert(
        "matches".into(),
        paged.get("items").cloned().unwrap_or(Value::Null),
    );
    map.insert("matches_total".into(), result.matches.len().into());
    map.insert("matches_offset".into(), offset.into());
    map.insert(
        "returned".into(),
        paged.get("returned").cloned().unwrap_or(Value::Null),
    );
    if let Some(next) = paged.get("next_offset") {
        map.insert("next_offset".into(), next.clone());
    }
    fit_rows(&mut value, "matches", budget, offset, result.matches.len());
    if let Some(map) = value.as_object_mut() {
        if let Some(returned) = map.remove("returned") {
            map.insert("matches_returned".into(), returned);
        }
    }
    value
}

/// How many rows from `offset` to turn into JSON: add up each row's size and
/// stop before the page budget is passed (at least one row, at most `limit`),
/// so a large `limit` never builds values for rows the reply cannot carry.
fn rows_that_fit(
    matches: &[crate::threat_detection::YaraFileMatch],
    offset: usize,
    limit: usize,
    budget: usize,
) -> usize {
    let start = offset.min(matches.len());
    let mut used = 0usize;
    let mut count = 0usize;
    for row in matches[start..].iter().take(limit.max(1)) {
        let size = json_size(row);
        if count > 0 && used.saturating_add(size) > budget {
            break;
        }
        used = used.saturating_add(size);
        count += 1;
    }
    count.max(1)
}

fn options_from_args(request: &YaraScanArgs) -> Result<YaraScanOptions, String> {
    let max_file_size = request.max_file_size.unwrap_or(MAX_YARA_FILE_BYTES);
    if max_file_size > MAX_YARA_FILE_BYTES {
        return Err(format!(
            "max_file_size {max_file_size} is above the limit of {MAX_YARA_FILE_BYTES} bytes \
             (each scanned file is read into memory). Ask for at most {MAX_YARA_FILE_BYTES}."
        ));
    }
    let bounded = |name: &str, value: Option<usize>, default: usize, ceiling: usize| {
        let value = value.unwrap_or(default);
        if value == 0 || value > ceiling {
            Err(format!(
                "{name} {value} is out of range: pass a value from 1 to {ceiling}."
            ))
        } else {
            Ok(value)
        }
    };
    let timeout_seconds = request.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    if timeout_seconds == 0 || timeout_seconds > MAX_TIMEOUT_SECONDS {
        return Err(format!(
            "timeout_seconds {timeout_seconds} is out of range: pass a value from 1 to \
             {MAX_TIMEOUT_SECONDS}."
        ));
    }
    Ok(YaraScanOptions {
        recursive: request.recursive.unwrap_or(true),
        max_file_size,
        detailed_matches: request.detailed_matches.unwrap_or(true),
        max_files: bounded(
            "max_files",
            request.max_files,
            DEFAULT_MAX_FILES,
            MAX_FILES_CEILING,
        )?,
        max_matches_per_rule: bounded(
            "max_matches_per_rule",
            request.max_matches_per_rule,
            DEFAULT_MAX_MATCHES_PER_RULE,
            MAX_MATCHES_PER_RULE_CEILING,
        )?,
        max_rules_per_file: bounded(
            "max_rules_per_file",
            request.max_rules_per_file,
            DEFAULT_MAX_RULES_PER_FILE,
            MAX_RULES_PER_FILE_CEILING,
        )?,
        timeout: Duration::from_secs(timeout_seconds),
    })
}

/// Compile the rules once and scan with them; the heavy part of the tool.
fn execute_scan(plan: &ScanPlan) -> Result<YaraScanResult, String> {
    let started = Instant::now();
    let (rules, warnings) = compile_rule_sources_with_warnings(&plan.sources)?;
    let rules_compiled = rules.iter().count();
    let mut scan = scan_path_with_rules(&plan.path, &rules, &plan.options);
    scan.rule_warnings = warnings;
    Ok(summarize(
        scan,
        rules_compiled,
        &plan.options,
        started.elapsed(),
    ))
}

fn summarize(
    scan: CustomYaraScanResult,
    rules_compiled: usize,
    options: &YaraScanOptions,
    elapsed: Duration,
) -> YaraScanResult {
    let mut limits = Vec::new();
    let at_least = if scan.more_files_not_counted {
        "at least "
    } else {
        ""
    };
    if scan.files_not_scanned > 0 {
        if scan.walk_timed_out {
            limits.push(format!(
                "The {} s time budget ran out while walking the directory: {at_least}{} files \
                 were not scanned. Raise timeout_seconds or narrow `path`.",
                options.timeout.as_secs(),
                scan.files_not_scanned
            ));
        } else if scan.timed_out {
            limits.push(format!(
                "The {} s time budget ran out: {at_least}{} files were not scanned. Raise \
                 timeout_seconds, narrow `path`, or simplify the rules.",
                options.timeout.as_secs(),
                scan.files_not_scanned
            ));
        } else {
            limits.push(format!(
                "max_files {} reached: {at_least}{} more files were not scanned (the walk \
                 stops there, so the full count is unknown). Raise max_files or narrow `path`.",
                options.max_files, scan.files_not_scanned
            ));
        }
    } else if scan.timed_out {
        limits.push(format!(
            "A file hit the {} s time budget (see `errors`).",
            options.timeout.as_secs()
        ));
    }
    if scan.detail_trimmed_files > 0 {
        limits.push(format!(
            "The scan kept all the match detail it may hold in memory; {} files list only their \
             first few rule names without strings, tags or metadata (`rules_total` and \
             `rule_hits` are exact). Narrow `path`, lower `max_files`, or turn \
             `detailed_matches` off.",
            scan.detail_trimmed_files
        ));
    }
    let strings_cut = scan
        .matches
        .iter()
        .flat_map(|file| &file.matches)
        .filter(|rule| options.detailed_matches && rule.strings_total > rule.strings.len())
        .count();
    if strings_cut > 0 {
        limits.push(format!(
            "{strings_cut} rule matches list only the first {} strings \
             (max_matches_per_rule); `strings_total` has the full count.",
            options.max_matches_per_rule
        ));
    }
    let rules_cut = scan
        .matches
        .iter()
        .filter(|file| file.rules_total > file.matches.len())
        .count();
    if rules_cut > 0 {
        limits.push(format!(
            "{rules_cut} files list only the first {} matching rules (max_rules_per_file); \
             `rules_total` has the full count.",
            options.max_rules_per_file
        ));
    }
    if scan.skipped_total > scan.skipped.len() {
        limits.push(format!(
            "{} skipped files are named; {} more are only counted in `skipped_total`.",
            scan.skipped.len(),
            scan.skipped_total - scan.skipped.len()
        ));
    }
    YaraScanResult {
        total_files_scanned: scan.total_files_scanned,
        total_matches: scan.total_matches,
        scan_duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        files_matched: scan.files_matched,
        rules_compiled,
        rule_hits: scan.rule_hits,
        matches: scan.matches,
        errors: scan.errors,
        skipped: scan.skipped,
        skipped_total: scan.skipped_total,
        files_not_scanned: scan.files_not_scanned,
        more_files_not_counted: scan.more_files_not_counted,
        timed_out: scan.timed_out,
        rule_warnings: scan.rule_warnings,
        limits_reached: limits,
    }
}

impl FileScannerMcp {
    /// Scan with rule text and the four classic options (the CLI path).
    pub async fn yara_scan_file(
        &self,
        request: YaraScanRequest,
    ) -> Result<Json<YaraScanResult>, String> {
        let path = PathBuf::from(&request.path);
        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.path));
        }
        let max_file_size = request.max_file_size.unwrap_or(MAX_YARA_FILE_BYTES);
        if max_file_size > MAX_YARA_FILE_BYTES {
            return Err(format!(
                "max_file_size {max_file_size} is above the limit of {MAX_YARA_FILE_BYTES} bytes \
                 (each scanned file is read into memory). Ask for at most {MAX_YARA_FILE_BYTES}."
            ));
        }
        let mut sources = Vec::new();
        if request
            .yara_rule
            .trim()
            .eq_ignore_ascii_case(BUILTIN_KEYWORD)
        {
            sources.extend(builtin_rule_sources());
        } else if !request.yara_rule.trim().is_empty() {
            sources.push(("yara_rule".to_string(), request.yara_rule));
        }
        if let Some(rule_path) = request.rule_path.as_deref() {
            sources.extend(load_rule_sources(&PathBuf::from(rule_path))?);
        }
        if sources.is_empty() {
            return Err("No rules given: pass a rule file or rule text.".to_string());
        }
        if request.max_files == Some(0) {
            return Err("max_files must be at least 1.".to_string());
        }
        if request.timeout_seconds == Some(0) {
            return Err("timeout_seconds must be at least 1.".to_string());
        }
        let plan = ScanPlan {
            path,
            sources,
            options: YaraScanOptions {
                recursive: request.recursive.unwrap_or(true),
                max_file_size,
                detailed_matches: request.detailed_matches.unwrap_or(true),
                // Without the flags the command line scans everything.
                max_files: request.max_files.unwrap_or(usize::MAX),
                timeout: Duration::from_secs(request.timeout_seconds.unwrap_or(24 * 60 * 60)),
                ..YaraScanOptions::default()
            },
        };
        let result = tokio::task::spawn_blocking(move || execute_scan(&plan))
            .await
            .map_err(|e| format!("YARA scan task failed: {e}"))??;
        Ok(Json(result))
    }
}

/// Words YARA reserves; a rule cannot be named with one.
const YARA_RESERVED: &[&str] = &[
    "all",
    "and",
    "any",
    "ascii",
    "at",
    "base64",
    "base64wide",
    "condition",
    "contains",
    "defined",
    "endswith",
    "entrypoint",
    "false",
    "filesize",
    "for",
    "fullword",
    "global",
    "icontains",
    "iendswith",
    "iequals",
    "import",
    "in",
    "include",
    "int16",
    "int16be",
    "int32",
    "int32be",
    "int8",
    "int8be",
    "istartswith",
    "matches",
    "meta",
    "nocase",
    "none",
    "not",
    "of",
    "or",
    "private",
    "rule",
    "startswith",
    "strings",
    "them",
    "true",
    "uint16",
    "uint16be",
    "uint32",
    "uint32be",
    "uint8",
    "uint8be",
    "wide",
    "xor",
];

/// A valid YARA rule identifier for a file name: the last path component
/// with every character outside `[A-Za-z0-9_]` replaced by `_`, and a
/// `sample_` prefix when it would start with a digit or is a reserved word.
fn rule_identifier(file_name: &str) -> String {
    let base = file_name
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("");
    let mut name: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if name.is_empty() {
        name = "sample".to_string();
    }
    if name.starts_with(|c: char| c.is_ascii_digit()) || YARA_RESERVED.contains(&name.as_str()) {
        name = format!("sample_{name}");
    }
    name.truncate(120);
    name
}

/// A quoted YARA string literal for `text`: quotes, backslashes and control
/// characters are escaped so the literal always parses.
fn yara_string_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let mut buf = [0u8; 4];
                for byte in c.encode_utf8(&mut buf).bytes() {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The rule text for a digest, with or without the hex header pattern.
fn build_yara_rule(analysis: &LlmFileAnalysisResult, rule_name: &str, with_header: bool) -> String {
    let mut conditions = vec![format!("filesize == {}", analysis.file_size)];
    let mut uses_math = false;

    // Entropy condition when the file looks packed
    if let Some(entropy) = analysis.entropy {
        if entropy > 7.0 {
            uses_math = true;
            conditions.push(format!("math.entropy(0, filesize) > {:.1}", entropy - 0.5));
        }
    }

    // Distinct key strings (a pattern may be declared once)
    let mut strings: Vec<&str> = Vec::new();
    for s in &analysis.key_strings {
        if !s.is_empty() && !strings.contains(&s.as_str()) {
            strings.push(s);
        }
        if strings.len() == 10 {
            break;
        }
    }
    let string_count = strings.len().min(5);
    if string_count > 0 {
        conditions.push(format!("{} of ($s*)", string_count.div_ceil(2)));
    }

    let header = if with_header {
        analysis
            .hex_patterns
            .first()
            .map(|h| h.trim())
            .filter(|h| !h.is_empty())
    } else {
        None
    };
    if header.is_some() {
        conditions.push("$header at 0".to_string());
    }

    let mut rule = String::new();
    if uses_math {
        rule.push_str("import \"math\"\n\n");
    }
    rule.push_str(&format!("rule {rule_name} {{\n"));
    rule.push_str("    meta:\n");
    rule.push_str(&format!("        md5 = \"{}\"\n", analysis.md5));
    // `filesize` is a YARA keyword, so the meta entry is named file_size.
    rule.push_str(&format!("        file_size = {}\n", analysis.file_size));
    if header.is_some() || !strings.is_empty() {
        rule.push_str("    strings:\n");
    }
    if let Some(header) = header {
        rule.push_str(&format!("        $header = {{ {header} }}\n"));
    }
    for (i, s) in strings.iter().enumerate() {
        rule.push_str(&format!(
            "        $s{} = {}\n",
            i + 1,
            yara_string_literal(s)
        ));
    }
    rule.push_str("    condition:\n");
    rule.push_str(&format!("        {}\n", conditions.join(" and ")));
    rule.push_str("}\n");
    rule
}

/// Draft a YARA rule from an `llm_analyze_file` digest.
///
/// The rule is compiled with this server's own engine before it is returned,
/// so it works in `yara_scan_file` as it stands. `Err` carries the reason no
/// rule is offered (the compiler's message). `llm_analyze_file` (in
/// `tools_analyze.rs`) calls this: keep the name and signature.
pub(crate) fn suggest_yara_rule(
    analysis: &LlmFileAnalysisResult,
    file_name: &str,
) -> Result<String, String> {
    let rule_name = rule_identifier(file_name);
    let mut last_error = String::new();
    // A malformed header pattern costs only the header, not the whole rule.
    for with_header in [true, false] {
        if !with_header && analysis.hex_patterns.is_empty() {
            break;
        }
        let rule = build_yara_rule(analysis, &rule_name, with_header);
        match crate::threat_detection::compile_rule_sources(&[(
            "yara_rule_suggestion".to_string(),
            rule.clone(),
        )]) {
            Ok(_) => return Ok(rule),
            Err(message) => last_error = message,
        }
    }
    Err(format!(
        "The drafted rule did not compile in this server's YARA engine, so it was left out: \
         {last_error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_server::yara_scan_files;
    use serde_json::json;
    use std::{fs, io::Write};
    use tempfile::TempDir;

    #[test]
    fn rows_that_fit_stops_at_the_budget_before_any_conversion() {
        use crate::threat_detection::YaraFileMatch;
        let rows: Vec<YaraFileMatch> = (0..300)
            .map(|i| YaraFileMatch {
                file_path: format!("f{i}-{}", "x".repeat(50_000)),
                ..Default::default()
            })
            .collect();
        let take = rows_that_fit(&rows, 0, 500, 80_000);
        assert_eq!(take, 1, "one 50 KB row fits an 80 KB budget, two do not");
        let small: Vec<YaraFileMatch> = (0..300).map(|_| YaraFileMatch::default()).collect();
        assert_eq!(rows_that_fit(&small, 10, 20, 1_000_000), 20);
        assert_eq!(rows_that_fit(&small, 290, 500, 1_000_000), 10);
        assert_eq!(rows_that_fit(&rows, 0, 500, 1), 1);
        let result = YaraScanResult {
            matches: rows,
            ..Default::default()
        };
        let value = reply_value(&result, 0, 500, 80_000, None);
        assert_eq!(value["matches_returned"], 1);
        assert_eq!(value["next_offset"], 1);
    }

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file.bin");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[tokio::test]
    async fn test_yara_scan_files_wrapper() {
        let content = b"this is a test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let rule = r#"
rule TestRule {
    strings:
        $a = "test"
    condition:
        $a
}
"#
        .to_string();

        let request = YaraScanRequest {
            path: file_path.to_string_lossy().to_string(),
            yara_rule: rule,
            rule_path: None,
            recursive: Some(false),
            max_file_size: None,
            detailed_matches: Some(true),
            max_files: None,
            timeout_seconds: None,
        };

        let result = yara_scan_files(request).await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.total_files_scanned, 1);
        assert!(scan.total_matches >= 1);
    }

    #[test]
    fn test_suggest_yara_rule() {
        let analysis = LlmFileAnalysisResult {
            md5: "abc123def456".to_string(),
            file_size: 1024,
            key_strings: vec![
                "suspicious_function".to_string(),
                "malware_string".to_string(),
                "http://evil.com".to_string(),
            ],
            hex_patterns: vec!["4D 5A 90 00".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            opcodes: vec!["E8 00 00 00".to_string()],
            entropy: Some(7.2),
            yara_rule_suggestion: None,
        };

        let yara_rule = suggest_yara_rule(&analysis, "test_malware.exe").unwrap();

        assert!(yara_rule.contains("rule test_malware_exe"));
        assert!(yara_rule.contains("md5 = \"abc123def456\""));
        assert!(yara_rule.contains("file_size = 1024"));
        assert!(yara_rule.starts_with("import \"math\""));
        assert!(yara_rule.contains("$header = { 4D 5A 90 00 }"));
        assert!(yara_rule.contains("$s1 = \"suspicious_function\""));
        assert!(yara_rule.contains("filesize == 1024"));
        assert!(yara_rule.contains("math.entropy"));
    }

    // ---- the drafted rule compiles in this server's own engine

    fn digest(entropy: Option<f64>, strings: &[&str], hex: &[&str]) -> LlmFileAnalysisResult {
        LlmFileAnalysisResult {
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            file_size: 4096,
            key_strings: strings.iter().map(|s| (*s).to_string()).collect(),
            hex_patterns: hex.iter().map(|s| (*s).to_string()).collect(),
            imports: vec![],
            opcodes: vec![],
            entropy,
            yara_rule_suggestion: None,
        }
    }

    fn compiles(rule: &str) -> Result<(), String> {
        crate::threat_detection::compile_rule_sources(&[("t".to_string(), rule.to_string())])
            .map(|_| ())
    }

    #[test]
    fn suggestion_compiles_for_low_and_high_entropy_and_odd_names() {
        let names = [
            "/bin/ls",
            "my sample (copy).bin",
            "lib+tool@2.bin",
            "7zip_like_name.bin",
            "invoice (1) final.bin",
            "all",
            "import",
            "",
            "/tmp/dir with space/üñí.exe",
        ];
        for entropy in [None, Some(3.2), Some(7.99)] {
            for name in names {
                let analysis = digest(
                    entropy,
                    &[
                        "plain text",
                        "has \"quote\" and \\ slash",
                        "line\nbreak\ttab",
                    ],
                    &["7F 45 4C 46"],
                );
                let rule = suggest_yara_rule(&analysis, name)
                    .unwrap_or_else(|e| panic!("{name} {entropy:?}: {e}"));
                compiles(&rule).unwrap_or_else(|e| panic!("{name} {entropy:?}: {e}\n{rule}"));
                assert_eq!(rule.contains("import \"math\""), entropy == Some(7.99));
                assert!(!rule.contains("\n        filesize = "), "{rule}");
            }
        }
    }

    #[test]
    fn suggestion_without_strings_or_header_compiles() {
        let rule = suggest_yara_rule(&digest(None, &[], &[]), "empty.bin").unwrap();
        compiles(&rule).unwrap();
    }

    #[test]
    fn a_malformed_header_pattern_costs_only_the_header() {
        let rule =
            suggest_yara_rule(&digest(None, &["abc def"], &["not hex at all"]), "x.bin").unwrap();
        assert!(!rule.contains("$header"), "{rule}");
        compiles(&rule).unwrap();
    }

    #[test]
    fn rule_identifiers_are_valid() {
        assert_eq!(rule_identifier("test_malware.exe"), "test_malware_exe");
        assert_eq!(rule_identifier("/a/b/7z.bin"), "sample_7z_bin");
        assert_eq!(rule_identifier("a b (1).bin"), "a_b__1__bin");
        assert_eq!(rule_identifier("rule"), "sample_rule");
        assert_eq!(rule_identifier(""), "sample");
        assert!(rule_identifier(&"x".repeat(500)).len() <= 120);
    }

    /// The suggestion for every binary in test_programs/ compiles, and the
    /// scanner then finds the very file it was drafted from.
    #[tokio::test]
    async fn suggestion_compiles_and_matches_for_every_test_program_binary() {
        use crate::mcp_server::LlmFileAnalysisRequest;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs");
        let mut binaries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with("_binary"))
            })
            .collect();
        binaries.sort();
        assert!(
            !binaries.is_empty(),
            "no *_binary files in {}",
            dir.display()
        );

        let mcp = FileScannerMcp::new();
        for binary in binaries {
            let analysis = mcp
                .llm_analyze_file(LlmFileAnalysisRequest {
                    file_path: binary.to_string_lossy().into_owned(),
                    token_limit: None,
                    min_string_length: None,
                    max_strings: None,
                    max_imports: None,
                    max_opcodes: None,
                    hex_pattern_size: None,
                    suggest_yara_rule: Some(true),
                })
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", binary.display()))
                .0;
            let rule = analysis
                .yara_rule_suggestion
                .unwrap_or_else(|| panic!("{}: no suggestion", binary.display()));
            compiles(&rule).unwrap_or_else(|e| panic!("{}: {e}\n{rule}", binary.display()));

            let scan = execute_scan(&ScanPlan {
                path: binary.clone(),
                sources: vec![("suggestion".to_string(), rule)],
                options: YaraScanOptions::default(),
            })
            .unwrap();
            assert_eq!(scan.total_matches, 1, "{}", binary.display());
        }
    }

    // ---- the tool

    /// The kept scan is one process-wide entry, so calls are serialized to
    /// keep one test's scan from evicting another's.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn call(mcp: &FileScannerMcp, args: serde_json::Value) -> (bool, Value) {
        let _serial = SERIAL.lock().await;
        call_unlocked(mcp, args).await
    }

    async fn call_unlocked(mcp: &FileScannerMcp, args: serde_json::Value) -> (bool, Value) {
        let args = args.as_object().unwrap().clone();
        let result = mcp.run_yara_scan(args).await;
        let value = serde_json::to_value(&result).unwrap();
        let text = value["content"][0]["text"].as_str().unwrap().to_string();
        let is_error = value["isError"] == true;
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (is_error, body)
    }

    fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn a_rule_that_does_not_compile_is_an_error_with_the_compiler_message() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.bin", b"data");
        let mcp = FileScannerMcp::new();
        for (rule, expect) in [
            ("rule t { condition: $a }", "$a"),
            ("rule t { strings: $a = \"x\" condition: $b }", "$b"),
            (
                "rule t { condition: math.entropy(0, filesize) > 1 }",
                "math",
            ),
            ("rule t { condition: true", "t"),
        ] {
            let (is_error, body) = call(&mcp, json!({"path": file, "yara_rule": rule})).await;
            assert!(is_error, "{rule}: {body}");
            let text = body.as_str().unwrap();
            assert!(text.contains("Failed to compile YARA rule"), "{text}");
            assert!(text.contains(expect), "{rule}: {text}");
            assert!(text.len() > 60, "{text}");
        }
    }

    #[tokio::test]
    async fn rules_are_required_and_unknown_arguments_are_rejected() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.bin", b"data");
        let mcp = FileScannerMcp::new();
        let (is_error, body) = call(&mcp, json!({"path": file})).await;
        assert!(
            is_error && body.as_str().unwrap().contains("No rules given"),
            "{body}"
        );
        let (is_error, body) = call(&mcp, json!({"path": file, "yara_rule": "  "})).await;
        assert!(
            is_error && body.as_str().unwrap().contains("No rules given"),
            "{body}"
        );
        let (is_error, body) = call(
            &mcp,
            json!({"path": file, "yara_rule": "rule t { condition: true }", "rule_file": "x"}),
        )
        .await;
        assert!(
            is_error && body.as_str().unwrap().contains("rule_file"),
            "{body}"
        );
        let (is_error, body) = call(
            &mcp,
            json!({"path": file, "yara_rule": "rule t { condition: true }", "max_files": 0}),
        )
        .await;
        assert!(
            is_error && body.as_str().unwrap().contains("max_files"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn rules_from_a_file_a_directory_and_the_builtin_set() {
        let dir = TempDir::new().unwrap();
        let target = write(
            dir.path(),
            "sample.txt",
            b"Your files have been encrypted. Please pay the ransom in Bitcoin.",
        );
        let rules = TempDir::new().unwrap();
        let one = write(
            rules.path(),
            "one.yar",
            b"rule from_file : filetag { strings: $a = \"ransom\" condition: $a }",
        );
        write(
            rules.path(),
            "two.yara",
            b"rule from_dir { strings: $a = \"Bitcoin\" condition: $a }",
        );
        write(rules.path(), "notes.txt", b"this is not a rule");
        let mcp = FileScannerMcp::new();

        let (err, body) = call(&mcp, json!({"path": target, "rule_path": one})).await;
        assert!(!err, "{body}");
        assert_eq!(body["total_matches"], 1);
        assert_eq!(
            body["matches"][0]["matches"][0]["rule_identifier"],
            "from_file"
        );
        assert_eq!(body["matches"][0]["matches"][0]["tags"][0], "filetag");

        let (err, body) = call(&mcp, json!({"path": target, "rule_path": rules.path()})).await;
        assert!(!err, "{body}");
        assert_eq!(body["rules_compiled"], 2);
        assert_eq!(body["total_matches"], 2);

        let (err, body) = call(&mcp, json!({"path": target, "yara_rule": "builtin"})).await;
        assert!(!err, "{body}");
        let ids: Vec<&str> = body["matches"][0]["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["rule_identifier"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"ransomware_indicators"), "{ids:?}");
        assert_eq!(body["rule_hits"][0]["files"], 1);

        // Inline text and a file together.
        let (err, body) = call(
            &mcp,
            json!({"path": target, "rule_path": one,
                   "yara_rule": "rule inline_rule { condition: true }"}),
        )
        .await;
        assert!(!err, "{body}");
        assert_eq!(body["total_matches"], 2);

        // A directory without rules, and a rule file that does not compile.
        let empty = TempDir::new().unwrap();
        let (err, body) = call(&mcp, json!({"path": target, "rule_path": empty.path()})).await;
        assert!(err && body.as_str().unwrap().contains("no .yar"), "{body}");
        let bad = write(empty.path(), "bad.yar", b"rule bad { condition: nope }");
        let (err, body) = call(&mcp, json!({"path": target, "rule_path": bad})).await;
        let text = body.as_str().unwrap();
        assert!(
            err && text.contains("bad.yar") && text.contains("nope"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn includes_are_not_followed() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.bin", b"data");
        let other = write(dir.path(), "other.yar", b"rule other { condition: true }");
        let mcp = FileScannerMcp::new();
        let rule = format!("include \"{}\"", other.display());
        let (is_error, body) = call(&mcp, json!({"path": file, "yara_rule": rule})).await;
        assert!(is_error, "{body}");
    }

    #[tokio::test]
    async fn tags_and_matched_bytes_of_hex_patterns_are_returned() {
        let dir = TempDir::new().unwrap();
        let file = write(
            dir.path(),
            "bin.dat",
            &[
                0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0xFF, 0xFE, 0x22,
            ],
        );
        let rule = "rule hexy : testtag secondtag { strings: $h = { DE AD BE EF 00 01 FF FE } \
                    condition: $h }";
        let (err, body) = call(&mcp(), json!({"path": file, "yara_rule": rule})).await;
        assert!(!err, "{body}");
        let m = &body["matches"][0]["matches"][0];
        assert_eq!(m["tags"], json!(["testtag", "secondtag"]));
        assert_eq!(m["strings"][0]["offset"], 2);
        assert_eq!(m["strings"][0]["length"], 8);
        assert_eq!(m["strings"][0]["hex"], "DE AD BE EF 00 01 FF FE");
        assert!(m["strings"][0].get("value").is_none(), "{m}");
        assert_eq!(m["strings_total"], 1);
    }

    fn mcp() -> FileScannerMcp {
        FileScannerMcp::new()
    }

    #[tokio::test]
    async fn listed_matches_are_capped_and_the_totals_are_reported() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "many.bin", &vec![b'a'; 5000]);
        let rule = "rule many { strings: $a = \"a\" condition: $a }";
        let (err, body) = call(&mcp(), json!({"path": file, "yara_rule": rule})).await;
        assert!(!err, "{body}");
        let m = &body["matches"][0]["matches"][0];
        assert_eq!(m["strings"].as_array().unwrap().len(), 10);
        assert_eq!(m["strings_total"], 5000);
        assert!(
            body["limits_reached"][0]
                .as_str()
                .unwrap()
                .contains("max_matches_per_rule"),
            "{body}"
        );
        // The reply is small even though the rule hit 5000 times.
        assert!(body.to_string().len() < 5000, "{}", body.to_string().len());

        let (_, body) = call(
            &mcp(),
            json!({"path": file, "yara_rule": rule, "max_matches_per_rule": 3}),
        )
        .await;
        assert_eq!(
            body["matches"][0]["matches"][0]["strings"]
                .as_array()
                .unwrap()
                .len(),
            3
        );

        let (_, body) = call(
            &mcp(),
            json!({"path": file, "yara_rule": rule, "detailed_matches": false}),
        )
        .await;
        let m = &body["matches"][0]["matches"][0];
        assert_eq!(m["strings"].as_array().unwrap().len(), 0);
        assert_eq!(m["strings_total"], 5000);
        assert!(body
            .get("limits_reached")
            .is_none_or(|l| l.as_array().unwrap().is_empty()));
    }

    #[tokio::test]
    async fn rules_per_file_are_capped() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.bin", b"x");
        let rules: String = (0..5)
            .map(|i| format!("rule r{i} {{ condition: true }}\n"))
            .collect();
        let (_, body) = call(
            &mcp(),
            json!({"path": file, "yara_rule": rules, "max_rules_per_file": 2}),
        )
        .await;
        assert_eq!(body["matches"][0]["matches"].as_array().unwrap().len(), 2);
        assert_eq!(body["matches"][0]["rules_total"], 5);
        assert_eq!(body["total_matches"], 5);
        assert!(body["limits_reached"][0]
            .as_str()
            .unwrap()
            .contains("max_rules_per_file"));
    }

    #[tokio::test]
    async fn file_count_is_capped_and_the_summary_comes_first_with_paged_matches() {
        let dir = TempDir::new().unwrap();
        for i in 0..8 {
            write(dir.path(), &format!("f{i}.txt"), b"hello");
        }
        let rule = "rule hello { strings: $a = \"hello\" condition: $a }";
        let (_, body) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": rule, "max_files": 5, "limit": 2}),
        )
        .await;
        assert_eq!(body["total_files_scanned"], 5);
        assert_eq!(body["files_not_scanned"], 1);
        assert_eq!(body["more_files_not_counted"], true);
        assert_eq!(body["files_matched"], 5);
        assert_eq!(body["matches"].as_array().unwrap().len(), 2);
        assert_eq!(body["matches_total"], 5);
        assert_eq!(body["next_offset"], 2);
        assert_eq!(body["rule_hits"][0], json!({"rule": "hello", "files": 5}));
        assert!(body["limits_reached"][0]
            .as_str()
            .unwrap()
            .contains("max_files"));

        let (_, page2) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": rule, "max_files": 5, "limit": 2,
                   "offset": 4}),
        )
        .await;
        assert_eq!(page2["matches"].as_array().unwrap().len(), 1);
        assert!(page2.get("next_offset").is_none());
    }

    #[tokio::test]
    async fn later_pages_come_from_one_kept_scan_and_the_cache_gets_only_pages() {
        let dir = TempDir::new().unwrap();
        for i in 0..30 {
            write(dir.path(), &format!("f{i:02}.txt"), b"hello hello hello");
        }
        let rule = "rule hello_pages_store_test { strings: $a = \"hello\" condition: $a }";
        let server = mcp();
        let mut seen = Vec::new();
        let mut hits = 0;
        let mut offset = 0;
        let _serial = SERIAL.lock().await;
        loop {
            let (_, body) = call_unlocked(
                &server,
                json!({"path": dir.path(), "yara_rule": rule, "limit": 7, "offset": offset}),
            )
            .await;
            if offset > 0 && body["cache"] == "hit" {
                hits += 1;
            }
            for m in body["matches"].as_array().unwrap() {
                seen.push(m["file_path"].as_str().unwrap().to_string());
            }
            match body.get("next_offset").and_then(Value::as_u64) {
                Some(next) => offset = next as usize,
                None => break,
            }
        }
        assert_eq!(seen.len(), 30);
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 30);
        // 30 files at 7 per page: pages 2 to 5 all come from the first call's scan.
        assert_eq!(hits, 4, "later pages must be served from the kept scan");
    }

    #[tokio::test]
    async fn a_byte_cut_page_reports_what_it_lists_and_keeps_the_summary() {
        let dir = TempDir::new().unwrap();
        for i in 0..60 {
            write(
                dir.path(),
                &format!("a_long_file_name_to_fill_the_page_{i:03}.txt"),
                b"hello",
            );
        }
        let rule = "rule hello_cut { strings: $a = \"hello\" condition: $a }";
        let (_, body) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": rule, "limit": 60, "max_files": 50,
                   "max_output_bytes": 4000}),
        )
        .await;
        let listed = body["matches"].as_array().unwrap().len();
        assert!(listed > 0 && listed < 50, "{listed}");
        assert_eq!(body["matches_returned"], listed);
        assert_eq!(body["next_offset"], listed);
        assert_eq!(body["matches_total"], 50);
        // The summary survives the cut.
        assert_eq!(body["total_files_scanned"], 50);
        assert_eq!(body["rule_hits"][0]["rule"], "hello_cut");
        assert!(body["limits_reached"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("max_files")));
        // Following next_offset skips no file.
        let (_, next) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": rule, "limit": 60, "max_files": 50,
                   "max_output_bytes": 4000, "offset": listed}),
        )
        .await;
        assert_eq!(
            next["matches"][0]["file_path"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap(),
            format!("a_long_file_name_to_fill_the_page_{listed:03}.txt")
        );
    }

    #[tokio::test]
    async fn rule_text_that_is_a_path_gets_a_hint_and_an_unreadable_file_is_an_error() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.bin", b"x");
        let rule_file = write(dir.path(), "r.yar", b"rule t { condition: true }");
        let (is_error, body) = call(
            &mcp(),
            json!({"path": file, "yara_rule": rule_file.to_string_lossy()}),
        )
        .await;
        assert!(is_error);
        assert!(body.to_string().contains("rule_path"), "{body}");

        // The hint is decided from the text alone: a name that exists in the
        // working directory and one that does not give the same error.
        let (_, existing) = call(&mcp(), json!({"path": file, "yara_rule": "Cargo.toml"})).await;
        let (_, missing) = call(&mcp(), json!({"path": file, "yara_rule": "Cargo.nope"})).await;
        assert_eq!(
            existing.to_string().replace("Cargo.toml", "X"),
            missing.to_string().replace("Cargo.nope", "X")
        );
        assert!(!existing.to_string().contains("rule_path"), "{existing}");

        // A file the process may not read is an error, not an empty result.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = write(dir.path(), "locked.bin", b"secret");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let readable = std::fs::read(&locked).is_ok(); // root ignores the mode
            let (is_error, body) = call(
                &mcp(),
                json!({"path": locked, "yara_rule": "rule t { condition: true }"}),
            )
            .await;
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
            if !readable {
                assert!(is_error, "{body}");
            }
        }
    }

    #[tokio::test]
    async fn a_first_call_always_scans_again_and_sees_changes_in_subdirectories() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        write(dir.path(), "a.txt", b"nothing");
        write(&dir.path().join("sub"), "b.txt", b"nothing");
        let rule = "rule stale_probe_marker { strings: $a = \"EVILMARKER\" condition: $a }";
        let args = json!({"path": dir.path(), "yara_rule": rule});
        let (_, first) = call(&mcp(), args.clone()).await;
        assert_eq!(first["files_matched"], 0);
        write(&dir.path().join("sub"), "new.txt", b"EVILMARKER");
        let (_, second) = call(&mcp(), args).await;
        assert_eq!(second["cache"], "miss", "{second}");
        assert_eq!(second["files_matched"], 1, "{second}");
    }

    #[tokio::test]
    async fn match_detail_is_bounded_and_the_result_says_when_it_was_dropped() {
        let dir = TempDir::new().unwrap();
        for i in 0..2500 {
            write(dir.path(), &format!("f{i:05}.txt"), b"aaaa bbbb");
        }
        let rules: String = (0..100)
            .map(|i| format!("rule budget_r{i} {{ strings: $a = \"aa\" condition: $a }}\n"))
            .collect();
        let (is_error, body) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": rules, "max_rules_per_file": 100}),
        )
        .await;
        assert!(!is_error, "{body}");
        assert_eq!(body["files_matched"], 2500);
        // Counts stay exact while the detail of later files is cut.
        assert_eq!(body["rule_hits"][0]["files"], 2500);
        assert!(
            body["limits_reached"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l.as_str().unwrap().contains("match detail")),
            "{body}"
        );
    }

    #[tokio::test]
    async fn oversize_and_unreadable_files_are_reported_as_skipped() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "small.txt", b"hi");
        write(dir.path(), "big.txt", &[b'x'; 64]);
        let (_, body) = call(
            &mcp(),
            json!({"path": dir.path(), "yara_rule": "rule t { condition: true }",
                   "max_file_size": 10}),
        )
        .await;
        assert_eq!(body["total_files_scanned"], 1);
        assert_eq!(body["skipped_total"], 1);
        let skipped = &body["skipped"][0];
        assert!(skipped["file_path"].as_str().unwrap().ends_with("big.txt"));
        assert!(skipped["reason"]
            .as_str()
            .unwrap()
            .contains("max_file_size"));

        // A file the process may not read is an error entry, not a silent drop.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = write(dir.path(), "locked.txt", b"secret");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let readable = std::fs::read(&locked).is_ok(); // root ignores the mode
            let (_, body) = call(
                &mcp(),
                json!({"path": dir.path(), "yara_rule": "rule t { condition: true }"}),
            )
            .await;
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
            if !readable {
                let errors = body["errors"].as_array().unwrap();
                assert!(
                    errors
                        .iter()
                        .any(|e| e["file_path"].as_str().unwrap().ends_with("locked.txt")),
                    "{body}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_slow_rule_is_stopped_by_the_timeout() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "big.bin", &vec![7u8; 400_000]);
        let rule = "rule slow { condition: for any i in (0..filesize) : (for any j in \
                    (0..filesize) : (uint8(i) != uint8(j))) }";
        let started = Instant::now();
        let (err, body) = call(
            &mcp(),
            json!({"path": file, "yara_rule": rule, "timeout_seconds": 1}),
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "timeout was not applied"
        );
        assert!(!err, "{body}");
        assert_eq!(body["timed_out"], true, "{body}");
        assert!(
            body["errors"][0]["error"]
                .as_str()
                .unwrap()
                .contains("timed out"),
            "{body}"
        );
        assert!(
            body["limits_reached"][0]
                .as_str()
                .unwrap()
                .contains("time budget"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn many_small_files_share_one_compiled_rule_set() {
        let dir = TempDir::new().unwrap();
        for i in 0..1500 {
            write(dir.path(), &format!("f{i:04}.txt"), b"needle in a haystack");
        }
        let rule = "rule needle { strings: $a = \"needle\" condition: $a }";
        let (err, body) = call(&mcp(), json!({"path": dir.path(), "yara_rule": rule})).await;
        assert!(!err, "{body}");
        assert_eq!(body["total_files_scanned"], 1500);
        assert_eq!(body["files_matched"], 1500);
        assert_eq!(body["total_matches"], 1500);
    }

    #[tokio::test]
    async fn a_scan_finds_a_match_the_old_one_listed_with_matches_as_an_array() {
        let dir = TempDir::new().unwrap();
        let file = write(dir.path(), "a.txt", b"plain text");
        let rule = r#"rule has_text { strings: $a = "plain text" condition: $a }"#;
        let (_, body) = call(&mcp(), json!({"path": dir.path(), "yara_rule": rule})).await;
        assert_eq!(body["total_matches"], 1);
        assert_eq!(
            body["matches"][0]["file_path"],
            file.to_string_lossy().as_ref()
        );
        assert_eq!(
            body["matches"][0]["matches"][0]["strings"][0]["value"],
            "plain text"
        );
    }

    #[test]
    fn the_advertised_schema_lists_every_argument_and_requires_only_the_path() {
        let tools = FileScannerMcp::new().tool_definitions();
        let tool = tools.iter().find(|t| t.name == "yara_scan_file").unwrap();
        let schema = Value::Object((*tool.input_schema).clone());
        let properties = schema["properties"].as_object().unwrap();
        for name in [
            "path",
            "yara_rule",
            "rule_path",
            "recursive",
            "max_file_size",
            "detailed_matches",
            "max_matches_per_rule",
            "max_rules_per_file",
            "max_files",
            "timeout_seconds",
            "offset",
            "limit",
            "max_output_bytes",
        ] {
            assert!(properties.contains_key(name), "missing {name}: {schema}");
        }
        assert_eq!(schema["required"], json!(["path"]), "{schema}");
        let description = tool.description.as_deref().unwrap();
        assert!(description.contains("builtin") && description.contains("rule_path"));
    }
}
