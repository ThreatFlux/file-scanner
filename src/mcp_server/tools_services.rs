//! Cross-file string search and cache management over MCP.
//!
//! `search_strings` and `string_details` answer "where does this string occur"
//! from the string tracker (every file indexed this session) or from one
//! file's cached string index; `cache_status` shows what the caches hold and
//! `cache_clear` (the one destructive tool) forgets it. Every list is paged and
//! every answer stays under the output budget (PRINCIPLE: overview first,
//! targeted drill-down second).

use std::{collections::HashMap, io::Read, path::Path, sync::Arc, time::Instant};

use rmcp::{
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    cache::{CacheSearchQuery, EntrySummary},
    string_tracker_compat::{StringContext, StringEntry, StringTracker},
};

use super::{
    output::{
        fit_rows, input_schema_with_budget, page, parse_request, respond, respond_result,
        tool_error, PageArgs,
    },
    paths::Expect,
    state::ServerState,
    FileScannerMcp,
};

/// Bytes of a file the string index reads (the rest is reported as not scanned).
pub const MAX_INDEX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
/// Most strings one file's index keeps.
pub const MAX_INDEX_STRINGS: usize = 200_000;
/// Longest string value kept in an index (longer ones are cut).
pub const MAX_INDEXED_VALUE_CHARS: usize = 2_000;
/// Longest value shown in a result (longer ones are cut, `value_cut: true`).
const MAX_SHOWN_VALUE_CHARS: usize = 400;
/// Offsets listed per string.
const MAX_OFFSETS_SHOWN: usize = 5;
/// Files listed per string in a session search.
const MAX_FILES_SHOWN: usize = 5;
/// Candidates a session search inspects before paging.
const MAX_SESSION_MATCHES: usize = 5_000;
/// Distinct strings a classification filter inspects in one file.
const MAX_CLASSIFIED: usize = 20_000;
/// Smallest and largest `min_length`, and the default.
const MIN_LEN_RANGE: (usize, usize) = (2, 256);
const DEFAULT_MIN_LEN: usize = 4;

const SEARCH_STRINGS_DESCRIPTION: &str = "Search strings. With `file_path`, searches that \
file's strings (extracted and cached on the first call, so later searches are instant) and \
reports each match's offset; without it, searches every string indexed this session across all \
analyzed files. Pass at least one of `query` (case-insensitive substring), `regex`, `category`, \
`min_entropy` or `suspicious_only`: the tool never lists every string. Results are paged \
(`offset`, `limit`; `next_offset` asks for the next page). Follow up with `string_details` for \
the files and offsets a string occurs at (the most recent occurrences only for very common strings). Strings are tracked from `analyze_file` (strings: true) \
and from this tool.";

const STRING_DETAILS_DESCRIPTION: &str = "Everything known about one exact string value: its \
total occurrences, the files (path, hash, offsets) it was found in, categories, entropy, whether it \
is suspicious, and related strings. Find values with `search_strings` first. Files are paged \
(`offset`, `limit`).";

const CACHE_STATUS_DESCRIPTION: &str = "Show what the caches hold. action `stats` (default): \
sizes, bounds, hit-relevant counts and where the cache lives. action `list`: past tool calls \
(newest first, paged, without their results), optionally filtered by `tool_name` or \
`file_path_pattern`. action `search`: like `list` but at least one filter is required. Use \
`analyze_file` with the same arguments to get a cached result back; use `cache_clear` to forget.";

const CACHE_CLEAR_DESCRIPTION: &str = "DESTRUCTIVE: forget cached analyses (the call history, \
the cached sections and the files on disk) and/or the tracked strings. `scope`: `all` (default), \
`analysis` or `strings`. Later calls recompute and re-index. Nothing else is deleted.";

#[tool_router(router = services_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "search_strings",
        title = "Search strings",
        description = SEARCH_STRINGS_DESCRIPTION,
        input_schema = input_schema_with_budget::<SearchStringsRequest>(),
        annotations(
            title = "Search strings",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn search_strings_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_search_strings(args).await)
    }

    #[tool(
        name = "string_details",
        title = "String details",
        description = STRING_DETAILS_DESCRIPTION,
        input_schema = input_schema_with_budget::<StringDetailsRequest>(),
        annotations(
            title = "String details",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn string_details_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_string_details(args).await)
    }

    #[tool(
        name = "cache_status",
        title = "Cache status",
        description = CACHE_STATUS_DESCRIPTION,
        input_schema = input_schema_with_budget::<CacheStatusRequest>(),
        annotations(
            title = "Cache status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn cache_status_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_cache_status(args).await)
    }

    #[tool(
        name = "cache_clear",
        title = "Clear caches",
        description = CACHE_CLEAR_DESCRIPTION,
        input_schema = input_schema_with_budget::<CacheClearRequest>(),
        annotations(
            title = "Clear caches",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn cache_clear_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_cache_clear(args).await)
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchStringsRequest {
    #[schemars(description = "Case-insensitive substring to look for")]
    pub query: Option<String>,
    #[schemars(description = "Regular expression (Rust syntax) matched against each string")]
    pub regex: Option<String>,
    #[schemars(
        description = "Absolute path of one file to search (its strings are extracted and cached \
                       on first use). Omit to search every string indexed this session"
    )]
    pub file_path: Option<String>,
    #[schemars(
        description = "Keep strings of this category (for example network, command, execution, \
                       crypto, encoding, path, credential, registry, malware, surveillance)"
    )]
    pub category: Option<String>,
    #[schemars(description = "Keep strings whose Shannon entropy is at least this")]
    pub min_entropy: Option<f64>,
    #[schemars(description = "Keep only strings flagged suspicious")]
    pub suspicious_only: Option<bool>,
    #[schemars(description = "With file_path: shortest string to extract (2 to 256, default 4)")]
    pub min_length: Option<usize>,
    #[schemars(description = "Number of matches to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Matches to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StringDetailsRequest {
    #[schemars(description = "The exact string value (as returned by search_strings)")]
    pub value: String,
    #[schemars(description = "Related strings to list (default 10, at most 50)")]
    pub related_limit: Option<usize>,
    #[schemars(description = "Files to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Files to list (default 50, at most 500)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CacheAction {
    /// Sizes, bounds and location.
    #[default]
    Stats,
    /// Past tool calls, newest first.
    List,
    /// Past tool calls matching a filter.
    Search,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheStatusRequest {
    #[schemars(description = "stats (default), list or search")]
    pub action: Option<CacheAction>,
    #[schemars(description = "list/search: only calls of this tool (for example analyze_file)")]
    pub tool_name: Option<String>,
    #[schemars(description = "list/search: only files whose path contains this text")]
    pub file_path_pattern: Option<String>,
    #[schemars(description = "list/search: calls to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "list/search: calls to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClearScope {
    /// Analysis history, cached sections and the files on disk, and tracked strings.
    #[default]
    All,
    /// Analysis history, cached sections and the files on disk.
    Analysis,
    /// Tracked strings only.
    Strings,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheClearRequest {
    #[schemars(description = "all (default), analysis or strings")]
    pub scope: Option<ClearScope>,
}

// ---------------------------------------------------------------------------
// String index of one file
// ---------------------------------------------------------------------------

/// Most bytes of string values one index keeps in all (a file of many
/// 2,000-character strings would otherwise need gigabytes).
const MAX_INDEX_VALUE_BYTES: usize = 32 * 1024 * 1024;
/// Bytes read from the file at a time.
const SCAN_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// What one pass over the bytes collects: the strings in offset order, with
/// the limits that stop it.
struct Collected {
    found: Vec<(usize, u8, String)>,
    value_bytes: usize,
    /// Strings that were left out because a limit was reached.
    capped: bool,
    /// Values cut at MAX_INDEXED_VALUE_CHARS.
    cut: usize,
}

impl Collected {
    fn push(&mut self, offset: usize, encoding: u8, text: String, cut: bool) {
        if self.capped {
            return;
        }
        if self.found.len() >= MAX_INDEX_STRINGS
            || self.value_bytes + text.len() > MAX_INDEX_VALUE_BYTES
        {
            self.capped = true;
            return;
        }
        self.value_bytes += text.len();
        self.cut += usize::from(cut);
        self.found.push((offset, encoding, text));
    }
}

fn printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

/// A run of printable bytes being read: its start, its full length and the
/// text kept (at most MAX_INDEXED_VALUE_CHARS characters).
struct Run {
    start: usize,
    len: usize,
    text: String,
}

impl Run {
    fn new(start: usize) -> Self {
        Self {
            start,
            len: 0,
            text: String::new(),
        }
    }

    fn add(&mut self, byte: u8) {
        self.len += 1;
        if self.text.len() < MAX_INDEXED_VALUE_CHARS {
            self.text.push(char::from(byte));
        }
    }

    fn finish(self, min_len: usize, encoding: u8, into: &mut Collected) {
        if self.len >= min_len {
            into.push(
                self.start,
                encoding,
                self.text,
                self.len > MAX_INDEXED_VALUE_CHARS,
            );
        }
    }
}

/// Strings of a file with their offsets: ASCII runs and UTF-16LE runs of
/// printable characters, at least `min_len` long, in file order. Returns the
/// JSON value kept in the section cache. The file is read in chunks and each
/// pass stops collecting at the limits, so memory does not grow with the
/// number of strings in the file.
fn build_string_index(path: &Path, min_len: usize) -> Result<Value, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let file_size = file.metadata().map_or(0, |m| m.len());
    let read_error = |error: std::io::Error| format!("Cannot read {}: {error}", path.display());

    let mut ascii = Collected {
        found: Vec::new(),
        value_bytes: 0,
        capped: false,
        cut: 0,
    };
    let mut wide = Collected {
        found: Vec::new(),
        value_bytes: 0,
        capped: false,
        cut: 0,
    };
    let mut ascii_run: Option<Run> = None;
    let mut wide_run: Option<Run> = None;
    // `buffer` holds the bytes not yet processed: at most one byte carried
    // over from the previous chunk (the UTF-16 pass looks one byte ahead).
    let mut buffer: Vec<u8> = Vec::with_capacity(SCAN_CHUNK_BYTES + 1);
    let mut buffer_start = 0usize; // file offset of buffer[0]
    let mut scanned = 0u64;
    let mut chunk = vec![0u8; SCAN_CHUNK_BYTES];
    let mut eof = false;
    while !eof {
        // Both passes stop when both have hit a limit.
        if ascii.capped && wide.capped {
            break;
        }
        let want = usize::try_from((MAX_INDEX_SCAN_BYTES - scanned).min(SCAN_CHUNK_BYTES as u64))
            .unwrap_or(SCAN_CHUNK_BYTES);
        let got = if want == 0 {
            0
        } else {
            read_full(&mut file, &mut chunk[..want]).map_err(read_error)?
        };
        scanned += got as u64;
        eof = got < want || want == 0;
        // Bytes carried over were seen by the ASCII pass already.
        let carried = buffer.len();
        buffer.extend_from_slice(&chunk[..got]);

        // The ASCII pass handles every byte of the buffer.
        if !ascii.capped {
            for (i, &byte) in buffer.iter().enumerate().skip(carried) {
                if printable(byte) {
                    ascii_run
                        .get_or_insert_with(|| Run::new(buffer_start + i))
                        .add(byte);
                } else if let Some(run) = ascii_run.take() {
                    run.finish(min_len, 0, &mut ascii);
                }
            }
        } else {
            ascii_run = None;
        }

        // The UTF-16 pass pairs a byte with the next one, so the last byte
        // waits for the next chunk (unless the file ended).
        let mut i = 0;
        let limit = if eof {
            buffer.len()
        } else {
            buffer.len().saturating_sub(1)
        };
        while !wide.capped && i < limit {
            let pair = i + 1 < buffer.len() && printable(buffer[i]) && buffer[i + 1] == 0;
            if pair {
                wide_run
                    .get_or_insert_with(|| Run::new(buffer_start + i))
                    .add(buffer[i]);
                i += 2;
            } else {
                if let Some(run) = wide_run.take() {
                    run.finish(min_len, 1, &mut wide);
                }
                i += 1;
            }
        }
        // A pair straddling the end of the processed part: i may point past
        // `limit` by one after a two-byte step; carry what is left.
        let mut consumed = i.min(buffer.len());
        if wide.capped {
            // The UTF-16 pass stopped: the ASCII pass already read every
            // byte of the buffer, so nothing needs to be kept.
            wide_run = None;
            consumed = buffer.len();
        }
        buffer.drain(..consumed);
        buffer_start += consumed;
    }
    if let Some(run) = ascii_run.take() {
        run.finish(min_len, 0, &mut ascii);
    }
    if let Some(run) = wide_run.take() {
        run.finish(min_len, 1, &mut wide);
    }

    let mut index_truncated = ascii.capped || wide.capped;
    let values_cut = ascii.cut + wide.cut;
    let mut found = ascii.found;
    found.extend(wide.found);
    found.sort_by_key(|(offset, encoding, _)| (*offset, *encoding));
    if found.len() > MAX_INDEX_STRINGS {
        // Two passes under their own caps can add up to more than the cap.
        found.truncate(MAX_INDEX_STRINGS);
        index_truncated = true;
    }
    let strings: Vec<Value> = found
        .into_iter()
        .map(|(offset, encoding, value)| json!([offset, encoding, value]))
        .collect();
    Ok(json!({
        "file_size": file_size,
        "scanned_bytes": scanned,
        "index_truncated": index_truncated,
        "values_cut": values_cut,
        "min_length": min_len,
        "strings": strings,
    }))
}

/// Read until `buf` is full or the file ends; returns the bytes read.
fn read_full(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Offsets kept per value when `analyze_file` feeds the tracker (the
/// `string_details` answer shows at most ten per file).
const MAX_OFFSETS_TRACKED: usize = 10;

/// Feed the strings `analyze_file` found to the tracker with their offsets.
///
/// The file's string index (the one `search_strings` builds, at the default
/// minimum length, cached under the same key) supplies the offsets. A string
/// the index does not hold (shorter than the minimum, or beyond the index's
/// scan and count limits) is tracked without an offset, and `string_details`
/// says so for that file. Returns the tracker's error for values outside its
/// bounds, as `track_strings_from_results` does.
pub(crate) fn track_analyzed_strings(
    cache: &super::state::SectionCache,
    tracker: &StringTracker,
    resolved: Option<&Path>,
    raw_path: &str,
    sha256: &str,
    strings: &[String],
) -> anyhow::Result<()> {
    let display = resolved.map_or_else(
        || raw_path.to_string(),
        |p| p.to_string_lossy().into_owned(),
    );
    let mut leftover: Option<Vec<String>> = None;
    if let Some(path) = resolved {
        let key = format!("strings_index:min={DEFAULT_MIN_LEN}");
        tracker.track_strings_at(
            || {
                let index = if let Some(hit) = cache.get(sha256, &key) {
                    hit
                } else if let Ok(built) = build_string_index(path, DEFAULT_MIN_LEN) {
                    let built = Arc::new(built);
                    cache.put(sha256, &key, &built);
                    built
                } else {
                    return Vec::new();
                };
                let wanted: std::collections::HashSet<&str> =
                    strings.iter().map(String::as_str).collect();
                let mut count: HashMap<&str, usize> = HashMap::new();
                let mut items = Vec::new();
                for item in index["strings"].as_array().map_or(&[][..], Vec::as_slice) {
                    let (Some(offset), Some(value)) = (item[0].as_u64(), item[2].as_str()) else {
                        continue;
                    };
                    if !wanted.contains(value) {
                        continue;
                    }
                    let n = count.entry(value).or_insert(0);
                    if *n < MAX_OFFSETS_TRACKED {
                        *n += 1;
                        items.push((value.to_string(), offset as usize));
                    }
                }
                leftover = Some(
                    strings
                        .iter()
                        .filter(|value| !count.contains_key(value.as_str()))
                        .cloned()
                        .collect(),
                );
                items
            },
            &display,
            sha256,
            "analyze_file",
            &key,
        );
    }
    let rest = leftover.unwrap_or_else(|| strings.to_vec());
    if rest.is_empty() {
        return Ok(());
    }
    tracker.track_strings_from_results(&rest, &display, sha256, "analyze_file")
}

/// One distinct string of a file's index.
struct Group {
    value: String,
    offsets: Vec<usize>,
    count: usize,
    utf16: bool,
}

fn compile_regex(pattern: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|error| {
            format!(
                "Invalid regex: {error}. Pass a pattern in Rust regex syntax (no look-around or \
                 back-references), or use `query` for a plain substring."
            )
        })
}

fn shown(value: &str) -> (String, bool) {
    if value.chars().count() > MAX_SHOWN_VALUE_CHARS {
        (value.chars().take(MAX_SHOWN_VALUE_CHARS).collect(), true)
    } else {
        (value.to_string(), false)
    }
}

fn entry_accepted(
    entry: &StringEntry,
    category: Option<&str>,
    min_entropy: Option<f64>,
    suspicious_only: bool,
) -> bool {
    category.is_none_or(|wanted| {
        entry
            .categories
            .iter()
            .any(|c| c.eq_ignore_ascii_case(wanted))
    }) && min_entropy.is_none_or(|min| entry.entropy >= min)
        && (!suspicious_only || entry.is_suspicious)
}

fn sorted_categories(entry: &StringEntry) -> Vec<&str> {
    let mut categories: Vec<&str> = entry.categories.iter().map(String::as_str).collect();
    categories.sort_unstable();
    categories
}

fn tracker_full_text() -> String {
    format!(
        "The session index is full ({} distinct strings): strings of files indexed after that \
         are missing from session searches and string_details. cache_clear with scope \
         \"strings\" frees it; a search with file_path is complete either way.",
        StringTracker::CAPACITY
    )
}

/// What to tell a caller whose session search matched nothing.
fn no_match_hint(tracker: &StringTracker, category: Option<&str>) -> String {
    let known: Vec<String> = {
        let mut names: Vec<String> = tracker
            .get_statistics(None)
            .category_distribution
            .into_keys()
            .collect();
        names.sort_unstable();
        names
    };
    if let Some(wanted) = category {
        if !known.iter().any(|name| name.eq_ignore_ascii_case(wanted)) {
            let list = if known.is_empty() {
                "none yet: nothing is indexed".to_string()
            } else {
                known.join(", ")
            };
            return format!(
                "No tracked string has the category \"{wanted}\". Categories in this session: \
                 {list}."
            );
        }
    }
    "No tracked string matches. Strings are tracked when analyze_file runs with strings: true or \
     when search_strings is given a file_path; cache_status shows what is indexed."
        .to_string()
}

/// The session search, on a blocking thread: it filters every tracked value.
fn search_session_blocking(
    state: &ServerState,
    query: Option<&str>,
    pattern: Option<&regex::Regex>,
    category: Option<&str>,
    min_entropy: Option<f64>,
    suspicious_only: bool,
    paging: PageArgs,
) -> Result<Value, String> {
    let tracker = state.string_tracker();
    let accept =
        move |entry: &StringEntry| entry_accepted(entry, category, min_entropy, suspicious_only);
    let found = tracker.search_filtered(query, pattern, MAX_SESSION_MATCHES, &accept);
    let items: Vec<Value> = found
        .iter()
        .map(|entry| {
            let (value, cut) = shown(&entry.value);
            let mut files: Vec<&str> = entry.unique_files.iter().map(String::as_str).collect();
            files.sort_unstable();
            let files_total = files.len();
            files.truncate(MAX_FILES_SHOWN);
            let mut item = json!({
                "value": value,
                "total_occurrences": entry.total_occurrences,
                "files_total": files_total,
                "files": files,
                "categories": sorted_categories(entry),
                "entropy": (entry.entropy * 100.0).round() / 100.0,
                "suspicious": entry.is_suspicious,
            });
            if cut {
                item["value_cut"] = true.into();
            }
            item
        })
        .collect();
    let mut out = page(
        &items,
        paging.offset.unwrap_or(0),
        paging.limit.unwrap_or(50),
    );
    out["scope"] = "session".into();
    if found.len() >= MAX_SESSION_MATCHES {
        out["note"] = format!(
            "More than {MAX_SESSION_MATCHES} strings match; only the most frequent \
             {MAX_SESSION_MATCHES} are paged. Narrow the search."
        )
        .into();
    }
    if items.is_empty() {
        out["hint"] = no_match_hint(&tracker, category).into();
    } else {
        out["next_steps"] = json!([
            "string_details {value} for the files and offsets a string occurs at",
            "search_strings with file_path to search one file and get offsets"
        ]);
    }
    if tracker.is_full() {
        out["tracker_full"] = tracker_full_text().into();
    }
    Ok(out)
}

impl FileScannerMcp {
    /// The `search_strings` tool body.
    pub(crate) async fn run_search_strings(&self, args: JsonObject) -> CallToolResult {
        let (request, budget, _raw) = match parse_request::<SearchStringsRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let suspicious_only = request.suspicious_only.unwrap_or(false);
        let query = request.query.as_deref().filter(|q| !q.is_empty());
        let category = request.category.as_deref().filter(|c| !c.is_empty());
        if query.is_none()
            && request.regex.is_none()
            && category.is_none()
            && request.min_entropy.is_none()
            && !suspicious_only
        {
            return tool_error(
                "search_strings needs something to look for: pass `query` (a substring), `regex`, \
                 `category`, `min_entropy` or `suspicious_only: true`. It never lists every \
                 string. Add `file_path` to search one file, or leave it out to search every \
                 file analyzed this session.",
            );
        }
        if let Some(min) = request.min_entropy {
            if !min.is_finite() || !(0.0..=8.0).contains(&min) {
                return tool_error(
                    "Invalid min_entropy: expected a number from 0 to 8 (Shannon bits per \
                     character; random-looking strings are above 4.5).",
                );
            }
        }
        let pattern = match request.regex.as_deref().map(compile_regex).transpose() {
            Ok(pattern) => pattern,
            Err(message) => return tool_error(message),
        };
        let paging = PageArgs {
            offset: request.offset,
            limit: request.limit,
        };
        let value = match &request.file_path {
            Some(raw) => {
                self.search_one_file(raw, &request, query, pattern, paging, suspicious_only)
                    .await
            }
            None => self.search_session(&request, query, pattern, paging).await,
        };
        match value {
            Ok(mut value) => {
                fit_page(&mut value, "items", budget);
                respond(value, budget)
            }
            Err(message) => tool_error(message),
        }
    }

    async fn search_session(
        &self,
        request: &SearchStringsRequest,
        query: Option<&str>,
        pattern: Option<regex::Regex>,
        paging: PageArgs,
    ) -> Result<Value, String> {
        let state = Arc::clone(&self.state);
        let query = query.map(str::to_string);
        let category = request.category.clone().filter(|c| !c.is_empty());
        let min_entropy = request.min_entropy;
        let suspicious_only = request.suspicious_only.unwrap_or(false);
        self.state
            .run_blocking("search_strings", move || {
                search_session_blocking(
                    &state,
                    query.as_deref(),
                    pattern.as_ref(),
                    category.as_deref(),
                    min_entropy,
                    suspicious_only,
                    paging,
                )
            })
            .await?
    }

    async fn search_one_file(
        &self,
        raw: &str,
        request: &SearchStringsRequest,
        query: Option<&str>,
        pattern: Option<regex::Regex>,
        paging: PageArgs,
        suspicious_only: bool,
    ) -> Result<Value, String> {
        let min_len = request.min_length.unwrap_or(DEFAULT_MIN_LEN);
        if !(MIN_LEN_RANGE.0..=MIN_LEN_RANGE.1).contains(&min_len) {
            return Err(format!(
                "Invalid min_length {min_len}: pass a number from {} to {}.",
                MIN_LEN_RANGE.0, MIN_LEN_RANGE.1
            ));
        }
        let path = self.state.resolve_path(raw, "File", Expect::File)?;
        let sha256 = self.state.file_sha256(&path).await?;
        let key = format!("strings_index:min={min_len}");

        let state = Arc::clone(&self.state);
        let query = query.map(str::to_lowercase);
        let category = request.category.clone().filter(|c| !c.is_empty());
        let min_entropy = request.min_entropy;
        let display_path = path.to_string_lossy().into_owned();
        let started = Instant::now();
        let outcome = self
            .state
            .run_blocking("search_strings", move || -> Result<Value, String> {
                let cache = state.section_cache();
                let (index, cache_state) = if let Some(hit) = cache.get(&sha256, &key) {
                    (hit, "hit")
                } else {
                    let built = Arc::new(build_string_index(&path, min_len)?);
                    let put = cache.put(&sha256, &key, &built);
                    let state_text = if put.kept { "miss" } else { "miss_not_cached" };
                    (built, state_text)
                };
                let strings = index["strings"].as_array().map_or(&[][..], Vec::as_slice);

                // Index the strings (once per file and length) so session
                // searches and string_details find them, offsets included.
                let tracker = state.string_tracker();
                let report = tracker.track_strings_at(
                    || {
                        strings
                            .iter()
                            .filter_map(|s| {
                                Some((s[2].as_str()?.to_string(), s[0].as_u64()? as usize))
                            })
                            .collect()
                    },
                    &display_path,
                    &sha256,
                    "search_strings",
                    &key,
                );

                // Group by value, in order of first appearance.
                let wants_class = category.is_some() || min_entropy.is_some() || suspicious_only;
                let mut order: Vec<Group> = Vec::new();
                let mut seen: HashMap<&str, usize> = HashMap::new();
                for item in strings {
                    let (Some(offset), Some(value)) = (item[0].as_u64(), item[2].as_str()) else {
                        continue;
                    };
                    let hit = query
                        .as_ref()
                        .is_none_or(|q| value.to_ascii_lowercase().contains(q.as_str()))
                        && pattern.as_ref().is_none_or(|p| p.is_match(value));
                    if !hit {
                        continue;
                    }
                    let slot = *seen.entry(value).or_insert_with(|| {
                        order.push(Group {
                            value: value.to_string(),
                            offsets: Vec::new(),
                            count: 0,
                            utf16: item[1].as_u64() == Some(1),
                        });
                        order.len() - 1
                    });
                    let group = &mut order[slot];
                    group.count += 1;
                    if group.offsets.len() < MAX_OFFSETS_SHOWN {
                        group.offsets.push(offset as usize);
                    }
                }

                let mut classified_all = true;
                let mut class: HashMap<String, StringEntry> = HashMap::new();
                if wants_class {
                    if order.len() > MAX_CLASSIFIED {
                        order.truncate(MAX_CLASSIFIED);
                        classified_all = false;
                    }
                    order.retain(|group| match tracker.classify(&group.value) {
                        Some(entry) => {
                            let ok = entry_accepted(
                                &entry,
                                category.as_deref(),
                                min_entropy,
                                suspicious_only,
                            );
                            if ok {
                                class.insert(group.value.clone(), entry);
                            }
                            ok
                        }
                        None => false,
                    });
                }

                let total = order.len();
                let start = paging.offset.unwrap_or(0).min(total);
                let items: Vec<Value> = order[start..]
                    .iter()
                    .take(paging.limit.unwrap_or(50).clamp(1, 500))
                    .map(|group| {
                        let (value, cut) = shown(&group.value);
                        let mut item = json!({
                            "value": value,
                            "offset": group.offsets.first(),
                            "offsets": group.offsets,
                            "count": group.count,
                            "encoding": if group.utf16 { "utf16le" } else { "ascii" },
                        });
                        if cut {
                            item["value_cut"] = true.into();
                        }
                        let entry = class
                            .get(&group.value)
                            .cloned()
                            .or_else(|| tracker.classify(&group.value));
                        if let Some(entry) = entry {
                            item["categories"] = json!(sorted_categories(&entry));
                            item["entropy"] = ((entry.entropy * 100.0).round() / 100.0).into();
                            item["suspicious"] = entry.is_suspicious.into();
                        }
                        item
                    })
                    .collect();

                // `page` pages a slice; this page is already cut, so build the
                // envelope by hand with the same member names.
                let returned = items.len();
                let mut out = json!({
                    "scope": "file",
                    "file_path": display_path,
                    "sha256": sha256,
                    "cache": cache_state,
                    "strings_in_file": strings.len(),
                    "scanned_bytes": index["scanned_bytes"],
                    "items": items,
                    "total": total,
                    "returned": returned,
                    "offset": paging.offset.unwrap_or(0),
                    "elapsed_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                });
                if start + returned < total {
                    out["next_offset"] = (start + returned).into();
                }
                if index["index_truncated"] == true {
                    out["note"] = format!(
                        "The file has more strings than the index keeps ({MAX_INDEX_STRINGS} \
                         strings or {} MiB of text, counted from the start of the file); the \
                         rest are not searchable. Raise min_length to keep fewer, longer strings.",
                        MAX_INDEX_VALUE_BYTES >> 20
                    )
                    .into();
                } else if index["scanned_bytes"].as_u64() < index["file_size"].as_u64() {
                    out["note"] = format!(
                        "Only the first {MAX_INDEX_SCAN_BYTES} bytes of the file were scanned."
                    )
                    .into();
                }
                if let Some(cut) = index["values_cut"].as_u64().filter(|n| *n > 0) {
                    out["values_note"] = format!(
                        "{cut} strings are longer than {MAX_INDEXED_VALUE_CHARS} characters and \
                         are indexed up to that length: a match beyond it is not found."
                    )
                    .into();
                }
                if !classified_all {
                    out["classification_note"] = format!(
                        "Category, entropy and suspicion filters inspected the first \
                         {MAX_CLASSIFIED} distinct matches only; add `query` or `regex` to narrow."
                    )
                    .into();
                }
                if report.skipped > 0 {
                    // Only say the search covered the whole file when it did.
                    let whole_file = index["index_truncated"] != true
                        && index["values_cut"].as_u64().unwrap_or(0) == 0
                        && index["scanned_bytes"].as_u64() >= index["file_size"].as_u64();
                    out["tracker_note"] = format!(
                        "{} strings of this file are not in the session index (too long, or the \
                         tracker is full: cache_clear with scope \"strings\" frees it); \
                         session searches and string_details will not find them.{}",
                        report.skipped,
                        if whole_file {
                            " This search of the file is complete."
                        } else {
                            ""
                        }
                    )
                    .into();
                }
                if total > 0 {
                    out["next_steps"] =
                        json!(["string_details {value} lists the files and offsets of one string"]);
                }
                Ok(out)
            })
            .await;
        match outcome {
            Err(crash) => Err(crash),
            Ok(result) => result,
        }
    }

    /// The `string_details` tool body.
    pub(crate) async fn run_string_details(&self, args: JsonObject) -> CallToolResult {
        let (request, budget, _raw) = match parse_request::<StringDetailsRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        if request.value.is_empty() {
            return tool_error(
                "string_details needs `value`: the exact string, as search_strings returned it.",
            );
        }
        let state = Arc::clone(&self.state);
        let outcome = self
            .state
            .run_blocking("string_details", move || {
                string_details_value(&state, &request)
            })
            .await;
        respond_result(
            outcome.map(|result| {
                result.map(|mut value| {
                    fit_page(&mut value, "files", budget);
                    value
                })
            }),
            budget,
        )
    }
}

/// Cut a paged answer to the output budget with `output::fit_rows`, so
/// `returned`, `next_offset` and the hint describe the rows actually sent.
fn fit_page(value: &mut Value, key: &str, budget: usize) {
    let offset = value["offset"].as_u64().map_or(0, |n| n as usize);
    let total = value["total"].as_u64().map_or(0, |n| n as usize);
    let start = offset.min(total);
    fit_rows(value, key, budget, start, total);
}

fn string_details_value(
    state: &ServerState,
    request: &StringDetailsRequest,
) -> Result<Value, String> {
    {
        let tracker = state.string_tracker();
        let mut lookup = request.value.clone();
        let mut exact = tracker.get_string_details(&lookup);
        let mut by_prefix = false;
        if exact.is_none() {
            // A value shown cut (`value_cut`, or blanked by the output budget)
            // is a prefix of the real one: accept it when only one matches.
            let marked = lookup.find("...[cut ");
            if let Some(at) = marked {
                lookup.truncate(at);
            }
            let looks_cut = marked.is_some() || lookup.chars().count() == MAX_SHOWN_VALUE_CHARS;
            if looks_cut && !lookup.is_empty() {
                let found = tracker.values_with_prefix(&lookup, 2);
                match found.as_slice() {
                    [one] => {
                        exact = tracker.get_string_details(one);
                        by_prefix = exact.is_some();
                    }
                    [_, _] => {
                        return Err(format!(
                            "That value is not tracked as given, and more than one tracked \
                             string starts with it ({} characters). A value that search_strings \
                             showed cut is a prefix: pass more of it, or search_strings with a \
                             longer `query` or a `regex` to find the whole value.",
                            lookup.chars().count()
                        ));
                    }
                    _ => {}
                }
            }
        }
        let Some(entry) = exact else {
            return Err(if tracker.is_full() {
                format!(
                    "That string is not tracked, and the session index is full ({} distinct \
                     strings), so strings of files indexed late were not kept. Run cache_clear \
                     with scope \"strings\" to free it, then search_strings with file_path \
                     again.",
                    StringTracker::CAPACITY
                )
            } else {
                "That string is not tracked. Find exact values with search_strings (it tracks \
                 the strings of every file it searches), or analyze the file with analyze_file \
                 and strings: true first. A value shown cut (`value_cut: true`) is accepted \
                 when it is the start of exactly one tracked string."
                    .to_string()
            });
        };
        // One row per file (path and hash) with the offsets seen there.
        let mut files: Vec<(String, String, usize, Vec<usize>)> = Vec::new();
        let mut slot: HashMap<(String, String), usize> = HashMap::new();
        for occurrence in &entry.occurrences {
            let key = (occurrence.file_path.clone(), occurrence.file_hash.clone());
            let at = *slot.entry(key).or_insert_with(|| {
                files.push((
                    occurrence.file_path.clone(),
                    occurrence.file_hash.clone(),
                    0,
                    Vec::new(),
                ));
                files.len() - 1
            });
            files[at].2 += 1;
            if let StringContext::FileString {
                offset: Some(offset),
            } = &occurrence.context
            {
                if files[at].3.len() < 10 {
                    files[at].3.push(*offset);
                }
            }
        }
        files.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        let rows: Vec<Value> = files
            .iter()
            .map(|(path, hash, count, offsets)| {
                let mut row = json!({"file_path": path, "file_hash": hash, "occurrences": count, "offsets": offsets});
                if offsets.is_empty() {
                    row["offsets_note"] = "No offset was recorded for this file: the string was \
                        indexed without one (it is shorter than 4 characters or lies beyond the \
                        string index's scan or count limits). search_strings with file_path and \
                        query gives its offsets."
                        .into();
                }
                row
            })
            .collect();
        let related = tracker
            .try_get_related_strings(
                &entry.value,
                request.related_limit.unwrap_or(10).clamp(1, 50),
            )
            .unwrap_or_default();
        let (value, cut) = shown(&entry.value);
        let mut out = page(
            &rows,
            request.offset.unwrap_or(0),
            request.limit.unwrap_or(50),
        );
        out["files"] = out["items"].take();
        if let Some(map) = out.as_object_mut() {
            map.remove("items");
        }
        out["value"] = value.into();
        if cut {
            out["value_cut"] = true.into();
        }
        if by_prefix {
            out["matched_by_prefix"] = true.into();
        }
        let detailed: usize = files.iter().map(|file| file.2).sum();
        if detailed < entry.total_occurrences || files.len() < entry.unique_files.len() {
            out["detail_note"] = format!(
                "Only the most recent {detailed} of {} occurrences are kept in detail, so the \
                 per-file counts and offsets below cover those and some files or offsets may be \
                 missing. For the exact count and first offsets in one file, use search_strings \
                 with file_path and query.",
                entry.total_occurrences
            )
            .into();
        }
        if tracker.totals_may_be_capped(entry.unique_files.len()) {
            out["total_note"] = "The totals are a lower bound: the session index keeps at most \
                1024 files per string and 1,000,000 recorded occurrences, and counts past \
                that were not kept. Use search_strings with file_path and query for the exact \
                count in one file."
                .into();
        }
        out["total_occurrences"] = entry.total_occurrences.into();
        out["files_total"] = entry.unique_files.len().into();
        out["categories"] = json!(sorted_categories(&entry));
        out["entropy"] = ((entry.entropy * 100.0).round() / 100.0).into();
        out["suspicious"] = entry.is_suspicious.into();
        out["first_seen"] = entry.first_seen.to_rfc3339().into();
        out["last_seen"] = entry.last_seen.to_rfc3339().into();
        out["related"] = related
            .iter()
            .map(|(value, score)| {
                let (value, _) = shown(value);
                json!({"value": value, "score": (score * 100.0).round() / 100.0})
            })
            .collect::<Vec<_>>()
            .into();
        Ok(out)
    }
}

fn cache_status_value(
    state: &ServerState,
    action: CacheAction,
    request: &CacheStatusRequest,
) -> Value {
    match action {
        CacheAction::Stats => cache_stats_value(state),
        CacheAction::List | CacheAction::Search => {
            let query = CacheSearchQuery {
                tool_name: request.tool_name.clone(),
                file_path_pattern: request.file_path_pattern.clone(),
                start_time: None,
                end_time: None,
                min_file_size: None,
                max_file_size: None,
            };
            let rows: Vec<EntrySummary> = state.analysis_cache().list_summaries(&query);
            let mut out = page(
                &rows,
                request.offset.unwrap_or(0),
                request.limit.unwrap_or(50),
            );
            if rows.is_empty() {
                out["hint"] = if state.cache_enabled() {
                    "Nothing cached matches. analyze_file and yara_scan_file calls are \
                     recorded here."
                } else {
                    "Caching is off (--no-cache): nothing is recorded, so this list stays \
                     empty. Restart without --no-cache to keep a call history."
                }
                .into();
            } else {
                let tools: std::collections::BTreeSet<&str> =
                    rows.iter().map(|row| row.tool_name.as_str()).collect();
                out["next_steps"] = if tools.iter().all(|tool| *tool == "analyze_file") {
                    json!(["analyze_file with the same arguments returns the cached result"])
                } else {
                    json!([
                        "string_details or search_strings drill into one file's strings",
                        "cache_status {action: \"search\", tool_name} narrows the list to one tool"
                    ])
                };
            }
            out
        }
    }
}

fn cache_stats_value(state: &ServerState) -> Value {
    let cache = state.analysis_cache();
    let rows = cache.list_summaries(&CacheSearchQuery {
        tool_name: None,
        file_path_pattern: None,
        start_time: None,
        end_time: None,
        min_file_size: None,
        max_file_size: None,
    });
    let mut tools: HashMap<&str, usize> = HashMap::new();
    let mut files: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut result_bytes = 0usize;
    for row in &rows {
        *tools.entry(row.tool_name.as_str()).or_insert(0) += 1;
        files.insert(row.file_hash.as_str());
        result_bytes += row.result_bytes;
    }
    let strings = state.string_tracker().get_statistics(None);
    let mut categories: Vec<(&String, &usize)> = strings.category_distribution.iter().collect();
    categories.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let mut out = json!({
        "enabled": state.cache_enabled(),
        "persistent": cache.is_persistent(),
        "directory": cache.directory().map(|d| d.display().to_string()),
        "analysis_history": {
            "entries": rows.len(),
            "files": files.len(),
            "result_bytes": result_bytes,
            "max_bytes_on_disk": cache.max_total_bytes(),
            "calls_by_tool": tools,
        },
        "sections": state.section_cache().stats(),
        "strings": {
            "unique": strings.total_unique_strings,
            "occurrences": strings.total_occurrences,
            "files": strings.total_files_analyzed,
            "categories": categories.into_iter().take(15).collect::<Vec<_>>(),
        },
        "next_steps": [
            "cache_status {action: \"list\"} pages through past calls",
            "search_strings {query} searches the indexed strings",
            "cache_clear forgets cached results (destructive)"
        ],
    });
    if !state.cache_enabled() {
        out["note"] = "Caching is off (--no-cache): no analysis history or cached sections are \
            kept and nothing is written to disk. The in-memory string index still fills, so \
            search_strings and string_details work; the `strings` counts below describe it, and \
            cache_clear with scope \"strings\" empties it."
            .into();
    }
    out
}

/// Forget what `scope` names, as the `cache_clear` tool and `POST /cache/clear`
/// both do; returns what was cleared, worded for the mode the server runs in.
pub(crate) async fn clear_scope(
    state: &ServerState,
    scope: ClearScope,
) -> Result<Vec<&'static str>, String> {
    let mut cleared = Vec::new();
    if matches!(scope, ClearScope::All | ClearScope::Analysis) {
        state.clear_analysis_caches().await.map_err(|error| {
            format!(
                "Could not clear the analysis cache: {error}. Check that the cache directory \
                 is writable (cache_status shows where it is)."
            )
        })?;
        // LEAD: call super::tools_java::forget_recent() here (the Java tool's in-memory store)
        cleared.push(if state.cache_enabled() {
            "analysis history, cached sections and files on disk"
        } else {
            "analysis history and cached sections (in memory; --no-cache keeps no files on disk, \
             so none were touched)"
        });
    }
    if matches!(scope, ClearScope::All | ClearScope::Strings) {
        state.string_tracker().clear();
        cleared.push(if state.cache_enabled() {
            "tracked strings"
        } else {
            "tracked strings (the in-memory string index, which --no-cache still fills)"
        });
    }
    Ok(cleared)
}

impl FileScannerMcp {
    /// The `cache_status` tool body.
    pub(crate) async fn run_cache_status(&self, args: JsonObject) -> CallToolResult {
        let (request, budget, _raw) = match parse_request::<CacheStatusRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let action = request.action.unwrap_or_default();
        if matches!(action, CacheAction::Search)
            && request.tool_name.is_none()
            && request.file_path_pattern.is_none()
        {
            return tool_error(
                "cache_status action `search` needs a filter: pass `tool_name` and/or \
                 `file_path_pattern`. Use action `list` to page through everything.",
            );
        }
        let state = Arc::clone(&self.state);
        let outcome = self
            .state
            .run_blocking("cache_status", move || {
                cache_status_value(&state, action, &request)
            })
            .await;
        respond_result(
            outcome.map(|mut value| {
                fit_page(&mut value, "items", budget);
                Ok(value)
            }),
            budget,
        )
    }

    /// The `cache_clear` tool body.
    pub(crate) async fn run_cache_clear(&self, args: JsonObject) -> CallToolResult {
        let (request, budget, _raw) = match parse_request::<CacheClearRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let scope = request.scope.unwrap_or_default();
        let cleared = match clear_scope(&self.state, scope).await {
            Ok(cleared) => cleared,
            Err(message) => return tool_error(message),
        };
        respond(json!({"cleared": cleared}), budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_server::state::{ServerState, StateConfig};
    use rmcp::{model::CallToolRequestParams, ServiceExt};
    use std::io::Write;

    /// A server over its own state and cache directory, and a connected client.
    async fn connect(
        dir: &Path,
    ) -> (
        Arc<ServerState>,
        rmcp::service::RunningService<rmcp::RoleClient, ()>,
    ) {
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: dir.to_path_buf(),
            ..StateConfig::default()
        }));
        let server = FileScannerMcp::with_state(Arc::clone(&state));
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = server.serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        (state, ().serve(client_io).await.expect("handshake"))
    }

    async fn call(
        client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
        name: &'static str,
        args: Value,
    ) -> (bool, Value) {
        let params = CallToolRequestParams::new(name)
            .with_arguments(args.as_object().cloned().unwrap_or_default());
        let result = client.call_tool(params).await.expect("answered");
        let text = result.content[0].as_text().unwrap().text.clone();
        let is_error = result.is_error == Some(true);
        let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (is_error, value)
    }

    fn sample_file(dir: &Path, name: &str, body: &[u8]) -> String {
        let path = dir.join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(body)
            .unwrap();
        path.to_string_lossy().into_owned()
    }

    fn payload() -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        bytes.extend_from_slice(b"http://evil.example.com/beacon\0\0");
        bytes.extend_from_slice(b"hello world, plain text\0");
        for c in "cmd.exe /c whoami".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 1, 2]);
        bytes.extend_from_slice(b"hello world, plain text\0");
        bytes
    }

    #[test]
    fn tools_are_listed_with_the_right_annotations() {
        let tools = FileScannerMcp::new().tool_definitions();
        let find = |name: &str| tools.iter().find(|t| t.name == name).unwrap().clone();
        for name in ["search_strings", "string_details", "cache_status"] {
            let tool = find(name);
            let annotations = tool.annotations.expect("annotations");
            assert_eq!(annotations.read_only_hint, Some(true), "{name}");
            assert_eq!(annotations.destructive_hint, Some(false), "{name}");
        }
        let clear = find("cache_clear").annotations.expect("annotations");
        assert_eq!(clear.destructive_hint, Some(true));
        assert_eq!(clear.read_only_hint, Some(false));
    }

    #[tokio::test]
    async fn search_strings_finds_offsets_and_caches_the_index() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "sample.bin", &payload());
        let (_state, client) = connect(cache.path()).await;

        let (error, first) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "evil"}),
        )
        .await;
        assert!(!error, "{first}");
        assert_eq!(first["cache"], "miss");
        assert_eq!(first["total"], 1);
        assert_eq!(first["items"][0]["offset"], 16);
        assert_eq!(first["items"][0]["value"], "http://evil.example.com/beacon");

        // The same file again is answered from the cache, with other filters.
        let (_, second) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "regex": "^hello"}),
        )
        .await;
        assert_eq!(second["cache"], "hit");
        assert_eq!(second["items"][0]["count"], 2, "{second}");
        assert_eq!(second["items"][0]["offsets"].as_array().unwrap().len(), 2);

        // UTF-16 strings are found and labelled.
        let (_, wide) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "whoami"}),
        )
        .await;
        assert_eq!(wide["items"][0]["encoding"], "utf16le", "{wide}");
    }

    #[tokio::test]
    async fn a_changed_file_is_a_miss_and_an_unchanged_one_is_not_rehashed_or_reindexed() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "sample.bin", &payload());
        let (state, client) = connect(cache.path()).await;
        let args = json!({"file_path": path, "query": "hello"});
        let (_, a) = call(&client, "search_strings", args.clone()).await;
        let (_, b) = call(&client, "search_strings", args.clone()).await;
        assert_eq!(
            (a["cache"].as_str(), b["cache"].as_str()),
            (Some("miss"), Some("hit"))
        );
        // Repeating the call does not double the tracker's counts.
        let tracked = state
            .string_tracker()
            .get_string_details("hello world, plain text")
            .unwrap();
        assert_eq!(tracked.total_occurrences, 2);

        std::thread::sleep(std::time::Duration::from_millis(20));
        sample_file(files.path(), "sample.bin", b"hello changed content here\0");
        let (_, c) = call(&client, "search_strings", args).await;
        assert_eq!(c["cache"], "miss", "{c}");
        assert_eq!(c["items"][0]["value"], "hello changed content here");
    }

    #[tokio::test]
    async fn search_strings_refuses_to_list_everything_and_explains() {
        let cache = tempfile::tempdir().unwrap();
        let (_state, client) = connect(cache.path()).await;
        let (error, text) = call(&client, "search_strings", json!({})).await;
        assert!(error);
        assert!(
            text.as_str().unwrap().contains("never lists every string"),
            "{text}"
        );
        let (error, text) = call(&client, "search_strings", json!({"regex": "(unclosed"})).await;
        assert!(error);
        assert!(text.as_str().unwrap().contains("Invalid regex"), "{text}");
        let (error, _) = call(&client, "search_strings", json!({"query": "x", "bogus": 1})).await;
        assert!(error, "unknown arguments are rejected");
        let (error, text) = call(
            &client,
            "search_strings",
            json!({"query": "x", "file_path": "/no/such/file"}),
        )
        .await;
        assert!(error, "{text}");
    }

    /// The tests of the string index builder.
    fn index_of(bytes: &[u8], min_len: usize) -> Value {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, bytes).unwrap();
        build_string_index(&path, min_len).unwrap()
    }

    fn found(index: &Value) -> Vec<(u64, u64, String)> {
        index["strings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s[0].as_u64().unwrap(),
                    s[1].as_u64().unwrap(),
                    s[2].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn the_index_finds_runs_across_read_chunks() {
        let mut bytes = vec![0u8; SCAN_CHUNK_BYTES * 2 + 100];
        // An ASCII run across the first chunk boundary.
        let ascii_at = SCAN_CHUNK_BYTES - 3;
        bytes[ascii_at..ascii_at + 9].copy_from_slice(b"straddled");
        // A UTF-16 run whose first character is the last byte of a chunk.
        let wide_at = SCAN_CHUNK_BYTES * 2 - 1;
        for (i, c) in "wideword".bytes().enumerate() {
            bytes[wide_at + 2 * i] = c;
        }
        let index = index_of(&bytes, 4);
        let strings = found(&index);
        assert!(
            strings.contains(&(ascii_at as u64, 0, "straddled".to_string())),
            "{strings:?}"
        );
        assert!(strings.contains(&(wide_at as u64, 1, "wideword".to_string())));
        assert_eq!(strings.len(), 2, "{strings:?}");
        assert_eq!(index["index_truncated"], false);
    }

    /// The straightforward whole-buffer scan the chunked one must agree with.
    fn reference(buffer: &[u8], min_len: usize) -> Vec<(u64, u64, String)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < buffer.len() {
            if printable(buffer[i]) {
                let start = i;
                while i < buffer.len() && printable(buffer[i]) {
                    i += 1;
                }
                if i - start >= min_len {
                    let text = String::from_utf8_lossy(&buffer[start..i]);
                    out.push((start as u64, 0, text.chars().take(2000).collect()));
                }
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i + 1 < buffer.len() {
            if printable(buffer[i]) && buffer[i + 1] == 0 {
                let start = i;
                let mut text = String::new();
                while i + 1 < buffer.len() && printable(buffer[i]) && buffer[i + 1] == 0 {
                    text.push(char::from(buffer[i]));
                    i += 2;
                }
                if text.len() >= min_len {
                    out.push((start as u64, 1, text.chars().take(2000).collect()));
                }
            } else {
                i += 1;
            }
        }
        out.sort_by_key(|(offset, encoding, _)| (*offset, *encoding));
        out
    }

    #[test]
    fn the_chunked_scan_agrees_with_a_whole_buffer_scan() {
        // Pseudo-random bytes: printable ASCII, NULs and others, in runs.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut bytes = Vec::with_capacity(SCAN_CHUNK_BYTES * 2 + 5000);
        while bytes.len() < SCAN_CHUNK_BYTES * 2 + 5000 {
            let pick = next();
            let byte = match pick % 16 {
                0..=9 => 0x20 + (pick >> 8) as u8 % 0x5f,
                10..=12 => 0,
                _ => 0x80 | (pick >> 8) as u8,
            };
            bytes.push(byte);
        }
        // UTF-16 text, one of them starting on the last byte of a chunk.
        for at in [123, SCAN_CHUNK_BYTES - 1, SCAN_CHUNK_BYTES * 2 - 4] {
            for (i, c) in "wide text here".bytes().enumerate() {
                bytes[at + 2 * i] = c;
                bytes[at + 2 * i + 1] = 0;
            }
        }
        for min_len in [9, 12, 16] {
            let expected = reference(&bytes, min_len);
            assert!(
                expected.len() <= MAX_INDEX_STRINGS,
                "the sample stays under the cap"
            );
            assert_eq!(found(&index_of(&bytes, min_len)), expected, "min {min_len}");
        }
    }

    #[test]
    fn a_file_of_millions_of_short_strings_stops_at_the_cap() {
        // 1.2 million five-byte strings.
        let bytes = b"abcd\n".repeat(1_200_000);
        let index = index_of(&bytes, 4);
        assert_eq!(index["index_truncated"], true);
        assert_eq!(
            index["strings"].as_array().unwrap().len(),
            MAX_INDEX_STRINGS
        );
        // Offsets are those of the first strings, in order.
        assert_eq!(index["strings"][1][0], 5);
    }

    #[test]
    fn long_strings_are_cut_and_counted() {
        let mut bytes = vec![b'q'; MAX_INDEXED_VALUE_CHARS + 500];
        bytes.push(0);
        let index = index_of(&bytes, 4);
        assert_eq!(index["values_cut"], 1);
        assert_eq!(
            found(&index)[0].2.len(),
            MAX_INDEXED_VALUE_CHARS,
            "cut to the indexed length"
        );
    }

    #[tokio::test]
    async fn session_filters_find_matches_that_sort_after_twenty_thousand_values() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for n in 0..25_000 {
            body.extend_from_slice(format!("aaaa plain filler {n:06}\0").as_bytes());
        }
        body.extend_from_slice(b"http://late.example.com/x\0");
        let path = sample_file(files.path(), "dense.bin", &body);
        let (_state, client) = connect(cache.path()).await;
        call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "late.example"}),
        )
        .await;
        let (error, by_category) =
            call(&client, "search_strings", json!({"category": "url"})).await;
        assert!(!error, "{by_category}");
        assert_eq!(by_category["total"], 1, "{by_category}");
        assert_eq!(
            by_category["items"][0]["value"],
            "http://late.example.com/x"
        );
        // A category nothing has names the ones that exist.
        let (_, none) = call(&client, "search_strings", json!({"category": "nonsense"})).await;
        assert_eq!(none["total"], 0);
        let hint = none["hint"].as_str().unwrap();
        assert!(hint.contains("nonsense") && hint.contains("url"), "{hint}");
    }

    #[tokio::test]
    async fn per_file_answers_do_not_depend_on_the_session_tracker_having_room() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "a.bin", &payload());
        let (state, client) = connect(cache.path()).await;
        // Fill the session tracker with other strings.
        let filler: Vec<(String, usize)> = (0..StringTracker::CAPACITY)
            .map(|n| (format!("filler value {n:07}"), n))
            .collect();
        state
            .string_tracker()
            .track_strings_at(|| filler, "/big", "hb", "search_strings", "min=4");
        assert!(state.string_tracker().is_full());

        for _ in 0..2 {
            let (error, answer) = call(
                &client,
                "search_strings",
                json!({"file_path": path, "category": "url"}),
            )
            .await;
            assert!(!error, "{answer}");
            assert_eq!(answer["total"], 1, "{answer}");
            let item = &answer["items"][0];
            assert!(item["categories"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == "url"));
            assert!(item["entropy"].is_number(), "{item}");
            // Said on every call, not only the one that indexed the file.
            assert!(answer["tracker_note"].is_string(), "{answer}");
        }
        // string_details says why it cannot find the value, and how to fix that.
        let (error, text) = call(
            &client,
            "string_details",
            json!({"value": "http://evil.example.com/beacon"}),
        )
        .await;
        assert!(error);
        let text = text.as_str().unwrap();
        assert!(
            text.contains("full") && text.contains("cache_clear"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn two_paths_of_one_content_and_two_routes_are_counted_once_each() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let a = sample_file(files.path(), "copy_a", &payload());
        let b = sample_file(files.path(), "copy_b", &payload());
        let (_state, client) = connect(cache.path()).await;
        for path in [&a, &b] {
            call(
                &client,
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            )
            .await;
        }
        let (_, details) = call(
            &client,
            "string_details",
            json!({"value": "http://evil.example.com/beacon"}),
        )
        .await;
        assert_eq!(details["files_total"], 2, "{details}");
        assert_eq!(details["total_occurrences"], 2);

        // analyze_file then search_strings of one file: one occurrence.
        let c = sample_file(
            files.path(),
            "other",
            b"padding\0http://other.example.org/zz\0",
        );
        let (error, analyzed) = call(
            &client,
            "analyze_file",
            json!({"file_path": c, "strings": true}),
        )
        .await;
        assert!(!error, "{analyzed}");
        call(
            &client,
            "search_strings",
            json!({"file_path": c, "query": "other.example"}),
        )
        .await;
        let (_, details) = call(
            &client,
            "string_details",
            json!({"value": "http://other.example.org/zz"}),
        )
        .await;
        assert_eq!(details["total_occurrences"], 1, "{details}");
    }

    #[tokio::test]
    async fn session_search_and_details_span_files() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let a = sample_file(files.path(), "a.bin", &payload());
        let b = sample_file(
            files.path(),
            "b.bin",
            b"padding\0http://evil.example.com/beacon\0",
        );
        let (_state, client) = connect(cache.path()).await;
        // Nothing is indexed yet.
        let (error, empty) = call(&client, "search_strings", json!({"query": "evil"})).await;
        assert!(!error);
        assert_eq!(empty["total"], 0);
        assert!(empty["hint"].as_str().unwrap().contains("file_path"));
        for path in [&a, &b] {
            call(
                &client,
                "search_strings",
                json!({"file_path": path, "query": "evil"}),
            )
            .await;
        }
        let (_, found) = call(&client, "search_strings", json!({"query": "evil"})).await;
        assert_eq!(found["scope"], "session");
        assert_eq!(found["items"][0]["total_occurrences"], 2, "{found}");
        assert_eq!(found["items"][0]["files_total"], 2);

        let (error, details) = call(
            &client,
            "string_details",
            json!({"value": "http://evil.example.com/beacon"}),
        )
        .await;
        assert!(!error, "{details}");
        assert_eq!(details["total_occurrences"], 2);
        let files_listed = details["files"].as_array().unwrap();
        assert_eq!(files_listed.len(), 2);
        assert!(
            files_listed.iter().any(|f| f["offsets"] == json!([16])),
            "{details}"
        );
        assert!(details["categories"].as_array().is_some());

        let (error, text) = call(&client, "string_details", json!({"value": "never seen"})).await;
        assert!(error);
        assert!(text.as_str().unwrap().contains("not tracked"));
    }

    #[tokio::test]
    async fn filters_by_category_entropy_and_suspicion_and_pages() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for i in 0..30 {
            body.extend_from_slice(format!("string number {i:03} here\0").as_bytes());
        }
        body.extend_from_slice(b"powershell -enc payload\0");
        let path = sample_file(files.path(), "many.bin", &body);
        let (_state, client) = connect(cache.path()).await;

        let (_, page1) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "string number", "limit": 10}),
        )
        .await;
        assert_eq!(page1["total"], 30);
        assert_eq!(page1["returned"], 10);
        assert_eq!(page1["next_offset"], 10);
        let (_, page3) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "string number", "limit": 10, "offset": 20}),
        )
        .await;
        assert_eq!(page3["returned"], 10);
        assert!(page3.get("next_offset").is_none());

        let (_, suspicious) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "suspicious_only": true}),
        )
        .await;
        let values: Vec<&str> = suspicious["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["value"].as_str().unwrap())
            .collect();
        assert!(values.contains(&"powershell -enc payload"), "{suspicious}");
        assert!(!values.iter().any(|v| v.starts_with("string number")));
    }

    #[tokio::test]
    async fn cache_status_lists_pages_and_clear_forgets() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let (state, client) = connect(cache.path()).await;
        for _ in 0..3 {
            let (error, _) = call(
                &client,
                "analyze_file",
                json!({"file_path": path, "hashes": true}),
            )
            .await;
            assert!(!error);
        }
        call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "evil"}),
        )
        .await;

        let (_, stats) = call(&client, "cache_status", json!({})).await;
        assert_eq!(stats["enabled"], true);
        assert_eq!(stats["persistent"], true, "{stats}");
        assert_eq!(stats["analysis_history"]["entries"], 3);
        assert!(stats["strings"]["unique"].as_u64().unwrap() > 0);

        let (_, list) = call(
            &client,
            "cache_status",
            json!({"action": "list", "limit": 2}),
        )
        .await;
        assert_eq!(list["total"], 3);
        assert_eq!(list["returned"], 2);
        assert!(
            list["items"][0].get("result").is_none(),
            "no results in a listing"
        );
        let (_, none) = call(
            &client,
            "cache_status",
            json!({"action": "search", "tool_name": "yara_scan_file"}),
        )
        .await;
        assert_eq!(none["total"], 0);
        let (error, _) = call(&client, "cache_status", json!({"action": "search"})).await;
        assert!(error, "search needs a filter");
        // Only analyze_file calls are served from the cache by repeating them.
        assert!(list["next_steps"][0]
            .as_str()
            .unwrap()
            .contains("analyze_file"));
        state
            .analysis_cache()
            .add_entry(crate::cache::CacheEntry {
                file_path: "/x".into(),
                file_hash: "yy".into(),
                tool_name: "yara_scan_file".into(),
                tool_args: HashMap::new(),
                result: Value::Null,
                timestamp: chrono::Utc::now(),
                file_size: 1,
                execution_time_ms: 1,
            })
            .await
            .unwrap();
        let (_, yara) = call(
            &client,
            "cache_status",
            json!({"action": "list", "tool_name": "yara_scan_file"}),
        )
        .await;
        assert!(
            !yara["next_steps"].to_string().contains("same arguments"),
            "{yara}"
        );

        let (error, cleared) = call(&client, "cache_clear", json!({})).await;
        assert!(!error, "{cleared}");
        let (_, stats) = call(&client, "cache_status", json!({})).await;
        assert_eq!(stats["analysis_history"]["entries"], 0);
        assert_eq!(stats["strings"]["unique"], 0);
        assert!(state
            .string_tracker()
            .get_string_details("http://evil.example.com/beacon")
            .is_none());
    }

    #[tokio::test]
    async fn analyze_file_repeat_is_answered_from_the_cache() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let (_state, client) = connect(cache.path()).await;
        let args = json!({"file_path": path, "strings": true});
        let (_, first) = call(&client, "analyze_file", args.clone()).await;
        let (_, second) = call(&client, "analyze_file", args).await;
        assert_eq!(first["cache"], "miss", "{first}");
        assert_eq!(second["cache"], "hit", "{second}");
    }

    #[tokio::test]
    async fn no_cache_turns_caching_off() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: cache.path().join("c"),
            cache_enabled: false,
            ..StateConfig::default()
        }));
        let server = FileScannerMcp::with_state(Arc::clone(&state));
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = server.serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        let client = ().serve(client_io).await.unwrap();
        let (_, a) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "evil"}),
        )
        .await;
        let (_, b) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "evil"}),
        )
        .await;
        assert_ne!(a["cache"], "hit");
        assert_ne!(b["cache"], "hit", "nothing is served from a disabled cache");
        assert_eq!(b["total"], 1, "searching still works");
        let (_, stats) = call(&client, "cache_status", json!({})).await;
        assert_eq!(stats["enabled"], false);
        assert!(
            !cache.path().join("c").exists(),
            "nothing is written to disk"
        );
    }

    #[tokio::test]
    async fn string_details_works_for_every_value_search_strings_returns_after_analyze_file() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        // analyze_file keeps 2,000 strings; this file has more.
        let mut body = Vec::new();
        for n in 0..3_000 {
            body.extend_from_slice(format!("string number {n:05} of the file\0").as_bytes());
        }
        let path = sample_file(files.path(), "many.bin", &body);
        let (_state, client) = connect(cache.path()).await;
        let (error, analyzed) = call(
            &client,
            "analyze_file",
            json!({"file_path": path, "strings": true}),
        )
        .await;
        assert!(!error, "{analyzed}");
        let (_, found) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "string number 02999"}),
        )
        .await;
        assert_eq!(found["total"], 1, "{found}");
        let value = found["items"][0]["value"].as_str().unwrap().to_string();
        let (error, details) = call(&client, "string_details", json!({"value": value})).await;
        assert!(!error, "{details}");
        assert_eq!(details["total_occurrences"], 1, "{details}");
        assert!(
            !details["files"][0]["offsets"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{details}"
        );
        // The session index knows it too.
        let (_, session) = call(&client, "search_strings", json!({"query": "number 02999"})).await;
        assert_eq!(session["total"], 1, "{session}");
    }

    #[tokio::test]
    async fn string_details_has_offsets_after_analyze_file_alone() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let (_state, client) = connect(cache.path()).await;
        let (error, analyzed) = call(&client, "analyze_file", json!({"file_path": path})).await;
        assert!(!error, "{analyzed}");
        let (error, details) = call(
            &client,
            "string_details",
            json!({"value": "http://evil.example.com/beacon"}),
        )
        .await;
        assert!(!error, "{details}");
        assert_eq!(details["files"][0]["offsets"], json!([16]), "{details}");
        assert!(details["files"][0].get("offsets_note").is_none());
        // The repeated string keeps both offsets and one record per offset.
        let (_, twice) = call(
            &client,
            "string_details",
            json!({"value": "hello world, plain text"}),
        )
        .await;
        assert_eq!(twice["files"][0]["offsets"].as_array().unwrap().len(), 2);
        assert_eq!(twice["total_occurrences"], 2, "{twice}");
    }

    #[tokio::test]
    async fn a_string_without_an_offset_says_so_in_string_details() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let (state, client) = connect(cache.path()).await;
        state
            .string_tracker()
            .track_strings_from_results(&["bare".to_string()], &path, "hash", "analyze_file")
            .unwrap();
        let (_, details) = call(&client, "string_details", json!({"value": "bare"})).await;
        assert_eq!(details["files"][0]["offsets"], json!([]), "{details}");
        assert!(
            details["files"][0]["offsets_note"]
                .as_str()
                .unwrap()
                .contains("search_strings"),
            "{details}"
        );
    }

    #[tokio::test]
    async fn no_cache_answers_say_what_exists_and_what_was_cleared() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(files.path(), "s.bin", &payload());
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: cache.path().join("c"),
            cache_enabled: false,
            ..StateConfig::default()
        }));
        let server = FileScannerMcp::with_state(Arc::clone(&state));
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = server.serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        let client = ().serve(client_io).await.unwrap();
        call(&client, "analyze_file", json!({"file_path": path})).await;
        let (_, stats) = call(&client, "cache_status", json!({})).await;
        assert!(
            stats["note"].as_str().unwrap().contains("string index"),
            "{stats}"
        );
        assert!(stats["strings"]["unique"].as_u64().unwrap() > 0, "{stats}");
        let (_, cleared) = call(&client, "cache_clear", json!({})).await;
        let text = cleared.to_string();
        assert!(!text.contains("files on disk\""), "{text}");
        assert!(text.contains("--no-cache"), "{text}");
        assert_eq!(
            state
                .string_tracker()
                .get_statistics(None)
                .total_unique_strings,
            0
        );
    }

    #[test]
    fn an_index_cut_by_the_sum_of_both_passes_says_so() {
        let files = tempfile::tempdir().unwrap();
        let half = MAX_INDEX_STRINGS / 2 + 10;
        let mut body = Vec::new();
        for n in 0..half {
            body.extend_from_slice(format!("asc_{n:06}\0").as_bytes());
        }
        for n in 0..half {
            for c in format!("wid_{n:06}").encode_utf16() {
                body.extend_from_slice(&c.to_le_bytes());
            }
            body.extend_from_slice(&[0, 0]);
        }
        let path = sample_file(files.path(), "mixed.bin", &body);
        let index = build_string_index(Path::new(&path), 4).unwrap();
        assert_eq!(
            index["strings"].as_array().unwrap().len(),
            MAX_INDEX_STRINGS
        );
        assert_eq!(index["index_truncated"], true);
    }

    #[test]
    fn a_capped_utf16_pass_keeps_the_first_strings_and_flags_the_cut() {
        // The buffer size is not observable from the result (measured by hand on
        // a 204 MB file instead); the index must still be right and flagged.
        let files = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for n in 0..(MAX_INDEX_STRINGS + 10) {
            for c in format!("w{n:06}").encode_utf16() {
                body.extend_from_slice(&c.to_le_bytes());
            }
            body.extend_from_slice(&[0, 0]);
        }
        body.extend_from_slice(b"\0plain tail string\0");
        let path = sample_file(files.path(), "wide.bin", &body);
        let index = build_string_index(Path::new(&path), 4).unwrap();
        assert_eq!(index["index_truncated"], true);
        assert_eq!(
            index["strings"].as_array().unwrap().len(),
            MAX_INDEX_STRINGS
        );
    }

    #[tokio::test]
    async fn string_details_accepts_a_value_shown_cut_and_explains_when_it_cannot() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let long = "B".repeat(450);
        let path = sample_file(files.path(), "long.bin", format!("\0{long}\0").as_bytes());
        let (_state, client) = connect(cache.path()).await;
        let (_, found) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "regex": "^B"}),
        )
        .await;
        let item = &found["items"][0];
        assert_eq!(item["value_cut"], true, "{found}");
        let shown_value = item["value"].as_str().unwrap().to_string();
        assert_eq!(shown_value.len(), MAX_SHOWN_VALUE_CHARS);
        let (error, details) = call(&client, "string_details", json!({"value": shown_value})).await;
        assert!(!error, "{details}");
        assert_eq!(details["matched_by_prefix"], true);
        assert_eq!(details["total_occurrences"], 1);

        // A second long value with the same start makes the prefix ambiguous.
        let other = format!("{}C", "B".repeat(450));
        let path2 = sample_file(files.path(), "long2.bin", format!("\0{other}\0").as_bytes());
        call(
            &client,
            "search_strings",
            json!({"file_path": path2, "regex": "^B"}),
        )
        .await;
        let (error, text) =
            call(&client, "string_details", json!({"value": "B".repeat(400)})).await;
        assert!(error);
        assert!(text.as_str().unwrap().contains("more than one"), "{text}");
        assert!(!text.as_str().unwrap().contains("  "), "{text}");

        // A short value that is not tracked says how cut values are handled.
        let (error, text) = call(&client, "string_details", json!({"value": "nope"})).await;
        assert!(error);
        assert!(text.as_str().unwrap().contains("value_cut"), "{text}");
    }

    #[tokio::test]
    async fn the_tracker_note_does_not_call_a_cut_index_complete() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for n in 0..(MAX_INDEX_STRINGS + 10) {
            body.extend_from_slice(format!("wid_{n:07}\0").as_bytes());
        }
        let path = sample_file(files.path(), "dense.bin", &body);
        let (_state, client) = connect(cache.path()).await;
        let (error, found) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "wid_0000001"}),
        )
        .await;
        assert!(!error, "{found}");
        assert!(found["note"]
            .as_str()
            .unwrap()
            .contains("rest are not searchable"));
        let tracker_note = found["tracker_note"].as_str().expect("a tracker note");
        assert!(!tracker_note.contains("is complete"), "{tracker_note}");
    }

    #[tokio::test]
    async fn the_tracker_note_does_not_call_a_search_complete_when_values_were_cut() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        // A file that fills the session tracker (100,000 distinct values).
        let mut filler = Vec::new();
        for n in 0..100_100 {
            filler.extend_from_slice(format!("fill_{n:07}\0").as_bytes());
        }
        let filler_path = sample_file(files.path(), "filler.bin", &filler);
        // A second file: one value longer than the index keeps, and a few
        // others the full tracker refuses.
        let mut body = b"\0lead_".to_vec();
        body.extend(std::iter::repeat_n(b'x', MAX_INDEXED_VALUE_CHARS + 500));
        body.extend_from_slice(b"\0another_one\0");
        let long_path = sample_file(files.path(), "long.bin", &body);
        let (_state, client) = connect(cache.path()).await;
        call(
            &client,
            "search_strings",
            json!({"file_path": filler_path, "query": "fill_0000001"}),
        )
        .await;
        let (error, found) = call(
            &client,
            "search_strings",
            json!({"file_path": long_path, "query": "another"}),
        )
        .await;
        assert!(!error, "{found}");
        assert!(found["values_note"].is_string(), "{found}");
        let tracker_note = found["tracker_note"].as_str().expect("a tracker note");
        assert!(!tracker_note.contains("is complete"), "{tracker_note}");

        // Control: nothing cut, tracker full: the sentence is true and stays.
        let plain_path = sample_file(files.path(), "plain.bin", b"\0plain_value\0");
        let (_, plain) = call(
            &client,
            "search_strings",
            json!({"file_path": plain_path, "query": "plain"}),
        )
        .await;
        assert!(plain.get("values_note").is_none(), "{plain}");
        let note = plain["tracker_note"].as_str().expect("a tracker note");
        assert!(
            note.contains("This search of the file is complete."),
            "{note}"
        );
    }

    #[tokio::test]
    async fn string_details_says_the_total_is_a_lower_bound_when_files_are_capped() {
        let cache = tempfile::tempdir().unwrap();
        let (state, client) = connect(cache.path()).await;
        let tracker = state.string_tracker();
        for n in 0..1_100 {
            tracker.track_strings_at(
                || vec![("capped_value_xyz".to_string(), 0)],
                &format!("/f/{n}"),
                &format!("hash{n:04}"),
                "search_strings",
                "k",
            );
        }
        let (error, details) = call(
            &client,
            "string_details",
            json!({"value": "capped_value_xyz"}),
        )
        .await;
        assert!(!error, "{details}");
        let note = details["total_note"].as_str().expect("a total note");
        assert!(note.contains("lower bound"), "{note}");
        // A value in a few files carries no such note.
        tracker.track_strings_at(
            || vec![("rare_value_xyz".to_string(), 0)],
            "/f/rare",
            "hashrare",
            "search_strings",
            "k",
        );
        let (_, few) = call(
            &client,
            "string_details",
            json!({"value": "rare_value_xyz"}),
        )
        .await;
        assert!(few.get("total_note").is_none(), "{few}");
    }

    #[tokio::test]
    async fn string_details_says_when_it_keeps_only_the_recent_occurrences() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let body = "repeated_value\0".repeat(1500);
        let path = sample_file(files.path(), "rep.bin", body.as_bytes());
        let (_state, client) = connect(cache.path()).await;
        call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "repeated_value"}),
        )
        .await;
        let (error, details) = call(
            &client,
            "string_details",
            json!({"value": "repeated_value"}),
        )
        .await;
        assert!(!error, "{details}");
        assert_eq!(details["total_occurrences"], 1500);
        let note = details["detail_note"].as_str().expect("a detail note");
        assert!(note.contains("search_strings"), "{note}");
        // A string with few occurrences carries no such note.
        let path = sample_file(files.path(), "few.bin", b"\0few_times_value\0");
        call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "few_times"}),
        )
        .await;
        let (_, few) = call(
            &client,
            "string_details",
            json!({"value": "few_times_value"}),
        )
        .await;
        assert!(few.get("detail_note").is_none(), "{few}");
    }

    #[tokio::test]
    async fn a_page_cut_by_the_budget_reports_the_rows_sent() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        for n in 0..1_000 {
            body.extend_from_slice(format!("padded value {n:05} {}\0", "x".repeat(150)).as_bytes());
        }
        let path = sample_file(files.path(), "rows.bin", &body);
        let (_state, client) = connect(cache.path()).await;
        let (error, page) = call(
            &client,
            "search_strings",
            json!({"file_path": path, "query": "padded", "limit": 500,
                   "max_output_bytes": 20000}),
        )
        .await;
        assert!(!error, "{page}");
        let sent = page["items"].as_array().unwrap().len();
        assert!(sent > 0 && sent < 500, "{sent}");
        assert_eq!(page["returned"], sent);
        assert_eq!(page["next_offset"], sent);
        assert_eq!(
            page["items"][sent - 1]["value"].as_str().unwrap()[13..18],
            format!("{:05}", sent - 1)
        );
    }

    #[tokio::test]
    async fn the_empty_history_hint_is_honest_without_a_cache() {
        let cache = tempfile::tempdir().unwrap();
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: cache.path().join("c"),
            cache_enabled: false,
            ..StateConfig::default()
        }));
        let server = FileScannerMcp::with_state(Arc::clone(&state));
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            if let Ok(service) = server.serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        let client = ().serve(client_io).await.unwrap();
        let (_, list) = call(&client, "cache_status", json!({"action": "list"})).await;
        let hint = list["hint"].as_str().unwrap();
        assert!(
            hint.contains("--no-cache") && hint.contains("nothing is recorded"),
            "{hint}"
        );
    }

    #[tokio::test]
    async fn one_file_with_two_min_lengths_is_counted_once_in_the_session_index() {
        let cache = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let path = sample_file(
            files.path(),
            "two.bin",
            b"\0/usr/lib/dyld\0..\0/usr/lib/dyld\0",
        );
        let (_state, client) = connect(cache.path()).await;
        for min in [4, 8] {
            call(
                &client,
                "search_strings",
                json!({"file_path": path, "query": "dyld", "min_length": min}),
            )
            .await;
        }
        let (_, details) = call(&client, "string_details", json!({"value": "/usr/lib/dyld"})).await;
        assert_eq!(details["total_occurrences"], 2, "{details}");
    }
}
