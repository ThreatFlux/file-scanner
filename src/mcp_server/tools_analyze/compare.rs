//! `compare_files`: how two files differ, in one small answer.
//!
//! Each file's `binary_info`, `strings` and `entropy` sections come from the
//! section cache (or are computed and stored), so comparing files already
//! analyzed is fast and a later `query_analysis` on either is a hit.

use std::collections::{BTreeMap, BTreeSet};

use rmcp::{model::JsonObject, schemars};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{
    identify,
    sections::{clip, plan, Ctx, Engine, Options},
};
use crate::mcp_server::{
    output::{parse_request, render, respond_text, tool_error},
    paths::Expect,
    FileScannerMcp,
};

/// Items listed per group when the caller names no `max_items`.
pub const DEFAULT_ITEMS: usize = 20;
/// Most items listed per group.
pub const MAX_ITEMS: usize = 200;

pub(super) const COMPARE_FILES_DESCRIPTION: &str = "Compare two files in one small answer: are \
they identical (SHA-256), how do size and entropy differ, and what do their imports, section \
names and categorized strings (URLs, IPs, paths, ...) share: counts of common / only in a / only \
in b with a similarity ratio and capped lists (`max_items`, default 20). Use it to see whether a \
sample is a variant of another, or what changed between two versions of a binary. It does not diff \
bytes or code. Call analyze_file on each file first if you do not know what they are; drill into \
a difference with query_analysis (filter on the string or import) afterwards.";

/// The arguments of `compare_files`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareFilesRequest {
    #[schemars(description = "Absolute path of the first file (a leading ~/ is expanded)")]
    pub file_a: String,
    #[schemars(description = "Absolute path of the second file (a leading ~/ is expanded)")]
    pub file_b: String,
    #[schemars(
        description = "Most items listed in each common / only_in_a / only_in_b group (default 20, at most 200)"
    )]
    pub max_items: Option<usize>,
}

/// What one side of the comparison is made of.
#[derive(Default)]
struct Side {
    path: String,
    sha256: String,
    size: u64,
    format: Option<String>,
    architecture: Option<String>,
    entropy: Option<f64>,
    imports: BTreeSet<String>,
    sections: BTreeSet<String>,
    /// String value to its category.
    strings: BTreeMap<String, String>,
    notes: Vec<String>,
}

fn load_side(
    engine: &mut Engine<'_>,
    side: &mut Side,
    label: &str,
    options: &Options,
    mtime_ns: u128,
) {
    let mut load = |name: &'static str| {
        let planned = plan(name, options, &side.path, mtime_ns);
        engine
            .load(&planned)
            .map_err(|failure| format!("{label}: {name}: {}", failure.message()))
    };
    let binary_info = load("binary_info");
    let strings = load("strings");
    let entropy = load("entropy");
    match binary_info {
        Ok(info) => {
            side.format = info.get("format").and_then(Value::as_str).map(String::from);
            let raw = matches!(side.format.as_deref(), Some("Raw" | "Unknown") | None);
            if raw {
                side.notes.push(format!(
                    "{label}: binary_info: not an executable format, so it has no imports or sections"
                ));
            }
            side.architecture = info
                .get("architecture")
                .and_then(Value::as_str)
                .map(String::from);
            // A raw file's one "section" is a placeholder, not structure.
            let keys: &[&str] = if raw { &[] } else { &["imports", "sections"] };
            for (key, set) in [
                ("imports", &mut side.imports),
                ("sections", &mut side.sections),
            ]
            .into_iter()
            .filter(|(key, _)| keys.contains(key))
            {
                for item in info
                    .get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = if key == "sections" {
                        item.get("name").and_then(Value::as_str)
                    } else {
                        item.as_str()
                    };
                    if let Some(name) = name {
                        set.insert(name.to_string());
                    }
                }
            }
        }
        Err(note) => side.notes.push(note),
    }
    match strings {
        Ok(section) => {
            if section.get("truncated").and_then(Value::as_bool) == Some(true) {
                side.notes.push(format!(
                    "{label}: strings: only the first {} of {} categorized strings were \
                     compared (the stored list is cut)",
                    section
                        .get("strings")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                    section.get("total_count").unwrap_or(&Value::Null)
                ));
            }
            for s in section
                .get("strings")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(category), Some(value)) = (
                    s.get("category").and_then(Value::as_str),
                    s.get("value").and_then(Value::as_str),
                ) {
                    side.strings
                        .entry(value.to_string())
                        .or_insert_with(|| category.to_string());
                }
            }
        }
        Err(note) => side.notes.push(note),
    }
    match entropy {
        Ok(section) => side.entropy = section.get("overall_entropy").and_then(Value::as_f64),
        Err(note) => side.notes.push(note),
    }
}

/// Counts, a similarity ratio and capped lists of two sets. `show` renders an
/// item for the lists.
fn diff<K: Ord + Clone>(
    a: &BTreeSet<K>,
    b: &BTreeSet<K>,
    max: usize,
    show: impl Fn(&K) -> String,
) -> Value {
    let common: Vec<&K> = a.intersection(b).collect();
    let only_a: Vec<&K> = a.difference(b).collect();
    let only_b: Vec<&K> = b.difference(a).collect();
    let union = common.len() + only_a.len() + only_b.len();
    let list = |items: &[&K]| -> Vec<String> { items.iter().take(max).map(|k| show(k)).collect() };
    let mut out = Map::new();
    out.insert("a".into(), a.len().into());
    out.insert("b".into(), b.len().into());
    out.insert("common".into(), common.len().into());
    out.insert("only_in_a".into(), only_a.len().into());
    out.insert("only_in_b".into(), only_b.len().into());
    if union > 0 {
        out.insert(
            "similarity".into(),
            ((common.len() as f64 / union as f64 * 1000.0).round() / 1000.0).into(),
        );
    }
    out.insert("common_items".into(), list(&common).into());
    out.insert("only_in_a_items".into(), list(&only_a).into());
    out.insert("only_in_b_items".into(), list(&only_b).into());
    let cut = common.len().saturating_sub(max)
        + only_a.len().saturating_sub(max)
        + only_b.len().saturating_sub(max);
    if cut > 0 {
        out.insert(
            "lists_capped".into(),
            format!(
                "each list shows at most {max} items; {cut} more exist (raise max_items, or use \
                 query_analysis with a filter on one file)"
            )
            .into(),
        );
    }
    Value::Object(out)
}

fn identity(side: &Side) -> Value {
    json!({
        "file_path": side.path,
        "size": side.size,
        "sha256": side.sha256,
        "format": side.format,
        "architecture": side.architecture,
        "entropy": side.entropy,
    })
}

impl FileScannerMcp {
    /// The `compare_files` tool body.
    pub(crate) async fn run_compare_files(&self, args: JsonObject) -> rmcp::model::CallToolResult {
        let (request, budget, _raw) = match parse_request::<CompareFilesRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let max = request
            .max_items
            .unwrap_or(DEFAULT_ITEMS)
            .clamp(1, MAX_ITEMS);
        let mut identities = Vec::new();
        for raw in [&request.file_a, &request.file_b] {
            match identify(self, raw, Expect::File).await {
                Ok(found) => identities.push(found),
                Err(error) => return *error,
            }
        }
        let (b_path, b_sha, b_size, b_mtime) = identities.pop().expect("two identities");
        let (a_path, a_sha, a_size, a_mtime) = identities.pop().expect("two identities");
        let state = std::sync::Arc::clone(&self.state);
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("compare_files", move || {
                let mut a = Side {
                    path: a_path.to_string_lossy().into_owned(),
                    sha256: a_sha.clone(),
                    size: a_size,
                    ..Side::default()
                };
                let mut b = Side {
                    path: b_path.to_string_lossy().into_owned(),
                    sha256: b_sha.clone(),
                    size: b_size,
                    ..Side::default()
                };
                if a_sha == b_sha {
                    return render(
                        json!({
                            "identical": true,
                            "sha256": a_sha,
                            "size": a_size,
                            "file_a": a.path,
                            "file_b": b.path,
                            "note": "The two files have the same content (same SHA-256); there is nothing to compare.",
                        }),
                        budget,
                    );
                }
                let options = Options::default();
                let (mut computed, mut cached) = (0, 0);
                for (side, path, sha, mtime, label) in [
                    (&mut a, &a_path, &a_sha, a_mtime, "file_a"),
                    (&mut b, &b_path, &b_sha, b_mtime, "file_b"),
                ] {
                    let ctx = Ctx::new(path, &runtime, options.clone(), Some(state.path_policy()));
                    let mut engine = Engine::new(state.section_cache(), sha, ctx, state.cache_enabled());
                    load_side(&mut engine, side, label, &options, mtime);
                    computed += engine.computed;
                    cached += engine.cached;
                }
                let entropy_delta = match (a.entropy, b.entropy) {
                    (Some(x), Some(y)) => Some(((y - x) * 1000.0).round() / 1000.0),
                    _ => None,
                };
                let mut value = json!({
                    "identical": false,
                    "file_a": identity(&a),
                    "file_b": identity(&b),
                    "size_delta": b.size as i128 - a.size as i128,
                    "entropy_delta": entropy_delta,
                    "same_format": a.format.is_some() && a.format == b.format,
                    "imports": diff(&a.imports, &b.imports, max, Clone::clone),
                    "sections": diff(&a.sections, &b.sections, max, Clone::clone),
                    "categorized_strings": diff(
                        &a.strings.keys().cloned().collect(),
                        &b.strings.keys().cloned().collect(),
                        max,
                        |v| {
                            let category = a
                                .strings
                                .get(v)
                                .or_else(|| b.strings.get(v))
                                .map_or("", String::as_str);
                            format!("{category}: {}", clip(v))
                        },
                    ),
                    "next_steps": [
                        {"tool": "query_analysis",
                         "arguments": {"file_path": a.path, "section": "strings", "category": "URL"},
                         "gives": "every URL string of file_a (the same call with file_b for the other side)"},
                        {"tool": "analyze_file",
                         "arguments": {"file_path": b.path},
                         "gives": "the overview of file_b"},
                    ],
                    "cache": if computed == 0 { "hit" } else if cached == 0 { "miss" } else { "partial" },
                });
                let notes: Vec<String> = a.notes.iter().chain(b.notes.iter()).cloned().collect();
                if !notes.is_empty() {
                    value["notes"] = notes.into();
                }
                render(value, budget)
            })
            .await;
        match outcome {
            Err(crash) => tool_error(crash),
            Ok(text) => respond_text(text),
        }
    }
}
