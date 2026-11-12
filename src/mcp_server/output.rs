//! Tool output: compact JSON, `None` fields omitted, a hard byte budget.
//!
//! Every tool result goes through [`respond`]. The budget is a ceiling on the
//! bytes of the text content block, so no tool can return more than
//! [`MAX_OUTPUT_BYTES`]. When something has to be cut, the biggest strings and
//! arrays are shortened first (never below the size of the next biggest one,
//! so one section cannot starve the others) and a `truncated` object says what
//! was cut and how to ask for the rest.

use std::{collections::BTreeMap, sync::Arc};

use rmcp::{
    handler::server::common::schema_for_input,
    model::{CallToolResult, ContentBlock, JsonObject},
    schemars::JsonSchema,
};
use serde_json::{json, Value};

/// Budget used when the caller does not pass `max_output_bytes`.
pub const DEFAULT_OUTPUT_BYTES: usize = 80_000;
/// Largest budget a caller can ask for.
pub const MAX_OUTPUT_BYTES: usize = 400_000;
/// Smallest budget that still has room for the `truncated` note.
pub const MIN_OUTPUT_BYTES: usize = 4_000;

/// Bytes kept free for the `truncated` note while cutting.
const NOTE_RESERVE: usize = 2_000;
/// Cut notes listed individually in the `truncated` object.
const MAX_LISTED_CUTS: usize = 10;
/// Strings shorter than this are never cut.
const MIN_CUT_STRING: usize = 200;
/// Arrays smaller than this (compact bytes) are never cut.
const MIN_CUT_ARRAY: usize = 64;

/// Name of the optional argument every tool accepts.
pub const BUDGET_ARG: &str = "max_output_bytes";

/// Items per page when the caller passes no `limit`.
pub const DEFAULT_LIMIT: usize = 50;
/// Most items one page can hold, whatever `limit` asks for.
pub const MAX_LIMIT: usize = 500;

/// The `offset` and `limit` arguments of a paged tool. Request structs copy
/// these two fields, or `#[serde(flatten)]` this type (which then cannot
/// combine with `deny_unknown_fields`).
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize, JsonSchema)]
pub struct PageArgs {
    /// Items to skip (default 0).
    #[schemars(description = "Number of items to skip (default 0)")]
    pub offset: Option<usize>,
    /// Items to return (default 50, at most 500).
    #[schemars(description = "Number of items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

impl PageArgs {
    /// [`page`] with this offset and limit (defaults filled in).
    pub fn page<T: serde::Serialize>(&self, items: &[T]) -> Value {
        page(
            items,
            self.offset.unwrap_or(0),
            self.limit.unwrap_or(DEFAULT_LIMIT),
        )
    }
}

/// One page of a list: `{items, total, returned, offset, next_offset}`.
///
/// `limit` is clamped to `1..=MAX_LIMIT`. `next_offset` is the `offset` that
/// asks for the following page and is left out on the last page. An `offset`
/// past the end gives an empty page that still reports `total`.
pub fn page<T: serde::Serialize>(items: &[T], offset: usize, limit: usize) -> Value {
    let total = items.len();
    let limit = limit.clamp(1, MAX_LIMIT);
    let start = offset.min(total);
    let end = start.saturating_add(limit).min(total);
    let mut out = serde_json::Map::new();
    out.insert(
        "items".into(),
        serde_json::to_value(&items[start..end]).unwrap_or(Value::Null),
    );
    out.insert("total".into(), total.into());
    out.insert("returned".into(), (end - start).into());
    out.insert("offset".into(), offset.into());
    if end < total {
        out.insert("next_offset".into(), end.into());
    }
    Value::Object(out)
}

/// A failed tool call: `isError: true` with a message a model can act on.
pub fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

/// Clamp a requested budget into `[MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES]`.
pub fn clamp_budget(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_OUTPUT_BYTES)
        .clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)
}

/// Remove the budget argument from a raw argument map.
///
/// Returns the budget the caller asked for (`None` when absent or `null`), or
/// an error message for a value that is not a non-negative integer.
pub fn take_budget(args: &mut JsonObject) -> Result<Option<usize>, String> {
    match args.remove(BUDGET_ARG) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(|n| Some(usize::try_from(n).unwrap_or(usize::MAX)))
            .ok_or_else(|| {
                format!(
                    "Invalid argument {BUDGET_ARG}: expected a non-negative integer \
                     (bytes, default {DEFAULT_OUTPUT_BYTES}, ceiling {MAX_OUTPUT_BYTES}), got {value}"
                )
            }),
    }
}

/// The `inputSchema` of a tool whose arguments are `T` plus [`BUDGET_ARG`].
///
/// `T` derives its schema (and, with `deny_unknown_fields`, forbids unknown
/// properties); this adds the output budget property to it.
pub fn input_schema_with_budget<T: JsonSchema + 'static>() -> Arc<JsonObject> {
    let schema = schema_for_input::<T>().unwrap_or_else(|error| {
        // A request struct that is not an object is a programming error.
        panic!("input schema for a tool request is not a JSON object: {error}")
    });
    let mut schema: JsonObject = (*schema).clone();
    let budget = json!({
        "type": "integer",
        "minimum": MIN_OUTPUT_BYTES,
        "maximum": MAX_OUTPUT_BYTES,
        "description": format!(
            "Hard cap on the size of this result in bytes (default {DEFAULT_OUTPUT_BYTES}, \
             ceiling {MAX_OUTPUT_BYTES}). Larger results are cut and the cut is listed \
             under 'truncated'."
        ),
    });
    match schema
        .entry("properties")
        .or_insert_with(|| Value::Object(JsonObject::new()))
    {
        Value::Object(properties) => {
            properties.insert(BUDGET_ARG.to_string(), budget);
        }
        other => *other = json!({ BUDGET_ARG: budget }),
    }
    Arc::new(schema)
}

/// Split raw tool arguments into the typed request, the output budget and a
/// copy of the arguments exactly as the caller sent them.
///
/// The error is the message for a tool error. Unknown arguments are rejected by `T` (`deny_unknown_fields`); the error
/// text names the offending argument and lists the accepted ones.
pub fn parse_request<T: serde::de::DeserializeOwned>(
    args: JsonObject,
) -> Result<(T, usize, JsonObject), String> {
    let raw = args.clone();
    let mut args = args;
    let budget = take_budget(&mut args)?;
    let request = serde_json::from_value::<T>(Value::Object(args)).map_err(|error| {
        format!(
            "Invalid arguments: {error}. Unknown arguments are rejected; see the tool's input \
             schema for the accepted ones (max_output_bytes is accepted too)."
        )
    })?;
    Ok((request, clamp_budget(budget), raw))
}

/// Turn the outcome of a blocking analysis into a tool result.
///
/// The outer error is a crash reported by `ServerState::run_blocking`, the
/// inner one a failure of the analysis itself; both are tool errors.
pub fn respond_result<T: serde::Serialize>(
    outcome: Result<Result<T, String>, String>,
    budget: usize,
) -> CallToolResult {
    match outcome {
        Err(crash) => tool_error(crash),
        Ok(Err(message)) => tool_error(message),
        Ok(Ok(result)) => match serde_json::to_value(&result) {
            Ok(value) => respond(value, budget),
            Err(error) => tool_error(format!("Could not serialize the result: {error}")),
        },
    }
}

/// Drop every object member that is `null`, recursively. Array elements stay.
pub fn strip_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        Value::Array(items) => {
            for v in items {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

/// Turn a result value into a tool result that fits `budget` bytes.
///
/// `None` fields (JSON `null` members) are omitted. The text block holds
/// compact JSON; there is no `structuredContent`, so the payload is not sent
/// twice.
pub fn respond(value: Value, budget: usize) -> CallToolResult {
    let budget = budget.clamp(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES);
    let text = render(value, budget);
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// A tool result from text that is already rendered (compact JSON within budget).
pub fn respond_text(text: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}

/// The compact JSON text [`respond`] puts in the content block.
pub fn render(mut value: Value, budget: usize) -> String {
    strip_nulls(&mut value);
    let original = compact_len(&value);
    if original <= budget {
        return value.to_string();
    }

    let mut cuts = Vec::new();
    shrink(&mut value, budget.saturating_sub(NOTE_RESERVE), &mut cuts);
    let mut root = match value {
        Value::Object(map) => map,
        other => {
            let mut map = JsonObject::new();
            map.insert("result".to_string(), other);
            map
        }
    };
    root.insert("truncated".to_string(), note(budget, original, &cuts));
    let text = Value::Object(root).to_string();
    if text.len() <= budget {
        return text;
    }
    preview_fallback(&text, budget, original)
}

/// Last resort: a short preview of the JSON that always fits.
fn preview_fallback(text: &str, budget: usize, original: usize) -> String {
    let mut keep = budget.saturating_sub(NOTE_RESERVE);
    loop {
        let preview = cut_str(text, keep);
        let rendered = json!({
            "preview": preview,
            "truncated": {
                "budget_bytes": budget,
                "original_bytes": original,
                "message": format!(
                    "The result could not be shortened section by section, so only the first \
                     {} bytes of its JSON are shown. Ask for a narrower view or raise \
                     {BUDGET_ARG} (ceiling {MAX_OUTPUT_BYTES}).",
                    preview.len()
                ),
            }
        })
        .to_string();
        // Escaping quotes and control characters can make the preview longer
        // than the text it came from, so shrink until the whole thing fits.
        if rendered.len() <= budget || keep == 0 {
            return rendered;
        }
        keep = keep.saturating_sub(rendered.len() - budget + 16);
    }
}

struct Cut {
    path: String,
    kind: &'static str,
    original: usize,
    kept: usize,
}

fn note(budget: usize, original: usize, cuts: &[Cut]) -> Value {
    let listed: Vec<Value> = cuts
        .iter()
        .take(MAX_LISTED_CUTS)
        .map(|cut| {
            json!({
                "path": cut.path,
                "kind": cut.kind,
                "original": cut.original,
                "kept": cut.kept,
            })
        })
        .collect();
    json!({
        "budget_bytes": budget,
        "original_bytes": original,
        "cut_total": cuts.len(),
        "cut": listed,
        "message": format!(
            "The result was cut to fit {budget} bytes. 'cut' lists the fields that were \
             shortened ('original' and 'kept' are bytes for strings and element counts for \
             arrays). To see more, ask for a narrower view (a single section, a filter, \
             or offset/limit paging where the tool has them) or raise {BUDGET_ARG} \
             (ceiling {MAX_OUTPUT_BYTES})."
        ),
    })
}

fn compact_len(value: &Value) -> usize {
    // `Value`'s Display is the compact serialization; count without allocating.
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
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

struct Candidate {
    path: String,
    is_string: bool,
    size: usize,
}

fn collect(value: &Value, path: &mut String, out: &mut Vec<Candidate>) {
    match value {
        Value::String(s) if s.len() >= MIN_CUT_STRING => out.push(Candidate {
            path: path.clone(),
            is_string: true,
            size: s.len() + 2,
        }),
        Value::Array(items) => {
            let before = out.len();
            for (index, item) in items.iter().enumerate() {
                let len = path.len();
                path.push('/');
                path.push_str(&index.to_string());
                collect(item, path, out);
                path.truncate(len);
            }
            // An array is cut by dropping elements only when none of its elements
            // has something bigger inside to shorten first (so a huge string does
            // not cost the array its small, valuable tail).
            if out.len() == before && !items.is_empty() {
                let size = compact_len(value);
                if size >= MIN_CUT_ARRAY {
                    out.push(Candidate {
                        path: path.clone(),
                        is_string: false,
                        size,
                    });
                }
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let len = path.len();
                path.push('/');
                path.push_str(&key.replace('~', "~0").replace('/', "~1"));
                collect(item, path, out);
                path.truncate(len);
            }
        }
        _ => {}
    }
}

/// Shorten the biggest strings and arrays until the value fits `target` bytes.
///
/// Each pass lowers every candidate above one common size level to that level
/// ("water filling"), choosing the level so the cuts add up to the excess. Big
/// sections therefore lose the most, small ones nothing, and no section is
/// wiped out while another stays whole.
fn shrink(value: &mut Value, target: usize, cuts: &mut Vec<Cut>) {
    for _ in 0..64 {
        let total = compact_len(value);
        if total <= target {
            return;
        }
        let mut candidates = Vec::new();
        collect(value, &mut String::new(), &mut candidates);
        if candidates.is_empty() {
            return;
        }
        candidates.sort_by_key(|c| std::cmp::Reverse(c.size));

        // Bytes to remove, with a margin for the cut markers.
        let excess = total - target;
        let mut needed = excess + 256;
        let mut sum = 0usize;
        let mut count = 0usize;
        let mut level = 0usize;
        for (index, candidate) in candidates.iter().enumerate() {
            sum += candidate.size;
            count = index + 1;
            needed += 48; // marker and bookkeeping per cut node
            let next = candidates.get(index + 1).map_or(0, |c| c.size);
            // Cost of lowering the first `count` candidates to `next`.
            let cost = sum - count * next;
            if cost >= needed {
                level = sum.saturating_sub(needed) / count;
                break;
            }
            level = next;
        }

        for candidate in candidates.iter().take(count) {
            let amount = candidate.size.saturating_sub(level);
            if amount == 0 {
                continue;
            }
            let Some(node) = value.pointer_mut(&candidate.path) else {
                continue;
            };
            let (original, kept) = if candidate.is_string {
                cut_string_node(node, amount)
            } else {
                cut_array_node(node, amount)
            };
            record(
                cuts,
                candidate.path.clone(),
                candidate.is_string,
                original,
                kept,
            );
        }
    }
}

fn record(cuts: &mut Vec<Cut>, path: String, is_string: bool, original: usize, kept: usize) {
    if let Some(existing) = cuts.iter_mut().find(|c| c.path == path) {
        existing.kept = kept;
        return;
    }
    cuts.push(Cut {
        path,
        kind: if is_string { "string" } else { "array" },
        original,
        kept,
    });
}

/// Longest prefix of `s` of at most `max` bytes, on a character boundary.
fn cut_str(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn cut_string_node(node: &mut Value, amount: usize) -> (usize, usize) {
    let Value::String(s) = node else {
        return (0, 0);
    };
    let original = s.len();
    let marker = format!("...[cut {amount} of {original} bytes]");
    let keep = original.saturating_sub(amount).saturating_sub(marker.len());
    let mut cut = cut_str(s, keep).to_string();
    let kept = cut.len();
    cut.push_str(&marker);
    *s = cut;
    (original, kept)
}

fn cut_array_node(node: &mut Value, amount: usize) -> (usize, usize) {
    let Value::Array(items) = node else {
        return (0, 0);
    };
    let original = items.len();
    let mut removed = 0usize;
    while removed < amount {
        let Some(last) = items.pop() else {
            break;
        };
        removed += compact_len(&last) + 1;
    }
    (original, items.len())
}

/// A map of per-path cut counts, handy in tests.
#[doc(hidden)]
pub fn cut_paths(text: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if let Some(Value::Array(list)) = value.pointer("/truncated/cut") {
            for cut in list {
                if let (Some(path), Some(kept)) = (
                    cut.get("path").and_then(Value::as_str),
                    cut.get("kept").and_then(Value::as_u64),
                ) {
                    out.insert(
                        path.to_string(),
                        usize::try_from(kept).unwrap_or(usize::MAX),
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {

    #[test]
    fn page_reports_total_returned_and_next_offset() {
        let items: Vec<u32> = (0..10).collect();
        let first = page(&items, 0, 4);
        assert_eq!(first["items"], json!([0, 1, 2, 3]));
        assert_eq!(first["total"], 10);
        assert_eq!(first["returned"], 4);
        assert_eq!(first["offset"], 0);
        assert_eq!(first["next_offset"], 4);
        let last = page(&items, 8, 4);
        assert_eq!(last["items"], json!([8, 9]));
        assert_eq!(last["returned"], 2);
        assert!(last.get("next_offset").is_none(), "{last}");
        let exact = page(&items, 6, 4);
        assert!(exact.get("next_offset").is_none(), "{exact}");
    }

    #[test]
    fn page_clamps_limit_and_tolerates_offsets_past_the_end() {
        let items: Vec<u32> = (0..1000).collect();
        let big = page(&items, 0, usize::MAX);
        assert_eq!(big["returned"], MAX_LIMIT);
        assert_eq!(big["next_offset"], MAX_LIMIT);
        assert_eq!(page(&items, 0, 0)["returned"], 1);
        let past = page(&items, 5_000, 10);
        assert_eq!(past["items"], json!([]));
        assert_eq!(past["total"], 1000);
        assert_eq!(past["returned"], 0);
        assert!(past.get("next_offset").is_none());
        assert_eq!(page::<u32>(&[], 0, 10)["total"], 0);
        assert_eq!(page(&items, usize::MAX, usize::MAX)["returned"], 0);
    }

    #[test]
    fn page_args_default_to_the_first_default_limit_items() {
        let items: Vec<usize> = (0..120).collect();
        let args: PageArgs = serde_json::from_value(json!({})).unwrap();
        let first = args.page(&items);
        assert_eq!(first["returned"], DEFAULT_LIMIT);
        assert_eq!(first["next_offset"], DEFAULT_LIMIT);
        let args: PageArgs = serde_json::from_value(json!({"offset": 100, "limit": 50})).unwrap();
        assert_eq!(args.page(&items)["returned"], 20);
    }
    use super::*;

    #[test]
    fn small_values_are_compact_and_drop_nulls() {
        let text = render(
            json!({"a": 1, "b": null, "c": {"d": null, "e": [null, 2]}}),
            80_000,
        );
        assert_eq!(text, r#"{"a":1,"c":{"e":[null,2]}}"#);
    }

    #[test]
    fn oversized_string_is_cut_and_reported() {
        let value = json!({"name": "x", "hex_dump": "ab".repeat(100_000)});
        let text = render(value, 10_000);
        assert!(text.len() <= 10_000, "{}", text.len());
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["name"], "x");
        assert_eq!(parsed["truncated"]["cut"][0]["path"], "/hex_dump");
        assert_eq!(parsed["truncated"]["original_bytes"], 200_026);
        assert!(parsed["hex_dump"].as_str().unwrap().contains("...[cut"));
    }

    #[test]
    fn arrays_are_cut_by_elements_and_siblings_survive() {
        let value = json!({
            "strings": (0..50_000).map(|i| format!("string number {i}")).collect::<Vec<_>>(),
            "small": ["keep", "me"],
        });
        let text = render(value, 20_000);
        assert!(text.len() <= 20_000);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["small"], json!(["keep", "me"]));
        let kept = parsed["strings"].as_array().unwrap().len();
        assert!(kept > 100 && kept < 50_000, "kept {kept}");
        assert_eq!(parsed["truncated"]["cut"][0]["kind"], "array");
    }

    #[test]
    fn a_huge_string_in_an_array_is_cut_before_the_array_loses_elements() {
        let value = json!({"strings": ["a".repeat(500_000), "malware_token"]});
        let text = render(value, 10_000);
        assert!(text.len() <= 10_000);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        let strings = parsed["strings"].as_array().unwrap();
        assert_eq!(strings.len(), 2, "{text}");
        assert_eq!(strings[1], "malware_token");
        assert_eq!(parsed["truncated"]["cut"][0]["path"], "/strings/0");
    }

    #[test]
    fn nested_arrays_of_objects_are_shortened_without_falling_back_to_a_preview() {
        let cfgs: Vec<Value> = (0..400)
            .map(|i| {
                json!({
                    "name": format!("function_{i}"),
                    "nodes": (0..40).map(|n| json!({"id": n, "label": format!("block {n}")})).collect::<Vec<_>>(),
                    "edges": (0..40).map(|n| json!([n, n + 1])).collect::<Vec<_>>(),
                })
            })
            .collect();
        let text = render(json!({"control_flow": {"cfgs": cfgs}, "small": 1}), 30_000);
        assert!(text.len() <= 30_000, "{}", text.len());
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert!(
            parsed.get("preview").is_none(),
            "should shorten, not preview"
        );
        assert_eq!(parsed["small"], 1);
        assert!(parsed["truncated"]["cut_total"].as_u64().unwrap() > 10);
    }

    #[test]
    fn biggest_sections_are_cut_evenly() {
        let value = json!({"a": "x".repeat(60_000), "b": "y".repeat(60_000)});
        let text = render(value, 40_000);
        assert!(text.len() <= 40_000);
        let kept = cut_paths(&text);
        let (a, b) = (kept["/a"], kept["/b"]);
        assert!(a > 10_000 && b > 10_000, "{a} {b}");
    }

    #[test]
    fn nothing_exceeds_the_ceiling_even_with_many_small_keys() {
        let map: serde_json::Map<String, Value> = (0..40_000)
            .map(|i| (format!("key_{i}"), Value::from(i)))
            .collect();
        let text = render(Value::Object(map), 5_000);
        assert!(text.len() <= 5_000, "{}", text.len());
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert!(parsed.get("preview").is_some());
    }

    #[test]
    fn budget_is_clamped_and_validated() {
        assert_eq!(clamp_budget(None), DEFAULT_OUTPUT_BYTES);
        assert_eq!(clamp_budget(Some(10)), MIN_OUTPUT_BYTES);
        assert_eq!(clamp_budget(Some(usize::MAX)), MAX_OUTPUT_BYTES);
        let mut args = JsonObject::new();
        args.insert(BUDGET_ARG.into(), json!("lots"));
        assert!(take_budget(&mut args).unwrap_err().contains(BUDGET_ARG));
        args.insert(BUDGET_ARG.into(), json!(5000));
        assert_eq!(take_budget(&mut args).unwrap(), Some(5000));
        assert!(args.is_empty());
    }

    #[test]
    fn multibyte_strings_are_cut_on_a_character_boundary() {
        let value = json!({"s": "é".repeat(50_000)});
        let text = render(value, 8_000);
        assert!(text.len() <= 8_000);
        assert!(serde_json::from_str::<Value>(&text).is_ok());
    }
}
