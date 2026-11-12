//! Filtering and paging the lists inside a cached section.

use regex::Regex;
use serde_json::Value;

use crate::mcp_server::output::{fit_rows, page, DEFAULT_LIMIT};

use super::sections::{brief, lists, ListSpec, BEHAVIOR_GROUPS};

/// Row fields `category` is matched against (besides a string's category).
const CATEGORY_FIELDS: [&str; 9] = [
    "category",
    "severity",
    "function_type",
    "library_type",
    "technique_type",
    "pattern_type",
    "issue_type",
    "indicator_type",
    "block_type",
];

/// What a `query_analysis` call asks of a section.
pub(super) struct Params<'a> {
    pub list: Option<&'a str>,
    pub filter: Option<&'a str>,
    pub regex: bool,
    pub category: Option<&'a str>,
    pub encoding: Option<&'a str>,
    pub offset: usize,
    pub limit: usize,
    pub detail: bool,
}

enum Matcher {
    None,
    Substring(String),
    Pattern(Regex),
}

impl Matcher {
    fn new(filter: Option<&str>, regex: bool) -> Result<Self, String> {
        let Some(filter) = filter.filter(|f| !f.is_empty()) else {
            return Ok(Self::None);
        };
        if regex {
            regex::RegexBuilder::new(filter)
                // The fields of a non-string row are joined with newlines, so
                // `^name$` has to match at a line.
                .multi_line(true)
                .size_limit(1 << 20)
                .build()
                .map(Self::Pattern)
                .map_err(|e| {
                    format!(
                        "filter is not a valid regular expression: {e}. Fix the pattern, or set \
                         regex to false to search for the text as it is."
                    )
                })
        } else {
            Ok(Self::Substring(filter.to_lowercase()))
        }
    }

    /// Byte position of the first match in `text`, when there is one.
    fn find(&self, text: &str) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Substring(needle) => text.to_lowercase().find(needle),
            Self::Pattern(pattern) => pattern.find(text).map(|m| m.start()),
        }
    }

    fn is_match(&self, text: &str) -> bool {
        match self {
            Self::None => true,
            Self::Substring(needle) => text.to_lowercase().contains(needle),
            Self::Pattern(pattern) => pattern.is_match(text),
        }
    }
}

/// The test a string must pass to be kept by a re-scan of the file: the same
/// filter, category and encoding `answer` applies to a cached list.
pub(super) fn string_filter(
    params: &Params<'_>,
) -> Result<impl Fn(&crate::strings::FoundString) -> bool, String> {
    let matcher = Matcher::new(params.filter, params.regex)?;
    let category = params.category.map(str::to_string);
    let encoding = params.encoding.map(str::to_string);
    Ok(move |found: &crate::strings::FoundString| {
        if let Some(wanted) = &category {
            if !found
                .category
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case(wanted))
            {
                return false;
            }
        }
        if let Some(wanted) = &encoding {
            if !found.encoding.name().eq_ignore_ascii_case(wanted) {
                return false;
            }
        }
        matcher.is_match(&found.value)
    })
}

/// The text a filter is matched against: a string's value, otherwise every
/// scalar field of the row (and the strings in its first-level lists).
fn haystack(item: &Value) -> String {
    match item {
        Value::String(s) => s.clone(),
        Value::Object(map) => {
            let mut text = String::new();
            for value in map.values() {
                match value {
                    Value::String(s) => {
                        text.push_str(s);
                        text.push('\n');
                    }
                    Value::Number(_) | Value::Bool(_) => {
                        text.push_str(&value.to_string());
                        text.push('\n');
                    }
                    Value::Array(items) => {
                        for inner in items.iter().filter_map(Value::as_str) {
                            text.push_str(inner);
                            text.push('\n');
                        }
                    }
                    _ => {}
                }
            }
            text
        }
        other => other.to_string(),
    }
}

fn category_matches(item: &Value, wanted: &str) -> bool {
    CATEGORY_FIELDS.iter().any(|field| {
        item.get(*field)
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case(wanted))
    })
}

/// The rows of one list, each with the group it came from (behaviors only).
fn rows<'v>(spec: &ListSpec, section: &'v Value) -> Vec<(Option<&'static str>, &'v Value)> {
    if spec.pointer == "@behaviors" {
        let mut out = Vec::new();
        for group in BEHAVIOR_GROUPS {
            if let Some(items) = section.get(group).and_then(Value::as_array) {
                out.extend(items.iter().map(|item| (Some(group), item)));
            }
        }
        return out;
    }
    section
        .pointer(spec.pointer)
        .and_then(Value::as_array)
        .map(|items| items.iter().map(|item| (None, item)).collect())
        .unwrap_or_default()
}

/// One page of the matching rows of a list of `name`d section `section`.
pub(super) fn answer(
    name: &str,
    section: &Value,
    params: &Params<'_>,
    budget: usize,
) -> Result<Value, String> {
    let specs = lists(name);
    if specs.is_empty() {
        return Err(format!(
            "The {name} section has no list to page: analyze_file returns it whole \
             (sections: [\"{name}\"])."
        ));
    }
    let spec = match params.list {
        None => &specs[0],
        Some(wanted) => specs.iter().find(|s| s.name == wanted).ok_or_else(|| {
            format!(
                "The {name} section has no list called '{wanted}'. Lists: {}.",
                specs.iter().map(|s| s.name).collect::<Vec<_>>().join(", ")
            )
        })?,
    };
    let matcher = Matcher::new(params.filter, params.regex)?;
    if name == "strings" {
        if let Some(encoding) = params.encoding {
            if !["ascii", "utf16le", "utf16be"]
                .iter()
                .any(|e| e.eq_ignore_ascii_case(encoding))
            {
                return Err(format!(
                    "encoding '{encoding}' is not one of: ascii, utf16le, utf16be."
                ));
            }
        }
    }
    let all = rows(spec, section);
    let unfiltered = all.len();
    let is_strings = name == "strings";
    let matched: Vec<&(Option<&'static str>, &Value)> = all
        .iter()
        .filter(|(_, item)| {
            if let Some(wanted) = params.category {
                let ok = if is_strings {
                    item.get("category")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.eq_ignore_ascii_case(wanted))
                } else {
                    category_matches(item, wanted)
                };
                if !ok {
                    return false;
                }
            }
            if is_strings {
                if let Some(encoding) = params.encoding {
                    let actual = item.get("encoding").and_then(Value::as_str).unwrap_or("");
                    if !actual.eq_ignore_ascii_case(encoding) {
                        return false;
                    }
                }
            }
            match &matcher {
                Matcher::None => true,
                m if is_strings => m.is_match(
                    item.get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
                m => m.is_match(&haystack(item)),
            }
        })
        .collect();

    let mut paged = page(&matched, params.offset, params.limit);
    // Only the page is turned into rows.
    let shown: Vec<Value> = paged["items"]
        .as_array()
        .map(|_| {
            let start = params.offset.min(matched.len());
            let end = start
                .saturating_add(params.limit.clamp(1, crate::mcp_server::output::MAX_LIMIT))
                .min(matched.len());
            let names = (name == "call_graph"
                && matches!(spec.name, "edges" | "unreachable_functions"))
            .then(|| node_names(section));
            let unreachable = name == "call_graph" && spec.name == "unreachable_functions";
            matched[start..end]
                .iter()
                .map(|(group, item)| {
                    if let (true, Some(address), Some(names)) = (unreachable, item.as_u64(), &names)
                    {
                        // A bare address becomes a row with the function's name.
                        return serde_json::json!({
                            "function_address": address,
                            "function_name": names.get(&address).map(|n| super::sections::clip(n)),
                        });
                    }
                    let mut out = row(*group, item, params.detail, is_strings, &matcher);
                    if !params.detail {
                        if let Some(names) = names.as_ref().filter(|_| !unreachable) {
                            name_edge(&mut out, names);
                        }
                        if name == "taint" && spec.name == "flows" {
                            out = flow_row(item);
                        }
                    }
                    out
                })
                .collect()
        })
        .unwrap_or_default();
    paged["items"] = shown.into();
    paged["section"] = name.into();
    paged["list"] = spec.name.into();
    paged["unfiltered_total"] = unfiltered.into();
    let mut applied = serde_json::Map::new();
    if let Some(f) = params.filter.filter(|f| !f.is_empty()) {
        applied.insert("filter".into(), f.into());
        applied.insert("regex".into(), params.regex.into());
    }
    if let Some(c) = params.category {
        applied.insert("category".into(), c.into());
    }
    if let Some(e) = params.encoding.filter(|_| is_strings) {
        applied.insert("encoding".into(), e.into());
    }
    if !applied.is_empty() {
        paged["applied"] = Value::Object(applied);
    }
    if let Some(wanted) = params.category {
        if matched.is_empty() {
            let mut present: Vec<String> = all
                .iter()
                .flat_map(|(_, item)| {
                    CATEGORY_FIELDS
                        .iter()
                        .filter_map(|f| item.get(*f).and_then(Value::as_str))
                })
                .map(str::to_string)
                .collect();
            present.sort();
            present.dedup();
            present.truncate(30);
            paged["note"] = format!(
                "No row has category '{wanted}'. Categories in this list: {}.",
                if present.is_empty() {
                    "none".to_string()
                } else {
                    present.join(", ")
                }
            )
            .into();
        }
    }
    paged["available_lists"] = specs.iter().map(|s| s.name).collect::<Vec<_>>().into();
    if paged.get("next_offset").is_some() {
        paged["hint"] = format!(
            "More rows match: repeat the call with offset {} (limit defaults to {DEFAULT_LIMIT}).",
            paged["next_offset"]
        )
        .into();
    }
    // Room for the fields the caller adds (file_path, cache).
    fit_rows(&mut paged, "items", budget, params.offset, matched.len());
    Ok(paged)
}

/// Function names by address, for naming the ends of an edge.
fn node_names(section: &Value) -> std::collections::HashMap<u64, String> {
    section
        .pointer("/graph/nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|node| {
            Some((
                node.get("function_address")?.as_u64()?,
                node.get("function_name")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// An edge row with the caller's and the callee's names added.
fn name_edge(row: &mut Value, names: &std::collections::HashMap<u64, String>) {
    let lookup = |key: &str| {
        row.get(key)
            .and_then(Value::as_u64)
            .and_then(|a| names.get(&a))
            .map(|n| super::sections::clip(n))
    };
    let (caller, callee) = (lookup("caller"), lookup("callee"));
    if let Some(map) = row.as_object_mut() {
        if let Some(caller) = caller {
            map.insert("caller_name".into(), caller.into());
        }
        if let Some(callee) = callee {
            map.insert("callee_name".into(), callee.into());
        }
    }
}

/// A taint flow as one flat row: where the data comes from and where it ends.
fn flow_row(flow: &Value) -> Value {
    let end = |key: &str| {
        let item = flow.get(key);
        let at = item.and_then(|i| i.get("location"));
        serde_json::json!({
            "line": at.and_then(|l| l.get("line_number")),
            "function": at.and_then(|l| l.get("function_name")),
            "code": at
                .and_then(|l| l.get("code_snippet"))
                .and_then(Value::as_str)
                .map(super::sections::clip),
            "description": item
                .and_then(|i| i.get("description"))
                .and_then(Value::as_str)
                .map(super::sections::clip),
        })
    };
    serde_json::json!({
        "flow_id": flow.get("flow_id"),
        "vulnerability_type": flow.get("vulnerability_type"),
        "risk_score": flow.get("risk_score"),
        "is_sanitized": flow.get("is_sanitized"),
        "source": end("source"),
        "sink": end("sink"),
        "steps": flow.get("path").and_then(Value::as_array).map(Vec::len),
        "attack_vector": flow.get("attack_vector").and_then(Value::as_str).map(super::sections::clip),
    })
}

fn row(
    group: Option<&str>,
    item: &Value,
    detail: bool,
    is_strings: bool,
    matcher: &Matcher,
) -> Value {
    let mut out = if is_strings {
        let mut out = item.clone();
        if let Some(value) = item.get("value").and_then(Value::as_str) {
            out["value"] = if detail {
                value.into()
            } else {
                // Centered on the filter's match, otherwise on the text that
                // made the string a URL, an address, a secret ...
                let hit = matcher.find(value).or_else(|| {
                    item.get("category")
                        .and_then(Value::as_str)
                        .and_then(|_| crate::strings::category_span(value))
                        .map(|(from, _)| from)
                });
                clip_around(value, hit).into()
            };
        }
        out
    } else if detail {
        item.clone()
    } else {
        brief(item)
    };
    if let (Some(group), Some(map)) = (group, out.as_object_mut()) {
        map.insert("group".into(), group.into());
    }
    out
}

/// Strings in rows are clipped at a few hundred characters (`detail` shows
/// all); when a filter matched, the clip is centered on the first match so the
/// matched text is always visible.
fn clip_around(s: &str, hit: Option<usize>) -> String {
    const LIMIT: usize = 500;
    if s.len() <= LIMIT {
        return s.to_string();
    }
    let Some(hit) = hit.map(|h| h.min(s.len())).filter(|h| *h > LIMIT / 2) else {
        return format!("{}…", &s[..s.floor_char_boundary(LIMIT)]);
    };
    let start = s.ceil_char_boundary(hit.saturating_sub(LIMIT / 2));
    let end = s.floor_char_boundary((start + LIMIT).min(s.len()));
    format!(
        "…{}{}",
        &s[start..end],
        if end < s.len() { "…" } else { "" }
    )
}
