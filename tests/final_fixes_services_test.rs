//! Final fixes of the REST cache and string routes and of `string_details`,
//! driven in process (no socket): `POST /cache/clear` scope in query or body,
//! `limit` counting visible rows on `/strings/search` and `/strings/related`,
//! and `string_details` never presenting a capped count as the total.

use std::{path::Path, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};
use file_scanner::mcp_server::{FileScannerMcp, ServerState, StateConfig};
use file_scanner::mcp_transport::rest::{call_tool_direct, router, RestState, ToolCallParams};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

struct Fixture {
    app: Router,
    handler: FileScannerMcp,
    state: Arc<ServerState>,
    data: TempDir,
    _cache: TempDir,
}

fn fixture(rooted: bool) -> Fixture {
    let cache = TempDir::new().unwrap();
    let data = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache.path().to_path_buf(),
        allow_roots: if rooted {
            vec![data.path().to_path_buf()]
        } else {
            Vec::new()
        },
        ..StateConfig::default()
    }));
    let handler = FileScannerMcp::with_state(Arc::clone(&state));
    let app = router(RestState::new(handler.clone()));
    Fixture {
        app,
        handler,
        state,
        data,
        _cache: cache,
    }
}

async fn send(app: &Router, method: Method, uri: &str, body: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(text) => {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(text.to_string())
        }
        None => Body::empty(),
    };
    let reply = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = reply.status();
    let bytes = to_bytes(reply.into_body(), 1 << 22).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, value)
}

async fn call(f: &Fixture, name: &str, arguments: Value) -> (bool, Value) {
    let reply = call_tool_direct(
        &f.handler,
        ToolCallParams {
            name: name.to_string(),
            arguments: arguments.as_object().cloned().unwrap_or_default(),
        },
    )
    .await
    .unwrap();
    let text = reply["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    (
        reply["isError"] == json!(true),
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.to_string_lossy().into_owned()
}

/// What the tracker and the history hold: (history entries, tracked strings).
async fn held(f: &Fixture) -> (u64, u64) {
    let (_, stats) = send(&f.app, Method::GET, "/cache/stats", None).await;
    let strings = f.state.string_tracker().get_statistics(None);
    (
        stats["total_entries"].as_u64().unwrap(),
        strings.total_unique_strings as u64,
    )
}

/// Fill the history (one analysis) and the tracker (strings of one file).
async fn fill(f: &Fixture) {
    let path = write(
        f.data.path(),
        "fill.txt",
        "a distinctive string for the tracker\n",
    );
    let (error, _) = call(
        f,
        "analyze_file",
        json!({"file_path": path, "strings": true}),
    )
    .await;
    assert!(!error);
    let (error, found) = call(
        f,
        "search_strings",
        json!({"file_path": path, "query": "distinctive"}),
    )
    .await;
    assert!(!error, "{found}");
    let (history, strings) = held(f).await;
    assert!(history > 0 && strings > 0, "fill: {history} {strings}");
}

#[tokio::test]
async fn cache_clear_reads_the_scope_from_the_query_or_the_body() {
    // (query, body, what must remain: (history kept, strings kept), or a 400)
    let all = (false, false);
    let analysis = (false, true);
    let strings = (true, false);
    type Case = (&'static str, Option<&'static str>, Result<(bool, bool), ()>);
    let cases: Vec<Case> = vec![
        ("", None, Ok(all)),
        ("", Some(""), Ok(all)),
        ("", Some("{}"), Ok(all)),
        ("?scope=all", None, Ok(all)),
        ("?scope=analysis", None, Ok(analysis)),
        ("?scope=strings", None, Ok(strings)),
        ("?scope=bogus", None, Err(())),
        ("", Some(r#"{"scope":"all"}"#), Ok(all)),
        ("", Some(r#"{"scope":"analysis"}"#), Ok(analysis)),
        ("", Some(r#"{"scope":"strings"}"#), Ok(strings)),
        ("", Some(r#"{"scope":"bogus"}"#), Err(())),
        ("", Some(r#"{"scope":"analysis","extra":1}"#), Err(())),
        ("", Some(r#"{"extra":1}"#), Err(())),
        ("", Some("[]"), Err(())),
        ("", Some(r#""analysis""#), Err(())),
        ("", Some("null"), Err(())),
        ("", Some(r#"{"scope":"#), Err(())),
        ("", Some(r#"{"scope":3}"#), Err(())),
        ("?scope=analysis", Some(r#"{"scope":"strings"}"#), Err(())),
        ("?scope=all", Some(r#"{"scope":"analysis"}"#), Err(())),
        (
            "?scope=analysis",
            Some(r#"{"scope":"analysis"}"#),
            Ok(analysis),
        ),
        ("?scope=analysis", Some("{}"), Ok(analysis)),
        ("?scope=bogus", Some(r#"{"scope":"analysis"}"#), Err(())),
    ];
    for (query, body, expected) in cases {
        let f = fixture(false);
        fill(&f).await;
        let before = held(&f).await;
        let (status, reply) =
            send(&f.app, Method::POST, &format!("/cache/clear{query}"), body).await;
        let after = held(&f).await;
        let label = format!("{query} {body:?}: {status} {reply}");
        match expected {
            Err(()) => {
                assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
                assert_eq!(after, before, "a 400 cleared something: {label}");
                let text = reply.to_string();
                assert!(
                    text.contains("analysis") && text.contains("strings") && text.contains("all"),
                    "the refusal must name the accepted values: {label}"
                );
            }
            Ok((history_kept, strings_kept)) => {
                assert_eq!(status, StatusCode::OK, "{label}");
                assert_eq!(after.0 > 0, history_kept, "history: {label}");
                assert_eq!(after.1 > 0, strings_kept, "strings: {label}");
            }
        }
    }
}

/// Track `value` in `path` with a hash, as `search_strings` does.
fn track(f: &Fixture, path: &str, hash: &str, value: &str, offsets: &[usize]) {
    let items: Vec<(String, usize)> = offsets.iter().map(|o| (value.to_string(), *o)).collect();
    f.state
        .string_tracker()
        .track_strings_at(|| items, path, hash, "search_strings", value);
}

#[tokio::test]
async fn rest_string_search_limit_counts_visible_results() {
    let f = fixture(true);
    let inside = write(f.data.path(), "in.txt", "x");
    let outside = TempDir::new().unwrap();
    let hidden = write(outside.path(), "out.txt", "x");
    // Hidden matches occur more often, so they sort first.
    for (i, name) in ["hid-alpha-needle", "hid-beta-needle", "hid-gamma-needle"]
        .iter()
        .enumerate()
    {
        track(&f, &hidden, "h1", name, &[1, 2, 3, 4, 5, 6][..6 - i]);
    }
    track(&f, &inside, "v1", "vis-needle", &[1]);
    for (limit, expect) in [(1, 1), (2, 1), (4, 1)] {
        let body = json!({"query": "needle", "limit": limit}).to_string();
        let (status, reply) = send(&f.app, Method::POST, "/strings/search", Some(&body)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reply["count"], expect, "limit {limit}: {reply}");
        assert_eq!(reply["results"][0]["value"], "vis-needle");
        assert!(!reply.to_string().contains("hid-"), "{reply}");
    }
    let (_, reply) = send(
        &f.app,
        Method::POST,
        "/strings/search",
        Some(r#"{"query":"needle"}"#),
    )
    .await;
    assert_eq!(reply["count"], 1, "{reply}");
}

#[tokio::test]
async fn rest_string_search_limit_still_applies_to_visible_results() {
    let f = fixture(true);
    let inside = write(f.data.path(), "in.txt", "x");
    for name in ["vis-needle-1", "vis-needle-2", "vis-needle-3"] {
        track(&f, &inside, "v1", name, &[1]);
    }
    let (_, reply) = send(
        &f.app,
        Method::POST,
        "/strings/search",
        Some(r#"{"query":"needle","limit":2}"#),
    )
    .await;
    assert_eq!(reply["count"], 2, "{reply}");
    // Without roots the limit is applied as before.
    let g = fixture(false);
    for name in ["vis-needle-1", "vis-needle-2", "vis-needle-3"] {
        track(&g, "/x/in.txt", "v1", name, &[1]);
    }
    let (_, reply) = send(
        &g.app,
        Method::POST,
        "/strings/search",
        Some(r#"{"query":"needle","limit":2}"#),
    )
    .await;
    assert_eq!(reply["count"], 2, "{reply}");
}

#[tokio::test]
async fn rest_strings_related_limit_counts_visible_results() {
    let f = fixture(true);
    let inside = write(f.data.path(), "in.txt", "x");
    let outside = TempDir::new().unwrap();
    let hidden = write(outside.path(), "out.txt", "x");
    // The asked value and one relative are visible; several relatives that
    // score at least as high live only outside the roots.
    let asked = "http://example.test/path/visible";
    track(&f, &inside, "v1", asked, &[1]);
    track(&f, &inside, "v1", "http://example.test/path/visible2", &[2]);
    for (i, name) in [
        "http://example.test/path/hidden-a",
        "http://example.test/path/hidden-b",
        "http://example.test/path/hidden-c",
    ]
    .iter()
    .enumerate()
    {
        track(&f, &hidden, "h1", name, &[i + 1]);
        track(&f, &inside, "v1", &format!("pad-{i}"), &[i + 10]);
    }
    // Make the hidden ones share the asked value's files too, so they relate.
    track(&f, &hidden, "h1", asked, &[9]);
    let mut seen = Vec::new();
    for limit in [1usize, 2, 10] {
        let body = json!({"value": asked, "limit": limit}).to_string();
        let (status, reply) = send(&f.app, Method::POST, "/strings/related", Some(&body)).await;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert!(!reply.to_string().contains("hidden"), "{reply}");
        seen.push(reply["count"].as_u64().unwrap());
    }
    // The visible relative is returned whenever the limit allows one.
    assert_eq!(
        seen[0],
        seen[2].min(1),
        "limit 1 counts visible rows: {seen:?}"
    );
}

#[tokio::test]
async fn string_details_does_not_present_a_capped_count_as_the_total() {
    let f = fixture(false);
    for (times, capped) in [(1usize, false), (10, true), (11, true), (40, true)] {
        let text = "ZZmarkerZZ-needle\n".repeat(times) + "filler line of text\n";
        let path = write(f.data.path(), &format!("many{times}.txt"), &text);
        let (error, analysis) = call(
            &f,
            "analyze_file",
            json!({"file_path": path, "strings": true, "max_output_bytes": 60000}),
        )
        .await;
        assert!(!error, "{analysis}");
        let (error, details) =
            call(&f, "string_details", json!({"value": "ZZmarkerZZ-needle"})).await;
        assert!(!error, "{details}");
        let total = details["total_occurrences"].as_u64().unwrap() as usize;
        if times < 10 {
            assert_eq!(total, times, "{details}");
        }
        if total < times {
            // A count below the truth must be marked as a lower bound.
            assert_eq!(
                details["total_occurrences_at_least"], true,
                "{times}: {details}"
            );
            assert!(
                details["note"].as_str().unwrap().contains("may be higher"),
                "{details}"
            );
            assert_eq!(
                details["files"][0]["occurrences_at_least"], true,
                "{details}"
            );
        }
        assert!(
            capped || details.get("note").is_none(),
            "{times}: {details}"
        );
        // search_strings records the real count and the note goes away.
        let (_, found) = call(
            &f,
            "search_strings",
            json!({"file_path": path, "query": "ZZmarkerZZ"}),
        )
        .await;
        assert_eq!(found["items"][0]["count"], times, "{found}");
        let (_, details) = call(&f, "string_details", json!({"value": "ZZmarkerZZ-needle"})).await;
        assert_eq!(details["total_occurrences"], times, "{details}");
        // Exactly 10 is indistinguishable from "10 or more" for the record
        // analyze_file made, and stays marked.
        assert_eq!(details.get("note").is_none(), times != 10, "{details}");
        call(&f, "cache_clear", json!({"scope": "strings"})).await;
    }
}

#[tokio::test]
async fn string_details_marks_only_the_capped_file_when_two_files_hold_the_string() {
    let f = fixture(false);
    let big = write(f.data.path(), "big.txt", &"ZZmarkerZZ-needle\n".repeat(40));
    let small = write(f.data.path(), "small.txt", "ZZmarkerZZ-needle\nother\n");
    for path in [&big, &small] {
        call(
            &f,
            "analyze_file",
            json!({"file_path": path, "strings": true}),
        )
        .await;
    }
    let (_, details) = call(&f, "string_details", json!({"value": "ZZmarkerZZ-needle"})).await;
    let files = details["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{details}");
    let capped: Vec<_> = files
        .iter()
        .filter(|row| row["occurrences_at_least"] == true)
        .collect();
    assert_eq!(capped.len(), 1, "{details}");
    assert!(capped[0]["file_path"]
        .as_str()
        .unwrap()
        .ends_with("big.txt"));
    assert_eq!(details["total_occurrences_at_least"], true);
}
