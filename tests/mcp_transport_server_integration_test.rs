#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::field_reassign_with_default,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::ignore_without_reason,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::ref_option,
    clippy::redundant_clone,
    clippy::redundant_pattern_matching,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_debug_formatting,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm,
    clippy::ignored_unit_patterns
)]

//! HTTP transport tests: the SDK's Streamable HTTP service at `/mcp` next to the
//! REST helper routes, over real loopback sockets on ephemeral ports.

use std::{sync::Arc, time::Duration};

use file_scanner::{
    mcp_server::{FileScannerMcp, ServerState, StateConfig},
    mcp_transport::{
        http::{BoundServer, HttpConfig},
        McpTransportServer,
    },
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

struct TestServer {
    base: String,
    shutdown: CancellationToken,
    state: Arc<ServerState>,
    _cache_dir: TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start() -> TestServer {
    start_with_roots(Vec::new()).await
}

async fn start_with_roots(allow_roots: Vec<std::path::PathBuf>) -> TestServer {
    let cache_dir = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        allow_roots,
        ..StateConfig::default()
    }));
    state.warm_up();
    let shutdown = CancellationToken::new();
    let server = BoundServer::bind(
        FileScannerMcp::with_state(Arc::clone(&state)),
        &HttpConfig::on_port(0),
        shutdown.clone(),
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    TestServer {
        base: format!("http://{address}"),
        shutdown,
        state,
        _cache_dir: cache_dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap()
}

/// The JSON-RPC message with `id` inside an SSE or JSON response body.
fn message_with_id(body: &str, id: u64) -> Value {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if value["id"] == id {
            return value;
        }
    }
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
        .find(|value| value["id"] == id)
        .unwrap_or_else(|| panic!("no message with id {id} in: {body}"))
}

const ACCEPT: &str = "application/json, text/event-stream";

#[tokio::test]
async fn run_http_and_the_sse_alias_start_and_keep_running() {
    let cache_dir = TempDir::new().unwrap();
    for alias in [false, true] {
        let transport = McpTransportServer::with_config(StateConfig {
            cache_dir: cache_dir.path().to_path_buf(),
            ..StateConfig::default()
        });
        let handle = tokio::spawn(async move {
            let _ = if alias {
                transport.run_sse(HttpConfig::on_port(0)).await
            } else {
                transport.run_http(HttpConfig::on_port(0)).await
            };
        });
        sleep(Duration::from_millis(200)).await;
        assert!(!handle.is_finished(), "alias={alias}");
        handle.abort();
    }
}

#[tokio::test]
async fn health_and_info_report_the_package_version() {
    let server = start().await;
    let health: Value = client()
        .get(format!("{}/health", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));

    let info: Value = client()
        .get(format!("{}/api/info", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["endpoints"]["/mcp"].is_string());
}

#[tokio::test]
async fn mcp_endpoint_serves_a_session_and_shares_state_with_the_rest_routes() {
    let server = start().await;
    let http = client();
    let url = format!("{}/mcp", server.base);

    let initialize = http
        .post(&url)
        .header("accept", ACCEPT)
        .json(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"http-test","version":"0"}}}),
        )
        .send()
        .await
        .unwrap();
    assert!(initialize.status().is_success(), "{}", initialize.status());
    let session = initialize
        .headers()
        .get("mcp-session-id")
        .expect("a session id")
        .to_str()
        .unwrap()
        .to_string();
    let body = initialize.text().await.unwrap();
    let reply = message_with_id(&body, 1);
    assert_eq!(reply["result"]["serverInfo"]["name"], "file-scanner");
    assert!(reply["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("analyze_file"));

    let accepted = http
        .post(&url)
        .header("accept", ACCEPT)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 202);

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("sample.bin");
    std::fs::write(&file, b"MZ\0http://tracked.example/path\0more text here\0").unwrap();
    let call = http
        .post(&url)
        .header("accept", ACCEPT)
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .json(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"analyze_file","arguments":{"file_path":file,"hashes":true,"strings":true}}}),
        )
        .send()
        .await
        .unwrap();
    assert!(call.status().is_success());
    let reply = message_with_id(&call.text().await.unwrap(), 2);
    assert_ne!(reply["result"]["isError"], json!(true), "{reply}");

    // The call made over /mcp is visible through the REST routes: same cache, same tracker.
    let stats: Value = http
        .get(format!("{}/cache/stats", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["total_entries"], 1);
    let strings: Value = http
        .post(format!("{}/strings/details", server.base))
        .json(&json!({"value": "http://tracked.example/path"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(strings.get("error").is_none(), "{strings}");
    assert!(server
        .state
        .string_tracker()
        .get_string_details("http://tracked.example/path")
        .is_some());
}

#[tokio::test]
async fn rest_tool_routes_use_the_tool_router() {
    let server = start().await;
    let http = client();

    let list: Value = http
        .post(format!("{}/tools/list", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["jsonrpc"], "2.0");
    let tools = list["result"]["tools"].as_array().unwrap();
    for name in [
        "analyze_file",
        "analyze_java_file",
        "analyze_npm_package",
        "analyze_python_package",
        "llm_analyze_file",
        "yara_scan_file",
    ] {
        assert!(tools.iter().any(|t| t["name"] == name), "missing {name}");
    }
    assert!(tools
        .iter()
        .all(|t| t["inputSchema"]["additionalProperties"] == json!(false)));

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("a.bin");
    std::fs::write(&file, b"abcdefgh ijklmnop").unwrap();
    let response = http
        .post(format!("{}/tools/call", server.base))
        .json(&json!({"name":"analyze_file","arguments":{"file_path":file,"hashes":true}}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let result: Value = response.json().await.unwrap();
    assert_ne!(result["isError"], json!(true), "{result}");
    assert_eq!(
        server.state.analysis_cache().get_all_entries().await.len(),
        1
    );

    let failed: Value = http
        .post(format!("{}/tools/call", server.base))
        .json(&json!({"name":"analyze_file","arguments":{"file_path":"/nonexistent"}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(failed["isError"], json!(true));

    let unknown = http
        .post(format!("{}/tools/call", server.base))
        .json(&json!({"name":"nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);
}

#[tokio::test]
async fn cache_string_and_documentation_routes_answer() {
    let server = start().await;
    let http = client();
    for path in [
        "/cache/list",
        "/cache/stats",
        "/strings/stats",
        "/api-docs/openapi.json",
        "/api/info",
        "/health",
    ] {
        let response = http
            .get(format!("{}{path}", server.base))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "{path}");
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin"),
            "{path}: no CORS header without an Origin, and never a wildcard"
        );
    }
    for (path, body) in [
        ("/cache/search", json!({})),
        ("/cache/clear", json!({})),
        ("/strings/search", json!({"query": "x"})),
        ("/strings/related", json!({"value": "x"})),
        ("/strings/filter", json!({})),
        ("/initialize", json!({})),
    ] {
        let response = http
            .post(format!("{}{path}", server.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
    }
    let openapi: Value = http
        .get(format!("{}/api-docs/openapi.json", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(openapi["openapi"].is_string());
    assert_eq!(openapi["info"]["title"], "File Scanner MCP API");
    assert!(openapi["components"].is_object());
}

#[tokio::test]
async fn rest_cache_clear_forgets_the_tracked_strings_like_the_tool_and_takes_a_scope() {
    let server = start().await;
    let http = client();
    let track = || {
        server
            .state
            .string_tracker()
            .track_strings_from_results(
                &["a tracked string".to_string()],
                "/tmp/x",
                "hash",
                "analyze_file",
            )
            .unwrap();
    };
    let unique = || {
        server
            .state
            .string_tracker()
            .get_statistics(None)
            .total_unique_strings
    };
    track();
    assert_eq!(unique(), 1);
    // Only the analysis side: the strings stay.
    let reply: Value = http
        .post(format!("{}/cache/clear?scope=analysis", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reply["status"], "success", "{reply}");
    assert_eq!(unique(), 1);
    // The default is the tool's default: both.
    let reply: Value = http
        .post(format!("{}/cache/clear", server.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        reply["cleared"].to_string().contains("tracked strings"),
        "{reply}"
    );
    assert_eq!(unique(), 0);
    track();
    let bad = http
        .post(format!("{}/cache/clear?scope=nope", server.base))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);
    assert_eq!(unique(), 1, "a refused scope clears nothing");
}

#[tokio::test]
async fn invalid_requests_to_mcp_are_rejected_not_served() {
    let server = start().await;
    let http = client();
    let url = format!("{}/mcp", server.base);
    let bad = http
        .post(&url)
        .header("accept", ACCEPT)
        .header("content-type", "application/json")
        .body("invalid json")
        .send()
        .await
        .unwrap();
    assert!(bad.status().is_client_error(), "{}", bad.status());
    // Without the Accept pair the SDK refuses (406); the server stays up.
    let missing_accept = http
        .post(&url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert!(missing_accept.status().is_client_error());
    assert!(http
        .get(format!("{}/health", server.base))
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}

#[tokio::test]
async fn shutdown_ends_an_open_event_stream_and_the_server_returns() {
    let cache_dir = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        ..StateConfig::default()
    }));
    let shutdown = CancellationToken::new();
    let config = HttpConfig {
        shutdown_grace: Duration::from_secs(30),
        ..HttpConfig::on_port(0)
    };
    let server = BoundServer::bind(FileScannerMcp::with_state(state), &config, shutdown.clone())
        .await
        .unwrap();
    let base = format!("http://{}", server.local_addr().unwrap());
    let serving = tokio::spawn(server.serve());

    let http = client();
    let initialize = http
        .post(format!("{base}/mcp"))
        .header("accept", ACCEPT)
        .json(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"shutdown-test","version":"0"}}}),
        )
        .send()
        .await
        .unwrap();
    let session = initialize
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    // A GET stream that stays open until the server ends it.
    let mut stream = http
        .get(format!("{base}/mcp"))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", &session)
        .header("mcp-protocol-version", "2025-11-25")
        .send()
        .await
        .unwrap();
    assert!(stream.status().is_success());
    let _ = stream.chunk().await;

    let started = std::time::Instant::now();
    shutdown.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(25), serving)
        .await
        .expect("the server returns although a stream was open")
        .unwrap();
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "stopped by ending the stream, not by waiting out the grace period"
    );
    // The listener is closed.
    assert!(http.get(format!("{base}/health")).send().await.is_err());
}

#[tokio::test]
async fn binding_a_taken_port_names_the_fix() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let cache_dir = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        ..StateConfig::default()
    }));
    let error = match BoundServer::bind(
        FileScannerMcp::with_state(state),
        &HttpConfig::on_port(port),
        CancellationToken::new(),
    )
    .await
    {
        Ok(_) => panic!("the port is taken"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("--port"), "{error:#}");
}

#[tokio::test]
async fn a_rooted_server_shows_no_cache_entry_or_string_of_a_file_outside_its_roots() {
    use file_scanner::cache::CacheEntry;
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let server = start_with_roots(vec![root.path().to_path_buf()]).await;
    let inside_path = root.path().join("in.bin").to_string_lossy().into_owned();
    let outside_path = outside
        .path()
        .join("out.bin")
        .to_string_lossy()
        .into_owned();
    let tracker = server.state.string_tracker();
    for (path, hash, value) in [
        (&inside_path, "aa", "INSIDE_ONLY_MARKER"),
        (&outside_path, "bb", "OUTSIDE_ONLY_MARKER"),
    ] {
        tracker
            .track_strings_from_results(
                &[value.to_string(), "SHARED_MARKER".into()],
                path,
                hash,
                "analyze_file",
            )
            .unwrap();
        server
            .state
            .analysis_cache()
            .add_entry(CacheEntry {
                file_path: path.clone(),
                file_hash: hash.into(),
                tool_name: "analyze_file".into(),
                tool_args: Default::default(),
                result: json!({"marker": value}),
                timestamp: chrono::Utc::now(),
                file_size: 10,
                execution_time_ms: 1,
            })
            .await
            .unwrap();
    }
    let http = client();
    let mut answers = Vec::new();
    let get = |path: &str| http.get(format!("{}{path}", server.base)).send();
    answers.push(get("/cache/list").await.unwrap().text().await.unwrap());
    answers.push(get("/strings/stats").await.unwrap().text().await.unwrap());
    answers.push(get("/cache/stats").await.unwrap().text().await.unwrap());
    for (path, body) in [
        ("/cache/search", json!({"file_path_pattern": "bin"})),
        ("/strings/search", json!({"query": "MARKER"})),
        ("/strings/filter", json!({})),
        ("/strings/related", json!({"value": "INSIDE_ONLY_MARKER"})),
        ("/strings/details", json!({"value": "SHARED_MARKER"})),
        (
            "/tools/call",
            json!({"name": "cache_status", "arguments": {"action": "list"}}),
        ),
        (
            "/tools/call",
            json!({"name": "search_strings", "arguments": {"query": "MARKER"}}),
        ),
        (
            "/tools/call",
            json!({"name": "string_details", "arguments": {"value": "SHARED_MARKER"}}),
        ),
    ] {
        let response = http
            .post(format!("{}{path}", server.base))
            .json(&body)
            .send()
            .await
            .unwrap();
        answers.push(response.text().await.unwrap());
    }
    for answer in &answers {
        assert!(!answer.contains("OUTSIDE_ONLY_MARKER"), "{answer}");
        assert!(!answer.contains(&outside_path), "{answer}");
        assert!(!answer.contains("\"bb\""), "{answer}");
    }
    assert!(answers[0].contains(&inside_path), "{}", answers[0]);
    assert!(answers[3].contains(&inside_path), "{}", answers[3]);
    assert!(answers[4].contains("INSIDE_ONLY_MARKER") && answers[4].contains("SHARED_MARKER"));
    // A string that lives only outside the roots is not found.
    let response = http
        .post(format!("{}/strings/details", server.base))
        .json(&json!({"value": "OUTSIDE_ONLY_MARKER"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "String not found");
}

#[tokio::test]
async fn rest_cache_routes_print_the_canonical_path_and_match_on_it() {
    use file_scanner::cache::CacheEntry;
    let work = TempDir::new().unwrap();
    let base = std::fs::canonicalize(work.path()).unwrap();
    let inside = base.join("in");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(base.join("outside_zone")).unwrap();
    std::fs::write(inside.join("a.bin"), b"data").unwrap();
    let server = start_with_roots(vec![inside.clone()]).await;
    let canonical = inside.join("a.bin").to_string_lossy().into_owned();
    let stored = format!("{}/outside_zone/../in/a.bin", base.display());
    server
        .state
        .analysis_cache()
        .add_entry(CacheEntry {
            file_path: stored.clone(),
            file_hash: "aa".into(),
            tool_name: "analyze_file".into(),
            tool_args: [("file_path".to_string(), json!(stored))].into(),
            result: json!({"path": stored}),
            timestamp: chrono::Utc::now(),
            file_size: 4,
            execution_time_ms: 1,
        })
        .await
        .unwrap();
    let http = client();
    let list = http
        .get(format!("{}/cache/list", server.base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let mut answers = vec![list];
    for body in [json!({}), json!({"file_path_pattern": "outside"})] {
        answers.push(
            http.post(format!("{}/cache/search", server.base))
                .json(&body)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
        );
    }
    for answer in &answers {
        assert!(!answer.contains("outside_zone"), "{answer}");
    }
    let listed: Value = serde_json::from_str(&answers[0]).unwrap();
    assert_eq!(listed["entries"][0]["file_path"], canonical.as_str());
    assert_eq!(
        listed["entries"][0]["tool_args"]["file_path"],
        canonical.as_str()
    );
    let all: Value = serde_json::from_str(&answers[1]).unwrap();
    assert_eq!(all["results"][0]["file_path"], canonical.as_str());
    let none: Value = serde_json::from_str(&answers[2]).unwrap();
    assert_eq!(none["count"], 0, "{none}");
}

#[tokio::test]
async fn strings_related_is_filtered_by_root() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let inside_path = root.path().join("in.bin").to_string_lossy().into_owned();
    let outside_path = outside
        .path()
        .join("out.bin")
        .to_string_lossy()
        .into_owned();
    let mut answers = Vec::new();
    for roots in [Vec::new(), vec![root.path().to_path_buf()]] {
        let server = start_with_roots(roots).await;
        let tracker = server.state.string_tracker();
        for (path, hash, values) in [
            (&inside_path, "aa", ["VALUE_A", "VALUE_B"]),
            (&outside_path, "bb", ["VALUE_A", "VALUE_C"]),
        ] {
            tracker
                .track_strings_from_results(&values.map(String::from), path, hash, "analyze_file")
                .unwrap();
        }
        let text = client()
            .post(format!("{}/strings/related", server.base))
            .json(&json!({"value": "VALUE_A"}))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        answers.push(text);
    }
    assert!(
        answers[0].contains("VALUE_B") && answers[0].contains("VALUE_C"),
        "{}",
        answers[0]
    );
    assert!(answers[1].contains("VALUE_B"), "{}", answers[1]);
    assert!(!answers[1].contains("VALUE_C"), "{}", answers[1]);
}

#[tokio::test]
async fn an_unknown_string_is_a_404_with_the_error_body() {
    let server = start().await;
    let response = client()
        .post(format!("{}/strings/details", server.base))
        .json(&json!({"value": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert_eq!(
        response.json::<Value>().await.unwrap(),
        json!({"error": "String not found"})
    );
}
