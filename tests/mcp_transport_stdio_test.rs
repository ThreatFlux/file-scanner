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

//! In-process tests of the real MCP server, driven by the SDK's own client over
//! an in-memory pipe, plus raw-wire checks of the framing rules.
//!
//! The server is `McpTransportServer::serve_transport` on one end of a
//! `tokio::io::duplex`, exactly the code `mcp-stdio` runs on stdin and stdout.

use std::{io::Write as _, path::PathBuf, sync::Arc, time::Duration};

use file_scanner::{
    mcp_server::{
        output::{DEFAULT_OUTPUT_BYTES, MAX_OUTPUT_BYTES},
        FileScannerMcp, ServerState, StateConfig,
    },
    mcp_transport::McpTransportServer,
};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ClientRequest,
        Implementation, PingRequest, ProtocolVersion,
    },
    service::{RunningService, ServiceError},
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient, ServiceExt,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

type Client = RunningService<RoleClient, TestClient>;

/// The exact inventory lives in this one list (checked by the annotations test);
/// every other test only checks that these names are present.
const TOOLS: [&str; 10] = [
    "analyze_file",
    "analyze_java_file",
    "analyze_npm_package",
    "analyze_python_package",
    "compare_files",
    "disassemble",
    "llm_analyze_file",
    "query_analysis",
    "read_hex",
    "yara_scan_file",
];

#[derive(Clone, Default)]
struct TestClient {
    version: Option<ProtocolVersion>,
}

impl ClientHandler for TestClient {
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("file-scanner-tests", "0.0.0"),
        );
        if let Some(version) = &self.version {
            info.protocol_version = version.clone();
        }
        info
    }
}

/// A server with its own cache directory, serving one end of an in-memory pipe.
struct Harness {
    state: Arc<ServerState>,
    _cache_dir: TempDir,
}

impl Harness {
    fn new() -> Self {
        let cache_dir = TempDir::new().unwrap();
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: cache_dir.path().to_path_buf(),
            ..StateConfig::default()
        }));
        Self {
            state,
            _cache_dir: cache_dir,
        }
    }

    fn serve(&self) -> DuplexStream {
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let server = McpTransportServer::with_state(Arc::clone(&self.state));
        tokio::spawn(async move {
            let _ = server.serve_transport(server_io, false).await;
        });
        client_io
    }

    async fn legacy(&self, version: ProtocolVersion) -> Client {
        TestClient {
            version: Some(version),
        }
        .serve(self.serve())
        .await
        .expect("initialize handshake")
    }

    async fn modern(&self) -> Client {
        TestClient::default()
            .serve_with_lifecycle(
                self.serve(),
                ClientLifecycleMode::Discover {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                },
            )
            .await
            .expect("discover startup")
    }
}

fn object(value: Value) -> rmcp::model::JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

async fn call(client: &Client, name: &str, arguments: Value) -> CallToolResult {
    client
        .call_tool(CallToolRequestParams::new(name.to_string()).with_arguments(object(arguments)))
        .await
        .unwrap_or_else(|error| panic!("{name} protocol error: {error}"))
}

fn text(result: &CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|text| text.text.clone())
        .expect("a text block")
}

fn json_of(result: &CallToolResult) -> Value {
    serde_json::from_str(&text(result))
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}", text(result)))
}

fn sample_file(dir: &TempDir) -> PathBuf {
    let path = dir.path().join("sample.bin");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(b"MZ\x90\x00\0http://example.com/update\0\0plain text marker here\0")
        .unwrap();
    path
}

// ---------------------------------------------------------------------------
// Handshake, identity, instructions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_with_a_2024_11_05_client() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2024_11_05).await;
    let info = client.peer_info().expect("server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
    check_identity(&client);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn handshake_with_a_2025_11_25_client() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let info = client.peer_info().expect("server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    check_identity(&client);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn handshake_with_a_2026_07_28_client() {
    let harness = Harness::new();
    let client = harness.modern().await;
    let info = client.peer_info().expect("server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
    check_identity(&client);
    // The stateless lifecycle serves tools too.
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    for name in TOOLS {
        assert!(names.iter().any(|n| n == name), "missing tool {name}");
    }
    client.cancel().await.unwrap();
}

fn check_identity(client: &Client) {
    let info = client.peer_info().expect("server info");
    let server = info.server_info.as_ref().expect("server identity");
    assert_eq!(server.name, "file-scanner");
    assert_eq!(server.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(server.title.as_deref(), Some("File Scanner"));
    let instructions = info
        .instructions
        .as_deref()
        .expect("instructions are delivered");
    assert!(
        instructions.contains("analyze_file first"),
        "{instructions}"
    );
    assert!(instructions.contains("absolute"), "{instructions}");
    assert!(info.capabilities.tools.is_some());
}

#[tokio::test]
async fn ping_is_answered() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    client
        .send_request(ClientRequest::PingRequest(PingRequest::default()))
        .await
        .expect("ping");
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// Wire framing: notifications are not answered, stdout stays JSON-RPC
// ---------------------------------------------------------------------------

async fn read_line(reader: &mut BufReader<tokio::io::ReadHalf<DuplexStream>>) -> Option<Value> {
    let mut line = String::new();
    match tokio::time::timeout(Duration::from_millis(400), reader.read_line(&mut line)).await {
        Ok(Ok(n)) if n > 0 => Some(serde_json::from_str(line.trim()).expect("a JSON-RPC line")),
        _ => None,
    }
}

#[tokio::test]
async fn notifications_get_no_reply_and_every_line_is_json_rpc() {
    let harness = Harness::new();
    let (read, mut write) = tokio::io::split(harness.serve());
    let mut reader = BufReader::new(read);
    let send = |value: Value| format!("{value}\n");

    write
        .write_all(
            send(
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"raw","version":"0"}}}),
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let init = read_line(&mut reader).await.expect("initialize reply");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");

    for notification in [
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}),
        json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"}),
    ] {
        write
            .write_all(send(notification).as_bytes())
            .await
            .unwrap();
    }
    assert!(
        read_line(&mut reader).await.is_none(),
        "a notification must not be answered"
    );

    write
        .write_all(send(json!({"jsonrpc":"2.0","id":2,"method":"ping"})).as_bytes())
        .await
        .unwrap();
    let pong = read_line(&mut reader).await.expect("ping reply");
    assert_eq!(pong["id"], 2);
    assert_eq!(pong["result"], json!({}));
}

#[tokio::test]
async fn closing_the_transport_before_a_session_is_a_clean_exit() {
    let harness = Harness::new();
    let (server_io, client_io) = tokio::io::duplex(1024);
    drop(client_io);
    let server = McpTransportServer::with_state(Arc::clone(&harness.state));
    server
        .serve_transport(server_io, false)
        .await
        .expect("EOF before any message is not an error");
}

#[tokio::test]
async fn closing_the_transport_after_a_session_is_a_clean_exit() {
    let harness = Harness::new();
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let server = McpTransportServer::with_state(Arc::clone(&harness.state));
    let serving = tokio::spawn(async move { server.serve_transport(server_io, false).await });
    let client = TestClient::default().serve(client_io).await.unwrap();
    client.cancel().await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("the server stops when the pipe closes")
        .unwrap();
    assert!(outcome.is_ok());
}

// ---------------------------------------------------------------------------
// tools/list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_has_every_tool_with_annotations_and_strict_schemas() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let tools = client.list_all_tools().await.unwrap();
    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, TOOLS);

    for tool in &tools {
        let annotations = tool.annotations.as_ref().expect("annotations");
        assert_eq!(annotations.read_only_hint, Some(true), "{}", tool.name);
        assert_eq!(annotations.destructive_hint, Some(false), "{}", tool.name);
        assert_eq!(annotations.idempotent_hint, Some(true), "{}", tool.name);
        assert_eq!(annotations.open_world_hint, Some(false), "{}", tool.name);
        assert!(tool.title.is_some(), "{}", tool.name);
        assert!(tool.description.as_deref().is_some_and(|d| !d.is_empty()));
        let schema = Value::Object((*tool.input_schema).clone());
        assert_eq!(schema["type"], "object", "{}", tool.name);
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{} must forbid unknown properties",
            tool.name
        );
        assert!(
            schema["properties"]["max_output_bytes"].is_object(),
            "{} advertises the output budget",
            tool.name
        );
    }
    let analyze = tools.iter().find(|t| t.name == "analyze_file").unwrap();
    let schema = Value::Object((*analyze.input_schema).clone());
    assert_eq!(schema["required"], json!(["file_path"]));
    assert!(schema["properties"]["enhanced_threats"].is_object());
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// One successful call per tool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn analyze_file_succeeds_and_leaves_the_shared_side_effects() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let dir = TempDir::new().unwrap();
    let path = sample_file(&dir);

    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": path, "metadata": true, "hashes": true, "strings": true}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let analysis = json_of(&result);
    assert_eq!(analysis["file_path"], path.to_string_lossy().as_ref());
    assert_eq!(
        analysis["metadata"]["file_size"],
        std::fs::metadata(&path).unwrap().len()
    );
    assert_eq!(analysis["hashes"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(analysis["cache"], "miss");
    assert!(
        analysis.get("binary_info").is_none(),
        "None fields are omitted"
    );
    // The strings section is a summary: counts and the categorized strings.
    assert!(analysis["strings"]["total_count"].as_u64().unwrap() >= 2);
    assert_eq!(analysis["strings"]["top"][0]["category"], "URL");

    // The side effects the REST routes depend on: one cache entry, strings tracked.
    let entries = harness.state.analysis_cache().get_all_entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tool_name, "analyze_file");
    assert_eq!(entries[0].file_path, path.to_string_lossy());
    assert_eq!(entries[0].tool_args["metadata"], json!(true));
    assert_eq!(entries[0].file_hash, analysis["hashes"]["sha256"]);
    assert!(harness
        .state
        .string_tracker()
        .get_string_details("http://example.com/update")
        .is_some());

    // The identical call is answered from the cache and still appends its entry.
    let again = json_of(
        &call(
            &client,
            "analyze_file",
            json!({"file_path": path, "metadata": true, "hashes": true, "strings": true}),
        )
        .await,
    );
    assert_eq!(again["cache"], "hit");
    assert_eq!(again["hashes"], analysis["hashes"]);
    assert_eq!(
        harness.state.analysis_cache().get_all_entries().await.len(),
        2
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn llm_analyze_file_succeeds_and_writes_nothing_to_the_cache() {
    let harness = Harness::new();
    let client = harness.modern().await;
    let dir = TempDir::new().unwrap();
    let path = sample_file(&dir);
    let result = call(&client, "llm_analyze_file", json!({"file_path": path})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let digest = json_of(&result);
    assert_eq!(digest["md5"].as_str().unwrap().len(), 32);
    assert!(digest["yara_rule_suggestion"]
        .as_str()
        .unwrap()
        .starts_with("rule "));
    assert!(harness
        .state
        .analysis_cache()
        .get_all_entries()
        .await
        .is_empty());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn yara_scan_file_succeeds_and_caches_the_scan() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2024_11_05).await;
    let dir = TempDir::new().unwrap();
    let path = sample_file(&dir);
    let rule = r#"rule has_hello { strings: $a = "plain text" condition: $a }"#;
    let result = call(
        &client,
        "yara_scan_file",
        json!({"path": dir.path(), "yara_rule": rule}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let scan = json_of(&result);
    assert_eq!(scan["total_matches"], 1);
    assert_eq!(
        scan["matches"][0]["file_path"],
        path.to_string_lossy().as_ref()
    );
    let entries = harness.state.analysis_cache().get_all_entries().await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tool_name, "yara_scan_file");
    assert_eq!(entries[0].file_hash, "yara_scan");
    assert_eq!(entries[0].file_size, 0);
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn analyze_java_file_succeeds() {
    use zip::{write::SimpleFileOptions, ZipWriter};
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let dir = TempDir::new().unwrap();
    let jar = dir.path().join("demo.jar");
    let mut zip = ZipWriter::new(std::fs::File::create(&jar).unwrap());
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\n\r\n")
        .unwrap();
    zip.finish().unwrap();

    let result = call(&client, "analyze_java_file", json!({"file_path": jar})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    assert!(json_of(&result).is_object());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn package_tools_succeed() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let dir = TempDir::new().unwrap();

    let npm = dir.path().join("npm-demo");
    std::fs::create_dir(&npm).unwrap();
    std::fs::write(
        npm.join("package.json"),
        r#"{"name":"demo-package","version":"1.0.0","dependencies":{"lodash":"4.17.0"}}"#,
    )
    .unwrap();
    let result = call(&client, "analyze_npm_package", json!({"package_path": npm})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    assert!(json_of(&result).is_object());

    let python = dir.path().join("py-demo");
    std::fs::create_dir(&python).unwrap();
    std::fs::write(
        python.join("setup.py"),
        "from setuptools import setup\nsetup(name='demo', version='1.0')\n",
    )
    .unwrap();
    let result = call(
        &client,
        "analyze_python_package",
        json!({"package_path": python}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    assert!(json_of(&result).is_object());
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// Failures are tool errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failures_are_tool_errors_with_useful_text() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let dir = TempDir::new().unwrap();
    let path = sample_file(&dir);

    // Missing file.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": "/nonexistent/x.bin"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(text(&result), "File does not exist: /nonexistent/x.bin");

    // A directory is a triage table; where a file is needed it says what to do.
    let result = call(&client, "analyze_file", json!({"file_path": dir.path()})).await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    assert_eq!(json_of(&result)["view"], "directory");
    let result = call(
        &client,
        "query_analysis",
        json!({"file_path": dir.path(), "section": "strings"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text(&result).contains("is a directory"),
        "{}",
        text(&result)
    );

    // Wrong argument type.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": path, "hashes": "yes"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let message = text(&result);
    assert!(message.contains("invalid type"), "{message}");
    assert!(message.contains("boolean"), "{message}");

    // Missing required argument.
    let result = call(&client, "analyze_file", json!({})).await;
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("file_path"), "{}", text(&result));

    // Unknown argument is rejected, and the message names it.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": path, "hash": true}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text(&result).contains("unknown field `hash`"),
        "{}",
        text(&result)
    );

    // A bad output budget.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": path, "max_output_bytes": "lots"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text(&result).contains("max_output_bytes"),
        "{}",
        text(&result)
    );

    // A YARA rule that does not compile: the compiler's message is in the text.
    let result = call(
        &client,
        "yara_scan_file",
        json!({"path": path, "yara_rule": "rule broken { condition: nosuchidentifier }"}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    let message = text(&result);
    assert!(message.contains("Failed to compile YARA rule"), "{message}");
    assert!(message.contains("nosuchidentifier"), "{message}");

    // An unsupported package file.
    let result = call(
        &client,
        "analyze_python_package",
        json!({"package_path": path}),
    )
    .await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        text(&result).contains("Unsupported file type"),
        "{}",
        text(&result)
    );

    // Failed calls leave nothing behind.
    assert!(harness
        .state
        .analysis_cache()
        .get_all_entries()
        .await
        .is_empty());
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let error = client
        .call_tool(CallToolRequestParams::new("no_such_tool"))
        .await
        .expect_err("unknown tools are protocol errors");
    match error {
        ServiceError::McpError(data) => {
            assert_eq!(data.code.0, -32602);
            assert!(data.message.contains("not found"), "{}", data.message);
        }
        other => panic!("unexpected error {other:?}"),
    }
    // The connection is still usable.
    let names: Vec<String> = client
        .list_all_tools()
        .await
        .unwrap()
        .iter()
        .map(|t| t.name.to_string())
        .collect();
    for name in TOOLS {
        assert!(names.iter().any(|n| n == name), "missing tool {name}");
    }
    client.cancel().await.unwrap();
}

// ---------------------------------------------------------------------------
// Robustness: panics, size ceiling, paths
// ---------------------------------------------------------------------------

/// PF06: a panic inside an analyzer used to end the whole process. Whatever the
/// analyzer does with this binary, the server must answer and stay up.
#[tokio::test]
async fn a_crashing_analysis_does_not_kill_the_server() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_programs/go_test_binary");
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": binary, "all": true}),
    )
    .await;
    // This sample used to overflow in the code-quality arithmetic; it must now
    // complete. The panic path itself is covered by the test_panic tool.
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let code_quality = call(
        &client,
        "analyze_file",
        json!({"file_path": binary, "code_quality": true}),
    )
    .await;
    assert_ne!(code_quality.is_error, Some(true), "{}", text(&code_quality));
    let still_alive = call(&client, "analyze_file", json!({"file_path": binary})).await;
    assert_ne!(still_alive.is_error, Some(true), "{}", text(&still_alive));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn no_result_exceeds_the_byte_ceiling() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_programs/c_advanced_binary");

    // `all` on a real binary is summaries: it fits the default budget whole.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": binary, "all": true}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    let body = text(&result);
    assert!(body.len() <= DEFAULT_OUTPUT_BYTES, "{} bytes", body.len());
    let analysis: Value = serde_json::from_str(&body).unwrap();
    assert!(analysis.get("truncated").is_none(), "summaries fit whole");
    assert!(analysis.get("hashes").is_some(), "small sections survive");

    // Asking for more is honored up to the ceiling and no further.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": binary, "all": true, "max_output_bytes": 100_000_000u64}),
    )
    .await;
    let body = text(&result);
    assert!(body.len() <= MAX_OUTPUT_BYTES, "{} bytes", body.len());

    // And a small budget is honored too.
    let result = call(
        &client,
        "analyze_file",
        json!({"file_path": binary, "all": true, "max_output_bytes": 6000}),
    )
    .await;
    assert!(text(&result).len() <= 6000, "{} bytes", text(&result).len());
    assert!(
        result.structured_content.is_none(),
        "the payload is sent once"
    );
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn tilde_paths_are_expanded() {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("fs-mcp-tilde-")
        .tempdir_in(&home);
    let Ok(dir) = dir else {
        return; // home is not writable here
    };
    std::fs::write(dir.path().join("f.txt"), b"hello").unwrap();
    let name = dir
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let result = call(
        &client,
        "llm_analyze_file",
        json!({"file_path": format!("~/{name}/f.txt")}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", text(&result));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn allow_roots_confine_every_tool() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let outside_file = sample_file(&outside);
    let inside_file = sample_file(&root);

    let cache_dir = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        allow_roots: vec![root.path().to_path_buf()],
        ..StateConfig::default()
    }));
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let server = McpTransportServer::with_state(state);
    tokio::spawn(async move {
        let _ = server.serve_transport(server_io, false).await;
    });
    let client = TestClient::default().serve(client_io).await.unwrap();

    let ok = call(
        &client,
        "llm_analyze_file",
        json!({"file_path": inside_file}),
    )
    .await;
    assert_ne!(ok.is_error, Some(true), "{}", text(&ok));
    for (tool, args) in [
        ("analyze_file", json!({"file_path": outside_file})),
        ("llm_analyze_file", json!({"file_path": outside_file})),
        ("analyze_java_file", json!({"file_path": outside_file})),
        (
            "analyze_npm_package",
            json!({"package_path": outside.path()}),
        ),
        (
            "analyze_python_package",
            json!({"package_path": outside.path()}),
        ),
        (
            "yara_scan_file",
            json!({"path": outside.path(), "yara_rule": "rule a { condition: true }"}),
        ),
    ] {
        let result = call(&client, tool, args).await;
        assert_eq!(result.is_error, Some(true), "{tool}");
        assert!(
            text(&result).contains("outside the directories"),
            "{tool}: {}",
            text(&result)
        );
    }
    client.cancel().await.unwrap();
}

/// A directory argument is vetted too: a symlink inside an allowed root that
/// points outside it must not let a tool read the target, and a FIFO must be
/// refused rather than hang the call.
#[cfg(unix)]
#[tokio::test]
async fn allow_roots_also_cover_what_a_directory_contains() {
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
    std::fs::write(
        outside.path().join("package.json"),
        br#"{"name":"outside-secret-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        outside.path().join("setup.py"),
        b"from setuptools import setup\nsetup(name='outside-secret-py', version='6.6.6')\n",
    )
    .unwrap();
    let symlink = std::os::unix::fs::symlink;

    let flat = root.path().join("flat");
    std::fs::create_dir(&flat).unwrap();
    symlink(outside.path().join("secret.txt"), flat.join("link.txt")).unwrap();
    let npm = root.path().join("npm_link");
    std::fs::create_dir(&npm).unwrap();
    symlink(
        outside.path().join("package.json"),
        npm.join("package.json"),
    )
    .unwrap();
    let python = root.path().join("py_link");
    std::fs::create_dir(&python).unwrap();
    symlink(outside.path().join("setup.py"), python.join("setup.py")).unwrap();

    let cache_dir = TempDir::new().unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        allow_roots: vec![root.path().to_path_buf()],
        ..StateConfig::default()
    }));
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let server = McpTransportServer::with_state(state);
    tokio::spawn(async move {
        let _ = server.serve_transport(server_io, false).await;
    });
    let client = TestClient::default().serve(client_io).await.unwrap();

    let rule = r#"rule s { strings: $a = "secret" condition: $a }"#;
    for (tool, args) in [
        (
            "yara_scan_file",
            json!({"path": flat, "recursive": false, "yara_rule": rule}),
        ),
        (
            "yara_scan_file",
            json!({"path": flat, "recursive": true, "yara_rule": rule}),
        ),
        ("analyze_npm_package", json!({"package_path": npm})),
        ("analyze_python_package", json!({"package_path": python})),
    ] {
        let result = call(&client, tool, args).await;
        let body = text(&result);
        assert_eq!(result.is_error, Some(true), "{tool}: {body}");
        assert!(body.contains("symlink"), "{tool}: {body}");
        assert!(
            !body.contains("outside-secret") && !body.contains("6.6.6"),
            "{tool} leaked: {body}"
        );
    }

    // A FIFO named like a package file must be refused, not waited on.
    let fifo_dir = root.path().join("npm_fifo");
    std::fs::create_dir(&fifo_dir).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(fifo_dir.join("package.json"))
        .status()
        .unwrap();
    assert!(status.success());
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        call(
            &client,
            "analyze_npm_package",
            json!({"package_path": fifo_dir}),
        ),
    )
    .await
    .expect("a FIFO in a package directory must not hang the call");
    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("named pipe"), "{}", text(&result));
    client.cancel().await.unwrap();
}

#[tokio::test]
async fn tool_calls_run_concurrently_with_a_shared_handler() {
    let harness = Harness::new();
    let client = harness.legacy(ProtocolVersion::V_2025_11_25).await;
    let dir = TempDir::new().unwrap();
    let path = sample_file(&dir);
    let (a, b, c) = tokio::join!(
        call(&client, "llm_analyze_file", json!({"file_path": path})),
        call(
            &client,
            "analyze_file",
            json!({"file_path": path, "hashes": true})
        ),
        client.list_all_tools(),
    );
    assert_ne!(a.is_error, Some(true));
    assert_ne!(b.is_error, Some(true));
    let names: Vec<String> = c.unwrap().iter().map(|t| t.name.to_string()).collect();
    for name in TOOLS {
        assert!(names.iter().any(|n| n == name), "missing tool {name}");
    }
    let _ = FileScannerMcp::new(); // the plain constructor still needs no runtime state
    client.cancel().await.unwrap();
}

/// A client that opens with `notifications/initialized` instead of `initialize`
/// gets one readable stderr line, not a Rust debug dump.
#[test]
fn initialized_before_initialize_gives_a_readable_error() {
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_file-scanner"))
        .arg("mcp-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must send an `initialize` request first"),
        "{stderr}"
    );
    assert!(!stderr.contains("JsonRpcNotification"), "{stderr}");
    assert!(output.stdout.is_empty());
}
