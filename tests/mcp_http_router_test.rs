//! The HTTP application driven in-process: the axum `Router` with `oneshot`, no
//! socket. Covers the protocol on `/mcp` for both eras, the Host/Origin/token
//! guard on every route, CORS, the REST helper routes and the file-system scope.

use std::{path::PathBuf, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use file_scanner::mcp_server::{FileScannerMcp, ServerState, StateConfig};
use file_scanner::mcp_transport::{
    http::{build_app, HttpConfig},
    rest::ROUTES,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:3000";
const TOKEN: &str = "test-token-0123456789";

struct Fixture {
    app: Router,
    sample: PathBuf,
    _dirs: Vec<TempDir>,
}

fn fixture_with(config: HttpConfig, allow_roots: Option<Vec<PathBuf>>) -> Fixture {
    let cache_dir = TempDir::new().unwrap();
    let data_dir = TempDir::new().unwrap();
    let sample = data_dir.path().join("sample.txt");
    std::fs::write(
        &sample,
        "plain text sample with a recognisable string: scanner-fixture-marker\n".repeat(20),
    )
    .unwrap();
    let state = Arc::new(ServerState::new(StateConfig {
        cache_dir: cache_dir.path().to_path_buf(),
        allow_roots: allow_roots.unwrap_or_default(),
        ..StateConfig::default()
    }));
    let app = build_app(
        FileScannerMcp::with_state(state),
        &config,
        CancellationToken::new(),
    )
    .unwrap();
    Fixture {
        app,
        sample,
        _dirs: vec![cache_dir, data_dir],
    }
}

fn fixture() -> Fixture {
    fixture_with(HttpConfig::default(), None)
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    /// The JSON-RPC message in a JSON or SSE body (the last non-empty `data:` line).
    fn rpc(&self) -> Value {
        let is_sse = self
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        if is_sse {
            let data = self
                .body
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim)
                .rfind(|data| !data.is_empty())
                .unwrap_or_else(|| panic!("no data line in {:?}", self.body));
            serde_json::from_str(data).unwrap()
        } else {
            serde_json::from_str(&self.body)
                .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
        }
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {:?}", self.body))
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, 8 * 1024 * 1024).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn request(
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        builder = builder.header(header::HOST, HOST);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

const MCP_ACCEPT: (&str, &str) = ("accept", "application/json, text/event-stream");

fn post_mcp(body: &Value, extra: &[(&str, &str)]) -> Request<Body> {
    let mut headers = vec![MCP_ACCEPT];
    headers.extend_from_slice(extra);
    request(Method::POST, "/mcp", &headers, Some(body))
}

fn initialize_body(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "router-test", "version": "0.0.0" }
        }
    })
}

/// Initialize as an older client and acknowledge; returns the session id.
async fn open_session(app: &Router, extra: &[(&str, &str)]) -> String {
    let reply = send(app, post_mcp(&initialize_body("2025-06-18"), extra)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let message = reply.rpc();
    assert_eq!(message["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(message["result"]["serverInfo"]["name"], "file-scanner");
    assert_eq!(
        message["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert!(message["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("analyze_file"));
    let session = reply.header("mcp-session-id").to_string();
    assert!(!session.is_empty(), "session mode returns Mcp-Session-Id");

    let mut headers = vec![("mcp-session-id", session.as_str())];
    headers.extend_from_slice(extra);
    let initialized = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let ack = send(app, post_mcp(&initialized, &headers)).await;
    assert_eq!(ack.status, StatusCode::ACCEPTED, "{}", ack.body);
    assert!(ack.body.is_empty());
    session
}

/// Call a tool inside a session; returns (isError, text).
async fn session_tool_call(
    app: &Router,
    session: &str,
    extra: &[(&str, &str)],
    name: &str,
    arguments: &Value,
) -> (bool, String) {
    let mut headers = vec![("mcp-session-id", session)];
    headers.extend_from_slice(extra);
    let body = json!({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    });
    let reply = send(app, post_mcp(&body, &headers)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let message = reply.rpc();
    let result = &message["result"];
    (
        result["isError"] == true,
        result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// The protocol on /mcp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_older_client_initializes_lists_and_calls_a_tool() {
    let fx = fixture();
    let session = open_session(&fx.app, &[]).await;

    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = send(&fx.app, post_mcp(&list, &[("mcp-session-id", &session)])).await;
    assert_eq!(reply.status, StatusCode::OK);
    let tools = reply.rpc()["result"]["tools"].as_array().unwrap().clone();
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

    let (is_error, text) = session_tool_call(
        &fx.app,
        &session,
        &[],
        "analyze_file",
        &json!({"file_path": fx.sample.to_string_lossy(), "hashes": true}),
    )
    .await;
    assert!(!is_error, "{text}");
    let result: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        result["file_path"].as_str().unwrap(),
        fx.sample.to_string_lossy()
    );
    assert!(result["hashes"]["sha256"].is_string(), "{text}");

    // Without a session id a non-initialize request is refused.
    let reply = send(&fx.app, post_mcp(&list, &[])).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_2026_07_28_request_is_served_statelessly() {
    let fx = fixture();
    let body = json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": { "file_path": fx.sample.to_string_lossy(), "hashes": true },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": { "name": "router-test", "version": "0.0.0" },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let reply = send(
        &fx.app,
        post_mcp(
            &body,
            &[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "analyze_file"),
            ],
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.headers.get("mcp-session-id").is_none(),
        "no session in revision 2026-07-28"
    );
    let message = reply.rpc();
    assert_eq!(message["result"]["resultType"], "complete", "{message}");
    assert_ne!(message["result"]["isError"], true, "{message}");
    let text = message["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("sha256"), "{text}");
}

#[tokio::test]
async fn a_notification_is_answered_202_with_no_body() {
    let fx = fixture();
    let session = open_session(&fx.app, &[]).await;
    let cancelled = json!({
        "jsonrpc": "2.0", "method": "notifications/cancelled",
        "params": { "requestId": 99 }
    });
    let reply = send(
        &fx.app,
        post_mcp(&cancelled, &[("mcp-session-id", &session)]),
    )
    .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    assert!(reply.body.is_empty());
}

#[tokio::test]
async fn an_unknown_protocol_version_header_is_refused() {
    let fx = fixture();
    let session = open_session(&fx.app, &[]).await;
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = send(
        &fx.app,
        post_mcp(
            &list,
            &[
                ("mcp-session-id", &session),
                ("mcp-protocol-version", "1999-01-01"),
            ],
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
}

// ---------------------------------------------------------------------------
// Host, Origin
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_foreign_host_is_403_on_every_route() {
    let fx = fixture();
    for (method, uri, body) in [
        (Method::POST, "/mcp", Some(initialize_body("2025-06-18"))),
        (Method::GET, "/health", None),
        (Method::GET, "/cache/list", None),
        (Method::POST, "/tools/list", Some(json!({}))),
    ] {
        let req = request(
            method,
            uri,
            &[("host", "evil.example:3000"), MCP_ACCEPT],
            body.as_ref(),
        );
        let reply = send(&fx.app, req).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{uri}: {}", reply.body);
        assert!(reply.body.contains("--allowed-host"), "{}", reply.body);
    }
}

#[tokio::test]
async fn a_listed_host_is_served() {
    let fx = fixture_with(
        HttpConfig {
            allowed_hosts: vec!["scanner.internal".into()],
            ..HttpConfig::default()
        },
        None,
    );
    let reply = send(
        &fx.app,
        request(
            Method::GET,
            "/health",
            &[("host", "scanner.internal:3000")],
            None,
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let reply = send(
        &fx.app,
        request(Method::GET, "/health", &[("host", "other.internal")], None),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_foreign_origin_is_403_on_mcp_and_on_rest_routes() {
    let fx = fixture();
    for origin in [
        "https://evil.example",
        "null",
        "http://localhost.evil.example",
    ] {
        let mcp = send(
            &fx.app,
            post_mcp(&initialize_body("2025-06-18"), &[("origin", origin)]),
        )
        .await;
        assert_eq!(mcp.status, StatusCode::FORBIDDEN, "{origin}: {}", mcp.body);
        for (method, uri) in [
            (Method::GET, "/cache/list"),
            (Method::POST, "/cache/clear"),
            (Method::GET, "/health"),
        ] {
            let reply = send(&fx.app, request(method, uri, &[("origin", origin)], None)).await;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin} {uri}");
            assert!(
                reply.headers.get("access-control-allow-origin").is_none(),
                "no wildcard and no echo for a foreign origin"
            );
        }
    }
}

#[tokio::test]
async fn a_loopback_origin_on_any_port_is_served() {
    let fx = fixture();
    let reply = send(
        &fx.app,
        request(
            Method::GET,
            "/health",
            &[("origin", "http://localhost:6274")],
            None,
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.header("access-control-allow-origin"),
        "http://localhost:6274"
    );
}

#[tokio::test]
async fn a_preflight_from_an_allowed_origin_succeeds_with_the_right_headers() {
    let fx = fixture_with(
        HttpConfig {
            allowed_origins: vec!["https://inspector.example".into()],
            ..HttpConfig::default()
        },
        None,
    );
    for origin in ["https://inspector.example", "http://127.0.0.1:6274"] {
        let reply = send(
            &fx.app,
            request(
                Method::OPTIONS,
                "/mcp",
                &[
                    ("origin", origin),
                    ("access-control-request-method", "POST"),
                    (
                        "access-control-request-headers",
                        "content-type, mcp-session-id, mcp-protocol-version, authorization",
                    ),
                ],
                None,
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{origin}");
        assert_eq!(reply.header("access-control-allow-origin"), origin);
        let methods = reply
            .header("access-control-allow-methods")
            .to_ascii_uppercase();
        assert!(
            methods.contains("POST") && methods.contains("DELETE"),
            "{methods}"
        );
        let headers = reply.header("access-control-allow-headers");
        for name in [
            "mcp-session-id",
            "mcp-protocol-version",
            "last-event-id",
            "authorization",
        ] {
            assert!(headers.contains(name), "{name} missing from {headers}");
        }
        assert_ne!(reply.header("access-control-allow-origin"), "*");
    }

    // A foreign origin's preflight is refused outright.
    let reply = send(
        &fx.app,
        request(
            Method::OPTIONS,
            "/mcp",
            &[
                ("origin", "https://evil.example"),
                ("access-control-request-method", "POST"),
            ],
            None,
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(reply.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn the_session_id_header_is_exposed_to_an_allowed_origin() {
    let fx = fixture();
    let reply = send(
        &fx.app,
        post_mcp(
            &initialize_body("2025-06-18"),
            &[("origin", "http://localhost:6274")],
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply
        .header("access-control-expose-headers")
        .to_ascii_lowercase()
        .contains("mcp-session-id"));
    assert_eq!(
        reply.header("access-control-allow-origin"),
        "http://localhost:6274"
    );
}

// ---------------------------------------------------------------------------
// Bearer token
// ---------------------------------------------------------------------------

fn with_token() -> Fixture {
    fixture_with(
        HttpConfig {
            auth_token: Some(TOKEN.to_string()),
            ..HttpConfig::default()
        },
        None,
    )
}

#[tokio::test]
async fn a_configured_token_is_required_on_mcp() {
    let fx = with_token();
    let missing = send(&fx.app, post_mcp(&initialize_body("2025-06-18"), &[])).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert!(missing
        .header("www-authenticate")
        .starts_with("Bearer realm="));
    assert!(!missing.header("www-authenticate").contains("invalid_token"));

    let wrong = send(
        &fx.app,
        post_mcp(
            &initialize_body("2025-06-18"),
            &[("authorization", "Bearer not-the-token")],
        ),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.header("www-authenticate").contains("invalid_token"));

    let bearer = format!("Bearer {TOKEN}");
    let ok = send(
        &fx.app,
        post_mcp(
            &initialize_body("2025-06-18"),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);

    // The whole session works with the header and fails without it.
    let session = open_session(&fx.app, &[("authorization", &bearer)]).await;
    let (is_error, text) = session_tool_call(
        &fx.app,
        &session,
        &[("authorization", &bearer)],
        "analyze_file",
        &json!({"file_path": fx.sample.to_string_lossy()}),
    )
    .await;
    assert!(!is_error, "{text}");
}

#[tokio::test]
async fn a_configured_token_is_required_on_rest_routes_except_health() {
    let fx = with_token();
    let bearer = format!("Bearer {TOKEN}");
    for (method, uri) in [
        (Method::GET, "/cache/stats"),
        (Method::POST, "/cache/clear"),
        (Method::GET, "/strings/stats"),
        (Method::GET, "/api/info"),
        (Method::GET, "/api-docs/openapi.json"),
    ] {
        let denied = send(&fx.app, request(method.clone(), uri, &[], None)).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "{uri}");
        let allowed = send(
            &fx.app,
            request(method, uri, &[("authorization", &bearer)], None),
        )
        .await;
        assert_eq!(allowed.status, StatusCode::OK, "{uri}: {}", allowed.body);
    }
    let health = send(&fx.app, request(Method::GET, "/health", &[], None)).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json()["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn a_preflight_needs_no_token_but_the_origin_check_still_applies() {
    let fx = with_token();
    let preflight = |origin: &'static str| {
        request(
            Method::OPTIONS,
            "/mcp",
            &[
                ("origin", origin),
                ("access-control-request-method", "POST"),
            ],
            None,
        )
    };
    let ok = send(&fx.app, preflight("http://localhost:6274")).await;
    assert_eq!(ok.status, StatusCode::OK);
    let foreign = send(&fx.app, preflight("https://evil.example")).await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_401_is_readable_by_an_allowed_browser_origin() {
    let fx = with_token();
    let reply = send(
        &fx.app,
        request(
            Method::GET,
            "/cache/stats",
            &[("origin", "http://localhost:6274")],
            None,
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        reply.header("access-control-allow-origin"),
        "http://localhost:6274"
    );
    assert!(reply
        .header("access-control-expose-headers")
        .to_ascii_lowercase()
        .contains("www-authenticate"));
}

// ---------------------------------------------------------------------------
// REST helpers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rest_tools_list_and_call_go_through_the_tool_router() {
    let fx = fixture();
    let list = send(
        &fx.app,
        request(Method::POST, "/tools/list", &[], Some(&json!({}))),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    let tools = list.json()["result"]["tools"].as_array().unwrap().clone();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "analyze_file",
        "llm_analyze_file",
        "yara_scan_file",
        "analyze_java_file",
        "analyze_npm_package",
        "analyze_python_package",
    ] {
        assert!(names.contains(&expected), "{expected} in {names:?}");
    }
    assert!(tools.iter().all(|t| t["inputSchema"]["type"] == "object"));

    let call = send(
        &fx.app,
        request(
            Method::POST,
            "/tools/call",
            &[],
            Some(&json!({
                "name": "analyze_file",
                "arguments": { "file_path": fx.sample.to_string_lossy(), "hashes": true }
            })),
        ),
    )
    .await;
    assert_eq!(call.status, StatusCode::OK, "{}", call.body);
    let text = call.json()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("sha256"), "{text}");

    // A failing tool is a result with isError, an unknown tool is 404.
    let failing = send(
        &fx.app,
        request(
            Method::POST,
            "/tools/call",
            &[],
            Some(&json!({"name": "analyze_file", "arguments": {"file_path": "/no/such/file"}})),
        ),
    )
    .await;
    assert_eq!(failing.status, StatusCode::OK);
    assert_eq!(failing.json()["isError"], true);
    let unknown = send(
        &fx.app,
        request(
            Method::POST,
            "/tools/call",
            &[],
            Some(&json!({"name": "nope", "arguments": {}})),
        ),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.json()["isError"], true);
    // Success, tool failure and protocol failure bodies carry the same keys.
    let keys =
        |value: Value| -> Vec<String> { value.as_object().unwrap().keys().cloned().collect() };
    let success_keys = keys(call.json());
    assert_eq!(keys(failing.json()), success_keys);
    assert_eq!(keys(unknown.json()), success_keys);
    assert!(
        success_keys.contains(&"content".to_string()),
        "{success_keys:?}"
    );
    assert!(
        success_keys.contains(&"isError".to_string()),
        "{success_keys:?}"
    );
}

#[tokio::test]
async fn cache_and_strings_routes_reflect_a_tool_call_made_over_mcp() {
    let fx = fixture();
    let before = send(&fx.app, request(Method::GET, "/cache/list", &[], None)).await;
    assert_eq!(before.json()["count"], 0);

    let session = open_session(&fx.app, &[]).await;
    let (is_error, text) = session_tool_call(
        &fx.app,
        &session,
        &[],
        "analyze_file",
        &json!({"file_path": fx.sample.to_string_lossy(), "strings": true, "hashes": true}),
    )
    .await;
    assert!(!is_error, "{text}");

    let list = send(&fx.app, request(Method::GET, "/cache/list", &[], None)).await;
    let entries = list.json()["entries"].as_array().unwrap().clone();
    assert_eq!(entries.len(), 1, "{}", list.body);
    assert!(entries[0]["file_path"]
        .as_str()
        .unwrap()
        .ends_with("sample.txt"));

    let stats = send(&fx.app, request(Method::GET, "/cache/stats", &[], None))
        .await
        .json();
    assert_eq!(stats["total_entries"], 1, "{stats}");
    assert_eq!(stats["tool_counts"]["analyze_file"], 1, "{stats}");

    let strings = send(&fx.app, request(Method::GET, "/strings/stats", &[], None))
        .await
        .json();
    assert!(
        strings["total_unique_strings"].as_u64().unwrap() > 0,
        "{strings}"
    );

    let found = send(
        &fx.app,
        request(
            Method::POST,
            "/strings/search",
            &[],
            Some(&json!({"query": "scanner-fixture-marker", "limit": 5})),
        ),
    )
    .await
    .json();
    assert!(found["count"].as_u64().unwrap() >= 1, "{found}");

    // The REST call path writes to the same objects.
    let rest_call = send(
        &fx.app,
        request(
            Method::POST,
            "/tools/call",
            &[],
            Some(&json!({"name": "analyze_file", "arguments": {"file_path": fx.sample.to_string_lossy()}})),
        ),
    )
    .await;
    assert_eq!(rest_call.status, StatusCode::OK);
    let stats = send(&fx.app, request(Method::GET, "/cache/stats", &[], None))
        .await
        .json();
    assert_eq!(stats["total_entries"], 2, "{stats}");

    let cleared = send(&fx.app, request(Method::POST, "/cache/clear", &[], None))
        .await
        .json();
    assert_eq!(cleared["status"], "success");
    let after = send(&fx.app, request(Method::GET, "/cache/list", &[], None)).await;
    assert_eq!(after.json()["count"], 0);

    // Clearing also forgets the sections analyze_file cached: the same call
    // is a miss again, not a hit served from memory.
    let args = json!({"name": "analyze_file", "arguments": {"file_path": fx.sample.to_string_lossy(), "hashes": true}});
    let cache_state = |response: &Reply| {
        let body = response.json();
        let text = body["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{body}"));
        serde_json::from_str::<Value>(text).unwrap()["cache"].clone()
    };
    let first = send(
        &fx.app,
        request(Method::POST, "/tools/call", &[], Some(&args)),
    )
    .await;
    let second = send(
        &fx.app,
        request(Method::POST, "/tools/call", &[], Some(&args)),
    )
    .await;
    assert_eq!(cache_state(&first), "miss");
    assert_eq!(cache_state(&second), "hit");
    send(&fx.app, request(Method::POST, "/cache/clear", &[], None)).await;
    let third = send(
        &fx.app,
        request(Method::POST, "/tools/call", &[], Some(&args)),
    )
    .await;
    assert_eq!(cache_state(&third), "miss");
}

#[tokio::test]
async fn api_info_openapi_and_the_router_list_the_same_routes() {
    let fx = fixture();
    let info = send(&fx.app, request(Method::GET, "/api/info", &[], None))
        .await
        .json();
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["uptime_seconds"].as_u64().unwrap() < 60, "{info}");
    let listed: std::collections::BTreeSet<String> = info["endpoints"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let expected: std::collections::BTreeSet<String> =
        ROUTES.iter().map(|r| r.path.to_string()).collect();
    assert_eq!(listed, expected);
    assert!(!listed.contains("/docs") && !listed.contains("/redoc"));

    // Every listed route exists (never 404 or 405 for its documented method).
    for route in ROUTES.iter().filter(|r| r.path != "/mcp") {
        let method = Method::from_bytes(route.method.as_bytes()).unwrap();
        let body =
            (route.method == "POST").then(|| json!({"name": "analyze_file", "arguments": {}}));
        let reply = send(&fx.app, request(method, route.path, &[], body.as_ref())).await;
        assert!(
            reply.status != StatusCode::NOT_FOUND && reply.status != StatusCode::METHOD_NOT_ALLOWED,
            "{} {} -> {}",
            route.method,
            route.path,
            reply.status
        );
    }
    for gone in ["/docs", "/redoc", "/sse"] {
        let reply = send(&fx.app, request(Method::GET, gone, &[], None)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{gone}");
    }

    let openapi = send(
        &fx.app,
        request(Method::GET, "/api-docs/openapi.json", &[], None),
    )
    .await
    .json();
    assert_eq!(openapi["info"]["version"], env!("CARGO_PKG_VERSION"));
    let documented = openapi["paths"].as_object().unwrap();
    assert_eq!(
        documented.len(),
        ROUTES.len() - 1,
        "every REST route, /mcp excluded"
    );
    assert!(documented.contains_key("/tools/call"));
    assert!(documented["/cache/search"]["post"]["requestBody"].is_object());
}

#[tokio::test]
async fn initialize_reports_the_real_identity() {
    let fx = fixture();
    let reply = send(
        &fx.app,
        request(Method::POST, "/initialize", &[], Some(&json!({}))),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let info = reply.json();
    assert_eq!(info["serverInfo"]["name"], "file-scanner");
    assert_eq!(info["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["instructions"]
        .as_str()
        .unwrap()
        .contains("analyze_file"));
}

// ---------------------------------------------------------------------------
// File-system scope and size caps, reached over HTTP
// ---------------------------------------------------------------------------

async fn rest_call(app: &Router, name: &str, arguments: Value) -> (StatusCode, Value) {
    let reply = send(
        app,
        request(
            Method::POST,
            "/tools/call",
            &[],
            Some(&json!({"name": name, "arguments": arguments})),
        ),
    )
    .await;
    (reply.status, reply.json())
}

#[tokio::test]
async fn allow_roots_confine_tool_paths_over_http() {
    let inside = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let ok_file = inside.path().join("ok.txt");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&ok_file, "fine").unwrap();
    std::fs::write(&secret, "secret").unwrap();
    std::os::unix::fs::symlink(&secret, inside.path().join("link.txt")).unwrap();
    let fx = fixture_with(
        HttpConfig::default(),
        Some(vec![inside.path().to_path_buf()]),
    );

    let (_, result) = rest_call(
        &fx.app,
        "analyze_file",
        json!({"file_path": ok_file.to_string_lossy()}),
    )
    .await;
    assert_ne!(result["isError"], true, "{result}");

    for path in [
        secret.to_string_lossy().into_owned(),
        inside
            .path()
            .join("link.txt")
            .to_string_lossy()
            .into_owned(),
        format!(
            "{}/../{}/secret.txt",
            inside.path().display(),
            outside.path().file_name().unwrap().to_string_lossy()
        ),
    ] {
        let (_, result) = rest_call(&fx.app, "analyze_file", json!({"file_path": path})).await;
        assert_eq!(result["isError"], true, "{path}: {result}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("--allow-root"), "{text}");
    }
    let (_, result) = rest_call(
        &fx.app,
        "yara_scan_file",
        json!({"path": outside.path().to_string_lossy(), "yara_rule": "rule r { condition: true }"}),
    )
    .await;
    assert_eq!(result["isError"], true, "{result}");
}

#[tokio::test]
async fn special_files_are_rejected_instead_of_hanging() {
    let dir = TempDir::new().unwrap();
    let fifo = dir.path().join("pipe");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let fx = fixture();
    let (_, result) = rest_call(
        &fx.app,
        "analyze_file",
        json!({"file_path": fifo.to_string_lossy()}),
    )
    .await;
    assert_eq!(result["isError"], true, "{result}");
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("named pipe"));
}

#[tokio::test]
async fn size_arguments_are_capped() {
    let fx = fixture();
    let sample = fx.sample.to_string_lossy().into_owned();
    let (_, result) = rest_call(
        &fx.app,
        "analyze_file",
        json!({"file_path": sample, "hex_dump": true, "hex_dump_size": 4_000_000_000_u64}),
    )
    .await;
    assert_eq!(result["isError"], true, "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("hex_dump_size") && text.contains("hex_dump_offset"),
        "{text}"
    );

    let (_, result) = rest_call(
        &fx.app,
        "analyze_file",
        json!({"file_path": sample, "hex_dump": true, "hex_dump_size": 64}),
    )
    .await;
    assert_ne!(result["isError"], true, "{result}");

    let (_, result) = rest_call(
        &fx.app,
        "yara_scan_file",
        json!({"path": sample, "yara_rule": "rule r { condition: true }", "max_file_size": 9_000_000_000_000_u64}),
    )
    .await;
    assert_eq!(result["isError"], true, "{result}");
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("max_file_size"));
}

#[tokio::test]
async fn rest_initialize_reports_a_revision_that_has_initialize() {
    let fx = fixture();
    let info = send(&fx.app, request(Method::POST, "/initialize", &[], None))
        .await
        .json();
    assert_eq!(info["protocolVersion"], "2025-11-25", "{info}");
}

/// Rejected REST bodies are `{"error": ...}` JSON, like every other REST failure.
#[tokio::test]
async fn rest_body_rejections_are_json() {
    let fx = fixture();
    let cases: [(Option<&str>, &str, StatusCode); 3] = [
        (
            Some("application/json"),
            "{not json",
            StatusCode::BAD_REQUEST,
        ),
        (None, "{}", StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            Some("application/json"),
            "{\"name\": 5}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];
    for (content_type, body, status) in cases {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/tools/call")
            .header(header::HOST, HOST);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let reply = send(&fx.app, builder.body(Body::from(body.to_string())).unwrap()).await;
        assert_eq!(reply.status, status, "{body}: {}", reply.body);
        let json = reply.json();
        assert!(
            json["error"].as_str().is_some_and(|e| !e.is_empty()),
            "{json}"
        );
    }
}
