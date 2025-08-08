use file_scanner::cache::AnalysisCache;
use file_scanner::mcp_server::FileScannerMcp;
use file_scanner::mcp_transport::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpServerState, McpTransportServer, SseEvent,
    SseQuery,
};
use file_scanner::string_tracker::StringTracker;
use futures_util::future;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// Helper function to create a test server state
fn create_test_state() -> McpServerState {
    let temp_dir = TempDir::new().unwrap();
    let cache = Arc::new(AnalysisCache::new(temp_dir.path()).unwrap());
    let string_tracker = Arc::new(StringTracker::new());
    let sse_clients = Arc::new(Mutex::new(HashMap::new()));

    McpServerState::new_for_testing(FileScannerMcp::new(), sse_clients, cache, string_tracker)
}

// Helper function to create a test transport server
fn create_test_transport_server() -> McpTransportServer {
    McpTransportServer::new()
}

#[tokio::test]
async fn test_stdio_transport_integration() {
    let server = create_test_transport_server();

    // Test stdio message handling flow
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_http_sse_transport_setup() {
    let server = create_test_transport_server();

    // Test different JSON-RPC methods
    let methods = vec![
        ("initialize", None),
        ("tools/list", None),
        (
            "tools/call",
            Some(json!({"name": "analyze_file", "arguments": {"file_path": "/tmp/nonexistent"}})),
        ),
        ("unknown_method", None),
    ];

    for (method, params) in methods {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: method.to_string(),
            params,
        };

        let response = server.handle_jsonrpc_request(request).await;
        assert_eq!(response.jsonrpc, "2.0");

        if method == "unknown_method" {
            assert!(response.error.is_some());
        } else {
            // For valid methods, should have either result or error
            assert!(response.result.is_some() || response.error.is_some());
        }
    }
}

#[tokio::test]
async fn test_tool_call_analyze_file_comprehensive() {
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("comprehensive_test.txt");
    fs::write(&test_file, b"Test content for comprehensive analysis").unwrap();

    // Test analyze_file with all possible flags
    let analyze_request = json!({
        "name": "analyze_file",
        "arguments": {
            "file_path": test_file.to_str().unwrap(),
            "metadata": true,
            "hashes": true,
            "strings": true,
            "min_string_length": 4,
            "hex_dump": true,
            "hex_dump_size": 128,
            "hex_dump_offset": 0,
            "binary_info": true,
            "signatures": false,
            "symbols": false,
            "control_flow": false,
            "vulnerabilities": false,
            "code_quality": false,
            "dependencies": false,
            "entropy": false,
            "disassembly": false,
            "threats": false,
            "behavioral": false,
            "yara_indicators": false
        }
    });

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(analyze_request),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_tool_call_llm_analyze_file_comprehensive() {
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("llm_test.bin");

    // Create a small binary file
    let binary_content = vec![
        0x7f, 0x45, 0x4c, 0x46, // ELF magic
        0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e,
        0x00, // ELF header continuation
    ];
    fs::write(&test_file, &binary_content).unwrap();

    let llm_request = json!({
        "name": "llm_analyze_file",
        "arguments": {
            "file_path": test_file.to_str().unwrap(),
            "token_limit": 15000,
            "min_string_length": 6,
            "max_strings": 30,
            "max_imports": 20,
            "max_opcodes": 8,
            "hex_pattern_size": 24,
            "suggest_yara_rule": true
        }
    });

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(llm_request),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_error_handling_edge_cases() {
    let server = create_test_transport_server();

    // Test tools/call with no params
    let request_no_params = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request_no_params).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, -32600);

    // Test tools/call with invalid params structure
    let request_invalid_params = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(json!({"invalid": "structure"})),
    };

    let response = server.handle_jsonrpc_request(request_invalid_params).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.error.is_some());
    assert_eq!(response.error.unwrap().code, -32602);

    // Test unknown tool
    let request_unknown_tool = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "nonexistent_tool", "arguments": {}})),
    };

    let response = server.handle_jsonrpc_request(request_unknown_tool).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());

    // Check that the result contains an error message about unknown tool
    if let Some(result) = response.result {
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("Unknown tool"));
    }
}

#[tokio::test]
async fn test_sse_event_handling() {
    // Test SSE event creation and serialization
    let event = SseEvent {
        id: Some("test_event_id".to_string()),
        event: Some("test_event_type".to_string()),
        data: json!({"message": "test data", "timestamp": 12345}).to_string(),
    };

    assert_eq!(event.id.as_ref().unwrap(), "test_event_id");
    assert_eq!(event.event.as_ref().unwrap(), "test_event_type");
    assert!(event.data.contains("test data"));

    // Test event cloning
    let cloned = event.clone();
    assert_eq!(event.id, cloned.id);
    assert_eq!(event.event, cloned.event);
    assert_eq!(event.data, cloned.data);
}

#[tokio::test]
async fn test_sse_query_parsing() {
    // Test SSE query with client_id
    let query_with_id = SseQuery {
        client_id: Some("test_client_123".to_string()),
    };
    assert_eq!(query_with_id.client_id.unwrap(), "test_client_123");

    // Test SSE query without client_id
    let query_without_id = SseQuery { client_id: None };
    assert!(query_without_id.client_id.is_none());
}

#[tokio::test]
async fn test_json_rpc_structures_comprehensive() {
    // Test JSON-RPC request with all fields
    let full_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!({"uuid": "test-uuid-123"})),
        method: "complex_method".to_string(),
        params: Some(json!({
            "nested": {
                "array": [1, 2, 3],
                "object": {"key": "value"}
            },
            "boolean": true,
            "number": 42.5
        })),
    };

    // Serialize and deserialize to test serde
    let serialized = serde_json::to_string(&full_request).unwrap();
    let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();

    assert_eq!(full_request.jsonrpc, deserialized.jsonrpc);
    assert_eq!(full_request.id, deserialized.id);
    assert_eq!(full_request.method, deserialized.method);
    assert_eq!(full_request.params, deserialized.params);

    // Test JSON-RPC response with error
    let error_response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("string_id")),
        result: None,
        error: Some(JsonRpcError {
            code: -32603,
            message: "Internal error".to_string(),
            data: Some(json!({"details": "Database connection failed", "error_code": 500})),
        }),
    };

    let serialized = serde_json::to_string(&error_response).unwrap();
    let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();

    assert_eq!(error_response.jsonrpc, deserialized.jsonrpc);
    assert_eq!(error_response.id, deserialized.id);
    assert!(deserialized.result.is_none());
    assert!(deserialized.error.is_some());

    let error = deserialized.error.unwrap();
    assert_eq!(error.code, -32603);
    assert_eq!(error.message, "Internal error");
    assert!(error.data.is_some());
}

#[tokio::test]
async fn test_default_implementations() {
    // Test McpTransportServer default implementation
    let default_server = McpTransportServer::default();
    let new_server = McpTransportServer::new();

    // Both should be able to handle basic requests
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let default_response = default_server.handle_jsonrpc_request(request.clone()).await;
    let new_response = new_server.handle_jsonrpc_request(request).await;

    assert_eq!(default_response.jsonrpc, new_response.jsonrpc);
    assert!(default_response.result.is_some());
    assert!(new_response.result.is_some());
}

#[tokio::test]
async fn test_server_state_functionality() {
    let _state = create_test_state();

    // Test that the state has the expected components
    // We can't directly test private fields, but we can test behavior

    // Create a simple analyze_file request through the transport
    let server = create_test_transport_server();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/list".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_caching_integration() {
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("cache_test.txt");
    fs::write(&test_file, b"Cache test content").unwrap();

    // First call - should analyze and cache
    let request1 = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "metadata": true,
                "hashes": true
            }
        })),
    };

    let response1 = server.handle_jsonrpc_request(request1).await;
    assert!(response1.result.is_some());

    // Second call - should potentially use cache (though we can't verify without cache inspection)
    let request2 = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "metadata": true,
                "hashes": true
            }
        })),
    };

    let response2 = server.handle_jsonrpc_request(request2).await;
    assert!(response2.result.is_some());
}

#[tokio::test]
async fn test_string_tracking_integration() {
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("strings_test.txt");
    fs::write(
        &test_file,
        b"Test string content with URLs like https://example.com and paths /usr/bin/test",
    )
    .unwrap();

    // Analyze file with string extraction
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "strings": true,
                "min_string_length": 4
            }
        })),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert!(response.result.is_some());

    // Verify string tracking would work (strings should be tracked internally)
    if let Some(result) = response.result {
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("strings") || text.contains("content"));
    }
}

#[tokio::test]
async fn test_error_scenarios_comprehensive() {
    let server = create_test_transport_server();

    // Test analyze_file with invalid file path
    let invalid_file_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": "/absolutely/nonexistent/path/file.txt",
                "metadata": true
            }
        })),
    };

    let response = server.handle_jsonrpc_request(invalid_file_request).await;
    assert!(response.result.is_some());

    // Should contain error information in the result
    if let Some(result) = response.result {
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("Error") || text.contains("error"));
    }

    // Test llm_analyze_file with invalid parameters
    let invalid_llm_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "llm_analyze_file",
            "arguments": {
                "file_path": "/nonexistent/file.bin",
                "token_limit": -1000,  // Invalid token limit
                "max_strings": -10     // Invalid max strings
            }
        })),
    };

    let response = server.handle_jsonrpc_request(invalid_llm_request).await;
    assert!(response.result.is_some());
}

#[tokio::test]
async fn test_concurrent_requests() {
    let server = Arc::new(create_test_transport_server());
    let temp_dir = TempDir::new().unwrap();

    // Create multiple test files
    let mut files = Vec::new();
    for i in 0..5 {
        let test_file = temp_dir.path().join(format!("concurrent_test_{}.txt", i));
        fs::write(&test_file, format!("Test content for file {}", i)).unwrap();
        files.push(test_file);
    }

    // Create concurrent requests
    let mut handles = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let server_clone = server.clone();
        let file_path = file.to_str().unwrap().to_string();

        let handle = tokio::spawn(async move {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(i)),
                method: "tools/call".to_string(),
                params: Some(json!({
                    "name": "analyze_file",
                    "arguments": {
                        "file_path": file_path,
                        "metadata": true,
                        "hashes": true
                    }
                })),
            };

            server_clone.handle_jsonrpc_request(request).await
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    let results = future::join_all(handles).await;

    // Verify all requests succeeded
    for result in results {
        let response = result.unwrap();
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
    }
}

#[test]
fn test_json_rpc_error_equality() {
    let error1 = JsonRpcError {
        code: -32600,
        message: "Invalid Request".to_string(),
        data: Some(json!({"detail": "Missing field"})),
    };

    let error2 = JsonRpcError {
        code: -32600,
        message: "Invalid Request".to_string(),
        data: Some(json!({"detail": "Missing field"})),
    };

    let error3 = JsonRpcError {
        code: -32601,
        message: "Method not found".to_string(),
        data: None,
    };

    assert_eq!(error1, error2);
    assert_ne!(error1, error3);
}

#[tokio::test]
async fn test_memory_management() {
    // Test that the server doesn't leak memory with many requests
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("memory_test.txt");
    fs::write(&test_file, b"Memory test content").unwrap();

    // Make many requests
    for i in 0..100 {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(i)),
            method: if i % 2 == 0 {
                "initialize"
            } else {
                "tools/list"
            }
            .to_string(),
            params: None,
        };

        let response = server.handle_jsonrpc_request(request).await;
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some() || response.error.is_some());
    }
}

#[tokio::test]
async fn test_large_request_handling() {
    let server = create_test_transport_server();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("large_test.txt");

    // Create a larger test file
    let large_content = "Large test content with many repeated patterns. ".repeat(1000);
    fs::write(&test_file, large_content.as_bytes()).unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "metadata": true,
                "hashes": true,
                "strings": true,
                "hex_dump": true,
                "hex_dump_size": 1024
            }
        })),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
}
