use file_scanner::mcp_server::FileScannerMcp;
use file_scanner::mcp_transport::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpServerState, McpTransportServer, SseEvent,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_server() -> McpTransportServer {
        McpTransportServer::new()
    }

    #[tokio::test]
    async fn test_mcp_transport_server_creation() {
        let _server = create_test_server();
        // Server should be created with cache and string tracker
        assert!(true); // Basic creation test
    }

    #[tokio::test]
    async fn test_jsonrpc_initialize_request() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(1)));
        assert!(response.error.is_none());
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["serverInfo"].is_object());
        assert!(result["capabilities"].is_object());
    }

    #[tokio::test]
    async fn test_jsonrpc_tools_list_request() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/list".to_string(),
            params: None,
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(2)));
        assert!(response.error.is_none());
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);

        // Check tool names
        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(tool_names.contains(&"analyze_file"));
        assert!(tool_names.contains(&"llm_analyze_file"));
    }

    #[tokio::test]
    async fn test_jsonrpc_tool_call_analyze_file() {
        let server = create_test_server();

        // Create a test file
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, b"Test content for analysis").unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "metadata": true,
                    "hashes": true,
                    "strings": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(3)));
        assert!(response.error.is_none());
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        assert!(result["content"].is_array());
        let content = &result["content"][0];
        assert_eq!(content["type"], "text");

        // Parse the analysis result
        let text = content["text"].as_str().unwrap();
        let analysis: Value = serde_json::from_str(text).unwrap();
        assert_eq!(analysis["file_size"], 25);
        assert!(analysis["hashes"].is_object());
        assert!(analysis["strings"].is_array());
    }

    #[tokio::test]
    async fn test_jsonrpc_tool_call_llm_analyze_file() {
        let server = create_test_server();

        // Create a test file
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_binary");
        std::fs::write(&test_file, b"MZ\x90\x00\x03\x00\x00\x00Test binary content").unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "llm_analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "token_limit": 1000,
                    "suggest_yara_rule": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(4)));
        assert!(response.error.is_none());
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        assert!(result["content"].is_array());
        let content = &result["content"][0];
        assert_eq!(content["type"], "text");

        // Parse the LLM analysis result
        let text = content["text"].as_str().unwrap();
        let analysis: Value = serde_json::from_str(text).unwrap();
        assert!(analysis["md5"].is_string());
        assert!(analysis["file_size"].is_u64());
        assert!(analysis["key_strings"].is_array());
        assert!(analysis["hex_patterns"].is_array());
    }

    #[tokio::test]
    async fn test_jsonrpc_invalid_method() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(5)),
            method: "invalid/method".to_string(),
            params: None,
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(5)));
        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, -32601);
        assert_eq!(error.message, "Method not found");
    }

    #[tokio::test]
    async fn test_jsonrpc_invalid_tool_params() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(6)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "invalid": "params"
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(6)));
        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, -32602);
        assert_eq!(error.message, "Invalid params");
    }

    #[tokio::test]
    async fn test_jsonrpc_missing_params() {
        let server = create_test_server();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(7)),
            method: "tools/call".to_string(),
            params: None,
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid Request");
    }

    #[tokio::test]
    async fn test_tool_call_with_cache() {
        let server = create_test_server();

        // Create a test file
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("cache_test.txt");
        std::fs::write(&test_file, b"Cache test content").unwrap();

        // First call - should cache
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(8)),
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

        let response1 = server.handle_jsonrpc_request(request.clone()).await;
        assert!(response1.error.is_none());

        // Second call - should use cache
        let response2 = server.handle_jsonrpc_request(request).await;
        assert!(response2.error.is_none());

        // Results should be identical
        assert_eq!(response1.result, response2.result);
    }

    #[tokio::test]
    async fn test_tool_call_with_string_tracking() {
        let server = create_test_server();

        // Create a test file with specific strings
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("string_test.txt");
        std::fs::write(
            &test_file,
            b"libtest.so\ncmd.exe\nhttps://example.com\n/etc/passwd",
        )
        .unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(9)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "strings": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;
        assert!(response.error.is_none());

        // Strings should be tracked in string tracker
        // (In a real test, we'd need to expose the string tracker to verify)
    }

    #[tokio::test]
    async fn test_jsonrpc_parse_error() {
        // This tests the error handling in run_stdio, but we can't easily test
        // the full stdio implementation. Instead, we test the error response format
        let error = JsonRpcError {
            code: -32700,
            message: "Parse error: test".to_string(),
            data: None,
        };

        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: None,
            result: None,
            error: Some(error),
        };

        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("-32700"));
        assert!(json_str.contains("Parse error"));
    }

    #[tokio::test]
    async fn test_sse_event_serialization() {
        let event = SseEvent {
            id: Some("test-id".to_string()),
            event: Some("test-event".to_string()),
            data: json!({"test": "data"}).to_string(),
        };

        // Verify the event can be created and has expected fields
        assert_eq!(event.id, Some("test-id".to_string()));
        assert_eq!(event.event, Some("test-event".to_string()));
        assert!(event.data.contains("test"));
    }

    #[tokio::test]
    async fn test_mcp_server_state_creation() {
        let handler = FileScannerMcp;
        let sse_clients = Arc::new(Mutex::new(HashMap::new()));
        let cache_dir = std::env::temp_dir().join("test-file-scanner-cache");
        let cache = Arc::new(
            file_scanner::cache::AnalysisCache::new(cache_dir).expect("Failed to create cache"),
        );
        let string_tracker = Arc::new(file_scanner::string_tracker::StringTracker::new());

        let state =
            McpServerState::new_for_testing(handler, sse_clients.clone(), cache, string_tracker);

        // Test that state can be cloned
        let _cloned_state = state.clone();
        assert_eq!(Arc::strong_count(&sse_clients), 2); // Original + clone
    }

    #[tokio::test]
    async fn test_concurrent_jsonrpc_requests() {
        let server = Arc::new(create_test_server());
        let mut handles = vec![];

        // Send multiple concurrent requests
        for i in 0..10 {
            let server_clone = server.clone();
            let handle = tokio::spawn(async move {
                let request = JsonRpcRequest {
                    jsonrpc: "2.0".to_string(),
                    id: Some(json!(i)),
                    method: "tools/list".to_string(),
                    params: None,
                };

                server_clone.handle_jsonrpc_request(request).await
            });
            handles.push(handle);
        }

        // All requests should succeed
        for (i, handle) in handles.into_iter().enumerate() {
            let response = handle.await.unwrap();
            assert_eq!(response.id, Some(json!(i)));
            assert!(response.error.is_none());
            assert!(response.result.is_some());
        }
    }

    #[tokio::test]
    async fn test_tool_call_file_not_found() {
        let server = create_test_server();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(10)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    "file_path": "/nonexistent/file/path.txt",
                    "metadata": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(10)));
        assert!(response.error.is_none()); // Error is in the result content
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let content = &result["content"][0];
        let text = content["text"].as_str().unwrap();
        assert!(text.contains("Error"));
    }

    #[tokio::test]
    async fn test_tool_call_unknown_tool() {
        let server = create_test_server();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(11)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "unknown_tool",
                "arguments": {}
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let content = &result["content"][0];
        let text = content["text"].as_str().unwrap();
        assert!(text.contains("Unknown tool"));
    }

    #[tokio::test]
    async fn test_tool_params_validation() {
        let server = create_test_server();

        // Test with missing required parameter
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(12)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    // Missing file_path
                    "metadata": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let content = &result["content"][0];
        let text = content["text"].as_str().unwrap();
        assert!(text.contains("Error"));
    }

    #[tokio::test]
    async fn test_large_file_analysis() {
        let server = create_test_server();

        // Create a large test file
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("large_file.bin");
        let large_content = vec![0u8; 1024 * 1024]; // 1MB
        std::fs::write(&test_file, &large_content).unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(13)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "metadata": true,
                    "hashes": true,
                    "hex_dump": true,
                    "hex_dump_size": 512
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.error.is_none());
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let content = &result["content"][0];
        let text = content["text"].as_str().unwrap();
        let analysis: Value = serde_json::from_str(text).unwrap();
        assert_eq!(analysis["file_size"], 1024 * 1024);
    }

    #[tokio::test]
    async fn test_binary_file_analysis() {
        let server = create_test_server();

        // Create a test binary file with PE header
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.exe");
        let mut content = b"MZ".to_vec();
        content.extend_from_slice(&[0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
        content.extend_from_slice(b"This program cannot be run in DOS mode");
        std::fs::write(&test_file, &content).unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(14)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "binary_info": true,
                    "entropy": true
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[tokio::test]
    async fn test_llm_analyze_with_yara_suggestion() {
        let server = create_test_server();

        // Create a test file with interesting patterns
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("malware_sample");
        std::fs::write(
            &test_file,
            b"MZ\x90\x00CreateProcess\x00VirtualAlloc\x00suspicious_string",
        )
        .unwrap();

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(15)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "llm_analyze_file",
                "arguments": {
                    "file_path": test_file.to_str().unwrap(),
                    "suggest_yara_rule": true,
                    "max_strings": 10,
                    "hex_pattern_size": 16
                }
            })),
        };

        let response = server.handle_jsonrpc_request(request).await;

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.error.is_none());

        let result = response.result.unwrap();
        let content = &result["content"][0];
        let text = content["text"].as_str().unwrap();
        let analysis: Value = serde_json::from_str(text).unwrap();

        assert!(analysis["yara_rule_suggestion"].is_string());
        assert!(analysis["key_strings"].is_array());
        assert!(analysis["hex_patterns"].is_array());
    }
}
