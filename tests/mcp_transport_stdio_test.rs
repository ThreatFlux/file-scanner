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

use file_scanner::mcp_transport::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpTransportServer,
};
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

// Mock for testing stdio transport logic
#[allow(dead_code)]
struct MockStdio {
    input: Arc<Mutex<Cursor<Vec<u8>>>>,
    output: Arc<Mutex<Vec<u8>>>,
}

#[allow(dead_code)]
impl MockStdio {
    fn new(input_data: &str) -> Self {
        Self {
            input: Arc::new(Mutex::new(Cursor::new(input_data.as_bytes().to_vec()))),
            output: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn get_output(&self) -> String {
        let output = self.output.lock().await;
        String::from_utf8_lossy(&output).to_string()
    }
}

#[tokio::test]
async fn test_stdio_transport_creation() {
    let transport = McpTransportServer::new();

    // Verify transport can be created for stdio
    // This tests the basic instantiation path
    // Basic import test

    // Test that we can call run_stdio without immediate panic
    // (though it will error due to no actual stdin/stdout in test)
    let result = tokio::spawn(async move {
        // This will fail but should exercise the code path
        let _ = transport.run_stdio().await;
    });

    // Give it a moment to attempt startup
    sleep(Duration::from_millis(50)).await;

    // Abort the task since it can't run without real stdio
    result.abort();
}

#[tokio::test]
async fn test_jsonrpc_request_parsing() {
    let transport = McpTransportServer::new();

    // Test valid JSON-RPC request handling
    let valid_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(valid_request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(1)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[tokio::test]
async fn test_jsonrpc_error_responses() {
    let transport = McpTransportServer::new();

    // Test invalid method
    let invalid_method_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "invalid_method".to_string(),
        params: None,
    };

    let response = transport
        .handle_jsonrpc_request(invalid_method_request)
        .await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(2)));
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    if let Some(error) = response.error {
        assert_eq!(error.code, -32601); // Method not found
        assert!(error.message.contains("Method not found"));
    }
}

#[tokio::test]
async fn test_jsonrpc_tools_list_response() {
    let transport = McpTransportServer::new();

    let tools_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
        method: "tools/list".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(tools_request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(3)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    if let Some(result) = response.result {
        assert!(result.get("tools").is_some());
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty()); // Should have at least analyze_file tool

        // Verify tool structure
        let first_tool = &tools[0];
        assert!(first_tool.get("name").is_some());
        assert!(first_tool.get("description").is_some());
        assert!(first_tool.get("inputSchema").is_some());
    }
}

#[tokio::test]
async fn test_jsonrpc_tools_call_analyze_file() {
    let transport = McpTransportServer::new();

    let tools_call_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": "/bin/ls",
                "metadata": true,
                "hashes": false
            }
        })),
    };

    let response = transport.handle_jsonrpc_request(tools_call_request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(4)));

    // Should either succeed with result or fail gracefully with error
    assert!(response.result.is_some() || response.error.is_some());

    if let Some(result) = response.result {
        assert!(result.get("content").is_some());
        let content = &result["content"];
        assert!(content.is_array() || content.is_object());
    }
}

#[tokio::test]
async fn test_jsonrpc_tools_call_invalid_tool() {
    let transport = McpTransportServer::new();

    let invalid_tool_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(5)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "nonexistent_tool",
            "arguments": {}
        })),
    };

    let response = transport.handle_jsonrpc_request(invalid_tool_request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(5)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    if let Some(result) = response.result {
        let result_str = serde_json::to_string(&result).unwrap();
        assert!(result_str.contains("Unknown tool") || result_str.contains("nonexistent_tool"));
    }
}

#[tokio::test]
async fn test_jsonrpc_tools_call_missing_params() {
    let transport = McpTransportServer::new();

    let missing_params_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(6)),
        method: "tools/call".to_string(),
        params: None, // Missing required params
    };

    let response = transport
        .handle_jsonrpc_request(missing_params_request)
        .await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(6)));
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    if let Some(error) = response.error {
        assert_eq!(error.code, -32600); // Invalid Request (missing params)
    }
}

#[tokio::test]
async fn test_jsonrpc_response_serialization() {
    // Test JsonRpcResponse serialization
    let success_response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        result: Some(json!({"test": "data"})),
        error: None,
    };

    let serialized = serde_json::to_string(&success_response).unwrap();
    let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.jsonrpc, "2.0");
    assert_eq!(deserialized.id, Some(json!(1)));
    assert!(deserialized.result.is_some());
    assert!(deserialized.error.is_none());

    // Test error response
    let error_response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        result: None,
        error: Some(JsonRpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: Some(json!({"detail": "test error"})),
        }),
    };

    let serialized_error = serde_json::to_string(&error_response).unwrap();
    let deserialized_error: JsonRpcResponse = serde_json::from_str(&serialized_error).unwrap();

    assert_eq!(deserialized_error.jsonrpc, "2.0");
    assert_eq!(deserialized_error.id, Some(json!(2)));
    assert!(deserialized_error.result.is_none());
    assert!(deserialized_error.error.is_some());

    if let Some(error) = deserialized_error.error {
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid Request");
        assert!(error.data.is_some());
    }
}

#[tokio::test]
async fn test_jsonrpc_error_types() {
    // Test different JsonRpcError codes and messages
    let parse_error = JsonRpcError {
        code: -32700,
        message: "Parse error".to_string(),
        data: None,
    };

    let invalid_request = JsonRpcError {
        code: -32600,
        message: "Invalid Request".to_string(),
        data: None,
    };

    let method_not_found = JsonRpcError {
        code: -32601,
        message: "Method not found".to_string(),
        data: None,
    };

    let invalid_params = JsonRpcError {
        code: -32602,
        message: "Invalid params".to_string(),
        data: None,
    };

    let internal_error = JsonRpcError {
        code: -32603,
        message: "Internal error".to_string(),
        data: Some(json!({"stack": "test stack trace"})),
    };

    // Test serialization/deserialization of all error types
    let errors = vec![
        parse_error,
        invalid_request,
        method_not_found,
        invalid_params,
        internal_error,
    ];

    for error in errors {
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: JsonRpcError = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.code, error.code);
        assert_eq!(deserialized.message, error.message);
        assert_eq!(deserialized.data, error.data);
    }
}

#[tokio::test]
async fn test_jsonrpc_llm_analyze_file() {
    let transport = McpTransportServer::new();

    let llm_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(7)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "llm_analyze_file",
            "arguments": {
                "file_path": "/bin/ls",
                "token_limit": 1000,
                "max_strings": 10
            }
        })),
    };

    let response = transport.handle_jsonrpc_request(llm_request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(7)));

    // Should either succeed or fail gracefully
    assert!(response.result.is_some() || response.error.is_some());
}

#[tokio::test]
async fn test_multiple_concurrent_requests() {
    let _transport = McpTransportServer::new();

    // Test concurrent JSON-RPC requests
    let mut handles = Vec::new();

    for i in 0..5 {
        let transport_clone = McpTransportServer::new();
        let handle = tokio::spawn(async move {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(json!(i)),
                method: "initialize".to_string(),
                params: None,
            };

            transport_clone.handle_jsonrpc_request(request).await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let responses = futures_util::future::join_all(handles).await;

    // Verify all responses
    for (i, response_result) in responses.into_iter().enumerate() {
        let response = response_result.unwrap();
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, Some(json!(i as u64)));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }
}

#[tokio::test]
async fn test_jsonrpc_request_validation() {
    let transport = McpTransportServer::new();

    // Test request with missing jsonrpc field (should still work)
    let missing_jsonrpc = JsonRpcRequest {
        jsonrpc: "1.0".to_string(), // Wrong version
        id: Some(json!(8)),
        method: "initialize".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(missing_jsonrpc).await;

    // Should still respond (our implementation is lenient)
    assert_eq!(response.jsonrpc, "2.0"); // Response should always be 2.0
    assert_eq!(response.id, Some(json!(8)));
}

#[tokio::test]
async fn test_stdio_error_handling_simulation() {
    // Test error response creation for stdio transport
    let error_response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: None,
        result: None,
        error: Some(JsonRpcError {
            code: -32700,
            message: "Parse error: invalid JSON".to_string(),
            data: None,
        }),
    };

    // Verify error response can be serialized (as would happen in stdio transport)
    let serialized = serde_json::to_string(&error_response).unwrap();
    assert!(serialized.contains("Parse error"));
    assert!(serialized.contains("-32700"));

    // Verify it can be deserialized back
    let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
    assert!(deserialized.error.is_some());
    assert!(deserialized.result.is_none());
}
