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

use file_scanner::mcp_transport::{JsonRpcRequest, McpTransportServer};
use serde_json::{json, Value};
use std::fs;
use tempfile::NamedTempFile;

/// Integration tests for `McpTransportServer` that exercise the actual execution paths
/// to improve line coverage for `mcp_transport.rs`

#[tokio::test]
async fn test_handle_jsonrpc_request_integration() {
    let server = McpTransportServer::new();

    // Test initialize request
    let init_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(init_request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    let result = response.result.unwrap();
    assert!(result.get("protocolVersion").is_some());
    assert!(result.get("serverInfo").is_some());
    assert!(result.get("capabilities").is_some());
}

#[tokio::test]
async fn test_handle_jsonrpc_initialized_integration() {
    let server = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "initialized".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    let result = response.result.unwrap();
    assert_eq!(result, json!({}));
}

#[tokio::test]
async fn test_handle_jsonrpc_tools_list_integration() {
    let server = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
        method: "tools/list".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    let result = response.result.unwrap();
    let tools = result.get("tools").unwrap().as_array().unwrap();
    assert_eq!(tools.len(), 6);

    let tool_names: Vec<&str> = tools
        .iter()
        .map(|t| t.get("name").unwrap().as_str().unwrap())
        .collect();
    assert!(tool_names.contains(&"analyze_file"));
    assert!(tool_names.contains(&"llm_analyze_file"));
    assert!(tool_names.contains(&"yara_scan_file"));
    assert!(tool_names.contains(&"analyze_java_file"));
    assert!(tool_names.contains(&"analyze_npm_package"));
    assert!(tool_names.contains(&"analyze_python_package"));
}

#[tokio::test]
async fn test_handle_jsonrpc_tools_call_analyze_file_integration() {
    let server = McpTransportServer::new();

    // Create a test file
    let test_file = NamedTempFile::new().unwrap();
    fs::write(
        &test_file,
        b"Hello, world! This is test content for file analysis.",
    )
    .unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": test_file.path().to_str().unwrap(),
                "metadata": true,
                "hashes": true,
                "strings": true,
                "min_string_length": 4
            }
        })),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    let result = response.result.unwrap();
    let content = result.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();

    // Parse the returned JSON to verify structure
    let analysis_result: Value = serde_json::from_str(text).unwrap();
    assert!(analysis_result.get("metadata").is_some());
    assert!(analysis_result.get("hashes").is_some());
    assert!(analysis_result.get("strings").is_some());
}

#[tokio::test]
async fn test_handle_jsonrpc_tools_call_llm_analyze_file_integration() {
    let server = McpTransportServer::new();

    // Create a test file
    let test_file = NamedTempFile::new().unwrap();
    fs::write(
        &test_file,
        b"Binary content with some strings like CreateFile and LoadLibrary",
    )
    .unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(5)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "llm_analyze_file",
            "arguments": {
                "file_path": test_file.path().to_str().unwrap(),
                "token_limit": 10000,
                "min_string_length": 6,
                "max_strings": 20,
                "suggest_yara_rule": true
            }
        })),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    let result = response.result.unwrap();
    let content = result.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();

    // Parse the returned JSON to verify structure
    let analysis_result: Value = serde_json::from_str(text).unwrap();
    assert!(analysis_result.get("md5").is_some());
    assert!(analysis_result.get("file_size").is_some());
}

#[tokio::test]
async fn test_handle_jsonrpc_tools_call_invalid_params_integration() {
    let server = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(6)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "invalid": "params_structure"
        })),
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    let error = response.error.unwrap();
    assert_eq!(error.code, -32602);
    assert_eq!(error.message, "Invalid params");
}

#[tokio::test]
async fn test_handle_jsonrpc_tools_call_missing_params_integration() {
    let server = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(7)),
        method: "tools/call".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    let error = response.error.unwrap();
    assert_eq!(error.code, -32600);
    assert_eq!(error.message, "Invalid Request");
}

#[tokio::test]
async fn test_handle_jsonrpc_unknown_method_integration() {
    let server = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(8)),
        method: "unknown/method".to_string(),
        params: None,
    };

    let response = server.handle_jsonrpc_request(request).await;
    assert_eq!(response.jsonrpc, "2.0");
    assert!(response.result.is_none());
    assert!(response.error.is_some());

    let error = response.error.unwrap();
    assert_eq!(error.code, -32601);
    assert_eq!(error.message, "Method not found");
}

#[tokio::test]
async fn test_handle_tool_call_with_file_path_integration() {
    let server = McpTransportServer::new();

    // Create a small binary file
    let test_file = NamedTempFile::new().unwrap();
    let binary_content = vec![
        0x4D, 0x5A, // PE header magic
        0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, b'H', b'e', b'l', b'l', b'o',
        0x00, // null-terminated string
        b'W', b'o', b'r', b'l', b'd', 0x00, // another string
    ];
    fs::write(&test_file, &binary_content).unwrap();

    let params = file_scanner::mcp_transport::ToolCallParams {
        name: "analyze_file".to_string(),
        arguments: {
            let mut args = std::collections::HashMap::new();
            args.insert(
                "file_path".to_string(),
                json!(test_file.path().to_str().unwrap()),
            );
            args.insert("metadata".to_string(), json!(true));
            args.insert("hashes".to_string(), json!(true));
            args.insert("binary_info".to_string(), json!(true));
            args.insert("strings".to_string(), json!(true));
            args.insert("hex_dump".to_string(), json!(true));
            args.insert("hex_dump_size".to_string(), json!(32));
            args
        },
    };

    let result = server.handle_tool_call(params).await;

    let content = result.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();

    // Should contain valid analysis result
    assert!(!text.contains("Error"));

    // Parse and verify the JSON structure
    let analysis_result: Value = serde_json::from_str(text).unwrap();
    assert!(analysis_result.get("metadata").is_some());
    assert!(analysis_result.get("hashes").is_some());
    assert!(analysis_result.get("strings").is_some());
    assert!(analysis_result.get("hex_dump").is_some());

    // Verify hex dump contains expected content (case insensitive)
    let hex_dump = analysis_result.get("hex_dump").unwrap().as_str().unwrap();
    assert!(hex_dump.to_uppercase().contains("4D 5A") || hex_dump.to_lowercase().contains("4d 5a"));
    // PE magic bytes
}

#[tokio::test]
async fn test_handle_tool_call_file_not_found_integration() {
    let server = McpTransportServer::new();

    let params = file_scanner::mcp_transport::ToolCallParams {
        name: "analyze_file".to_string(),
        arguments: {
            let mut args = std::collections::HashMap::new();
            args.insert("file_path".to_string(), json!("/nonexistent/path/file.bin"));
            args.insert("metadata".to_string(), json!(true));
            args
        },
    };

    let result = server.handle_tool_call(params).await;

    let content = result.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();

    // Should contain error message
    assert!(text.contains("Error"));
}

#[tokio::test]
async fn test_handle_tool_call_unknown_tool_integration() {
    let server = McpTransportServer::new();

    let params = file_scanner::mcp_transport::ToolCallParams {
        name: "nonexistent_tool".to_string(),
        arguments: std::collections::HashMap::new(),
    };

    let result = server.handle_tool_call(params).await;

    let content = result.get("content").unwrap().as_array().unwrap();
    let text = content[0].get("text").unwrap().as_str().unwrap();

    assert!(text.contains("Error: Unknown tool: nonexistent_tool"));
}

#[tokio::test]
async fn test_constructor_integration() {
    // Test the Default implementation path
    let server1 = McpTransportServer::default();
    let server2 = McpTransportServer::new();

    // Verify both servers can handle requests
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let response1 = server1.handle_jsonrpc_request(request.clone()).await;
    let response2 = server2.handle_jsonrpc_request(request).await;

    assert_eq!(response1.jsonrpc, "2.0");
    assert_eq!(response2.jsonrpc, "2.0");
    assert!(response1.result.is_some());
    assert!(response2.result.is_some());
}
