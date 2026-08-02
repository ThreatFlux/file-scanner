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
use serde_json::json;
use std::fs;
use tempfile::TempDir;

#[tokio::test]
async fn test_transport_creation() {
    let transport = McpTransportServer::new();
    // Just verify it can be created without panicking
    assert!(!std::ptr::addr_of!(transport).is_null());
}

#[tokio::test]
async fn test_jsonrpc_initialize() {
    let transport = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "initialize".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(1)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    if let Some(result) = response.result {
        assert!(result.get("protocolVersion").is_some());
        assert!(result.get("serverInfo").is_some());
        assert!(result.get("capabilities").is_some());
    }
}

#[tokio::test]
async fn test_jsonrpc_tools_list() {
    let transport = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: "tools/list".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(2)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    if let Some(result) = response.result {
        if let Some(tools) = result.get("tools") {
            assert!(tools.is_array());
            let tools_array = tools.as_array().unwrap();
            assert!(!tools_array.is_empty());

            // Check that analyze_file tool exists
            let has_analyze_tool = tools_array.iter().any(|tool| {
                if let Some(name) = tool.get("name") {
                    name.as_str() == Some("analyze_file")
                } else {
                    false
                }
            });
            assert!(has_analyze_tool);
        }
    }
}

#[tokio::test]
async fn test_jsonrpc_analyze_file_tool() {
    let transport = McpTransportServer::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"Hello, World!").unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(3)),
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

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(3)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());

    if let Some(result) = response.result {
        if let Some(content) = result.get("content") {
            assert!(content.is_array());
            let content_array = content.as_array().unwrap();
            assert!(!content_array.is_empty());

            // Check that we got some analysis data
            if let Some(first_result) = content_array.first() {
                if let Some(text_data) = first_result.get("text") {
                    let text_str = text_data.as_str().unwrap();
                    assert!(text_str.contains("file_path"));
                    assert!(text_str.contains("metadata"));
                    assert!(text_str.contains("hashes"));
                }
            }
        }
    }
}

#[tokio::test]
async fn test_jsonrpc_llm_analyze_file_tool() {
    let transport = McpTransportServer::new();
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.bin");
    // Create a small binary-like file
    let content = vec![0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]; // ELF header start
    fs::write(&test_file, &content).unwrap();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(4)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "llm_analyze_file",
            "arguments": {
                "file_path": test_file.to_str().unwrap(),
                "token_limit": 5000,
                "max_strings": 10
            }
        })),
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(4)));
    assert!(response.result.is_some());
    assert!(response.error.is_none());
}

#[tokio::test]
async fn test_jsonrpc_nonexistent_file() {
    let transport = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(5)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file",
            "arguments": {
                "file_path": "/nonexistent/file.txt",
                "metadata": true
            }
        })),
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(5)));
    // Should either have an error or a result indicating file not found
    assert!(response.result.is_some() || response.error.is_some());
}

#[tokio::test]
async fn test_jsonrpc_invalid_method() {
    let transport = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(6)),
        method: "invalid/method".to_string(),
        params: None,
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(6)));
    assert!(response.error.is_some());

    if let Some(error) = response.error {
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("Method not found"));
    }
}

#[tokio::test]
async fn test_jsonrpc_malformed_tool_call() {
    let transport = McpTransportServer::new();

    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(7)),
        method: "tools/call".to_string(),
        params: Some(json!({
            "name": "analyze_file"
            // Missing required arguments
        })),
    };

    let response = transport.handle_jsonrpc_request(request).await;

    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, Some(json!(7)));
    // Should have an error due to missing arguments
    assert!(response.error.is_some());
}
