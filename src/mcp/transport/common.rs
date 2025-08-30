use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::mcp::error::McpError;
use crate::mcp::handler::McpHandler;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl From<McpError> for JsonRpcError {
    fn from(err: McpError) -> Self {
        JsonRpcError {
            code: err.code,
            message: err.message,
            data: err.data,
        }
    }
}

#[derive(Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    pub arguments: HashMap<String, Value>,
}

/// Common JSON-RPC request handling
pub async fn handle_jsonrpc_request(
    handler: &McpHandler,
    request: JsonRpcRequest,
) -> JsonRpcResponse {
    use rmcp::ServerHandler;
    use serde_json::json;

    match request.method.as_str() {
        "initialize" => {
            let info = handler.get_info();
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": info.server_info,
                    "capabilities": info.capabilities
                })),
                error: None,
            }
        }
        "initialized" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: Some(json!({})),
            error: None,
        },
        "tools/list" => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: Some(json!({
                "tools": handler.list_tools()
            })),
            error: None,
        },
        "tools/call" => {
            if let Some(params) = request.params {
                match serde_json::from_value::<ToolCallParams>(params) {
                    Ok(tool_call) => match handler
                        .handle_tool_call(&tool_call.name, tool_call.arguments)
                        .await
                    {
                        Ok(result) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: Some(result),
                            error: None,
                        },
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: request.id,
                            result: None,
                            error: Some(e.into()),
                        },
                    },
                    Err(_) => JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: request.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32602,
                            message: "Invalid params".to_string(),
                            data: None,
                        }),
                    },
                }
            } else {
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: request.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32600,
                        message: "Invalid Request".to_string(),
                        data: None,
                    }),
                }
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: request.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: None,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_jsonrpc_request_serialization() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "test".to_string(),
            params: Some(json!({"key": "value"})),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request.jsonrpc, deserialized.jsonrpc);
        assert_eq!(request.id, deserialized.id);
        assert_eq!(request.method, deserialized.method);
        assert_eq!(request.params, deserialized.params);
    }

    #[test]
    fn test_jsonrpc_response_serialization() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            result: Some(json!({"status": "ok"})),
            error: None,
        };

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains("error"));

        let response_with_error = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: None,
            }),
        };

        let serialized_error = serde_json::to_string(&response_with_error).unwrap();
        assert!(!serialized_error.contains("result"));
    }

    #[test]
    fn test_mcp_error_to_jsonrpc_error() {
        let mcp_error = McpError::method_not_found("test_method");
        let jsonrpc_error: JsonRpcError = mcp_error.into();

        assert_eq!(jsonrpc_error.code, -32601);
        assert!(jsonrpc_error.message.contains("test_method"));
    }
}
