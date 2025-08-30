use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::Value;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use crate::mcp::handler::McpHandler;
use crate::mcp::transport::common::{handle_jsonrpc_request, JsonRpcRequest, JsonRpcResponse};

pub struct HttpTransport {
    handler: McpHandler,
    port: u16,
}

impl HttpTransport {
    pub fn new(handler: McpHandler, port: u16) -> Self {
        Self { handler, port }
    }

    pub async fn run(self) -> Result<()> {
        use rmcp::ServerHandler;

        let info = self.handler.get_info();
        eprintln!("MCP HTTP Server starting: {}", info.server_info.name);
        eprintln!("Version: {}", info.server_info.version);
        eprintln!("Protocol: {}", info.protocol_version);
        eprintln!("Listening on: http://0.0.0.0:{}", self.port);
        eprintln!("MCP endpoint: http://0.0.0.0:{}/mcp", self.port);
        eprintln!(
            "Use with: npx @modelcontextprotocol/inspector http://localhost:{}/mcp",
            self.port
        );

        let handler = Arc::new(self.handler);

        let app = Router::new()
            .route("/health", get(health_check))
            .route("/mcp", post(mcp_handler))
            .layer(ServiceBuilder::new().layer(CorsLayer::permissive()))
            .with_state(handler);

        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

async fn health_check() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "file-scanner-mcp",
        "transport": "http"
    }))
}

async fn mcp_handler(
    State(handler): State<Arc<McpHandler>>,
    _headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Result<Json<JsonRpcResponse>, (StatusCode, Json<JsonRpcResponse>)> {
    // Log the request for debugging
    eprintln!("MCP HTTP Request: {} {}", request.method, request.jsonrpc);

    let response = handle_jsonrpc_request(&handler, request).await;

    // Return the response
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        let value = response.0;
        assert_eq!(value["status"], "ok");
        assert_eq!(value["service"], "file-scanner-mcp");
        assert_eq!(value["transport"], "http");
    }

    #[tokio::test]
    async fn test_mcp_handler() {
        let handler = McpHandler::new(None, None);
        let handler = Arc::new(handler);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };

        let headers = HeaderMap::new();
        let result = mcp_handler(State(handler), headers, Json(request)).await;

        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
    }
}
