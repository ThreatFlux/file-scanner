use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Json,
    },
    routing::{get, post},
    Router,
};
use futures_util::stream::{self, Stream, StreamExt};
use serde_json::Value;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;

use crate::mcp::handler::McpHandler;
use crate::mcp::transport::common::{handle_jsonrpc_request, JsonRpcRequest, JsonRpcResponse};

pub struct SseTransport {
    handler: McpHandler,
    port: u16,
}

impl SseTransport {
    pub fn new(handler: McpHandler, port: u16) -> Self {
        Self { handler, port }
    }

    pub async fn run(self) -> Result<()> {
        use rmcp::ServerHandler;

        let info = self.handler.get_info();
        eprintln!("MCP SSE Server starting: {}", info.server_info.name);
        eprintln!("Version: {}", info.server_info.version);
        eprintln!("Protocol: {}", info.protocol_version);
        eprintln!("Listening on: http://0.0.0.0:{}", self.port);
        eprintln!("SSE endpoint: http://0.0.0.0:{}/sse", self.port);
        eprintln!(
            "Use with: npx @modelcontextprotocol/inspector http://localhost:{}/sse",
            self.port
        );

        let handler = Arc::new(self.handler);

        let app = Router::new()
            .route("/health", get(health_check))
            .route("/sse", get(sse_handler))
            .route("/sse", post(sse_request_handler))
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
        "transport": "sse"
    }))
}

async fn sse_handler(
    State(handler): State<Arc<McpHandler>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    use rmcp::ServerHandler;

    eprintln!("SSE connection established");

    let info = handler.get_info();
    let init_event = Event::default().event("server_info").data(
        serde_json::to_string(&serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": info.server_info,
            "capabilities": info.capabilities
        }))
        .unwrap(),
    );

    let stream = stream::iter(vec![Ok(init_event)]).chain(
        stream::repeat_with(|| Ok(Event::default().event("ping").data("alive"))).then(
            |event| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                event
            },
        ),
    );

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn sse_request_handler(
    State(handler): State<Arc<McpHandler>>,
    Json(request): Json<JsonRpcRequest>,
) -> Result<Json<JsonRpcResponse>, (StatusCode, Json<JsonRpcResponse>)> {
    eprintln!("MCP SSE Request: {} {}", request.method, request.jsonrpc);

    let response = handle_jsonrpc_request(&handler, request).await;

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
        assert_eq!(value["transport"], "sse");
    }

    #[tokio::test]
    async fn test_sse_request_handler() {
        let handler = McpHandler::new(None, None);
        let handler = Arc::new(handler);

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };

        let result = sse_request_handler(State(handler), Json(request)).await;

        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
    }
}
