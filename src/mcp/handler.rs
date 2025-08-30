use rmcp::{
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    ServerHandler,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::cache::AnalysisCache;
use crate::mcp::error::{McpError, McpResult};
use crate::mcp::registry::ToolRegistry;
use crate::mcp::tools::*;
use crate::string_tracker_compat::StringTracker;

/// Main MCP handler that manages tools and requests
#[derive(Clone)]
pub struct McpHandler {
    registry: ToolRegistry,
    cache: Option<Arc<AnalysisCache>>,
    string_tracker: Option<Arc<StringTracker>>,
}

impl McpHandler {
    pub fn new(
        cache: Option<Arc<AnalysisCache>>,
        string_tracker: Option<Arc<StringTracker>>,
    ) -> Self {
        // Build tool registry
        let registry = ToolRegistry::builder()
            .register(AnalyzeFileTool)
            .register(LlmAnalyzeTool)
            .register(YaraScanTool)
            .register(JavaAnalyzeTool)
            .register(NpmAnalyzeTool)
            .register(PythonAnalyzeTool)
            .build();

        Self {
            registry,
            cache,
            string_tracker,
        }
    }

    /// Handle a tool call
    pub async fn handle_tool_call(
        &self,
        name: &str,
        arguments: HashMap<String, Value>,
    ) -> McpResult<Value> {
        let tool = self
            .registry
            .get(name)
            .ok_or_else(|| McpError::method_not_found(name))?;

        tool.execute(arguments).await
    }

    /// Get list of available tools
    pub fn list_tools(&self) -> Vec<Value> {
        self.registry
            .list()
            .into_iter()
            .map(|metadata| {
                json!({
                    "name": metadata.name,
                    "description": metadata.description,
                    "inputSchema": metadata.input_schema,
                })
            })
            .collect()
    }
}

impl ServerHandler for McpHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            server_info: Implementation {
                name: "file-scanner".into(),
                version: "0.1.0".into(),
            },
            instructions: Some("A comprehensive file scanner with analyze_file, llm_analyze_file, yara_scan_file, analyze_java_file, analyze_npm_package, and analyze_python_package tools.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_handler() -> McpHandler {
        McpHandler::new(None, None)
    }

    #[test]
    fn test_handler_creation() {
        let handler = create_test_handler();
        let tools = handler.list_tools();
        assert_eq!(tools.len(), 6);
    }

    #[test]
    fn test_tool_listing() {
        let handler = create_test_handler();
        let tools = handler.list_tools();

        let tool_names: Vec<String> = tools
            .iter()
            .filter_map(|t| {
                t.get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();

        assert!(tool_names.contains(&"analyze_file".to_string()));
        assert!(tool_names.contains(&"llm_analyze_file".to_string()));
        assert!(tool_names.contains(&"yara_scan_file".to_string()));
        assert!(tool_names.contains(&"analyze_java_file".to_string()));
        assert!(tool_names.contains(&"analyze_npm_package".to_string()));
        assert!(tool_names.contains(&"analyze_python_package".to_string()));
    }

    #[tokio::test]
    async fn test_invalid_tool_call() {
        let handler = create_test_handler();
        let result = handler
            .handle_tool_call("nonexistent_tool", HashMap::new())
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.contains("Method not found"));
        }
    }

    #[test]
    fn test_server_info() {
        let handler = create_test_handler();
        let info = handler.get_info();

        assert_eq!(info.server_info.name, "file-scanner");
        assert_eq!(info.server_info.version, "0.1.0");
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_handler_with_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache = Arc::new(AnalysisCache::new(temp_dir.path()).unwrap());
        let string_tracker = Arc::new(StringTracker::new());

        let handler = McpHandler::new(Some(cache), Some(string_tracker));
        let tools = handler.list_tools();
        assert_eq!(tools.len(), 6);
    }
}
