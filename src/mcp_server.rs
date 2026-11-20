//! The MCP server: request and result types, the [`FileScannerMcp`] handler and
//! the `ServerHandler` implementation served by the SDK on every transport.
//!
//! Layout (see the module list below): shared state, output budget and path
//! policy live in submodules; each `tools_*` submodule registers one group of
//! tools with `#[tool_router]`, and `FileScannerMcp::new()` sums the routers.

use anyhow::Result;
use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{Implementation, ProtocolVersion, ServerCapabilities, ServerConfig},
    tool_handler, ServerHandler,
};
use std::sync::Arc;

pub mod output;
pub mod paths;
pub mod state;
pub(crate) mod tools_analyze;
pub(crate) mod tools_documents;
pub(crate) mod tools_formats;
pub(crate) mod tools_java;
pub(crate) mod tools_packages;
pub(crate) mod tools_services;
pub(crate) mod tools_yara;

#[cfg(test)]
mod test_support;

// The binary compiles this module too and does not use every re-export.
#[allow(unused_imports)]
pub use tools_analyze::{
    FileAnalysisRequest, FileAnalysisResult, LlmFileAnalysisRequest, LlmFileAnalysisResult,
    YaraIndicators, MAX_HEX_DUMP_BYTES,
};
#[allow(unused_imports)]
pub use tools_java::JavaAnalysisRequest;
#[allow(unused_imports)]
pub use tools_packages::{NpmAnalysisRequest, PythonAnalysisRequest};
#[allow(unused_imports)]
pub use tools_yara::{YaraScanRequest, YaraScanResult, MAX_YARA_FILE_BYTES};

// The binary compiles this module too and does not use every re-export.
#[allow(unused_imports)]
pub use state::{mark_section, SectionCache, ServerState, StateConfig};

// Re-export YARA types from threat_detection module
#[allow(unused_imports)]
pub use crate::threat_detection::{YaraFileMatch, YaraScanError};

/// The MCP handler.
///
/// Cloning is cheap (the router and the shared state are reference counted
/// inside), which is what the Streamable HTTP transport needs: it builds one
/// handler per session from a factory. Every clone shares one [`ServerState`].
#[derive(Debug, Clone)]
pub struct FileScannerMcp {
    pub(crate) tool_router: ToolRouter<Self>,
    pub(crate) state: Arc<ServerState>,
}

impl Default for FileScannerMcp {
    fn default() -> Self {
        Self::new()
    }
}

impl FileScannerMcp {
    /// A handler with its own default state (nothing is created until a tool
    /// needs it, so this works outside a Tokio runtime).
    pub fn new() -> Self {
        Self::with_state(Arc::new(ServerState::default()))
    }

    /// A handler sharing `state` with every other handler and the REST routes.
    pub fn with_state(state: Arc<ServerState>) -> Self {
        let router = Self::analyze_router()
            + Self::yara_router()
            + Self::java_router()
            + Self::packages_router()
            + Self::formats_router()
            + Self::documents_router()
            + Self::services_router();
        #[cfg(test)]
        let router = router + Self::test_support_router();
        let mut router = router;
        // The one place every tool definition passes: `tools/list` on stdio and
        // HTTP, the REST listing and the OpenAPI-facing definitions all read it.
        for route in router.map.values_mut() {
            let mut schema = (*route.attr.input_schema).clone();
            drop_numeric_formats(&mut schema);
            route.attr.input_schema = Arc::new(schema);
        }
        Self {
            tool_router: router,
            state,
        }
    }

    /// The shared state.
    pub const fn state(&self) -> &Arc<ServerState> {
        &self.state
    }

    /// Every tool definition, sorted by name: what `tools/list` returns.
    pub fn tool_definitions(&self) -> Vec<rmcp::model::Tool> {
        self.tool_router.list_all()
    }

    /// Under `--isolation bwrap`, the tool error that refuses a call of `tool`
    /// before it reads anything; `None` when the call may go on. Every tool
    /// wrapper asks first. Allowed: the tools that read only the server's own
    /// caches, and `analyze_file`, which refuses everything but its sandboxed
    /// metadata section itself. Without a sandbox nothing is refused.
    pub(crate) fn isolation_refusal(
        &self,
        tool: &str,
        args: &rmcp::model::JsonObject,
    ) -> Option<rmcp::model::CallToolResult> {
        self.state.sandbox()?;
        let allowed = match tool {
            "analyze_file" | "cache_status" | "cache_clear" | "string_details" => true,
            // With a file it extracts that file's strings in the server.
            "search_strings" => !args.contains_key("file_path"),
            _ => false,
        };
        (!allowed).then(|| output::tool_error(crate::isolation::refusal_text(tool)))
    }
}

/// Remove the `format` of every integer or number node of a tool's input
/// schema. The schema generator writes the Rust type there (`uint`, `uint64`,
/// `int64`, `double` ...), which JSON Schema does not define: strict
/// validators, and model APIs that accept a fixed list of formats, refuse them.
/// `minimum`, `maximum`, `type` and the rest of the node stay as they are.
fn drop_numeric_formats(node: &mut serde_json::Map<String, serde_json::Value>) {
    use serde_json::Value;
    let numeric = match node.get("type") {
        Some(Value::String(t)) => t == "integer" || t == "number",
        Some(Value::Array(types)) => types
            .iter()
            .any(|t| matches!(t.as_str(), Some("integer" | "number"))),
        _ => false,
    };
    if numeric {
        node.remove("format");
    }
    for value in node.values_mut() {
        drop_numeric_formats_in(value);
    }
}

fn drop_numeric_formats_in(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => drop_numeric_formats(map),
        serde_json::Value::Array(items) => items.iter_mut().for_each(drop_numeric_formats_in),
        _ => {}
    }
}

/// What the server tells a client at `initialize` (and `server/discover`).
pub const INSTRUCTIONS: &str = "File Scanner is a static analyzer for files and packages (nothing is executed). \
Call analyze_file first with only a path: it returns a small overview (type, hashes, headline facts, \
the most telling strings) and `next_steps` naming the right next call. Then dig in: analyze_file with \
`sections: [...]` returns a summary of those sections, and query_analysis pages and filters their lists \
(strings, symbols, imports, functions, findings ...). `all: true` runs every analysis once, still \
answers with summaries, and makes the later query_analysis and disassemble calls on that \
file fast (answered from the cache; cache_status and cache_clear show and empty it). Other tools: \
disassemble (function list, then one function's instructions), read_hex (raw bytes at any offset), \
compare_files, search_strings and string_details (strings across files), llm_analyze_file (a compact \
digest and draft YARA rule) and yara_scan_file (test a rule). By file kind: analyze_document (PDF, \
Office), analyze_script, inspect_archive (zip, tar, rar, 7z), analyze_java_file, \
analyze_npm_package and analyze_python_package. Pass absolute paths (a leading ~/ is expanded). \
Every result is capped at max_output_bytes (default 80000, ceiling 400000): lists come back in \
pages (`returned`, `next_offset`, `total`; repeat the call with `offset`), anything cut is listed \
under `truncated`, and a failed call returns isError with a message that says what to fix.";

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FileScannerMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(
                Implementation::new("file-scanner", env!("CARGO_PKG_VERSION"))
                    .with_title("File Scanner"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

// Public functions for CLI usage
pub async fn analyze_file_llm(request: LlmFileAnalysisRequest) -> Result<LlmFileAnalysisResult> {
    let handler = FileScannerMcp::new();
    let result = handler
        .llm_analyze_file(request)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(result.0)
}

pub async fn yara_scan_files(request: YaraScanRequest) -> Result<YaraScanResult> {
    let handler = FileScannerMcp::new();
    let result = handler
        .yara_scan_file(request)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(result.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_handler_get_info() {
        let mcp = FileScannerMcp::new();
        let info = mcp.get_info();

        assert_eq!(info.server_info.name, "file-scanner");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert!(info.instructions.is_some());
        assert!(info.capabilities.tools.is_some());
    }

    /// The instructions name every tool, and the session-opening advice the
    /// transport tests rely on, and stay short (a model reads them every session).
    #[test]
    fn the_instructions_name_every_tool_and_stay_short() {
        let mcp = FileScannerMcp::new();
        for tool in mcp.tool_definitions() {
            if tool.name == "test_panic" || tool.name == "sample" {
                continue;
            }
            assert!(
                INSTRUCTIONS.contains(tool.name.as_ref()),
                "the instructions do not mention {}",
                tool.name
            );
        }
        for phrase in [
            "analyze_file first",
            "absolute",
            "all: true",
            "query_analysis",
            "max_output_bytes",
            "next_offset",
        ] {
            assert!(INSTRUCTIONS.contains(phrase), "missing: {phrase}");
        }
        assert!(INSTRUCTIONS.len() < 2_600, "{} bytes", INSTRUCTIONS.len());
    }

    /// Under `--isolation bwrap` every tool that would analyze a file in the
    /// server is refused through the router (the path MCP and REST share),
    /// whatever its arguments; only the cache-only tools and analyze_file's
    /// sandboxed metadata section get past the gate. A new tool fails this
    /// test until it is gated.
    #[tokio::test]
    async fn isolation_refuses_every_in_process_analysis_through_the_router() {
        use crate::mcp_transport::rest::{call_tool_direct, ToolCallParams};
        use serde_json::{json, Value};

        let dir = tempfile::tempdir().unwrap();
        let sample = dir.path().join("sample.bin");
        std::fs::write(&sample, b"\x7FELF\x02\x01\x01 benign bytes").unwrap();
        let path = sample.to_string_lossy().into_owned();
        let state = Arc::new(ServerState::new(StateConfig {
            cache_dir: dir.path().join("cache"),
            sandbox: Some(Arc::new(crate::isolation::Sandbox::unverified_for_tests(
                dir.path().join("no-bwrap-here"),
                dir.path(),
            ))),
            ..StateConfig::default()
        }));
        let mcp = FileScannerMcp::with_state(state);
        let call = |name: &str, arguments: Value| {
            let params = ToolCallParams {
                name: name.to_string(),
                arguments: arguments.as_object().cloned().unwrap_or_default(),
            };
            let mcp = mcp.clone();
            async move { call_tool_direct(&mcp, params).await.unwrap() }
        };
        let text = |reply: &Value| {
            reply["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string()
        };

        let cache_only = [
            "cache_status",
            "cache_clear",
            "string_details",
            "test_panic",
        ];
        for tool in mcp.tool_definitions() {
            let name = tool.name.to_string();
            if cache_only.contains(&name.as_str()) || name == "analyze_file" {
                continue;
            }
            let reply = call(&name, json!({"file_path": path, "package_path": path})).await;
            assert_eq!(reply["isError"], true, "{name}: {reply}");
            assert!(
                text(&reply).starts_with(&format!("{name} is refused")),
                "{name}: {reply}"
            );
        }

        // search_strings over the server's index only is a cache read.
        let reply = call("search_strings", json!({"query": "x"})).await;
        assert!(!text(&reply).contains("is refused"), "{reply}");
        let reply = call("cache_status", json!({})).await;
        assert_ne!(reply["isError"], true, "{reply}");

        // analyze_file: everything but the metadata section is refused...
        for arguments in [
            json!({"file_path": path}),
            json!({"file_path": path, "all": true}),
            json!({"file_path": path, "sections": ["metadata", "strings"]}),
            json!({"file_path": path, "hashes": true}),
            json!({"file_path": dir.path().to_string_lossy()}),
        ] {
            let reply = call("analyze_file", arguments.clone()).await;
            assert_eq!(reply["isError"], true, "{arguments}: {reply}");
            assert!(text(&reply).contains("is refused"), "{arguments}: {reply}");
        }
        // ...and the metadata section goes to the sandbox, here one that
        // cannot start: a typed failure, never an in-process answer. (Off
        // Linux no root can be opened, so admission refuses it first.)
        for arguments in [
            json!({"file_path": path, "sections": ["metadata"]}),
            json!({"file_path": path, "metadata": true}),
        ] {
            let reply = call("analyze_file", arguments.clone()).await;
            assert_eq!(reply["isError"], true, "{arguments}: {reply}");
            let message = text(&reply);
            if cfg!(target_os = "linux") {
                assert!(message.contains("cannot start the sandbox"), "{message}");
            } else {
                assert!(
                    message.contains("not spelled under an allowed root"),
                    "{message}"
                );
            }
            assert!(!message.contains("application/x-elf"), "{message}");
        }
        let reply = call(
            "analyze_file",
            json!({"file_path": dir.path().to_string_lossy(), "metadata": true}),
        )
        .await;
        assert_eq!(reply["isError"], true, "{reply}");
        if cfg!(target_os = "linux") {
            assert!(
                text(&reply).starts_with("analyze_file on a directory is refused"),
                "{reply}"
            );
        }
    }
}
