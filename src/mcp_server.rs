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
}

/// What the server tells a client at `initialize` (and `server/discover`).
pub const INSTRUCTIONS: &str = "File Scanner analyzes files and packages for security work. \
Call analyze_file first and pass the flags for what you need (metadata and hashes are a cheap \
start; `all: true` runs every analysis, and later calls for single sections on the same file are \
answered from the cache), then dig in with the other tools: llm_analyze_file for a compact digest and a draft \
YARA rule, yara_scan_file to test a rule against a file or directory, analyze_java_file for \
JAR/WAR/EAR/APK/AAR/CLASS files, analyze_npm_package and analyze_python_package for packages. \
Always pass absolute paths (a leading ~/ is expanded; relative paths depend on the server's \
working directory). Every result is compact JSON capped at max_output_bytes (default 80000, \
ceiling 400000); anything cut is listed under 'truncated' - ask for a narrower view instead of \
raising the cap. A failed call returns isError with a message that says what to fix.";

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
}
