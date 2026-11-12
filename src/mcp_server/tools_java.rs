//! `analyze_java_file`.

use std::path::PathBuf;

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};

use crate::java_analysis::{analyze_class_file, analyze_java_archive, JavaAnalysisResult};

use super::{
    output::{input_schema_with_budget, parse_request, respond_result, tool_error},
    paths::Expect,
    FileScannerMcp,
};

const ANALYZE_JAVA_DESCRIPTION: &str = "Analyze Java archives (JAR/WAR/EAR/APK/AAR) and class \
files. Pass an absolute path to one archive or .class file; call analyze_file first if you are \
unsure what the file is. Results are compact JSON capped at `max_output_bytes` (default 80000, \
ceiling 400000); cut lists are reported under `truncated`.";

#[tool_router(router = java_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "analyze_java_file",
        title = "Analyze Java file",
        description = ANALYZE_JAVA_DESCRIPTION,
        input_schema = input_schema_with_budget::<JavaAnalysisRequest>(),
        annotations(
            title = "Analyze Java file",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_java_file_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let (mut request, budget, _raw) = match parse_request::<JavaAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let path = match self
            .state
            .resolve_path(&request.file_path, "File", Expect::File)
        {
            Ok(path) => path,
            Err(message) => return Ok(tool_error(message)),
        };
        request.file_path = path.to_string_lossy().into_owned();

        let analyzer = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("analyze_java_file", move || {
                runtime
                    .block_on(analyzer.analyze_java_file(request))
                    .map(|json| json.0)
            })
            .await;
        Ok(respond_result(outcome, budget))
    }
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavaAnalysisRequest {
    #[schemars(
        description = "Absolute path of the Java file to analyze (JAR/WAR/EAR/APK/AAR/CLASS)"
    )]
    pub file_path: String,
}

impl FileScannerMcp {
    pub async fn analyze_java_file(
        &self,
        request: JavaAnalysisRequest,
    ) -> Result<Json<JavaAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);

        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }

        // Determine if it's a Java archive or class file
        let is_class_file = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.to_lowercase() == "class");

        let analysis_result = if is_class_file {
            analyze_class_file(&path).map_err(|e| format!("{e:#}"))?
        } else {
            analyze_java_archive(&path).map_err(|e| {
                format!(
                    "Not a Java archive or class file: {e:#}. Pass a .jar, .war, .ear, .apk or \
                     .aar archive or a .class file."
                )
            })?
        };

        Ok(Json(analysis_result))
    }
}
