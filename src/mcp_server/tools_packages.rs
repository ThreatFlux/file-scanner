//! `analyze_npm_package` and `analyze_python_package`.

use std::path::PathBuf;

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};

use crate::{
    npm_analysis::{analyze_npm_package, NpmPackageAnalysis},
    python_analysis::{analyze_python_package, PythonPackageAnalysis},
};

use super::{
    output::{input_schema_with_budget, parse_request, respond_result, tool_error},
    paths::Expect,
    FileScannerMcp,
};

const ANALYZE_NPM_DESCRIPTION: &str = "Analyze npm packages for vulnerabilities, malicious code, \
typosquatting, and supply chain attacks. Pass the absolute path of a .tgz file or of a directory \
that contains package.json. Call analyze_file on suspicious files inside the package first or \
afterwards for per-file detail, and yara_scan_file to test a rule against the package. Results are compact JSON capped at `max_output_bytes` (default \
80000, ceiling 400000); cut lists are reported under `truncated`.";

const ANALYZE_PYTHON_DESCRIPTION: &str = "Analyze Python packages for vulnerabilities, malicious \
code, typosquatting, and supply chain attacks. Pass the absolute path of a .whl, .tar.gz or .zip \
file, or of a directory with setup.py or pyproject.toml. Call analyze_file on suspicious files \
inside the package first or afterwards for per-file detail, and yara_scan_file to test a rule \
against the package. Results are compact JSON capped at \
`max_output_bytes` (default 80000, ceiling 400000); cut lists are reported under `truncated`.";

#[tool_router(router = packages_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "analyze_npm_package",
        title = "Analyze npm package",
        description = ANALYZE_NPM_DESCRIPTION,
        input_schema = input_schema_with_budget::<NpmAnalysisRequest>(),
        annotations(
            title = "Analyze npm package",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_npm_package_tool(
        &self,
        args: JsonObject,
    ) -> Result<CallToolResult, ErrorData> {
        let (mut request, budget, _raw) = match parse_request::<NpmAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let path = match self
            .state
            .resolve_path(&request.package_path, "Path", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return Ok(tool_error(message)),
        };
        if let Err(message) = self.state.check_tree(&path, true) {
            return Ok(tool_error(message));
        }
        request.package_path = path.to_string_lossy().into_owned();

        let analyzer = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("analyze_npm_package", move || {
                runtime
                    .block_on(analyzer.analyze_npm_package(request))
                    .map(|json| json.0)
            })
            .await;
        Ok(respond_result(outcome, budget))
    }

    #[tool(
        name = "analyze_python_package",
        title = "Analyze Python package",
        description = ANALYZE_PYTHON_DESCRIPTION,
        input_schema = input_schema_with_budget::<PythonAnalysisRequest>(),
        annotations(
            title = "Analyze Python package",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_python_package_tool(
        &self,
        args: JsonObject,
    ) -> Result<CallToolResult, ErrorData> {
        let (mut request, budget, _raw) = match parse_request::<PythonAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let path = match self
            .state
            .resolve_path(&request.package_path, "Path", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return Ok(tool_error(message)),
        };
        if let Err(message) = self.state.check_tree(&path, true) {
            return Ok(tool_error(message));
        }
        request.package_path = path.to_string_lossy().into_owned();

        let analyzer = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("analyze_python_package", move || {
                runtime
                    .block_on(analyzer.analyze_python_package(request))
                    .map(|json| json.0)
            })
            .await;
        Ok(respond_result(outcome, budget))
    }
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NpmAnalysisRequest {
    #[schemars(
        description = "Absolute path of the npm package (can be .tgz file or directory with package.json)"
    )]
    pub package_path: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonAnalysisRequest {
    #[schemars(
        description = "Absolute path of the Python package (can be .whl, .tar.gz, .zip file or directory with setup.py/pyproject.toml)"
    )]
    pub package_path: String,
}

impl FileScannerMcp {
    pub async fn analyze_npm_package(
        &self,
        request: NpmAnalysisRequest,
    ) -> Result<Json<NpmPackageAnalysis>, String> {
        let path = PathBuf::from(&request.package_path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.package_path));
        }

        let analysis_result = analyze_npm_package(&path).map_err(|e| format!("{e:#}"))?;

        Ok(Json(analysis_result))
    }

    pub async fn analyze_python_package(
        &self,
        request: PythonAnalysisRequest,
    ) -> Result<Json<PythonPackageAnalysis>, String> {
        let path = PathBuf::from(&request.package_path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.package_path));
        }

        let analysis_result = analyze_python_package(&path).map_err(|e| format!("{e:#}"))?;

        Ok(Json(analysis_result))
    }
}
