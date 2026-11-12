//! `yara_scan_file` and the YARA rule suggestion used by `llm_analyze_file`.

use std::{path::PathBuf, time::Instant};

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};

use super::{
    output::{input_schema_with_budget, parse_request, respond, tool_error},
    paths::Expect,
    tools_analyze::LlmFileAnalysisResult,
    FileScannerMcp,
};

const YARA_SCAN_DESCRIPTION: &str = "Scan files or directories with custom YARA rules. Pass the \
rule text in `yara_rule` and an absolute file or directory in `path` (directories are scanned \
recursively unless `recursive` is false). A rule that does not compile is returned as an error \
that includes the compiler's message, so fix the rule and call again. Draft a rule with \
llm_analyze_file first. Results are compact JSON capped at `max_output_bytes` (default 80000, \
ceiling 400000); cut matches are listed under `truncated`.";

#[tool_router(router = yara_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "yara_scan_file",
        title = "Scan with YARA",
        description = YARA_SCAN_DESCRIPTION,
        input_schema = input_schema_with_budget::<YaraScanRequest>(),
        annotations(
            title = "Scan with YARA",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn yara_scan_file_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        Ok(self.run_yara_scan(args).await)
    }
}

impl FileScannerMcp {
    /// The `yara_scan_file` tool body.
    pub(crate) async fn run_yara_scan(&self, args: JsonObject) -> CallToolResult {
        let started = Instant::now();
        let (mut request, budget, raw_args) = match parse_request::<YaraScanRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return tool_error(message),
        };
        let raw_path = request.path.clone();
        let path = match self
            .state
            .resolve_path(&raw_path, "Path", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        // The scan reads what is inside a directory, so vet its members too.
        if let Err(message) = self
            .state
            .check_tree(&path, request.recursive.unwrap_or(true))
        {
            return tool_error(message);
        }
        request.path = path.to_string_lossy().into_owned();

        let analyzer = self.clone();
        let runtime = tokio::runtime::Handle::current();
        let outcome = self
            .state
            .run_blocking("yara_scan_file", move || {
                runtime.block_on(analyzer.yara_scan_file(request))
            })
            .await;
        let result = match outcome {
            Err(crash) => return tool_error(crash),
            Ok(Err(message)) => return tool_error(message),
            Ok(Ok(result)) => result.0,
        };
        let value = match serde_json::to_value(&result) {
            Ok(value) => value,
            Err(error) => return tool_error(format!("Could not serialize the result: {error}")),
        };
        self.state
            .record_yara_scan(&raw_args, &raw_path, &value, started)
            .await;
        respond(value, budget)
    }
}

/// Largest `max_file_size` a YARA scan accepts (each file is read into memory).
pub const MAX_YARA_FILE_BYTES: u64 = 100 * 1024 * 1024;

use crate::threat_detection::{YaraFileMatch, YaraScanError};

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraScanRequest {
    #[schemars(
        description = "Absolute path of the file or directory to scan (a leading ~/ is expanded)"
    )]
    pub path: String,

    #[schemars(description = "YARA rule content to use for scanning")]
    pub yara_rule: String,

    #[schemars(description = "If true, recursively scan directories (default: true)")]
    pub recursive: Option<bool>,

    #[schemars(description = "Maximum file size to scan in bytes (default: 100MB)")]
    pub max_file_size: Option<u64>,

    #[schemars(description = "Include detailed match information (default: true)")]
    pub detailed_matches: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct YaraScanResult {
    pub total_files_scanned: usize,
    pub total_matches: usize,
    pub scan_duration_ms: u64,
    pub matches: Vec<YaraFileMatch>,
    pub errors: Vec<YaraScanError>,
}

impl FileScannerMcp {
    pub async fn yara_scan_file(
        &self,
        request: YaraScanRequest,
    ) -> Result<Json<YaraScanResult>, String> {
        use crate::threat_detection::scan_with_custom_rule;
        use std::time::Instant;

        let start_time = Instant::now();
        let path = PathBuf::from(&request.path);

        if !path.exists() {
            return Err(format!("Path does not exist: {}", request.path));
        }

        let recursive = request.recursive.unwrap_or(true);
        let max_file_size = request.max_file_size.unwrap_or(MAX_YARA_FILE_BYTES);
        if max_file_size > MAX_YARA_FILE_BYTES {
            return Err(format!(
                "max_file_size {max_file_size} is above the limit of {MAX_YARA_FILE_BYTES} bytes \
                 (each scanned file is read into memory). Ask for at most {MAX_YARA_FILE_BYTES}."
            ));
        }
        let detailed_matches = request.detailed_matches.unwrap_or(true);

        // Scan files
        let scan_result = scan_with_custom_rule(
            &path,
            &request.yara_rule,
            recursive,
            max_file_size,
            detailed_matches,
        )
        .await
        .map_err(|e| format!("{e:#}"))?;

        let duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(Json(YaraScanResult {
            total_files_scanned: scan_result.total_files_scanned,
            total_matches: scan_result.total_matches,
            scan_duration_ms: duration_ms,
            matches: scan_result.matches,
            errors: scan_result.errors,
        }))
    }
}

/// Draft a YARA rule from an `llm_analyze_file` digest.
///
/// `Err` carries the reason no rule is offered. `llm_analyze_file` (in
/// `tools_analyze.rs`) calls this: keep the name and signature.
pub(crate) fn suggest_yara_rule(
    analysis: &LlmFileAnalysisResult,
    file_name: &str,
) -> Result<String, String> {
    let rule_name = file_name.replace(['/', '.', '-'], "_");
    let mut conditions = Vec::new();

    // Add file size condition
    conditions.push(format!("filesize == {}", analysis.file_size));

    // Add entropy condition if packed
    if let Some(entropy) = analysis.entropy {
        if entropy > 7.0 {
            conditions.push(format!("math.entropy(0, filesize) > {:.1}", entropy - 0.5));
        }
    }

    // Build string conditions
    let string_count = analysis.key_strings.len().min(5);
    if string_count > 0 {
        conditions.push(format!("{} of ($s*)", string_count.div_ceil(2)));
    }

    // Add hex pattern conditions
    if !analysis.hex_patterns.is_empty() {
        conditions.push("$header at 0".to_string());
    }

    // Build the rule
    let mut rule = format!("rule {rule_name} {{\n");
    rule.push_str("    meta:\n");
    rule.push_str(&format!("        md5 = \"{}\"\n", analysis.md5));
    rule.push_str(&format!("        filesize = {}\n", analysis.file_size));

    rule.push_str("    strings:\n");

    // Add hex patterns
    if let Some(header) = analysis.hex_patterns.first() {
        rule.push_str(&format!("        $header = {{ {header} }}\n"));
    }

    // Add key strings
    for (i, s) in analysis.key_strings.iter().take(10).enumerate() {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        rule.push_str(&format!("        $s{} = \"{}\"\n", i + 1, escaped));
    }

    // Add condition
    rule.push_str("    condition:\n");
    rule.push_str(&format!("        {}\n", conditions.join(" and ")));
    rule.push_str("}\n");

    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_server::yara_scan_files;
    use std::{fs, io::Write};
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf), std::io::Error> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file.bin");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    #[tokio::test]
    async fn test_yara_scan_files_wrapper() {
        let content = b"this is a test";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let rule = r#"
rule TestRule {
    strings:
        $a = "test"
    condition:
        $a
}
"#
        .to_string();

        let request = YaraScanRequest {
            path: file_path.to_string_lossy().to_string(),
            yara_rule: rule,
            recursive: Some(false),
            max_file_size: None,
            detailed_matches: Some(true),
        };

        let result = yara_scan_files(request).await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.total_files_scanned, 1);
        assert!(scan.total_matches >= 1);
    }

    #[test]
    fn test_suggest_yara_rule() {
        let analysis = LlmFileAnalysisResult {
            md5: "abc123def456".to_string(),
            file_size: 1024,
            key_strings: vec![
                "suspicious_function".to_string(),
                "malware_string".to_string(),
                "http://evil.com".to_string(),
            ],
            hex_patterns: vec!["4D 5A 90 00".to_string()],
            imports: vec!["kernel32.dll".to_string()],
            opcodes: vec!["E8 00 00 00".to_string()],
            entropy: Some(7.2),
            yara_rule_suggestion: None,
        };

        let yara_rule = suggest_yara_rule(&analysis, "test_malware.exe").unwrap();

        assert!(yara_rule.contains("rule test_malware_exe"));
        assert!(yara_rule.contains("md5 = \"abc123def456\""));
        assert!(yara_rule.contains("filesize = 1024"));
        assert!(yara_rule.contains("$header = { 4D 5A 90 00 }"));
        assert!(yara_rule.contains("$s1 = \"suspicious_function\""));
        assert!(yara_rule.contains("filesize == 1024"));
        assert!(yara_rule.contains("math.entropy"));
    }
}
