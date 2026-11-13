//! `analyze_npm_package` and `analyze_python_package`.
//!
//! Both tools follow the overview-first rule: the default call returns a
//! summary (risk, what was scanned, counts, the advisory-data provenance and
//! the top findings). `section` selects a paged list (`findings`, `files`,
//! `dependencies`) or the install scripts (`scripts`). The full analysis is
//! cached by the SHA-256 of the package (a fingerprint for a directory), so
//! the drill-down calls slice the stored result and do not scan again.
//!
//! The tools are offline: they read local files and never download a package.

use std::path::{Path, PathBuf};

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    npm_analysis::{analyze_npm_package, NpmPackageAnalysis},
    package_scan::{looks_like_registry_spec, severity_rank},
    python_analysis::{analyze_python_package, PythonPackageAnalysis},
};

use super::{
    output::{input_schema_with_budget, page, parse_request, respond, tool_error, DEFAULT_LIMIT},
    paths::Expect,
    FileScannerMcp,
};

/// The source files both package tools scan, whatever the ecosystem (a `.py` inside an
/// npm package and a `.js` inside a Python package are scanned too).
macro_rules! scanned_files {
    () => {
        "Source files (JavaScript/TypeScript .js .mjs .cjs .jsx .ts .tsx .mts .cts, Python .py .pyw .pth, \
and scripts .sh .bash .zsh .cmd .bat .ps1, in every package; up to 400 files, 1 MiB each, 16 MiB in all)"
    };
}

const ANALYZE_NPM_DESCRIPTION: &str = concat!("Vet an npm package for malicious code, vulnerable \
dependencies and typosquatting. Offline: pass the absolute path of a LOCAL .tgz/.tar.gz (what \
`npm pack` writes; detected by content), an unpacked package directory, or a package-lock.json / \
npm-shrinkwrap.json (dependency list only). A registry name such as `express` or `lodash@4.17.4` \
is rejected: nothing is downloaded. ", scanned_files!(), " are scanned for download-and-execute (shell one-liners and Node/Python download-write-run code), eval of decoded payloads, credential and wallet \
access, exfiltration endpoints, miners, reverse shells and obfuscation, with file and line \
evidence; a file an install hook runs (`node scripts/setup.js`) counts as install-time code. A dependency on a release the table marks as malicious rates High or more; archive entries with `..`, absolute paths or links rate High. Vulnerability data is a SMALL OFFLINE TABLE (6 packages, newest advisory 2022): an empty \
vulnerability list does not mean a package is clean; every result states the table's source, date \
and size. The first call returns a summary. Then use `section` = findings (paged, worst first), \
files, dependencies (paged; `query` filters by name) or scripts to dig in. For one suspicious \
file call analyze_file or analyze_script on it; yara_scan_file needs the UNPACKED directory (on a .tgz, .whl or .zip it would scan the compressed bytes and find nothing). \
Results are compact JSON capped at `max_output_bytes` (default 80000, ceiling 400000); cut lists \
are reported under `truncated`.");

const ANALYZE_PYTHON_DESCRIPTION: &str = concat!("Vet a Python package for malicious code, vulnerable \
dependencies and typosquatting. Offline: pass the absolute path of a LOCAL wheel (.whl), sdist \
(.tar.gz/.tgz) or .zip (all detected by content), a source directory, a setup.py / pyproject.toml, \
or a dependency list (requirements.txt, poetry.lock). A PyPI name such as `requests` or \
`requests==2.5.0` is rejected: nothing is downloaded. ", scanned_files!(), " are scanned for download-and-execute (shell one-liners and Node/Python download-write-run code), exec of decoded payloads, credential and wallet \
access, exfiltration endpoints, miners, reverse shells and obfuscation, with file and line \
evidence; setup.py is checked for install-time behaviour. A dependency on a release the table marks as malicious rates High or more; archive entries with `..`, absolute paths or links rate High. Vulnerability data is a SMALL OFFLINE \
TABLE (7 packages, newest advisory 2023): an empty vulnerability list does not mean a package is \
clean; every result states the table's source, date and size. Version matching follows PEP 440 \
with normalised names; an unpinned requirement is unknown, not vulnerable. The first call returns \
a summary. Then use `section` = findings (paged, worst first), files, dependencies (paged; \
`query` filters by name) or scripts to dig in. For one suspicious file call analyze_file or \
analyze_script on it; yara_scan_file needs the UNPACKED directory (on a .tgz, .whl or .zip it would scan the compressed bytes and find nothing). Results are compact JSON \
capped at `max_output_bytes` (default 80000, ceiling 400000); cut lists are reported under \
`truncated`.");

/// Which part of the analysis a call returns.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema, PartialEq, Eq,
)]
#[serde(rename_all = "snake_case")]
pub enum PackageSection {
    /// Overview: risk, coverage, counts, top findings (default).
    #[default]
    Summary,
    /// Source findings with file and line, worst first (paged).
    Findings,
    /// Files in the package (paged).
    Files,
    /// Declared and locked dependencies with advisories (paged).
    Dependencies,
    /// Install scripts and setup behaviour.
    Scripts,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NpmAnalysisRequest {
    #[schemars(
        description = "Absolute path of a LOCAL npm package: a .tgz/.tar.gz, a directory with package.json, a package.json, or a package-lock.json. Registry names are not supported (offline)."
    )]
    pub package_path: String,
    #[serde(default)]
    #[schemars(
        description = "What to return: summary (default), findings, files, dependencies or scripts"
    )]
    pub section: Option<PackageSection>,
    #[serde(default)]
    #[schemars(
        description = "Substring filter: finding rule/file/evidence, file path, or dependency name (case-insensitive)"
    )]
    pub query: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "section=findings: lowest severity to return (Critical, High, Medium or Low)"
    )]
    pub min_severity: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "section=files: only files with findings; section=dependencies: only dependencies with advisories (default false)"
    )]
    pub only_flagged: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Number of list items to skip (default 0)")]
    pub offset: Option<usize>,
    #[serde(default)]
    #[schemars(description = "Number of list items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PythonAnalysisRequest {
    #[schemars(
        description = "Absolute path of a LOCAL Python package: a .whl, .tar.gz, .tgz or .zip, a directory with setup.py/pyproject.toml, or a requirements.txt / poetry.lock. PyPI names are not supported (offline)."
    )]
    pub package_path: String,
    #[serde(default)]
    #[schemars(
        description = "What to return: summary (default), findings, files, dependencies or scripts"
    )]
    pub section: Option<PackageSection>,
    #[serde(default)]
    #[schemars(
        description = "Substring filter: finding rule/file/evidence, file path, or dependency name (case-insensitive)"
    )]
    pub query: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "section=findings: lowest severity to return (Critical, High, Medium or Low)"
    )]
    pub min_severity: Option<String>,
    #[serde(default)]
    #[schemars(
        description = "section=files: only files with findings; section=dependencies: only dependencies with advisories (default false)"
    )]
    pub only_flagged: Option<bool>,
    #[serde(default)]
    #[schemars(description = "Number of list items to skip (default 0)")]
    pub offset: Option<usize>,
    #[serde(default)]
    #[schemars(description = "Number of list items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

/// The arguments the two requests share.
struct View {
    section: PackageSection,
    query: Option<String>,
    min_severity: Option<String>,
    only_flagged: bool,
    offset: usize,
    limit: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ecosystem {
    Npm,
    Python,
}

impl Ecosystem {
    const fn tool(self) -> &'static str {
        match self {
            Self::Npm => "analyze_npm_package",
            Self::Python => "analyze_python_package",
        }
    }

    const fn cache_key(self) -> &'static str {
        match self {
            Self::Npm => "package:npm:v2",
            Self::Python => "package:python:v2",
        }
    }

    fn registry_error(self, raw: &str) -> String {
        // A specifier such as `django>=4` or `lodash@^4` is quoted so a shell
        // does not read `>` as a redirect or `^`, `~` or `!` as its own.
        let spec = if raw.contains([
            '<', '>', '!', '~', '=', '^', ' ', '*', '|', '&', ';', '$', '(', ')',
        ]) {
            format!("'{}'", raw.replace('\'', "'\\''"))
        } else {
            raw.to_string()
        };
        match self {
            Self::Npm => format!(
                "'{raw}' looks like an npm registry name, not a path. This tool is offline and \
                 only analyzes local files; it never downloads packages. Run `npm pack {spec}` \
                 (it writes a .tgz in the current directory) and pass the absolute path of that \
                 .tgz, or pass an unpacked package directory, or a package-lock.json for a \
                 dependency list."
            ),
            Self::Python => format!(
                "'{raw}' looks like a PyPI name, not a path. This tool is offline and only \
                 analyzes local files; it never downloads packages. Run `pip download {spec} \
                 --no-deps -d <dir>` and pass the absolute path of the downloaded wheel or \
                 sdist, or pass a source directory, a requirements.txt or a poetry.lock for a \
                 dependency list."
            ),
        }
    }
}

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
        let (request, budget, _raw) = match parse_request::<NpmAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let view = View {
            section: request.section.unwrap_or_default(),
            query: request.query,
            min_severity: request.min_severity,
            only_flagged: request.only_flagged.unwrap_or(false),
            offset: request.offset.unwrap_or(0),
            limit: request.limit.unwrap_or(DEFAULT_LIMIT),
        };
        Ok(self
            .package_call(Ecosystem::Npm, &request.package_path, &view, budget)
            .await)
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
        let (request, budget, _raw) = match parse_request::<PythonAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let view = View {
            section: request.section.unwrap_or_default(),
            query: request.query,
            min_severity: request.min_severity,
            only_flagged: request.only_flagged.unwrap_or(false),
            offset: request.offset.unwrap_or(0),
            limit: request.limit.unwrap_or(DEFAULT_LIMIT),
        };
        Ok(self
            .package_call(Ecosystem::Python, &request.package_path, &view, budget)
            .await)
    }
}

impl FileScannerMcp {
    /// Shared body of the two tools.
    async fn package_call(
        &self,
        ecosystem: Ecosystem,
        raw_path: &str,
        view: &View,
        budget: usize,
    ) -> CallToolResult {
        if let Some(severity) = view.min_severity.as_deref() {
            if !matches!(
                severity.trim().to_ascii_lowercase().as_str(),
                "critical" | "high" | "medium" | "low"
            ) {
                return tool_error(format!(
                    "min_severity '{severity}' is not a severity. Use one of: critical, high, medium, low."
                ));
            }
        }
        if looks_like_registry_spec(raw_path) && !Path::new(raw_path.trim()).exists() {
            return tool_error(ecosystem.registry_error(raw_path.trim()));
        }
        let path = match self
            .state
            .resolve_path(raw_path, "Package", Expect::FileOrDir)
        {
            Ok(path) => path,
            Err(message) => return tool_error(message),
        };
        // A manifest file stands for its whole directory: the analysis reads
        // the sibling sources, so the cache key and the tree check cover them.
        let target = analysis_target(ecosystem, &path);
        if let Err(message) = self.state.check_tree(&target, true) {
            return tool_error(message);
        }

        // Identify the package so repeated calls are answered from the cache.
        let fingerprint_path = target.clone();
        let fingerprint = match self
            .state
            .run_blocking(ecosystem.tool(), move || fingerprint(&fingerprint_path))
            .await
        {
            Ok(Ok(fingerprint)) => fingerprint,
            Ok(Err(message)) | Err(message) => return tool_error(message),
        };

        let cache = self.state.section_cache();
        let (full, cache_state) = if let Some(hit) = cache.get(&fingerprint, ecosystem.cache_key())
        {
            (hit, "hit")
        } else {
            let analysis_path = path.clone();
            let outcome = self
                .state
                .run_blocking(ecosystem.tool(), move || {
                    run_analysis(ecosystem, &analysis_path)
                })
                .await;
            let value = match outcome {
                Ok(Ok(value)) => value,
                Ok(Err(message)) | Err(message) => return tool_error(message),
            };
            cache.put(&fingerprint, ecosystem.cache_key(), &value);
            (std::sync::Arc::new(value), "miss")
        };

        let mut result = build_view(ecosystem, &path, &full, view);
        // The byte budget may cut a page: `returned` and `next_offset` must then
        // describe the rows that were sent.
        if let Some(total) = result["total"].as_u64() {
            let offset = result["offset"].as_u64().unwrap_or(0) as usize;
            let effective = budget.clamp(
                crate::mcp_server::output::MIN_OUTPUT_BYTES,
                crate::mcp_server::output::MAX_OUTPUT_BYTES,
            );
            crate::mcp_server::output::fit_rows(
                &mut result,
                "items",
                effective,
                offset,
                total as usize,
            );
        }
        if let Some(object) = result.as_object_mut() {
            object.insert("cache".to_string(), json!(cache_state));
        }
        respond(result, budget)
    }

    /// Library-level entry: the complete npm analysis (no paging).
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

    /// Library-level entry: the complete Python analysis (no paging).
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

/// What the analysis really reads: the parent directory when the path is a
/// manifest file (`package.json`, `setup.py`, `setup.cfg`, `pyproject.toml`).
fn analysis_target(ecosystem: Ecosystem, path: &Path) -> PathBuf {
    if !path.is_file() {
        return path.to_path_buf();
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_manifest = match ecosystem {
        Ecosystem::Npm => name == "package.json",
        Ecosystem::Python => matches!(name.as_str(), "setup.py" | "setup.cfg" | "pyproject.toml"),
    };
    if is_manifest {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            return parent.to_path_buf();
        }
    }
    path.to_path_buf()
}

fn run_analysis(ecosystem: Ecosystem, path: &Path) -> Result<Value, String> {
    let value = match ecosystem {
        Ecosystem::Npm => {
            serde_json::to_value(analyze_npm_package(path).map_err(|e| format!("{e:#}"))?)
        }
        Ecosystem::Python => {
            serde_json::to_value(analyze_python_package(path).map_err(|e| format!("{e:#}"))?)
        }
    };
    value.map_err(|e| format!("Could not serialize the analysis: {e}"))
}

/// A stable identity for the package: the SHA-256 of a file, or a digest of
/// the names, sizes and modification times of the files of a directory.
fn fingerprint(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    /// Content of files up to this size is hashed, up to [`HASH_BUDGET`] bytes in all.
    const HASH_FILE_LIMIT: u64 = 2 * 1024 * 1024;
    const HASH_BUDGET: u64 = 128 * 1024 * 1024;

    let mut hasher = Sha256::new();
    if path.is_dir() {
        hasher.update(b"dir:");
        let mut hashed = 0u64;
        let walker = walkdir::WalkDir::new(path)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            // The directories the analysis does not enter are not read here either,
            // so the content-hashed set is the one the analysis reads.
            .filter_entry(|entry| {
                entry.depth() == 0
                    || !(entry.file_type().is_dir()
                        && crate::package_scan::SKIPPED_DIRS
                            .contains(&entry.file_name().to_string_lossy().as_ref()))
            });
        // Content is hashed only for what the analysis reads: manifests and the
        // shallowest sources (the same order package_scan reads them in). The rest
        // is covered by size and time, so a call on a big tree does not read it all.
        let mut manifests: Vec<std::path::PathBuf> = Vec::new();
        let mut sources: Vec<(usize, std::path::PathBuf)> = Vec::new();
        for entry in walker.filter_map(Result::ok).take(200_000) {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let modified = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            hasher.update(entry.path().to_string_lossy().as_bytes());
            hasher.update(metadata.len().to_le_bytes());
            hasher.update(modified.to_le_bytes());
            // The inode change time moves with every write and cannot be set back,
            // so for a source file it stands in for reading the content.
            #[cfg(unix)]
            let changed_at = {
                use std::os::unix::fs::MetadataExt as _;
                Some((metadata.ctime(), metadata.ctime_nsec()))
            };
            #[cfg(not(unix))]
            let changed_at: Option<(i64, i64)> = None;
            if let Some((secs, nanos)) = changed_at {
                hasher.update(secs.to_le_bytes());
                hasher.update(nanos.to_le_bytes());
            }
            // Size and time are not enough: an edit that keeps both would be served
            // from the cache.
            if metadata.len() > HASH_FILE_LIMIT {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            let is_manifest = matches!(
                name.as_ref(),
                "package.json"
                    | "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "setup.py"
                    | "setup.cfg"
                    | "pyproject.toml"
                    | "PKG-INFO"
                    | "METADATA"
                    | "poetry.lock"
            ) || (name.starts_with("requirements") && name.ends_with(".txt"));
            if is_manifest {
                manifests.push(entry.path().to_path_buf());
            } else if changed_at.is_none() && crate::package_scan::language_of(&name).is_some() {
                let relative = entry.path().strip_prefix(path).unwrap_or(entry.path());
                let depth = relative.to_string_lossy().matches('/').count();
                sources.push((depth, entry.path().to_path_buf()));
            }
        }
        sources.sort();
        sources.truncate(crate::package_scan::MAX_SCANNED_FILES);
        // The manifest the analysis reads is the shallowest one; in walk order
        // many nested manifests can sort before it and push it past the cap.
        manifests.sort_by_key(|file| {
            let relative = file.strip_prefix(path).unwrap_or(file);
            (relative.components().count(), file.clone())
        });
        for file in manifests
            .iter()
            .take(64)
            .chain(sources.iter().map(|(_, f)| f))
        {
            if hashed >= HASH_BUDGET {
                break;
            }
            if let Ok(bytes) = std::fs::read(file) {
                hashed += bytes.len() as u64;
                hasher.update(&bytes);
            }
        }
        hasher.update(path.to_string_lossy().as_bytes());
    } else {
        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buffer)
                .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

// ---------------------------------------------------------------------------
// Views over the cached analysis
// ---------------------------------------------------------------------------

fn text_of<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(needle)
}

fn build_view(ecosystem: Ecosystem, path: &Path, full: &Value, view: &View) -> Value {
    match view.section {
        PackageSection::Summary => summary(ecosystem, path, full),
        PackageSection::Findings => findings_page(full, view),
        PackageSection::Files => files_page(full, view),
        PackageSection::Dependencies => dependencies_page(full, view),
        PackageSection::Scripts => scripts_view(ecosystem, full),
    }
}

fn next_step(ecosystem: Ecosystem, path: &Path, section: &str, gives: &str) -> Value {
    json!({
        "tool": ecosystem.tool(),
        "arguments": {"package_path": path.to_string_lossy(), "section": section},
        "gives": gives,
    })
}

fn summary(ecosystem: Ecosystem, path: &Path, full: &Value) -> Value {
    let info = &full["package_info"];
    let indicators = &full["malicious_indicators"];
    let findings = full["source_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let deps = &full["dependencies"];
    let dep_summary = &deps["vulnerability_summary"];
    let direct = [
        "dependencies",
        "dev_dependencies",
        "peer_dependencies",
        "optional_dependencies",
        "install_requires",
        "setup_requires",
        "tests_require",
    ]
    .iter()
    .map(|key| deps[key].as_object().map_or(0, serde_json::Map::len))
    .sum::<usize>()
        + deps["extras_require"].as_object().map_or(0, |extras| {
            extras
                .values()
                .map(|group| group.as_object().map_or(0, serde_json::Map::len))
                .sum()
        });
    let locked = deps["locked_packages"].as_array().map(Vec::len);

    let mut by_severity = json!({"critical": 0, "high": 0, "medium": 0, "low": 0});
    for finding in &findings {
        let key = finding["severity"].as_str().unwrap_or("Low").to_lowercase();
        if let Some(count) = by_severity.get_mut(&key) {
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
    }
    let top: Vec<Value> = findings.iter().take(5).cloned().collect();

    let security = &full["security_analysis"];
    let mut package = json!({
        "name": info["name"],
        "version": info["version"],
        "description": info["description"],
        "license": info["license"],
    });
    if ecosystem == Ecosystem::Python {
        package["format"] = info["package_format"].clone();
    }

    let mut install = serde_json::Map::new();
    match ecosystem {
        Ecosystem::Npm => {
            for key in [
                "has_preinstall_script",
                "has_postinstall_script",
                "has_install_script",
            ] {
                install.insert(key.to_string(), security[key].clone());
            }
            let hooks: Vec<&String> = full["scripts_analysis"]["script_hooks"]
                .as_object()
                .map(|hooks| hooks.keys().collect())
                .unwrap_or_default();
            install.insert("hooks".to_string(), json!(hooks));
            install.insert(
                "dangerous_commands".to_string(),
                json!(full["scripts_analysis"]["dangerous_commands"]
                    .as_array()
                    .map_or(0, Vec::len)),
            );
        }
        Ecosystem::Python => {
            for key in ["has_setup_script", "has_install_script", "has_post_install"] {
                install.insert(key.to_string(), security[key].clone());
            }
            install.insert(
                "dangerous_operations".to_string(),
                json!(full["setup_analysis"]["dangerous_operations"]
                    .as_array()
                    .map_or(0, Vec::len)),
            );
        }
    }

    let mut vulnerable: Vec<Value> = dep_summary["vulnerable_packages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    vulnerable.truncate(10);
    let mut unresolved: Vec<Value> = dep_summary["unresolved_range_hits"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    unresolved.truncate(10);

    let similar: Vec<Value> = indicators["typosquatting_risk"]["similar_packages"]
        .as_array()
        .map(|list| list.iter().take(5).map(|p| p["name"].clone()).collect())
        .unwrap_or_default();

    let mut next_steps = Vec::new();
    if !findings.is_empty() {
        next_steps.push(next_step(
            ecosystem,
            path,
            "findings",
            "source findings with file, line and evidence, worst first",
        ));
    }
    if direct > 0 || locked.unwrap_or(0) > 0 {
        next_steps.push(next_step(
            ecosystem,
            path,
            "dependencies",
            "dependencies with advisories, versions and lock-file resolution",
        ));
    }
    if full["input"]["files_total"].as_u64().unwrap_or(0) > 0 {
        next_steps.push(next_step(
            ecosystem,
            path,
            "files",
            "file list with per-file findings",
        ));
    }
    next_steps.push(next_step(
        ecosystem,
        path,
        "scripts",
        "install scripts and setup behaviour",
    ));

    let mut out = json!({
        "package": package,
        "input": full["input"],
        "risk": {
            "level": indicators["risk_level"],
            "score": indicators["overall_risk_score"],
            "reasons": indicators["risk_reasons"],
        },
        "findings": {"total": findings.len(), "by_severity": by_severity, "top": top},
        "install_scripts": Value::Object(install),
        "dependencies": {
            "direct": direct,
            "locked": locked,
            "with_advisories": dep_summary["vulnerable_packages"].as_array().map_or(0, Vec::len),
            "advisories_by_severity": {
                "critical": dep_summary["critical_count"],
                "high": dep_summary["high_count"],
                "medium": dep_summary["medium_count"],
                "low": dep_summary["low_count"],
            },
            "vulnerable": vulnerable,
            "range_may_include_vulnerable": unresolved,
            "known_malicious_releases": dep_summary["malicious_releases"],
        },
        "package_advisories": deps["package_vulnerabilities"]
            .as_array()
            .map(|list| list.iter().map(|v| v["cve_id"].clone()).collect::<Vec<_>>())
            .unwrap_or_default(),
        "typosquatting": {
            "suspected": indicators["typosquatting_risk"]["is_potential_typosquatting"],
            "similar_to": similar,
            "name_patterns": indicators["typosquatting_risk"]["suspicious_name_patterns"],
        },
        "signals": {
            "obfuscation": security["obfuscation_detected"],
            "crypto_mining": security["crypto_mining_indicators"],
            "data_exfiltration": security["data_exfiltration_risk"],
            "dependency_confusion": indicators["dependency_confusion_risk"],
        },
        "advisory_data": deps["vulnerability_db"],
        "next_steps": next_steps,
    });
    // A clean summary of a package whose content was not scanned must not read as clean.
    if full["input"]["content_scanned"] == json!(false) {
        out["warning"] = json!(
            "Only the dependency list was examined. No source files were scanned, so this says nothing about malicious code."
        );
    }
    out
}

fn findings_page(full: &Value, view: &View) -> Value {
    let floor = view
        .min_severity
        .as_deref()
        .map_or(0, |s| severity_rank(&capitalise(s.trim())));
    let needle = view.query.as_deref().map(str::to_lowercase);
    let rows: Vec<&Value> = full["source_findings"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|f| severity_rank(f["severity"].as_str().unwrap_or("")) >= floor)
                .filter(|f| {
                    needle.as_deref().is_none_or(|n| {
                        ["rule", "file", "evidence", "category"]
                            .iter()
                            .any(|key| contains_ci(f[key].as_str().unwrap_or(""), n))
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = page(&rows, view.offset, view.limit);
    let indicators = &full["malicious_indicators"];
    let mut signals = serde_json::Map::new();
    for key in [
        "known_malicious_patterns",
        "code_injection_patterns",
        "backdoor_indicators",
    ] {
        if let Some(list) = indicators[key].as_array() {
            if !list.is_empty() {
                signals.insert(
                    key.to_string(),
                    Value::Array(list.iter().take(20).cloned().collect()),
                );
            }
        }
    }
    if let Some(list) = full["security_analysis"]["suspicious_scripts"].as_array() {
        if !list.is_empty() {
            signals.insert(
                "suspicious_scripts".to_string(),
                Value::Array(
                    list.iter()
                        .take(20)
                        .map(|s| {
                            json!({
                                "script_name": s["script_name"],
                                "risk_indicators": s["risk_indicators"],
                                "external_commands": s["external_commands"],
                            })
                        })
                        .collect(),
                ),
            );
        }
    }
    if let Some(object) = out.as_object_mut() {
        object.insert("section".to_string(), json!("findings"));
        if !signals.is_empty() {
            object.insert("other_signals".to_string(), Value::Object(signals));
        }
    }
    out
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
    })
}

fn files_page(full: &Value, view: &View) -> Value {
    let needle = view.query.as_deref().map(str::to_lowercase);
    let rows: Vec<Value> = full["files_analysis"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter(|f| {
                    needle
                        .as_deref()
                        .is_none_or(|n| contains_ci(f["file_path"].as_str().unwrap_or(""), n))
                })
                .filter(|f| {
                    !view.only_flagged
                        || f["suspicious_content"]
                            .as_array()
                            .is_some_and(|list| !list.is_empty())
                })
                .map(|f| {
                    let flagged = f["suspicious_content"].as_array().map_or(0, Vec::len);
                    // Entropy and obfuscation score exist only for files that were read.
                    let scanned = f["source_scanned"].as_bool().unwrap_or(false);
                    json!({
                        "path": f["file_path"],
                        "type": f["file_type"],
                        "size": f["size"],
                        "source_scanned": scanned,
                        "entropy": if scanned { f["entropy"].clone() } else { Value::Null },
                        "obfuscation_score": if scanned { f["obfuscation_score"].clone() } else { Value::Null },
                        "findings": if flagged > 0 { json!(flagged) } else { Value::Null },
                        "rules": f["suspicious_content"].as_array().filter(|l| !l.is_empty()).map(|l| l.iter().take(5).cloned().collect::<Vec<_>>()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = page(&rows, view.offset, view.limit);
    if let Some(object) = out.as_object_mut() {
        object.insert("section".to_string(), json!("files"));
        object.insert("scanned".to_string(), full["input"].clone());
    }
    out
}

fn dependencies_page(full: &Value, view: &View) -> Value {
    let deps = &full["dependencies"];
    let needle = view.query.as_deref().map(str::to_lowercase);
    let mut rows: Vec<Value> = Vec::new();
    let mut direct_names = std::collections::HashSet::new();

    let mut push_group = |kind: &str, group: &Value, rows: &mut Vec<Value>| {
        let Some(map) = group.as_object() else { return };
        for (name, details) in map {
            direct_names.insert(name.to_lowercase().replace(['_', '.'], "-"));
            rows.push(json!({
                "name": name,
                "kind": kind,
                "spec": details["version_spec"],
                "direct_reference": if details["is_git"] == json!(true) {
                    json!("git")
                } else if details["is_url"] == json!(true) {
                    json!("url or path")
                } else {
                    Value::Null
                },
                "resolved": details["resolved_version"],
                "known_malicious_release": malicious_flag(details).then_some(true),
                "advisories": advisories(&details["vulnerabilities"]),
                "range_may_include": details["range_floor_advisories"].as_array().filter(|l| !l.is_empty()),
            }));
        }
    };
    for kind in [
        "dependencies",
        "dev_dependencies",
        "peer_dependencies",
        "optional_dependencies",
        "install_requires",
        "setup_requires",
        "tests_require",
    ] {
        push_group(kind, &deps[kind], &mut rows);
    }
    if let Some(extras) = deps["extras_require"].as_object() {
        for (extra, group) in extras {
            push_group(&format!("extra:{extra}"), group, &mut rows);
        }
    }
    if let Some(locked) = deps["locked_packages"].as_array() {
        for package in locked {
            let name = package["name"].as_str().unwrap_or("");
            if direct_names.contains(&name.to_lowercase().replace(['_', '.'], "-")) {
                continue;
            }
            let dev = package["dev"].as_bool().unwrap_or(false);
            rows.push(json!({
                "name": name,
                "kind": if dev { "locked-dev" } else { "locked" },
                "resolved": package["version"],
                "known_malicious_release": malicious_flag(package).then_some(true),
                "advisories": advisories(&package["vulnerabilities"]),
            }));
        }
    }

    let flagged = |row: &Value| {
        row["advisories"].as_array().is_some_and(|l| !l.is_empty())
            || row["range_may_include"]
                .as_array()
                .is_some_and(|l| !l.is_empty())
    };
    rows.retain(|row| {
        needle
            .as_deref()
            .is_none_or(|n| contains_ci(row["name"].as_str().unwrap_or(""), n))
            && (!view.only_flagged || flagged(row))
    });
    rows.sort_by(|a, b| {
        flagged(b)
            .cmp(&flagged(a))
            .then_with(|| a["name"].as_str().cmp(&b["name"].as_str()))
    });

    let mut out = page(&rows, view.offset, view.limit);
    if let Some(object) = out.as_object_mut() {
        object.insert("section".to_string(), json!("dependencies"));
        if deps["vulnerability_summary"]["malicious_releases"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
        {
            object.insert(
                "known_malicious_releases".to_string(),
                deps["vulnerability_summary"]["malicious_releases"].clone(),
            );
        }
        object.insert(
            "advisory_data".to_string(),
            deps["vulnerability_db"].clone(),
        );
        if let Some(own) = deps["package_vulnerabilities"].as_array() {
            if !own.is_empty() {
                object.insert("package_advisories".to_string(), advisories(&json!(own)));
            }
        }
    }
    out
}

/// A dependency that is a release or package the built-in table marks as malware: the
/// npm analysis sets the flag; the Python table writes a `KNOWN-` advisory entry.
fn malicious_flag(row: &Value) -> bool {
    row["known_malicious_release"] == json!(true)
        || row["vulnerabilities"].as_array().is_some_and(|list| {
            list.iter().any(|v| {
                matches!(
                    v["cve_id"].as_str(),
                    Some("KNOWN-COMPROMISED-RELEASE" | "KNOWN-MALICIOUS-PACKAGE")
                )
            })
        })
}

fn advisories(list: &Value) -> Value {
    match list.as_array() {
        Some(items) if !items.is_empty() => Value::Array(
            items
                .iter()
                .map(|v| {
                    json!({
                        "id": v["cve_id"],
                        "severity": v["severity"],
                        "summary": text_of(v, &["description"]).map(|d| d.chars().take(140).collect::<String>()),
                        "fixed_in": v["fixed_in"],
                    })
                })
                .collect(),
        ),
        _ => Value::Null,
    }
}

fn clip_text(value: &Value, max: usize) -> Value {
    match value.as_str() {
        Some(text) if text.chars().count() > max => {
            json!(format!("{}…", text.chars().take(max).collect::<String>()))
        }
        _ => value.clone(),
    }
}

fn scripts_view(ecosystem: Ecosystem, full: &Value) -> Value {
    match ecosystem {
        Ecosystem::Npm => {
            let scripts = &full["scripts_analysis"];
            let hooks: serde_json::Map<String, Value> = scripts["script_hooks"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .take(40)
                        .map(|(k, v)| (k.clone(), clip_text(v, 400)))
                        .collect()
                })
                .unwrap_or_default();
            let custom: serde_json::Map<String, Value> = scripts["custom_scripts"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .take(40)
                        .map(|(k, v)| (k.clone(), clip_text(v, 200)))
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "section": "scripts",
                "install_hooks": hooks,
                "custom_scripts": custom,
                "dangerous_commands": scripts["dangerous_commands"].as_array().map(|l| l.iter().take(20).map(|c| json!({
                    "script": c["script_name"], "reason": c["risk_reason"], "command": clip_text(&c["command"], 200),
                })).collect::<Vec<_>>()),
                "external_downloads": scripts["external_downloads"].as_array().map(|l| l.iter().take(20).map(|c| clip_text(c, 200)).collect::<Vec<_>>()),
                "suspicious_scripts": full["security_analysis"]["suspicious_scripts"].as_array().map(|l| l.iter().take(20).map(|s| json!({
                    "script_name": s["script_name"],
                    "risk_indicators": s["risk_indicators"],
                    "obfuscation_level": s["obfuscation_level"],
                    "external_commands": s["external_commands"],
                })).collect::<Vec<_>>()),
                "shell_injection_risk": scripts["shell_injection_risk"],
            })
        }
        Ecosystem::Python => {
            let setup = &full["setup_analysis"];
            let kind = full["input"]["kind"].as_str().unwrap_or("");
            // A dependency list or a wheel has no setup script: do not name a setup
            // type it does not have.
            let no_setup = match kind {
                "requirements" | "lockfile" => Some(
                    "A dependency list has no setup script: nothing in it runs at install time.",
                ),
                "wheel" => Some(
                    "A wheel is already built and has no setup script; installing it runs none of the package's code (except .pth files).",
                ),
                _ => None,
            };
            if let Some(note) = no_setup {
                // A .pth file of a wheel is run by Python at every start: say
                // where its findings are rather than read as clean.
                let pth: Vec<Value> = if kind == "wheel" {
                    full["source_findings"]
                        .as_array()
                        .map(|list| {
                            list.iter()
                                .filter(|f| {
                                    f["file"].as_str().is_some_and(|n| n.ends_with(".pth"))
                                        && f["in_comment"] != json!(true)
                                })
                                .take(40)
                                .map(|f| {
                                    json!({
                                        "operation": f["rule"],
                                        "location": format!(
                                            "{}:{}",
                                            f["file"].as_str().unwrap_or(""),
                                            f["line"]
                                        ),
                                        "risk_reason": format!(
                                            "a .pth file runs when Python starts: {}",
                                            f["evidence"].as_str().unwrap_or("")
                                        ),
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let note = if pth.is_empty() {
                    note.to_string()
                } else {
                    "A wheel is already built and has no setup script, but it ships a .pth file with findings (listed under dangerous_operations, file:line in location). Python runs the code in a .pth file every time it starts, so this is install-time code.".to_string()
                };
                return json!({
                    "section": "scripts",
                    "setup_type": Value::Null,
                    "note": note,
                    "setup_commands": [],
                    "dangerous_operations": pth,
                    "external_downloads": [],
                    "suspicious_imports": [],
                });
            }
            // Operations are listed under dangerous_operations; the import rows are
            // only the modules a setup script imports.
            let operation_names: std::collections::HashSet<&str> = setup["dangerous_operations"]
                .as_array()
                .map(|l| l.iter().filter_map(|o| o["operation"].as_str()).collect())
                .unwrap_or_default();
            let modules: Vec<Value> = full["security_analysis"]["suspicious_imports"]
                .as_array()
                .map(|l| {
                    l.iter()
                        .filter(|i| {
                            !i["module_name"]
                                .as_str()
                                .is_some_and(|m| operation_names.contains(m))
                        })
                        .take(40)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "section": "scripts",
                "setup_type": setup["setup_type"],
                "setup_commands": setup["setup_commands"].as_array().map(|l| l.iter().take(20).cloned().collect::<Vec<_>>()),
                "custom_commands": setup["custom_commands"],
                "dangerous_operations": setup["dangerous_operations"].as_array().map(|l| l.iter().take(40).cloned().collect::<Vec<_>>()),
                "external_downloads": setup["external_downloads"],
                "suspicious_imports": modules,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_errors_say_the_tool_is_offline() {
        let npm = Ecosystem::Npm.registry_error("express");
        assert!(
            npm.contains("offline") && npm.contains("npm pack express"),
            "{npm}"
        );
        let py = Ecosystem::Python.registry_error("requests==2.5.0");
        assert!(
            py.contains("offline") && py.contains("pip download"),
            "{py}"
        );
    }

    #[test]
    fn capitalise_normalises_severity_names() {
        assert_eq!(capitalise("high"), "High");
        assert_eq!(capitalise("CRITICAL"), "Critical");
    }

    #[test]
    fn fingerprint_changes_when_a_file_changes() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "one").unwrap();
        let first = fingerprint(&file).unwrap();
        std::fs::write(&file, "two").unwrap();
        assert_ne!(first, fingerprint(&file).unwrap());
        let dir_first = fingerprint(dir.path()).unwrap();
        std::fs::write(dir.path().join("b.txt"), "x").unwrap();
        assert_ne!(dir_first, fingerprint(dir.path()).unwrap());
    }

    #[test]
    fn fingerprint_hashes_what_the_analysis_reads_not_node_modules() {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src/lib");
        std::fs::create_dir_all(&src).unwrap();
        let file = src.join("x.js");
        std::fs::write(&file, "// aaaa\n").unwrap();
        let modules = dir.path().join("node_modules");
        std::fs::create_dir_all(&modules).unwrap();
        for n in 0..450 {
            std::fs::write(modules.join(format!("m{n}.js")), "x\n").unwrap();
        }
        let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
        let first = fingerprint(dir.path()).unwrap();
        // Same length, same modification time, different content.
        std::fs::write(&file, "// bbbb\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert_ne!(first, fingerprint(dir.path()).unwrap());
    }

    #[test]
    fn fingerprint_sees_the_root_manifest_behind_many_nested_ones() {
        let dir = tempfile::TempDir::new().unwrap();
        for n in 0..70 {
            let nested = dir.path().join(format!("a/p{n:02}"));
            std::fs::create_dir_all(&nested).unwrap();
            std::fs::write(nested.join("package.json"), "{}").unwrap();
        }
        let root = dir.path().join("package.json");
        std::fs::write(&root, "{\"scripts\":{\"postinstall\":\"echo aaaa\"}}").unwrap();
        let modified = std::fs::metadata(&root).unwrap().modified().unwrap();
        let first = fingerprint(dir.path()).unwrap();
        // Same length, same modification time, different content.
        std::fs::write(&root, "{\"scripts\":{\"postinstall\":\"echo bbbb\"}}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&root)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        assert_ne!(first, fingerprint(dir.path()).unwrap());
    }
}
