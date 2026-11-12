//! `analyze_java_file`: an overview of a Java archive or class file, then paged
//! drill-down into classes, dangerous-API findings, resources and single classes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use rmcp::{
    handler::server::wrapper::Json,
    model::{CallToolResult, JsonObject},
    schemars, tool, tool_router, ErrorData,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::calculate_sha256_only;
use crate::java_analysis::{
    analyze_java_path, ClassInfo, CodeSigningStatus, JavaAnalysisResult, JavaArchiveType,
    LEGACY_LIST_CAP,
};

use super::{
    output::{
        fit_rows, input_schema_with_budget, page, parse_request, respond_result, tool_error,
        DEFAULT_LIMIT,
    },
    paths::Expect,
    state::ServerState,
    FileScannerMcp,
};

const ANALYZE_JAVA_DESCRIPTION: &str = "Analyze a Java archive (JAR/WAR/EAR/AAR/APK) or a class \
file; the kind is decided by the file's content, not its extension. The default call returns an \
overview: counts, Java versions, manifest main attributes, Android package/permissions/exported \
components, signature-file presence, threat level with its basis, and the top dangerous-API \
findings, plus next_steps. Then dig in with `view`: classes (paged, `filter` matches class name \
or API), findings (every dangerous API with class counts), resources (paged, `filter` on path), \
class (one class by `class` name: methods, fields, referenced classes and method calls, paged), \
manifest (every MANIFEST.MF attribute; values are returned whole up to a third of `max_output_bytes`, \
longer ones are marked `value_cut` with their `value_length`; `filter` matches the name), \
android (paged permissions, features and components with exported flag and intent actions; \
`filter` matches kind or name), nested (paged nested archives with their status). \
Class files are parsed for real; dangerous APIs (Runtime.exec, ProcessBuilder, reflection, class \
and native loading, network, crypto, deserialization, JNDI, scripting, Unsafe) come from the \
constant pool, and the threat level follows from them. Nested archives (AAR classes.jar, WAR \
WEB-INF/lib, EAR modules) are opened up to two levels deep (an EAR's WAR's libraries) within byte caps; deeper ones are reported as not read. Not done: signatures are \
listed as 'signature files present, not verified'; classes.dex (DEX) is not parsed, so APK code \
is not assessed. Call analyze_file first if you are unsure what the file is. Results are \
compact JSON capped at `max_output_bytes` (default 80000, ceiling 400000). When a cap cuts a \
list, the answer says so: the overview and nested lists carry `truncated` with their `total`, \
and a paged view (classes, resources, class, android, nested) returns the rows that fit with `next_offset` \
and a `hint`; pass `next_offset` as `offset` for the rest. Nested archives are named by their \
full path from the analyzed file, joined with `!` (a.war!WEB-INF/lib/util.jar); a class's \
`container` and `filter` use the same paths.";

/// Cache section for the full parse of one file (keyed by the file's SHA-256).
const CACHE_KEY: &str = "java_analysis:v5";

/// Parsed results kept in memory, newest last, so a follow-up call on the same file neither
/// inflates the cached text nor parses it again (each of those costs the full result in
/// allocations). Keyed by the server state and SHA-256; at most [`RECENT_RESULTS`] of them,
/// and only results whose serialized form is under [`RECENT_MAX_TEXT_BYTES`].
type RecentResults = Vec<(Weak<ServerState>, String, Arc<JavaAnalysisResult>)>;
static RECENT: Mutex<RecentResults> = Mutex::new(Vec::new());

/// Drops this server's entries from the in-memory result store (cache_clear calls this so
/// the next call recomputes). Entries of other servers in the same process are kept.
pub(crate) fn forget_recent(state: &ServerState) {
    RECENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|(weak, _, _)| weak.strong_count() > 0 && !std::ptr::eq(weak.as_ptr(), state));
}
const RECENT_RESULTS: usize = 2;
const RECENT_MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;

fn recent_get(state: &Arc<ServerState>, sha256: &str) -> Option<Arc<JavaAnalysisResult>> {
    let mut recent = RECENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    recent.retain(|(weak, _, _)| weak.strong_count() > 0);
    let at = recent.iter().position(|(weak, sha, _)| {
        std::ptr::eq(weak.as_ptr(), Arc::as_ptr(state)) && sha == sha256
    })?;
    let entry = recent.remove(at);
    let result = Arc::clone(&entry.2);
    recent.push(entry);
    Some(result)
}

fn recent_put(state: &Arc<ServerState>, sha256: &str, result: Arc<JavaAnalysisResult>) {
    let mut recent = RECENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    recent.retain(|(weak, sha, _)| {
        weak.strong_count() > 0
            && !(std::ptr::eq(weak.as_ptr(), Arc::as_ptr(state)) && sha == sha256)
    });
    recent.push((Arc::downgrade(state), sha256.to_string(), result));
    while recent.len() > RECENT_RESULTS {
        recent.remove(0);
    }
}

/// Times a result was parsed from a file in this process (tests assert that cached calls
/// do not parse again).
#[cfg(test)]
static PARSE_COUNTS: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

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
        let (request, budget, _raw) = match parse_request::<JavaAnalysisRequest>(args) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(tool_error(message)),
        };
        let view = match request.resolved_view() {
            Ok(view) => view,
            Err(message) => return Ok(tool_error(message)),
        };
        let path = match self
            .state
            .resolve_path(&request.file_path, "File", Expect::File)
        {
            Ok(path) => path,
            Err(message) => return Ok(tool_error(message)),
        };
        let sha256 = match calculate_sha256_only(&path).await {
            Ok(sha256) => sha256,
            Err(error) => {
                return Ok(tool_error(format!(
                    "Cannot read {}: {error:#}",
                    request.file_path
                )))
            }
        };

        let state = Arc::clone(&self.state);
        let outcome = self
            .state
            .run_blocking("analyze_java_file", move || {
                let use_memory = state.cache_enabled();
                if let Some(result) = use_memory.then(|| recent_get(&state, &sha256)).flatten() {
                    return respond_view(&result, view, &request, &path, &sha256, true, budget);
                }
                let cache = state.section_cache();
                // Text in, text out: no intermediate `Value` tree, which costs several times
                // the size of the result.
                let cached = cache
                    .get_text(&sha256, CACHE_KEY)
                    .and_then(|text| serde_json::from_str::<JavaAnalysisResult>(&text).ok());
                let (result, hit) = match cached {
                    Some(result) => (result, true),
                    None => {
                        #[cfg(test)]
                        {
                            let mut counts = PARSE_COUNTS
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            match counts.iter_mut().find(|(p, _)| *p == path) {
                                Some(entry) => entry.1 += 1,
                                None => counts.push((path.clone(), 1)),
                            }
                        }
                        (parse(&path)?, false)
                    }
                };
                let mut keep_in_memory = hit;
                if !hit {
                    if let Ok(text) = serde_json::to_string(&result) {
                        keep_in_memory = text.len() <= RECENT_MAX_TEXT_BYTES;
                        cache.put_text(&sha256, CACHE_KEY, text);
                    }
                }
                let result = Arc::new(result);
                if keep_in_memory && use_memory {
                    recent_put(&state, &sha256, Arc::clone(&result));
                }
                respond_view(&result, view, &request, &path, &sha256, hit, budget)
            })
            .await;
        Ok(respond_result(outcome, budget))
    }
}

fn parse(path: &Path) -> Result<JavaAnalysisResult, String> {
    analyze_java_path(path).map_err(|e| format!("{e:#}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JavaView {
    /// Counts, versions, manifest, Android facts, signing, threat level, top findings (default).
    Summary,
    /// Paged list of classes; `filter` matches class name, container or API.
    Classes,
    /// Every dangerous API found, with class counts and example classes.
    Findings,
    /// Paged list of archive entries; `filter` matches the path.
    Resources,
    /// One class by name (`class`): methods, fields, referenced classes, method calls.
    Class,
    /// Every `MANIFEST.MF` main-section attribute (long values cut at a third of the byte
    /// budget, marked), and Class-Path entries.
    Manifest,
    /// Paged Android permissions, features and components; `filter` matches kind or name.
    Android,
    /// Paged nested archives (WEB-INF/lib jars, AAR classes.jar) with their status.
    Nested,
}

#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavaAnalysisRequest {
    #[schemars(
        description = "Absolute path of the Java file to analyze (JAR/WAR/EAR/APK/AAR/CLASS)"
    )]
    pub file_path: String,
    #[schemars(
        description = "What to return: summary (default), classes, findings, resources, class, manifest, \
                       android or nested. Defaults to class when `class` is given."
    )]
    pub view: Option<JavaView>,
    #[schemars(
        description = "Class to describe for view=class, as named in view=classes (dots or slashes), \
                       or <container>!<class> as findings and also_in list one copy of it"
    )]
    pub class: Option<String>,
    #[schemars(
        description = "Case-insensitive substring filter: class name, container or API \
                       (classes, findings, class), entry path (resources), attribute name \
                       (manifest), kind or name (android), or archive path (nested)"
    )]
    pub filter: Option<String>,
    #[schemars(description = "Number of items to skip (default 0)")]
    pub offset: Option<usize>,
    #[schemars(description = "Number of items to return (default 50, at most 500)")]
    pub limit: Option<usize>,
}

impl JavaAnalysisRequest {
    fn resolved_view(&self) -> Result<JavaView, String> {
        let view = self.view.unwrap_or(if self.class.is_some() {
            JavaView::Class
        } else {
            JavaView::Summary
        });
        if view == JavaView::Class && self.class.as_deref().is_none_or(str::is_empty) {
            return Err(
                "view=class needs `class`: a class name as listed by view=classes \
                        (use filter to find it, e.g. view=classes filter=<part of the name>)."
                    .to_string(),
            );
        }
        Ok(view)
    }
}

impl FileScannerMcp {
    /// Library entry point: analyze by content, with the class and resource lists cut
    /// to [`LEGACY_LIST_CAP`] entries (the MCP tool returns paged views instead).
    pub async fn analyze_java_file(
        &self,
        request: JavaAnalysisRequest,
    ) -> Result<Json<JavaAnalysisResult>, String> {
        let path = PathBuf::from(&request.file_path);
        if !path.exists() {
            return Err(format!("File does not exist: {}", request.file_path));
        }
        Ok(Json(parse(&path)?.bounded(LEGACY_LIST_CAP)))
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

fn respond_view(
    result: &JavaAnalysisResult,
    view: JavaView,
    request: &JavaAnalysisRequest,
    path: &Path,
    sha256: &str,
    hit: bool,
    budget: usize,
) -> Result<Value, String> {
    let offset = request.offset.unwrap_or(0);
    let limit = request.limit.unwrap_or(DEFAULT_LIMIT);
    let filter = request.filter.as_deref().map(str::to_lowercase);
    let path_text = path.to_string_lossy().into_owned();
    let cache = if hit { "hit" } else { "miss" };

    let mut out = match view {
        JavaView::Summary => summary(result, &path_text, sha256),
        JavaView::Classes => {
            let rows: Vec<Value> = result
                .classes
                .iter()
                .filter(|c| class_matches(c, filter.as_deref()))
                .map(class_row)
                .collect();
            json!({
                "view": "classes",
                "filter": request.filter,
                "classes": fit_page(&rows, offset, limit, budget / 2),
                "hint": "Pass `class` (a name from this list) for methods, fields and references.",
            })
        }
        JavaView::Findings => {
            let rows: Vec<Value> = finding_rows(result)
                .into_iter()
                .filter(|row| {
                    filter.as_deref().is_none_or(|f| {
                        let text = |key: &str| {
                            row[key]
                                .as_str()
                                .is_some_and(|t| t.to_lowercase().contains(f))
                        };
                        text("category")
                            || text("api")
                            || row["example_classes"].as_array().is_some_and(|names| {
                                names.iter().any(|n| {
                                    n.as_str().is_some_and(|t| t.to_lowercase().contains(f))
                                })
                            })
                    })
                })
                .collect();
            json!({
                "view": "findings",
                "filter": request.filter,
                "threat_level": format!("{:?}", result.security_analysis.threat_level),
                "threat_basis": result.security_analysis.threat_basis,
                "findings": fit_page(&rows, offset, limit, budget / 2),
                "hint": "view=classes with filter=<api> lists the classes that use an API.",
            })
        }
        JavaView::Resources => {
            let rows: Vec<Value> = result
                .resources
                .iter()
                .filter(|r| {
                    filter
                        .as_deref()
                        .is_none_or(|f| r.path.to_lowercase().contains(f))
                })
                .map(|r| {
                    json!({
                        "path": r.path,
                        "size": r.size,
                        "type": format!("{:?}", r.resource_type),
                    })
                })
                .collect();
            json!({
                "view": "resources",
                "filter": request.filter,
                "resources": fit_page(&rows, offset, limit, budget / 2),
            })
        }
        JavaView::Manifest => {
            manifest_view(result, request, filter.as_deref(), offset, limit, budget)?
        }
        JavaView::Class => class_view(result, request, filter.as_deref(), offset, limit, budget)?,
        JavaView::Android => {
            android_view(result, request, filter.as_deref(), offset, limit, budget)?
        }
        JavaView::Nested => {
            let rows: Vec<Value> = result
                .nested_archives
                .iter()
                .filter(|n| {
                    filter
                        .as_deref()
                        .is_none_or(|f| n.path.to_lowercase().contains(f))
                })
                .map(nested_row)
                .collect();
            let listed = result.nested_archives.len();
            let counted = result.nested_total.max(listed);
            let hint = if counted > listed {
                format!(
                    "filter matches the archive path. The archive holds {counted} nested \
                     archives; rows stop at {listed} (the cap), so the rest cannot be listed."
                )
            } else {
                "filter matches the archive path.".to_string()
            };
            json!({
                "view": "nested",
                "filter": request.filter,
                "nested_archives": fit_page(&rows, offset, limit, budget / 2),
                "nested_archives_counted": counted,
                "hint": hint,
            })
        }
    };
    if let Value::Object(map) = &mut out {
        map.insert("file_path".into(), path_text.into());
        map.insert("cache".into(), cache.into());
        if view != JavaView::Summary {
            map.insert(
                "archive_type".into(),
                format!("{:?}", result.archive_type).into(),
            );
        }
    }
    Ok(out)
}

fn class_matches(class: &ClassInfo, filter: Option<&str>) -> bool {
    let Some(f) = filter else { return true };
    class.name.to_lowercase().contains(f)
        || class
            .container
            .as_deref()
            .is_some_and(|c| c.to_lowercase().contains(f))
        || class
            .dangerous_apis
            .iter()
            .any(|a| a.api.to_lowercase().contains(f) || a.category.contains(f))
}

fn kind_of(class: &ClassInfo) -> &'static str {
    if class.is_annotation {
        "annotation"
    } else if class.is_interface {
        "interface"
    } else if class.is_enum {
        "enum"
    } else if class.is_abstract {
        "abstract class"
    } else {
        "class"
    }
}

fn class_row(class: &ClassInfo) -> Value {
    let apis: Vec<&str> = class
        .dangerous_apis
        .iter()
        .map(|a| a.api.as_str())
        .collect();
    json!({
        "name": class.name,
        "container": class.container,
        "java": class.java_version.split(" (").next().unwrap_or(""),
        "kind": kind_of(class),
        "super": class.super_class,
        "methods": class.method_count(),
        "fields": class.field_count(),
        "apis": if apis.is_empty() { Value::Null } else { json!(apis) },
    })
}

fn finding_rows(result: &JavaAnalysisResult) -> Vec<Value> {
    let security = &result.security_analysis;
    let mut rows: Vec<Value> = security
        .api_findings
        .iter()
        .map(|f| {
            json!({
                "category": f.category,
                "api": f.api,
                "severity": format!("{:?}", f.severity),
                "classes": f.class_count,
                "example_classes": f.example_classes,
            })
        })
        .collect();
    for permission in &security.suspicious_permissions {
        rows.push(json!({
            "category": "permission",
            "api": permission,
            "severity": "Medium",
        }));
    }
    for vulnerability in &security.security_vulnerabilities {
        rows.push(json!({
            "category": vulnerability.vulnerability_type,
            "api": vulnerability.description,
            "severity": format!("{:?}", vulnerability.severity),
        }));
    }
    rows
}

fn modifiers(access: u16, table: &[(u16, &str)]) -> String {
    table
        .iter()
        .filter(|(bit, _)| access & bit != 0)
        .map(|(_, word)| *word)
        .collect::<Vec<_>>()
        .join(" ")
}

const METHOD_FLAGS: &[(u16, &str)] = &[
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0100, "native"),
    (0x0400, "abstract"),
];
const FIELD_FLAGS: &[(u16, &str)] = &[
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0040, "volatile"),
    (0x0080, "transient"),
];

fn class_view(
    result: &JavaAnalysisResult,
    request: &JavaAnalysisRequest,
    filter: Option<&str>,
    offset: usize,
    limit: usize,
    budget: usize,
) -> Result<Value, String> {
    // `<container>!<class>` (as findings and `also_in` list it) picks one copy; a bare name
    // matches all. The container is a path and is compared as given, so only the class part
    // has its slashes turned into dots.
    let raw = request.class.as_deref().unwrap_or("");
    let (want_container, name_part) = match raw.rsplit_once('!') {
        Some((c, n)) if !c.is_empty() && !n.is_empty() => (Some(c), n),
        _ => (None, raw),
    };
    let wanted = name_part.replace('/', ".");
    let wanted = wanted.strip_suffix(".class").unwrap_or(&wanted).to_string();
    let matching: Vec<&ClassInfo> = result
        .classes
        .iter()
        .filter(|c| {
            c.name == wanted && want_container.is_none_or(|w| c.container.as_deref() == Some(w))
        })
        .collect();
    let Some(class) = matching.first() else {
        let lower = wanted.to_lowercase();
        let close: Vec<String> = result
            .classes
            .iter()
            .filter(|c| c.name.to_lowercase().contains(&lower))
            .take(5)
            .map(|c| match c.container.as_deref() {
                Some(container) => format!("{container}!{}", c.name),
                None => c.name.clone(),
            })
            .collect();
        let hint = if close.is_empty() {
            "Use view=classes with filter=<part of the name> to find it.".to_string()
        } else {
            format!("Close matches: {}.", close.join(", "))
        };
        let place = match want_container {
            Some(container) => format!("in '{}' inside this file", clip(container, 200)),
            None => "in this file".to_string(),
        };
        return Err(format!(
            "No class named '{}' {place} ({} classes in all). {hint}",
            clip(&wanted, 200),
            result.classes.len()
        ));
    };
    let keep = |text: &str| filter.is_none_or(|f| text.to_lowercase().contains(f));

    let methods: Vec<Value> = class
        .methods
        .iter()
        .filter(|m| keep(&m.name) || keep(&m.descriptor))
        .map(|m| {
            json!({
                "name": m.name,
                "descriptor": m.descriptor,
                "modifiers": modifiers(m.access_flags, METHOD_FLAGS),
                "throws": if m.exception_table.is_empty() { Value::Null } else { json!(m.exception_table) },
            })
        })
        .collect();
    let fields: Vec<Value> = class
        .fields
        .iter()
        .filter(|f| keep(&f.name) || keep(&f.descriptor))
        .map(|f| {
            json!({
                "name": f.name,
                "descriptor": f.descriptor,
                "modifiers": modifiers(f.access_flags, FIELD_FLAGS),
                "constant": f.constant_value,
            })
        })
        .collect();
    let referenced: Vec<&String> = class
        .referenced_classes
        .iter()
        .filter(|c| keep(c))
        .collect();
    let calls: Vec<&String> = class.method_refs.iter().filter(|m| keep(m)).collect();
    let interfaces: Vec<&String> = class.interfaces.iter().filter(|c| keep(c)).collect();
    let inner: Vec<&String> = class.inner_classes.iter().filter(|c| keep(c)).collect();
    let apis: Vec<Value> = class
        .dangerous_apis
        .iter()
        .filter(|a| keep(&a.api) || keep(&a.category))
        .map(|a| json!({"category": a.category, "api": a.api}))
        .collect();
    let also_in: Vec<String> = matching
        .iter()
        .skip(1)
        .map(|c| match &c.container {
            Some(container) => format!("{container}!{}", c.entry),
            None => c.entry.clone(),
        })
        .collect();

    let header = json!({
        "name": class.name,
        "kind": kind_of(class),
        "entry": clip(&class.entry, 400),
        "container": class.container.as_deref().map(|c| clip(c, 400)),
        "java_version": class.java_version,
        "access": modifiers(class.access_flags, &[(0x0001, "public"), (0x0010, "final"), (0x0400, "abstract")]),
        "super": class.super_class,
        "interface_count": class.interface_count(),
        "method_count": class.method_count(),
        "field_count": class.field_count(),
        "source_file": class.source_file,
        "dangerous_api_count": class.dangerous_apis.len(),
        "also_in_count": also_in.len(),
        "parse_warning": class.parse_warning,
    });
    let hint = "offset and limit apply to each of the eight lists (interfaces, inner_classes, \
                methods, fields, referenced_classes, method_refs, dangerous_apis, also_in); \
                filter narrows them. When class.parse_warning says member lists were cut or \
                dropped, method_count and field_count are the real totals; the names \
                themselves are not kept for that class. Extract the entry and analyze the \
                .class file alone to see its members. A list whose page is empty with \
                next_offset equal to its offset found no room under max_output_bytes: raise it.";
    // One byte counter for the whole answer: what the header, the hint and the list keys
    // take comes off first, and each list gets an equal share of what is left, so the
    // lists together never exceed the budget and the generic cutter never has to remove
    // rows that `returned` and `next_offset` count.
    let fixed = serde_json::to_vec(&header).map_or(0, |v| v.len()) + hint.len() + 512;
    let mut remaining = budget.saturating_sub(fixed);
    let mut lists_left = 8usize;
    let mut fit = |build: &dyn Fn(usize, usize) -> Value| -> Value {
        let share = remaining / lists_left.max(1);
        lists_left = lists_left.saturating_sub(1);
        // A row larger than the share may use every byte not yet spent, keeping enough
        // for an empty page of each list still to come.
        let most = remaining
            .saturating_sub(EMPTY_LIST_BYTES * lists_left)
            .max(share);
        let value = build(share, most);
        remaining = remaining.saturating_sub(serde_json::to_vec(&value).map_or(0, |v| v.len()));
        value
    };
    let dangerous_apis = fit(&|share, most| fit_list(&apis, offset, limit, share, most));
    let also_in_page = fit(&|share, most| fit_list(&also_in, offset, limit, share, most));
    let interfaces_page = fit(&|share, most| fit_list(&interfaces, offset, limit, share, most));
    let inner_page = fit(&|share, most| fit_list(&inner, offset, limit, share, most));
    let methods_page = fit(&|share, most| fit_list(&methods, offset, limit, share, most));
    let fields_page = fit(&|share, most| fit_list(&fields, offset, limit, share, most));
    let referenced_page = fit(&|share, most| fit_list(&referenced, offset, limit, share, most));
    let calls_page = fit(&|share, most| fit_list(&calls, offset, limit, share, most));

    Ok(json!({
        "view": "class",
        "filter": request.filter.as_deref().map(|f| clip(f, MAX_FILTER_ECHO_CHARS)),
        "class": header,
        "dangerous_apis": dangerous_apis,
        "also_in": also_in_page,
        "interfaces": interfaces_page,
        "inner_classes": inner_page,
        "methods": methods_page,
        "fields": fields_page,
        "referenced_classes": referenced_page,
        "method_refs": calls_page,
        "hint": hint,
    }))
}

/// Bytes kept back for each list still to come: an empty page with its counters.
const EMPTY_LIST_BYTES: usize = 150;

/// The echoed `filter` is clipped to this many characters so it stays a small part of the
/// fixed byte cost of a class page.
const MAX_FILTER_ECHO_CHARS: usize = 200;

/// [`fit_page`] for one of several lists sharing a byte budget. A page is cut to `share`
/// bytes; when even one row is larger than that, the page is the one row alone, kept when
/// it fits `most` (every byte not yet spent). Only when the row does not fit even then does the page carry no
/// rows (`returned` 0, `next_offset` equal to `offset`), and its hint says how many bytes
/// that row needs instead of pointing at the next row, which would skip it.
fn fit_list<T: Serialize>(
    items: &[T],
    offset: usize,
    limit: usize,
    share: usize,
    most: usize,
) -> Value {
    let size_of = |v: &Value| serde_json::to_vec(v).map_or(0, |v| v.len());
    let has_rows = |v: &Value| {
        v.get("items")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty())
    };
    let value = fit_page(items, offset, limit, share);
    if size_of(&value) <= share || !has_rows(&value) {
        return value;
    }
    // Only the one row that missed its share, so later lists keep their bytes.
    let mut value = fit_page(items, offset, limit, 0);
    if size_of(&value) <= most || !has_rows(&value) {
        return value;
    }
    let row = items
        .get(offset)
        .map_or(0, |item| serde_json::to_vec(item).map_or(0, |v| v.len()));
    value["items"] = json!([]);
    value["returned"] = 0.into();
    value["next_offset"] = offset.into();
    value["hint"] =
        format!("The row at offset {offset} needs about {row} bytes; raise max_output_bytes.")
            .into();
    value
}

/// One page of a list, cut by [`fit_rows`] to `budget` bytes (at least one row is always
/// returned), so `returned`, `next_offset` and the hint describe what was really sent.
fn fit_page<T: Serialize>(items: &[T], offset: usize, limit: usize, budget: usize) -> Value {
    let mut page_value = page(items, offset, limit);
    fit_rows(&mut page_value, "items", budget, offset, items.len());
    page_value
}

/// Smallest cap on a manifest value returned by view=manifest.
const MIN_MANIFEST_VALUE_CHARS: usize = 1_000;

fn manifest_view(
    result: &JavaAnalysisResult,
    request: &JavaAnalysisRequest,
    filter: Option<&str>,
    offset: usize,
    limit: usize,
    budget: usize,
) -> Result<Value, String> {
    let Some(m) = &result.manifest else {
        return Err(
            "This file has no META-INF/MANIFEST.MF (class files and some archives have \
                    none). Use view=resources to see what the archive holds."
                .to_string(),
        );
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, value: &Option<String>| {
        if let Some(value) = value {
            pairs.push((name.to_string(), value.clone()));
        }
    };
    add("Main-Class", &m.main_class);
    add("Implementation-Title", &m.implementation_title);
    add("Implementation-Version", &m.implementation_version);
    add("Implementation-Vendor", &m.implementation_vendor);
    add("Specification-Title", &m.specification_title);
    add("Specification-Version", &m.specification_version);
    add("Specification-Vendor", &m.specification_vendor);
    add("Built-By", &m.built_by);
    add("Build-Jdk", &m.build_jdk);
    add("Created-By", &m.created_by);
    for (name, value) in &m.custom_attributes {
        pairs.push((name.clone(), value.clone()));
    }
    // A value may take up to its list's share of the byte budget.
    let value_cap = (budget / 3).max(MIN_MANIFEST_VALUE_CHARS);
    let rows: Vec<Value> = pairs
        .iter()
        .filter(|(name, _)| filter.is_none_or(|f| name.to_lowercase().contains(f)))
        .map(|(name, value)| {
            let length = value.chars().count();
            if length > value_cap {
                json!({
                    "name": name,
                    "value": clip(value, value_cap),
                    "value_length": length,
                    "value_cut": true,
                })
            } else {
                json!({"name": name, "value": value})
            }
        })
        .collect();
    let class_path: Vec<&String> = m
        .class_path
        .iter()
        .filter(|entry| filter.is_none_or(|f| entry.to_lowercase().contains(f)))
        .collect();
    Ok(json!({
        "view": "manifest",
        "filter": request.filter,
        "attributes": fit_page(&rows, offset, limit, budget / 3),
        "class_path": fit_page(&class_path, offset, limit, budget / 3),
        "entry_sections": m.entry_sections,
        "hint": if pairs.iter().any(|(_, v)| v.chars().count() > value_cap) {
            "filter matches the attribute name (and Class-Path entries); offset and limit \
             apply to both lists. A value marked value_cut is cut at a third of max_output_bytes: \
             raise max_output_bytes (and filter to that attribute) to read more of it."
        } else {
            "filter matches the attribute name (and Class-Path entries); offset and limit \
             apply to both lists."
        },
    }))
}

fn nested_row(n: &crate::java_analysis::NestedArchive) -> Value {
    json!({
        "path": n.path,
        "size": n.size,
        "opened": n.opened,
        "entries": n.entries,
        "classes": n.classes,
        "note": n.note,
    })
}

/// Paged Android permissions, features and components.
fn android_view(
    result: &JavaAnalysisResult,
    request: &JavaAnalysisRequest,
    filter: Option<&str>,
    offset: usize,
    limit: usize,
    budget: usize,
) -> Result<Value, String> {
    let Some(a) = &result.android_manifest else {
        return Err(
            "This file has no readable AndroidManifest.xml (only APKs and AARs carry one). \
             Use view=resources to see what the archive holds."
                .to_string(),
        );
    };
    let mut rows: Vec<Value> = Vec::new();
    for name in &a.permissions {
        rows.push(json!({"kind": "permission", "name": name}));
    }
    for name in &a.uses_features {
        rows.push(json!({"kind": "feature", "name": name}));
    }
    for (kind, list) in [
        ("activity", &a.activities),
        ("service", &a.services),
        ("receiver", &a.receivers),
        ("provider", &a.providers),
    ] {
        for c in list {
            let actions: Vec<&String> = c
                .intent_filters
                .iter()
                .flat_map(|f| f.actions.iter())
                .collect();
            rows.push(json!({
                "kind": kind,
                "name": c.name,
                "exported": c.exported,
                "enabled": c.enabled,
                "action_count": actions.len(),
                "actions": if actions.is_empty() { Value::Null } else { short_list(&actions, 10) },
            }));
        }
    }
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|row| {
            filter.is_none_or(|f| {
                ["kind", "name"].iter().any(|k| {
                    row[*k]
                        .as_str()
                        .is_some_and(|t| t.to_lowercase().contains(f))
                })
            })
        })
        .collect();
    Ok(json!({
        "view": "android",
        "filter": request.filter,
        "package": a.package_name,
        "notes": if a.notes.is_empty() { Value::Null } else { json!(a.notes) },
        "entries": fit_page(&rows, offset, limit, budget / 2),
        "hint": "filter matches the kind (permission, feature, activity, service, receiver, \
                 provider) or the name. A component shows its first 10 intent actions (see \
                 action_count); categories and data schemes are not listed.",
    }))
}

/// A list as an array when it fits, else `{items, total}` with the first `max`.
fn short_list<T: Serialize>(items: &[T], max: usize) -> Value {
    if items.len() <= max {
        json!(items)
    } else {
        json!({"items": &items[..max], "total": items.len(), "truncated": true})
    }
}

fn top_counts(counts: &std::collections::BTreeMap<String, usize>, max: usize) -> Value {
    let mut pairs: Vec<(&String, &usize)> = counts.iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let mut map = serde_json::Map::new();
    for (key, count) in pairs.into_iter().take(max) {
        map.insert(key.clone(), (*count).into());
    }
    Value::Object(map)
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let head: String = text.chars().take(max).collect();
        format!("{head}...")
    }
}

fn summary(result: &JavaAnalysisResult, path: &str, sha256: &str) -> Value {
    let security = &result.security_analysis;
    let signing = if result.signature_files.is_empty()
        || security.code_signing_status == CodeSigningStatus::Unsigned
    {
        "no signature files found"
    } else {
        "signature files present, not verified"
    };

    let mut manifest_cut = false;
    let manifest = result.manifest.as_ref().map(|m| {
        let mut cut_values: Vec<&String> = Vec::new();
        let attributes: std::collections::BTreeMap<&String, String> = m
            .custom_attributes
            .iter()
            .take(25)
            .map(|(k, v)| {
                if v.chars().count() > 300 {
                    cut_values.push(k);
                }
                (k, clip(v, 300))
            })
            .collect();
        manifest_cut =
            !cut_values.is_empty() || m.custom_attributes.len() > 25 || m.class_path.len() > 20;
        json!({
            "main_class": m.main_class,
            "class_path": short_list(&m.class_path, 20),
            "implementation_title": m.implementation_title,
            "implementation_version": m.implementation_version,
            "implementation_vendor": m.implementation_vendor,
            "specification_title": m.specification_title,
            "specification_version": m.specification_version,
            "built_by": m.built_by,
            "build_jdk": m.build_jdk,
            "created_by": m.created_by,
            "other_attributes": attributes,
            "other_attribute_count": m.custom_attributes.len(),
            "values_cut_at_300_chars": short_list(&cut_values, 10),
            "entry_sections": m.entry_sections,
        })
    });

    let android = match (&result.android_manifest, &result.archive_type) {
        (Some(a), _) => {
            let components = |list: &[crate::java_analysis::AndroidComponent]| {
                let exported: Vec<&str> = list
                    .iter()
                    .filter(|c| c.exported)
                    .map(|c| c.name.as_str())
                    .collect();
                json!({
                    "total": list.len(),
                    "exported": exported.len(),
                    "exported_names": short_list(&exported, 10),
                })
            };
            Some(json!({
                "parsed": true,
                "package": a.package_name,
                "version_code": a.version_code,
                "version_name": a.version_name,
                "min_sdk": a.min_sdk_version,
                "target_sdk": a.target_sdk_version,
                "compile_sdk": a.compile_sdk_version,
                "debuggable": a.debuggable,
                "permissions": short_list(&a.permissions, 40),
                "activities": components(&a.activities),
                "services": components(&a.services),
                "receivers": components(&a.receivers),
                "providers": components(&a.providers),
                "uses_features": short_list(&a.uses_features, 20),
                "notes": if a.notes.is_empty() { Value::Null } else { json!(a.notes) },
            }))
        }
        (None, JavaArchiveType::Apk | JavaArchiveType::Aar) => Some(json!({
            "parsed": false,
            "note": "AndroidManifest.xml missing or not readable; package, permissions and \
                     components are unknown",
        })),
        _ => None,
    };

    let top: Vec<Value> = finding_rows(result).into_iter().take(10).collect();
    let finding_total = security.api_findings.len()
        + security.suspicious_permissions.len()
        + security.security_vulnerabilities.len();
    let nested_opened = result
        .nested_opened_total
        .max(result.nested_archives.iter().filter(|n| n.opened).count());
    let nested_total = result.nested_total.max(result.nested_archives.len());
    let nested_rows: Vec<Value> = result
        .nested_archives
        .iter()
        .take(15)
        .map(nested_row)
        .collect();
    let nested_list = if nested_total > 15 {
        json!({"items": nested_rows, "total": nested_total, "truncated": true})
    } else {
        json!(nested_rows)
    };
    let largest: Vec<Value> = result
        .metadata
        .largest_entries
        .iter()
        .take(5)
        .map(|(name, size)| json!({"path": name, "size": size}))
        .collect();

    let mut next_steps: Vec<Value> = Vec::new();
    let step = |arguments: Value, gives: &str| {
        let mut args = json!({"file_path": path});
        if let (Value::Object(base), Value::Object(extra)) = (&mut args, arguments) {
            base.extend(extra);
        }
        json!({"tool": "analyze_java_file", "arguments": args, "gives": gives})
    };
    if finding_total > 0 {
        next_steps.push(step(
            json!({"view": "findings"}),
            "every dangerous API with class counts and example classes",
        ));
    }
    if result.classes_total > 0 {
        next_steps.push(step(
            json!({"view": "classes"}),
            "a page of the classes with their dangerous APIs (filter by name, container or API)",
        ));
        let target = result
            .classes
            .iter()
            .find(|c| !c.dangerous_apis.is_empty())
            .or_else(|| result.classes.first());
        if let Some(class) = target {
            next_steps.push(step(
                json!({"view": "class", "class": class.name}),
                "methods, fields, referenced classes and method calls of this class",
            ));
        }
    }
    if result.resources_total > 0 {
        next_steps.push(step(
            json!({"view": "resources"}),
            "a page of the archive entries (filter on path)",
        ));
    }
    if manifest_cut {
        next_steps.push(step(
            json!({"view": "manifest"}),
            "every MANIFEST.MF attribute, long values whole up to a third of the budget",
        ));
    }
    if let Some(a) = &result.android_manifest {
        let component_cut = [&a.activities, &a.services, &a.receivers, &a.providers]
            .iter()
            .any(|l| l.iter().filter(|c| c.exported).count() > 10);
        if a.permissions.len() > 40 || a.uses_features.len() > 20 || component_cut {
            next_steps.push(step(
                json!({"view": "android"}),
                "the full permission, feature and component lists with exported flags",
            ));
        }
    }
    if nested_total > 15 {
        next_steps.push(step(
            json!({"view": "nested"}),
            "every nested archive with its full path and whether it was opened",
        ));
    }

    json!({
        "view": "summary",
        "sha256": sha256,
        "archive_type": format!("{:?}", result.archive_type),
        "counts": {
            "entries": result.metadata.total_entries,
            "classes": result.classes_total,
            "unparsed_classes": result.unparsed_classes,
            "resources": result.resources_total,
            "nested_archives": nested_total,
            "nested_archives_opened": nested_opened,
            "dex_files": result.dex_files.len(),
            "signature_files": result.signature_files.len(),
            "total_size": result.metadata.total_size,
            "compressed_size": result.metadata.compressed_size,
        },
        "java_versions": result.java_versions,
        "manifest": manifest,
        "android": android,
        "dex_files": short_list(&result.dex_files, 10),
        "signing": {
            "status": signing,
            "files": short_list(&result.signature_files, 10),
        },
        "security": {
            "threat_level": format!("{:?}", security.threat_level),
            "basis": security.threat_basis,
            "malware_indicators": security.malware_indicators,
            "suspicious_permissions": short_list(&security.suspicious_permissions, 20),
            "privacy_concerns": short_list(&security.privacy_concerns, 20),
            "obfuscation_indicators": security.obfuscation_indicators,
            "archive_anomalies": short_list(&security.archive_anomalies, 10),
            "findings_total": finding_total,
            "top_findings": top,
        },
        "nested_archives": nested_list,
        "entry_types": top_counts(&result.metadata.entry_count_by_type, 12),
        "largest_entries": largest,
        "warnings": short_list(&result.warnings, 10),
        "warnings_suppressed": result.warnings_suppressed,
        "limitations": result.limitations,
        "next_steps": next_steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::java_analysis::test_class_builder::{
        axml, minimal_class, runtime_exec_class, zip_bytes, Av, ClassBuilder,
    };
    use serde_json::Value;
    use tempfile::TempDir;

    async fn call(mcp: &FileScannerMcp, args: Value) -> (bool, Value, String) {
        let Value::Object(map) = args else { panic!() };
        let result = mcp.analyze_java_file_tool(map).await.unwrap();
        let text = result.content[0].as_text().unwrap().text.clone();
        let json = serde_json::from_str(&text).unwrap_or(Value::Null);
        (result.is_error == Some(true), json, text)
    }

    fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// CF07: a class file is recognized by content whatever the extension.
    #[tokio::test]
    async fn class_file_is_detected_by_content_not_extension() {
        let dir = TempDir::new().unwrap();
        let bytes = ClassBuilder::new("com/example/Hello").build();
        let mcp = FileScannerMcp::new();
        for name in ["Hello.bin", "Hello", "Hello.jar"] {
            let path = write(&dir, name, &bytes);
            let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
            assert!(!is_error, "{name}: {text}");
            assert_eq!(json["archive_type"], "ClassFile", "{name}");
            assert_eq!(json["counts"]["classes"], 1);
        }
    }

    /// CF07: DEX and non-Java input are tool errors that say what to do.
    #[tokio::test]
    async fn dex_and_garbage_are_tool_errors() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let dex = write(&dir, "classes.dex", b"dex\n035\0aaaaaaaaaaaaaaaa");
        let (is_error, _, text) = call(&mcp, json!({"file_path": dex})).await;
        assert!(is_error);
        assert!(text.contains("DEX is not supported"), "{text}");
        let junk = write(&dir, "junk.jar", b"just some text, not a zip");
        let (is_error, _, text) = call(&mcp, json!({"file_path": junk})).await;
        assert!(is_error);
        assert!(text.contains("Not a Java archive"), "{text}");
        // Unknown arguments are rejected.
        let (is_error, _, text) = call(
            &mcp,
            json!({"file_path": junk, "max_classes": 3, "summary_only": true}),
        )
        .await;
        assert!(is_error);
        assert!(text.contains("Invalid arguments"), "{text}");
    }

    /// CF03: a 100-class library fits the default budget, a 3000-class one still
    /// answers with an overview, and the class list pages.
    #[tokio::test]
    async fn large_archives_get_a_bounded_overview_and_paged_lists() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        for count in [100usize, 3000] {
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            for i in 0..count {
                let class = ClassBuilder::new(&format!("com/lib/pkg{}/C{i}", i % 7))
                    .method("run", "(I)V", 1)
                    .field("value", "I", 2)
                    .calls(
                        "java/lang/Runtime",
                        "exec",
                        "(Ljava/lang/String;)Ljava/lang/Process;",
                    );
                entries.push((format!("com/lib/pkg{}/C{i}.class", i % 7), class.build()));
            }
            let borrowed: Vec<(&str, &[u8])> = entries
                .iter()
                .map(|(n, b)| (n.as_str(), b.as_slice()))
                .collect();
            let path = write(&dir, &format!("lib{count}.jar"), &zip_bytes(&borrowed));

            let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
            assert!(!is_error, "{text}");
            assert!(text.len() < 80_000, "{count} classes: {} bytes", text.len());
            assert!(json.get("truncated").is_none(), "{count}: summary was cut");
            assert_eq!(json["counts"]["classes"], count);

            let (_, page1, text) = call(
                &mcp,
                json!({"file_path": path, "view": "classes", "limit": 10, "offset": 5}),
            )
            .await;
            assert!(text.len() < 20_000);
            assert_eq!(page1["classes"]["returned"], 10);
            assert_eq!(page1["classes"]["total"], count);
            assert_eq!(page1["classes"]["next_offset"], 15);
            assert_eq!(page1["cache"], "hit", "drill-down is served from the cache");
        }
    }

    /// CF02: dangerous APIs from the constant pool set the findings and threat level.
    #[tokio::test]
    async fn dangerous_apis_drive_findings_and_drill_down() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let jar = zip_bytes(&[
            (
                "com/example/Hello.class",
                &runtime_exec_class("com/example/Hello"),
            ),
            (
                "com/example/Quiet.class",
                &minimal_class("com/example/Quiet"),
            ),
        ]);
        let path = write(&dir, "app.jar", &jar);

        let (_, json, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(json["security"]["threat_level"], "High");
        assert_eq!(
            json["security"]["top_findings"][0]["api"],
            "java.lang.Runtime.exec"
        );
        assert!(json["next_steps"].as_array().unwrap().len() >= 3);

        let (_, findings, _) = call(&mcp, json!({"file_path": path, "view": "findings"})).await;
        assert_eq!(findings["findings"]["items"][0]["category"], "process_exec");
        assert_eq!(findings["findings"]["items"][0]["classes"], 1);

        let (_, classes, _) = call(
            &mcp,
            json!({"file_path": path, "view": "classes", "filter": "runtime.exec"}),
        )
        .await;
        assert_eq!(classes["classes"]["total"], 1);
        assert_eq!(classes["classes"]["items"][0]["name"], "com.example.Hello");

        let (_, class, _) = call(
            &mcp,
            json!({"file_path": path, "class": "com/example/Hello", "filter": "exec"}),
        )
        .await;
        assert_eq!(class["class"]["name"], "com.example.Hello");
        assert_eq!(class["method_refs"]["total"], 1);
        assert_eq!(
            class["dangerous_apis"]["items"][0]["category"],
            "process_exec"
        );

        let (is_error, _, text) = call(
            &mcp,
            json!({"file_path": path, "class": "com.example.Hell"}),
        )
        .await;
        assert!(is_error);
        assert!(text.contains("Close matches: com.example.Hello"), "{text}");
        let (is_error, _, text) = call(&mcp, json!({"file_path": path, "view": "class"})).await;
        assert!(is_error);
        assert!(text.contains("needs `class`"), "{text}");
    }

    /// CF05: the binary manifest is parsed; signature files are not called Signed.
    #[tokio::test]
    async fn apk_manifest_and_signing_are_reported_honestly() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let manifest = axml(&[
            Some((
                "manifest",
                vec![
                    ("package", Av::Str("com.example.audit")),
                    ("versionCode", Av::Int(7)),
                    ("versionName", Av::Str("1.2")),
                ],
            )),
            Some((
                "uses-permission",
                vec![("name", Av::Str("android.permission.SEND_SMS"))],
            )),
            None,
            Some((
                "uses-permission",
                vec![("name", Av::Str("android.permission.INTERNET"))],
            )),
            None,
            Some(("application", vec![("debuggable", Av::Bool(true))])),
            Some((
                "activity",
                vec![("name", Av::Str(".Main")), ("exported", Av::Bool(true))],
            )),
            None,
            Some(("service", vec![("name", Av::Str("com.example.audit.Sync"))])),
            None,
            None,
            None,
        ]);
        let apk = zip_bytes(&[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0"),
            ("META-INF/CERT.RSA", b"not a signature block"),
            ("META-INF/CERT.SF", b"Signature-Version: 1.0\n"),
        ]);
        let path = write(&dir, "app.apk", &apk);
        let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
        assert!(!is_error, "{text}");
        assert_eq!(json["android"]["package"], "com.example.audit");
        assert_eq!(json["android"]["version_code"], 7);
        assert_eq!(
            json["android"]["permissions"][0],
            "android.permission.SEND_SMS"
        );
        assert_eq!(
            json["android"]["activities"]["exported_names"][0],
            "com.example.audit.Main"
        );
        assert_eq!(json["android"]["services"]["exported"], 0);
        assert_eq!(
            json["signing"]["status"],
            "signature files present, not verified"
        );
        assert_eq!(json["counts"]["dex_files"], 1);
        assert_eq!(json["security"]["threat_level"], "Medium");
        assert!(
            text.contains("classes.dex is present but not parsed"),
            "{text}"
        );
        assert!(!text.contains("\"Signed\""));
    }

    /// CF06: an entry that declares more than the read cap is skipped and flagged.
    #[tokio::test]
    async fn oversized_entries_are_skipped_and_flagged() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let mut zeros = vec![0xCA, 0xFE, 0xBA, 0xBE];
        zeros.resize(20 * 1024 * 1024, 0);
        let jar = zip_bytes(&[("Big.class", &zeros), ("Ok.class", &minimal_class("Ok"))]);
        let path = write(&dir, "bomb.jar", &jar);
        let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
        assert!(!is_error, "{text}");
        assert_eq!(json["counts"]["classes"], 1);
        assert_eq!(json["counts"]["unparsed_classes"], 1);
        assert!(json["security"]["archive_anomalies"][0]
            .as_str()
            .unwrap()
            .contains("Big.class"));
        assert!(json["warnings"][0].as_str().unwrap().contains("read cap"));
    }

    fn mixed_loader_class(name: &str, kinds: &[&str]) -> Vec<u8> {
        let mut b = ClassBuilder::new(name);
        for kind in kinds {
            b = match *kind {
                "net" => b.calls(
                    "java/net/URL",
                    "openConnection",
                    "()Ljava/net/URLConnection;",
                ),
                "exec" => b.calls(
                    "java/lang/Runtime",
                    "exec",
                    "(Ljava/lang/String;)Ljava/lang/Process;",
                ),
                _ => b.calls("java/net/URLClassLoader", "<init>", "([Ljava/net/URL;)V"),
            };
        }
        b.method("run", "()V", 1).build()
    }

    /// Calibration: the dropper shape must meet in one class; spread over classes it is
    /// just a library.
    #[tokio::test]
    async fn dropper_shape_needs_one_class() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let spread = zip_bytes(&[
            ("a/N.class", &mixed_loader_class("a/N", &["net"])),
            ("a/E.class", &mixed_loader_class("a/E", &["exec"])),
            ("a/L.class", &mixed_loader_class("a/L", &["load"])),
        ]);
        let path = write(&dir, "spread.jar", &spread);
        let (_, json, _) = call(&mcp, json!({"file_path": path})).await;
        assert_ne!(json["security"]["threat_level"], "Critical", "{json}");
        assert_eq!(json["security"]["malware_indicators"], json!([]));
        let together = zip_bytes(&[(
            "a/D.class",
            &mixed_loader_class("a/D", &["net", "exec", "load"]),
        )]);
        let path = write(&dir, "together.jar", &together);
        let (_, json, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(json["security"]["threat_level"], "Critical", "{json}");
        assert!(json["security"]["malware_indicators"][0]
            .as_str()
            .unwrap()
            .contains("a.D"));
    }

    /// Blocker: a JAR with leading bytes (launcher script, one stray byte) still opens.
    #[tokio::test]
    async fn prefixed_jar_is_still_analyzed() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let jar = zip_bytes(&[("a/Q.class", &minimal_class("a/Q"))]);
        for (name, prefix) in [
            ("one.jar", b"X".to_vec()),
            ("script.jar", b"#!/bin/sh\nexec java -jar \"$0\"\n".to_vec()),
        ] {
            let mut bytes = prefix.clone();
            bytes.extend(&jar);
            let path = write(&dir, name, &bytes);
            let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
            assert!(!is_error, "{name}: {text}");
            assert_eq!(json["archive_type"], "Jar");
            assert_eq!(json["counts"]["classes"], 1);
            assert!(
                json["warnings"][0]
                    .as_str()
                    .unwrap()
                    .contains("bytes into the file"),
                "{json}"
            );
        }
    }

    /// Blocker: the same bytes give the same answer under any name and in any call order.
    #[tokio::test]
    async fn answer_does_not_depend_on_file_name_or_call_order() {
        let dir = TempDir::new().unwrap();
        let manifest = axml(&[
            Some(("manifest", vec![("package", Av::Str("com.x.y"))])),
            None,
        ]);
        let apk = zip_bytes(&[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0xxxxxxxxxxxxxxxxxxxx"),
        ]);
        let jar_like = zip_bytes(&[("a/Q.class", &minimal_class("a/Q"))]);
        for (bytes, expected) in [(&apk, "Apk"), (&jar_like, "Jar")] {
            for names in [["x.jar", "x.apk", "x.class"], ["x.class", "x.apk", "x.jar"]] {
                let mcp = FileScannerMcp::new();
                let mut seen: Vec<Value> = Vec::new();
                for (i, name) in names.iter().enumerate() {
                    let path = write(&dir, &format!("{i}{name}"), bytes);
                    let (is_error, json, text) = call(&mcp, json!({"file_path": path})).await;
                    assert!(!is_error, "{text}");
                    assert_eq!(json["archive_type"], expected, "{name}");
                    seen.push(json["limitations"].clone());
                }
                assert!(seen.windows(2).all(|w| w[0] == w[1]), "{seen:?}");
            }
        }
    }

    /// view=resources lists the manifests too.
    #[tokio::test]
    async fn resources_view_includes_manifests() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let jar = zip_bytes(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("a/Q.class", &minimal_class("a/Q")),
        ]);
        let path = write(&dir, "m.jar", &jar);
        let (_, json, _) = call(
            &mcp,
            json!({"file_path": path, "view": "resources", "filter": "META-INF"}),
        )
        .await;
        assert_eq!(json["resources"]["total"], 1, "{json}");
        let (_, summary, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(summary["counts"]["entries"], 2);
        assert_eq!(summary["counts"]["resources"], 2);
    }

    /// view=manifest returns long values whole; the summary says what it cut.
    #[tokio::test]
    async fn manifest_view_returns_full_values_and_summary_marks_cuts() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let long: String = (0..900).map(|i| format!("pkg.n{i},")).collect();
        let mut text = String::from("Manifest-Version: 1.0\nMain-Class: a.Main\nExport-Package: ");
        // fold at 72 bytes like a real manifest
        let mut line = String::new();
        for c in long.chars() {
            line.push(c);
            if line.len() == 70 {
                text.push_str(&line);
                text.push_str("\n ");
                line.clear();
            }
        }
        text.push_str(&line);
        text.push_str("\n\n");
        let jar = zip_bytes(&[
            ("META-INF/MANIFEST.MF", text.as_bytes()),
            ("a/Main.class", &minimal_class("a/Main")),
        ]);
        let path = write(&dir, "long.jar", &jar);
        let (_, summary, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(
            summary["manifest"]["values_cut_at_300_chars"],
            json!(["Export-Package"]),
            "{summary}"
        );
        assert!(summary["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["arguments"]["view"] == "manifest"));
        let (is_error, full, _) = call(
            &mcp,
            json!({"file_path": path, "view": "manifest", "filter": "export"}),
        )
        .await;
        assert!(!is_error);
        assert_eq!(full["attributes"]["items"][0]["value"], long.as_str());
        let (is_error, _, text) = call(
            &mcp,
            json!({"file_path": write(&dir, "q.class", &minimal_class("a/Q")), "view": "manifest"}),
        )
        .await;
        assert!(is_error);
        assert!(text.contains("no META-INF/MANIFEST.MF"), "{text}");
    }

    /// A budget-cut page reports what it returned, so next_offset skips nothing.
    #[tokio::test]
    async fn page_counters_describe_the_rows_actually_sent() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
        for i in 0..300 {
            let mut b = ClassBuilder::new(&format!("com/example/long/package/name/Class{i}"));
            for m in 0..20 {
                b = b.method(&format!("method{m}"), "()V", 1);
            }
            owned.push((
                format!("com/example/long/package/name/Class{i}.class"),
                b.build(),
            ));
        }
        let entries: Vec<(&str, &[u8])> = owned
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let path = write(&dir, "many.jar", &zip_bytes(&entries));
        let (_, json, _) = call(
            &mcp,
            json!({"file_path": path, "view": "classes", "limit": 300, "max_output_bytes": 8000}),
        )
        .await;
        let items = json["classes"]["items"].as_array().unwrap().len();
        assert!(items > 0 && items < 300, "{items}");
        assert_eq!(json["classes"]["returned"], items);
        assert_eq!(json["classes"]["next_offset"], items);
        assert!(json.get("truncated").is_none(), "{json}");
    }

    /// A class with thousands of interface entries answers with a paged, bounded list.
    #[tokio::test]
    async fn hostile_interface_list_is_paged_and_bounded() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let big = "i".repeat(60_000);
        let mut b = ClassBuilder::new("p/I");
        for _ in 0..3000 {
            b = b.interface(&big);
        }
        let jar = zip_bytes(&[("p/I.class", &b.build())]);
        let path = write(&dir, "ifaces.jar", &jar);
        let (is_error, json, text) = call(
            &mcp,
            json!({"file_path": path, "class": "p.I", "max_output_bytes": 4000}),
        )
        .await;
        assert!(!is_error, "{text}");
        assert!(text.len() < 8_000, "{}", text.len());
        assert_eq!(json["class"]["interface_count"], 3000);
        let items = json["interfaces"]["items"].as_array().unwrap().len();
        assert_eq!(json["interfaces"]["returned"], items);
        assert_eq!(json["interfaces"]["next_offset"], items);
        assert!(!text.contains("cut 65"), "no cutter marker needed: {text}");
        let (_, summary, _) = call(&mcp, json!({"file_path": path, "view": "classes"})).await;
        assert_eq!(summary["classes"]["items"][0]["methods"], 0);
    }

    /// view=android pages every permission and component; the summary points to it.
    #[tokio::test]
    async fn android_view_pages_what_the_summary_cuts() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let names: Vec<&'static str> = (0..60)
            .map(|i| &*Box::leak(format!("android.permission.P{i}").into_boxed_str()))
            .collect();
        let acts: Vec<&'static str> = (0..25)
            .map(|i| &*Box::leak(format!("com.x.Act{i}").into_boxed_str()))
            .collect();
        let mut events = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
        for n in &names {
            events.push(Some(("uses-permission", vec![("name", Av::Str(n))])));
            events.push(None);
        }
        events.push(Some(("application", vec![])));
        for a in &acts {
            events.push(Some((
                "activity",
                vec![("name", Av::Str(a)), ("exported", Av::Bool(true))],
            )));
            events.push(None);
        }
        events.push(None);
        events.push(None);
        let apk = zip_bytes(&[
            ("AndroidManifest.xml", &axml(&events)),
            ("classes.dex", b"dex\n035\0"),
        ]);
        let path = write(&dir, "big.apk", &apk);
        let (_, summary, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(summary["android"]["permissions"]["truncated"], true);
        assert!(summary["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["arguments"]["view"] == "android"));
        let (is_error, page, text) = call(
            &mcp,
            json!({"file_path": path, "view": "android", "filter": "P59"}),
        )
        .await;
        assert!(!is_error, "{text}");
        assert_eq!(
            page["entries"]["items"][0]["name"],
            "android.permission.P59"
        );
        let (_, page, _) = call(
            &mcp,
            json!({"file_path": path, "view": "android", "filter": "act24"}),
        )
        .await;
        assert_eq!(page["entries"]["items"][0]["kind"], "activity");
        assert_eq!(page["entries"]["items"][0]["exported"], true);
        let (is_error, _, text) = call(
            &mcp,
            json!({"file_path": write(&dir, "q.class", &minimal_class("a/Q")), "view": "android"}),
        )
        .await;
        assert!(is_error);
        assert!(text.contains("no readable AndroidManifest.xml"), "{text}");
    }

    /// The findings filter matches category, API and example classes, not JSON keys.
    #[tokio::test]
    async fn findings_filter_ignores_key_names() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let jar = zip_bytes(&[(
            "com/example/Hello.class",
            &runtime_exec_class("com/example/Hello"),
        )]);
        let path = write(&dir, "app.jar", &jar);
        let (_, json, _) = call(
            &mcp,
            json!({"file_path": path, "view": "findings", "filter": "classes"}),
        )
        .await;
        assert_eq!(json["findings"]["total"], 0, "{json}");
        let (_, json, _) = call(
            &mcp,
            json!({"file_path": path, "view": "findings", "filter": "hello"}),
        )
        .await;
        assert!(json["findings"]["total"].as_u64().unwrap() >= 1);
    }

    /// view=nested lists every nested archive; the summary marks its own cut.
    #[tokio::test]
    async fn nested_view_pages_all_nested_archives() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let inner = zip_bytes(&[("a/Q.class", &minimal_class("a/Q"))]);
        let names: Vec<String> = (0..30).map(|i| format!("lib/m{i}.jar")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), inner.as_slice()))
            .collect();
        let path = write(&dir, "many.war", &zip_bytes(&entries));
        let (_, summary, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(summary["nested_archives"]["total"], 30);
        assert_eq!(summary["nested_archives"]["truncated"], true);
        let (_, page, _) = call(
            &mcp,
            json!({"file_path": path, "view": "nested", "offset": 25}),
        )
        .await;
        assert_eq!(page["nested_archives"]["returned"], 5);
    }

    /// The class view pages its dangerous-API list instead of leaving it to the cutter.
    #[tokio::test]
    async fn class_view_pages_dangerous_apis() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let mut b = ClassBuilder::new("p/S");
        for i in 0..100 {
            b = b.calls("sun/misc/Unsafe", &format!("m{i:03}"), "()V");
        }
        let path = write(&dir, "apis.jar", &zip_bytes(&[("p/S.class", &b.build())]));
        let (is_error, page, text) = call(
            &mcp,
            json!({"file_path": path, "class": "p.S", "limit": 10, "offset": 90}),
        )
        .await;
        assert!(!is_error, "{text}");
        assert_eq!(page["class"]["dangerous_api_count"], 100);
        assert_eq!(page["dangerous_apis"]["total"], 100);
        assert_eq!(page["dangerous_apis"]["returned"], 10);
        assert!(page["also_in"]["total"].as_u64() == Some(0));
        assert!(!text.contains("...[cut"), "{text}");
    }

    /// Findings name the copy of a class that makes the call, and that name opens it.
    #[tokio::test]
    async fn findings_example_classes_open_the_right_copy() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let bad = ClassBuilder::new("p/S")
            .calls("sun/misc/Unsafe", "boom", "()V")
            .build();
        let x = zip_bytes(&[("p/S.class", &minimal_class("p/S"))]);
        let y = zip_bytes(&[("p/S.class", &bad)]);
        let path = write(&dir, "v.ear", &zip_bytes(&[("x.war", &x), ("y.war", &y)]));
        let (is_error, page, text) =
            call(&mcp, json!({"file_path": path, "view": "findings"})).await;
        assert!(!is_error, "{text}");
        let example = page["findings"]["items"][0]["example_classes"][0]
            .as_str()
            .unwrap_or_else(|| panic!("{text}"))
            .to_string();
        assert_eq!(example, "y.war!p.S", "{text}");
        let (is_error, page, text) = call(&mcp, json!({"file_path": path, "class": example})).await;
        assert!(!is_error, "{text}");
        assert_eq!(page["class"]["dangerous_api_count"], 1, "{text}");
        assert_eq!(page["class"]["container"], "y.war", "{text}");
    }

    /// The same holds when the copy sits in a library whose path has slashes, as every
    /// library under WEB-INF/lib does, and for the `also_in` spelling of a copy.
    #[tokio::test]
    async fn findings_example_classes_open_a_copy_in_a_slashed_container() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let bad = ClassBuilder::new("p/S")
            .calls("sun/misc/Unsafe", "boom", "()V")
            .build();
        let x = zip_bytes(&[("p/S.class", &minimal_class("p/S"))]);
        let y = zip_bytes(&[("p/S.class", &bad)]);
        let path = write(
            &dir,
            "slash.war",
            &zip_bytes(&[("x.jar", &x), ("WEB-INF/lib/y.jar", &y)]),
        );
        let (is_error, page, text) =
            call(&mcp, json!({"file_path": path, "view": "findings"})).await;
        assert!(!is_error, "{text}");
        let example = page["findings"]["items"][0]["example_classes"][0]
            .as_str()
            .unwrap_or_else(|| panic!("{text}"))
            .to_string();
        assert_eq!(example, "WEB-INF/lib/y.jar!p.S", "{text}");
        for name in [example.as_str(), "WEB-INF/lib/y.jar!p/S.class"] {
            let (is_error, page, text) =
                call(&mcp, json!({"file_path": path, "class": name})).await;
            assert!(!is_error, "{name}: {text}");
            assert_eq!(page["class"]["dangerous_api_count"], 1, "{text}");
            assert_eq!(page["class"]["container"], "WEB-INF/lib/y.jar", "{text}");
        }
        // A container that holds no such class is named in the error with the copies that exist.
        let (is_error, _, text) = call(
            &mcp,
            json!({"file_path": path, "class": "WEB-INF/lib/z.jar!p.S"}),
        )
        .await;
        assert!(is_error, "{text}");
        assert!(text.contains("WEB-INF/lib/z.jar"), "{text}");
        assert!(text.contains("WEB-INF/lib/y.jar!p.S"), "{text}");
    }

    /// view=nested says when the rows stop short of the real count.
    #[tokio::test]
    async fn nested_view_states_the_count_when_rows_stop() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let inner = zip_bytes(&[("a/Q.class", &minimal_class("a/Q"))]);
        let names: Vec<String> = (0..5).map(|i| format!("lib/m{i}.jar")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), inner.as_slice()))
            .collect();
        let path = write(&dir, "five.war", &zip_bytes(&entries));
        let (_, page, _) = call(&mcp, json!({"file_path": path, "view": "nested"})).await;
        assert_eq!(page["nested_archives_counted"], 5);
        assert!(!page["hint"].as_str().unwrap().contains("rows stop"));
    }

    /// Under --no-cache nothing is served from memory: every call recomputes and says miss.
    #[tokio::test]
    async fn no_cache_never_answers_hit() {
        let dir = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let state = Arc::new(ServerState::new(crate::mcp_server::state::StateConfig {
            cache_dir: cache.path().join("c"),
            cache_enabled: false,
            ..crate::mcp_server::state::StateConfig::default()
        }));
        let mcp = FileScannerMcp::with_state(state);
        let path = write(
            &dir,
            "nc.jar",
            &zip_bytes(&[("p/Nc.class", &minimal_class("p/Nc"))]),
        );
        for view in ["summary", "summary", "classes"] {
            let (is_error, json, text) = call(&mcp, json!({"file_path": path, "view": view})).await;
            assert!(!is_error, "{text}");
            assert_eq!(json["cache"], "miss", "{view}: {text}");
        }
    }

    /// cache_clear also empties the in-memory store, so the next call is a miss again.
    #[tokio::test]
    async fn cache_clear_makes_the_next_call_recompute() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let path = write(
            &dir,
            "fr.jar",
            &zip_bytes(&[("p/Fr.class", &minimal_class("p/Fr"))]),
        );
        let (_, first, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(first["cache"], "miss");
        let (_, second, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(second["cache"], "hit");
        crate::mcp_server::tools_services::clear_scope(
            &mcp.state,
            crate::mcp_server::tools_services::ClearScope::Analysis,
        )
        .await
        .unwrap();
        let (_, third, _) = call(&mcp, json!({"file_path": path})).await;
        assert_eq!(third["cache"], "miss");
    }

    /// An APK whose code is only DEX is not rated Low: the code was not assessed.
    #[tokio::test]
    async fn dex_only_apk_is_not_low() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let apk = zip_bytes(&[
            ("AndroidManifest.xml", b"<manifest package=\"x.y\"/>"),
            ("classes.dex", b"dex\n035\0"),
        ]);
        let path = write(&dir, "dexonly.apk", &apk);
        for view in ["summary", "findings"] {
            let (is_error, json, text) = call(&mcp, json!({"file_path": path, "view": view})).await;
            assert!(!is_error, "{text}");
            let level = json["security"]["threat_level"]
                .as_str()
                .or_else(|| json["threat_level"].as_str());
            assert_eq!(level, Some("Medium"), "{view}: {text}");
            assert!(text.contains("not assessed"), "{view}: {text}");
            assert!(!text.contains("0 were not read"), "{view}: {text}");
        }
    }

    /// Twenty cached calls neither inflate nor parse again, and the server's memory does
    /// not grow with them.
    #[tokio::test]
    async fn cached_calls_do_not_parse_again() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let path = write(
            &dir,
            "once.jar",
            &zip_bytes(&[("p/A.class", &minimal_class("p/A"))]),
        );
        for i in 0..20 {
            let view = ["summary", "classes", "findings", "resources"][i % 4];
            let (is_error, _, text) = call(&mcp, json!({"file_path": path, "view": view})).await;
            assert!(!is_error, "{text}");
        }
        let counts = PARSE_COUNTS.lock().unwrap();
        let parsed = counts
            .iter()
            .find(|(p, _)| p.to_string_lossy().ends_with("once.jar"))
            .map_or(0, |e| e.1);
        assert_eq!(parsed, 1);
    }

    /// With all eight lists full, the call budget is shared: no list is cut by the generic
    /// cutter, and every `returned` counts the rows really sent.
    #[tokio::test]
    async fn class_view_with_eight_full_lists_stays_inside_the_budget() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let names: Vec<String> = (0..1500).map(|i| format!("p/Inner{i:04}")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut b = ClassBuilder::new("p/S").inner_classes(&name_refs);
        for i in 0..1500 {
            b = b
                .interface(&format!("p/I{i:04}"))
                .field(&format!("f{i:04}"), "I", 1)
                .method(&format!("m{i:04}"), "()V", 1)
                .refers_to(&format!("p/R{i:04}"))
                .calls("p/Q", &format!("c{i:04}"), "()V");
        }
        for i in 0..100 {
            b = b.calls("sun/misc/Unsafe", &format!("u{i:03}"), "()V");
        }
        let class = b.build();
        // The same class twice, so `also_in` has a row.
        let path = write(
            &dir,
            "eight.jar",
            &zip_bytes(&[("p/S.class", &class), ("q/S.class", &class)]),
        );
        let lists = [
            "dangerous_apis",
            "also_in",
            "interfaces",
            "inner_classes",
            "methods",
            "fields",
            "referenced_classes",
            "method_refs",
        ];
        for (limit, budget) in [(500, 4_000), (500, 80_000), (50, 80_000), (500, 12_000)] {
            let (is_error, page, text) = call(
                &mcp,
                json!({"file_path": path, "class": "p.S", "limit": limit,
                       "max_output_bytes": budget}),
            )
            .await;
            assert!(!is_error, "{text}");
            assert!(text.len() <= budget, "{} > {budget}", text.len());
            assert!(
                page.get("truncated").is_none(),
                "cut at {limit}/{budget}: {text}"
            );
            for list in lists {
                let rows = page[list]["items"].as_array().unwrap().len() as u64;
                assert_eq!(
                    page[list]["returned"].as_u64().unwrap(),
                    rows,
                    "{list} at {limit}/{budget}"
                );
                if let Some(next) = page[list]["next_offset"].as_u64() {
                    assert_eq!(next, page[list]["offset"].as_u64().unwrap() + rows);
                    if budget >= 12_000 {
                        assert!(rows > 0, "{list} empty at {limit}/{budget}");
                    }
                }
            }
        }
    }

    /// Every page's hint that names an offset names `next_offset`.
    fn assert_hints_agree(page: &Value) {
        for list in [
            "dangerous_apis",
            "also_in",
            "interfaces",
            "inner_classes",
            "methods",
            "fields",
            "referenced_classes",
            "method_refs",
        ] {
            let l = &page[list];
            if let Some(hint) = l.get("hint").and_then(Value::as_str) {
                let next = l["next_offset"].as_u64().expect("hint without next_offset");
                assert!(hint.contains(&format!("offset {next}")), "{list}: {hint}");
            }
        }
    }

    /// A class shaped like GraphManagerImpl walked at 4,000 and 5,000 bytes by the smallest
    /// next_offset: no list stalls on an empty page and every row of every list is seen.
    #[tokio::test]
    async fn class_view_walk_at_small_budgets_sees_every_row_of_every_list() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let mut b = ClassBuilder::new("p/G");
        let pad = "x".repeat(150);
        for i in 0..100 {
            let desc = format!("({})V", "I".repeat(350 + i % 7));
            b = b.method(&format!("method{i:03}"), &desc, 1);
        }
        for i in 0..300 {
            b = b.refers_to(&format!("p/{pad}/Ref{i:03}")).calls(
                "p/Q",
                &format!("call{pad}{i:03}"),
                "()V",
            );
        }
        let inner: Vec<String> = (0..240).map(|i| format!("p/G$In{i:03}")).collect();
        let inner_refs: Vec<&str> = inner.iter().map(String::as_str).collect();
        b = b.inner_classes(&inner_refs);
        let path = write(&dir, "walk.jar", &zip_bytes(&[("p/G.class", &b.build())]));
        // The true row counts: pages of 500 at a budget with room for everything.
        let lists = [
            "inner_classes",
            "methods",
            "referenced_classes",
            "method_refs",
        ];
        let mut totals = [0usize; 4];
        for (n, list) in lists.iter().enumerate() {
            let mut offset = 0u64;
            loop {
                let (_, all, _) = call(
                    &mcp,
                    json!({"file_path": path, "class": "p.G", "limit": 500,
                           "max_output_bytes": 4_000_000, "offset": offset}),
                )
                .await;
                totals[n] += all[*list]["items"].as_array().unwrap().len();
                match all[*list]["next_offset"].as_u64() {
                    Some(next) => offset = next,
                    None => break,
                }
            }
        }
        let expected = [
            (lists[0], totals[0]),
            (lists[1], totals[1]),
            (lists[2], totals[2]),
            (lists[3], totals[3]),
        ];
        assert_eq!(expected[0].1, 240);
        assert_eq!(expected[1].1, 100);
        assert!(expected[2].1 >= 300 && expected[3].1 >= 300, "{expected:?}");
        for budget in [4_000u64, 5_000] {
            let mut seen: std::collections::BTreeMap<&str, std::collections::BTreeSet<u64>> =
                std::collections::BTreeMap::new();
            let mut offset = 0u64;
            for _ in 0..5_000 {
                let (is_error, page, text) = call(
                    &mcp,
                    json!({"file_path": path, "class": "p.G", "limit": 500,
                           "max_output_bytes": budget, "offset": offset}),
                )
                .await;
                assert!(!is_error, "{text}");
                assert!(text.len() as u64 <= budget, "{} > {budget}", text.len());
                assert_hints_agree(&page);
                let mut next_min: Option<u64> = None;
                for (list, _) in expected {
                    let l = &page[list];
                    let rows = l["items"].as_array().unwrap().len() as u64;
                    if let Some(next) = l["next_offset"].as_u64() {
                        assert!(
                            next > offset,
                            "{list} stalled at {offset} ({budget} bytes): {text}"
                        );
                        next_min = Some(next_min.map_or(next, |m| m.min(next)));
                    }
                    let set = seen.entry(list).or_default();
                    for i in 0..rows {
                        set.insert(offset + i);
                    }
                }
                match next_min {
                    Some(next) => offset = next,
                    None => break,
                }
            }
            for (list, count) in expected {
                let set = &seen[list];
                assert_eq!(
                    set.len(),
                    count,
                    "{list} at {budget} bytes: rows seen {}",
                    set.len()
                );
            }
        }
    }

    /// A multi-kilobyte filter is echoed clipped, so it cannot starve the lists of bytes.
    #[tokio::test]
    async fn class_view_clips_a_long_filter_echo() {
        let dir = TempDir::new().unwrap();
        let mcp = FileScannerMcp::new();
        let class = ClassBuilder::new("p/S").method("m", "()V", 1).build();
        let path = write(
            &dir,
            "f.jar",
            &zip_bytes(&[("p/S.class", &class), ("q/S.class", &class)]),
        );
        let (is_error, page, text) = call(
            &mcp,
            json!({"file_path": path, "class": "p.S", "max_output_bytes": 4_000,
                   "filter": "x".repeat(2_500)}),
        )
        .await;
        assert!(!is_error, "{text}");
        assert!(page["filter"].as_str().unwrap().len() < 250, "{text}");
        assert!(page.get("truncated").is_none(), "{text}");
        assert_eq!(page["also_in"]["returned"], 1, "{text}");
        assert_eq!(page["also_in"]["items"].as_array().unwrap().len(), 1);
    }

    /// One 33 KB row (a method with 64 long throws) is returned when it fits what is left
    /// of the whole budget although it is larger than one list's share, and when it does
    /// not fit at all the page is empty, stays put and says what the row needs.
    #[test]
    fn fit_list_gives_a_very_large_row_the_unspent_bytes() {
        let rows = vec![
            json!({"name": "big", "throws": vec!["x".repeat(500); 64]}),
            json!({"name": "small"}),
        ];
        let big = serde_json::to_vec(&rows[0]).unwrap().len();
        assert!(big > 32_000, "{big}");
        // The default budget: share one eighth, the rest still unspent.
        let page = fit_list(&rows, 0, 500, 9_000, 78_000);
        assert!(page["returned"].as_u64().unwrap() >= 1, "{page}");
        assert_eq!(page["items"][0]["name"], "big");
        // Not enough room anywhere: no rows, no skip, honest hint.
        let page = fit_list(&rows, 0, 500, 500, 3_000);
        assert_eq!(page["returned"], 0);
        assert_eq!(page["next_offset"], 0);
        let hint = page["hint"].as_str().unwrap();
        assert!(
            hint.contains("offset 0") && hint.contains("needs about"),
            "{hint}"
        );
        assert!(!hint.contains("cut to"), "{hint}");
    }
}
