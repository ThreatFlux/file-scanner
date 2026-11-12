//! `analyze_java_file`: an overview of a Java archive or class file, then paged
//! drill-down into classes, dangerous-API findings, resources and single classes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        input_schema_with_budget, parse_request, respond_result, tool_error, DEFAULT_LIMIT,
        MAX_LIMIT,
    },
    paths::Expect,
    FileScannerMcp,
};

const ANALYZE_JAVA_DESCRIPTION: &str = "Analyze a Java archive (JAR/WAR/EAR/AAR/APK) or a class \
file; the kind is decided by the file's content, not its extension. The default call returns an \
overview: counts, Java versions, manifest main attributes, Android package/permissions/exported \
components, signature-file presence, threat level with its basis, and the top dangerous-API \
findings, plus next_steps. Then dig in with `view`: classes (paged, `filter` matches class name \
or API), findings (every dangerous API with class counts), resources (paged, `filter` on path), \
class (one class by `class` name: methods, fields, referenced classes and method calls, paged), \
manifest (every MANIFEST.MF attribute with its full value; `filter` matches the name). \
Class files are parsed for real; dangerous APIs (Runtime.exec, ProcessBuilder, reflection, class \
and native loading, network, crypto, deserialization, JNDI, scripting, Unsafe) come from the \
constant pool, and the threat level follows from them. Nested archives (AAR classes.jar, WAR \
WEB-INF/lib, EAR modules) are opened one level deep within byte caps. Not done: signatures are \
listed as 'signature files present, not verified'; classes.dex (DEX) is not parsed, so APK code \
is not assessed. Call analyze_file first if you are unsure what the file is. Results are \
compact JSON capped at `max_output_bytes` (default 80000, ceiling 400000); cut lists are \
reported under `truncated`.";

/// Cache section for the full parse of one file (keyed by the file's SHA-256).
const CACHE_KEY: &str = "java_analysis:v1";

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
                let cache = state.section_cache();
                let (result, hit) = match cache.get(&sha256, CACHE_KEY) {
                    Some(value) => match JavaAnalysisResult::deserialize(&*value) {
                        Ok(result) => (result, true),
                        Err(_) => (parse(&path)?, false),
                    },
                    None => (parse(&path)?, false),
                };
                if !hit {
                    if let Ok(value) = serde_json::to_value(&result) {
                        cache.put(&sha256, CACHE_KEY, &value);
                    }
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
    /// Every `MANIFEST.MF` main-section attribute with its full value, and Class-Path entries.
    Manifest,
}

#[derive(Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavaAnalysisRequest {
    #[schemars(
        description = "Absolute path of the Java file to analyze (JAR/WAR/EAR/APK/AAR/CLASS)"
    )]
    pub file_path: String,
    #[schemars(
        description = "What to return: summary (default), classes, findings, resources, class or manifest. \
                       Defaults to class when `class` is given."
    )]
    pub view: Option<JavaView>,
    #[schemars(
        description = "Class to describe for view=class, as named in view=classes (dots or slashes)"
    )]
    pub class: Option<String>,
    #[schemars(
        description = "Case-insensitive substring filter: class name, container or API \
                       (classes, findings, class), or entry path (resources)"
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
                    filter
                        .as_deref()
                        .is_none_or(|f| row.to_string().to_lowercase().contains(f))
                })
                .collect();
            json!({
                "view": "findings",
                "filter": request.filter,
                "threat_level": format!("{:?}", result.security_analysis.threat_level),
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
        "methods": class.methods.len(),
        "fields": class.fields.len(),
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
    let wanted = request.class.as_deref().unwrap_or("");
    let wanted = wanted.replace('/', ".");
    let wanted = wanted.strip_suffix(".class").unwrap_or(&wanted).to_string();
    let matching: Vec<&ClassInfo> = result.classes.iter().filter(|c| c.name == wanted).collect();
    let Some(class) = matching.first() else {
        let lower = wanted.to_lowercase();
        let close: Vec<&str> = result
            .classes
            .iter()
            .filter(|c| c.name.to_lowercase().contains(&lower))
            .take(5)
            .map(|c| c.name.as_str())
            .collect();
        let hint = if close.is_empty() {
            "Use view=classes with filter=<part of the name> to find it.".to_string()
        } else {
            format!("Close matches: {}.", close.join(", "))
        };
        return Err(format!(
            "No class named '{wanted}' in this file ({} classes). {hint}",
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
    let apis: Vec<Value> = class
        .dangerous_apis
        .iter()
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

    Ok(json!({
        "view": "class",
        "filter": request.filter,
        "class": {
            "name": class.name,
            "kind": kind_of(class),
            "entry": class.entry,
            "container": class.container,
            "java_version": class.java_version,
            "access": modifiers(class.access_flags, &[(0x0001, "public"), (0x0010, "final"), (0x0400, "abstract")]),
            "super": class.super_class,
            "interfaces": class.interfaces,
            "source_file": class.source_file,
            "inner_classes": class.inner_classes.iter().take(50).collect::<Vec<_>>(),
            "dangerous_apis": apis,
            "parse_warning": class.parse_warning,
        },
        "also_in": if also_in.is_empty() { Value::Null } else { json!(also_in) },
        "methods": fit_page(&methods, offset, limit, budget / 5),
        "fields": fit_page(&fields, offset, limit, budget / 5),
        "referenced_classes": fit_page(&referenced, offset, limit, budget / 5),
        "method_refs": fit_page(&calls, offset, limit, budget / 5),
        "hint": "offset and limit apply to each of the four lists; filter narrows all of them.",
    }))
}

/// One page of a list like [`super::output::page`], but it stops adding rows once the
/// serialized rows reach `budget` bytes (at least one row is always returned), so
/// `returned` and `next_offset` describe what was really sent.
fn fit_page<T: Serialize>(items: &[T], offset: usize, limit: usize, budget: usize) -> Value {
    let total = items.len();
    let limit = limit.clamp(1, MAX_LIMIT);
    let start = offset.min(total);
    let mut end = start;
    let mut used = 0usize;
    while end < total && end - start < limit {
        let size = serde_json::to_string(&items[end]).map_or(0, |text| text.len() + 1);
        if end > start && used + size > budget {
            break;
        }
        used += size;
        end += 1;
    }
    let mut out = serde_json::Map::new();
    out.insert(
        "items".into(),
        serde_json::to_value(&items[start..end]).unwrap_or(Value::Null),
    );
    out.insert("total".into(), total.into());
    out.insert("returned".into(), (end - start).into());
    out.insert("offset".into(), offset.into());
    if end < total {
        out.insert("next_offset".into(), end.into());
    }
    Value::Object(out)
}

/// Longest manifest value returned by view=manifest.
const MAX_MANIFEST_VALUE_CHARS: usize = 20_000;

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
    let rows: Vec<Value> = pairs
        .iter()
        .filter(|(name, _)| filter.is_none_or(|f| name.to_lowercase().contains(f)))
        .map(|(name, value)| {
            let length = value.chars().count();
            if length > MAX_MANIFEST_VALUE_CHARS {
                json!({
                    "name": name,
                    "value": clip(value, MAX_MANIFEST_VALUE_CHARS),
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
        "hint": "filter matches the attribute name (and Class-Path entries); offset and limit \
                 apply to both lists.",
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
    let nested_opened = result.nested_archives.iter().filter(|n| n.opened).count();
    let nested_rows: Vec<Value> = result
        .nested_archives
        .iter()
        .take(15)
        .map(|n| {
            json!({
                "path": n.path,
                "opened": n.opened,
                "classes": n.classes,
                "note": n.note,
            })
        })
        .collect();
    let largest: Vec<Value> = result
        .metadata
        .largest_entries
        .iter()
        .take(5)
        .map(|(name, size)| json!({"path": name, "size": size}))
        .collect();

    let mut next_steps: Vec<Value> = Vec::new();
    let step = |arguments: Value| {
        let mut args = json!({"file_path": path});
        if let (Value::Object(base), Value::Object(extra)) = (&mut args, arguments) {
            base.extend(extra);
        }
        json!({"tool": "analyze_java_file", "arguments": args})
    };
    if finding_total > 0 {
        next_steps.push(step(json!({"view": "findings"})));
    }
    if result.classes_total > 0 {
        next_steps.push(step(json!({"view": "classes"})));
        let target = result
            .classes
            .iter()
            .find(|c| !c.dangerous_apis.is_empty())
            .or_else(|| result.classes.first());
        if let Some(class) = target {
            next_steps.push(step(json!({"view": "class", "class": class.name})));
        }
    }
    if result.resources_total > 0 {
        next_steps.push(step(json!({"view": "resources"})));
    }
    if manifest_cut {
        next_steps.push(step(json!({"view": "manifest"})));
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
            "nested_archives": result.nested_archives.len(),
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
        "nested_archives": short_list(&nested_rows, 15),
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
            class["class"]["dangerous_apis"][0]["category"],
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
}
