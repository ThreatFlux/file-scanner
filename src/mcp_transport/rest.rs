//! REST helper routes served next to `/mcp`: health, API info, a plain
//! `initialize`/`tools/list`/`tools/call`, the analysis-cache and string-tracker
//! views, and the OpenAPI document.
//!
//! `/tools/list` and `/tools/call` go through the same tool router the MCP
//! service uses (no second dispatcher), so their side effects land in the
//! shared cache and tracker.

use std::{collections::BTreeMap, sync::Arc, time::Instant};

use axum::{
    extract::State,
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
    Router,
};
use rmcp::{
    handler::server::tool::ToolCallContext,
    model::{CallToolRequestParams, CallToolResponse, RequestId},
    service::{serve_directly, RequestContext},
    RoleServer, ServerHandler,
};
use serde::Deserialize;
use serde_json::{json, Value};
use utoipa::{OpenApi, ToSchema};

use crate::{
    cache::{AnalysisCache, CacheEntry, CacheSearchQuery},
    mcp_server::FileScannerMcp,
    string_tracker_compat::{StringFilter, StringTracker},
};

/// One served route: the single list `/api/info`, the OpenAPI document and the
/// tests all agree on.
#[derive(Debug, Clone, Copy)]
pub struct RouteInfo {
    pub method: &'static str,
    pub path: &'static str,
    pub summary: &'static str,
}

/// Every route this server answers, `/mcp` included.
pub const ROUTES: &[RouteInfo] = &[
    RouteInfo {
        method: "POST",
        path: "/mcp",
        summary:
            "MCP Streamable HTTP endpoint (JSON-RPC; GET and DELETE serve session-mode clients)",
    },
    RouteInfo {
        method: "GET",
        path: "/health",
        summary: "Health check (never needs the token)",
    },
    RouteInfo {
        method: "GET",
        path: "/api/info",
        summary: "This route list, version and uptime",
    },
    RouteInfo {
        method: "POST",
        path: "/initialize",
        summary: "Server identity, capabilities and instructions",
    },
    RouteInfo {
        method: "POST",
        path: "/tools/list",
        summary: "List the MCP tools with their input schemas",
    },
    RouteInfo {
        method: "POST",
        path: "/tools/call",
        summary: "Call an MCP tool without an MCP client",
    },
    RouteInfo {
        method: "GET",
        path: "/cache/list",
        summary: "List analysis cache entries",
    },
    RouteInfo {
        method: "POST",
        path: "/cache/search",
        summary: "Search the analysis cache",
    },
    RouteInfo {
        method: "GET",
        path: "/cache/stats",
        summary: "Analysis cache statistics",
    },
    RouteInfo {
        method: "POST",
        path: "/cache/clear",
        summary: "Clear the analysis history, cached sections and tracked strings (optional ?scope=all|analysis|strings)",
    },
    RouteInfo {
        method: "GET",
        path: "/strings/stats",
        summary: "String tracker statistics",
    },
    RouteInfo {
        method: "POST",
        path: "/strings/search",
        summary: "Search tracked strings",
    },
    RouteInfo {
        method: "POST",
        path: "/strings/details",
        summary: "Details of one tracked string",
    },
    RouteInfo {
        method: "POST",
        path: "/strings/related",
        summary: "Strings related to one string",
    },
    RouteInfo {
        method: "POST",
        path: "/strings/filter",
        summary: "String statistics for a filter",
    },
    RouteInfo {
        method: "GET",
        path: "/api-docs/openapi.json",
        summary: "OpenAPI description of the REST routes",
    },
];

/// The OpenAPI document describes the REST helper routes. `/mcp` is described by
/// the MCP specification, not here.
#[derive(OpenApi)]
#[openapi(
    paths(
        health_check,
        handle_api_info,
        handle_initialize,
        handle_tools_list,
        handle_tools_call,
        list_cache_entries,
        search_cache,
        get_cache_stats,
        clear_cache,
        get_string_stats,
        search_strings,
        handle_string_details,
        handle_strings_related,
        handle_strings_filter,
        serve_openapi
    ),
    components(schemas(
        CacheEntry,
        CacheSearchQuery,
        StringFilter,
        ToolCallParams,
        StringSearchRequest,
        StringValueRequest
    )),
    info(
        title = "File Scanner MCP API",
        description = "REST helper routes served next to the MCP endpoint (/mcp, Streamable HTTP).",
        version = "0.0.0"
    )
)]
struct ApiDoc;

/// State of the REST routes: the handler (and through it the tool router) and
/// the two shared objects the routes read.
#[derive(Clone)]
pub struct RestState {
    pub(crate) handler: FileScannerMcp,
    pub(crate) cache: Arc<AnalysisCache>,
    pub(crate) string_tracker: Arc<StringTracker>,
    started: Instant,
}

impl RestState {
    /// REST state over `handler`'s shared state (builds the cache and tracker
    /// if they do not exist yet). Uptime counts from here.
    pub fn new(handler: FileScannerMcp) -> Self {
        let cache = handler.state().analysis_cache();
        let string_tracker = handler.state().string_tracker();
        Self {
            handler,
            cache,
            string_tracker,
            started: Instant::now(),
        }
    }
}

/// The REST routes, with their state applied.
pub fn router(state: RestState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/api/info", get(handle_api_info))
        .route("/initialize", post(handle_initialize))
        .route("/tools/list", post(handle_tools_list))
        .route("/tools/call", post(handle_tools_call))
        .route("/cache/list", get(list_cache_entries))
        .route("/cache/search", post(search_cache))
        .route("/cache/stats", get(get_cache_stats))
        .route("/cache/clear", post(clear_cache))
        .route("/strings/stats", get(get_string_stats))
        .route("/strings/search", post(search_strings))
        .route("/strings/details", post(handle_string_details))
        .route("/strings/related", post(handle_strings_related))
        .route("/strings/filter", post(handle_strings_filter))
        .route("/api-docs/openapi.json", get(serve_openapi))
        .with_state(state)
}

/// `{"error": ...}` with a status, for failures a caller can act on.
fn rest_error(
    status: StatusCode,
    message: impl std::fmt::Display,
) -> (StatusCode, AxumJson<Value>) {
    (status, AxumJson(json!({ "error": message.to_string() })))
}

/// A JSON request body whose rejection (bad JSON, wrong or missing
/// `Content-Type`, wrong shape) is `{"error": ...}` JSON like every other REST
/// failure, with the status axum chose (400, 415 or 422).
struct JsonBody<T>(T);

impl<T, S> axum::extract::FromRequest<S> for JsonBody<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, AxumJson<Value>);

    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match AxumJson::<T>::from_request(request, state).await {
            Ok(AxumJson(value)) => Ok(Self(value)),
            Err(rejection) => Err(rest_error(
                rejection.status(),
                format!(
                    "{}. Send a JSON body with Content-Type: application/json.",
                    rejection.body_text()
                ),
            )),
        }
    }
}

type RestResult = Result<AxumJson<Value>, (StatusCode, AxumJson<Value>)>;

/// Body of `POST /tools/call`.
#[derive(Deserialize, ToSchema)]
pub struct ToolCallParams {
    /// Tool name, as listed by `/tools/list`.
    pub name: String,
    /// Tool arguments (an object; may be omitted for a tool without required ones).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub arguments: serde_json::Map<String, Value>,
}

/// Body of `POST /strings/search`.
#[derive(Deserialize, ToSchema)]
pub struct StringSearchRequest {
    /// Text to look for in tracked strings (default: everything).
    #[serde(default)]
    pub query: String,
    /// Most results to return (default 100).
    pub limit: Option<usize>,
}

/// Body of `POST /strings/details` and `POST /strings/related`.
#[derive(Deserialize, ToSchema)]
pub struct StringValueRequest {
    /// The string to look up.
    #[serde(default)]
    pub value: String,
    /// Most related strings to return (`/strings/related` only, default 20).
    pub limit: Option<usize>,
}

/// Call a tool through the router without an MCP client.
///
/// A protocol-level failure (unknown tool) is returned as `Err`; a tool failure
/// is a normal result with `isError: true`.
pub async fn call_tool_direct(
    handler: &FileScannerMcp,
    params: ToolCallParams,
) -> Result<Value, rmcp::ErrorData> {
    // `Peer::new` is crate-private in the SDK, so borrow a peer from a service
    // attached to nothing: the read side is at EOF and the write side discards.
    let detached = serve_directly::<RoleServer, _, _, _, _>(
        handler.clone(),
        (tokio::io::empty(), tokio::io::sink()),
        None,
    );
    let context = RequestContext::new(RequestId::Number(1), detached.peer().clone());
    let request = CallToolRequestParams::new(params.name).with_arguments(params.arguments);
    let call = ToolCallContext::new(handler, request, context);
    match handler.tool_router.call(call).await? {
        CallToolResponse::Complete(result) => serde_json::to_value(&result)
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None)),
        _ => Err(rmcp::ErrorData::internal_error(
            "the tool returned a result type this route cannot show".to_string(),
            None,
        )),
    }
}

#[utoipa::path(post, path = "/initialize", responses((status = 200, description = "Server identity, capabilities and instructions")))]
async fn handle_initialize(State(state): State<RestState>) -> AxumJson<Value> {
    let info = state.handler.get_info();
    AxumJson(json!({
        "protocolVersion": rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE,
        "serverInfo": info.server_info,
        "capabilities": info.capabilities,
        "instructions": info.instructions,
    }))
}

#[utoipa::path(post, path = "/tools/list", responses((status = 200, description = "`{jsonrpc, result: {tools: [...]}}` with each tool's input schema")))]
async fn handle_tools_list(State(state): State<RestState>) -> RestResult {
    let tools = serde_json::to_value(state.handler.tool_definitions())
        .map_err(|e| rest_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(AxumJson(json!({
        "jsonrpc": "2.0",
        "result": { "tools": tools }
    })))
}

#[utoipa::path(
    post,
    path = "/tools/call",
    request_body = ToolCallParams,
    responses(
        (status = 200, description = "The tool result: `{resultType, content: [...], isError}`; `isError` is true when the tool failed"),
        (status = 404, description = "Unknown tool. The body has the same shape as a result: `{resultType, content: [{type: \"text\", text: <what went wrong>}], isError: true}`"),
        (status = 500, description = "Internal error, same body shape as the 404")
    )
)]
async fn handle_tools_call(
    State(state): State<RestState>,
    JsonBody(params): JsonBody<ToolCallParams>,
) -> (StatusCode, AxumJson<Value>) {
    match call_tool_direct(&state.handler, params).await {
        Ok(result) => (StatusCode::OK, AxumJson(result)),
        Err(error) => {
            let status = if error.code == rmcp::model::ErrorCode::INVALID_PARAMS {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            // The same serialization as a tool result, so success and failure
            // bodies carry the same keys.
            let body = serde_json::to_value(crate::mcp_server::output::tool_error(error.message))
                .unwrap_or(Value::Null);
            (status, AxumJson(body))
        }
    }
}

#[utoipa::path(get, path = "/health", responses((status = 200, description = "`status`, `service`, `version`, `transports`")))]
async fn health_check() -> AxumJson<Value> {
    AxumJson(json!({
        "status": "ok",
        "service": "file-scanner-mcp",
        "version": env!("CARGO_PKG_VERSION"),
        "transports": ["streamable-http"]
    }))
}

#[utoipa::path(get, path = "/api-docs/openapi.json", responses((status = 200, description = "This document")))]
async fn serve_openapi() -> RestResult {
    let mut openapi = ApiDoc::openapi();
    openapi.info.version = env!("CARGO_PKG_VERSION").to_string();
    let openapi_json = serde_json::to_value(openapi)
        .map_err(|e| rest_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(AxumJson(openapi_json))
}

/// `1h 2m 3s` style duration, whole seconds.
fn format_uptime(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, rest) = (rest / 3_600, rest % 3_600);
    let (minutes, secs) = (rest / 60, rest % 60);
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if days > 0 || hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if days > 0 || hours > 0 || minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    parts.push(format!("{secs}s"));
    parts.join(" ")
}

#[utoipa::path(get, path = "/api/info", responses((status = 200, description = "Routes that exist, version, uptime")))]
async fn handle_api_info(State(state): State<RestState>) -> AxumJson<Value> {
    let endpoints: BTreeMap<&str, String> = ROUTES
        .iter()
        .map(|route| (route.path, format!("{} - {}", route.method, route.summary)))
        .collect();
    let uptime = state.started.elapsed().as_secs();
    AxumJson(json!({
        "name": "File Scanner MCP API",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "File analysis over the Model Context Protocol (Streamable HTTP at /mcp) with REST helper routes for the analysis cache and string tracker.",
        "endpoints": endpoints,
        "uptime": format_uptime(uptime),
        "uptime_seconds": uptime,
        "status": "healthy"
    }))
}

// Cache management handlers
#[utoipa::path(get, path = "/cache/list", responses((status = 200, description = "`{entries, count}`")))]
async fn list_cache_entries(State(state): State<RestState>) -> AxumJson<Value> {
    let entries = state.cache.get_all_entries().await;
    let entries = state.handler.state().visible_cache_entries(entries, None);
    AxumJson(json!({
        "entries": entries,
        "count": entries.len()
    }))
}

#[utoipa::path(post, path = "/cache/search", request_body = CacheSearchQuery, responses((status = 200, description = "`{results, count}`")))]
async fn search_cache(
    State(state): State<RestState>,
    JsonBody(query): JsonBody<CacheSearchQuery>,
) -> AxumJson<Value> {
    let rooted = !state.handler.state().allowed_roots().is_empty();
    // A rooted server matches the pattern against the path it prints.
    let results = if rooted {
        let mut stored = query.clone();
        stored.file_path_pattern = None;
        state.cache.search_entries(&stored).await
    } else {
        state.cache.search_entries(&query).await
    };
    let results = state
        .handler
        .state()
        .visible_cache_entries(results, query.file_path_pattern.as_deref());
    AxumJson(json!({
        "results": results,
        "count": results.len()
    }))
}

#[utoipa::path(get, path = "/cache/stats", responses((status = 200, description = "Entry counts, sizes and per-tool counts")))]
async fn get_cache_stats(State(state): State<RestState>) -> AxumJson<Value> {
    let stats = state.cache.get_statistics().await;
    let metadata = state.cache.get_metadata().await;
    AxumJson(json!({
        "total_entries": metadata.total_entries,
        "total_unique_files": metadata.total_unique_files,
        "cache_size_bytes": metadata.cache_size_bytes,
        "last_updated": metadata.last_updated,
        "tool_counts": stats.tool_counts,
        "file_type_counts": stats.file_type_counts,
        "total_analyses": stats.total_analyses,
        "unique_files": stats.unique_files,
        "avg_execution_time_ms": stats.avg_execution_time_ms
    }))
}

#[utoipa::path(post, path = "/cache/clear", responses((status = 200, description = "`{status, message, cleared}`")))]
async fn clear_cache(
    State(state): State<RestState>,
    axum::extract::Query(query): axum::extract::Query<BTreeMap<String, String>>,
) -> (StatusCode, AxumJson<Value>) {
    use crate::mcp_server::tools_services::{clear_scope, ClearScope};
    // The same optional scope as the cache_clear tool: all (default),
    // analysis or strings.
    let scope = match query
        .get("scope")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("" | "all") => ClearScope::All,
        Some("analysis") => ClearScope::Analysis,
        Some("strings") => ClearScope::Strings,
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(json!({
                    "status": "error",
                    "message": format!("Unknown scope '{other}': use all (default), analysis or strings")
                })),
            )
        }
    };
    match clear_scope(state.handler.state(), scope).await {
        Ok(cleared) => (
            StatusCode::OK,
            AxumJson(json!({
                "status": "success",
                "message": "Cache cleared successfully",
                "cleared": cleared
            })),
        ),
        Err(message) => (
            StatusCode::OK,
            AxumJson(json!({"status": "error", "message": message})),
        ),
    }
}

// String tracker handlers
#[utoipa::path(get, path = "/strings/stats", responses((status = 200, description = "String tracker statistics")))]
async fn get_string_stats(State(state): State<RestState>) -> AxumJson<Value> {
    let stats = state
        .handler
        .state()
        .visible_string_statistics(state.string_tracker.get_statistics(None));
    AxumJson(json!({
        "total_strings": stats.total_unique_strings,
        "total_unique_strings": stats.total_unique_strings,
        "total_occurrences": stats.total_occurrences,
        "total_files_analyzed": stats.total_files_analyzed,
        "most_common": stats.most_common,
        "suspicious_strings": stats.suspicious_strings,
        "high_entropy_strings": stats.high_entropy_strings,
        "category_distribution": stats.category_distribution,
        "length_distribution": stats.length_distribution
    }))
}

#[utoipa::path(
    post,
    path = "/strings/search",
    request_body = StringSearchRequest,
    responses((status = 200, description = "`{results, count}`"), (status = 400, description = "The query was rejected"))
)]
async fn search_strings(
    State(state): State<RestState>,
    JsonBody(request): JsonBody<StringSearchRequest>,
) -> RestResult {
    let results: Vec<_> = state
        .string_tracker
        .try_search_strings(&request.query, request.limit.unwrap_or(100))
        .map_err(|e| rest_error(StatusCode::BAD_REQUEST, e))?
        .into_iter()
        .filter_map(|entry| state.handler.state().visible_string_entry(entry))
        .collect();
    Ok(AxumJson(json!({
        "results": results,
        "count": results.len()
    })))
}

#[utoipa::path(post, path = "/strings/details", request_body = StringValueRequest, responses((status = 200, description = "The tracked string"), (status = 404, description = "`{error: \"String not found\"}`")))]
async fn handle_string_details(
    State(state): State<RestState>,
    JsonBody(request): JsonBody<StringValueRequest>,
) -> (StatusCode, AxumJson<Value>) {
    match state
        .string_tracker
        .get_string_details(&request.value)
        .and_then(|entry| state.handler.state().visible_string_entry(entry))
    {
        Some(details) => (StatusCode::OK, AxumJson(json!(details))),
        None => rest_error(StatusCode::NOT_FOUND, "String not found"),
    }
}

#[utoipa::path(
    post,
    path = "/strings/related",
    request_body = StringValueRequest,
    responses((status = 200, description = "`{related, count}`"), (status = 400, description = "The value was rejected"))
)]
async fn handle_strings_related(
    State(state): State<RestState>,
    JsonBody(request): JsonBody<StringValueRequest>,
) -> RestResult {
    let shared = state.handler.state();
    let mut related = state
        .string_tracker
        .try_get_related_strings(&request.value, request.limit.unwrap_or(20))
        .map_err(|e| rest_error(StatusCode::BAD_REQUEST, e))?;
    // Neither the asked value nor its relatives may live only outside the roots.
    if !shared.string_value_is_visible(&request.value) {
        related.clear();
    }
    related.retain(|(value, _)| shared.string_value_is_visible(value));
    Ok(AxumJson(json!({
        "related": related,
        "count": related.len()
    })))
}

#[utoipa::path(
    post,
    path = "/strings/filter",
    request_body = StringFilter,
    responses((status = 200, description = "String statistics for the filter"), (status = 400, description = "The filter was rejected (for example a bad regex)"))
)]
async fn handle_strings_filter(
    State(state): State<RestState>,
    JsonBody(filter): JsonBody<StringFilter>,
) -> RestResult {
    let stats = state
        .string_tracker
        .try_get_statistics(Some(&filter))
        .map_err(|e| rest_error(StatusCode::BAD_REQUEST, e))?;
    Ok(AxumJson(json!(state
        .handler
        .state()
        .visible_string_statistics(stats))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_is_formatted_in_whole_units() {
        assert_eq!(format_uptime(5), "5s");
        assert_eq!(format_uptime(65), "1m 5s");
        assert_eq!(format_uptime(3_725), "1h 2m 5s");
        assert_eq!(format_uptime(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn openapi_paths_are_exactly_the_rest_routes() {
        let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let documented: std::collections::BTreeSet<String> = document["paths"]
            .as_object()
            .unwrap()
            .iter()
            .flat_map(|(path, item)| {
                item.as_object()
                    .unwrap()
                    .keys()
                    .map(|method| format!("{} {path}", method.to_uppercase()))
                    .collect::<Vec<_>>()
            })
            .collect();
        let served: std::collections::BTreeSet<String> = ROUTES
            .iter()
            .filter(|route| route.path != "/mcp")
            .map(|route| format!("{} {}", route.method, route.path))
            .collect();
        assert_eq!(documented, served);
    }
}
