//! The axum application: the SDK's Streamable HTTP service at `/mcp` next to
//! the REST routes, behind one guard.
//!
//! What protects the server, outermost first:
//!
//! 1. [`gate`]: the `Host` header must be a loopback name or an `--allowed-host`
//!    (DNS rebinding), and an `Origin` header, when present, must be a loopback
//!    origin or an `--allowed-origin` (403 otherwise). Every route is covered,
//!    REST routes included.
//! 2. The CORS layer: answers preflights for allowed origins only, exposes
//!    `Mcp-Session-Id`, never uses a wildcard.
//! 3. [`authenticate`]: when a bearer token is configured, every route except
//!    `/health` needs `Authorization: Bearer <token>` (401 and `WWW-Authenticate`
//!    otherwise). The comparison is constant time. Preflights pass, because
//!    browsers do not send credentials on them.
//! 4. The REST routes only: a concurrency limit and a request timeout. `/mcp`
//!    carries long-lived streams and is bounded by the SDK instead.
//!
//! The SDK's own Host and Origin checks are configured with the same lists, so
//! they still hold if the service is ever mounted without the guard.
//!
//! `/mcp` runs the SDK's default mode: sessions (`Mcp-Session-Id`) for clients
//! older than revision 2026-07-28, stateless requests for 2026-07-28 and later.
//!
//! One [`CancellationToken`] is shared by the SDK config and axum's graceful
//! shutdown; cancelling it ends open streams and lets the server stop.

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{Request, State},
    http::{
        header::{
            HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN,
            WWW_AUTHENTICATE,
        },
        uri::Authority,
        HeaderMap, Method, StatusCode, Uri,
    },
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowOrigin, CorsLayer};

use super::rest::{self, RestState};
use crate::mcp_server::FileScannerMcp;

/// Port used when none is given.
pub const DEFAULT_PORT: u16 = 3000;
/// Address bound when none is given.
pub const DEFAULT_HOST: &str = "127.0.0.1";
/// Environment variable that supplies the bearer token.
pub const AUTH_TOKEN_ENV: &str = "FILE_SCANNER_AUTH_TOKEN";

/// Host names that are always allowed (the SDK's own defaults).
const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Realm named in `WWW-Authenticate`.
const AUTH_REALM: &str = "file-scanner";

/// Settings of the HTTP server.
#[derive(Clone)]
pub struct HttpConfig {
    /// Address to bind (an IP address or a name; default `127.0.0.1`).
    pub host: String,
    /// Port to bind (`0` picks a free one).
    pub port: u16,
    /// Host header values accepted besides the loopback names (`name` or
    /// `name:port`).
    pub allowed_hosts: Vec<String>,
    /// Origins accepted besides loopback ones (`scheme://host[:port|:*]`, or
    /// `null`).
    pub allowed_origins: Vec<String>,
    /// Bearer token required on every route except `/health`.
    pub auth_token: Option<String>,
    /// Longest a REST request may take, wait for a free slot included.
    pub rest_timeout: Duration,
    /// REST requests served at the same time; further ones wait.
    pub rest_concurrency: usize,
    /// How long shutdown waits for open connections before giving up on them.
    pub shutdown_grace: Duration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            auth_token: None,
            rest_timeout: Duration::from_secs(120),
            rest_concurrency: 16,
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field("rest_timeout", &self.rest_timeout)
            .field("rest_concurrency", &self.rest_concurrency)
            .field("shutdown_grace", &self.shutdown_grace)
            .finish()
    }
}

impl HttpConfig {
    /// Defaults on `port`.
    pub fn on_port(port: u16) -> Self {
        Self {
            port,
            ..Self::default()
        }
    }

    /// Whether the bind address is loopback only.
    pub fn binds_loopback(&self) -> bool {
        let host = self.bind_host();
        host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// The host without the brackets of an IPv6 literal.
    fn bind_host(&self) -> &str {
        let host = self
            .host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        // `localhost` can resolve to ::1 first, which would refuse 127.0.0.1
        // (the address clients and the docs use); bind the IPv4 loopback.
        if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1"
        } else {
            host
        }
    }

    /// Check every setting; the message names the setting and the fix.
    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            bail!("--host is empty; pass an address such as 127.0.0.1 or 0.0.0.0");
        }
        if let Some(token) = &self.auth_token {
            if token.is_empty() {
                bail!(
                    "the auth token is empty; pass a non-empty --auth-token or set \
                     {AUTH_TOKEN_ENV}"
                );
            }
            if token.chars().any(|c| c.is_control() || c.is_whitespace()) {
                bail!("the auth token must not contain whitespace or control characters");
            }
        }
        if self.rest_concurrency == 0 {
            bail!("the REST concurrency limit must be at least 1");
        }
        Guard::new(self).map(drop).map_err(anyhow::Error::msg)
    }
}

// ---------------------------------------------------------------------------
// Host and Origin rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostRule {
    host: String,
    port: Option<u16>,
}

impl HostRule {
    fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        let invalid = || {
            format!(
                "invalid --allowed-host {raw:?}: expected a host name or address, optionally \
                 with a port (example.com, example.com:3000, 10.0.0.5)"
            )
        };
        if trimmed.is_empty() || trimmed.contains("://") || trimmed.contains('/') {
            return Err(invalid());
        }
        // A bare IPv6 address has several colons and no brackets.
        if !trimmed.starts_with('[') && trimmed.matches(':').count() > 1 {
            return trimmed
                .parse::<IpAddr>()
                .map(|ip| Self {
                    host: ip.to_string(),
                    port: None,
                })
                .map_err(|_| invalid());
        }
        let authority = Authority::from_str(trimmed).map_err(|_| invalid())?;
        Ok(Self {
            host: normalize_host(authority.host()),
            port: authority.port_u16(),
        })
    }

    fn matches(&self, host: &str, port: Option<u16>) -> bool {
        self.host == host && self.port.is_none_or(|expected| Some(expected) == port)
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn is_loopback_name(host: &str) -> bool {
    LOOPBACK_HOSTS.contains(&host)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortRule {
    Any,
    Exact(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginRule {
    /// The literal `Origin: null`.
    Null,
    Exact {
        scheme: String,
        host: String,
        port: PortRule,
    },
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

impl OriginRule {
    fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed == "null" {
            return Ok(Self::Null);
        }
        let invalid = || {
            format!(
                "invalid --allowed-origin {raw:?}: expected scheme://host[:port], for example \
                 https://app.example.com or http://localhost:*, or the word null"
            )
        };
        let (scheme, rest) = trimmed.split_once("://").ok_or_else(invalid)?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(invalid());
        }
        let rest = rest.trim_end_matches('/');
        let (authority_text, port) = match rest.strip_suffix(":*") {
            Some(without) => (without, PortRule::Any),
            None => (rest, PortRule::Exact(0)),
        };
        if authority_text.is_empty() || authority_text.contains('/') || authority_text == "*" {
            return Err(invalid());
        }
        let authority = Authority::from_str(authority_text).map_err(|_| invalid())?;
        let port = match port {
            PortRule::Any => PortRule::Any,
            PortRule::Exact(_) => PortRule::Exact(
                authority
                    .port_u16()
                    .unwrap_or_else(|| default_port(&scheme)),
            ),
        };
        Ok(Self::Exact {
            scheme,
            host: normalize_host(authority.host()),
            port,
        })
    }

    /// The spelling the SDK's own allow-list understands.
    fn for_sdk(&self) -> String {
        match self {
            Self::Null => "null".to_string(),
            Self::Exact { scheme, host, port } => {
                let host = if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.clone()
                };
                match port {
                    PortRule::Any => format!("{scheme}://{host}:*"),
                    PortRule::Exact(port) => format!("{scheme}://{host}:{port}"),
                }
            }
        }
    }
}

/// The parsed pieces of an `Origin` header value.
struct OriginParts {
    scheme: String,
    host: String,
    port: u16,
}

fn parse_origin_header(value: &str) -> Option<OriginParts> {
    let uri: Uri = value.trim().parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    // An origin has no path, query or user information.
    if uri.path_and_query().is_some_and(|pq| pq.as_str() != "/") {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = normalize_host(authority.host());
    let port = authority
        .port_u16()
        .unwrap_or_else(|| default_port(&scheme));
    Some(OriginParts { scheme, host, port })
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// The request policy: Host and Origin rules, and the optional token.
pub struct Guard {
    hosts: Vec<HostRule>,
    origins: Vec<OriginRule>,
    /// HMAC-SHA-256 of the token under a fixed key; a presented token is
    /// tagged the same way and verified in constant time, so neither the
    /// content nor the length of the secret shows in the timing.
    token_tag: Option<ring::hmac::Tag>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("hosts", &self.hosts)
            .field("origins", &self.origins)
            .field("token", &self.token_tag.as_ref().map(|_| "<set>"))
            .finish()
    }
}

impl Guard {
    /// Build the policy from the configuration; the error names the bad setting.
    pub fn new(config: &HttpConfig) -> Result<Self, String> {
        let hosts = config
            .allowed_hosts
            .iter()
            .map(|raw| HostRule::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;
        let origins = config
            .allowed_origins
            .iter()
            .map(|raw| OriginRule::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;
        let token_tag = config
            .auth_token
            .as_ref()
            .map(|token| ring::hmac::sign(&tag_key(), token.as_bytes()));
        Ok(Self {
            hosts,
            origins,
            token_tag,
        })
    }

    /// Whether a bearer token is required.
    pub const fn requires_token(&self) -> bool {
        self.token_tag.is_some()
    }

    /// Host names for the SDK's allow-list.
    fn sdk_hosts(&self, config: &HttpConfig) -> Vec<String> {
        LOOPBACK_HOSTS
            .iter()
            .map(|name| (*name).to_string())
            .chain(
                config
                    .allowed_hosts
                    .iter()
                    .map(|raw| raw.trim().to_string()),
            )
            .collect()
    }

    /// Origins for the SDK's allow-list: loopback on any port, plus the listed ones.
    fn sdk_origins(&self) -> Vec<String> {
        let mut list = Vec::new();
        for scheme in ["http", "https"] {
            for host in ["localhost", "127.0.0.1", "[::1]"] {
                list.push(format!("{scheme}://{host}:*"));
            }
        }
        list.extend(self.origins.iter().map(OriginRule::for_sdk));
        list
    }

    /// Whether the request's host (name and port) is allowed.
    fn host_allowed(&self, host: &str, port: Option<u16>) -> bool {
        is_loopback_name(host) || self.hosts.iter().any(|rule| rule.matches(host, port))
    }

    /// Whether an `Origin` header value is allowed.
    pub fn origin_allowed(&self, value: &str) -> bool {
        if value.trim() == "null" {
            return self.origins.contains(&OriginRule::Null);
        }
        let Some(origin) = parse_origin_header(value) else {
            return false;
        };
        if is_loopback_name(&origin.host) {
            return true;
        }
        self.origins.iter().any(|rule| match rule {
            OriginRule::Null => false,
            OriginRule::Exact { scheme, host, port } => {
                *scheme == origin.scheme
                    && *host == origin.host
                    && match port {
                        PortRule::Any => true,
                        PortRule::Exact(expected) => *expected == origin.port,
                    }
            }
        })
    }

    /// Constant-time comparison of a presented token with the configured one.
    fn token_matches(&self, presented: &str) -> bool {
        self.token_tag.as_ref().is_some_and(|expected| {
            ring::hmac::verify(&tag_key(), presented.as_bytes(), expected.as_ref()).is_ok()
        })
    }
}

/// The fixed key of the token tag. It is not a secret: it only turns the
/// token into a fixed-length value that `ring::hmac::verify` compares in
/// constant time.
fn tag_key() -> ring::hmac::Key {
    ring::hmac::Key::new(
        ring::hmac::HMAC_SHA256,
        b"file-scanner bearer token comparison",
    )
}

/// The host and port a request was addressed to: the `Host` header, or the
/// request-target authority when the header is absent.
fn request_authority(uri: &Uri, headers: &HeaderMap) -> Option<(String, Option<u16>)> {
    match headers.get(HOST) {
        Some(value) => {
            let authority: Authority = value.to_str().ok()?.parse().ok()?;
            Some((normalize_host(authority.host()), authority.port_u16()))
        }
        None => uri
            .authority()
            .map(|authority| (normalize_host(authority.host()), authority.port_u16())),
    }
}

fn plain(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

/// One stderr line for a refused request: method, path (no query) and reason.
/// Never the token or any header value that could carry it.
fn log_refusal(request: &Request, status: StatusCode, reason: &str) {
    eprintln!(
        "file-scanner: refused {} {:?} ({}): {reason}",
        request.method(),
        request.uri().path(),
        status.as_u16()
    );
}

/// Host and Origin check on every request (403 when either is not allowed).
pub async fn gate(State(guard): State<Arc<Guard>>, request: Request, next: Next) -> Response {
    let Some((host, port)) = request_authority(request.uri(), request.headers()) else {
        return plain(
            StatusCode::BAD_REQUEST,
            "Bad Request: missing or invalid Host header",
        );
    };
    if !guard.host_allowed(&host, port) {
        log_refusal(
            &request,
            StatusCode::FORBIDDEN,
            &format!("Host {host:?} is not allowed"),
        );
        return plain(
            StatusCode::FORBIDDEN,
            "Forbidden: Host header is not allowed (start the server with --allowed-host <name> \
             to serve this name)",
        );
    }
    if let Some(origin) = request.headers().get(ORIGIN) {
        if !origin
            .to_str()
            .is_ok_and(|value| guard.origin_allowed(value))
        {
            log_refusal(
                &request,
                StatusCode::FORBIDDEN,
                &format!("Origin {origin:?} is not allowed"),
            );
            return plain(
                StatusCode::FORBIDDEN,
                "Forbidden: Origin header is not allowed (start the server with \
                 --allowed-origin <origin> to allow it)",
            );
        }
    }
    next.run(request).await
}

fn unauthorized(detail: Option<&str>) -> Response {
    let challenge = detail.map_or_else(
        || format!("Bearer realm=\"{AUTH_REALM}\""),
        |detail| format!("Bearer realm=\"{AUTH_REALM}\", {detail}"),
    );
    let mut response = (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "unauthorized",
            "message": "Send the server's token as 'Authorization: Bearer <token>'.",
        })),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim_start())
}

fn is_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request.headers().contains_key(ORIGIN)
        && request
            .headers()
            .contains_key("access-control-request-method")
}

/// Bearer-token check (a no-op when no token is configured).
pub async fn authenticate(
    State(guard): State<Arc<Guard>>,
    request: Request,
    next: Next,
) -> Response {
    if !guard.requires_token() || request.uri().path() == "/health" || is_preflight(&request) {
        return next.run(request).await;
    }
    match bearer_token(request.headers()) {
        None => {
            log_refusal(&request, StatusCode::UNAUTHORIZED, "no bearer token sent");
            unauthorized(None)
        }
        Some(token) if guard.token_matches(token) => next.run(request).await,
        Some(_) => {
            log_refusal(
                &request,
                StatusCode::UNAUTHORIZED,
                "bearer token does not match",
            );
            unauthorized(Some("error=\"invalid_token\""))
        }
    }
}

// ---------------------------------------------------------------------------
// REST limits
// ---------------------------------------------------------------------------

/// Concurrency limit and timeout of the REST routes.
pub struct RestLimits {
    slots: Semaphore,
    timeout: Duration,
    /// Cancelled when the server is asked to stop.
    shutdown: CancellationToken,
}

impl RestLimits {
    fn new(config: &HttpConfig, shutdown: CancellationToken) -> Self {
        Self {
            slots: Semaphore::new(config.rest_concurrency),
            timeout: config.rest_timeout,
            shutdown,
        }
    }
}

/// Wait for a free slot, run the request, and answer 504 when the whole thing
/// takes longer than the timeout. When the server is shutting down the request
/// stops waiting and gets a 503, so a graceful shutdown does not wait for it. A
/// tool call already running keeps running in its blocking thread; only the
/// HTTP answer is given up.
async fn limit_rest(
    State(limits): State<Arc<RestLimits>>,
    request: Request,
    next: Next,
) -> Response {
    let work = async {
        // The semaphore is never closed.
        let _slot = limits.slots.acquire().await;
        next.run(request).await
    };
    let outcome = tokio::select! {
        outcome = tokio::time::timeout(limits.timeout, work) => outcome,
        () = limits.shutdown.cancelled() => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({"error": "shutting down"})),
            )
                .into_response();
        }
    };
    match outcome {
        Ok(response) => response,
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            axum::Json(serde_json::json!({
                "error": "timeout",
                "message": format!(
                    "The request took longer than {} seconds. Ask for less (a smaller section or \
                     a lower limit) or use the MCP endpoint.",
                    limits.timeout.as_secs()
                ),
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// The application
// ---------------------------------------------------------------------------

fn cors_layer(guard: Arc<Guard>) -> CorsLayer {
    let header = HeaderName::from_static;
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            origin
                .to_str()
                .is_ok_and(|value| guard.origin_allowed(value))
        }))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            CONTENT_TYPE,
            ACCEPT,
            AUTHORIZATION,
            header("mcp-session-id"),
            header("mcp-protocol-version"),
            header("last-event-id"),
            // Revision 2026-07-28 standard request headers.
            header("mcp-method"),
            header("mcp-name"),
        ])
        // Without these a browser client cannot read the session id of the
        // initialize response or the challenge of a 401.
        .expose_headers([header("mcp-session-id"), WWW_AUTHENTICATE])
        .max_age(Duration::from_secs(600))
}

/// Build the application. `shutdown` ends open streams when cancelled and must
/// be the token that also ends `axum::serve`.
///
/// The factory clones one shared handler, so every session (and every
/// stateless request) sees the same cache, string tracker and tool router, and
/// so do the REST routes.
pub fn build_app(
    handler: FileScannerMcp,
    config: &HttpConfig,
    shutdown: CancellationToken,
) -> Result<Router> {
    let guard = Arc::new(Guard::new(config).map_err(anyhow::Error::msg)?);

    let mcp_config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(guard.sdk_hosts(config))
        .with_allowed_origins(guard.sdk_origins())
        .with_cancellation_token(shutdown.clone());
    let shared = handler.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(shared.clone()),
        Arc::new(LocalSessionManager::default()),
        mcp_config,
    );

    // The limits wrap the REST routes only: `/mcp` is added after the layer.
    let limits = Arc::new(RestLimits::new(config, shutdown.clone()));
    let routes = rest::router(RestState::new(handler))
        .layer(from_fn_with_state(limits, limit_rest))
        .route_service("/mcp", mcp);

    // A layer added later wraps the earlier ones: the gate runs first, then
    // CORS (which answers preflights), then the token check.
    Ok(routes
        .layer(from_fn_with_state(Arc::clone(&guard), authenticate))
        .layer(cors_layer(Arc::clone(&guard)))
        .layer(from_fn_with_state(guard, gate)))
}

// ---------------------------------------------------------------------------
// Binding, banner and serving
// ---------------------------------------------------------------------------

/// A bound listener with its application, ready to serve.
pub struct BoundServer {
    listener: TcpListener,
    app: Router,
    shutdown: CancellationToken,
    grace: Duration,
}

impl BoundServer {
    /// Bind the address of `config` and build the application.
    pub async fn bind(
        handler: FileScannerMcp,
        config: &HttpConfig,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        config.validate()?;
        let app = build_app(handler, config, shutdown.clone())?;
        let listener = TcpListener::bind((config.bind_host(), config.port))
            .await
            .with_context(|| {
                format!(
                    "cannot listen on {}:{} (is the port already in use? pick another with \
                     --port)",
                    config.host, config.port
                )
            })?;
        Ok(Self {
            listener,
            app,
            shutdown,
            grace: config.shutdown_grace,
        })
    }

    /// The address actually bound (the port is real even when 0 was asked for).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The token that stops the server when cancelled.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Serve until the token is cancelled, then give open connections the
    /// grace period and return.
    pub async fn serve(self) -> Result<()> {
        let Self {
            listener,
            app,
            shutdown,
            grace,
        } = self;
        let stopping = shutdown.clone();
        let server = axum::serve(listener, app)
            .with_graceful_shutdown(async move { stopping.cancelled_owned().await });
        tokio::select! {
            result = server => result.map_err(Into::into),
            () = async {
                shutdown.cancelled().await;
                tokio::time::sleep(grace).await;
            } => {
                eprintln!(
                    "file-scanner: shutdown grace period ({}s) elapsed, closing the remaining \
                     connections",
                    grace.as_secs()
                );
                Ok(())
            }
        }
    }
}

/// Resolves when the process receives SIGINT or SIGTERM (Ctrl-C only, off Unix).
/// Registers the SIGINT and SIGTERM handlers now (not on first poll) and returns the future
/// that resolves when either arrives, so a signal sent early is not lost.
pub fn arm_shutdown_signal() -> impl std::future::Future<Output = ()> + Send + 'static {
    #[cfg(unix)]
    let streams = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::terminate()).ok(),
            signal(SignalKind::interrupt()).ok(),
        )
    };
    async move {
        #[cfg(unix)]
        {
            let (terminate, interrupt) = streams;
            match (terminate, interrupt) {
                (Some(mut t), Some(mut i)) => {
                    tokio::select! { _ = t.recv() => {} _ = i.recv() => {} }
                }
                (Some(mut t), None) => {
                    tokio::select! { _ = t.recv() => {} _ = tokio::signal::ctrl_c() => {} }
                }
                (None, Some(mut i)) => {
                    i.recv().await;
                }
                (None, None) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Warnings to print before the banner (empty for a safe configuration).
pub fn startup_warnings(config: &HttpConfig, allow_roots: &[std::path::PathBuf]) -> Vec<String> {
    let mut warnings = Vec::new();
    if !config.binds_loopback() && config.auth_token.is_none() {
        warnings.push(format!(
            "warning: listening on {} without a bearer token. Anyone who can reach this port can \
             read every file this server's user can read. Set --auth-token (or {AUTH_TOKEN_ENV}) \
             and limit the files with --allow-root <dir>.",
            config.host
        ));
    } else if !config.binds_loopback() && allow_roots.is_empty() {
        warnings.push(
            "warning: no --allow-root is set, so authenticated callers can read every file this \
             server's user can read."
                .to_string(),
        );
    }
    if !config.binds_loopback() && config.allowed_hosts.is_empty() {
        warnings.push(format!(
            "warning: listening on {} but only localhost, 127.0.0.1 and ::1 are accepted as the \
             Host header, so remote clients get 403. Add --allowed-host <name or address> for \
             each name or address clients use to reach this server.",
            config.host
        ));
    }
    for root in allow_roots {
        if !root.exists() {
            warnings.push(format!(
                "warning: --allow-root {} does not exist, so nothing under it can be read.",
                root.display()
            ));
        }
    }
    warnings
}

/// The startup banner: the real bind address and which protections are active.
pub fn banner(
    config: &HttpConfig,
    address: SocketAddr,
    allow_roots: &[std::path::PathBuf],
) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "file-scanner {} MCP HTTP server listening on http://{address}/mcp",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        text,
        "  REST helpers on the same address: /health, /api/info, /tools/list, /tools/call, \
         /cache/*, /strings/*, /api-docs/openapi.json"
    );
    let mut hosts = LOOPBACK_HOSTS.join(", ");
    for host in &config.allowed_hosts {
        let _ = write!(hosts, ", {}", host.trim());
    }
    let _ = writeln!(text, "  Host allow-list: {hosts}");
    let mut origins = "loopback origins".to_string();
    for origin in &config.allowed_origins {
        let _ = write!(origins, ", {}", origin.trim());
    }
    let _ = writeln!(text, "  Origin check: {origins}; no CORS wildcard");
    let _ = writeln!(
        text,
        "  Bearer token: {}",
        if config.auth_token.is_some() {
            "required on every route except /health"
        } else {
            "not set"
        }
    );
    if allow_roots.is_empty() {
        let _ = writeln!(text, "  File access: unrestricted (no --allow-root)");
    } else {
        let roots = allow_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(text, "  File access: limited to {roots}");
    }
    let _ = writeln!(
        text,
        "  REST limits: {} at a time, {}s timeout",
        config.rest_concurrency,
        config.rest_timeout.as_secs()
    );
    let _ = write!(text, "  Stop with Ctrl-C or SIGTERM");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard_with(hosts: &[&str], origins: &[&str], token: Option<&str>) -> Guard {
        Guard::new(&HttpConfig {
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            allowed_origins: origins.iter().map(ToString::to_string).collect(),
            auth_token: token.map(ToString::to_string),
            ..HttpConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn loopback_hosts_are_always_allowed() {
        let guard = guard_with(&[], &[], None);
        for (host, port) in [
            ("localhost", Some(3000)),
            ("127.0.0.1", None),
            ("::1", Some(1)),
        ] {
            assert!(guard.host_allowed(host, port), "{host}");
        }
        assert!(!guard.host_allowed("evil.example", Some(3000)));
        assert!(!guard.host_allowed("192.168.1.5", Some(3000)));
    }

    #[test]
    fn listed_hosts_match_with_and_without_a_port() {
        let guard = guard_with(
            &["scanner.internal", "Other.Example:8080", "::2"],
            &[],
            None,
        );
        assert!(guard.host_allowed("scanner.internal", Some(3000)));
        assert!(guard.host_allowed("other.example", Some(8080)));
        assert!(!guard.host_allowed("other.example", Some(9090)));
        assert!(!guard.host_allowed("other.example", None));
        assert!(guard.host_allowed("::2", Some(3000)));
    }

    #[test]
    fn bad_host_and_origin_entries_are_rejected_with_the_fix() {
        for entry in ["", "http://example.com", "example.com/path"] {
            let error = HostRule::parse(entry).unwrap_err();
            assert!(error.contains("--allowed-host"), "{entry}: {error}");
        }
        for entry in [
            "example.com",
            "ftp://example.com",
            "https://",
            "https://*",
            "*",
        ] {
            let error = OriginRule::parse(entry).unwrap_err();
            assert!(error.contains("--allowed-origin"), "{entry}: {error}");
        }
    }

    #[test]
    fn loopback_origins_pass_on_any_port_and_foreign_ones_do_not() {
        let guard = guard_with(&[], &[], None);
        for origin in [
            "http://localhost",
            "http://localhost:6274",
            "http://127.0.0.1:38500",
            "http://[::1]:38500",
            "https://LOCALHOST:8443",
        ] {
            assert!(guard.origin_allowed(origin), "{origin}");
        }
        for origin in [
            "null",
            "",
            "http://evil.example",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example:38500",
            "file:///etc/passwd",
            "http://localhost:6274/path",
            "http://user@localhost",
            "chrome-extension://abc",
        ] {
            assert!(!guard.origin_allowed(origin), "{origin:?}");
        }
    }

    #[test]
    fn listed_origins_match_scheme_host_and_port() {
        let guard = guard_with(
            &[],
            &["https://app.example.com", "http://tools.example:*", "null"],
            None,
        );
        assert!(guard.origin_allowed("https://app.example.com"));
        assert!(guard.origin_allowed("https://app.example.com:443"));
        assert!(!guard.origin_allowed("http://app.example.com"));
        assert!(!guard.origin_allowed("https://app.example.com:8443"));
        assert!(guard.origin_allowed("http://tools.example:9000"));
        assert!(!guard.origin_allowed("https://tools.example:9000"));
        assert!(guard.origin_allowed("null"));
        assert!(!guard_with(&[], &[], None).origin_allowed("null"));
    }

    #[test]
    fn sdk_allow_lists_carry_the_same_entries() {
        let guard = guard_with(&["a.example"], &["https://app.example.com"], None);
        let config = HttpConfig {
            allowed_hosts: vec!["a.example".into()],
            ..HttpConfig::default()
        };
        let hosts = guard.sdk_hosts(&config);
        assert!(hosts.contains(&"a.example".to_string()));
        assert!(hosts.contains(&"::1".to_string()));
        let origins = guard.sdk_origins();
        assert!(origins.contains(&"https://app.example.com:443".to_string()));
        assert!(origins.contains(&"http://localhost:*".to_string()));
        assert!(origins.contains(&"https://[::1]:*".to_string()));
    }

    #[test]
    fn token_comparison_accepts_only_the_exact_token() {
        let guard = guard_with(&[], &[], Some("s3cret-token"));
        assert!(guard.requires_token());
        assert!(guard.token_matches("s3cret-token"));
        for wrong in ["", "s3cret-toke", "s3cret-token ", "S3CRET-TOKEN", "x"] {
            assert!(!guard.token_matches(wrong), "{wrong:?}");
        }
        assert!(!guard_with(&[], &[], None).requires_token());
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_required() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("bearer abc"));
        assert_eq!(bearer_token(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), None);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("abc"));
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn validate_names_the_bad_setting() {
        let empty_token = HttpConfig {
            auth_token: Some(String::new()),
            ..HttpConfig::default()
        };
        assert!(empty_token
            .validate()
            .unwrap_err()
            .to_string()
            .contains("--auth-token"));
        let bad_origin = HttpConfig {
            allowed_origins: vec!["example.com".into()],
            ..HttpConfig::default()
        };
        assert!(bad_origin
            .validate()
            .unwrap_err()
            .to_string()
            .contains("--allowed-origin"));
        assert!(HttpConfig::default().validate().is_ok());
    }

    fn slow_app(limits: RestLimits) -> Router {
        use axum::routing::get;
        Router::new()
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    "done"
                }),
            )
            .layer(from_fn_with_state(Arc::new(limits), limit_rest))
    }

    fn get_slow() -> Request {
        Request::builder()
            .uri("/slow")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_slow_rest_request_gets_a_504_that_says_what_to_do() {
        use tower::ServiceExt;
        let config = HttpConfig {
            rest_timeout: Duration::from_millis(30),
            ..HttpConfig::default()
        };
        let response = slow_app(RestLimits::new(&config, CancellationToken::new()))
            .oneshot(get_slow())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("longer than"));
    }

    #[tokio::test]
    async fn a_rest_request_in_flight_gets_a_503_when_the_server_shuts_down() {
        use tower::ServiceExt;
        let config = HttpConfig {
            rest_timeout: Duration::from_secs(30),
            ..HttpConfig::default()
        };
        let token = CancellationToken::new();
        let app = slow_app(RestLimits::new(&config, token.clone()));
        let stopper = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stopper.cancel();
        });
        let started = std::time::Instant::now();
        let response = app.oneshot(get_slow()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            started.elapsed() < Duration::from_millis(120),
            "{:?}",
            started.elapsed()
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"error":"shutting down"}"#);
    }

    #[tokio::test]
    async fn the_rest_concurrency_limit_makes_extra_requests_wait() {
        use tower::ServiceExt;
        let config = HttpConfig {
            rest_concurrency: 1,
            rest_timeout: Duration::from_secs(10),
            ..HttpConfig::default()
        };
        let app = slow_app(RestLimits::new(&config, CancellationToken::new()));
        let started = std::time::Instant::now();
        let (a, b) = tokio::join!(app.clone().oneshot(get_slow()), app.oneshot(get_slow()));
        assert_eq!(a.unwrap().status(), StatusCode::OK);
        assert_eq!(b.unwrap().status(), StatusCode::OK);
        assert!(
            started.elapsed() >= Duration::from_millis(290),
            "one at a time: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn localhost_binds_the_ipv4_loopback() {
        // `localhost` may resolve to ::1 first; clients and docs use 127.0.0.1.
        let config = HttpConfig {
            host: "LocalHost".to_string(),
            ..HttpConfig::default()
        };
        assert_eq!(config.bind_host(), "127.0.0.1");
        assert!(config.binds_loopback());
    }

    #[test]
    fn loopback_binds_are_recognised() {
        for (host, loopback) in [
            ("127.0.0.1", true),
            ("localhost", true),
            ("::1", true),
            ("[::1]", true),
            ("0.0.0.0", false),
            ("192.168.1.5", false),
            ("::", false),
            ("scanner.internal", false),
        ] {
            let config = HttpConfig {
                host: host.to_string(),
                ..HttpConfig::default()
            };
            assert_eq!(config.binds_loopback(), loopback, "{host}");
        }
    }

    #[test]
    fn warnings_cover_an_open_bind_and_a_missing_root() {
        let open = HttpConfig {
            host: "0.0.0.0".into(),
            ..HttpConfig::default()
        };
        let warnings = startup_warnings(&open, &[]);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].contains("without a bearer token"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].contains("remote clients get 403"),
            "{warnings:?}"
        );
        let protected = HttpConfig {
            auth_token: Some("t".into()),
            allowed_hosts: vec!["files.example".into()],
            ..open
        };
        assert!(startup_warnings(&protected, &[std::env::temp_dir()]).is_empty());
        let missing = startup_warnings(
            &HttpConfig::default(),
            &[std::path::PathBuf::from("/definitely/not/here")],
        );
        assert!(missing[0].contains("does not exist"), "{missing:?}");
        assert!(startup_warnings(&HttpConfig::default(), &[]).is_empty());
    }

    #[test]
    fn banner_states_the_real_address_and_protections() {
        let config = HttpConfig {
            allowed_hosts: vec!["scanner.internal".into()],
            auth_token: Some("t".into()),
            ..HttpConfig::default()
        };
        let address: SocketAddr = "127.0.0.1:41234".parse().unwrap();
        let text = banner(
            &config,
            address,
            &[std::path::PathBuf::from("/srv/samples")],
        );
        assert!(text.contains("http://127.0.0.1:41234/mcp"), "{text}");
        assert!(text.contains("scanner.internal"));
        assert!(text.contains("required on every route except /health"));
        assert!(text.contains("limited to /srv/samples"));
        assert!(!text.contains("--auth-token t"));
    }
}
