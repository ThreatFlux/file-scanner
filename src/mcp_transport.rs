//! Transports for the MCP server: stdio, Streamable HTTP (plus the REST helper
//! routes) and the deprecated `mcp-sse` alias.
//!
//! The protocol is served by the SDK's own runtime; this module only wires a
//! handler to a transport.

use std::sync::Arc;

use anyhow::Result;
use rmcp::{
    service::ServerInitializeError,
    transport::{stdio, IntoTransport},
    RoleServer, ServiceExt,
};
use tokio_util::sync::CancellationToken;

use crate::mcp_server::{state::StateConfig, FileScannerMcp, ServerState};

pub mod http;
pub mod rest;

pub use http::HttpConfig;

/// Owns the one handler (and through it the one shared state) of a process.
pub struct McpTransportServer {
    handler: FileScannerMcp,
}

impl Default for McpTransportServer {
    fn default() -> Self {
        Self::new()
    }
}

impl McpTransportServer {
    /// A server whose state is configured from the environment
    /// (`FILE_SCANNER_ALLOWED_ROOTS`). The cache and string tracker are created
    /// once, when serving starts.
    pub fn new() -> Self {
        Self::with_state(Arc::new(ServerState::new(StateConfig::from_env())))
    }

    /// A server whose state is built from `config` (the command line).
    pub fn with_config(config: StateConfig) -> Self {
        Self::with_state(Arc::new(ServerState::new(config)))
    }

    /// A server over an explicit state (tests, embedding).
    pub fn with_state(state: Arc<ServerState>) -> Self {
        Self {
            handler: FileScannerMcp::with_state(state),
        }
    }

    /// The handler this server serves.
    pub const fn handler(&self) -> &FileScannerMcp {
        &self.handler
    }

    /// Serve MCP over stdin and stdout.
    ///
    /// Stdout carries JSON-RPC and nothing else; diagnostics go to stderr. A
    /// closed stdin, before or after a session, ends the server cleanly.
    pub async fn run_stdio(&self) -> Result<()> {
        self.handler.state().warm_up();
        eprintln!(
            "file-scanner {} MCP server on stdio (protocol revisions 2024-11-05 to 2026-07-28)",
            env!("CARGO_PKG_VERSION")
        );
        let roots = &self.handler.state().config().allow_roots;
        if roots.is_empty() {
            eprintln!("  File access: unrestricted (no --allow-root)");
        } else {
            let listed = roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            eprintln!("  File access: limited to {listed}");
            for root in roots.iter().filter(|root| !root.exists()) {
                eprintln!(
                    "warning: --allow-root {} does not exist, so nothing under it can be read.",
                    root.display()
                );
            }
        }
        self.serve_transport(stdio(), true).await
    }

    /// Serve one connection over `transport` until it closes.
    ///
    /// With `handle_ctrl_c`, Ctrl-C asks the service to stop (in-flight calls
    /// get a short drain). A transport that closes before the client has
    /// started a session is a clean exit, not an error.
    pub async fn serve_transport<T, E, A>(&self, transport: T, handle_ctrl_c: bool) -> Result<()>
    where
        T: IntoTransport<RoleServer, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let service = match self.handler.clone().serve(transport).await {
            Ok(service) => service,
            Err(ServerInitializeError::ConnectionClosed(_)) => return Ok(()),
            Err(_) => {
                anyhow::bail!(
                    "The MCP handshake failed: a client must send an `initialize` request \
                     first and `notifications/initialized` after the reply"
                );
            }
        };
        if handle_ctrl_c {
            let cancel = service.cancellation_token();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    cancel.cancel();
                }
            });
        }
        service.waiting().await?;
        Ok(())
    }

    /// Serve Streamable HTTP at `/mcp` next to the REST routes until SIGINT or
    /// SIGTERM.
    ///
    /// Prints warnings and a banner on stderr (the real bind address and the
    /// protections that are active). The one cancellation token ends open
    /// streams and axum's graceful shutdown together.
    pub async fn run_http(&self, config: HttpConfig) -> Result<()> {
        self.handler.state().warm_up();
        let shutdown = CancellationToken::new();
        let server =
            http::BoundServer::bind(self.handler.clone(), &config, shutdown.clone()).await?;
        let address = server.local_addr()?;
        let roots = self.handler.state().config().allow_roots.clone();
        for warning in http::startup_warnings(&config, &roots) {
            eprintln!("{warning}");
        }
        eprintln!("{}", http::banner(&config, address, &roots));
        tokio::spawn(async move {
            http::shutdown_signal().await;
            eprintln!("file-scanner: shutting down");
            shutdown.cancel();
        });
        server.serve().await
    }

    /// Deprecated alias of [`Self::run_http`]: the SDK has no SSE server
    /// transport, so `mcp-sse` starts the Streamable HTTP server.
    pub async fn run_sse(&self, config: HttpConfig) -> Result<()> {
        eprintln!(
            "file-scanner: mcp-sse is deprecated and now starts the Streamable HTTP server; use \
             mcp-http and connect to /mcp"
        );
        self.run_http(config).await
    }
}
