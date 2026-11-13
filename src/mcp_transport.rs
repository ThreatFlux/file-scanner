//! Transports for the MCP server: stdio, Streamable HTTP (plus the REST helper
//! routes) and the deprecated `mcp-sse` alias.
//!
//! The protocol is served by the SDK's own runtime; this module only wires a
//! handler to a transport.

use std::sync::Arc;

use anyhow::Result;
use rmcp::{service::ServerInitializeError, transport::IntoTransport, RoleServer, ServiceExt};
use tokio_util::sync::CancellationToken;

/// How long the stdio server keeps running after its input reached end of
/// file, so a call that is about to finish can still be answered. Matches the
/// SDK's own drain; an ordinary session still exits as soon as its calls are
/// answered.
const STDIN_EOF_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// A reader that tells `closed` when the input ends.
struct EofSignal<R> {
    inner: R,
    closed: Arc<tokio::sync::Notify>,
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for EofSignal<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &polled {
            if buf.filled().len() == before && buf.remaining() > 0 {
                self.closed.notify_one();
            }
        }
        polled
    }
}

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
    /// closed stdin, before or after a session, ends the server cleanly: a call
    /// still running gets five seconds to answer; if it is still unanswered then,
    /// one line on stderr says so and the process exits.
    pub async fn run_stdio(&self) -> Result<()> {
        self.handler.state().warm_up();
        eprintln!(
            "file-scanner {} MCP server on stdio (protocol revisions 2024-11-05 to 2026-07-28)",
            env!("CARGO_PKG_VERSION")
        );
        let roots = self.handler.state().allowed_roots();
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
        // The SDK keeps draining in-flight work for 5 s after its input
        // closes, and a scan on a blocking thread can run far longer. Once
        // stdin has reached end of file, answers still being written get a
        // grace period and then the process ends.
        let closed = Arc::new(tokio::sync::Notify::new());
        let input = EofSignal {
            inner: tokio::io::stdin(),
            closed: Arc::clone(&closed),
        };
        let serving = self.serve_transport((input, tokio::io::stdout()), true);
        tokio::pin!(serving);
        tokio::select! {
            outcome = &mut serving => outcome?,
            () = async {
                closed.notified().await;
                tokio::time::sleep(STDIN_EOF_GRACE).await;
            } => {
                eprintln!(
                    "file-scanner: input closed and a call was still running after {} s; \
                     exiting without its answer",
                    STDIN_EOF_GRACE.as_secs()
                );
            }
        }
        {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
        }
        std::process::exit(0)
    }

    /// Serve one connection over `transport` until it closes.
    ///
    /// With `handle_ctrl_c`, Ctrl-C (and SIGTERM on Unix) asks the service to stop (in-flight calls
    /// get a short drain). A transport that closes before the client has
    /// started a session is a clean exit, not an error.
    pub async fn serve_transport<T, E, A>(&self, transport: T, handle_ctrl_c: bool) -> Result<()>
    where
        T: IntoTransport<RoleServer, E, A>,
        E: std::error::Error + Send + Sync + 'static,
    {
        // Handlers are registered before the handshake so a signal at any moment ends the
        // server cleanly.
        let mut signal = handle_ctrl_c.then(|| Box::pin(http::arm_shutdown_signal()));
        let handshake = self.handler.clone().serve(transport);
        let result = match signal.as_mut() {
            Some(signal) => tokio::select! {
                result = handshake => result,
                _ = signal.as_mut() => return Ok(()),
            },
            None => handshake.await,
        };
        let service = match result {
            Ok(service) => service,
            Err(ServerInitializeError::ConnectionClosed(_)) => return Ok(()),
            Err(_) => {
                anyhow::bail!(
                    "The MCP handshake failed: a client must send an `initialize` request \
                     first and `notifications/initialized` after the reply"
                );
            }
        };
        if let Some(signal) = signal {
            let cancel = service.cancellation_token();
            tokio::spawn(async move {
                signal.await;
                cancel.cancel();
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
        let roots = self.handler.state().allowed_roots().to_vec();
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
