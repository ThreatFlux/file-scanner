# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MCP: `analyze_file` caches each section of a result on its own (by file SHA-256 and the options
  that change it), so a full run answers later single-section calls, and a repeated identical call
  is answered from the rendered answer. The cache holds deflate-compressed JSON text (default
  256 MiB of compressed bytes, `FILE_SCANNER_SECTION_CACHE_MB`) with a small bounded map of
  parsed values in front, so paging through one section does not parse it again. When it is
  full, other files' sections go first; a section too big to keep, and any section of the same
  file dropped to make room, is named in `cache_note`. `cache` is `hit`, `partial` or `miss`;
  a call that names no analysis returns a `hint` instead. Analysis cache entries over 4 MiB keep the trimmed answer.
  At most `max(4, CPUs)` analyses run at once across all transports.
- MCP: the server is now served by the rmcp SDK runtime on stdio and HTTP. Every protocol
  revision the SDK knows (2024-11-05 through 2026-07-28) is negotiated; `ping`,
  `notifications/*` and `server/discover` behave per the specification, and the server
  reports its real name, version, title and usage instructions.
- MCP: tools carry titles and read-only annotations, input schemas are generated from the
  request types and reject unknown arguments, and every tool accepts `max_output_bytes`.
- MCP: results are compact JSON with unset fields omitted and a hard byte budget (default
  80,000, ceiling 400,000); anything cut is listed under `truncated`.
- MCP: `FILE_SCANNER_ALLOWED_ROOTS` (`:`-separated) confines every tool path to the listed
  directories; `~/` is expanded, and FIFOs, sockets and devices are rejected with a message
  that names the fix. A directory argument is vetted too: with roots set, a symlink inside it
  that points outside them is refused (`yara_scan_file`, `analyze_npm_package`,
  `analyze_python_package`), and a FIFO, socket or device inside it is always refused. Without
  a root, a missing path no longer says whether it exists outside the roots.
- MCP: a repeated identical `analyze_file` call on an unchanged file is answered from a
  bounded in-memory section cache (`cache: "hit"`).
- MCP: `mcp-http` serves the SDK's Streamable HTTP transport at `/mcp` next to the REST
  helper routes. Sessions (`Mcp-Session-Id`) serve clients older than revision 2026-07-28;
  2026-07-28 requests are served statelessly.
- MCP: `mcp-http` and `mcp-sse` take `--host` (default `127.0.0.1`), `--port`,
  `--allowed-host`, `--allowed-origin` (both repeatable) and `--auth-token` (also
  `FILE_SCANNER_AUTH_TOKEN`). With a token, every route except `/health` needs
  `Authorization: Bearer <token>` (401 and `WWW-Authenticate` otherwise).
- MCP: `--allow-root <dir>` (repeatable, also `FILE_SCANNER_ALLOWED_ROOTS`) on `mcp-stdio`,
  `mcp-http` and `mcp-sse`; the flag wins over the variable.
- MCP: the startup banner on stderr states the real bind address and which protections are
  active; binding a non-loopback `--host` without a token prints a warning.
- MCP: the HTTP server stops on SIGINT and SIGTERM (open streams are ended, exit code 0);
  REST routes have a request timeout (120 s, 504) and a concurrency limit (16); a REST call
  still running at shutdown is answered `503 {"error":"shutting down"}` so the server stops
  at once. Each refused request (401, 403) is logged on stderr (method, path, reason, never
  the token).
- MCP: the cache directory is created with mode 0700 and its files 0600 on Unix.
- MCP: `mcp_server::output::page` and `PageArgs` (offset, limit, `total`, `returned`,
  `next_offset`) are the shared paging helper for tools that return lists.
- `file-scanner --version` prints the package version.

### Changed

- MCP: HTTP security defaults. The server binds `127.0.0.1` instead of all interfaces; the
  `Host` header must be a loopback name or an `--allowed-host`; a present `Origin` header
  must be a loopback origin or an `--allowed-origin` (403 otherwise) on every route, REST
  routes included. The wildcard `Access-Control-Allow-Origin: *` is gone: CORS preflights are
  answered for allowed origins only and `Mcp-Session-Id` is exposed. Deployments that
  publish the port (containers, systemd) must pass `--host 0.0.0.0`, an `--allowed-host`
  for the name clients use, and should set `--auth-token`.
- MCP: `hex_dump_size` above 1 MiB and a YARA `max_file_size` above 100 MiB are tool errors
  that name the limit instead of reading the whole file into memory.
- MCP: `/api/info` lists exactly the routes that exist (no `/docs` or `/redoc`), reports a
  real uptime (`uptime`, `uptime_seconds`) and the package version, and `/health` reports
  `transports: ["streamable-http"]`. The OpenAPI document describes every REST route.
- MCP: `POST /tools/call` answers success, tool failure and unknown tool with the same body
  shape (`resultType`, `content`, `isError`); the OpenAPI document says so.
- MCP: `make docker-run-http` passes `--host 0.0.0.0` so the published port reaches the server.
- MCP: REST routes answer failures as `{"error": ...}` JSON (400 for a rejected string
  query or filter) instead of an empty body.
- MCP: tool failures (missing file, bad or unknown argument, failing YARA rule, unsupported
  package) are tool errors (`isError: true`) whose text includes the underlying cause,
  such as the YARA compiler's message. An unknown tool is a JSON-RPC `-32602` error.
- MCP: a panic inside an analyzer becomes a tool error naming the section instead of ending
  the server; the release profile no longer uses `panic = "abort"`.
- MCP: `mcp-stdio` exits 0 when stdin closes before or after a session and writes only
  JSON-RPC to stdout; requests before `initialize` need the 2026-07-28 request metadata.
- MCP: `mcp-sse` is a deprecated alias that starts the Streamable HTTP server. The `/sse`
  route and the SSE event types are removed.
- MCP: `/health`, `/api/info` and the OpenAPI document report the package version.
- MCP: a failing cache directory no longer stops the server from starting; the analysis
  cache degrades to memory-only with one line on stderr.
- `estimate_technical_debt` uses saturating arithmetic, so extreme metrics no longer
  overflow and panic.
- Consolidate dependency updates on Rust 1.99.1, refresh stable crate/tool/container
  pins and migrate archive readers to ZIP 9's fallible filename API.
- Replace deprecated `serde_yaml`/unmaintained `unsafe-libyaml` with maintained
  `serde-saphyr` 2.0.0 under the existing source alias. YAML data remains compatible;
  emitted formatting may differ.
- Refresh the documented stable YARA-X runtime/crypto patch and patch the latest
  binary-analysis release to remove its vulnerable ZIP 8 dependency. Repository
  overrides do not propagate to downstream crates.io library consumers.
- Add complete open security-alert assessments and per-TP remediation plans in
  `docs/security`, including deployment and evidence limits.

### Fixed

- MCP: a panic in an analyzer (for example the technical-debt overflow in debug builds)
  no longer ends the server or leaves a request unanswered.
- `analyze_file` with `code_quality` or `all: true` completes on binaries with extreme
  metrics (the Go samples): every debt calculation saturates instead of overflowing.
- `POST /cache/clear` also empties the in-memory section cache.
- The non-recursive directory scan of `yara_scan_file` no longer follows symlinks to files
  outside the directory.
- Remediate the eleven confirmed runtime findings with a pinned Wolfi glibc 2.44
  runtime and patched static zlib 1.3.2. Backport upstream's nonblocking gzip
  security fix into stable libz-sys; verify it with AddressSanitizer and a source
  guard rather than relying only on package-version scans.
- Dismiss sixteen verified false positives with both-platform/source evidence.
  Preserve complete all-severity container reports, verify exact image identity
  and application inventories, scan both published architectures, and fail the
  security gate on any reported vulnerability.

### Removed

- MCP: the permissive CORS middleware and the `/docs` and `/redoc` entries of `/api/info`.
- The uncompiled `src/mcp/` tree, `src/hash_wrapper.rs`, `MCP_REFACTORING_GUIDE.md` and
  `MCP_REFACTORING_SUMMARY.md`, and the dependencies that only they or the hand-written
  JSON-RPC transport used (`async-trait`, `tokio-stream`, `futures-util`,
  `threatflux-hashing`), plus `utoipa-redoc` and `utoipa-swagger-ui`, which nothing used
  after the `/docs` and `/redoc` routes went. `tower` is now a dev-dependency (tests);
  `tower-http` stays, for the CORS layer.
- The hand-written JSON-RPC dispatcher and its types (`JsonRpcRequest`, `JsonRpcResponse`,
  `JsonRpcError`, `ToolCallParams` dispatch, `McpServerState`, `SseEvent`, `SseQuery`).

## [0.3.7] - 2026-10-07

### Changed

- The crate is renamed to `threatflux-file-scanner` so it can be published on crates.io,
  where the unrelated `file_scanner` crate owns the `file-scanner` name (crates.io treats
  `-` and `_` alike). The installed binary is still `file-scanner`, the library is still
  imported as `file_scanner`, and release asset names and the
  `ghcr.io/threatflux/file-scanner` image are unchanged. Once the crate is on crates.io,
  install it with `cargo install threatflux-file-scanner --locked`
- Enhanced threat analysis uses `threatflux-threat-detection` 0.2.3 from crates.io with its
  YARA engine, replacing the unpublished local 0.1.0 copy, whose YARA engine was a
  placeholder that never scanned. The local copy is removed
- The crates.io package ships only the library and binary sources, `Cargo.lock`, the
  README, this changelog and the license; tests, benchmarks, test corpora, scripts and the
  vendored YARA-X source stay in the repository. The crates.io build uses the upstream
  YARA-X release; release binaries and images keep the vendored Wasmtime 49.0.2 patch
- Release dry runs now verify the crates.io package with `cargo publish --dry-run` while
  publishing is disabled, instead of only listing its files

### Fixed

- The Windows release checksum (`*-windows-amd64.zip.sha256`) ended in CRLF, which macOS
  `shasum -a 256 -c` and `sha256sum -c` cannot read; it now ends in LF like the other
  checksums, and the release job refuses to publish a checksum file in any other format

## [0.3.6] - 2026-10-07

### Added

- Added `release.yml`: release binaries for Linux (x86_64, arm64), macOS (arm64,
  x86_64) and Windows with checksums and a CycloneDX SBOM, a `dry_run` mode, and
  crates.io trusted publishing (OIDC) gated by the `CRATES_IO_PUBLISH` variable
- Auto-release cuts releases as the `threatflux-automation` GitHub App, whose tag
  push starts `release.yml` and `docker.yml`, and supports `dry_run`

### Changed

- Builds with Rust 1.99.0; the minimum supported Rust version (1.97.1) is checked in CI
- Updated to current stable crates, including threatflux-hashing 1.7.0,
  threatflux-string-analysis 0.2.2, threatflux-binary-analysis 0.3.0, threatflux-cache
  0.2.0, rmcp 3.5.0 and yara-x 1.21.0; a string-analysis compatibility layer keeps the
  existing JSON output fields
- Moved the container runtime to distroless Debian 13
  (`gcr.io/distroless/cc-debian13:nonroot`) running as uid 65532 under `tini`
- Hardened workflows: read-only default permissions, no persisted checkout
  credentials, Codecov uploads via OIDC instead of a token, and a zizmor audit in
  workflow validation
- Marked the local `threatflux-threat-detection` and `threatflux-package-security`
  crates `publish = false` and removed their inert workflow copies, which
  referenced retired registry credentials

### Fixed

- The Docker workflow no longer prunes untagged GHCR versions on `main`: they include the
  per-platform images of every multi-arch tag, so released tags such as `0.3.5` lost their
  `linux/amd64` and `linux/arm64` images and could no longer be pulled
- String extraction compiled its twelve categorization regexes for every extracted string
  (about 2.6 ms per string); they are now compiled once, so 1,000 strings take about
  0.6 ms instead of 2.6 s and the `main` benchmark run finishes within its timeout
- Threat-detection tests no longer require a nonzero duration from an engine-less
  scan, which can finish within one clock tick on macOS
- Mach-O import attribution keeps two-level install names, with safe handling of special
  ordinals
- Partial batch tracking, the `package.json` input and negative-offset CLI inputs are fixed,
  and the previously disconnected CLI tests run again

### Security

- YARA-X is vendored with its Wasmtime requirement raised to the patched Wasmtime 49.0.2

## Earlier releases (0.1.1 to 0.3.5)

This file was not updated for each release between 0.1.0 and 0.3.6; see
[GitHub Releases](https://github.com/ThreatFlux/file-scanner/releases) for per-version notes.
The entries below were listed under Unreleased during that period, and all of them were
already part of the 0.3.0 release.

### Added

- Comprehensive CI/CD configuration with GitHub Actions
- Docker multi-stage builds with health checks
- Dependabot configuration for automated dependency updates
- Pre-commit hooks for code quality enforcement
- Issue and pull request templates
- Automated changelog management
- MCP (Model Context Protocol) server with STDIO, HTTP, and SSE transports
- LLM-optimized analysis tool for YARA rule generation
- Advanced static analysis features (100% task completion)
- YARA-X integration for threat detection
- Behavioral pattern analysis
- Call graph generation
- Entropy analysis and packing detection
- Vulnerability detection engine
- Code quality metrics
- String tracking and statistics system

### Changed

- Updated Dockerfile to use Rust 1.87.0
- Improved error handling in MCP tests
- Enhanced caching strategy for better performance
- Explicitly excluded `threatflux-package-security` from the root workspace so it can be updated and validated independently
- Added Dependabot coverage for the standalone `threatflux-package-security` crate

### Fixed

- Critical concurrency bugs causing memory leaks and resource exhaustion
- MCP server JSON-RPC protocol compliance
- Windows build errors with cross-platform metadata handling
- Docker build configuration for proper Rust version

### Security

- Added cargo-audit to CI pipeline
- Implemented security vulnerability reporting templates
- Enhanced input validation for file paths
- Refreshed root and standalone Cargo lockfiles to pick up patched transitive dependencies
- Updated the Docker security scan action to a patched Trivy release

## [0.1.0] - 2025-05-29

### Added

- Initial release with core file scanning functionality
- File metadata extraction
- Cryptographic hash calculations (MD5, SHA256, SHA512, BLAKE3)
- String extraction (ASCII and Unicode)
- Binary format analysis (PE/ELF/Mach-O)
- Digital signature verification
- Hex dump capabilities
- Multiple output formats (JSON, YAML, Pretty JSON)
- Basic CLI interface
- Docker support
- Benchmark suite

### Known Issues

- MCP server requires files to be accessible within Docker container mount points
- ARM64 cross-compilation may require additional dependencies

[Unreleased]: https://github.com/ThreatFlux/file-scanner/compare/v0.3.7...HEAD
[0.3.7]: https://github.com/ThreatFlux/file-scanner/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/ThreatFlux/file-scanner/compare/v0.3.5...v0.3.6
[0.1.0]: https://github.com/vtriple/file-scanner/releases/tag/v0.1.0
