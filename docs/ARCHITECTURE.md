# Architecture

This page describes how the code is laid out so that you can find the right file to change. It describes
the code as built. Names of files and functions here exist in the repository.

## Overview

One crate, `threatflux-file-scanner`, builds two things from the same source:

- the library `file_scanner` (`src/lib.rs`), and
- the binary `file-scanner` (`src/main.rs`), a command-line scanner and an MCP server.

`src/main.rs` declares the same modules as `src/lib.rs`, so the binary does not link the library: it
compiles the modules again. Add a module to both lists.

The binary runs in one of these modes, chosen by the first argument:

| Invocation | Code |
|------------|------|
| `file-scanner <file> [flags]` | `main.rs` builds a `FileMetadata` and runs the analyses the flags ask for. |
| `llm-analyze`, `yara-scan`, `analyze-npm`, `analyze-python`, `analyze-java` | Handlers in `main.rs`. |
| `mcp-stdio`, `mcp-http`, `mcp-sse` | `McpTransportServer` in `src/mcp_transport.rs`. |

## Source layout

```text
src/
  main.rs                  CLI: flags, subcommands, output formats
  lib.rs                   public module list
  metadata.rs              FileMetadata: basic info plus the optional analysis sections
  hash.rs                  MD5, SHA-256, SHA-512, BLAKE3 with bounded concurrency
  strings.rs               ASCII and UTF-16 string extraction and categorization
  binary_parser.rs         PE / ELF / Mach-O via threatflux-binary-analysis
  signature.rs             Authenticode, macOS and GPG signature checks
  hexdump.rs               header, footer and offset hex dumps
  entropy_analysis.rs, control_flow.rs, call_graph.rs, disassembly.rs, function_analysis.rs,
  vulnerability_detection.rs, code_metrics.rs, dependency_analysis.rs, taint_tracking.rs,
  behavioral_analysis.rs, threat_detection.rs   the analyses behind the CLI flags
  archive_analysis.rs, tar_analysis.rs, rar_analysis.rs, sevenz_analysis.rs   archive listing
  pdf_analysis.rs, ole_vba_analysis.rs, script_analysis.rs   documents and scripts
  java_analysis.rs (+ java_analysis/)   Java archives and class files
  package_scan.rs          shared loader for package archives and directories
  npm_analysis.rs, npm_vuln_db.rs, python_analysis.rs, python_vuln_db.rs   package vetting
  cache.rs                 on-disk analysis history (one file per file hash)
  string_tracker_compat.rs adapter over threatflux-string-analysis
  mcp_server.rs            FileScannerMcp handler, INSTRUCTIONS, tool router assembly
  mcp_server/              state, output budget, path policy and the tools
  mcp_transport.rs         McpTransportServer: stdio, HTTP, the mcp-sse alias
  mcp_transport/           http.rs (axum app and guard), rest.rs (REST helper routes)
```

### Libraries it uses

Three ThreatFlux crates from crates.io do part of the work: `threatflux-binary-analysis` (format parsing;
the build uses a vendored copy under `vendor/`), `threatflux-string-analysis` (string tracking, wrapped by
`string_tracker_compat.rs`) and `threatflux-threat-detection` (YARA engine and built-in rules, wrapped by
`threat_detection.rs`). Hashing, caching and package analysis are in this crate. The directory
`threatflux-package-security/` is a separate crate that is excluded from the workspace and is not used.

YARA rules run on `yara-x` (vendored under `vendor/`). The MCP runtime is the `rmcp` SDK, and the HTTP
server is `axum`.

## The MCP server

### Handler and state

`src/mcp_server.rs` defines `FileScannerMcp`, the handler the SDK serves. Each `tools_*` module registers
its tools with `#[tool_router]`, and `FileScannerMcp::with_state` adds the routers together.
`get_info` returns the server name, version and the `INSTRUCTIONS` text that clients read at `initialize`.

`FileScannerMcp` is cheap to clone. All clones share one `ServerState` (`src/mcp_server/state.rs`), created
once per process, which owns:

- the analysis cache (`src/cache.rs`) and the section cache (full per-section results, in memory and on
  disk, keyed by file hash),
- the string tracker that `search_strings`, `string_details` and the `/strings/*` routes read,
- the path scope (`--allow-root`), and
- a limit on how many analyses run at once. Analyses run on the blocking thread pool, and a panic inside
  one is caught and returned as a tool error.

### Tool modules

| File (in `src/mcp_server/`) | Tools |
|------|-------|
| `tools_analyze.rs` | `analyze_file`, `query_analysis`, `llm_analyze_file` |
| (same file) | `disassemble`, `read_hex`, `compare_files` |
| `tools_documents.rs` | `analyze_document`, `analyze_script` |
| `tools_formats.rs` | `inspect_archive`, and the file-kind detection `analyze_file` uses |
| `tools_java.rs` | `analyze_java_file` |
| `tools_packages.rs` | `analyze_npm_package`, `analyze_python_package` |
| `tools_services.rs` | `search_strings`, `string_details`, `cache_status`, `cache_clear` |
| `tools_yara.rs` | `yara_scan_file` |

That is 17 tools. `tools_analyze/` splits the analysis tools: `triage.rs` (the overview),
`sections.rs` (section summaries), `query.rs` (paged lists), `compare.rs`, `inspect.rs`, `llm.rs`.

Two shared modules shape every result:

- `output.rs` caps each result at `max_output_bytes` (default 80000, ceiling 400000). Lists are paged
  (`returned`, `next_offset`, `total`), and whatever is cut is listed under `truncated`.
- `paths.rs` expands `~/`, applies `--allow-root`, and detects file kinds. Its errors say what to fix.

The design rule across the tools is: overview first, then targeted, paged drill-down. The first call on a
file returns a small summary and `next_steps`. A full analysis is computed once, stored in the section
cache, and later `query_analysis` and `disassemble` calls are answered from it (`"cache": "hit"` in the
result). `read_hex` reads the file directly and has no `cache` field.

### Transports

`src/mcp_transport.rs` wires one handler to a transport:

- `run_stdio`: JSON-RPC on stdin and stdout through the SDK. Diagnostics go to stderr only.
- `run_http`: `src/mcp_transport/http.rs` builds an axum app with the SDK's Streamable HTTP service at
  `/mcp` and the REST routes from `rest.rs`, behind one guard. In order: Host and Origin checks, CORS for
  allowed origins only, the optional bearer token (all routes except `/health`), and a concurrency limit
  and timeout on the REST routes. It binds `127.0.0.1` unless told otherwise, prints warnings for unsafe
  combinations, and shuts down on SIGINT or SIGTERM.
- `run_sse`: prints a deprecation line and calls `run_http`. There is no SSE transport.

The REST routes call the same tool router as MCP, so a call on either path updates the same caches.

## Adding or changing a tool

1. Add a request struct (`Deserialize`, `JsonSchema`, `#[serde(deny_unknown_fields)]`) and a method
   annotated `#[tool(name = ..., description = ...)]` in the right `tools_*` module. A new group needs a
   router function and a line in `FileScannerMcp::with_state`.
2. Send the result through `output::respond` so the byte budget and paging apply, and check the path with
   the helpers in `paths.rs` before touching the file.
3. Mention the tool in `INSTRUCTIONS` in `src/mcp_server.rs`. A unit test there fails if a tool is missing
   from the text.
4. Add the name to `EXPECTED_TOOLS` in `scripts/mcp-smoke.py`, and document the tool in `docs/MCP.md`.
5. Add a test in `tests/` (`mcp_tools_*_test.rs`, `mcp_transport_*_test.rs`).

The tool list is generated from the router, so there is no second list to edit.

## Concurrency

- Hashing runs on tokio tasks with a semaphore (at most 10 hashes at once).
- MCP analyses run on the blocking pool behind the state's concurrency limit.
- The REST routes allow 16 requests at a time; `/mcp` is bounded by the SDK.
- Caches use their own locks; the on-disk cache writes each entry to a temporary name and renames it.

## Errors

The library uses `anyhow::Result`. In the MCP server, a failed call returns a result with `isError: true`
and a message written for the caller to act on (what is wrong, what to pass). Only protocol faults are
JSON-RPC errors. The CLI prints `Error: ...` on stderr and exits with status 1.

## Tests

`tests/` holds integration tests; the MCP ones are `mcp_*_test.rs`. `make mcp-test` runs the transport
tests. `scripts/mcp-smoke.py` runs a handshake against a built binary and is called from CI.
