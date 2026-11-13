# File Scanner - Claude Code Project

## Project Overview

A native file scanner written in Rust that provides detailed metadata, hash calculations,
string extraction, binary analysis, hex dumping, and digital signature verification. Built using Rust 1.99.1
with modern async capabilities and multiple output formats.

## Key Features

- **File Metadata Extraction**: Complete file system metadata including timestamps, permissions, ownership
- **Cryptographic Hashing**: MD5, SHA256, SHA512, and BLAKE3 hash calculations with async processing
- **String Analysis**: ASCII and Unicode string extraction
- **Binary Format Analysis**: PE/ELF/Mach-O parsing with compiler detection and section analysis
- **Digital Signature Verification**: Support for Authenticode, GPG, and macOS code signatures
- **Hex Dumping**: Flexible hex dump capabilities for headers, footers, or custom offsets
- **Multiple Output Formats**: JSON, YAML, and pretty-printed JSON support
- **MCP Server Support**: Model Context Protocol server with 17 tools over stdio and Streamable HTTP (see
  `docs/MCP.md`)
- **Analysis Caching**: Section results are cached by file SHA-256 (memory and a per-user directory on disk) so
  drill-down calls are fast
- **String Tracking**: Strings from analyzed files are indexed with offsets, categories and entropy for
  `search_strings` and `string_details`
- **NPM Package Analysis**: Offline security analysis of npm packages: source patterns, install scripts,
  typosquatting and a small built-in advisory table
- **Python Package Analysis**: The same for Python packages (wheel, sdist, zip, directories), including setup.py
  checks
- **Other Formats**: PDF and Office macro triage, scripts, archives (zip, tar, RAR, 7z) and Java archives

## Build and Test Commands

```bash
# Build the project
cargo build --release

# Regular file scanning mode
./target/release/file-scanner /path/to/file

# Full analysis with all features
./target/release/file-scanner /path/to/file --strings --hex-dump \
  --verify-signatures --format yaml

# Test with different output formats
./target/release/file-scanner /bin/ls --format json
./target/release/file-scanner /bin/ls --format yaml

# Hex dump examples
./target/release/file-scanner /bin/ls --hex-dump --hex-dump-size 256
./target/release/file-scanner /bin/ls --hex-dump --hex-dump-offset=-128 --hex-dump-size=128  # last 128 bytes

# String extraction
./target/release/file-scanner /bin/ls --strings --min-string-len 8

# MCP server modes
./target/release/file-scanner mcp-stdio                       # stdio transport
./target/release/file-scanner mcp-stdio --allow-root /path    # confine tools to a directory
./target/release/file-scanner mcp-http --port 3000            # Streamable HTTP at /mcp, binds 127.0.0.1
./target/release/file-scanner mcp-http --port 0               # let the system pick a port (see the banner)
# mcp-sse is a deprecated alias of mcp-http

# Call the server by hand: one JSON object per line on stdin (see docs/MCP.md "Testing by hand")
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"ping"}' | ./target/release/file-scanner mcp-stdio 2>/dev/null

# Smoke test of a built binary (initialize, tools/list, a tool call)
python3 scripts/mcp-smoke.py ./target/release/file-scanner
```

## Project Structure

```text
src/
├── main.rs                  # CLI (clap) and the MCP subcommands
├── lib.rs                   # Library entry point (imported as file_scanner)
├── metadata.rs              # File metadata extraction and core data structures
├── hash.rs                  # Cryptographic hash calculations (async)
├── strings.rs               # String extraction and categorization
├── binary_parser.rs         # PE/ELF/Mach-O parsing
├── signature.rs             # Digital signature checks
├── hexdump.rs               # Hex dump generation
├── disassembly.rs, control_flow.rs, call_graph.rs, taint_tracking.rs, vulnerability_detection.rs,
│   code_metrics.rs, function_analysis.rs, dependency_analysis.rs, entropy_analysis.rs,
│   behavioral_analysis.rs, threat_detection.rs   # analyses behind the analyze_file sections
├── pdf_analysis.rs, ole_vba_analysis.rs, script_analysis.rs        # analyze_document, analyze_script
├── archive_analysis.rs, tar_analysis.rs, rar_analysis.rs, sevenz_analysis.rs   # inspect_archive
├── java_analysis.rs         # analyze_java_file (class files, archives, Android manifests)
├── package_scan.rs          # Shared loader and source scanner of the npm and Python analyzers
├── npm_analysis.rs, npm_vuln_db.rs               # analyze_npm_package, advisory and malicious-name tables
├── python_analysis.rs, python_vuln_db.rs         # analyze_python_package, advisory and malicious-name tables
├── cache.rs                 # Analysis history cache (per-hash files, bounded, LRU)
├── string_tracker_compat.rs # String tracker over the threatflux-string-analysis library
├── mcp_server.rs            # FileScannerMcp handler, request types, ServerHandler impl
├── mcp_server/
│   ├── output.rs            # Compact JSON, the max_output_bytes budget, paging helper (page, PageArgs)
│   ├── paths.rs             # ~ expansion, --allow-root policy, file-kind checks
│   ├── state.rs             # ServerState: caches, string tracker, section cache, concurrency limit
│   ├── tools_analyze.rs     # analyze_file, query_analysis, disassemble, read_hex, compare_files,
│   │                        #   llm_analyze_file (helpers in tools_analyze/)
│   ├── tools_documents.rs   # analyze_document, analyze_script
│   ├── tools_formats.rs     # inspect_archive
│   ├── tools_java.rs        # analyze_java_file
│   ├── tools_packages.rs    # analyze_npm_package, analyze_python_package
│   ├── tools_services.rs    # search_strings, string_details, cache_status, cache_clear
│   └── tools_yara.rs        # yara_scan_file
├── mcp_transport.rs         # Starts the server on stdio or HTTP (the SDK serves the protocol)
└── mcp_transport/
    ├── http.rs              # axum app: /mcp, Host and Origin checks, bearer token, CORS, shutdown
    └── rest.rs              # REST helper routes (/health, /tools/*, /cache/*, /strings/*, OpenAPI)
```

The old hand-written JSON-RPC dispatcher, the uncompiled `src/mcp/` tree and the `string_tracker.rs` file are gone.
Add a tool by writing a `#[tool]` method in the matching `tools_*.rs` file; the SDK builds the tools/list entry and
input schema from the request struct, and the REST `/tools/*` routes use the same definitions.

## Dependencies

- **Core**: `tokio` (async runtime), `anyhow` (error handling), `clap` (CLI)
- **Hashing**: `sha2`, `md-5`, `blake3`
- **Binary Parsing**: `goblin`, `object`
- **String Processing**: `regex`, `encoding_rs`
- **Serialization**: `serde`, `serde_json`, `serde_yaml` (a source alias of `serde-saphyr`)
- **System Info**: `chrono`, `filetime`
- **MCP**: `rmcp` (Model Context Protocol SDK, serves stdio and Streamable HTTP), `schemars`
- **YARA**: `yara-x`
- **HTTP Server**: `axum`, `tower-http` (CORS), `tokio-util`

## Testing Examples

The scanner has been tested on various file types:

1. **ELF Binaries** (`/bin/ls`): Successfully extracts metadata, hashes, binary info, and strings
2. **Text Files** (`/etc/passwd`): Proper MIME type detection and hex dumping
3. **Self-Analysis**: Can analyze its own binary for testing

### Test Program Suite

The project includes test programs in 7 compiled languages to validate detection
capabilities:

- **C** (`c_advanced_binary`): Buffer overflows, format strings, anti-debugging
- **C++** (`cpp_test_binary`): Polymorphism, templates, anti-analysis
- **Go** (`go_test_binary`, `crypto_miner_binary`): Goroutines, crypto mining
- **Rust** (`rust_test_binary`, `packed_rust_binary`): Unsafe operations, packing
- **Nim** (`nim_test_binary`): Compile-time obfuscation, metaprogramming
- **D** (`d_test_binary`): Template obfuscation, parallel processing
- **Fortran** (`fortran_test_binary`): Scientific computing, resource exhaustion

All test binaries simulate malicious behaviors including:

- Anti-debugging techniques (ptrace, timing checks)
- Network C2 communication (msftupdater.com)
- Process injection simulation
- Persistence mechanisms
- Resource exhaustion
- Data exfiltration
- Polymorphic code generation

## Development Notes

- Built with the project Rust 1.99.1 toolchain
- Uses async processing for hash calculations to improve performance on large files
- Modular design allows easy extension for new file formats or analysis types
- Memory-efficient processing with configurable limits for large files

## Common Use Cases

1. **Security Analysis**: Hash verification, signature validation, string analysis
2. **Reverse Engineering**: Binary format analysis, hex dumps, compiler detection
3. **Forensics**: Complete file metadata, hex dumps at specific offsets
4. **File Classification**: MIME type detection, format identification
5. **Compliance**: Digital signature verification, integrity checking
6. **MCP Integration**: Use as a tool in AI assistants and coding environments

## Output Formats

### JSON (Compact)

```bash
./target/release/file-scanner file.bin --format json
```

### YAML (Human-readable)

```bash
./target/release/file-scanner file.bin --format yaml
```

### Pretty JSON (Default)

```bash
./target/release/file-scanner file.bin
```

## Performance Considerations

- Hash calculations run concurrently using tokio tasks
- String extraction limited to prevent memory exhaustion on large files
- Hex dumps configurable with size limits for performance
- Binary parsing optimized for common formats

## MCP Server Integration

The file-scanner runs as an MCP server. The full guide is `docs/MCP.md`; this section is the short version for
working on the code.

### Transports

- `mcp-stdio`: JSON-RPC over stdin and stdout, one message per line. Only JSON-RPC goes to stdout; the banner goes to
  stderr.
- `mcp-http`: Streamable HTTP at `/mcp` (rmcp SDK) plus REST helper routes. Binds `127.0.0.1` by default; checks the
  `Host` and `Origin` headers; `--auth-token` (or `FILE_SCANNER_AUTH_TOKEN`) requires a bearer token on every route
  except `/health`; no CORS wildcard. Options: `--port`, `--host`, `--allowed-host`, `--allowed-origin`.
- `mcp-sse`: deprecated alias of `mcp-http`. The SSE transport and `/sse` route no longer exist.
- All three take `--allow-root <dir>` (repeatable; `FILE_SCANNER_ALLOWED_ROOTS`, `:`-separated), `--cache-dir`
  (`FILE_SCANNER_CACHE_DIR`) and `--no-cache`.
- Protocol revisions 2024-11-05 through 2026-07-28 are negotiated by the SDK.

### Tools (17)

| Group | Tools |
| --- | --- |
| Overview and drill-down | `analyze_file`, `query_analysis`, `disassemble`, `read_hex`, `compare_files` |
| Strings | `search_strings`, `string_details` |
| By file kind | `analyze_document`, `analyze_script`, `inspect_archive`, `analyze_java_file` |
| Packages | `analyze_npm_package`, `analyze_python_package` |
| Detection | `llm_analyze_file`, `yara_scan_file` |
| Cache | `cache_status`, `cache_clear` (the only destructive tool) |

Design rules every tool follows:

- A bare `analyze_file` call returns a small overview and `next_steps`; sections are computed on request, cached by
  SHA-256 and returned as summaries; `query_analysis` pages the items. `all: true` runs everything once and still
  returns summaries only.
- Every tool takes `max_output_bytes` (default 80,000, ceiling 400,000). Output is compact JSON; anything cut is
  named in the answer: a cut page has `hint` and `next_offset`, a cut `disassemble` listing has `note` and
  `next_address`, section summaries reduced to counts have `note`, and `compare_files` and `llm_analyze_file` list
  the cut under `truncated`. Lists page with `offset` and `limit`; most answers carry `total`, `returned` and
  `next_offset`, with per-tool field names (see `docs/MCP.md`, Paging).
- `next_steps` entries, in every tool that has them, are `{tool, arguments, gives}` objects (no `why`, no plain
  strings); advice that is not a call goes in `hint` or `summary.notes`.
- Answers that can come from the cache carry `cache: hit | miss` (`partial` for a section set that was partly
  stored, and for `disassemble` code outside the stored window).
- Input schemas reject unknown fields. Failures are tool errors (`isError: true`) whose message names the fix.
- All tools are read-only except `cache_clear`. Nothing is executed.

### Cache

- Section cache: compressed JSON in memory (256 MiB) and on disk (1 GiB), keyed by file SHA-256 and options.
- Analysis history: one file per file hash (bounded in bytes and entries, LRU), read by `cache_status` and the REST
  `/cache/*` routes. Every server that uses the same cache directory shares it. With `--allow-root`, `cache_status`
  `list` and `search`, `search_strings`, `string_details`, `/cache/list`, `/cache/search` and `/strings/*` show only
  entries of files inside a root; counts and sizes (`cache_status` `stats`, `/cache/stats`, string totals) stay global.
- The threats, enhanced_threats and package section keys carry a revision, so ratings stored by an earlier build are
  recomputed.
- Location: `--cache-dir`, else `FILE_SCANNER_CACHE_DIR`, else `$XDG_CACHE_HOME/file-scanner`, else
  `~/.cache/file-scanner` (Linux) or `~/Library/Caches/file-scanner` (macOS). Mode 0700 directory, 0600 files. An
  unusable directory degrades to memory-only with one line on stderr.
- `FILE_SCANNER_CACHE_DISK_MB` and `FILE_SCANNER_SECTION_CACHE_MB` set the budgets. The only `FILE_SCANNER_*`
  variables are these two plus `FILE_SCANNER_CACHE_DIR`, `FILE_SCANNER_ALLOWED_ROOTS` and `FILE_SCANNER_AUTH_TOKEN`.

### Client configuration

```bash
claude mcp add file-scanner -- /absolute/path/to/file-scanner mcp-stdio
claude mcp add --transport http file-scanner http://127.0.0.1:3000/mcp
```

Claude Desktop, Cursor and VS Code snippets are in `docs/MCP.md`.

### Testing

```bash
# Unit and integration tests for the MCP server
cargo test --test mcp_tools_analyze_test --test mcp_transport_stdio_test --test mcp_http_router_test

# Real handshake against a built binary
python3 scripts/mcp-smoke.py ./target/debug/file-scanner

# Interactive: the MCP Inspector against a stdio server
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
```

Manual checks of a running HTTP server:

```bash
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/api/info
curl http://127.0.0.1:3000/cache/stats
curl -X POST http://127.0.0.1:3000/cache/search -H 'Content-Type: application/json' \
  -d '{"file_path_pattern": "/bin/ls"}'
curl -X POST http://127.0.0.1:3000/tools/call -H 'Content-Type: application/json' \
  -d '{"name":"read_hex","arguments":{"file_path":"/bin/ls","length":16}}'
curl http://127.0.0.1:3000/api-docs/openapi.json
```

## NPM Package Analysis

Offline analysis of a local npm package (`.tgz`, directory, `package.json`, `package-lock.json`). Nothing is
downloaded; a registry name is rejected with a message that says to run `npm pack`.

- Source scan (`package_scan.rs`): up to 400 files, 1 MiB each, 16 MiB in all, for download-and-execute (shell
  one-liners and Node or Python download, write and run code), decoded `eval`, a decoded payload passed to a process
  call, a download passed to `eval` or `exec`, credential and wallet access, credential files or the whole
  environment sent over the network, exfiltration endpoints, miners, reverse shells and obfuscation, with file and
  line evidence. The multi-line checks need the statements within 60 lines of each other (8 for the environment) and
  skip lines over 1,000 characters. One named environment variable beside a URL or HTTP call is not a finding. A
  run is tied to a write only when it names the written variable, field, expression or path literal, or starts a
  shell, interpreter or `chmod`; a call whose first argument is only a string literal (`spawn('sh', [path])`) is
  not seen as a run, except a literal `chmod +x` (`exec('chmod +x /tmp/x.sh')`), which is.
- Install hooks (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) are judged by their command string
  (for example a download piped to a shell) and also by the file they run. A file named by a hook (`node
  scripts/setup.js`, `sh setup.sh`, `./setup.sh`, also after `&&`, `cd dir &&` or leading `NAME=value` words; an
  extensionless path or a directory is tried with `.js`, `.cjs`, `.mjs` and `index.js`) is install-time code: its
  High findings and any obfuscation finding in it set `install_scripts.dangerous_commands`, raise the package to at
  least High and add a risk reason such as `an install-time script runs suspicious code: ... (preinstall runs
  scripts/setup.js)`. The tool reads the runner from the command. A runner such as `npx`, a path that leaves the
  package, a file reached only through `require()`, and a download in one file that is run from another are not
  followed.
- Risk floors: a dependency on a known malicious release is at least High; a suspected typosquat is at least Medium;
  a tarball or zip with a `..`, absolute-path or link entry is at least High (category `unsafe-path`).
- Typosquatting check against a popular-package list; a popular package is never a typosquat of itself.
- Advisories: `src/npm_vuln_db.rs` holds a small table (6 packages: event-stream, ua-parser-js, node-ipc, colors,
  lodash, minimist) matched by semver range. Every result states the table's date and size. An empty list means "not
  in this table", not "clean".
- Known-malicious data in `npm_vuln_db.rs`: `get_known_malicious_packages()` (names that are malicious at every
  version; a legitimate package never belongs there) and `get_known_malicious_versions()` (compromised releases of
  legitimate packages, such as event-stream 3.3.6 and node-ipc 10.1.1).
- MCP: `analyze_npm_package` with `section` = `summary` (default), `findings`, `files`, `dependencies`, `scripts`.
- Library: `file_scanner::npm_analysis::analyze_npm_package(path)`.
- CLI: `file-scanner analyze-npm <path>`.

```bash
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name analyze_npm_package \
  --tool-arg package_path=/absolute/path/to/package.tgz
```

## Python Package Analysis

The same design for Python: a local `.whl`, `.tar.gz`/`.tgz`, `.zip`, a source directory, `setup.py`,
`pyproject.toml`, `requirements.txt` or `poetry.lock`. A PyPI name is rejected with a message that says to run
`pip download`.

- Source scan of the same extensions and with the same limits as the npm tool; `setup.py` is checked for install-time
  behaviour.
- Advisories: `src/python_vuln_db.rs` holds a small table (7 packages: Django, Flask, requests, Pillow, PyYAML, NumPy,
  urllib3) matched with PEP 440 and normalized names. An unpinned requirement is unknown, not vulnerable.
- Obfuscation in `setup.py` raises the package to at least High (reason `setup.py runs suspicious code at install
  time: <rule> (line N)`). A known-malicious release is named `name==version` (for example `ctx==0.1.2`).
- Known-malicious data in `python_vuln_db.rs`: `get_known_malicious_packages()` (malicious at every version, for
  example colourama and python3-dateutil) and `get_known_malicious_versions()` (hijacked releases such as ctx 0.1.2
  and some ultralytics 8.3.x). Names of legitimate packages were removed from the first list (sklearn, pytorch,
  beautifulsoup, crypto, acquisition, yarnpkg); do not add a name there unless the package is malicious at every
  version.
- MCP: `analyze_python_package` takes the same arguments as the npm tool.
- Library: `file_scanner::python_analysis::analyze_python_package(path)`.
- CLI: `file-scanner analyze-python <path>`.

## Future Enhancement Ideas

- Support for additional binary formats (.NET assemblies, DEX code)
- Extended signature verification (jar signing, etc.)
- File content classification using machine learning
- Batch processing capabilities
- Plugin architecture for custom analyzers
- Enhanced MCP features (resources, prompts)
- Ruby gem security analysis
- Vulnerable-library (CVE) checks for Java archives
- Container image scanning

GitHub Pages is configured for benchmark results.
