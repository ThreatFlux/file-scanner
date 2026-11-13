# Rust and HTTP API

This page covers two programmatic interfaces: the Rust library, and the REST helper routes served next to
the MCP endpoint. For the MCP tools themselves, see [MCP.md](MCP.md).

## Rust library

The package is `threatflux-file-scanner`. The library is imported as `file_scanner`, and the installed
binary is `file-scanner`. The unrelated `file-scanner` crate on crates.io is not this project.

The examples below use items added after 0.3.11 (`scan_strings`, `scan_bytes`, `calculate_sha256_only`,
the `rule_path`, `max_files` and `timeout_seconds` fields of `YaraScanRequest`, `files_matched`,
`StateConfig`, `with_config` and `HttpConfig`). The `"0.3"` requirement resolves to 0.3.11 and does not
have them, so until the next release is published, depend on the repository. The git dependency resolves the
default branch, which has these items only after the change that adds them is merged. A dependent build also
does not apply this repository's `[patch.crates-io]` entries, which Cargo ignores outside the workspace root;
that build was not tried here.

```toml
[dependencies]
threatflux-file-scanner = { git = "https://github.com/ThreatFlux/file-scanner" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
anyhow = "1"
```

The crate has no Cargo features. The documentation of every public item is on
[docs.rs](https://docs.rs/threatflux-file-scanner). The library is the code the binary is built from, so
its surface is large and has changed between releases: pin the version you test against.

### Modules

All modules are public. The ones most programs need:

| Module | What it has |
|--------|-------------|
| `metadata` | `FileMetadata`: size, timestamps, permissions, hashes and the optional analysis sections. |
| `hash` | `calculate_all_hashes`, `calculate_sha256_only`, `calculate_md5`; `Hashes`. |
| `strings` | `extract_strings`, `scan_strings`, `scan_bytes`; `ExtractedStrings`, `StringScan`. |
| `signature` | `verify_signature`; `SignatureInfo`. |
| `binary_parser`, `entropy_analysis`, `threat_detection`, `behavioral_analysis` | The analyses behind the CLI flags. |
| `npm_analysis` | `analyze_npm_package(&Path)`. |
| `python_analysis` | `analyze_python_package`. |
| `java_analysis` | Java archive and class file analysis. |
| `mcp_server` | `FileScannerMcp` (the handler), tool request and result types, `analyze_file_llm`, `yara_scan_files`. |
| `mcp_transport` | `McpTransportServer`, with `run_stdio` and `run_http`; `HttpConfig`. |

### Scan a file

```rust
use std::path::Path;

use file_scanner::metadata::FileMetadata;
use file_scanner::strings::extract_strings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = Path::new("/bin/ls");

    let mut meta = FileMetadata::new(path)?;
    meta.extract_basic_info()?;
    meta.calculate_hashes().await?;
    println!("{} bytes, sha256 {}", meta.file_size, meta.hashes.as_ref().unwrap().sha256);

    let strings = extract_strings(path, 6)?;
    println!("{} strings, {} unique", strings.total_count, strings.unique_count);
    Ok(())
}
```

Output on a macOS `/bin/ls`:

```text
252512 bytes, sha256 a7a0dcb6...
972 strings, 310 unique
```

`extract_strings` keeps at most 1000 strings per kind, which is what the command line prints. Use
`scan_strings` for exact counts.

### The digest and YARA scan used by the tools

```rust
use file_scanner::mcp_server::{
    analyze_file_llm, yara_scan_files, LlmFileAnalysisRequest, YaraScanRequest,
};

async fn digest_and_scan() -> anyhow::Result<()> {
    let digest = analyze_file_llm(LlmFileAnalysisRequest {
        file_path: "/bin/ls".into(),
        token_limit: None,
        min_string_length: None,
        max_strings: Some(20),
        max_imports: None,
        max_opcodes: None,
        hex_pattern_size: None,
        suggest_yara_rule: Some(true),
    })
    .await?;
    println!("{} key strings", digest.key_strings.len());

    let scan = yara_scan_files(YaraScanRequest {
        path: "/usr/bin".into(),
        yara_rule: r#"rule has_usage { strings: $a = "usage" nocase condition: $a }"#.into(),
        rule_path: None,
        recursive: Some(false),
        max_file_size: None,
        detailed_matches: Some(false),
        max_files: Some(200),
        timeout_seconds: Some(30),
    })
    .await?;
    println!("{} of {} files matched", scan.files_matched, scan.total_files_scanned);
    Ok(())
}
```

Output:

```text
20 key strings
147 of 200 files matched
```

These two functions use a fresh handler with default state: no path scope, no shared cache.

### Package analysis

```rust
use std::path::Path;
use file_scanner::npm_analysis::analyze_npm_package;

fn check() -> anyhow::Result<()> {
    // A package directory, a package.json, a package-lock.json or an npm tarball.
    let report = analyze_npm_package(Path::new("./some-package"))?;
    println!("{}", report.package_info.name);
    Ok(())
}
```

A path that is none of those returns an error that says what to pass.

### Serve MCP from your own program

```rust
use file_scanner::mcp_server::state::StateConfig;
use file_scanner::mcp_transport::McpTransportServer;

async fn serve() -> anyhow::Result<()> {
    let config = StateConfig {
        allow_roots: vec!["/srv/samples".into()],
        ..StateConfig::from_env()
    };
    McpTransportServer::with_config(config).run_stdio().await
}
```

`run_stdio` writes only JSON-RPC to stdout and prints its banner on stderr. `run_http(HttpConfig { .. })`
serves Streamable HTTP and the REST routes below; `HttpConfig::default()` binds `127.0.0.1:3000` with no
token.

The examples above were compiled and run against the library at this revision (not against 0.3.11).

## REST helper routes

`mcp-http` serves a few plain HTTP routes on the same address as `/mcp`. They exist for scripts and for
looking at the caches. They are protected by the same Host and Origin checks, and by the bearer token when
one is set. Only `/health` is open without the token.

| Route | Method | Purpose |
|-------|--------|---------|
| `/health` | GET | `{"status":"ok","service":"file-scanner-mcp","version":"...","transports":["streamable-http"]}` |
| `/api/info` | GET | Route list, version and uptime. |
| `/api-docs/openapi.json` | GET | OpenAPI 3.1 description of these routes. |
| `/initialize` | POST | The bare `initialize` result (version, server info, instructions); opens no session. |
| `/tools/list` | POST | The tool list in an envelope: `{"jsonrpc", "result": {"tools": [...]}}`. |
| `/tools/call` | POST | Call one tool; returns the bare result. Body: `{"name": "...", "arguments": {...}}`. |
| `/cache/stats`, `/cache/list` | GET | What the analysis cache holds. |
| `/cache/search`, `/cache/clear` | POST | Search the cache; empty it (`?scope=all\|analysis\|strings`, default all). |
| `/strings/stats` | GET | Statistics of the tracked strings. |
| `/strings/search`, `/strings/details`, `/strings/related`, `/strings/filter` | POST | Query the string index. |

Example, with a token and a path scope set:

```bash
curl -s -X POST http://127.0.0.1:3000/tools/call \
  -H "Authorization: Bearer $FILE_SCANNER_AUTH_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"read_hex","arguments":{"file_path":"/srv/samples/note.txt","length":8}}'
```

```json
{"resultType":"complete","content":[{"type":"text","text":"{\"file_path\":\"/srv/samples/note.txt\",\"offset\":0,
...\"total_bytes\":35,\"lines\":[\"00000000  68 65 6c 6c 6f 20 73 63  |hello sc|\"],\"next_offset\":8}"}],
 "isError":false}
```

REST calls run at most 16 at a time and time out after 120 seconds. The `--allow-root` scope applies to
them as it does to MCP calls. For anything that needs a session or streaming, use `/mcp`.
