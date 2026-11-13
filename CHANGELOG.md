# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The MCP server was rebuilt. It now runs on the rmcp SDK, has 17 tools that give an overview first and paged detail
on request, and is safe by default over HTTP. Read "Changed" before you upgrade a deployment: the HTTP server binds
to loopback, the tool output shapes changed, and some arguments and routes are gone.

### Added

- MCP server on the rmcp SDK over stdio and Streamable HTTP (`/mcp`). Protocol revisions 2024-11-05 through
  2026-07-28 are negotiated. The server reports its name, version, title and usage instructions, tools carry titles
  and read-only annotations, and input schemas are generated from the request types and reject unknown arguments.
- Overview-first analysis. `analyze_file` with only a path returns a small overview (type, hashes, headline facts, the
  most telling strings) and `next_steps` that name the next call. Every `next_steps` entry of every tool is a `{tool,
  arguments, gives}` object with real arguments; advice that is not a call goes in `hint` or `summary.notes`. A
  directory path returns a paged triage table (`recursive`, `max_files`, `offset`, `limit`). Sections, flags and `all:
  true` return per-section summaries; each full section is cached by SHA-256 for later drill-down. New sections
  `call_graph` and `taint`, and an `arch` argument that picks the slice of a universal Mach-O for every per-slice
  section. Slices are named `x86_64`, `arm64e` and `arm64-subtype-12`; `arm64` and `aarch64` pick the slice
  named `arm64` when the file has one, else the only ARM64-family slice; an unknown name, or `arm64` when several slices
  are ARM64-family and none is named `arm64`, is an error that lists the slices present; directory triage rows name
  them the same way.
  The overview offers only what applies: no native sections or `disassemble` step for a Java class file, no native
  `symbols` and `threats` pair or `disassemble` step for a zip, no `inspect_archive` step for a gzip stream that is not
  a tar or for a zip whose central directory cannot be read (`format_details.archive.error`), `analyze_script` only for
  shell, PowerShell, JavaScript, Python, batch and VBScript files (none for Perl, Ruby, PHP, Lua or AWK), both package
  steps for a `.tgz` as for a `.tar.gz`, no function or symbol counts for a Java class file and no `symbols` note for a
  Java archive. The x86-only sections are listed under `not_applicable` for ARM code, with a hint to pass `arch:
  "x86_64"` when such a slice exists; the steps of section answers spell the slice as the overview does. A `.war`,
  `.ear` or `.aar`, and a zip that the parser reads as a Java archive (for example with `WEB-INF/` entries), is reported
  as kind `jar` and gets an `analyze_java_file` step.
- 11 new tools (the server had six: `analyze_file`, `llm_analyze_file`, `yara_scan_file`, `analyze_java_file`,
  `analyze_npm_package` and `analyze_python_package`):
  - `query_analysis` pages and filters the lists of any section (strings by text, regex, category or encoding;
    symbols, imports, functions, findings, call-graph edges, taint flows, and more).
  - `disassemble` lists one function or address range (it works on an ELF, a PE, a thin Mach-O, or one slice of a
    universal Mach-O). It finds a function by any name in the symbol table, also beyond the first 5,000 grouped
    functions, and its function list says when it holds only part of them. `function` also takes an address, as
    `0x...` or as a decimal string when no function name contains that text. The next step of a function list passes
    the row's `address` when its name is shared by several functions. An ARM64 PE (COFF machine `0xAA64`) is decoded
    as ARM64; a PE with any machine other than x86, x86-64 or ARM64 is an error that names the machine value. An
    address outside the listing gets an error that gives the decoded range. Code outside the stored window is decoded
    again and the answer carries `cache: "partial"`. `read_hex` reads raw bytes at any offset (negative counts from
    the end); `compare_files` compares two files.
  - `search_strings` and `string_details` search strings in one file or across every file indexed in the session.
    `analyze_file` records offsets only for strings of 4 or more characters, and `string_details` says so for a
    string that has none.
  - `analyze_document` (PDF structure, JavaScript, launch actions, embedded files, up to 5,000 link targets; Office
    macros, auto-exec entry points, keywords), `analyze_script` (shell, PowerShell, JavaScript, Python, batch,
    VBScript; `line_from` and `line_to` scan a range again to reach findings beyond the 2,000 kept for a whole
    file; a script whose shebang names an unsupported interpreter such as perl, ruby or php is refused unless its
    extension names a language or `language` is given), `inspect_archive` (zip and zip-based formats, tar, tar.gz,
    RAR 4 and 5, 7z, with risk flags) cover file kinds that had no tool.
  - `cache_status` and `cache_clear` show and empty the caches on every transport.
- `analyze_java_file`, `analyze_npm_package` and `analyze_python_package` are rebuilt. The Java tool parses class
  files and archives and has views for classes, findings, resources, manifest, Android and nested archives. Nested
  archives, class containers and `example_classes` are named by their full path from the analyzed file joined with
  `!` (`a.war!WEB-INF/lib/util.jar`), and `view: "class"` accepts `<container>!<class>` to pick one copy. The package
  tools are offline: source scan with file and line evidence, install scripts, dependency advisories, typosquatting;
  they accept tarballs, wheels, zips, directories and lock or requirements files, and page `findings`, `files`,
  `dependencies` and `scripts`. For a wheel that ships a `.pth` file with findings, `section: "scripts"` lists them
  under `dangerous_operations`.
- Output control on every tool: `max_output_bytes` (default 80,000, ceiling 400,000) caps each result, anything cut is
  named in the answer (`truncated`, `hint` or `note`; a `next_steps` entry is kept whole or dropped, never shortened,
  and the top-level path echo is shortened only as a last resort), and lists page with `offset`, `limit`, `total`,
  `returned` and `next_offset` (`yara_scan_file` names them `matches_total`, `matches_returned` and `matches_offset`).
  Answers say `cache: hit` or `miss`. Failures are tool errors (`isError: true`) whose message says what to fix.
- `yara_scan_file` takes rules as text, as `rule_path` (a file or a directory of `.yar`/`.yara` files) or as
  `builtin`, and has limits (`max_matches_per_rule`, `max_rules_per_file`, `max_files`, `timeout_seconds`, each at
  least 1, and paging).
  Results include tags, metadata, matched strings with offsets and per-rule hit counts; whatever was cut is named
  under `limits_reached`, and many skipped files give one message with `skipped_total`. A symlinked directory given
  as `path` is scanned. The command-line `yara-scan` gains `--max-files` and `--timeout`, and `--rule` accepts a
  directory.
- HTTP safety options: `--host` (default `127.0.0.1`), `--allowed-host` and `--allowed-origin` (repeatable), and
  `--auth-token` (also `FILE_SCANNER_AUTH_TOKEN`), which requires `Authorization: Bearer <token>` on every route
  except `/health`. The startup banner on stderr states the bind address and which protections are active, and
  warns when a non-loopback host is used without a token. `mcp-http` stops cleanly on SIGINT and SIGTERM, and
  `mcp-stdio` exits 0 on both as well, also when the signal comes during the handshake.
- `--allow-root <dir>` (repeatable; also `FILE_SCANNER_ALLOWED_ROOTS`, `:`-separated) on `mcp-stdio`, `mcp-http` and
  `mcp-sse` confines every tool path to the listed directories. Symlinks and `..` are resolved before the check. A
  symlink inside a `yara_scan_file` directory that points outside the roots refuses the call; the `analyze_file` triage
  table never follows links and counts them under `links_skipped`. FIFOs, sockets and devices are always refused as a
  path; inside a directory they are skipped and listed as skipped. A leading `~/` is expanded. The cache and string
  tools and routes show only files inside a root (`cache_status` `list` and `search`, `search_strings`,
  `string_details`, `/cache/list`, `/cache/search` and the `/strings/*` routes, `/strings/related` included); the cache
  listings print each row's canonical path in `file_path` and `tool_args` and match `file_path_pattern` against it, and
  a path argument outside the roots (such as a `rule_path`) is shown as `<outside the allowed roots>`; counts and sizes
  (`cache_status` `stats`, `/cache/stats`, string totals) stay global and name no path. The analysis history is shared
  by every server that uses the same cache directory, and a rooted server lists only the entries inside its roots.
- `--cache-dir <dir>` (also `FILE_SCANNER_CACHE_DIR`) and `--no-cache` on the MCP commands;
  `FILE_SCANNER_CACHE_DISK_MB` and `FILE_SCANNER_SECTION_CACHE_MB` set cache budgets. Section results are also
  cached on disk, so drill-down survives a server restart. At most `max(4, CPUs)` analyses run at once. `--no-cache`
  keeps no section cache or history, also for `analyze_java_file`; the in-memory string index still fills, and
  `cache_status` and `cache_clear` say so.
- Analysis coverage: universal (fat) Mach-O files are analyzed on one slice and list all slices; Authenticode tables,
  ad-hoc Mach-O signatures and detached `.sig`/`.asc` files are recognized; dependencies are grouped by library;
  entropy analysis measures bytes that no section covers; disassembly, control flow, vulnerability and call-graph
  analysis cover ELF, PE and Mach-O with reported coverage (an ARM64 PE is decoded as ARM64); a tail call to an unsafe
  function is reported like a call; ARM64 branch targets are decoded.
- `file-scanner --version` prints the package version.

### Changed

- HTTP security defaults. The server binds `127.0.0.1` instead of all interfaces. The `Host` header must be a
  loopback name or an `--allowed-host`, and a present `Origin` header must be a loopback origin or an
  `--allowed-origin` (403 otherwise) on every route. The wildcard `Access-Control-Allow-Origin: *` is gone.
  What to change: a deployment that publishes the port (a container, systemd, a cluster) must pass `--host 0.0.0.0`,
  an `--allowed-host` for the name clients use, and should set `--auth-token` and `--allow-root`.
- Tool results changed shape. `analyze_file` no longer returns full sections: it returns an overview, or summaries
  with the full data in the cache for `query_analysis`. With `all: true` it no longer returns hundreds of kilobytes.
  The string list is now a summary (`total_count`, `unique_count`, `categories`, `top`); read the strings with
  `query_analysis`. Sections that fail or do not apply are listed under `errors` or `notes`, not `null`.
  What to change: clients that read `analyze_file` fields directly should call `query_analysis` for lists.
- `analyze_file` arguments: `hex_dump_size` is at most 4,096 (use `read_hex` for more) and needs `hex_dump: true`;
  `hex_dump_offset` accepts a negative value; `min_string_length` is at most 4,096; unknown arguments are rejected.
  `llm_analyze_file` returns sha256, file type, architecture and a packed flag; `token_limit` is an enforced budget
  in characters, and `truncated.how` names the limit that cut the answer (`max_output_bytes` or `token_limit`);
  `hex_pattern_size` must be 1 to 1,024. Its opcodes are the instructions at the entry point of an ELF or PE file
  (ARM64 for an ARM64 PE; a PE machine other than x86, x86-64 and ARM64 gives none and a note), and the `file_type`
  of a universal Mach-O names the slices as `arch` accepts them.
- Threat results are calmer. `threats` reports the YARA matches the engine computes (tags, metadata, matched strings
  and offsets) instead of a three-rule substring check; `enhanced_threats` keeps the engine's generic findings under
  `enhanced_analysis`, so ordinary programs and documents are no longer rated Suspicious or Malicious because of them.
  Behavioral analysis searches all strings, not the first 1,000, and no longer rates ordinary URLs as command and
  control. A rule match whose strings are all under 4 bytes or a padding run, or whose text-file match only describes
  a technique in words, is listed with `evidence_strength: weak` and an `evidence_reason` and adds no classification
  or level, so ordinary files (vim, Node.js, Markdown documentation, binaries with padding) are no longer rated
  Suspicious or Critical. The built-in rules `backdoor_patterns`, `anti_analysis` and `ransomware_indicators` match
  less broadly, and `update_lookalike_domain`, `self_announcing_evasion` and `hardcoded_xor_key` are new, so the
  simulated samples in `test_programs` still rate Suspicious or Malicious. The word `schtasks` alone no longer matches
  `persistence_mechanisms` (a created task, or the word in a file that also names a Run key, does), a match on
  hypervisor product names alone is weak, the get-pc and SEH shellcode patterns in a file over 256 KiB are weak, and
  `backdoor_patterns` also matches a Python reverse shell (a file that creates a socket, calls connect, calls dup2 at
  least once and names the path of `sh` or a pty spawn, all four present).
  The threats and enhanced_threats caches carry a revision, so results from earlier builds are recomputed, and
  `query_analysis` `filter` on those rows also searches the metadata values (`filter: "weak"` finds weak-evidence
  rows). Weak vulnerability rules are counted in `pattern_counts` instead of listed, and use-after-free, double-free
  and format-string call rules report Low severity.
- Entropy and signatures are less alarmist and more honest: ordinary binaries are no longer called likely encrypted,
  a verified compression header is needed to exempt a debug section, a missing signature verifier reports "Not
  checked", and PE files with a certificate table report "Present, not verified".
- The cache is now a real cache. Section results are stored by SHA-256 and served on later calls; one private file
  per hash (directory mode 0700, files 0600), bounded in bytes and entries with least-recently-used eviction, written
  atomically. The default location moved from the shared temp directory to the user's cache directory
  (`~/.cache/file-scanner`, `~/Library/Caches/file-scanner`, or `$XDG_CACHE_HOME`). An unusable cache directory no
  longer stops the server: it reports once on stderr and caches in memory.
- Errors. Failed tool calls are tool errors with the cause in the text (a YARA compile error carries the compiler's
  message, line and column); an unknown tool is JSON-RPC `-32602`. A panic in one analyzer fails only that section;
  the release profile no longer uses `panic = "abort"`.
- `mcp-stdio` writes only JSON-RPC to stdout, exits 0 when stdin closes (after up to 5 seconds for calls that are
  still running; a call that is not done by then gets no answer and one line on stderr), and expects one JSON object
  per line.
  Requests before `initialize` need the 2026-07-28 request metadata (`ping` is answered on a connection that has not
  used it). Over HTTP, a 2026-07-28 request also needs the `MCP-Protocol-Version`, `Mcp-Method` and, for `tools/call`,
  `Mcp-Name` headers. JSON-RPC batches are not accepted.
- REST helper routes: `/api/info` lists exactly the routes that exist and a real uptime; `/health` reports
  `transports: ["streamable-http"]` and the package version; `POST /tools/call` answers success, tool failure and
  unknown tool with one body shape (`resultType`, `content`, `isError`); failures are `{"error": ...}` JSON.
  `POST /strings/details` answers 404 for an unknown string. `POST /cache/search` filters on `file_path_pattern`, not
  `file_path`. `POST /cache/clear` clears the analysis
  history, the cached sections (in memory too), the tracked strings and the Java tool's in-memory results, and takes
  `?scope=all|analysis|strings`.
- Package tools. Registry names (`express`, `requests==2.5.0`) are rejected with an offline message; pass a local file
  (a specifier that a shell would misread is quoted in the suggested command, `pip download 'django>=4'`). Mainstream
  packages are no longer flagged as typosquats of themselves or labelled malicious. Known-malicious names are Critical
  on their own; compromised releases of legitimate packages are matched by name and version, and a dependency on one
  rates at least High and is named `name@version` (npm) or `name==version` (Python, for example `ctx==0.1.2`). A
  suspected typosquat rates at least Medium. A tarball, sdist or zip with a `..`, absolute-path or link entry rates at
  least High, with one finding per entry. Every result states its advisory data (a small offline table: 6 npm
  packages, 7 PyPI packages) and that an empty list is not a clean bill of health. Packages that were not read in full
  are never rated Safe, and a dependency list alone is at least Low.
- Archive, document and Java results: archive risk is `unknown` instead of `low` when the listing is unavailable or
  capped, when an archive holds nested archives (named, up to 5, and not opened) or when all entries are encrypted,
  and `medium` when some are; a possible compression bomb marks its entry as `CompressionBomb (critical)`, so
  `risky_only` returns it; the `inspect_archive` summary always carries `entries`, `uncompressed_bytes` and
  `compression_ratio`, null when not measured. Its `next_steps` are `{tool, arguments, gives}` calls; the advice for
  nested and encrypted entries is in `summary.notes`. A PDF in which no object could be read is rated at least medium.
  Signing is reported as "signature files present, not verified"; `classes.dex` is reported as not parsed and an
  archive with DEX files is rated at least Medium; the archive kind is decided from content, not the file name.
- Bounded analysis. Parsers for hostile input carry byte, count and time budgets: strings and disassembly are kept
  in bounded form (counts stay exact), archives, packages, PDFs, Office files, Java archives and YARA directory
  scans stop at documented limits and say so. Directory YARA scans share one compiled rule set across a bounded
  worker pool.
- `estimate_technical_debt` uses saturating arithmetic, so extreme metrics no longer overflow and panic.
- Consolidate dependency updates on Rust 1.100.0, refresh stable crate/tool/container pins and migrate archive
  readers to ZIP 9's fallible filename API.
- Adopt the verified shared v0.7.11 release workflow and final stable ThreatFlux libraries; update the locked TLS
  verifier to 0.103.17.
- Update the reviewed MCP SDK pin to 3.10.0, including its tool-schema dependency property-name fix.
- Replace deprecated `serde_yaml`/unmaintained `unsafe-libyaml` with maintained `serde-saphyr` 2.1.1 under the
  existing source alias. YAML data remains compatible; emitted formatting may differ.
- Consume the reviewed binary-analysis release with ZIP 9 and preserve the stable YARA-X runtime/crypto override.
  Repository overrides do not propagate to downstream crates.io library consumers.
- Add complete open security-alert assessments and per-TP remediation plans in `docs/security`, including
  deployment and evidence limits.

### Fixed

- Strings: UTF-16 extraction returns printable strings only and reports the right endianness; strings carry
  offsets, encodings and categories; counts are exact even when the list is bounded.
- Mach-O and ELF: universal binaries are no longer reported as Java classes; thin arm64 reports its architecture;
  chained-fixup imports are listed; malformed headers and crafted symbol, bind-opcode and version tables no longer
  panic, overflow the stack or stall for minutes.
- Disassembly no longer stops at the first undecodable byte and no longer uses gigabytes of memory on crafted
  inputs; control-flow and call-graph analysis choose the right decoder for the architecture and report why a graph
  is empty.
- `llm_analyze_file` no longer crashes on `hex_pattern_size: 0`; its suggested YARA rule compiles and is checked
  before it is returned.
- `yara_scan_file` reports compile errors with position, lists skipped and unreadable files instead of dropping them,
  and applies `max_files` and `timeout_seconds` to the directory walk. The non-recursive directory scan no longer
  follows symlinks outside the directory.
- PDF and Office: the PDF analyzer reports what the file contains instead of constants; macros are found in any VBA
  storage and in OOXML packages; `has_macros` is no longer true for every OLE2 file.
- Package tools: install scripts that download and run code are rated High or Critical, also when the code is in a
  file an install hook runs (`node scripts/setup.js`, also through `cd dir && node file`, leading `NAME=value` words,
  an extensionless path or a directory); an obfuscated hook file, or obfuscation in `setup.py`, rates at least High;
  download, write and run code (Node `https.get`; Python `urlretrieve`), a download passed to `eval` or `exec`, a
  decoded payload passed to `exec`, `spawn`, `os.system` or `subprocess`, and credential files or the whole
  environment sent over the network are High findings when the statements lie close together. A run counts only when
  it starts what was written (the same name, field, expression or path literal, or a shell, interpreter or `chmod`; in
  `setup.py` also a literal temp path, a `./` script, or a shell or interpreter command after a write that names its
  path as a literal), so an update check beside a generic `spawn(command, args)` runner is not a dropper, and one
  named environment variable (`process.env.API_URL`, `os.getenv('X')`) beside a URL is not an exfiltration finding;
  payloads in `.d.ts` files, after block comments or in template literals are no longer missed; Python metadata is
  read from PEP 621, Poetry, `setup.py` and `PKG-INFO`; a tarball with a hidden or oversized header is refused.
- Java: analysis of tiny crafted class files, manifests and archives no longer exhausts memory; a JAR with leading
  bytes opens; a class file followed by a JAR is no longer reported clean.
- `analyze_file` with `code_quality` or `all: true` completes on binaries with extreme metrics (the Go samples).
- The cache is no longer truncated when a stdio session ends, and symlinks planted in the cache directory are not
  followed.
- Remediate the eleven confirmed runtime findings with a pinned Wolfi glibc 2.44 runtime and stable libz-sys 1.1.33
  with pristine bundled zlib 1.4, which includes the prior nonblocking gzip fix. Retain the AddressSanitizer
  regression and exact native-source guard.
- Dismiss sixteen verified false positives with both-platform/source evidence. Preserve complete all-severity
  container reports, verify exact image identity and application inventories, scan both published architectures, and
  fail the security gate on any reported vulnerability.

### Deprecated

- `mcp-sse` is a deprecated alias of `mcp-http`: it prints a notice and starts the same server. Use `mcp-http` and
  point SSE clients at `http://host:port/mcp`.

### Removed

- The old MCP transport code: the hand-written JSON-RPC dispatcher and its types, the SSE transport and `/sse`
  route, the permissive CORS middleware, and the `/docs` and `/redoc` entries of `/api/info`.
- Environment variables that were documented but never read (`RUST_LOG`, `FILE_SCANNER_DB_PATH`,
  `FILE_SCANNER_CACHE_SIZE`, `FILE_SCANNER_CACHE_TTL`, `THREATFLUX_*` and others). The variables that exist are
  `FILE_SCANNER_ALLOWED_ROOTS`, `FILE_SCANNER_AUTH_TOKEN`, `FILE_SCANNER_CACHE_DIR`, `FILE_SCANNER_CACHE_DISK_MB`
  and `FILE_SCANNER_SECTION_CACHE_MB`.
- Names of legitimate packages from the known-malicious lists (sklearn, pytorch, beautifulsoup, crypto, acquisition,
  yarnpkg, and official companions such as jest-cli and puppeteer-core).
- Archive risk scores derived from the archive's own file name or size, and the constant tar compression ratio.
- The uncompiled `src/mcp/` tree, `src/hash_wrapper.rs`, `MCP_REFACTORING_GUIDE.md` and
  `MCP_REFACTORING_SUMMARY.md`; the unused `typosquatting_detection` and `repository_integrity` modules; and the
  dependencies only they or the old transport used (`async-trait`, `tokio-stream`, `futures-util`,
  `threatflux-hashing`, `utoipa-redoc`, `utoipa-swagger-ui`). `tower` is now a dev-dependency.

### Security

- The HTTP server is no longer an open file-reading service by default: loopback bind, `Host` and `Origin` checks, no
  CORS wildcard, an optional bearer token (compared in constant time, never logged) and `--allow-root` path scope.
  Refused requests (401, 403) are logged on stderr without the token.
- Cached results, which can hold extracted strings and hex samples, live in a per-user directory with owner-only
  permissions instead of a shared temp path, and are not followed through symlinks.
- Hostile-file hardening: bounded memory, work and time in the binary, document, archive, package, Java and YARA
  analyzers (crafted files that used gigabytes of memory or minutes of CPU now stop at a budget). This is
  best-effort; run the server under OS or container limits when scanning untrusted files.
- Package analysis never contacts the network, and credentials in requirement URLs are not echoed.

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
- Explicitly excluded `threatflux-package-security` from the root workspace so it can be updated and validated
  independently
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
