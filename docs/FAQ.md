# Frequently Asked Questions (FAQ)

## Table of Contents

- [General Questions](#general-questions)
- [Installation Issues](#installation-issues)
- [Usage Questions](#usage-questions)
- [Performance Questions](#performance-questions)
- [MCP Integration](#mcp-integration)
- [Security Concerns](#security-concerns)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## General Questions

### What is File Scanner?

File Scanner is a static file analysis tool written in Rust. It provides:

- Metadata extraction
- Cryptographic hashes (MD5, SHA-256, SHA-512, BLAKE3)
- String extraction and categorization
- Binary format analysis (PE, ELF, Mach-O)
- Digital signature verification
- Threat, behavioral and YARA indicator analysis
- Analyzers for archives, PDF and Office files, scripts, Java files, and npm and Python packages
- An MCP server for AI assistants

### How does File Scanner compare to other tools?

It combines things that are usually separate tools. It does not replace them.

| Feature | File Scanner | file | strings | binwalk | YARA |
|---------|--------------|------|---------|---------|------|
| Hashes | Yes | No | No | No | No |
| Strings | Categorized | No | Basic | Yes | No |
| Binary format analysis | Yes | Basic | No | Yes | No |
| Signature checks | Yes | No | No | No | No |
| Custom rule matching | Yes (YARA-X) | No | No | No | Yes |
| MCP server | Yes | No | No | No | No |

### Is File Scanner suitable for production use?

The scanner is a Rust library, a command-line tool and an MCP server. Know its limits before you rely on it: it
reports indicators, not verdicts; it analyzes one file per CLI run; and the HTTP server has no TLS or rate
limiting of its own. See [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md).

### What file types are supported?

Any file gets metadata, hashes, strings, hex dumps and entropy. Specialized analysis exists for:

- **Executables**: PE (Windows), ELF (Linux), Mach-O (macOS)
- **Archives**: zip, tar, rar and 7z are listed without extraction (MCP `inspect_archive`)
- **Documents**: PDF and Microsoft Office files (MCP `analyze_document`)
- **Scripts**: shell, PowerShell, JavaScript, Python, batch, VBScript (MCP `analyze_script`)
- **Java**: JAR, WAR, EAR, AAR, APK and class files (`analyze-java`)
- **Packages**: npm and Python packages (`analyze-npm`, `analyze-python`)

## Installation Issues

### Rust version error

#### Q: I get "error: package requires rustc 1.97.1"

A: Update Rust to the latest version:

```bash
rustup update stable
rustup default stable
```

### Missing dependencies

#### Q: Build fails with a C compiler error

A: The dependency set does not use OpenSSL (`Cargo.lock` has no `openssl-sys`), so you do not need
`pkg-config` or `libssl-dev`. Some crates (for example `ring` and `aws-lc-sys`) compile C code, so a C
compiler must be installed:

```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS
xcode-select --install
```

### Compilation errors

#### Q: "error: linker cc not found"

A: Install build tools:

```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS
xcode-select --install

# Windows
# Install Visual Studio Build Tools
```

## Usage Questions

### How do I scan multiple files?

The scanner takes one file per run. Use the shell:

```bash
find /path -name "*.exe" -print0 | \
  xargs -0 -n1 -P 8 file-scanner --format json > results.jsonl

for file in *.bin; do
  file-scanner "$file" > "${file}.analysis.json"
done
```

With `--format json` each run prints one line of JSON.

### Can I scan compressed files?

`file-scanner` analyzes a file as it is and does not extract it. For a list of what an archive holds, use
the MCP tool `inspect_archive` (zip, tar, rar, 7z). To scan the contents, extract first:

```bash
unzip archive.zip -d temp/
for f in temp/*; do file-scanner "$f" --format json; done
```

### How do I filter output?

Use `jq`:

```bash
file-scanner file.exe --format json | jq .hashes

file-scanner file.exe --strings --format json | \
  jq -r '.extracted_strings.interesting_strings[] | select(.category == "URL") | .value'
```

## Performance Questions

### Why is scanning slow?

1. Large files: ask for fewer sections. Without `--all`, only metadata, hashes and binary info are computed.
2. Many files: run several processes in parallel (see above).
3. Network drives: copy the files locally first.
4. Signature verification (`--verify-signatures`) may start external programs; leave it off if you do not
   need it.

### Memory usage is too high

There is no memory-limit setting. Scan fewer sections at a time, and limit the process from outside
(container memory limit, `ulimit -v` on Linux).

## MCP Integration

The full guide is [MCP.md](MCP.md): client setup, every tool, worked examples, security and limits.

### How do I add the server to Claude Code, Claude Desktop, Cursor or VS Code?

Each client has its own config file and key. Commands and snippets for all four are in
[MCP.md](MCP.md#client-setup). For Claude Code:

```bash
claude mcp add file-scanner -- /absolute/path/to/file-scanner mcp-stdio
```

### Claude Code or another client can't find file-scanner

GUI clients often start with a different `PATH` than your shell. Use the absolute path of the binary
(`command -v file-scanner`; `cargo install` puts it at `~/.cargo/bin/file-scanner`):

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

### "Address already in use"

Another process is using the port. Find it, or pick another port (`--port 0` picks a free one and prints it):

```bash
lsof -i :3000
file-scanner mcp-http --port 3001
```

### MCP tools not showing up

Restart the client after editing its config, then check the server by hand. stdio messages are one JSON object
per line, and the server expects `initialize` first:

```bash
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
INIT+='"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'
printf '%s\n' "$INIT" \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | file-scanner mcp-stdio 2>/dev/null | jq -c '{id, tools: (.result.tools // [] | length)}'
```

The second reply should say 17 tools. Do not pretty-print the requests: each line is parsed on its own.

### The HTTP server answers 403 or 401

403 means the `Host` or `Origin` header is not allowed: add `--allowed-host <name>` for the name clients use, or
`--allowed-origin <origin>` for a browser app. 401 means the server was started with a token: send
`Authorization: Bearer <token>`.

### A tool says a path is outside the directories the server may read

The server was started with `--allow-root` (or `FILE_SCANNER_ALLOWED_ROOTS`) and the path is not under a root. The
message names the allowed directories.

### Can I run the MCP server from the Docker image?

Yes, if you mount the files. A container only sees what you mount, so mount them at the same path inside as
outside; see [MCP.md](MCP.md#docker).

### Where does the cache live, and how do I turn it off?

In your user cache directory (`~/.cache/file-scanner` on Linux, `~/Library/Caches/file-scanner` on macOS). Use
`--cache-dir` or `FILE_SCANNER_CACHE_DIR` to move it, `--no-cache` to turn it off, and the `cache_clear` tool to empty
it. See [MCP.md](MCP.md#the-cache).

### Answers are cut off or the client complains about output size

Every answer is capped at `max_output_bytes` (default 80,000). Look for `truncated`, `returned` and `next_offset`,
page with `offset`, narrow with `filter`, or raise `max_output_bytes` (ceiling 400,000).

## Security Concerns

### Is it safe to scan untrusted files?

The scanner does not run the files it analyzes. It does parse them, and parsers can have bugs, so scan
hostile files in a container or VM, as an unprivileged user, with the files mounted read-only:

```bash
docker run --rm -v /suspicious:/data:ro --memory=1g --cpus=1 \
  ghcr.io/threatflux/file-scanner /data/sample.exe
```

See [SECURITY_CONSIDERATIONS.md](../SECURITY_CONSIDERATIONS.md).

### Can File Scanner detect all malware?

No. It reports facts and heuristic indicators (suspicious strings and APIs, packed or high-entropy
sections, YARA rule matches). It is not an antivirus: it has no signature database of known malware and
no sandbox. A clean report does not mean a file is safe.

### What about privacy?

The scanner runs offline. It has no telemetry. In CLI mode it makes no network connections. The HTTP
server listens on a port (loopback by default). The MCP server keeps a cache of results on disk; see
[SECURITY_CONSIDERATIONS.md](../SECURITY_CONSIDERATIONS.md#the-cache) to move or disable it.

## Troubleshooting

### "Permission denied" errors

The scanner can only read what its user can read.

```bash
ls -la file.bin
sudo chown "$USER" file.bin     # or run as a user that can read it
```

### "File not found" but the file exists

Check the path: relative paths resolve against the current directory, and names with spaces need quotes.

```bash
file-scanner "$(pwd)/file name with spaces.exe"
```

### Output is huge

Without flags the report has metadata, hashes and binary info. `--all` adds every section and can be
large. Ask for only what you need, or use the MCP server, which returns a small overview first and pages
the rest.

### "unexpected argument" from the command line

The flag does not exist. The complete list is in [USAGE.md](USAGE.md), or run `file-scanner --help`.
The scanner takes one file per run; loop in the shell to scan many.

### High CPU usage

Analyses such as `--all`, `--disassembly` and `--control-flow` on large binaries take time. Lower the
priority of the process, or limit it with the operating system:

```bash
nice -n 19 file-scanner large.iso --entropy
```

## Development

### How do I add a new analysis module?

1. Add `src/my_analysis.rs` and declare it in both `src/lib.rs` and `src/main.rs` (the binary compiles
   the modules itself).
2. Write a function that takes a `&Path` and returns `anyhow::Result<YourResult>`, with a
   `Serialize` result type.
3. For the command line, add a flag in `src/main.rs` and a field on `FileMetadata`
   (`src/metadata.rs`). For MCP, add a tool; see "Adding or changing a tool" in
   [ARCHITECTURE.md](ARCHITECTURE.md).
4. Add tests in `tests/`.
5. Update the documentation.

### How do I contribute?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Where can I get help?

- [Documentation](https://github.com/ThreatFlux/file-scanner/tree/main/docs)
- [GitHub Discussions](https://github.com/ThreatFlux/file-scanner/discussions)
- [Issue Tracker](https://github.com/ThreatFlux/file-scanner/issues)

## Still have questions?

If your question isn't answered here:

1. Check the [full documentation](https://github.com/ThreatFlux/file-scanner/tree/main/docs)
2. Search [existing issues](https://github.com/ThreatFlux/file-scanner/issues)
3. Ask in [GitHub Discussions](https://github.com/ThreatFlux/file-scanner/discussions)
4. Open a [new issue](https://github.com/ThreatFlux/file-scanner/issues/new)
