# Security Considerations

This page is for people who run `file-scanner`, and especially its MCP server. It says what the program
does to protect you, what it does not do, and what to put around it. To report a vulnerability in
`file-scanner` itself, see [SECURITY.md](SECURITY.md).

## What the scanner is

`file-scanner` is a static analyzer. It reads files and reports on them. It does not run the files it
analyzes, and it does not download anything.

Two things are worth knowing:

- Signature checks (`--verify-signatures`, and the `analyze_file` overview and its `signatures` section)
  may start external programs such as `codesign`, `gpg` or `osslsigncode` when they are installed. They
  are given the path of the file under analysis. The `analyze_file` overview runs this check for every
  file below the large-file threshold, so these programs may start on any file you analyze, not only
  when you ask for signatures.
- It parses untrusted input: executables, archives, PDFs, Office files, Java classes and package
  archives. Parsers can have bugs. The code limits what it reads (see below), isolates panics inside MCP
  analyses, and is written in Rust, but this is not a sandbox.

## Analyzing untrusted files

Treat the scanner as a program that opens hostile files, because that is what it is.

- Run it as an unprivileged user, in a container or VM, with no access to secrets. The published
  container image runs as uid 65532 with no shell and no package manager.
- Mount the samples read-only (`-v "$PWD:/data:ro"`). The scanner never needs to write to them.
- Keep the system that runs it off the network, or restrict its outbound traffic. The scanner does not
  need a network connection to analyze a file.
- Do not open the scanner's output in a tool that interprets it. Strings pulled from a file are
  attacker-controlled text. This matters most when an AI assistant reads tool results: a file can contain
  text that looks like an instruction to the model. Treat results as data.
- A scan result is evidence, not a verdict. A clean report does not mean a file is safe. Detection rules
  are heuristics; vulnerability data for npm and Python packages is a small built-in list.

### Limits in the code

| Area | Limit |
|------|-------|
| MCP tool results | `max_output_bytes`, default 80000, ceiling 400000; lists are paged |
| Package analysis (npm, Python) | at most 400 files scanned, 1 MiB per file, 16 MiB in total, 50000 listed entries |
| `analyze_file` hex dump | `hex_dump_size` at most 4096 bytes per call (default 256), an error above that |
| `read_hex` | `length` at most 4096 per call |
| `yara_scan_file` | default/max: `max_file_size` 100/100 MB, `max_files` 10000/100000, `timeout_seconds` 60/600 |
| Concurrent MCP analyses | bounded; further calls wait |
| REST routes | 16 at a time, 120 second timeout |

There is no per-call CPU or memory limit for a single analysis. Run the process under the operating
system's limits (cgroups, `ulimit`, container limits) if you scan files you do not trust.

## The MCP server

### stdio

`mcp-stdio` has no network exposure. It runs with the permissions of the user that started it, and the
client that started it can read any file that user can read. Narrow that with `--allow-root`:

```bash
file-scanner mcp-stdio --allow-root ~/samples
```

With a root set, every tool path must resolve to a place under a root. The check resolves symlinks and
`..` first, so a link that points outside the root is refused. A refused call returns an error that
names the allowed directories. Without `--allow-root` (and without `FILE_SCANNER_ALLOWED_ROOTS`), every
readable path is allowed. The server expands a leading `~/` in `--allow-root` and in
`FILE_SCANNER_ALLOWED_ROOTS` to the home directory, so a JSON client config may use it. The startup banner
prints the expanded path.

### HTTP

`mcp-http` is a network service that returns file contents and analysis of files. The defaults are
conservative; the protections are these:

| Protection | How |
|------------|-----|
| Loopback only | `--host` defaults to `127.0.0.1`. |
| DNS rebinding | The `Host` header must be `localhost`, `127.0.0.1`, `::1` or an `--allowed-host`. Otherwise 403. |
| Browser requests | An `Origin` header must be a loopback origin or an `--allowed-origin`. No CORS wildcard. |
| Authentication | `--auth-token` or `FILE_SCANNER_AUTH_TOKEN`: one shared bearer token on every route but `/health`. |
| File scope | `--allow-root`, as above. |

The startup banner on stderr lists which of these are active. If you bind a non-loopback address without a
token, or with a `Host` list that no remote client can match, the server prints a warning.

What is not there:

- No TLS. Traffic, including the bearer token, is plain text on the wire. Put the server behind a
  reverse proxy or load balancer that terminates TLS, or keep it on loopback or a private link.
- No rate limiting. Do it in the proxy.
- No users, roles or audit log. One token grants everything the server can do, including `cache_clear`.
- No request logging. The server prints a line to stderr for refused requests only.

Recommended setups, safest first:

1. stdio, started by the client, with `--allow-root`.
2. HTTP on `127.0.0.1` for local tools, with `--allow-root`.
3. HTTP on a private network behind a TLS-terminating proxy, with a long random token, `--allow-root`
   and `--allowed-host` for the proxy's name. Pass the token in the environment, not on the command line,
   where other users can see it. See the [deployment guide](DEPLOYMENT_GUIDE.md).

Do not publish the port to the internet. Do not bind `0.0.0.0` on a machine with sensitive files unless
`--allow-root` limits the server to a directory that holds only samples.

### The cache

The server stores results of its analyses on disk so that later calls are fast. They can contain strings
and paths from the analyzed files.

- The directory is private to the user (mode 0700, files 0600). By default it is under
  `$XDG_CACHE_HOME/file-scanner`, `~/Library/Caches/file-scanner` (macOS) or `~/.cache/file-scanner`.
- Move it with `--cache-dir` or `FILE_SCANNER_CACHE_DIR`. Turn it off with `--no-cache`: nothing is stored.
- The `cache_clear` tool, `POST /cache/clear` and deleting the directory remove it. The on-disk size is
  bounded (see `FILE_SCANNER_CACHE_DISK_MB`).
- If the directory cannot be used, the server says so on stderr and keeps results in memory.

If you analyze files that are confidential, put the cache on an encrypted volume, or use `--no-cache`.

## Dependencies and supply chain

Releases are built from locked dependencies (`Cargo.lock`, `cargo build --locked`). CI runs `cargo
deny` and security scanners, and the container image is scanned and signed. See `deny.toml`, the files in
`.github/workflows/` and `docs/security/` for what is checked and what has been reviewed.

## Checklist

- [ ] Analyze untrusted files in a container or VM, as an unprivileged user.
- [ ] Mount sample directories read-only.
- [ ] Set `--allow-root` for every MCP server.
- [ ] Keep HTTP on loopback, or put TLS, a token and a rate limit in front of it.
- [ ] Pass the token through `FILE_SCANNER_AUTH_TOKEN`.
- [ ] Treat tool output as untrusted data.
- [ ] Decide where the cache lives, or turn it off.
