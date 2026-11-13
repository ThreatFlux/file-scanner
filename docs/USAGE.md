# Usage Guide

`file-scanner` is a command-line scanner and an MCP server. This guide is the command-line reference.
The MCP server is described in [MCP.md](MCP.md). Every flag below is taken from `file-scanner --help`
and each subcommand's `--help`.

## Synopsis

```text
file-scanner [OPTIONS] [FILE_PATH] [COMMAND]
```

With a `FILE_PATH` and no subcommand, the scanner analyzes that one file and prints a report on stdout.
It takes exactly one file. There is no `-` for stdin, no `-o`, no `--quiet` and no `analyze` subcommand.
`file-scanner --version` prints the version.

## Subcommands

| Command | What it does |
|---------|--------------|
| `mcp-stdio` | Run the MCP server on stdin and stdout. |
| `mcp-http` | Run the MCP server over Streamable HTTP at `/mcp`. |
| `mcp-sse` | Deprecated alias of `mcp-http`. |
| `llm-analyze` | A compact digest of one file, meant for writing a YARA rule. |
| `yara-scan` | Scan a file or directory with YARA rules. |
| `analyze-npm` | Check an npm package for malicious code and vulnerable dependencies. |
| `analyze-python` | Check a Python package the same way. |
| `analyze-java` | Analyze a JAR, WAR, EAR, APK, AAR or class file. |

## Scanning one file

### Options

```text
  -f, --format <FORMAT>                    Output format (json, yaml, pretty)
  -a, --all                                Enable all analysis options
  -s, --strings                            Extract strings from file
      --min-string-len <MIN_STRING_LEN>    Minimum string length to extract
  -v, --verify-signatures                  Verify digital signatures
      --hex-dump                           Include hex dump of file header/footer
      --hex-dump-size <HEX_DUMP_SIZE>      Bytes to dump from start of file [default: 512]
      --hex-dump-offset <HEX_DUMP_OFFSET>  Hex dump offset (0 for header, negative for footer)
      --symbols                            Analyze function symbols and symbol tables
      --control-flow                       Analyze control flow graphs and patterns
      --vulnerabilities                    Detect security vulnerabilities
      --code-quality                       Analyze code quality metrics
      --dependencies                       Analyze library dependencies and imports
      --entropy                            Analyze entropy patterns and packing detection
      --disassembly                        Disassemble binary code
      --threats                            Detect threats and malware patterns
      --behavioral                         Analyze behavioral patterns
      --yara-indicators                    Extract YARA rule indicators
  -h, --help                               Print help
  -V, --version                            Print version
```

Metadata, hashes (MD5, SHA-256, SHA-512, BLAKE3) and binary format information are always included.
Each other flag adds one section to the report. `--all` turns every section on.

### Output formats

`--format json` prints compact JSON on one line. `--format yaml` prints YAML. Without `--format`, or with
any other value (including `pretty`), the output is indented JSON. Only `json` and `yaml` change the
output.

```bash
file-scanner sample.txt --strings --min-string-len 4 --format yaml
```

The output below is shortened. The lines before `extracted_strings` (path, size, times, permissions, MIME type,
`hashes` and `binary_info`) and, after `hex_dump`, `owner_uid`, `group_gid` and the analysis keys
(all `null` here) are left out.

```yaml
extracted_strings:
  total_count: 1
  unique_count: 1
  ascii_strings:
  - hello scanner http://example.com/x
  unicode_strings: []
  interesting_strings:
  - category: URL
    value: hello scanner http://example.com/x
    offset: 0
signature_info: null
hex_dump: null
```

Sections you did not ask for are present and `null`. Errors go to stderr and the exit status is 1:

```console
$ file-scanner /nonexistent
Error: File not found: /nonexistent
$ echo $?
1
```

An unknown flag is a usage error with exit status 2.

### Strings

```bash
file-scanner sample.bin --strings                       # minimum length 4
file-scanner sample.bin --strings --min-string-len 8
```

The report keeps at most 1000 ASCII and 1000 UTF-16 strings, and puts URLs, paths, IP addresses and
similar strings in `interesting_strings`. There is no `--max-strings` flag. For more control, use the MCP
tools `query_analysis` and `search_strings`, or `llm-analyze --max-strings`.

### Hex dump

```bash
file-scanner sample.bin --hex-dump                              # first 512 bytes
file-scanner sample.bin --hex-dump --hex-dump-size 64
file-scanner sample.bin --hex-dump --hex-dump-offset -64 --hex-dump-size 64   # last 64 bytes
file-scanner sample.bin --hex-dump --hex-dump-offset 4096 --hex-dump-size 128
```

A negative offset dumps the end of the file. A non-negative offset starts at that byte.

### Signatures

```bash
file-scanner sample.exe --verify-signatures
```

Checks Authenticode (PE), macOS code signatures and GPG signatures. The result has `is_signed` and a
`verification_status`; a check that could not run is reported as not checked rather than as unsigned.

### Everything

```bash
file-scanner /bin/ls --all --format json > ls.json
```

## llm-analyze

```text
Usage: file-scanner llm-analyze [OPTIONS] <FILE_PATH>
      --token-limit <TOKEN_LIMIT>              Token limit for response [default: 25000]
      --min-string-length <MIN_STRING_LENGTH>  Minimum string length [default: 6]
      --max-strings <MAX_STRINGS>              Maximum strings to return [default: 50]
      --max-imports <MAX_IMPORTS>              Maximum imports to return [default: 30]
      --suggest-yara-rule                      Generate YARA rule suggestion
```

```bash
file-scanner llm-analyze sample.bin --max-strings 20 --suggest-yara-rule
```

```json
{"md5":"436e...","file_size":34,"key_strings":["hello scanner http://example.com/x"],
 "hex_patterns":["68 65 6C ...","6C 6C 6F ..."],"imports":[],"opcodes":[],"entropy":3.98,
 "yara_rule_suggestion":"rule sample_bin {\n    meta:\n        md5 = \"436e...\"\n        file_size = 34\n    ...
   condition:\n        filesize == 34 and 1 of ($s*) and $header at 0\n}\n"}
```

Without `--suggest-yara-rule`, `yara_rule_suggestion` is `null`. Long values are shortened here.

## yara-scan

```text
Usage: file-scanner yara-scan [OPTIONS] --rule <RULE> <PATH>
  -r, --rule <RULE>                        YARA rule file, directory of .yar/.yara files, or inline rule
  -R, --recursive                          Recursively scan directories
      --max-file-size-mb <MAX_FILE_SIZE_MB>  Maximum file size to scan in MB [default: 100]
      --detailed                           Show detailed match information
      --max-files <MAX_FILES>              Most files to examine (default: no limit)
      --timeout <TIMEOUT>                  Stop the scan after this many seconds (default: no limit)
```

```bash
file-scanner yara-scan ./samples --recursive \
  --rule 'rule t { strings: $a = "scanner" condition: $a }'
```

```json
{"total_files_scanned":2,"total_matches":1,"scan_duration_ms":71,"files_matched":1,"rules_compiled":1,
 "rule_hits":[{"rule":"t","files":1}],"matches":[{"file_path":"./samples/note.txt", ...}],"errors":[], ...}
```

`--rule` takes a path or the rule text itself. Use `--max-files` and `--timeout` on large trees.

## Package analysis

```bash
file-scanner analyze-npm ./some-package          # a directory, package.json, or the .tgz from `npm pack`
file-scanner analyze-python ./pkg-1.0-py3-none-any.whl   # .whl, .tar.gz, .zip or a source directory
file-scanner analyze-java ./app.jar              # JAR/WAR/EAR/APK/AAR or a class file
```

Each prints a JSON report. The analysis is offline: the scanner does not download packages or contact
a registry. Vulnerability data is a built-in list that covers only a small set of well-known packages.
A wrong input gives a message that says what to pass, for example:

```console
$ file-scanner analyze-java note.txt
Error: Not a Java archive or class file: it is neither a ZIP (JAR/WAR/EAR/AAR/APK) nor a class file ...
```

## Scanning many files

The scanner takes one file per run. Loop in the shell:

```bash
for f in samples/*; do
  file-scanner "$f" --format json
done > scans.jsonl

# Several at once
find samples -type f -print0 | xargs -0 -n1 -P4 file-scanner --format json > scans.jsonl
```

Each run prints one line of JSON with `--format json`, so the output is JSON Lines. Failed files print
an error on stderr and do not stop the loop.

## Working with the output

```bash
file-scanner sample.bin --format json | jq '{sha256: .hashes.sha256, size: .file_size}'
file-scanner sample.bin --strings --format json \
  | jq -r '.extracted_strings.interesting_strings[] | select(.category=="URL") | .value'
```

Field names come from the JSON itself; run a scan once and look.

## MCP server

```bash
file-scanner mcp-stdio                           # for an MCP client that starts the process
file-scanner mcp-http --port 3000                # loopback only by default
```

Flags for both are listed in [MCP.md](MCP.md) and in the [deployment guide](../DEPLOYMENT_GUIDE.md).

## Troubleshooting

- `unexpected argument '...' found`: the flag does not exist. Compare with the lists above.
- `Error: File path is required for scanning mode`: you ran the binary with no file and no subcommand.
- `Error: File not found`: check the path. Relative paths resolve against the current directory.
- Slow scans on big files: scan without `--all`, and add only the sections you need.
