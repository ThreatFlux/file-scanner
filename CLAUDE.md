# File Scanner - Claude Code Project

## Project Overview

A comprehensive native file scanner written in Rust that provides detailed metadata, hash calculations,
string extraction, binary analysis, hex dumping, and digital signature verification. Built using Rust 1.96.0
with modern async capabilities and multiple output formats.

## Key Features

- **File Metadata Extraction**: Complete file system metadata including timestamps, permissions, ownership
- **Cryptographic Hashing**: MD5, SHA256, SHA512, and BLAKE3 hash calculations with async processing
- **String Analysis**: ASCII and Unicode string extraction with intelligent pattern matching
- **Binary Format Analysis**: PE/ELF/Mach-O parsing with compiler detection and section analysis
- **Digital Signature Verification**: Support for Authenticode, GPG, and macOS code signatures
- **Hex Dumping**: Flexible hex dump capabilities for headers, footers, or custom offsets
- **Multiple Output Formats**: JSON, YAML, and pretty-printed JSON support
- **Performance Optimized**: Concurrent hash calculation and efficient memory usage
- **MCP Server Support**: Model Context Protocol server with STDIO, HTTP, and SSE transports
- **Analysis Caching**: Automatic caching of analysis results with persistence for improved performance
- **String Tracking & Statistics**: Advanced string analysis with usage statistics, categorization,
  and filtering
- **NPM Package Analysis**: Comprehensive security analysis of npm packages including vulnerability
  detection, malicious code patterns, typosquatting detection, and supply chain risk assessment
- **Python Package Analysis**: Security analysis of Python packages (wheel, tar.gz, zip) with vulnerability
  detection, setup.py risk assessment, typosquatting detection, and malicious pattern identification

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
./target/release/file-scanner /bin/ls --hex-dump --hex-dump-offset=-128  # footer dump

# String extraction
./target/release/file-scanner /bin/ls --strings --min-string-len 8

# MCP Server Modes
./target/release/file-scanner mcp-stdio              # STDIO transport
./target/release/file-scanner mcp-http --port 3000   # HTTP transport
./target/release/file-scanner mcp-sse --port 3000    # SSE transport

# Test MCP server with inspector (FIXED - now working!)
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
npx @modelcontextprotocol/inspector http://localhost:3000/mcp
npx @modelcontextprotocol/inspector http://localhost:3000/sse

# CLI testing mode for individual tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/list
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name get_file_metadata \
  --tool-arg file_path=/bin/ls
```

## Project Structure

```text
src/
├── main.rs              # CLI interface and main application logic
├── metadata.rs          # File metadata extraction and core data structures
├── hash.rs              # Cryptographic hash calculations (async)
├── strings.rs           # String extraction and pattern matching
├── binary_parser.rs     # PE/ELF/Mach-O binary format parsing
├── signature.rs         # Digital signature verification
├── hexdump.rs           # Hex dump generation and formatting
├── cache.rs             # Analysis cache with persistence support
├── string_tracker.rs    # String tracking and statistics engine
├── npm_analysis.rs      # NPM package security analysis
├── npm_vuln_db.rs       # NPM vulnerability database and patterns
├── python_analysis.rs   # Python package security analysis
├── python_vuln_db.rs    # Python vulnerability database and patterns
├── mcp_server.rs        # MCP server implementation with file scanner tools
└── mcp_transport.rs     # MCP transport implementations (STDIO, HTTP, SSE)
```

## Dependencies

- **Core**: `tokio` (async runtime), `anyhow` (error handling), `clap` (CLI)
- **Hashing**: `sha2`, `md-5`, `blake3`
- **Binary Parsing**: `goblin`, `object`
- **String Processing**: `regex`, `encoding_rs`
- **Serialization**: `serde`, `serde_json`, `serde_yaml`
- **System Info**: `chrono`, `filetime`
- **MCP**: `rmcp` (Model Context Protocol SDK), `schemars`
- **HTTP Server**: `axum`, `tower`, `hyper`

## Testing Examples

The scanner has been tested on various file types:

1. **ELF Binaries** (`/bin/ls`): Successfully extracts metadata, hashes, binary info, and strings
2. **Text Files** (`/etc/passwd`): Proper MIME type detection and hex dumping
3. **Self-Analysis**: Can analyze its own binary for comprehensive testing

### Test Program Suite

The project includes comprehensive test programs in 9 compiled languages to validate detection
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

- Built with the project Rust 1.96.0 toolchain
- Uses async processing for hash calculations to improve performance on large files
- Modular design allows easy extension for new file formats or analysis types
- Comprehensive error handling with descriptive messages
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

The file-scanner can run as an MCP (Model Context Protocol) server, exposing its capabilities as tools for
AI assistants. **The MCP server is now fully functional and tested with comprehensive OpenAPI 3.0
documentation!**

### Available MCP Tools

The file scanner provides three powerful tools through the MCP interface:

#### 1. `analyze_file` - Comprehensive Analysis Tool

A unified tool that allows you to specify exactly which analyses to perform using boolean flags:

**Tool Name:** `analyze_file`

**Parameters:**

- `file_path` (required): Path to the file to analyze
- `all`: Enable all analysis options (overrides individual flags)
- `metadata`: Include file metadata (size, timestamps, permissions)
- `hashes`: Calculate cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)
- `strings`: Extract ASCII and Unicode strings
- `min_string_length`: Minimum string length (default: 4)
- `hex_dump`: Generate hex dump
- `hex_dump_size`: Hex dump size in bytes (default: 256, or entire file up to 100MB when 'all' is true)
- `hex_dump_offset`: Hex dump offset from start
- `binary_info`: Analyze binary format (PE/ELF/Mach-O)
- `signatures`: Verify digital signatures
- `symbols`: Analyze function symbols
- `control_flow`: Analyze control flow
- `vulnerabilities`: Detect vulnerabilities
- `code_quality`: Analyze code quality metrics
- `dependencies`: Analyze dependencies
- `entropy`: Analyze entropy patterns
- `disassembly`: Disassemble code
- `threats`: Detect threats and malware
- `behavioral`: Analyze behavioral patterns
- `yara_indicators`: Extract YARA rule indicators

**Example Usage:**

```json
{
  "file_path": "/bin/ls",
  "metadata": true,
  "hashes": true,
  "strings": true,
  "binary_info": true
}
```

**Example with 'all' flag:**

```json
{
  "file_path": "/bin/ls",
  "all": true
}
```

#### 2. `llm_analyze_file` - LLM-Optimized Analysis Tool

A focused analysis tool designed specifically for LLM consumption and YARA rule generation. Returns only
the most relevant information within a controlled token limit.

**Tool Name:** `llm_analyze_file`

**Key Features:**

- Returns only MD5 hash (not all hash types)
- Extracts key strings prioritized for YARA rules
- Identifies important hex patterns and opcodes
- Provides imports and entropy analysis
- Generates YARA rule suggestions
- Token-limited output (default 25K tokens)

**Parameters:**

- `file_path` (required): Path to the file to analyze
- `token_limit`: Maximum response size in characters (default: 25000)
- `min_string_length`: Minimum string length to extract (default: 6)
- `max_strings`: Maximum number of strings to return (default: 50)
- `max_imports`: Maximum number of imports to return (default: 30)
- `max_opcodes`: Maximum number of opcodes to return (default: 10)
- `hex_pattern_size`: Size of hex patterns to extract (default: 32)
- `suggest_yara_rule`: Generate YARA rule suggestion (default: true)

**Example Usage:**

```json
{
  "file_path": "/suspicious/malware.exe",
  "token_limit": 25000,
  "max_strings": 30,
  "suggest_yara_rule": true
}
```

**Example Output:**

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "file_size": 45056,
  "key_strings": [
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "cmd.exe /c",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
  ],
  "hex_patterns": [
    "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00"
  ],
  "imports": [
    "kernel32.dll",
    "ntdll.dll",
    "advapi32.dll"
  ],
  "opcodes": [
    "E8 00 00 00 00",
    "48 8B 05 00",
    "FF 15 00 00"
  ],
  "entropy": 7.8,
  "yara_rule_suggestion": "rule suspicious_malware_exe { /* YARA rule content */ }"
}
```

#### 3. `yara_scan_file` - Custom YARA Rule Scanner

A powerful tool for scanning files or directories with custom YARA rules. Supports recursive directory scanning and concurrent file processing.

**Tool Name:** `yara_scan_file`

**Parameters:**

- `path` (required): Path to the file or directory to scan
- `yara_rule` (required): The YARA rule content to use for scanning
- `recursive`: Recursively scan subdirectories (default: true)
- `max_file_size`: Maximum file size to scan in bytes (default: 100MB)
- `detailed_matches`: Include detailed match information (default: true)

**Example Usage:**

```json
{
  "path": "/suspicious/files",
  "yara_rule": "rule detect_malware {\n    strings:\n        $api1 = \"VirtualAlloc\"\n        $api2 = \"WriteProcessMemory\"\n        $api3 = \"CreateRemoteThread\"\n    condition:\n        2 of them\n}",
  "recursive": true,
  "max_file_size": 104857600,
  "detailed_matches": true
}
```

**Example Output:**

```json
{
  "total_files_scanned": 42,
  "total_matches": 3,
  "scan_duration_ms": 1523,
  "matches": [
    {
      "file_path": "/suspicious/files/malware.exe",
      "file_size": 65536,
      "matches": [
        {
          "rule_identifier": "detect_malware",
          "tags": [],
          "metadata": {},
          "strings": [
            {
              "identifier": "$api1",
              "offset": 4096,
              "length": 12,
              "value": "VirtualAlloc"
            },
            {
              "identifier": "$api3",
              "offset": 8192,
              "length": 18,
              "value": "CreateRemoteThread"
            }
          ]
        }
      ]
    }
  ],
  "errors": []
}
```

**Use Cases:**

- Scan entire directories for specific malware patterns
- Hunt for IOCs across multiple files
- Validate YARA rules against sample sets
- Perform incident response file sweeps
- Search for specific code patterns or strings

### MCP Configuration for Claude Code

**STDIO Transport (Recommended):**

```json
{
  "mcpServers": {
    "file-scanner": {
      "command": "./target/release/file-scanner",
      "args": ["mcp-stdio"]
    }
  }
}
```

**HTTP Transport:**

```json
{
  "mcpServers": {
    "file-scanner-http": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

**SSE Transport:**

```json
{
  "mcpServers": {
    "file-scanner-sse": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

### MCP Testing Status

✅ **FIXED**: JSON-RPC protocol compliance issues resolved
✅ **UNIFIED**: Single `analyze_file` tool with configurable analysis options
✅ **TESTED**: MCP Inspector CLI and UI modes working
✅ **VERIFIED**: Tool calls return proper formatted responses
✅ **CACHING**: Automatic result caching with persistence across sessions
✅ **COMPLIANT**: Now under 15-tool MCP limit with comprehensive functionality
✅ **ENHANCED**: Added `yara_scan_file` tool for custom YARA rule scanning

**Known Working Commands:**

```bash
# List all available tools
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/list

# Test analyze_file tool with individual flags
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name analyze_file \
  --tool-arg file_path=/bin/ls --tool-arg metadata=true --tool-arg hashes=true

# Test analyze_file tool with 'all' flag
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name analyze_file \
  --tool-arg file_path=/bin/ls --tool-arg all=true

# Test yara_scan_file tool
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name yara_scan_file \
  --tool-arg path=/bin --tool-arg yara_rule="rule test { strings: \$a = \"ELF\" condition: \$a }"

# Interactive UI testing
npx @modelcontextprotocol/inspector ./target/release/file-scanner mcp-stdio
```

### Cache Management (HTTP/SSE Transport)

When running as an HTTP or SSE server, the file scanner provides cache management endpoints:

```bash
# Start HTTP server
./target/release/file-scanner mcp-http --port 3000

# View cache statistics
curl http://localhost:3000/cache/stats

# List all cache entries
curl http://localhost:3000/cache/list

# Search cache by criteria
curl -X POST http://localhost:3000/cache/search \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "calculate_file_hashes"}'

# Clear cache
curl -X POST http://localhost:3000/cache/clear
```

**Cache Features:**

- Automatic caching of all MCP tool call results
- Persistence to disk in temp directory (`/tmp/file-scanner-cache/`)
- SHA256-based file identification for cache hits
- Per-file analysis history tracking
- Execution time tracking for performance monitoring
- Cache statistics and search capabilities

### String Tracking & Analysis

The file scanner includes an advanced string tracking system that analyzes and categorizes all strings
found during file analysis:

```bash
# String statistics
curl http://localhost:3000/strings/stats

# Search for strings
curl -X POST http://localhost:3000/strings/search \
  -H "Content-Type: application/json" \
  -d '{"query": "lib", "limit": 20}'

# Get detailed information about a specific string
curl -X POST http://localhost:3000/strings/details \
  -H "Content-Type: application/json" \
  -d '{"value": "libc.so.6"}'

# Find related strings
curl -X POST http://localhost:3000/strings/related \
  -H "Content-Type: application/json" \
  -d '{"value": "libc.so.6", "limit": 10}'

# Advanced filtering
curl -X POST http://localhost:3000/strings/filter \
  -H "Content-Type: application/json" \
  -d '{
    "min_occurrences": 2,
    "min_entropy": 4.0,
    "categories": ["import", "path"],
    "suspicious_only": true
  }'
```

**String Tracking Features:**

- Automatic categorization (URLs, paths, imports, commands, etc.)
- Entropy calculation for detecting encoded/encrypted strings
- Suspicious string detection using pattern matching
- File association tracking (which files contain which strings)
- Similarity analysis to find related strings
- Advanced filtering by multiple criteria:
  - Occurrence count
  - String length
  - Entropy level
  - Categories
  - File associations
  - Suspicious indicators
  - Regular expression patterns
- Real-time statistics:
  - Most common strings
  - Category distribution
  - Length distribution
  - High-entropy strings
  - Suspicious strings

See `MCP_TESTING.md` for comprehensive testing instructions.

### OpenAPI 3.0 Documentation

The HTTP transport now includes comprehensive OpenAPI 3.0 specification support for easy API exploration
and integration:

**API Documentation Endpoints:**

```bash
# OpenAPI 3.0 JSON specification
curl http://localhost:3000/api-docs/openapi.json

# API information and endpoint listing
curl http://localhost:3000/api/info

# Health check
curl http://localhost:3000/health
```

**OpenAPI Features:**

- Complete OpenAPI 3.0 specification with schema definitions
- Automatic generation of JSON-RPC, Cache, SSE, and other data models
- Structured endpoint documentation for all HTTP routes
- Schema validation for request/response bodies
- Compatible with OpenAPI tooling and code generators

**Integration Examples:**

```bash
# Generate client SDKs using OpenAPI Generator
npx @openapitools/openapi-generator-cli generate \
  -i http://localhost:3000/api-docs/openapi.json \
  -g python-client \
  -o ./python-client

# Import into Postman, Insomnia, or other API tools
# Use the OpenAPI spec URL: http://localhost:3000/api-docs/openapi.json

# Generate documentation with ReDoc
npx redoc-cli build http://localhost:3000/api-docs/openapi.json
```

The OpenAPI specification includes schemas for:

- `JsonRpcRequest` / `JsonRpcResponse` / `JsonRpcError` - MCP protocol types
- `CacheEntry` / `CacheSearchQuery` - Cache management types
- `SseEvent` / `SseQuery` - Server-Sent Events types
- Additional analysis and tool-specific data structures

This enables seamless integration with API development tools, client SDK generation, and automated
testing frameworks.

## NPM Package Analysis

The file scanner includes comprehensive npm package security analysis capabilities to detect vulnerabilities,
malicious code patterns, and supply chain attacks.

### Features

- **Vulnerability Detection**: Checks dependencies against a built-in vulnerability database
- **Malicious Pattern Detection**: Identifies suspicious code patterns including:
  - Installation script hooks (preinstall/postinstall) with external downloads
  - Obfuscated code and dynamic code execution
  - Environment variable exfiltration
  - Cryptocurrency mining indicators
  - Reverse shell patterns
  - Data exfiltration attempts
- **Typosquatting Detection**: Identifies packages with names similar to popular packages
- **Dependency Confusion**: Detects potential dependency confusion attacks
- **Supply Chain Risk Assessment**: Calculates risk scores based on various security indicators
- **Script Analysis**: Analyzes npm scripts for dangerous commands and patterns

### Usage

The npm analysis can be used in two ways:

1. **As a library function**:
```rust
use file_scanner::npm_analysis::analyze_npm_package;
use std::path::Path;

let analysis = analyze_npm_package(Path::new("path/to/package"))?;
```

2. **Via MCP tool** (when available):
```bash
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name analyze_npm_package \
  --tool-arg package_path=/path/to/package
```

### Analysis Results

The analysis provides comprehensive information including:

- Package metadata (name, version, license, author)
- Dependency analysis with vulnerability information
- Security analysis of scripts and code patterns
- Malicious indicators and risk scoring
- Quality metrics (documentation, tests, CI/CD)

### Built-in Vulnerability Database

The scanner includes known vulnerabilities for packages like:
- event-stream (cryptocurrency wallet theft)
- ua-parser-js (crypto mining malware)
- node-ipc (protestware)
- lodash (prototype pollution)
- minimist (prototype pollution)

### Example Analysis Output

```json
{
  "package_info": {
    "name": "suspicious-package",
    "version": "1.0.0"
  },
  "malicious_indicators": {
    "overall_risk_score": 75.5,
    "risk_level": "High",
    "typosquatting_risk": {
      "is_potential_typosquatting": true,
      "similar_packages": ["express"]
    }
  },
  "security_analysis": {
    "has_preinstall_script": true,
    "crypto_mining_indicators": false,
    "supply_chain_risk_score": 40.0
  }
}
```

## Python Package Analysis

The file scanner includes comprehensive Python package security analysis capabilities to detect vulnerabilities,
malicious code patterns, and supply chain attacks. Supports multiple package formats including wheel (.whl),
source distributions (.tar.gz), zip archives, and source directories.

### Features

- **Multiple Package Format Support**:
  - Wheel packages (.whl)
  - Source distributions (.tar.gz)
  - Zip archives (.zip)
  - Source directories with setup.py/pyproject.toml
- **Vulnerability Detection**: Checks dependencies against a built-in vulnerability database with CVEs
- **Malicious Pattern Detection**: Identifies suspicious patterns including:
  - Setup.py code execution during installation
  - Obfuscated code and eval/exec usage
  - Network backdoors and reverse shells
  - Credential theft attempts
  - Cryptocurrency mining
  - File system manipulation
- **Typosquatting Detection**: Advanced detection of packages with names similar to popular packages
- **Dependency Confusion**: Detects internal package name patterns used in attacks
- **Supply Chain Risk Assessment**: Comprehensive risk scoring based on multiple factors
- **Setup Script Analysis**: Deep analysis of setup.py for dangerous operations
- **Quality Metrics**: Assesses package quality including documentation, tests, and CI/CD

### Usage

The Python analysis can be used in two ways:

1. **As a library function**:
```rust
use file_scanner::python_analysis::analyze_python_package;
use std::path::Path;

let analysis = analyze_python_package(Path::new("path/to/package.whl"))?;
```

2. **Via MCP tool**:
```bash
npx @modelcontextprotocol/inspector --cli ./target/release/file-scanner \
  mcp-stdio --method tools/call --tool-name analyze_python_package \
  --tool-arg package_path=/path/to/package.whl
```

### Analysis Results

The analysis provides detailed information including:

- Package metadata from multiple sources (setup.py, pyproject.toml, METADATA)
- Comprehensive dependency analysis with vulnerability information
- Security analysis of setup scripts and import patterns
- Malicious indicators with detailed risk scoring
- Maintainer information and trust scoring
- Quality metrics for code and documentation

### Built-in Vulnerability Database

The scanner includes known vulnerabilities for packages like:
- Django (multiple CVEs for various versions)
- Flask (security header vulnerabilities)
- requests (proxy header leakage)
- Pillow (uncontrolled resource consumption)
- PyYAML (arbitrary code execution)
- NumPy (NULL pointer dereference)
- urllib3 (cookie header leakage)

### Known Malicious Packages

The scanner maintains a database of known malicious packages including typosquatting attempts like:
- colourama (typosquatting colorama)
- python-sqlite, python-mysql (fake database packages)
- pytorch (should be torch)
- sklearn (should be scikit-learn)
- beautifulsoup (should be beautifulsoup4)

### Example Analysis Output

```json
{
  "package_info": {
    "name": "suspicious-package",
    "version": "1.0.0",
    "package_format": "Wheel"
  },
  "dependencies": {
    "vulnerability_summary": {
      "critical_count": 1,
      "high_count": 2,
      "total_count": 3
    }
  },
  "security_analysis": {
    "has_setup_script": true,
    "supply_chain_risk_score": 65.0,
    "suspicious_imports": [
      {
        "module_name": "subprocess",
        "risk_level": "High",
        "reason": "Process execution"
      }
    ]
  },
  "malicious_indicators": {
    "overall_risk_score": 78.5,
    "risk_level": "High",
    "typosquatting_risk": {
      "is_potential_typosquatting": true,
      "similar_packages": ["requests"]
    }
  }
}
```

## Future Enhancement Ideas

- Support for additional binary formats (Java class files, .NET assemblies)
- Extended signature verification (jar signing, etc.)
- File content classification using machine learning
- Batch processing capabilities
- Plugin architecture for custom analyzers
- Enhanced MCP features (resources, prompts)
- Ruby gem security analysis
- Java/Maven package analysis
- Container image scanning
# GitHub Pages configured for benchmark results
